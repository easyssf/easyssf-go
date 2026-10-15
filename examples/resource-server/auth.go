package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
)

// Validates the access tokens of the identity provider, the part Spring Security's resource
// server support plays in the Java example: the signature against the keys of the issuer, iss
// and exp. The identity provider is the SSF transmitter and signs access tokens and SETs with
// the same keys, so the JWKSetSource of the receiver's transmitter is reused; it refreshes the
// keys when a token names one it does not know. The
// claims are left on the request for the handlers and for the revocation middleware of the
// receiver, which reads iss, sub, sid and iat from them.

type accessTokenKey struct{}

// AccessToken are the claims of a validated access token.
type AccessToken ssf.Claims

// String is a string claim.
func (t AccessToken) String(claim string) string { return ssf.StringMember(ssf.Claims(t), claim) }

// Time is a numeric date claim (iat, exp), zero if absent.
func (t AccessToken) Time(claim string) time.Time {
	if seconds, ok := ssf.Int64(t[claim]); ok {
		return time.Unix(seconds, 0).UTC()
	}
	return time.Time{}
}

// Claims are the claims the revocation check of the receiver reads.
func (t AccessToken) Claims() receiver.TokenClaims {
	return receiver.TokenClaims{Issuer: t.String("iss"), Subject: t.String("sub"), SessionID: t.String("sid"), IssuedAt: t.Time("iat")}
}

// AccessTokens validates the access tokens of one issuer with its keys.
type AccessTokens struct {
	issuer string
	keys   receiver.JWKSetSource
}

var acceptedAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.EdDSA}

// Validate checks the token and returns its claims: signed with a key of the issuer (fetching the
// keys again once for an unknown kid, as identity providers rotate them), issued by the expected issuer
// and not expired. The audience is not checked, see below.
func (a *AccessTokens) Validate(ctx context.Context, token string) (AccessToken, error) {
	jws, err := jose.ParseSigned(token, acceptedAlgorithms)
	if err != nil {
		return nil, err
	}
	kid := jws.Signatures[0].Header.KeyID
	keys, err := a.keys.JWKSet(ctx, false)
	if err != nil {
		return nil, err
	}
	if len(keys.Key(kid)) == 0 {
		// the identity provider rotated its keys: fetch them again, rate limited by the source
		if keys, err = a.keys.JWKSet(ctx, true); err != nil {
			return nil, err
		}
	}
	var payload []byte
	for _, key := range keys.Key(kid) {
		if payload, err = jws.Verify(key.Key); err == nil {
			break
		}
	}
	if payload == nil {
		return nil, errUnknownKey
	}
	claims, err := ssf.ParseClaims(payload)
	if err != nil {
		return nil, err
	}
	if ssf.StringMember(claims, "iss") != a.issuer {
		return nil, errWrongIssuer
	}
	// which audience an access token carries depends on the identity provider and its
	// configuration, so this example does not check it; a real resource server does
	if exp, ok := ssf.Int64(claims["exp"]); !ok || time.Now().Unix() > exp+30 {
		return nil, errExpired
	}
	return AccessToken(claims), nil
}

type authError string

func (e authError) Error() string { return string(e) }

const (
	errUnknownKey  = authError("the token is signed with an unknown key")
	errWrongIssuer = authError("the token was not issued by the expected issuer")
	errExpired     = authError("the token expired")
)

// RequireAccessToken is middleware that requires a valid access token in the Authorization
// header and leaves its claims on the request; it answers 401 with a WWW-Authenticate challenge
// (RFC 6750) otherwise.
func (a *AccessTokens) RequireAccessToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if len(authorization) < 7 || !strings.EqualFold(authorization[:7], "Bearer ") {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		token, err := a.Validate(r.Context(), strings.TrimSpace(authorization[7:]))
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+strings.ReplaceAll(err.Error(), `"`, "'")+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), accessTokenKey{}, token)))
	})
}

// TokenOf is the validated access token of the request, nil if the middleware did not run.
func TokenOf(r *http.Request) AccessToken {
	token, _ := r.Context().Value(accessTokenKey{}).(AccessToken)
	return token
}

// tokenClaims is the receiver.TokenClaimsExtractor for the revocation middleware.
func tokenClaims(r *http.Request) (receiver.TokenClaims, bool) {
	token := TokenOf(r)
	if token == nil {
		return receiver.TokenClaims{}, false
	}
	return token.Claims(), true
}

// me is GET /api/me: the user of the access token, as the Java example shows it.
func me(w http.ResponseWriter, r *http.Request) {
	token := TokenOf(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"username":       token.String("preferred_username"),
		"subject":        token.String("sub"),
		"sessionId":      token.String("sid"),
		"tokenIssuedAt":  rfc3339(token.Time("iat")),
		"tokenExpiresAt": rfc3339(token.Time("exp")),
	})
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
