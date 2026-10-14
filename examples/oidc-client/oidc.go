package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/easyssf/easyssf-go/ssf"
)

// The login with OpenID Connect, by hand: discovery, the authorization code flow with PKCE, the
// ID token verified with go-jose against the JWK Set of the provider, and the RP-initiated
// logout. What Spring Security does for the Java example and the openidconnect crate for the
// Rust one. Not a general OIDC client: enough for the example.

// OIDCConfig is the OpenID Provider the application logs in with.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURL  string
}

// LoggedInUser is what the application keeps of the ID token.
type LoggedInUser struct {
	Issuer   string
	Subject  string
	SID      string
	Username string
	Email    string
	IDToken  string
	// Claims are the claims of the ID token, for receiver.SubjectMatches.
	Claims ssf.Claims
}

// LoginState is what a login in progress remembers between the redirect to the provider and
// the callback.
type LoginState struct {
	State, Nonce, Verifier string
}

type providerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// OIDC logs users in with the provider.
type OIDC struct {
	config   OIDCConfig
	client   *http.Client
	mu       sync.Mutex
	metadata *providerMetadata
	keys     *jose.JSONWebKeySet
	keysAt   time.Time
}

// NewOIDC is a client of the provider.
func NewOIDC(config OIDCConfig) *OIDC {
	return &OIDC{config: config, client: &http.Client{Timeout: 10 * time.Second}}
}

func (o *OIDC) discover(ctx context.Context) (*providerMetadata, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.metadata != nil {
		return o.metadata, nil
	}
	var metadata providerMetadata
	if err := o.getJSON(ctx, strings.TrimSuffix(o.config.Issuer, "/")+"/.well-known/openid-configuration", &metadata); err != nil {
		return nil, fmt.Errorf("could not discover the OpenID Provider %s: %w", o.config.Issuer, err)
	}
	if metadata.Issuer != o.config.Issuer {
		return nil, fmt.Errorf("the OpenID Provider calls itself %q, not %q", metadata.Issuer, o.config.Issuer)
	}
	o.metadata = &metadata
	return o.metadata, nil
}

func (o *OIDC) getJSON(ctx context.Context, u string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	response, err := o.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered with status %d", u, response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(into)
}

// StartLogin returns the authorization URL to send the browser to and what the session has to
// remember.
func (o *OIDC) StartLogin(ctx context.Context) (string, *LoginState, error) {
	metadata, err := o.discover(ctx)
	if err != nil {
		return "", nil, err
	}
	state := &LoginState{State: randomHex(16), Nonce: randomHex(16), Verifier: randomHex(32)}
	challenge := sha256.Sum256([]byte(state.Verifier))
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {o.config.ClientID},
		"redirect_uri":          {o.config.RedirectURL},
		"scope":                 {strings.Join(o.config.Scopes, " ")},
		"state":                 {state.State},
		"nonce":                 {state.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	return metadata.AuthorizationEndpoint + "?" + query.Encode(), state, nil
}

// FinishLogin exchanges the code of the callback for the tokens and validates the ID token.
func (o *OIDC) FinishLogin(ctx context.Context, login *LoginState, query url.Values) (*LoggedInUser, error) {
	if login == nil {
		return nil, errors.New("no login in progress")
	}
	if query.Get("error") != "" {
		return nil, fmt.Errorf("the provider answered %s: %s", query.Get("error"), query.Get("error_description"))
	}
	if query.Get("state") != login.State {
		return nil, errors.New("the state of the callback is not the one of the login")
	}
	metadata, err := o.discover(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {query.Get("code")},
		"redirect_uri":  {o.config.RedirectURL},
		"code_verifier": {login.Verifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(url.QueryEscape(o.config.ClientID), url.QueryEscape(o.config.ClientSecret))
	response, err := o.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the token endpoint answered with status %d: %s", response.StatusCode, body)
	}
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil || tokens.IDToken == "" {
		return nil, errors.New("the token response has no id_token")
	}
	claims, err := o.verifyIDToken(ctx, tokens.IDToken, login.Nonce)
	if err != nil {
		return nil, err
	}
	return &LoggedInUser{Issuer: ssf.StringMember(claims, "iss"), Subject: ssf.StringMember(claims, "sub"), SID: ssf.StringMember(claims, "sid"),
		Username: ssf.StringMember(claims, "preferred_username"), Email: ssf.StringMember(claims, "email"), IDToken: tokens.IDToken, Claims: claims}, nil
}

// verifyIDToken checks the signature against the JWK Set of the provider and the claims OpenID
// Connect Core 1.0, section 3.1.3.7 requires of a client.
func (o *OIDC) verifyIDToken(ctx context.Context, idToken, nonce string) (ssf.Claims, error) {
	jws, err := jose.ParseSigned(idToken, []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("the ID token is not a signed JWT: %w", err)
	}
	if len(jws.Signatures) == 0 {
		return nil, errors.New("the ID token is not signed")
	}
	kid := jws.Signatures[0].Header.KeyID
	keys, err := o.jwks(ctx, kid)
	if err != nil {
		return nil, err
	}
	var payload []byte
	for _, key := range keys.Key(kid) {
		if payload, err = jws.Verify(key.Key); err == nil {
			break
		}
	}
	if payload == nil {
		return nil, errors.New("the signature of the ID token could not be verified")
	}
	claims, err := ssf.ParseClaims(payload)
	if err != nil {
		return nil, err
	}
	if ssf.StringMember(claims, "iss") != o.config.Issuer {
		return nil, errors.New("the ID token was not issued by the provider")
	}
	audience := false
	for _, aud := range ssf.Audiences(claims["aud"]) {
		audience = audience || aud == o.config.ClientID
	}
	if !audience {
		return nil, errors.New("the ID token is not for this client")
	}
	if exp, ok := ssf.Int64(claims["exp"]); !ok || time.Now().Unix() > exp+60 {
		return nil, errors.New("the ID token expired")
	}
	if ssf.StringMember(claims, "nonce") != nonce {
		return nil, errors.New("the nonce of the ID token is not the one of the login")
	}
	return claims, nil
}

// jwks is the JWK Set of the provider, fetched again when it lacks the key or is older than ten
// minutes.
func (o *OIDC) jwks(ctx context.Context, kid string) (*jose.JSONWebKeySet, error) {
	metadata, err := o.discover(ctx)
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.keys != nil && time.Since(o.keysAt) < 10*time.Minute && len(o.keys.Key(kid)) > 0 {
		return o.keys, nil
	}
	var keys jose.JSONWebKeySet
	if err := o.getJSON(ctx, metadata.JWKSURI, &keys); err != nil {
		return nil, fmt.Errorf("could not fetch the keys of the provider: %w", err)
	}
	o.keys, o.keysAt = &keys, time.Now()
	return o.keys, nil
}

// LogoutURL is where to send the browser to end the session at the provider as well
// (RP-initiated logout), "" if the provider has no end_session_endpoint.
func (o *OIDC) LogoutURL(ctx context.Context, user *LoggedInUser, postLogoutRedirect string) (string, error) {
	metadata, err := o.discover(ctx)
	if err != nil {
		return "", err
	}
	if metadata.EndSessionEndpoint == "" {
		return "", nil
	}
	query := url.Values{"id_token_hint": {user.IDToken}, "post_logout_redirect_uri": {postLogoutRedirect}, "client_id": {o.config.ClientID}}
	return metadata.EndSessionEndpoint + "?" + query.Encode(), nil
}
