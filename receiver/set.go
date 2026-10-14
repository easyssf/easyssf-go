package receiver

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/easyssf/easyssf-go/ssf"
)

// SecEventJWTType is the media type a SET must be explicitly typed with (RFC 8417, section 2.3).
const SecEventJWTType = "secevent+jwt"

// Verifier verifies an encoded Security Event Token (RFC 8417): its signature and claims, in JWS
// compact serialization. It returns a RejectedError for an invalid SET and a
// TransmitterUnavailableError when the keys could not be obtained.
type Verifier interface {
	Verify(ctx context.Context, encodedSET string) (*ssf.EventToken, error)
}

// SupportedAlgorithms are the asymmetric signature algorithms SETs may be signed with: the RSA,
// RSA-PSS and ECDSA algorithms of RFC 7518, section 3, and EdDSA (RFC 8037).
var SupportedAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
}

// SupportedAlgorithm returns the algorithm with the given JWS name if it is one of the
// SupportedAlgorithms.
func SupportedAlgorithm(name string) (jose.SignatureAlgorithm, bool) {
	for _, algorithm := range SupportedAlgorithms {
		if string(algorithm) == strings.TrimSpace(name) {
			return algorithm, true
		}
	}
	return "", false
}

// ExpectedAudiencesProvider supplies the audiences a SET must be addressed to, consulted for every
// SET: for example the audience of a stream once it is registered. Any audience is accepted while
// it returns none.
type ExpectedAudiencesProvider func() ([]string, error)

// VerifierOptions say how a JWTVerifier verifies SETs; the Java setters. Read for every SET. The
// zero value is not usable, start from DefaultVerifierOptions.
type VerifierOptions struct {
	// ExpectedAudiences are the audiences a SET must be addressed to; it has to be addressed to
	// at least one of them. Any audience is accepted while this is empty and no provider is set.
	ExpectedAudiences []string
	// ExpectedAudiencesProvider supplies the audiences instead of ExpectedAudiences.
	ExpectedAudiencesProvider ExpectedAudiencesProvider
	// AcceptedAlgorithms are the JWS algorithms SETs may be signed with, RS256 by default; only
	// the SupportedAlgorithms are allowed.
	AcceptedAlgorithms []jose.SignatureAlgorithm
	// MinRSAKeySize is the minimum size of RSA signing keys in bits, 0 to accept any. 2048 by
	// default.
	MinRSAKeySize int
	// RequireTypeHeader says whether a SET must have a typ header of secevent+jwt (RFC 8417,
	// section 2.3). true by default.
	RequireTypeHeader bool
	// SubjectCompatibility says how strictly the subject of a SET is validated: ssf.Strict
	// requires the top-level sub_id claim of SSF 1.0, ssf.Legacy accepts SETs of transmitters
	// following earlier drafts, which put the subject into the event payload.
	SubjectCompatibility ssf.SubjectCompatibilityMode
	// ClockSkew is how far in the future a SET may be issued according to the local clock. One
	// minute by default.
	ClockSkew time.Duration
	// Clock is the clock iat is checked against.
	Clock Clock
}

// DefaultVerifierOptions are the defaults: RS256, 2048 bit keys, typ required, strict subjects,
// one minute of skew.
func DefaultVerifierOptions() VerifierOptions {
	return VerifierOptions{
		AcceptedAlgorithms:   []jose.SignatureAlgorithm{jose.RS256},
		MinRSAKeySize:        2048,
		RequireTypeHeader:    true,
		SubjectCompatibility: ssf.Strict,
		ClockSkew:            time.Minute,
		Clock:                SystemClock,
	}
}

// JWTVerifier is a Verifier that verifies SET signatures against the transmitter's JWK Set and
// validates the claims required by RFC 8417 and the SSF profile (NimbusSsfSetVerifier in Java,
// JwtSsfSetVerifier in .NET and Rust).
//
// go-jose checks the signature only. Every claim rule is applied here, so that the error codes
// of RFC 8935 stay ours: a SET has no exp (RFC 8417, section 2.2), and a JWT library's claim
// validation would reject every SET.
type JWTVerifier struct {
	issuer  string
	keys    JWKSetSource
	options VerifierOptions
}

// NewJWTVerifier is a verifier for the SETs of one transmitter. It fails if
// options.AcceptedAlgorithms is empty or names an algorithm that is not asymmetric.
func NewJWTVerifier(issuer string, keys JWKSetSource, options VerifierOptions) (*JWTVerifier, error) {
	if len(options.AcceptedAlgorithms) == 0 {
		return nil, errors.New("AcceptedAlgorithms must not be empty")
	}
	for _, algorithm := range options.AcceptedAlgorithms {
		if _, ok := SupportedAlgorithm(string(algorithm)); !ok {
			return nil, errors.New("not an asymmetric signature algorithm: " + string(algorithm))
		}
	}
	if options.Clock == nil {
		options.Clock = SystemClock
	}
	return &JWTVerifier{issuer: issuer, keys: keys, options: options}, nil
}

// Issuer is the issuer every SET must be issued by.
func (v *JWTVerifier) Issuer() string { return v.issuer }

// Options say how SETs are verified.
func (v *JWTVerifier) Options() VerifierOptions { return v.options }

// Verify implements Verifier.
func (v *JWTVerifier) Verify(ctx context.Context, encodedSET string) (*ssf.EventToken, error) {
	encodedSET = strings.TrimSpace(encodedSET)
	if encodedSET == "" {
		return nil, Rejected(InvalidRequest, "The SET is empty")
	}
	parts := strings.Split(encodedSET, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil, Rejected(InvalidRequest, "The SET is not a JWS in compact serialization")
	}
	if parts[2] == "" {
		return nil, Rejected(InvalidRequest, "The SET is not a signed JWT")
	}
	header, err := decodeHeader(parts[0])
	if err != nil {
		return nil, Rejected(InvalidRequest, "The SET is not a signed JWT: %v", err)
	}
	// RFC 8417, section 2.3
	if v.options.RequireTypeHeader && !strings.EqualFold(ssf.StringMember(header, "typ"), SecEventJWTType) {
		return nil, Rejected(InvalidRequest, "The SET must be typed with a typ header of %s", SecEventJWTType)
	}
	algorithm, supported := SupportedAlgorithm(ssf.StringMember(header, "alg"))
	if !supported || !contains(v.options.AcceptedAlgorithms, algorithm) {
		return nil, Rejected(InvalidKey, "The SET is signed with the algorithm %q, which is not accepted", ssf.StringMember(header, "alg"))
	}
	key, err := v.selectKey(ctx, ssf.StringMember(header, "kid"), algorithm)
	if err != nil {
		return nil, err
	}
	jws, err := jose.ParseSignedCompact(encodedSET, []jose.SignatureAlgorithm{algorithm})
	if err != nil {
		return nil, Rejected(InvalidRequest, "The SET is not a signed JWT: %v", err)
	}
	payload, err := jws.Verify(key.Key)
	if err != nil {
		return nil, Rejected(InvalidKey, "The signature of the SET is invalid")
	}
	claims, err := ssf.ParseClaims(payload)
	if err != nil {
		return nil, Rejected(InvalidRequest, "The payload of the SET is not a JSON object: %v", err)
	}
	return v.validateClaims(claims)
}

func (v *JWTVerifier) expectedAudiences() ([]string, error) {
	if v.options.ExpectedAudiencesProvider != nil {
		return v.options.ExpectedAudiencesProvider()
	}
	return v.options.ExpectedAudiences, nil
}

func (v *JWTVerifier) selectKey(ctx context.Context, kid string, algorithm jose.SignatureAlgorithm) (*jose.JSONWebKey, error) {
	keys, err := v.keys.JWKSet(ctx, false)
	if err != nil {
		return nil, err
	}
	if key := v.matching(keys, kid, algorithm); key != nil {
		return key, nil
	}
	if kid != "" {
		// the transmitter may have rotated its keys since the JWK Set was fetched
		keys, err = v.keys.JWKSet(ctx, true)
		if err != nil {
			return nil, err
		}
		if key := v.matching(keys, kid, algorithm); key != nil {
			return key, nil
		}
	}
	return nil, Rejected(InvalidKey, "The SET is signed with an unknown key")
}

func (v *JWTVerifier) matching(keys *jose.JSONWebKeySet, kid string, algorithm jose.SignatureAlgorithm) *jose.JSONWebKey {
	var candidates []*jose.JSONWebKey
	for i := range keys.Keys {
		key := &keys.Keys[i]
		if kid != "" && key.KeyID != kid {
			continue
		}
		if key.Use == "enc" {
			continue
		}
		if key.Algorithm != "" && key.Algorithm != string(algorithm) {
			continue
		}
		if !keyTypeMatches(key, algorithm) {
			continue
		}
		if bits := RSAKeyBits(key); v.options.MinRSAKeySize > 0 && bits > 0 && bits < v.options.MinRSAKeySize {
			continue
		}
		candidates = append(candidates, key)
	}
	// without a kid only an unambiguous JWK Set is usable
	switch {
	case kid != "" && len(candidates) > 0:
		return candidates[0]
	case kid == "" && len(candidates) == 1:
		return candidates[0]
	}
	return nil
}

func (v *JWTVerifier) validateClaims(claims ssf.Claims) (*ssf.EventToken, error) {
	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return nil, Rejected(InvalidIssuer, "The SET was not issued by the expected transmitter")
	}
	expected, err := v.expectedAudiences()
	if err != nil {
		return nil, err
	}
	if aud, present := claims["aud"]; present && !wellFormedAudience(aud) {
		return nil, Rejected(InvalidRequest, "The aud claim of the SET is malformed")
	}
	audiences := ssf.Audiences(claims["aud"])
	if len(expected) > 0 && !anyIn(audiences, expected) {
		return nil, Rejected(InvalidAudience, "The SET is not addressed to this receiver")
	}
	if ssf.StringMember(claims, "jti") == "" {
		return nil, Rejected(InvalidRequest, "The SET has no jti claim")
	}
	issuedAt, ok := ssf.Int64(claims["iat"])
	if !ok {
		return nil, Rejected(InvalidRequest, "The SET has no iat claim")
	}
	if issuedAt > v.options.Clock().Unix()+int64(v.options.ClockSkew/time.Second) {
		return nil, Rejected(InvalidRequest, "The SET was issued in the future")
	}
	if len(ssf.ObjectMember(claims, "events")) == 0 {
		return nil, Rejected(InvalidRequest, "The SET has no events claim")
	}
	if v.options.SubjectCompatibility == ssf.Strict && len(ssf.ObjectMember(claims, "sub_id")) == 0 {
		return nil, Rejected(InvalidRequest, "The SET has no top-level sub_id claim, which SSF 1.0 requires "+
			"(the subject compatibility mode legacy accepts SETs of transmitters that put the subject into the event)")
	}
	token := ssf.EventTokenFromClaims(claims)
	if token == nil {
		return nil, Rejected(InvalidRequest, "The SET lacks jti, iss, iat or events")
	}
	return token, nil
}

// RSAKeyBits is the size of an RSA key in bits, 0 for other key types.
func RSAKeyBits(key *jose.JSONWebKey) int {
	if public, ok := key.Key.(*rsa.PublicKey); ok {
		return public.N.BitLen()
	}
	return 0
}

func keyTypeMatches(key *jose.JSONWebKey, algorithm jose.SignatureAlgorithm) bool {
	switch key.Key.(type) {
	case *rsa.PublicKey:
		return strings.HasPrefix(string(algorithm), "RS") || strings.HasPrefix(string(algorithm), "PS")
	case *ecdsa.PublicKey:
		return strings.HasPrefix(string(algorithm), "ES")
	case ed25519.PublicKey:
		return algorithm == jose.EdDSA
	}
	return false
}

func wellFormedAudience(aud any) bool {
	switch v := aud.(type) {
	case string:
		return true
	case []any:
		for _, element := range v {
			if _, ok := element.(string); !ok {
				return false
			}
		}
		return true
	}
	return false
}

func anyIn(values, set []string) bool {
	for _, value := range values {
		for _, candidate := range set {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

func contains(algorithms []jose.SignatureAlgorithm, algorithm jose.SignatureAlgorithm) bool {
	for _, candidate := range algorithms {
		if candidate == algorithm {
			return true
		}
	}
	return false
}

func decodeHeader(segment string) (ssf.Claims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, err
	}
	return ssf.ParseClaims(raw)
}

// UnverifiedPayload reads the claims of a SET before it is verified, to decide how to verify it.
// Nothing read this way is trusted. nil if the SET cannot be parsed.
func UnverifiedPayload(encodedSET string) ssf.Claims {
	parts := strings.Split(strings.TrimSpace(encodedSET), ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	claims, err := ssf.ParseClaims(raw)
	if err != nil {
		return nil
	}
	return claims
}

// UnverifiedIssuer reads the iss claim of a SET before it is verified, to decide how to verify
// it. Nothing read this way is trusted. "" if the SET cannot be parsed or has no issuer.
func UnverifiedIssuer(encodedSET string) string {
	return ssf.StringMember(UnverifiedPayload(encodedSET), "iss")
}

// IssuerRoutingVerifier verifies SETs of several transmitters: the iss claim of a SET selects the
// Verifier of that transmitter, which then verifies the SET, including its issuer. A SET of an
// unknown issuer is rejected.
type IssuerRoutingVerifier struct {
	verifiers map[string]Verifier
}

// NewIssuerRoutingVerifier routes by issuer.
func NewIssuerRoutingVerifier(verifiers map[string]Verifier) *IssuerRoutingVerifier {
	return &IssuerRoutingVerifier{verifiers: verifiers}
}

// Verify implements Verifier.
func (v *IssuerRoutingVerifier) Verify(ctx context.Context, encodedSET string) (*ssf.EventToken, error) {
	issuer := UnverifiedIssuer(encodedSET)
	verifier, ok := v.verifiers[issuer]
	if !ok {
		return nil, Rejected(InvalidIssuer, "The SET was not issued by a known transmitter")
	}
	return verifier.Verify(ctx, encodedSET)
}
