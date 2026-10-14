// Package signing signs SETs and other JWTs: the transmitter side of the SET, for the test
// transmitter, the examples and anyone who sends SETs, over go-jose. The receiver does not need
// it.
package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/easyssf/easyssf-go/ssf"
)

// The typ headers a Signer sets.
const (
	// SecEventJWTType is the typ of a SET (RFC 8417, section 2.3): "secevent+jwt".
	SecEventJWTType = "secevent+jwt"
	// JWTType is the typ of a plain JWT (RFC 7519, section 5.1).
	JWTType = "JWT"
)

// Signer signs claims with one private key under one algorithm and key id. Safe for concurrent
// use.
type Signer struct {
	key       crypto.PrivateKey
	public    crypto.PublicKey
	algorithm jose.SignatureAlgorithm
	keyID     string
}

// NewSigner makes a signer for the key: an *rsa.PrivateKey, *ecdsa.PrivateKey or
// ed25519.PrivateKey. algorithm is a signature algorithm of RFC 7518 that fits the key
// (RS256, PS256, ES256, EdDSA, ...); "" picks RS256 for RSA, the ES algorithm of the curve for
// ECDSA, EdDSA for Ed25519. keyID is the kid the SETs carry, so that the receiver finds the key
// in the JWK Set; it must not be empty. An RSA key below 2048 bits is refused, as RFC 7518,
// section 3.3 demands: the receivers reject its SETs anyway.
func NewSigner(key crypto.PrivateKey, algorithm jose.SignatureAlgorithm, keyID string) (*Signer, error) {
	if keyID == "" {
		return nil, errors.New("signing: the key id must not be empty")
	}
	var public crypto.PublicKey
	var fallback jose.SignatureAlgorithm
	var allowed []jose.SignatureAlgorithm
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("signing: the RSA key has %d bits, 2048 are the minimum", k.N.BitLen())
		}
		public, fallback = &k.PublicKey, jose.RS256
		allowed = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512}
	case *ecdsa.PrivateKey:
		public = &k.PublicKey
		switch k.Curve {
		case elliptic.P256():
			fallback = jose.ES256
		case elliptic.P384():
			fallback = jose.ES384
		case elliptic.P521():
			fallback = jose.ES512
		default:
			return nil, fmt.Errorf("signing: unsupported curve %s", k.Curve.Params().Name)
		}
		allowed = []jose.SignatureAlgorithm{fallback}
	case ed25519.PrivateKey:
		public, fallback = k.Public(), jose.EdDSA
		allowed = []jose.SignatureAlgorithm{jose.EdDSA}
	default:
		return nil, fmt.Errorf("signing: unsupported key type %T", key)
	}
	if algorithm == "" {
		algorithm = fallback
	}
	fits := false
	for _, candidate := range allowed {
		fits = fits || candidate == algorithm
	}
	if !fits {
		return nil, fmt.Errorf("signing: algorithm %s does not fit the %T", algorithm, key)
	}
	return &Signer{key: key, public: public, algorithm: algorithm, keyID: keyID}, nil
}

// Algorithm is the signature algorithm.
func (s *Signer) Algorithm() jose.SignatureAlgorithm { return s.algorithm }

// KeyID is the kid the signed tokens carry.
func (s *Signer) KeyID() string { return s.keyID }

// PublicJWK is the public key as a JWK with the kid, alg and use the receiver matches on.
func (s *Signer) PublicJWK() jose.JSONWebKey {
	return jose.JSONWebKey{Key: s.public, KeyID: s.keyID, Algorithm: string(s.algorithm), Use: "sig"}
}

// Sign signs the claims as a SET: a JWS in compact serialization with typ secevent+jwt (RFC
// 8417, section 2.3) and the kid.
func (s *Signer) Sign(claims ssf.Claims) (string, error) {
	return s.SignTyped(SecEventJWTType, claims)
}

// SignTyped signs the claims as a JWT with the given typ header, left out if "".
func (s *Signer) SignTyped(typ string, claims ssf.Claims) (string, error) {
	options := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), s.keyID)
	if typ != "" {
		options = options.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.algorithm, Key: s.key}, options)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return compact, nil
}

// JWKSet is a JWK Set of the public keys of the signers, to publish at the jwks_uri.
func JWKSet(signers ...*Signer) jose.JSONWebKeySet {
	set := jose.JSONWebKeySet{}
	for _, signer := range signers {
		set.Keys = append(set.Keys, signer.PublicJWK())
	}
	return set
}
