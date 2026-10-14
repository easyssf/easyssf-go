package signing_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/signing"
)

func claims() ssf.Claims {
	return ssf.NewSET("https://idp.example").Event("CaepSessionRevoked", nil).MustClaims()
}

func verify(t *testing.T, signer *signing.Signer, encoded string) (map[string]any, jose.Header) {
	t.Helper()
	jws, err := jose.ParseSigned(encoded, []jose.SignatureAlgorithm{signer.Algorithm()})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jws.Verify(signer.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded, jws.Signatures[0].Header
}

func TestSignsSETWithRSAKeyTypedSecEventJWTAndKeyID(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, err := signing.NewSigner(key, "", "rsa-1")
	if err != nil {
		t.Fatal(err)
	}
	if signer.Algorithm() != jose.RS256 {
		t.Fatal(signer.Algorithm())
	}
	encoded, err := signer.Sign(claims())
	if err != nil {
		t.Fatal(err)
	}
	decoded, header := verify(t, signer, encoded)
	if header.KeyID != "rsa-1" || header.ExtraHeaders[jose.HeaderType] != signing.SecEventJWTType {
		t.Fatalf("%v", header)
	}
	if decoded["iss"] != "https://idp.example" {
		t.Fatalf("%v", decoded)
	}
}

func TestSignsWithECDSAAndEd25519Keys(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecSigner, err := signing.NewSigner(ec, "", "ec-1")
	if err != nil || ecSigner.Algorithm() != jose.ES256 {
		t.Fatalf("%v %v", ecSigner, err)
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	edSigner, err := signing.NewSigner(ed, "", "ed-1")
	if err != nil || edSigner.Algorithm() != jose.EdDSA {
		t.Fatalf("%v %v", edSigner, err)
	}
	for _, signer := range []*signing.Signer{ecSigner, edSigner} {
		encoded, err := signer.SignTyped(signing.JWTType, ssf.Claims{"sub": "alice"})
		if err != nil {
			t.Fatal(err)
		}
		if decoded, header := verify(t, signer, encoded); decoded["sub"] != "alice" || header.ExtraHeaders[jose.HeaderType] != "JWT" {
			t.Fatalf("%v %v", decoded, header)
		}
	}
	if set := signing.JWKSet(ecSigner, edSigner); len(set.Keys) != 2 || set.Keys[0].KeyID != "ec-1" || set.Keys[1].Algorithm != "EdDSA" {
		t.Fatalf("%v", set)
	}
}

func TestRefusesWeakKeysMismatchedAlgorithmsAndMissingKeyID(t *testing.T) {
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := signing.NewSigner(weak, "", "weak"); err == nil {
		t.Fatal("1024 bit RSA")
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := signing.NewSigner(ec, jose.RS256, "ec"); err == nil {
		t.Fatal("RS256 with an EC key")
	}
	if _, err := signing.NewSigner(ec, "", ""); err == nil {
		t.Fatal("no kid")
	}
	if _, err := signing.NewSigner("not a key", "", "x"); err == nil {
		t.Fatal("unsupported key")
	}
}
