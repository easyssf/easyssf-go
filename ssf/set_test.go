package ssf

import (
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

func TestBuildsSETWithTheRequiredClaimsAndOneEvent(t *testing.T) {
	issuedAt := time.Unix(1700000000, 0)
	claims, err := NewSET("https://idp.example").JTI("set-1").IssuedAt(issuedAt).Audience("https://app.example").
		Subject(Email("alice@example.com")).Txn("txn-1").
		Event("CaepSessionRevoked", Claims{"event_timestamp": int64(1700000000)}).Claims()
	if err != nil {
		t.Fatal(err)
	}
	token := EventTokenFromClaims(claims)
	if token == nil || token.JTI() != "set-1" || token.Issuer() != "https://idp.example" || token.IssuedAtSeconds() != 1700000000 || token.Txn() != "txn-1" {
		t.Fatalf("%v", claims)
	}
	if aud := token.Audience(); len(aud) != 1 || aud[0] != "https://app.example" {
		t.Fatalf("%v", aud)
	}
	if _, single := claims["aud"].(string); !single {
		t.Fatal("one audience is a string")
	}
	if token.Events()[eventtypes.CaepSessionRevoked] == nil {
		t.Fatalf("alias resolved: %v", token.Events())
	}
	if SubjectFrom(token.SubjectID()).Email() != "alice@example.com" {
		t.Fatalf("%v", token.SubjectID())
	}
}

func TestSeveralAudiencesAreAnArrayAndTheJTIIsRandom(t *testing.T) {
	first := NewSET("https://idp.example").Audience("a", "b").Event(eventtypes.RiscAccountDisabled, nil).MustClaims()
	second := NewSET("https://idp.example").Event(eventtypes.RiscAccountDisabled, nil).MustClaims()
	if aud, _ := first["aud"].([]string); len(aud) != 2 {
		t.Fatalf("%v", first["aud"])
	}
	if first["jti"] == second["jti"] || len(first["jti"].(string)) != 32 {
		t.Fatalf("%v %v", first["jti"], second["jti"])
	}
	if payload, _ := first["events"].(Claims)[eventtypes.RiscAccountDisabled].(Claims); payload == nil {
		t.Fatal("a nil payload becomes an empty object")
	}
}

func TestRefusesSETWithoutEventOrIssuer(t *testing.T) {
	if _, err := NewSET("https://idp.example").Claims(); err == nil {
		t.Fatal("no event")
	}
	if _, err := NewSET("").Event("CaepSessionRevoked", nil).Claims(); err == nil {
		t.Fatal("no issuer")
	}
	if _, err := NewSET("https://idp.example").Event("", nil).Claims(); err == nil {
		t.Fatal("empty event type")
	}
}

func TestClaimsOfTheBuilderAreACopy(t *testing.T) {
	builder := NewSET("https://idp.example").Event("CaepSessionRevoked", nil)
	claims := builder.MustClaims()
	claims["iss"] = "changed"
	if builder.MustClaims()["iss"] != "https://idp.example" {
		t.Fatal("the builder keeps its claims")
	}
}
