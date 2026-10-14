package caep_test

import (
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/caep"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

func token(events ssf.Claims) *ssf.EventToken {
	return ssf.EventTokenFromClaims(ssf.Claims{"jti": "1", "iss": "https://t.example", "iat": float64(1700000000), "events": events})
}

func TestEveryCaepEventTypeHasAKindAndAnAlias(t *testing.T) {
	for _, known := range caep.Known {
		if kind, ok := caep.KindOf(known.EventType); !ok || kind != known.Kind || known.Kind.EventType() != known.EventType {
			t.Fatal(known.EventType)
		}
		alias := eventtypes.AliasOf(known.EventType)
		if alias == known.EventType {
			t.Fatalf("%s has no alias", known.EventType)
		}
		if kind, _ := caep.KindOf(alias); kind != known.Kind {
			t.Fatal(alias)
		}
	}
	if caep.Other.EventType() != "" {
		t.Fatal("other")
	}
}

func TestUnknownEventTypeInTheCaepNamespaceIsOtherAndAnythingElseIsNotCaep(t *testing.T) {
	if kind, ok := caep.KindOf("https://schemas.openid.net/secevent/caep/event-type/future"); !ok || kind != caep.Other {
		t.Fatal("future")
	}
	for _, notCaep := range []string{"RiscAccountDisabled", "https://events.acme.example/login"} {
		if _, ok := caep.KindOf(notCaep); ok {
			t.Fatal(notCaep)
		}
	}
}

func TestCommonClaimsOfSection2AreTypedForEveryKind(t *testing.T) {
	payload := ssf.Claims{"event_timestamp": float64(1700000000), "initiating_entity": "admin",
		"reason_admin": map[string]any{"en": "Landspeed violation", "de": "Zu schnell"}, "reason_user": map[string]any{"en": "You moved too fast"}}
	for _, known := range caep.Known {
		event := caep.Of(known.EventType, payload)
		ts, ok := event.EventTimestamp()
		if event.Kind() != known.Kind || !ok || !ts.Equal(time.Unix(1700000000, 0)) || event.InitiatingEntity() != "admin" ||
			event.ReasonAdmin()["de"] != "Zu schnell" || event.ReasonUser()["en"] != "You moved too fast" {
			t.Fatal(known.EventType)
		}
	}
}

func TestAbsentCommonClaimsAreEmptyAndMillisecondsAreTolerated(t *testing.T) {
	event := caep.Of("CaepSessionRevoked", nil)
	if _, ok := event.EventTimestamp(); ok || event.InitiatingEntity() != "" || len(event.ReasonAdmin()) != 0 || len(event.AMR()) != 0 || event.Claims() != nil {
		t.Fatal("absent")
	}
	millis := caep.Of("CaepSessionRevoked", ssf.Claims{"event_timestamp": float64(1700000000123)})
	if ts, ok := millis.EventTimestamp(); !ok || !ts.Equal(time.Unix(1700000000, 0)) {
		t.Fatal("millis")
	}
}

func TestPlainStringReasonIsKeptUnderTheEmptyLanguageTag(t *testing.T) {
	event := caep.Of("CaepSessionRevoked", ssf.Claims{"reason_admin": "Policy", "reason_user": float64(42)})
	if event.ReasonAdmin()[""] != "Policy" || event.ReasonUser()[""] != "42" {
		t.Fatalf("%v %v", event.ReasonAdmin(), event.ReasonUser())
	}
}

func TestEventSpecificClaims(t *testing.T) {
	claims := caep.Of("CaepTokenClaimsChange", ssf.Claims{"claims": map[string]any{"role": "ro", "level": float64(2)}})
	if claims.Claims()["role"] != "ro" || claims.Claims()["level"] != float64(2) {
		t.Fatal("claims")
	}
	credential := caep.Of("CaepCredentialChange", ssf.Claims{"credential_type": "fido2-roaming", "change_type": "create", "friendly_name": "Yubikey",
		"x509_issuer": "CN=CA", "x509_serial": "1234", "fido2_aaguid": "aaguid"})
	if credential.CredentialType() != "fido2-roaming" || credential.ChangeType() != "create" || credential.FriendlyName() != "Yubikey" ||
		credential.X509Issuer() != "CN=CA" || credential.X509Serial() != "1234" || credential.FIDO2AAGUID() != "aaguid" {
		t.Fatal("credential")
	}
	assurance := caep.Of("CaepAssuranceLevelChange", ssf.Claims{"namespace": "NIST-AAL", "current_level": "nist-aal1", "previous_level": "nist-aal2", "change_direction": "decrease"})
	if assurance.Namespace() != "NIST-AAL" || assurance.CurrentLevel() != "nist-aal1" || assurance.PreviousLevel() != "nist-aal2" || assurance.ChangeDirection() != "decrease" {
		t.Fatal("assurance")
	}
	device := caep.Of("CaepDeviceComplianceChange", ssf.Claims{"current_status": "not-compliant", "previous_status": "compliant"})
	if device.CurrentStatus() != "not-compliant" || device.PreviousStatus() != "compliant" {
		t.Fatal("device")
	}
	session := caep.Of("CaepSessionEstablished", ssf.Claims{"fp_ua": "abc", "acr": "urn:acr", "amr": []any{"pwd", "otp", float64(3)}, "ext_id": "saml-1"})
	if session.FPUA() != "abc" || session.ACR() != "urn:acr" || len(session.AMR()) != 2 || session.AMR()[1] != "otp" || session.ExtID() != "saml-1" {
		t.Fatal("session")
	}
	if caep.Of("CaepSessionPresented", nil).Kind() != caep.SessionPresented {
		t.Fatal("presented")
	}
	risk := caep.Of("CaepRiskLevelChange", ssf.Claims{"principal": "USER", "current_level": "HIGH", "previous_level": "LOW", "risk_reason": "Credential stuffing"})
	if risk.Principal() != "USER" || risk.CurrentLevel() != "HIGH" || risk.PreviousLevel() != "LOW" || risk.RiskReason() != "Credential stuffing" {
		t.Fatal("risk")
	}
}

func TestFindsAllCaepEventsOfASetInOrderAndIgnoresOthers(t *testing.T) {
	set := token(ssf.Claims{
		eventtypes.CaepSessionRevoked:                                ssf.Claims{"event_timestamp": float64(1)},
		eventtypes.RiscAccountDisabled:                               ssf.Claims{},
		"https://schemas.openid.net/secevent/caep/event-type/future": "not an object",
		eventtypes.CaepCredentialChange:                              ssf.Claims{"change_type": "revoke"},
	})
	events := caep.InToken(set)
	if len(events) != 3 || events[0].Kind() != caep.CredentialChange || events[0].ChangeType() != "revoke" ||
		events[1].Kind() != caep.Other || len(events[1].Payload()) != 0 || events[2].Kind() != caep.SessionRevoked {
		t.Fatalf("%v", events)
	}
	if len(caep.InToken(token(ssf.Claims{eventtypes.RiscAccountDisabled: ssf.Claims{}}))) != 0 {
		t.Fatal("none")
	}
}

func TestOfResolvesAliasesAndRejectsOtherEventTypes(t *testing.T) {
	if caep.Of("CaepSessionRevoked", nil).EventType() != eventtypes.CaepSessionRevoked {
		t.Fatal("alias")
	}
	if caep.Of("RiscAccountDisabled", nil) != nil || caep.Of("https://events.acme.example/login", nil) != nil {
		t.Fatal("not caep")
	}
}
