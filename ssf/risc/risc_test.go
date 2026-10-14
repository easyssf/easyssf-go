package risc_test

import (
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
	"github.com/easyssf/easyssf-go/ssf/risc"
)

func token(events ssf.Claims) *ssf.EventToken {
	return ssf.EventTokenFromClaims(ssf.Claims{"jti": "1", "iss": "https://t.example", "iat": float64(1700000000), "events": events})
}

func TestEveryRiscEventTypeHasAKindAndAnAlias(t *testing.T) {
	for _, known := range risc.Known {
		if kind, ok := risc.KindOf(known.EventType); !ok || kind != known.Kind || known.Kind.EventType() != known.EventType {
			t.Fatal(known.EventType)
		}
		if eventtypes.AliasOf(known.EventType) == known.EventType {
			t.Fatalf("%s has no alias", known.EventType)
		}
	}
}

func TestUnknownEventTypeInTheRiscNamespaceIsOtherAndAnythingElseIsNotRisc(t *testing.T) {
	if kind, ok := risc.KindOf("https://schemas.openid.net/secevent/risc/event-type/future"); !ok || kind != risc.Other {
		t.Fatal("future")
	}
	if _, ok := risc.KindOf("CaepSessionRevoked"); ok {
		t.Fatal("caep")
	}
}

func TestOptInAndOptOutEventsReportTheParticipation(t *testing.T) {
	for _, kind := range []risc.Kind{risc.OptIn, risc.OptOutInitiated, risc.OptOutCancelled, risc.OptOutEffective} {
		if !kind.IsOptOutState() {
			t.Fatal(kind)
		}
	}
	if risc.AccountDisabled.IsOptOutState() {
		t.Fatal("disabled")
	}
}

func TestAttributes(t *testing.T) {
	if risc.Of("RiscAccountDisabled", ssf.Claims{"reason": "hijacking"}).Reason() != "hijacking" || risc.Of("RiscAccountDisabled", nil).Reason() != "" {
		t.Fatal("reason")
	}
	if risc.Of("RiscIdentifierChanged", ssf.Claims{"new-value": "new@example.com"}).NewValue() != "new@example.com" {
		t.Fatal("new-value")
	}
	compromise := risc.Of("RiscCredentialCompromise", ssf.Claims{"credential_type": "password", "event_timestamp": float64(1700000000),
		"reason_admin": map[string]any{"en": "leak"}, "reason_user": "Change it"})
	ts, ok := compromise.EventTimestamp()
	if compromise.CredentialType() != "password" || !ok || !ts.Equal(time.Unix(1700000000, 0)) || compromise.ReasonAdmin() != `{"en":"leak"}` || compromise.ReasonUser() != "Change it" {
		t.Fatal("compromise")
	}
	purged := risc.Of("RiscAccountPurged", nil)
	if _, ok := purged.EventTimestamp(); len(purged.Payload()) != 0 || purged.Reason() != "" || ok {
		t.Fatal("purged")
	}
}

func TestFindsAllRiscEventsOfASetInOrderAndIgnoresOthers(t *testing.T) {
	events := risc.InToken(token(ssf.Claims{eventtypes.CaepSessionRevoked: ssf.Claims{}, eventtypes.RiscAccountDisabled: ssf.Claims{"reason": "hijacking"}, eventtypes.RiscSessionsRevoked: ssf.Claims{}}))
	if len(events) != 2 || events[0].Kind() != risc.AccountDisabled || events[1].Kind() != risc.SessionsRevoked {
		t.Fatalf("%v", events)
	}
	if risc.Of("RiscAccountEnabled", nil).EventType() != eventtypes.RiscAccountEnabled || risc.Of("CaepSessionRevoked", nil) != nil {
		t.Fatal("of")
	}
}
