package eventtypes

import (
	"strings"
	"testing"
)

func TestResolvesBuiltInAliasesAndPassesURIsThrough(t *testing.T) {
	if Resolve("CaepSessionRevoked") != CaepSessionRevoked || Resolve(CaepSessionRevoked) != CaepSessionRevoked {
		t.Fatal("alias and URI resolve to the URI")
	}
	if Resolve("https://events.acme.example/login") != "https://events.acme.example/login" {
		t.Fatal("unknown URIs pass through")
	}
	if AliasOf(RiscAccountDisabled) != "RiscAccountDisabled" || AliasOf("https://events.acme.example/unaliased") != "https://events.acme.example/unaliased" {
		t.Fatal("alias_of")
	}
	if !IsAlias("CaepCredentialChange") || IsAlias("Nope") {
		t.Fatal("is_alias")
	}
	if !IsCaepEvent("CaepSessionRevoked") || !IsCaepEvent("https://schemas.openid.net/secevent/caep/event-type/future") || IsCaepEvent("RiscAccountDisabled") {
		t.Fatal("is_caep_event")
	}
	if !IsRiscEvent(RiscSessionsRevoked) || !IsSSFEvent("SsfStreamVerification") {
		t.Fatal("families")
	}
}

func TestScimEventTypesAreURNsWithAliases(t *testing.T) {
	if Resolve("ScimProvCreateFull") != "urn:ietf:params:scim:event:prov:create:full" || AliasOf(ScimProvDeactivate) != "ScimProvDeactivate" || !IsScimEvent("ScimFeedAdd") {
		t.Fatal("scim")
	}
	scim := 0
	for _, pair := range Aliases() {
		if strings.HasPrefix(pair[0], "Scim") {
			scim++
		}
	}
	if scim != 12 {
		t.Fatalf("%d scim aliases", scim)
	}
}

func TestRegisteredAliasResolvesLikeABuiltInOne(t *testing.T) {
	if err := RegisterAlias("AcmeLoginTest", "https://events.acme.example/login"); err != nil {
		t.Fatal(err)
	}
	if Resolve("AcmeLoginTest") != "https://events.acme.example/login" || AliasOf("https://events.acme.example/login") != "AcmeLoginTest" {
		t.Fatal("registered alias")
	}
	// registering the same mapping again does nothing
	if err := RegisterAlias("AcmeLoginTest", "https://events.acme.example/login"); err != nil {
		t.Fatal(err)
	}
}

func TestAliasCannotBeMappedToAnotherURI(t *testing.T) {
	err := RegisterAlias("CaepSessionRevoked", "https://events.acme.example/other")
	if err == nil || !strings.Contains(err.Error(), "already mapped") {
		t.Fatalf("expected conflict, got %v", err)
	}
	if err := RegisterAlias("AcmeOnce", "https://events.acme.example/once"); err != nil {
		t.Fatal(err)
	}
	if RegisterAlias("AcmeOnce", "https://events.acme.example/twice") == nil {
		t.Fatal("expected conflict")
	}
}

func TestURIMayHaveSeveralAliasesAndKeepsTheFirstForDisplay(t *testing.T) {
	_ = RegisterAlias("AcmeFirst", "https://events.acme.example/several")
	_ = RegisterAlias("AcmeSecond", "https://events.acme.example/several")
	if Resolve("AcmeSecond") != "https://events.acme.example/several" || AliasOf("https://events.acme.example/several") != "AcmeFirst" {
		t.Fatal("several aliases")
	}
}

func TestRejectsMalformedAliasesAndURIs(t *testing.T) {
	for _, tc := range [][2]string{
		{"", "https://x.example/e"}, {"has:colon", "https://x.example/e"}, {"has/slash", "https://x.example/e"},
		{" padded", "https://x.example/e"}, {"Ok", "not-a-uri"}, {"Ok", ""},
	} {
		if RegisterAlias(tc[0], tc[1]) == nil {
			t.Errorf("accepted %q -> %q", tc[0], tc[1])
		}
	}
}
