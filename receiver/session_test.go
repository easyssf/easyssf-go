package receiver_test

// SsfSessionTerminationEventHandlerTests and SsfSubjectClaimsMatcherTests of the Java library.

import (
	"context"
	"sync"
	"testing"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssftest"
)

// sessions are the claims of logged-in users that a terminator ends when the subject matches.
type sessions struct {
	mu         sync.Mutex
	loggedIn   []ssf.Claims
	terminated []*ssf.Subject
}

func (s *sessions) TerminateSessions(_ context.Context, subject *ssf.Subject) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminated = append(s.terminated, subject)
	before := len(s.loggedIn)
	kept := s.loggedIn[:0]
	for _, claims := range s.loggedIn {
		if !receiver.SubjectMatches(subject, claims, "") {
			kept = append(kept, claims)
		}
	}
	s.loggedIn = kept
	return before - len(kept), nil
}

func claims(iss, sub, sid string) ssf.Claims {
	c := ssf.Claims{}
	if iss != "" {
		c["iss"] = iss
	}
	if sub != "" {
		c["sub"] = sub
	}
	if sid != "" {
		c["sid"] = sid
	}
	return c
}

func subject(identifier ssf.Claims) *ssf.Subject { return ssf.SubjectFrom(identifier) }

func loginAndHandle(t *testing.T, transmitter *ssftest.TestTransmitter, s *sessions, eventType string, subject ssf.Claims) int {
	t.Helper()
	s.mu.Lock()
	s.terminated = nil
	s.loggedIn = []ssf.Claims{claims(idp, "alice", "s1"), claims(idp, "alice", "s2"), claims(idp, "bob", "s3")}
	s.mu.Unlock()
	p := processor(t, transmitter, receiver.NewSessionTerminationHandler(s, nil, nil, nil))
	if _, err := p.Process(ctx, transmitter.Set(eventType, subject), ssf.Push); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return 3 - len(s.loggedIn)
}

func TestSessionEventTerminatesTheSessionNamed(t *testing.T) {
	transmitter := ssftest.New()
	s := &sessions{}
	if terminated := loginAndHandle(t, transmitter, s, "CaepSessionRevoked", ssf.Complex(ssf.IssSub(idp, "alice"), ssf.Opaque("s1"))); terminated != 1 || s.terminated[0].SessionID() != "s1" {
		t.Fatalf("%d", terminated)
	}
	// naming only the user ends all sessions of the user
	if terminated := loginAndHandle(t, transmitter, s, "CaepSessionRevoked", ssf.IssSub(idp, "alice")); terminated != 2 {
		t.Fatalf("%d", terminated)
	}
}

func TestUserEventTerminatesAllSessionsOfTheUser(t *testing.T) {
	transmitter := ssftest.New()
	s := &sessions{}
	if terminated := loginAndHandle(t, transmitter, s, "CaepCredentialChange", ssf.Complex(ssf.IssSub(idp, "alice"), ssf.Opaque("s1"))); terminated != 2 || s.terminated[0].SessionID() != "" {
		t.Fatalf("the session of the event is ignored, the user is widened: %d", terminated)
	}
}

func TestScimDeactivateAndDeleteTerminateTheSessionsOfTheResource(t *testing.T) {
	transmitter := ssftest.New()
	s := &sessions{loggedIn: []ssf.Claims{claims(idp, "ext-alice", "s1")}}
	handler := receiver.NewSessionTerminationHandler(s, []string{"CaepSessionRevoked"}, []string{"ScimProvDeactivate", "ScimProvDelete"}, nil)
	p := processor(t, transmitter, handler)
	if _, err := p.Process(ctx, transmitter.Set("ScimProvDeactivate", ssf.SCIM("/Users/42", "ext-alice")), ssf.Push); err != nil {
		t.Fatal(err)
	}
	if len(s.loggedIn) != 0 {
		t.Fatal("terminated")
	}
}

func TestEventWithoutSubjectTerminatesNothing(t *testing.T) {
	transmitter := ssftest.New()
	s := &sessions{loggedIn: []ssf.Claims{claims(idp, "alice", "s1")}}
	p := processor(t, transmitter, receiver.NewSessionTerminationHandler(s, nil, nil, nil))
	// a subject without a format resolves to nothing
	if _, err := p.Process(ctx, transmitter.Set("CaepSessionRevoked", ssf.Claims{"sub": "alice"}), ssf.Push); err != nil {
		t.Fatal(err)
	}
	if len(s.terminated) != 0 || len(s.loggedIn) != 1 {
		t.Fatal("nothing terminated")
	}
}

// SsfSubjectClaimsMatcherTests

func matches(subject *ssf.Subject, claims ssf.Claims) bool {
	return receiver.SubjectMatches(subject, claims, "")
}

func TestSessionSubjectMatchesThatSessionOnly(t *testing.T) {
	s := subject(ssf.Complex(ssf.IssSub(idp, "alice"), ssf.Opaque("s1")))
	if !matches(s, claims(idp, "alice", "s1")) || matches(s, claims(idp, "alice", "s2")) || matches(s, claims(idp, "alice", "")) {
		t.Fatal("session")
	}
	// the user is not compared when a session is named
	if !matches(s, claims(idp, "bob", "s1")) {
		t.Fatal("user not compared")
	}
}

func TestSessionSubjectMatchesOnlyAtTheIssuerOfItsUser(t *testing.T) {
	s := subject(ssf.Complex(ssf.IssSub(idp, "alice"), ssf.Opaque("s1")))
	if matches(s, claims("https://other.example", "", "s1")) || matches(s, claims("", "", "s1")) {
		t.Fatal("issuer")
	}
	// a session without an issuer matches any
	if !matches(subject(ssf.Complex(nil, ssf.Opaque("s1"))), claims("", "", "s1")) {
		t.Fatal("no issuer")
	}
	// or the issuer of an iss_sub session identifier
	withIssuer := subject(ssf.Complex(nil, ssf.IssSub(idp, "s1")))
	if !matches(withIssuer, claims(idp, "", "s1")) || matches(withIssuer, claims("https://other.example", "", "s1")) {
		t.Fatal("session issuer")
	}
}

func TestUserSubjectMatchesSubjectOfThatIssuer(t *testing.T) {
	s := subject(ssf.IssSub(idp, "alice"))
	if !matches(s, claims(idp, "alice", "s1")) || !matches(s, claims(idp, "alice", "s2")) || matches(s, claims(idp, "bob", "")) {
		t.Fatal("user")
	}
	// iss_sub requires the issuer of the claims
	if matches(s, claims("", "alice", "")) || matches(s, claims("https://other.example", "alice", "")) {
		t.Fatal("issuer required")
	}
}

func TestEmailSubjectMatchesIgnoringCase(t *testing.T) {
	s := subject(ssf.Email("Alice@Example.com"))
	if !matches(s, ssf.Claims{"email": "alice@example.com"}) || matches(s, ssf.Claims{"email": "bob@example.com"}) || matches(s, ssf.Claims{"sub": "Alice@Example.com"}) {
		t.Fatal("email")
	}
}

func TestOpaqueSubjectMatchesSessionOrUser(t *testing.T) {
	s := subject(ssf.Opaque("xyz"))
	if !matches(s, ssf.Claims{"sid": "xyz"}) || !matches(s, ssf.Claims{"sub": "xyz"}) || matches(s, claims("", "abc", "def")) {
		t.Fatal("opaque")
	}
}

func TestNameIsUsedWhenClaimsHaveNoSubject(t *testing.T) {
	s := subject(ssf.IssSub(idp, "alice"))
	if !receiver.SubjectMatches(s, claims(idp, "", ""), "alice") || receiver.SubjectMatches(s, claims(idp, "", ""), "bob") {
		t.Fatal("name")
	}
	if receiver.SubjectMatches(s, claims(idp, "bob", ""), "alice") {
		t.Fatal("a sub claim wins over the name")
	}
}

func TestPhoneNumberAndOtherFormatsMatchTheClaimOfTheSameName(t *testing.T) {
	if !matches(subject(ssf.PhoneNumber("+15555550123")), ssf.Claims{"phone_number": "+15555550123"}) ||
		matches(subject(ssf.PhoneNumber("+15555550123")), ssf.Claims{"phone_number": "+15555550124"}) {
		t.Fatal("phone")
	}
	if matches(subject(ssf.Claims{"format": "employee_id", "employee_id": "E-1"}), ssf.Claims{"employee_id": "E-1"}) {
		t.Fatal("an unknown format has no value")
	}
	if !matches(subject(ssf.DID("did:example:1")), ssf.Claims{"did": "did:example:1"}) {
		t.Fatal("did")
	}
}

func TestAliasesMatchIfAnyIdentifierDoes(t *testing.T) {
	s := subject(ssf.Aliases(ssf.IssSub(idp, "alice"), ssf.Email("alice@example.com")))
	if !matches(s, ssf.Claims{"email": "ALICE@example.com"}) || !matches(s, claims(idp, "alice", "")) || matches(s, claims(idp, "bob", "")) {
		t.Fatal("aliases")
	}
}

func TestScimResourceMatchesByExternalIDOrIDAgainstTheSubject(t *testing.T) {
	s := subject(ssf.SCIM("/Users/42", "ext-alice"))
	if !matches(s, ssf.Claims{"sub": "ext-alice"}) || !matches(s, ssf.Claims{"sub": "42"}) || matches(s, ssf.Claims{"sub": "bob"}) {
		t.Fatal("scim")
	}
	if !receiver.SubjectMatches(s, ssf.Claims{}, "42") {
		t.Fatal("name")
	}
}

func TestScimResourceMatchesByUserNameAgainstThePreferredUsername(t *testing.T) {
	s := subject(ssf.Claims{"format": "scim", "uri": "/Users/42", "userName": "alice"})
	if !matches(s, ssf.Claims{"preferred_username": "alice"}) || matches(s, ssf.Claims{"preferred_username": "bob"}) {
		t.Fatal("userName")
	}
}

func TestScimAttributeClaimsAreConfigurable(t *testing.T) {
	s := subject(ssf.Claims{"format": "scim", "uri": "/Users/42", "userName": "alice", "externalId": "ext"})
	pairs := [][2]string{{"userName", "sub"}}
	if !receiver.SubjectMatchesWith(s, ssf.Claims{"sub": "alice"}, "", pairs) || receiver.SubjectMatchesWith(s, ssf.Claims{"sub": "ext"}, "", pairs) {
		t.Fatal("configurable")
	}
	if len(receiver.DefaultScimAttributeClaims) != 3 {
		t.Fatal("defaults")
	}
}

func TestMultiValuedScimAttributesMatchByAnyValue(t *testing.T) {
	s := subject(ssf.Claims{"format": "scim", "uri": "/Users/42",
		"emails": []any{map[string]any{"value": "Alice@Example.com", "primary": true}, "alias@example.com", float64(3)}})
	pairs := [][2]string{{"emails", "email"}}
	if !receiver.SubjectMatchesWith(s, ssf.Claims{"email": "alice@example.com"}, "", pairs) ||
		!receiver.SubjectMatchesWith(s, ssf.Claims{"email": "alias@example.com"}, "", pairs) ||
		receiver.SubjectMatchesWith(s, ssf.Claims{"email": "bob@example.com"}, "", pairs) {
		t.Fatal("emails")
	}
}

func TestComplexSubjectWithOtherMembersOnlyDoesNotMatch(t *testing.T) {
	s := subject(ssf.ComplexMembers(map[string]ssf.Claims{"device": ssf.Opaque("d1"), "tenant": ssf.Opaque("t1")}))
	if matches(s, claims(idp, "alice", "d1")) || matches(ssf.EmptySubject(), ssf.Claims{"sub": "alice"}) || matches(subject(ssf.SCIM("/Users/42", "")), ssf.Claims{"sub": "43"}) {
		t.Fatal("no match")
	}
}
