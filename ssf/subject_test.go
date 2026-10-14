package ssf

import (
	"reflect"
	"testing"
	"time"
)

func TestAbsentSubjectIsEmpty(t *testing.T) {
	if !SubjectFrom(nil).IsEmpty() || !SubjectFrom(Claims{}).IsEmpty() {
		t.Fatal("expected empty subject")
	}
	if SubjectFrom(nil).HasUser() || SubjectFrom(nil).SessionID() != "" {
		t.Fatal("empty subject has no user and no session")
	}
}

func TestResolvesIssSub(t *testing.T) {
	subject := SubjectFrom(IssSub("https://idp.example", "alice"))
	if subject.Issuer() != "https://idp.example" || subject.Sub() != "alice" {
		t.Fatalf("issuer %q sub %q", subject.Issuer(), subject.Sub())
	}
	if !subject.HasUser() || subject.IsComplex() || subject.SessionID() != "" {
		t.Fatal("simple iss_sub subject names a user and no session")
	}
	if subject.Identifier().Format() != FormatIssSub || len(subject.MemberNames()) != 0 {
		t.Fatal("simple subject has an identifier and no members")
	}
}

func TestResolvesEmail(t *testing.T) {
	subject := SubjectFrom(Email("alice@example.com"))
	if subject.Email() != "alice@example.com" || subject.Sub() != "" || !subject.HasUser() {
		t.Fatalf("unexpected %+v", subject)
	}
}

func TestSimpleOpaqueSubjectIsNeitherUserNorSession(t *testing.T) {
	subject := SubjectFrom(Opaque("abc"))
	if subject.OpaqueID() != "abc" || subject.HasUser() || subject.Sub() != "" || subject.SessionID() != "" || subject.IsEmpty() {
		t.Fatalf("unexpected %+v", subject)
	}
}

func TestResolvesComplexSubjectWithUserAndSession(t *testing.T) {
	subject := SubjectFrom(Complex(IssSub("https://idp.example", "alice"), Opaque("session-1")))
	if !subject.IsComplex() || subject.Issuer() != "https://idp.example" || subject.Sub() != "alice" || subject.SessionID() != "session-1" {
		t.Fatalf("unexpected %+v", subject)
	}
	if subject.Session().Format() != FormatOpaque {
		t.Fatal("session is opaque")
	}
	if !reflect.DeepEqual(subject.MemberNames(), []string{"session", "user"}) {
		t.Fatalf("member names %v", subject.MemberNames())
	}
}

func TestKeycloakAllSessionsMarkerNamesOnlyTheUser(t *testing.T) {
	subject := SubjectFrom(Complex(IssSub("https://idp.example", "alice"), Opaque(AllSessions)))
	if subject.Sub() != "alice" || subject.SessionID() != "" || subject.Session() != nil {
		t.Fatalf("unexpected %+v", subject)
	}
	// the raw claim keeps the member
	if !reflect.DeepEqual(subject.MemberNames(), []string{"session", "user"}) {
		t.Fatalf("member names %v", subject.MemberNames())
	}
	// without a user the marker is an ordinary session identifier
	if SubjectFrom(Complex(nil, Opaque(AllSessions))).SessionID() != AllSessions {
		t.Fatal("marker without user is a session")
	}
}

func TestResolvesComplexSubjectWithOpaqueUser(t *testing.T) {
	subject := SubjectFrom(Complex(Opaque("user-1"), Opaque("session-1")))
	if subject.Sub() != "user-1" || subject.Issuer() != "" || subject.OpaqueID() != "" || !subject.HasUser() {
		t.Fatalf("unexpected %+v", subject)
	}
}

func TestResolvesComplexSubjectWithoutFormatOfEarlyDrafts(t *testing.T) {
	subject := SubjectFrom(Claims{
		"user":    map[string]any{"format": "iss_sub", "iss": "https://idp.example", "sub": "alice"},
		"session": map[string]any{"format": "opaque", "id": "s1"},
	})
	if !subject.IsComplex() || subject.Sub() != "alice" || subject.SessionID() != "s1" {
		t.Fatalf("unexpected %+v", subject)
	}
}

func TestOtherFormatsOfRFC9493NameTheUser(t *testing.T) {
	for _, tc := range []struct {
		identifier Claims
		value      string
	}{
		{Account("acct:alice@example.com"), "acct:alice@example.com"},
		{PhoneNumber("+12025550123"), "+12025550123"},
		{DID("did:example:123"), "did:example:123"},
		{URI("https://example.com/alice"), "https://example.com/alice"},
	} {
		subject := SubjectFrom(tc.identifier)
		if !subject.HasUser() || subject.UserIdentifier().Value() != tc.value || subject.Sub() != "" {
			t.Errorf("%v: unexpected %+v", tc.identifier, subject)
		}
	}
}

func TestSCIMResourceOfRFC9967NamesTheUserByItsURI(t *testing.T) {
	user := SubjectFrom(SCIM("/Users/2b2f880a", "ext-1")).UserIdentifier()
	if !user.IsSCIM() || user.Value() != "/Users/2b2f880a" || user.Claim("externalId") != "ext-1" {
		t.Fatalf("unexpected %+v", user)
	}
}

func TestAliasesCarryEveryIdentifier(t *testing.T) {
	user := SubjectFrom(Aliases(IssSub("https://idp.example", "alice"), Email("alice@example.com"))).UserIdentifier()
	if user.Value() != "" {
		t.Fatal("an aliases identifier has no value of its own")
	}
	aliases := user.Aliases()
	if len(aliases) != 2 || aliases[0].Value() != "alice" || aliases[1].Value() != "alice@example.com" {
		t.Fatalf("aliases %v", aliases)
	}
	if len(SubjectIdentifierFrom(IssSub("i", "s")).Aliases()) != 0 {
		t.Fatal("other formats have no aliases")
	}
}

func TestUnknownFormatIsKeptWithoutValue(t *testing.T) {
	user := SubjectFrom(Claims{"format": "custom", "thing": "x"}).UserIdentifier()
	if user.Format() != "custom" || user.Value() != "" || user.Claim("thing") != "x" {
		t.Fatalf("unexpected %+v", user)
	}
}

func TestIdentifierWithoutFormatIsEmpty(t *testing.T) {
	if !SubjectFrom(Claims{"sub": "alice"}).IsEmpty() {
		t.Fatal("no format, no subject")
	}
	if SubjectIdentifierFrom(Claims{}) != nil || SubjectIdentifierFrom(Claims{"format": " "}) != nil {
		t.Fatal("blank format is none")
	}
}

func TestComplexSubjectExposesAllMembers(t *testing.T) {
	subject := SubjectFrom(ComplexMembers(map[string]Claims{
		"user": IssSub("https://idp.example", "alice"), "device": Opaque("dev-1"), "tenant": Opaque("t-1"),
		"application": Opaque("app-1"), "org_unit": Opaque("ou-1"), "group": Opaque("g-1"),
	}))
	if subject.Device().Value() != "dev-1" || subject.Tenant().Value() != "t-1" || subject.Application().Value() != "app-1" ||
		subject.OrgUnit().Value() != "ou-1" || subject.Group().Value() != "g-1" || subject.Member("device") != subject.Device() {
		t.Fatalf("unexpected %+v", subject)
	}
	count := 0
	subject.Members(func(string, *SubjectIdentifier) bool { count++; return true })
	if count != 6 || len(Members) != 7 {
		t.Fatalf("%d members", count)
	}
}

func TestWithoutSessionWidensToUser(t *testing.T) {
	subject := SubjectFrom(Complex(IssSub("https://idp.example", "alice"), Opaque("session-1")))
	widened := subject.WithoutSession()
	if widened.Sub() != "alice" || widened.SessionID() != "" || !reflect.DeepEqual(widened.Raw(), subject.Raw()) {
		t.Fatalf("unexpected %+v", widened)
	}
	simple := SubjectFrom(Email("a@b"))
	if simple.WithoutSession() != simple {
		t.Fatal("a subject without session is returned as it is")
	}
}

func TestEventTokenReadsTheProfileClaims(t *testing.T) {
	claims, err := ParseClaims([]byte(`{
		"jti": "1", "iss": "https://t.example", "iat": 1700000000, "aud": ["a", "b"],
		"txn": "tx-1", "sub_id": { "format": "opaque", "id": "x" },
		"events": { "https://e.example/one": {} }
	}`))
	if err != nil {
		t.Fatal(err)
	}
	token := EventTokenFromClaims(claims)
	if token == nil {
		t.Fatal("expected a token")
	}
	if token.JTI() != "1" || token.Issuer() != "https://t.example" || !token.IssuedAt().Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("unexpected %+v", token)
	}
	if !reflect.DeepEqual(token.Audience(), []string{"a", "b"}) || token.Txn() != "tx-1" || token.SubjectID()["id"] != "x" {
		t.Fatalf("unexpected %+v", token)
	}
	if token.IdempotencyKey() != "https://t.example::1" || len(token.Claims()) != 7 {
		t.Fatalf("unexpected %+v", token)
	}

	single := EventTokenFromClaims(Claims{"jti": "1", "iss": "i", "iat": float64(1), "aud": "one", "events": Claims{"e": Claims{}}})
	if !reflect.DeepEqual(single.Audience(), []string{"one"}) || single.Txn() != "" || single.SubjectID() != nil {
		t.Fatalf("unexpected %+v", single)
	}

	for _, broken := range []string{
		`{ "iss": "i", "iat": 1, "events": { "e": {} } }`,
		`{ "jti": "", "iss": "i", "iat": 1, "events": { "e": {} } }`,
		`{ "jti": "1", "iat": 1, "events": { "e": {} } }`,
		`{ "jti": "1", "iss": "i", "events": { "e": {} } }`,
		`{ "jti": "1", "iss": "i", "iat": "now", "events": { "e": {} } }`,
		`{ "jti": "1", "iss": "i", "iat": 1, "events": {} }`,
		`{ "jti": "1", "iss": "i", "iat": 1 }`,
	} {
		claims, _ := ParseClaims([]byte(broken))
		if EventTokenFromClaims(claims) != nil {
			t.Errorf("accepted %s", broken)
		}
	}
}

func TestEventTimestampInSecondsOrMilliseconds(t *testing.T) {
	if ts, ok := EventTimestamp(float64(1700000000)); !ok || !ts.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("%v %v", ts, ok)
	}
	if ts, ok := EventTimestamp(int64(1700000000123)); !ok || !ts.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("%v %v", ts, ok)
	}
	if _, ok := EventTimestamp("2024-01-01"); ok {
		t.Fatal("a string is no timestamp")
	}
	if _, ok := EventTimestamp(nil); ok {
		t.Fatal("nil is no timestamp")
	}
}
