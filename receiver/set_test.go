package receiver_test

// NimbusSsfSetVerifierTests of the Java library.

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
	"github.com/easyssf/easyssf-go/ssftest"
)

var ctx = context.Background()

// testClock is a clock the tests move by hand.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock { return &testClock{now: time.Now()} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func options() receiver.VerifierOptions {
	o := receiver.DefaultVerifierOptions()
	o.ExpectedAudiences = []string{ssftest.Audience}
	return o
}

func jwksURL(t *testing.T, transmitter *ssftest.TestTransmitter) *url.URL {
	t.Helper()
	u, err := url.Parse(transmitter.JWKSURL())
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func verifierWith(t *testing.T, transmitter *ssftest.TestTransmitter, o receiver.VerifierOptions) *receiver.JWTVerifier {
	t.Helper()
	keys := receiver.NewHTTPJWKSetSource(transmitter.Client, jwksURL(t, transmitter))
	v, err := receiver.NewJWTVerifier(transmitter.Issuer(), keys, o)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func verifier(t *testing.T, transmitter *ssftest.TestTransmitter) *receiver.JWTVerifier {
	return verifierWith(t, transmitter, options())
}

func code(t *testing.T, err error) receiver.ErrorCode {
	t.Helper()
	rejected := receiver.RejectionOf(err)
	if rejected == nil {
		t.Fatalf("not a rejection: %v", err)
	}
	return rejected.Code
}

func alice(transmitter *ssftest.TestTransmitter) ssf.Claims {
	return ssf.IssSub(transmitter.Issuer(), "alice")
}

func TestVerifiesSET(t *testing.T) {
	transmitter := ssftest.New()
	set := transmitter.Set("CaepSessionRevoked", alice(transmitter))
	token, err := verifier(t, transmitter).Verify(ctx, set)
	if err != nil {
		t.Fatal(err)
	}
	if token.Issuer() != transmitter.Issuer() || token.Audience()[0] != ssftest.Audience {
		t.Fatalf("unexpected %+v", token)
	}
	if _, ok := token.Events()[eventtypes.CaepSessionRevoked]; !ok || token.SubjectID()["sub"] != "alice" {
		t.Fatalf("unexpected %+v", token)
	}
}

func TestRejectsMalformedSET(t *testing.T) {
	v := verifier(t, ssftest.New())
	for _, malformed := range []string{"", "   ", "not.a.jwt", "a.b", "a.b.c.d", "eyJ.eyJ.sig"} {
		_, err := v.Verify(ctx, malformed)
		if code(t, err) != receiver.InvalidRequest {
			t.Errorf("%q: %v", malformed, err)
		}
	}
}

func TestRejectsSETSignedWithUnknownKey(t *testing.T) {
	transmitter := ssftest.New()
	other := ssftest.GenerateKey(2048, "other-key")
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	_, err := verifier(t, transmitter).Verify(ctx, ssftest.Sign(other, ssftest.SecEventJWTType, claims))
	if code(t, err) != receiver.InvalidKey {
		t.Fatal(err)
	}
	// the same kid as the transmitter's key, another key: the signature does not verify
	forged := ssftest.GenerateKey(2048, "test-key")
	_, err = verifier(t, transmitter).Verify(ctx, ssftest.Sign(forged, ssftest.SecEventJWTType, claims))
	if code(t, err) != receiver.InvalidKey {
		t.Fatal(err)
	}
}

func TestRejectsUnsignedSET(t *testing.T) {
	transmitter := ssftest.New()
	_, err := verifier(t, transmitter).Verify(ctx, ssftest.Unsigned(transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))))
	if code(t, err) != receiver.InvalidRequest {
		t.Fatal(err)
	}
}

func TestRejectsAlgorithmThatIsNotAccepted(t *testing.T) {
	transmitter := ssftest.New()
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	set := ssftest.SignWith(transmitter.Key(), jose.RS512, ssftest.SecEventJWTType, claims)
	if _, err := verifier(t, transmitter).Verify(ctx, set); code(t, err) != receiver.InvalidKey {
		t.Fatal(err)
	}
	accepting := options()
	accepting.AcceptedAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.RS512}
	if _, err := verifierWith(t, transmitter, accepting).Verify(ctx, set); err != nil {
		t.Fatal(err)
	}
	ps := ssftest.SignWith(transmitter.Key(), jose.PS256, ssftest.SecEventJWTType, claims)
	psOnly := options()
	psOnly.AcceptedAlgorithms = []jose.SignatureAlgorithm{jose.PS256}
	if _, err := verifierWith(t, transmitter, psOnly).Verify(ctx, ps); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsSigningKeyBelowMinimumSize(t *testing.T) {
	transmitter := ssftest.New()
	weak := ssftest.GenerateKey(1024, "weak")
	transmitter.PublishJWKS(transmitter.Key(), weak)
	set := ssftest.Sign(weak, ssftest.SecEventJWTType, transmitter.SetClaims("CaepSessionRevoked", alice(transmitter)))
	if _, err := verifier(t, transmitter).Verify(ctx, set); code(t, err) != receiver.InvalidKey {
		t.Fatal(err)
	}
	anySize := options()
	anySize.MinRSAKeySize = 0
	if _, err := verifierWith(t, transmitter, anySize).Verify(ctx, set); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsSETThatIsNotTypedAsSecurityEvent(t *testing.T) {
	transmitter := ssftest.New()
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	untyped := ssftest.Sign(transmitter.Key(), "", claims)
	if _, err := verifier(t, transmitter).Verify(ctx, untyped); code(t, err) != receiver.InvalidRequest {
		t.Fatal(err)
	}
	lenient := options()
	lenient.RequireTypeHeader = false
	if _, err := verifierWith(t, transmitter, lenient).Verify(ctx, untyped); err != nil {
		t.Fatal(err)
	}
	// the type is compared ignoring case
	if _, err := verifier(t, transmitter).Verify(ctx, ssftest.Sign(transmitter.Key(), "SECEVENT+JWT", claims)); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsAccessTokenPresentedAsSET(t *testing.T) {
	transmitter := ssftest.New()
	_, err := verifier(t, transmitter).Verify(ctx, transmitter.AccessTokenFor("alice", "session-1", time.Now()))
	if code(t, err) != receiver.InvalidRequest {
		t.Fatal(err)
	}
}

func TestRejectsSETOfAnotherIssuer(t *testing.T) {
	transmitter := ssftest.New()
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	claims["iss"] = "https://evil.example"
	_, err := verifier(t, transmitter).Verify(ctx, transmitter.SignSET(claims))
	if code(t, err) != receiver.InvalidIssuer {
		t.Fatal(err)
	}
}

func TestRejectsSETForAnotherAudience(t *testing.T) {
	transmitter := ssftest.New()
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	claims["aud"] = []string{"https://other.example"}
	if _, err := verifier(t, transmitter).Verify(ctx, transmitter.SignSET(claims)); code(t, err) != receiver.InvalidAudience {
		t.Fatal(err)
	}
	// one of several audiences is enough
	claims["aud"] = []string{"https://other.example", ssftest.Audience}
	if _, err := verifier(t, transmitter).Verify(ctx, transmitter.SignSET(claims)); err != nil {
		t.Fatal(err)
	}
	// a provider decides per SET
	provided := options()
	provided.ExpectedAudiences = nil
	provided.ExpectedAudiencesProvider = func() ([]string, error) { return []string{"https://other.example"}, nil }
	claims["aud"] = ssftest.Audience
	if _, err := verifierWith(t, transmitter, provided).Verify(ctx, transmitter.SignSET(claims)); code(t, err) != receiver.InvalidAudience {
		t.Fatal(err)
	}
}

func TestAcceptsAnyAudienceWhenNoneIsExpected(t *testing.T) {
	transmitter := ssftest.New()
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	claims["aud"] = "https://other.example"
	anyAudience := options()
	anyAudience.ExpectedAudiences = nil
	if _, err := verifierWith(t, transmitter, anyAudience).Verify(ctx, transmitter.SignSET(claims)); err != nil {
		t.Fatal(err)
	}
	delete(claims, "aud")
	if _, err := verifierWith(t, transmitter, anyAudience).Verify(ctx, transmitter.SignSET(claims)); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsSETWithoutRequiredClaims(t *testing.T) {
	transmitter := ssftest.New()
	v := verifier(t, transmitter)
	for _, claim := range []string{"jti", "iat", "events"} {
		claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
		delete(claims, claim)
		if _, err := v.Verify(ctx, transmitter.SignSET(claims)); code(t, err) != receiver.InvalidRequest {
			t.Errorf("%s: %v", claim, err)
		}
	}
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	claims["events"] = ssf.Claims{}
	if _, err := v.Verify(ctx, transmitter.SignSET(claims)); code(t, err) != receiver.InvalidRequest {
		t.Fatal(err)
	}
	claims["events"] = ssf.Claims{"e": ssf.Claims{}}
	claims["aud"] = 42
	if _, err := v.Verify(ctx, transmitter.SignSET(claims)); code(t, err) != receiver.InvalidRequest {
		t.Fatal(err)
	}
}

func TestRejectsSETWithoutTopLevelSubjectUnlessAllowed(t *testing.T) {
	transmitter := ssftest.New()
	payload := ssf.Claims{"subject": ssf.Email("alice@example.com")}
	set := transmitter.SignSET(transmitter.SetClaimsWithPayload("CaepSessionRevoked", nil, payload))
	if _, err := verifier(t, transmitter).Verify(ctx, set); code(t, err) != receiver.InvalidRequest {
		t.Fatal(err)
	}
	legacy := options()
	legacy.SubjectCompatibility = ssf.Legacy
	token, err := verifierWith(t, transmitter, legacy).Verify(ctx, set)
	if err != nil || token.SubjectID() != nil {
		t.Fatalf("%v %v", token, err)
	}
}

func TestRejectsSETIssuedInTheFuture(t *testing.T) {
	transmitter := ssftest.New()
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	claims["iat"] = time.Now().Unix() + 120
	if _, err := verifier(t, transmitter).Verify(ctx, transmitter.SignSET(claims)); code(t, err) != receiver.InvalidRequest {
		t.Fatal(err)
	}
	// within the clock skew
	claims["iat"] = time.Now().Unix() + 30
	if _, err := verifier(t, transmitter).Verify(ctx, transmitter.SignSET(claims)); err != nil {
		t.Fatal(err)
	}
}

func TestUnreachableJWKSetIsReportedAsUnavailable(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.RemoveDocument("/realms/test/protocol/openid-connect/certs")
	set := transmitter.Set("CaepSessionRevoked", alice(transmitter))
	v := verifier(t, transmitter)
	if _, err := v.Verify(ctx, set); !receiver.IsTransmitterUnavailable(err) {
		t.Fatalf("expected unavailable, got %v", err)
	}
	// not cached: the next SET fetches again
	transmitter.PublishJWKS(transmitter.Key())
	if _, err := v.Verify(ctx, set); err != nil {
		t.Fatal(err)
	}
}

func TestFetchesTheJWKSetAgainForAnUnknownKeyButRateLimited(t *testing.T) {
	transmitter := ssftest.New()
	clock := newTestClock()
	keys := receiver.NewHTTPJWKSetSource(transmitter.Client, jwksURL(t, transmitter))
	keys.RefreshRateLimit = 30 * time.Second
	keys.Clock = clock.Now
	v, err := receiver.NewJWTVerifier(transmitter.Issuer(), keys, options())
	if err != nil {
		t.Fatal(err)
	}
	set := transmitter.Set("CaepSessionRevoked", alice(transmitter))
	if _, err := v.Verify(ctx, set); err != nil {
		t.Fatal(err)
	}
	fetches := transmitter.Requests()

	// the transmitter rotates its key: the first SET with the new kid triggers a fetch
	rotated := ssftest.GenerateKey(2048, "rotated")
	transmitter.PublishJWKS(rotated)
	signedWithRotated := ssftest.Sign(rotated, ssftest.SecEventJWTType, transmitter.SetClaims("CaepSessionRevoked", alice(transmitter)))
	if _, err := v.Verify(ctx, signedWithRotated); code(t, err) != receiver.InvalidKey {
		t.Fatal(err)
	}
	if transmitter.Requests() != fetches {
		t.Fatal("within the rate limit no fetch happens")
	}
	clock.Advance(31 * time.Second)
	if _, err := v.Verify(ctx, signedWithRotated); err != nil {
		t.Fatal(err)
	}
	if transmitter.Requests() != fetches+1 {
		t.Fatalf("%d requests", transmitter.Requests())
	}
	// and the old key is gone
	if _, err := v.Verify(ctx, set); code(t, err) != receiver.InvalidKey {
		t.Fatal(err)
	}
}

func TestJWKSetLocationIsResolvedFromTheMetadataOnFirstUse(t *testing.T) {
	transmitter := ssftest.New()
	resolver, err := receiver.NewMetadataResolver(transmitter.Issuer(), nil, transmitter.Client, receiver.URIPolicy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := receiver.NewResolvedHTTPJWKSetSource(transmitter.Client, func(ctx context.Context) (*url.URL, error) {
		metadata, err := resolver.Resolve(ctx)
		if err != nil {
			return nil, err
		}
		return metadata.JWKSURI(), nil
	})
	v, err := receiver.NewJWTVerifier(transmitter.Issuer(), keys, options())
	if err != nil {
		t.Fatal(err)
	}
	if transmitter.Requests() != 0 {
		t.Fatal("nothing is fetched before the first SET")
	}
	set := transmitter.Set("CaepSessionRevoked", alice(transmitter))
	if _, err := v.Verify(ctx, set); err != nil {
		t.Fatal(err)
	}
	if transmitter.Requests() != 2 {
		t.Fatalf("metadata and JWK Set: %d requests", transmitter.Requests())
	}
	if _, err := v.Verify(ctx, set); err != nil {
		t.Fatal(err)
	}
	if transmitter.Requests() != 2 {
		t.Fatal("both are cached")
	}
}
