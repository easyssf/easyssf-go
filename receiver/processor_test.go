package receiver_test

// SsfSetProcessorTests and SsfTokenRevocationEventHandlerTests of the Java library, the first
// few; the rest (claim renewal under a long handler, eviction, the configured receiver) follow
// the same pattern.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssftest"
)

const idp = "https://idp.example"

func TestHandsVerifiedSETToAllHandlers(t *testing.T) {
	transmitter := ssftest.New()
	first, second := &recorder{}, &recorder{}
	p := processor(t, transmitter, first, second)
	outcome, err := p.Process(ctx, transmitter.Set("CaepSessionRevoked", alice(transmitter)), ssf.Push)
	if err != nil || outcome != receiver.Handled || first.count.Load() != 1 || second.count.Load() != 1 {
		t.Fatalf("%v %v", outcome, err)
	}
}

func TestSkipsSETThatWasProcessedBefore(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	p := processor(t, transmitter, r)
	set := transmitter.Set("CaepSessionRevoked", alice(transmitter))
	_, _ = p.Process(ctx, set, ssf.Push)
	outcome, err := p.Process(ctx, set, ssf.Poll)
	if err != nil || outcome != receiver.Duplicate || r.count.Load() != 1 {
		t.Fatalf("%v %v", outcome, err)
	}
}

// A handler that outlives the lease loses the SET to the instance that takes it over. The
// first instance still reports what its handlers did, as they ran and succeeded (the delivery
// is acknowledged, as the Java library does), but the outcome recorded in the store is the one
// of the instance that took the SET over: the first instance's claim no longer fences.
func TestSETTakenOverWhileItsHandlersRanIsRecordedByTheInstanceThatTookItOver(t *testing.T) {
	transmitter := ssftest.New()
	clock := newTestClock()
	store := receiver.NewInMemoryJTIDedupStore(10, 60*time.Second, clock.Now)
	slow := &recorder{}
	release, running := make(chan struct{}), make(chan struct{})
	slowHandler := receiver.HandlerFunc(func(ctx context.Context, event *receiver.Context) error {
		close(running)
		<-release
		return slow.Handle(ctx, event)
	})
	options := receiver.ProcessorOptions{ClaimRenewal: 10 * time.Millisecond}
	first := receiver.NewProcessor(verifier(t, transmitter), store, options).AddHandler(slowHandler)
	other := &recorder{}
	second := receiver.NewProcessor(verifier(t, transmitter), store, options).AddHandler(other)
	set := transmitter.Set("CaepSessionRevoked", alice(transmitter))

	type result struct {
		outcome receiver.ProcessingOutcome
		err     error
	}
	results := make(chan result, 1)
	go func() {
		outcome, err := first.Process(ctx, set, ssf.Push)
		results <- result{outcome, err}
	}()
	<-running
	// the first instance's handler outlives the lease: the second instance takes the SET over
	clock.Advance(61 * time.Second)
	if outcome, err := second.Process(ctx, set, ssf.Push); err != nil || outcome != receiver.Handled || other.count.Load() != 1 {
		t.Fatalf("taken over: %v %v", outcome, err)
	}
	close(release)
	got := <-results
	if got.err != nil || got.outcome != receiver.Handled || slow.count.Load() != 1 {
		t.Fatalf("the first instance's handler succeeded: %v %v", got.outcome, got.err)
	}
	if outcome, err := second.Process(ctx, set, ssf.Push); err != nil || outcome != receiver.Duplicate {
		t.Fatalf("recorded as processed: %v %v", outcome, err)
	}
	if other.count.Load() != 1 || slow.count.Load() != 1 {
		t.Fatal("handled once by each instance")
	}
}

func TestProcessesDuplicatesWithoutDedupStore(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	p := receiver.NewProcessor(verifier(t, transmitter), nil, receiver.ProcessorOptions{}).AddHandler(r)
	set := transmitter.Set("CaepSessionRevoked", alice(transmitter))
	_, _ = p.Process(ctx, set, ssf.Push)
	_, _ = p.Process(ctx, set, ssf.Push)
	if r.count.Load() != 2 {
		t.Fatal("both handled")
	}
}

func TestFailingHandlerDoesNotKeepOthersFromHandlingAndAllowsRedelivery(t *testing.T) {
	transmitter := ssftest.New()
	after := &recorder{}
	boom := receiver.HandlerFunc(func(context.Context, *receiver.Context) error { return errors.New("boom") })
	p := processor(t, transmitter, boom, after)
	set := transmitter.Set("CaepSessionRevoked", alice(transmitter))
	_, err := p.Process(ctx, set, ssf.Push)
	var handling *receiver.HandlingError
	if !errors.As(err, &handling) || handling.Failed != 1 || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("%v", err)
	}
	if after.count.Load() != 1 {
		t.Fatal("the handler after the failing one ran")
	}
	// the redelivery runs the handlers again
	if _, err := p.Process(ctx, set, ssf.Push); err == nil || after.count.Load() != 2 {
		t.Fatal("redelivered")
	}
}

func TestPanickingHandlerCountsAsFailed(t *testing.T) {
	transmitter := ssftest.New()
	panicking := receiver.HandlerFunc(func(context.Context, *receiver.Context) error { panic("kaboom") })
	_, err := processor(t, transmitter, panicking).Process(ctx, transmitter.Set("CaepSessionRevoked", alice(transmitter)), ssf.Push)
	var handling *receiver.HandlingError
	if !errors.As(err, &handling) || !strings.Contains(err.Error(), "kaboom") {
		t.Fatalf("%v", err)
	}
}

// inProgressStore says every SET is in progress elsewhere.
type inProgressStore struct{ receiver.JTIDedupStore }

func (inProgressStore) Claim(context.Context, *ssf.EventToken) (receiver.JTIClaim, error) {
	return receiver.JTIClaim{State: receiver.InProgress}, nil
}

func TestSETBeingHandledElsewhereIsLeftForARedelivery(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	p := receiver.NewProcessor(verifier(t, transmitter), inProgressStore{}, receiver.ProcessorOptions{}).AddHandler(r)
	_, err := p.Process(ctx, transmitter.Set("CaepSessionRevoked", alice(transmitter)), ssf.Push)
	if !errors.Is(err, receiver.ErrInProgress) || r.count.Load() != 0 {
		t.Fatalf("%v", err)
	}
}

func TestRejectsSETWithCriticalSubjectMemberTheReceiverDoesNotUnderstand(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	p := receiver.NewProcessor(verifier(t, transmitter), receiver.NewInMemoryJTIDedupStore(10, 0, nil), receiver.ProcessorOptions{
		UnderstoodSubjectMembers: []string{"user", "session"},
		CriticalSubjectMembers:   func(string) []string { return []string{"tenant", "device"} },
	}).AddHandler(r)
	withTenant := ssf.ComplexMembers(map[string]ssf.Claims{"user": alice(transmitter), "tenant": ssf.Opaque("t-1")})
	_, err := p.Process(ctx, transmitter.Set("CaepSessionRevoked", withTenant), ssf.Push)
	if code(t, err) != receiver.InvalidRequest || !strings.Contains(err.Error(), "tenant") || r.count.Load() != 0 {
		t.Fatalf("%v", err)
	}
	// a critical member that is absent, or one that is understood, is fine
	withSession := transmitter.Set("CaepSessionRevoked", ssf.Complex(alice(transmitter), ssf.Opaque("s1")))
	if _, err := p.Process(ctx, withSession, ssf.Push); err != nil || r.count.Load() != 1 {
		t.Fatal(err)
	}
}

func revoke(t *testing.T, transmitter *ssftest.TestTransmitter, store receiver.TokenRevocationStore, eventType string, subject ssf.Claims) {
	t.Helper()
	p := processor(t, transmitter, receiver.NewTokenRevocationHandler(store, nil, nil, nil))
	if _, err := p.Process(ctx, transmitter.Set(eventType, subject), ssf.Push); err != nil {
		t.Fatal(err)
	}
}

func revoked(t *testing.T, store receiver.TokenRevocationStore, claims receiver.TokenClaims) bool {
	t.Helper()
	r, err := receiver.IsRevoked(ctx, store, claims)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSessionEventRevokesTokensOfThatSessionOnly(t *testing.T) {
	transmitter := ssftest.New()
	store := receiver.NewInMemoryTokenRevocationStore(0, nil)
	revoke(t, transmitter, store, "CaepSessionRevoked", ssf.Complex(ssf.IssSub(idp, "alice"), ssf.Opaque("s1")))
	if !revoked(t, store, receiver.TokenClaims{Issuer: idp, Subject: "alice", SessionID: "s1"}) {
		t.Fatal("s1 revoked")
	}
	if revoked(t, store, receiver.TokenClaims{Issuer: idp, Subject: "alice", SessionID: "s2"}) || revoked(t, store, receiver.TokenClaims{Issuer: idp, Subject: "alice"}) {
		t.Fatal("other sessions and the user are not")
	}
}

func TestUserEventRevokesTokensIssuedUpToTheEvent(t *testing.T) {
	transmitter := ssftest.New()
	store := receiver.NewInMemoryTokenRevocationStore(0, nil)
	revoke(t, transmitter, store, "CaepSessionRevoked", ssf.IssSub(idp, "alice"))
	if !revoked(t, store, receiver.TokenClaims{Issuer: idp, Subject: "alice", IssuedAt: time.Now().Add(-time.Minute)}) {
		t.Fatal("issued before the event")
	}
	if revoked(t, store, receiver.TokenClaims{Issuer: idp, Subject: "alice", IssuedAt: time.Now().Add(time.Minute)}) {
		t.Fatal("issued after the event")
	}
	if revoked(t, store, receiver.TokenClaims{Issuer: "https://other.example", Subject: "alice"}) {
		t.Fatal("scoped to the issuer")
	}
}

func TestRevocationMiddlewareRejectsRevokedTokens(t *testing.T) {
	store := receiver.NewInMemoryTokenRevocationStore(0, nil)
	_ = store.RevokeSession(ctx, idp, "s1")
	extract := func(r *http.Request) (receiver.TokenClaims, bool) {
		return receiver.TokenClaims{Issuer: idp, Subject: "alice", SessionID: r.Header.Get("X-Session")}, true
	}
	handler := receiver.RevocationMiddleware(store, extract)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for session, status := range map[string]int{"s1": 401, "s2": 200} {
		request := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
		request.Header.Set("X-Session", session)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Errorf("%s: %d", session, response.Code)
		}
	}
}

func TestReceiverAssemblesFromConfiguration(t *testing.T) {
	transmitter := ssftest.New()
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = transmitter.Issuer()
	config.ExpectedAudience = ssftest.Audience
	config.Push.ExpectedAuthHeader = secret
	r := &recorder{}
	rcv, err := receiver.New(config, receiver.WithHTTPClient(transmitter.Client), receiver.WithHandler(receiver.ForEvent("CaepSessionRevoked", r)))
	if err != nil {
		t.Fatal(err)
	}
	rcv.Start(ctx)
	defer rcv.Stop(ctx)
	set := []byte(transmitter.Set("CaepSessionRevoked", ssf.Complex(ssf.IssSub(idp, "alice"), ssf.Opaque("s1"))))
	if response := rcv.PushHandler().Handle(ctx, secret, set); response.Status != 202 || r.count.Load() != 1 {
		t.Fatalf("%+v", response)
	}
	if !revoked(t, rcv.TokenRevocationStore(), receiver.TokenClaims{Issuer: idp, Subject: "alice", SessionID: "s1"}) {
		t.Fatal("the built-in revocation handler ran")
	}
	if rcv.PushEndpointPath() != "/ssf/push" || rcv.Health(ctx).Status != receiver.HealthHealthy {
		t.Fatal("defaults")
	}
}

func TestConfigValidationReportsEveryFailure(t *testing.T) {
	config := receiver.DefaultConfig()
	err := config.Validate()
	var configError *receiver.ConfigError
	if !errors.As(err, &configError) || !strings.Contains(err.Error(), "transmitter-issuer") {
		t.Fatalf("%v", err)
	}
	config.TransmitterIssuer = "http://idp.example/realm"
	config.DeliveryMethod = "carrier-pigeon"
	config.SetValidation.AcceptedAlgorithms = []string{"HS256"}
	err = config.Validate()
	for _, expected := range []string{"must use https", "delivery-method", "HS256", "expected-audience"} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("missing %q in %v", expected, err)
		}
	}
	if _, err := receiver.New(config); err == nil {
		t.Fatal("New validates")
	}
	config.Enabled = false
	if _, err := receiver.New(config); !errors.Is(err, receiver.ErrDisabled) {
		t.Fatal("disabled")
	}
}
