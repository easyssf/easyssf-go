package receiver_test

// SsfStreamManagementTests and SsfStreamVerificationTests of the Java library.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
	"github.com/easyssf/easyssf-go/ssftest"
)

func metadataResolver(t *testing.T, transmitter *ssftest.TestTransmitter) *receiver.MetadataResolver {
	t.Helper()
	resolver, err := receiver.NewMetadataResolver(transmitter.Issuer(), nil, transmitter.Client, receiver.URIPolicy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func tokenProvider(t *testing.T, transmitter *ssftest.TestTransmitter) *receiver.ClientCredentialsTokenProvider {
	t.Helper()
	tokenURL, _ := url.Parse(transmitter.TokenURL())
	return receiver.NewClientCredentialsTokenProvider(transmitter.Client, tokenURL, ssftest.ClientID, ssftest.ClientSecret, receiver.DefaultClientCredentialsOptions())
}

func streamClient(t *testing.T, transmitter *ssftest.TestTransmitter) *receiver.StreamClient {
	return receiver.NewStreamClient(metadataResolver(t, transmitter), transmitter.Client, tokenProvider(t, transmitter))
}

func pushStream(events ...string) *ssf.StreamConfiguration {
	endpoint, _ := url.Parse("https://app.example/ssf/push")
	return ssf.PushStream(endpoint, "Bearer s3cr3t", events, "test stream")
}

func TestManagesStream(t *testing.T) {
	transmitter := ssftest.New()
	client := streamClient(t, transmitter)
	if streams, err := client.Streams(ctx); err != nil || len(streams) != 0 {
		t.Fatalf("%v %v", streams, err)
	}
	created, err := client.CreateStream(ctx, pushStream("CaepSessionRevoked"))
	if err != nil {
		t.Fatal(err)
	}
	streamID := created.StreamID()
	if created.Issuer() != transmitter.Issuer() || created.Audience()[0] != ssftest.ClientID+"/"+streamID {
		t.Fatalf("%v", created.Claims())
	}
	if delivered := created.EventsDelivered(); len(delivered) != 1 || delivered[0] != eventtypes.CaepSessionRevoked {
		t.Fatalf("%v", delivered)
	}
	if _, echoed := ssf.ObjectMember(created.Claims(), "delivery")["authorization_header"]; echoed {
		t.Fatal("the transmitter does not echo the header")
	}
	if streams, _ := client.Streams(ctx); len(streams) != 1 {
		t.Fatal("one stream")
	}
	if stream, err := client.Stream(ctx, streamID); err != nil || stream.StreamID() != streamID {
		t.Fatalf("%v %v", stream, err)
	}
	updated, err := client.UpdateStream(ctx, streamID, ssf.Claims{"description": "changed"})
	if err != nil || updated.Description() != "changed" {
		t.Fatalf("%v %v", updated, err)
	}
	replaced, err := client.ReplaceStream(ctx, streamID, pushStream("CaepCredentialChange"))
	if err != nil || replaced.EventsRequested()[0] != eventtypes.CaepCredentialChange {
		t.Fatalf("%v %v", replaced, err)
	}
	if status, err := client.Status(ctx, streamID); err != nil || status.Status != ssf.StreamEnabled {
		t.Fatalf("%v %v", status, err)
	}
	if paused, err := client.UpdateStatus(ctx, streamID, ssf.StreamPaused, "maintenance"); err != nil || paused.Status != ssf.StreamPaused {
		t.Fatalf("%v %v", paused, err)
	}
	if err := client.AddSubject(ctx, streamID, ssf.Email("alice@example.com"), true); err != nil {
		t.Fatal(err)
	}
	if transmitter.AddedSubjects()[0]["email"] != "alice@example.com" {
		t.Fatal("added")
	}
	if err := client.RemoveSubject(ctx, streamID, ssf.Email("alice@example.com")); err != nil || len(transmitter.RemovedSubjects()) != 1 {
		t.Fatal("removed")
	}
	if err := client.RequestVerification(ctx, streamID, "state-1"); err != nil || transmitter.VerificationRequests()[0] != "state-1" {
		t.Fatal("verification")
	}
	if err := client.DeleteStream(ctx, streamID); err != nil {
		t.Fatal(err)
	}
	if streams, _ := client.Streams(ctx); len(streams) != 0 {
		t.Fatal("deleted")
	}
}

func TestReportsStatusOfFailedCalls(t *testing.T) {
	transmitter := ssftest.New()
	client := streamClient(t, transmitter)
	_, err := client.Stream(ctx, "missing")
	if receiver.StreamStatusOf(err) != 404 || !strings.Contains(err.Error(), "404") {
		t.Fatalf("%v", err)
	}
	transmitter.SetAvailable(false)
	_, err = client.Streams(ctx)
	if receiver.StreamStatusOf(err) != 503 {
		t.Fatalf("the cached token was used, the transmitter answered: %v", err)
	}
	_, err = streamClient(t, transmitter).Streams(ctx)
	if receiver.StreamStatusOf(err) != 0 || !receiver.IsTransmitterUnavailable(err) {
		t.Fatalf("the token request failed, the transmitter was not called: %v", err)
	}
}

func TestRefusesStreamCreatedWithAnotherIssuer(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetStreamIssuer("https://other.example")
	_, err := streamClient(t, transmitter).CreateStream(ctx, pushStream("CaepSessionRevoked"))
	var mismatch *receiver.IssuerMismatchError
	if !errors.As(err, &mismatch) || !strings.Contains(err.Error(), "https://other.example") {
		t.Fatalf("%v", err)
	}
}

func TestRegistrarDeletesStreamCreatedWithAnotherIssuerAndGivesUp(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetStreamIssuer("https://other.example")
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), stream, pushStream("CaepSessionRevoked"))
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the registrar gave up", func() bool { return registrar.State() == receiver.StreamFailed })
	if !strings.Contains(registrar.LastError(), "https://other.example") || len(transmitter.Streams()) != 0 || stream.Configuration() != nil {
		t.Fatalf("%q %v", registrar.LastError(), transmitter.Streams())
	}
	registrar.Stop(ctx)
}

func TestObtainsNewAccessTokenWhenTheTransmitterRejectsTheCurrentOne(t *testing.T) {
	transmitter := ssftest.New()
	client := streamClient(t, transmitter)
	if _, err := client.Streams(ctx); err != nil {
		t.Fatal(err)
	}
	transmitter.ExpireAccessTokens()
	if _, err := client.Streams(ctx); err != nil {
		t.Fatal(err)
	}
	if transmitter.TokenRequests() != 2 {
		t.Fatalf("%d token requests", transmitter.TokenRequests())
	}
}

func TestRegistrarCreatesStream(t *testing.T) {
	transmitter := ssftest.New()
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), stream, pushStream("CaepSessionRevoked"))
	if registrar.State() != receiver.StreamNotStarted {
		t.Fatal("not started")
	}
	registered, err := registrar.Register(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if registrar.State() != receiver.StreamRegistered || stream.StreamID() != registered.StreamID() || len(stream.Audience()) != 1 || len(transmitter.Streams()) != 1 {
		t.Fatal("registered")
	}
}

func TestRegistrarTellsItsListenersOnceTheStreamIsRegistered(t *testing.T) {
	transmitter := ssftest.New()
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), stream, pushStream("CaepSessionRevoked"))
	var mu sync.Mutex
	var told []string
	registrar.AddListener(func(s *ssf.StreamConfiguration) {
		mu.Lock()
		defer mu.Unlock()
		told = append(told, s.StreamID())
	})
	registrar.Start(ctx)
	if !registrar.IsRunning() {
		t.Fatal("running")
	}
	ssftest.Eventually(t, 5*time.Second, "the listener was told", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(told) > 0
	})
	mu.Lock()
	if told[0] != stream.StreamID() {
		t.Fatal("told the stream")
	}
	mu.Unlock()
	registrar.Stop(ctx)
	if registrar.IsRunning() {
		t.Fatal("stopped")
	}
}

func TestRegistrarReusesExistingStream(t *testing.T) {
	transmitter := ssftest.New()
	existing := transmitter.AddStream(pushStream("CaepSessionRevoked").Claims())
	registrar := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), receiver.NewReceiverStream(), pushStream("CaepSessionRevoked"))
	registered, err := registrar.Register(ctx)
	if err != nil || registered.StreamID() != existing["stream_id"] || len(transmitter.Streams()) != 1 {
		t.Fatalf("%v %v", registered, err)
	}
}

func TestRegistrarUpdatesRequestedEventsOfExistingStream(t *testing.T) {
	transmitter := ssftest.New()
	existing := transmitter.AddStream(pushStream("CaepSessionRevoked").Claims())
	registrar := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), receiver.NewReceiverStream(), pushStream("CaepSessionRevoked", "CaepCredentialChange"))
	registered, err := registrar.Register(ctx)
	if err != nil || registered.StreamID() != existing["stream_id"] || len(registered.EventsRequested()) != 2 || len(transmitter.Streams()) != 1 {
		t.Fatalf("%v %v", registered, err)
	}
}

func TestRegistrarChangesDeliveryOfTheOnlyStreamTheTransmitterAllows(t *testing.T) {
	transmitter := ssftest.New()
	existing := transmitter.AddStream(ssf.PollStream([]string{"CaepSessionRevoked"}, "").Claims())
	registrar := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), receiver.NewReceiverStream(), pushStream("CaepSessionRevoked"))
	registered, err := registrar.Register(ctx)
	if err != nil || registered.StreamID() != existing["stream_id"] || registered.DeliveryMethodURI() != ssf.PushURI ||
		registered.DeliveryEndpointURL().String() != "https://app.example/ssf/push" {
		t.Fatalf("%v %v", registered, err)
	}
}

func TestRegistrarLooksUpStreamCreatedAtTheTransmitter(t *testing.T) {
	transmitter := ssftest.New()
	existing := transmitter.AddStream(ssf.PollStream([]string{"CaepSessionRevoked"}, "").Claims())
	streamID := existing["stream_id"].(string)
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForExistingStream(streamClient(t, transmitter), stream, streamID)
	if _, err := registrar.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if stream.StreamID() != streamID || stream.PollEndpointURL().String() != transmitter.PollURL() {
		t.Fatal("looked up")
	}
	missing := receiver.NewStreamRegistrarForExistingStream(streamClient(t, transmitter), receiver.NewReceiverStream(), "missing")
	if _, err := missing.Register(ctx); receiver.StreamStatusOf(err) != 404 {
		t.Fatalf("%v", err)
	}
}

func TestRegistrarRetriesInTheBackgroundUntilTheTransmitterAnswers(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetAvailable(false)
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), stream, pushStream("CaepSessionRevoked"))
	registrar.InitialRetryDelay = 20 * time.Millisecond
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "a failed attempt", func() bool { return registrar.LastError() != "" })
	if registrar.State() != receiver.StreamRegistering {
		t.Fatal("registering")
	}
	transmitter.SetAvailable(true)
	ssftest.Eventually(t, 5*time.Second, "the registration", func() bool { return registrar.State() == receiver.StreamRegistered })
	if registrar.LastError() != "" || stream.StreamID() == "" {
		t.Fatal("registered")
	}
	registrar.Stop(ctx)
}

func TestRegistrarDeletesManagedStreamOnShutdownIfAsked(t *testing.T) {
	transmitter := ssftest.New()
	registrar := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), receiver.NewReceiverStream(), pushStream("CaepSessionRevoked"))
	registrar.DeleteOnShutdown = true
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the registration", func() bool { return registrar.State() == receiver.StreamRegistered })
	if len(transmitter.Streams()) != 1 {
		t.Fatal("created")
	}
	registrar.Stop(ctx)
	if len(transmitter.Streams()) != 0 {
		t.Fatal("deleted")
	}
	// not asked: the stream stays
	keep := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), receiver.NewReceiverStream(), pushStream("CaepSessionRevoked"))
	if _, err := keep.Register(ctx); err != nil {
		t.Fatal(err)
	}
	keep.Stop(ctx)
	if len(transmitter.Streams()) != 1 {
		t.Fatal("kept")
	}
}

// SsfStreamVerificationTests

func verificationEvent(streamID, state string) *receiver.Context {
	event := ssf.Claims{}
	if state != "" {
		event["state"] = state
	}
	claims := ssf.Claims{"jti": "1", "iss": "https://t.example", "iat": float64(1), "events": ssf.Claims{eventtypes.SSFStreamVerification: event}}
	if streamID != "" {
		claims["sub_id"] = ssf.Opaque(streamID)
	}
	return receiver.NewContext(ssf.EventTokenFromClaims(claims), ssf.Push)
}

func forStream(streamID string) *receiver.StreamVerification {
	return receiver.NewStreamVerification(func() string { return streamID })
}

func TestAcceptsVerificationEventThatEchoesTheRequestedState(t *testing.T) {
	verification := forStream("s-1")
	state := verification.NewState()
	if !verification.IsPending() {
		t.Fatal("pending")
	}
	if err := verification.Check(verificationEvent("s-1", state)); err != nil {
		t.Fatal(err)
	}
	if verification.IsPending() {
		t.Fatal("answered")
	}
}

func TestRejectsVerificationEventWithAnotherStateThanTheRequestedOne(t *testing.T) {
	verification := forStream("s-1")
	_ = verification.NewState()
	if code(t, verification.Check(verificationEvent("s-1", "other"))) != receiver.InvalidState {
		t.Fatal("invalid_state")
	}
	if !verification.IsPending() {
		t.Fatal("the request stays pending")
	}
}

func TestAcceptsVerificationEventInitiatedByTheTransmitter(t *testing.T) {
	verification := forStream("s-1")
	if err := verification.Check(verificationEvent("s-1", "")); err != nil {
		t.Fatal(err)
	}
	_ = verification.NewState()
	if err := verification.Check(verificationEvent("s-1", "")); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptsStateWhenNoVerificationWasRequestedUnlessStrict(t *testing.T) {
	if err := forStream("s-1").Check(verificationEvent("s-1", "transmitter-state")); err != nil {
		t.Fatal(err)
	}
	strict := forStream("s-1")
	strict.RejectUnrequestedState = true
	if code(t, strict.Check(verificationEvent("s-1", "transmitter-state"))) != receiver.InvalidState {
		t.Fatal("strict")
	}
}

func TestRejectsVerificationEventAboutAnotherStream(t *testing.T) {
	verification := forStream("s-1")
	if code(t, verification.Check(verificationEvent("s-2", ""))) != receiver.InvalidRequest {
		t.Fatal("other stream")
	}
	// an iss_sub subject is not a stream either
	claims := ssf.Claims{"jti": "1", "iss": "i", "iat": float64(1), "sub_id": ssf.IssSub("i", "s-1"), "events": ssf.Claims{eventtypes.SSFStreamVerification: ssf.Claims{}}}
	if code(t, verification.Check(receiver.NewContext(ssf.EventTokenFromClaims(claims), ssf.Push))) != receiver.InvalidRequest {
		t.Fatal("iss_sub")
	}
}

func TestRejectsVerificationEventWithoutSubjectID(t *testing.T) {
	if code(t, forStream("s-1").Check(verificationEvent("", ""))) != receiver.InvalidRequest {
		t.Fatal("no subject")
	}
}

func TestDoesNotCheckTheStreamWhileItIsUnknown(t *testing.T) {
	verification := receiver.NewStreamVerification(nil)
	if err := verification.Check(verificationEvent("whatever", "")); err != nil {
		t.Fatal(err)
	}
	if err := verification.Check(verificationEvent("", "")); err != nil {
		t.Fatal(err)
	}
}

func TestIgnoresOtherEvents(t *testing.T) {
	verification := forStream("s-1")
	_ = verification.NewState()
	claims := ssf.Claims{"jti": "1", "iss": "i", "iat": float64(1), "sub_id": ssf.IssSub("i", "alice"), "events": ssf.Claims{eventtypes.CaepSessionRevoked: ssf.Claims{"state": "x"}}}
	if err := verification.Check(receiver.NewContext(ssf.EventTokenFromClaims(claims), ssf.Push)); err != nil || !verification.IsPending() {
		t.Fatal(err)
	}
}

func TestProcessorRejectsInvalidVerificationEventWithoutHandlingOrRememberingIt(t *testing.T) {
	transmitter := ssftest.New()
	verification := forStream("s-1")
	r := &recorder{}
	p := receiver.NewProcessor(verifier(t, transmitter), receiver.NewInMemoryJTIDedupStore(10, 0, nil), receiver.ProcessorOptions{
		StreamVerifications: func(string) func(*receiver.Context) error { return verification.Check },
	}).AddHandler(r)
	_ = verification.NewState()
	set := transmitter.SignSET(transmitter.SetClaimsWithPayload("SsfStreamVerification", ssf.Opaque("s-1"), ssf.Claims{"state": "unexpected"}))
	if _, err := p.Process(ctx, set, ssf.Push); code(t, err) != receiver.InvalidState || r.count.Load() != 0 {
		t.Fatalf("%v", err)
	}
	// a valid one is handled, and the SET was not remembered as processed by the rejection
	set = transmitter.SignSET(transmitter.SetClaimsWithPayload("SsfStreamVerification", ssf.Opaque("s-1"), nil))
	if _, err := p.Process(ctx, set, ssf.Push); err != nil || r.count.Load() != 1 {
		t.Fatal(err)
	}
}

// holdFirst is an http.RoundTripper that holds the first request until release is closed,
// ignoring the context of the request as a transport that does not notice a cancellation
// does, and passes every other request on.
type holdFirst struct {
	inner     http.RoundTripper
	first     sync.Once
	held      chan struct{} // closed once the first request is held
	release   chan struct{} // close to let the first request go on
	completed chan struct{} // closed once the first request completed
}

func holdFirstRequestOf(client *http.Client) (*http.Client, *holdFirst) {
	hold := &holdFirst{inner: client.Transport, held: make(chan struct{}), release: make(chan struct{}), completed: make(chan struct{})}
	return &http.Client{Transport: hold}, hold
}

func (h *holdFirst) RoundTrip(r *http.Request) (*http.Response, error) {
	first := false
	h.first.Do(func() { first = true })
	if !first {
		return h.inner.RoundTrip(r)
	}
	close(h.held)
	<-h.release
	defer close(h.completed)
	// completes regardless of the cancellation, as a transport that does not notice it does
	return h.inner.RoundTrip(r.WithContext(context.WithoutCancel(r.Context())))
}

func TestCancelledRegistrationDoesNotPublishItsResultAfterARestart(t *testing.T) {
	transmitter := ssftest.New()
	client, hold := holdFirstRequestOf(transmitter.Client)
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(receiver.NewStreamClient(metadataResolver(t, transmitter), client, tokenProvider(t, transmitter)), stream, pushStream("CaepSessionRevoked"))
	var notified atomic.Int32
	registrar.AddListener(func(*ssf.StreamConfiguration) { notified.Add(1) })
	first, cancel := context.WithCancel(ctx)
	registrar.Start(first)
	<-hold.held
	cancel()
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the stream", func() bool { return registrar.State() == receiver.StreamRegistered })
	if notified.Load() != 1 {
		t.Fatal("notified of the registration")
	}
	registered := stream.StreamID()
	// the request of the cancelled registration completes now, and its result is stale
	close(hold.release)
	<-hold.completed
	ssftest.During(t, 200*time.Millisecond, "the cancelled registration to publish nothing", func() bool {
		return notified.Load() == 1 && stream.StreamID() == registered && registrar.State() == receiver.StreamRegistered
	})
	registrar.Stop(ctx)
}

func TestRegistrarStartsAgainWhileTheGoroutineOfTheCancelledStartIsStillEnding(t *testing.T) {
	transmitter := ssftest.New()
	client, hold := holdFirstRequestOf(transmitter.Client)
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(receiver.NewStreamClient(metadataResolver(t, transmitter), client, tokenProvider(t, transmitter)), stream, pushStream("CaepSessionRevoked"))
	first, cancel := context.WithCancel(ctx)
	registrar.Start(first)
	<-hold.held
	cancel()
	// the goroutine of the first Start is stuck in its request and has not ended yet
	registrar.Start(ctx)
	if !registrar.IsRunning() {
		t.Fatal("not started again")
	}
	close(hold.release)
	ssftest.Eventually(t, 5*time.Second, "the stream", func() bool { return registrar.State() == receiver.StreamRegistered })
	if stream.StreamID() == "" {
		t.Fatal("registered by the second Start")
	}
	registrar.Stop(ctx)
}

func TestRegistrarStartsAgainAfterTheContextOfStartWasCancelled(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetAvailable(false)
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), stream, pushStream("CaepSessionRevoked"))
	registrar.InitialRetryDelay = 10 * time.Millisecond
	first, cancel := context.WithCancel(ctx)
	registrar.Start(first)
	if !registrar.IsRunning() {
		t.Fatal("not running")
	}
	cancel()
	ssftest.Eventually(t, 5*time.Second, "the registrar to end", func() bool { return !registrar.IsRunning() })
	transmitter.SetAvailable(true)
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the stream", func() bool { return registrar.State() == receiver.StreamRegistered })
	registrar.Stop(ctx)
}
