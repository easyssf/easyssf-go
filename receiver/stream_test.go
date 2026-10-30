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

// holdRequest is an http.RoundTripper that holds the nth request until release is closed,
// ignoring the context of the request as a transport that does not notice a cancellation
// does, and passes every other request on.
type holdRequest struct {
	inner     http.RoundTripper
	nth       int32
	count     atomic.Int32
	held      chan struct{} // closed once the request is held
	release   chan struct{} // close to let the request go on
	completed chan struct{} // closed once the request completed
}

func holdFirstRequestOf(client *http.Client) (*http.Client, *holdRequest) {
	return holdRequestOf(client, 1)
}

func holdRequestOf(client *http.Client, nth int32) (*http.Client, *holdRequest) {
	hold := &holdRequest{inner: client.Transport, nth: nth, held: make(chan struct{}), release: make(chan struct{}), completed: make(chan struct{})}
	return &http.Client{Transport: hold}, hold
}

func (h *holdRequest) RoundTrip(r *http.Request) (*http.Response, error) {
	if h.count.Add(1) != h.nth {
		return h.inner.RoundTrip(r)
	}
	close(h.held)
	<-h.release
	defer close(h.completed)
	// completes regardless of the cancellation, as a transport that does not notice it does
	return h.inner.RoundTrip(r.WithContext(context.WithoutCancel(r.Context())))
}

func TestCancelledRegistrationThatFailsAfterARestartDoesNotRecordItsFailure(t *testing.T) {
	transmitter := ssftest.New()
	// the second request of the registration creates the stream, after the listing found none;
	// held until the transmitter issues streams for another issuer
	client, hold := holdRequestOf(transmitter.Client, 2)
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(receiver.NewStreamClient(metadataResolver(t, transmitter), client, tokenProvider(t, transmitter)), stream, pushStream("CaepSessionRevoked"))
	first, cancel := context.WithCancel(ctx)
	registrar.Start(first)
	<-hold.held
	cancel()
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the stream", func() bool { return registrar.State() == receiver.StreamRegistered })
	registered := stream.StreamID()
	// the held create succeeds once the transmitter has room for a stream again, with a
	// stream of another issuer: the cancelled registration ends in an issuer mismatch
	if err := streamClient(t, transmitter).DeleteStream(ctx, registered); err != nil {
		t.Fatal(err)
	}
	transmitter.SetStreamIssuer("https://other.example")
	close(hold.release)
	<-hold.completed
	ssftest.During(t, 200*time.Millisecond, "the cancelled registration to record no failure", func() bool {
		return registrar.State() == receiver.StreamRegistered && registrar.LastError() == "" && stream.StreamID() == registered
	})
	registrar.Stop(ctx)
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

func TestRefusesExistingStreamsWithAnotherIssuer(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetStreamIssuer("https://other.example")
	streamID := transmitter.AddStream(ssf.PollStream([]string{"CaepSessionRevoked"}, "").Claims())["stream_id"].(string)
	client := streamClient(t, transmitter)
	_, getErr := client.Stream(ctx, streamID)
	_, listErr := client.Streams(ctx)
	_, updateErr := client.UpdateStream(ctx, streamID, ssf.Claims{"description": "x"})
	_, replaceErr := client.ReplaceStream(ctx, streamID, ssf.PollStream([]string{"CaepSessionRevoked"}, ""))
	for name, err := range map[string]error{"get": getErr, "list": listErr, "update": updateErr, "replace": replaceErr} {
		var mismatch *receiver.IssuerMismatchError
		if !errors.As(err, &mismatch) || mismatch.Stream.StreamID() != streamID {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRegistrarGivesUpOnExistingStreamWithAnotherIssuerWithoutDeletingIt(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetStreamIssuer("https://other.example")
	streamID := transmitter.AddStream(ssf.PollStream([]string{"CaepSessionRevoked"}, "").Claims())["stream_id"].(string)
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForExistingStream(streamClient(t, transmitter), stream, streamID)
	registrar.InitialRetryDelay = 50 * time.Millisecond
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the registrar gave up", func() bool { return registrar.State() == receiver.StreamFailed })
	registrar.Stop(ctx)
	if !strings.Contains(registrar.LastError(), "https://other.example") || stream.StreamID() != "" {
		t.Fatalf("%q", registrar.LastError())
	}
	// the stream is not this registrar's to delete
	if len(transmitter.Streams()) != 1 {
		t.Fatal("deleted")
	}
	// a managed stream finds it while it looks for its own, and leaves it alone as well
	managed := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), receiver.NewReceiverStream(), pushStream("CaepSessionRevoked"))
	managed.DeleteOnShutdown = true
	managed.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the registrar gave up", func() bool { return managed.State() == receiver.StreamFailed })
	managed.Stop(ctx)
	if len(transmitter.Streams()) != 1 {
		t.Fatal("deleted")
	}
}

func TestRegistrarStartIsIdempotentAndStopEndsTheRegistration(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetAvailable(false)
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return transmitter.Client.Transport.RoundTrip(r)
	})}
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(receiver.NewStreamClient(metadataResolver(t, transmitter), client, receiver.FixedToken(ssftest.AccessToken)), stream, ssf.PollStream([]string{"CaepSessionRevoked"}, ""))
	registrar.InitialRetryDelay = 20 * time.Millisecond
	registrar.Start(ctx)
	registrar.Start(ctx)
	if !registrar.IsRunning() {
		t.Fatal("not running")
	}
	ssftest.Eventually(t, 5*time.Second, "three attempts", func() bool { return calls.Load() >= 3 })
	registrar.Stop(ctx)
	registrar.Stop(ctx)
	if registrar.IsRunning() {
		t.Fatal("still running")
	}
	callsAtStop := calls.Load()
	ssftest.During(t, 200*time.Millisecond, "no more attempts", func() bool { return calls.Load() == callsAtStop })
	if stream.StreamID() != "" {
		t.Fatal("registered")
	}
}

// stall holds the first request to the configuration endpoint with its method that when, if
// set, accepts, before or after it reached the transmitter, until release is closed.
type stall struct {
	method   string
	after    bool // the request reaches the transmitter first, its response is held
	when     func(*http.Request) bool
	armed    atomic.Bool
	streamID atomic.Value // the stream_id of the request held
	held     chan struct{}
	release  chan struct{}
}

func newStall(method string, after bool) *stall {
	s := &stall{method: method, after: after, held: make(chan struct{}), release: make(chan struct{})}
	s.armed.Store(true)
	return s
}

func (s *stall) takes(r *http.Request) bool {
	return r.Method == s.method && strings.HasSuffix(r.URL.Path, "/ssf/streams") && (s.when == nil || s.when(r)) && s.armed.CompareAndSwap(true, false)
}

func (s *stall) hold(r *http.Request) {
	s.streamID.Store(r.URL.Query().Get("stream_id"))
	close(s.held)
	<-s.release
}

func waitFor(t *testing.T, c <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// deaf is an http.RoundTripper that does not notice the cancellation of a request, as some
// transports do not, and holds the requests its stalls take.
type deaf struct {
	inner  http.RoundTripper
	stalls []*stall
}

func (d *deaf) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.WithContext(context.WithoutCancel(r.Context()))
	var taken *stall
	for _, s := range d.stalls {
		if s.takes(r) {
			taken = s
			break
		}
	}
	if taken != nil && !taken.after {
		taken.hold(r)
	}
	response, err := d.inner.RoundTrip(r)
	if taken != nil && taken.after {
		taken.hold(r)
	}
	return response, err
}

// deafRegistrar manages a poll stream through a deaf transport, deletes it on shutdown and
// gives a registration in flight 200 milliseconds on Stop: the registrations of these tests
// outlive their Stop on purpose.
func deafRegistrar(t *testing.T, transmitter *ssftest.TestTransmitter, stalls ...*stall) (*receiver.StreamRegistrar, *receiver.ReceiverStream, *atomic.Int32) {
	client := &http.Client{Transport: &deaf{inner: transmitter.Client.Transport, stalls: stalls}}
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(receiver.NewStreamClient(metadataResolver(t, transmitter), client, receiver.FixedToken(ssftest.AccessToken)), stream, ssf.PollStream([]string{"CaepSessionRevoked"}, ""))
	registrar.DeleteOnShutdown = true
	registrar.StopTimeout = 200 * time.Millisecond
	registrar.InitialRetryDelay = 50 * time.Millisecond
	var registered atomic.Int32
	registrar.AddListener(func(*ssf.StreamConfiguration) { registered.Add(1) })
	return registrar, stream, &registered
}

func streamIDs(transmitter *ssftest.TestTransmitter) []string {
	streams := transmitter.Streams()
	ids := make([]string, 0, len(streams))
	for _, stream := range streams {
		ids = append(ids, stream["stream_id"].(string))
	}
	return ids
}

func TestRegistrationThatCompletesAfterStopPublishesNothing(t *testing.T) {
	transmitter := ssftest.New()
	discovery := newStall(http.MethodGet, false)
	registrar, stream, registered := deafRegistrar(t, transmitter, discovery)
	registrar.StopTimeout = 10 * time.Second
	registrar.Start(ctx)
	waitFor(t, discovery.held, "the look-up")

	var stopping atomic.Bool
	stopping.Store(true)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		registrar.Stop(ctx)
		stopping.Store(false)
	}()
	// Stop waits for the registration, which completes only once released
	ssftest.During(t, 200*time.Millisecond, "Stop to wait", stopping.Load)
	close(discovery.release)
	waitFor(t, stopped, "Stop")

	// the stream created on the way is deleted, as it would have been on shutdown
	ssftest.Eventually(t, 5*time.Second, "the stream to be deleted", func() bool { return len(transmitter.Streams()) == 0 })
	if registered.Load() != 0 || stream.StreamID() != "" || registrar.State() == receiver.StreamRegistered {
		t.Fatal("published")
	}
}

func TestStopWaitsForAPublicationInProgressAndDeletesTheStreamItPublished(t *testing.T) {
	transmitter := ssftest.New()
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(streamClient(t, transmitter), stream, ssf.PollStream([]string{"CaepSessionRevoked"}, ""))
	registrar.DeleteOnShutdown = true
	publishing, release := make(chan struct{}), make(chan struct{})
	var registered atomic.Value
	registrar.AddListener(func(s *ssf.StreamConfiguration) {
		// the registration published and tells its listeners when Stop is called
		registered.Store(s.StreamID())
		close(publishing)
		<-release
	})
	registrar.Start(ctx)
	waitFor(t, publishing, "the publication")

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		registrar.Stop(ctx)
	}()
	ssftest.During(t, 200*time.Millisecond, "Stop to wait", func() bool {
		select {
		case <-stopped:
			return false
		default:
			return len(transmitter.Streams()) == 1
		}
	})
	close(release)
	waitFor(t, stopped, "Stop")

	// the publication completed before Stop went on, so the stream it published is the one
	// Stop deleted
	if stream.StreamID() != registered.Load() || len(transmitter.Streams()) != 0 {
		t.Fatalf("%v", streamIDs(transmitter))
	}
}

func TestRegistrationThatOutlivesItsStopLeavesTheStreamToTheRegistrationThatFollowed(t *testing.T) {
	transmitter := ssftest.New()
	// the transmitter created the stream, but the transport does not return, nor does it notice
	// the cancellation of Stop
	create := newStall(http.MethodPost, true)
	registrar, stream, registered := deafRegistrar(t, transmitter, create)
	registrar.Start(ctx)
	waitFor(t, create.held, "the create request")
	created := streamIDs(transmitter)[0]

	// Stop gives the first registration up after its timeout, Start begins a second one, which
	// finds the stream the first created and adopts it
	stopping := time.Now()
	registrar.Stop(ctx)
	if elapsed := time.Since(stopping); elapsed < 200*time.Millisecond {
		t.Fatalf("Stop returned after %v", elapsed)
	}
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the second registration", func() bool { return stream.StreamID() != "" })
	if stream.StreamID() != created {
		t.Fatal(stream.StreamID())
	}

	// the first registration returns at last: it neither publishes nor deletes the stream the
	// second one uses
	close(create.release)
	ssftest.During(t, 300*time.Millisecond, "the stream to stay", func() bool { return len(transmitter.Streams()) == 1 })
	if registered.Load() != 1 || registrar.State() != receiver.StreamRegistered {
		t.Fatal("published twice")
	}

	registrar.Stop(ctx)
	if len(transmitter.Streams()) != 0 {
		t.Fatal("not deleted")
	}
}

func TestRegistrationThatOutlivesItsStopDeletesTheStreamItCreatedAfterTheNextOnePublished(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetSeveralStreamsAllowed(true)
	// the first registration stalls after it looked for streams and found none
	discovery := newStall(http.MethodGet, true)
	registrar, stream, _ := deafRegistrar(t, transmitter, discovery)
	registrar.Start(ctx)
	waitFor(t, discovery.held, "the look-up")

	// Stop gives the first registration up, the second finds no stream and creates one
	registrar.Stop(ctx)
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the second registration", func() bool { return stream.StreamID() != "" })
	published := stream.StreamID()

	// the first registration goes on to create a stream of its own, which nobody uses
	close(discovery.release)
	ssftest.Eventually(t, 5*time.Second, "the orphan to be deleted", func() bool { return len(transmitter.Streams()) == 1 })
	ssftest.During(t, 300*time.Millisecond, "one stream", func() bool { return len(transmitter.Streams()) == 1 })
	if streamIDs(transmitter)[0] != published || stream.StreamID() != published {
		t.Fatalf("%v, published %s", streamIDs(transmitter), published)
	}

	registrar.Stop(ctx)
	if len(transmitter.Streams()) != 0 {
		t.Fatal("not deleted")
	}
}

func TestStreamAStoppedRegistrationLeavesIsAdoptedByTheNextOneAndNotMistakenForAnEarlierOne(t *testing.T) {
	transmitter := ssftest.New()
	create := newStall(http.MethodPost, true)
	create.armed.Store(false)
	discovery := newStall(http.MethodGet, true)
	discovery.armed.Store(false)
	registrar, stream, _ := deafRegistrar(t, transmitter, create, discovery)
	// a first registration published a stream and Stop deleted it; the receiver still
	// remembers that stream, which must not pass for the one the next registration uses
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the first registration", func() bool { return stream.StreamID() != "" })
	earlier := stream.StreamID()
	registrar.Stop(ctx)
	if len(transmitter.Streams()) != 0 || stream.StreamID() != earlier {
		t.Fatal("deleted on Stop")
	}

	// the second registration creates a stream and stalls; Stop gives it up and the third finds
	// that stream, and stalls before it publishes it
	create.armed.Store(true)
	registrar.Start(ctx)
	waitFor(t, create.held, "the create request")
	created := streamIDs(transmitter)[0]
	registrar.Stop(ctx)
	discovery.armed.Store(true)
	registrar.Start(ctx)
	waitFor(t, discovery.held, "the look-up")

	// the second returns now: the third has not published, so the stream is left to it, not
	// deleted for differing from the stream of the first
	close(create.release)
	ssftest.During(t, 300*time.Millisecond, "the stream to stay", func() bool { return len(transmitter.Streams()) == 1 })
	close(discovery.release)
	ssftest.Eventually(t, 5*time.Second, "the third registration", func() bool { return stream.StreamID() == created })
	if len(transmitter.Streams()) != 1 || registrar.State() != receiver.StreamRegistered {
		t.Fatal("adopted")
	}

	registrar.Stop(ctx)
	if len(transmitter.Streams()) != 0 {
		t.Fatal("not deleted")
	}
}

func TestStreamAStoppedRegistrationCreatesAfterTheNextOneLookedIsDeletedOnceTheNextOnePublished(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetSeveralStreamsAllowed(true)
	// the first registration stalls after it looked and found no stream; the second finds none
	// either, creates a stream and stalls before it publishes; the first then creates a stream
	// nobody will adopt
	discovery := newStall(http.MethodGet, true)
	create := newStall(http.MethodPost, true)
	create.armed.Store(false)
	registrar, stream, _ := deafRegistrar(t, transmitter, discovery, create)
	registrar.Start(ctx)
	waitFor(t, discovery.held, "the look-up")
	registrar.Stop(ctx)
	create.armed.Store(true)
	registrar.Start(ctx)
	waitFor(t, create.held, "the create request")
	published := streamIDs(transmitter)[0]

	// the first creates its stream while the second has not published
	close(discovery.release)
	ssftest.Eventually(t, 5*time.Second, "the second stream", func() bool { return len(transmitter.Streams()) == 2 })
	ssftest.During(t, 300*time.Millisecond, "both streams to stay", func() bool { return len(transmitter.Streams()) == 2 })

	// the second publishes its own stream: the other one is an orphan and goes
	close(create.release)
	ssftest.Eventually(t, 5*time.Second, "the orphan to be deleted", func() bool { return len(transmitter.Streams()) == 1 })
	if streamIDs(transmitter)[0] != published || stream.StreamID() != published {
		t.Fatalf("%v, published %s", streamIDs(transmitter), published)
	}

	registrar.Stop(ctx)
	if len(transmitter.Streams()) != 0 {
		t.Fatal("not deleted")
	}
}

func TestStreamWhoseDeletionIsUnderWayIsNotAdoptedByTheNextRegistration(t *testing.T) {
	// the first registration stalls after it looked and found no stream; the second creates a
	// stream and publishes it; the first then creates an orphan and deletes it, which the
	// transmitter takes its time for; the registrar is restarted meanwhile
	transmitter := ssftest.New()
	transmitter.SetSeveralStreamsAllowed(true)
	discovery := newStall(http.MethodGet, true)
	var second atomic.Value
	second.Store("")
	// the delete of the orphan, the only stream deleted while the second is in use
	deleting := newStall(http.MethodDelete, false)
	deleting.when = func(r *http.Request) bool {
		id := second.Load().(string)
		return id != "" && r.URL.Query().Get("stream_id") != id
	}
	registrar, stream, registered := deafRegistrar(t, transmitter, discovery, deleting)
	registrar.Start(ctx)
	waitFor(t, discovery.held, "the look-up")
	registrar.Stop(ctx)
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the second registration", func() bool { return stream.StreamID() != "" })
	second.Store(stream.StreamID())

	// the first creates its stream, an orphan, and gets stuck deleting it
	close(discovery.release)
	waitFor(t, deleting.held, "the delete of the orphan")
	orphan := deleting.streamID.Load().(string)
	if len(transmitter.Streams()) != 2 {
		t.Fatalf("%v", streamIDs(transmitter))
	}

	// restarted while the orphan still exists: the third registration finds it and must not
	// adopt it, it creates a stream of its own instead
	registrar.Stop(ctx)
	if len(transmitter.Streams()) != 1 {
		t.Fatalf("%v", streamIDs(transmitter))
	}
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the third registration", func() bool { return registered.Load() == 2 })
	third := stream.StreamID()
	if third == orphan || third == second.Load() {
		t.Fatalf("adopted %s", third)
	}

	close(deleting.release)
	ssftest.Eventually(t, 5*time.Second, "the orphan to be deleted", func() bool { return len(transmitter.Streams()) == 1 })
	if streamIDs(transmitter)[0] != third {
		t.Fatalf("%v", streamIDs(transmitter))
	}

	registrar.Stop(ctx)
	if len(transmitter.Streams()) != 0 {
		t.Fatal("not deleted")
	}
}

func TestStopDeletesOnlyAStreamPublishedSinceTheLastStop(t *testing.T) {
	transmitter := ssftest.New()
	var deletes atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
		}
		return transmitter.Client.Transport.RoundTrip(r)
	})}
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(receiver.NewStreamClient(metadataResolver(t, transmitter), client, receiver.FixedToken(ssftest.AccessToken)), stream, ssf.PollStream([]string{"CaepSessionRevoked"}, ""))
	registrar.DeleteOnShutdown = true
	registrar.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the registration", func() bool { return registrar.State() == receiver.StreamRegistered })
	registrar.Stop(ctx)
	// the receiver still knows the stream; a second Stop does not delete it again
	registrar.Stop(ctx)
	if deletes.Load() != 1 || stream.StreamID() == "" {
		t.Fatalf("%d deletes", deletes.Load())
	}
}
