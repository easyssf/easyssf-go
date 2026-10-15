package receiver_test

// SsfPollerTests and SsfPollerRateLimitTests of the Java library.

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
	"github.com/easyssf/easyssf-go/ssftest"
)

func pollerOptions() receiver.PollerOptions {
	o := receiver.DefaultPollerOptions()
	o.Interval = 100 * time.Millisecond
	o.EndpointRetry = 20 * time.Millisecond
	return o
}

func pollURL(t *testing.T, transmitter *ssftest.TestTransmitter) *url.URL {
	t.Helper()
	u, err := url.Parse(transmitter.PollURL())
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func pollerWith(t *testing.T, transmitter *ssftest.TestTransmitter, p *receiver.Processor, options receiver.PollerOptions) *receiver.Poller {
	t.Helper()
	return receiver.NewPoller(transmitter.Client, receiver.FixedToken(ssftest.AccessToken), receiver.FixedPollEndpoint(pollURL(t, transmitter)), p, options)
}

func poller(t *testing.T, transmitter *ssftest.TestTransmitter, r *recorder) *receiver.Poller {
	return pollerWith(t, transmitter, processor(t, transmitter, r), pollerOptions())
}

func queue(transmitter *ssftest.TestTransmitter) string {
	set := transmitter.Set("CaepSessionRevoked", alice(transmitter))
	transmitter.QueueSet(set)
	return ssftest.ClaimsOf(set)["jti"].(string)
}

func pollNow(t *testing.T, p *receiver.Poller) int {
	t.Helper()
	fetched, err := p.PollNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return fetched
}

func TestStartIsIdempotentAndStopEndsThePollingGoroutine(t *testing.T) {
	transmitter := ssftest.New()
	p := poller(t, transmitter, &recorder{})
	if p.IsRunning() {
		t.Fatal("not running")
	}
	p.Start(ctx)
	p.Start(ctx)
	if !p.IsRunning() {
		t.Fatal("running")
	}
	ssftest.Eventually(t, 5*time.Second, "a poll", func() bool { return transmitter.PollRequests() > 0 })
	p.Stop(ctx)
	if p.IsRunning() {
		t.Fatal("stopped")
	}
	polls := transmitter.PollRequests()
	ssftest.During(t, 250*time.Millisecond, "no more polls", func() bool { return transmitter.PollRequests() == polls })
	p.Stop(ctx)
}

func TestHandlesAndAcknowledgesAvailableSets(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	p := poller(t, transmitter, r)
	jti := queue(transmitter)
	if pollNow(t, p) != 1 || r.count.Load() != 1 {
		t.Fatal("fetched")
	}
	if acked := transmitter.AcknowledgedSets(); len(acked) != 1 || acked[0] != jti {
		t.Fatalf("acknowledged with a second, immediate request: %v", acked)
	}
	if transmitter.QueuedSetCount() != 0 || p.PendingAckCount(ctx) != 0 || p.LastSuccessfulPollAt().IsZero() || p.LastPollError() != "" {
		t.Fatal("state")
	}
	if pollNow(t, p) != 0 {
		t.Fatal("nothing more")
	}
}

func TestFetchesAllSetsWhenMoreAreAvailableThanFitInOneRequest(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	options := pollerOptions()
	options.MaxEvents = 2
	p := pollerWith(t, transmitter, processor(t, transmitter, r), options)
	for i := 0; i < 5; i++ {
		queue(transmitter)
	}
	if pollNow(t, p) != 5 || r.count.Load() != 5 || len(transmitter.AcknowledgedSets()) != 5 {
		t.Fatal("all five")
	}
}

func TestReportsInvalidSetToTheTransmitter(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	p := poller(t, transmitter, r)
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	claims["aud"] = "https://other.example"
	transmitter.QueueSetWithJTI("bad", transmitter.SignSET(claims))
	transmitter.QueueSetWithJTI("garbage", "not a set")
	if pollNow(t, p) != 2 || r.count.Load() != 0 {
		t.Fatal("fetched, not handled")
	}
	codes := map[string]string{}
	for _, reported := range transmitter.ReportedErrors() {
		codes[reported.JTI] = reported.Code
	}
	if codes["bad"] != "invalid_audience" || codes["garbage"] != "invalid_request" || len(transmitter.AcknowledgedSets()) != 0 {
		t.Fatalf("%v", codes)
	}
}

func TestDoesNotAcknowledgeSetThatCouldNotBeHandledSoThatItIsDeliveredAgain(t *testing.T) {
	transmitter := ssftest.New()
	var attempts atomic.Int32
	failing := receiver.HandlerFunc(func(context.Context, *receiver.Context) error {
		if attempts.Add(1) == 1 {
			return errors.New("first attempt fails")
		}
		return nil
	})
	p := pollerWith(t, transmitter, processor(t, transmitter, failing), pollerOptions())
	jti := queue(transmitter)
	if pollNow(t, p) != 1 || len(transmitter.AcknowledgedSets()) != 0 || transmitter.QueuedSetCount() != 1 {
		t.Fatal("not acknowledged")
	}
	// delivered again with the next poll
	if pollNow(t, p) != 1 || transmitter.AcknowledgedSets()[0] != jti || attempts.Load() != 2 {
		t.Fatal("redelivered")
	}
}

func TestPollerObtainsNewAccessTokenWhenTheTransmitterRejectsTheCurrentOne(t *testing.T) {
	transmitter := ssftest.New()
	p := receiver.NewPoller(transmitter.Client, tokenProvider(t, transmitter), receiver.FixedPollEndpoint(pollURL(t, transmitter)), processor(t, transmitter, &recorder{}), pollerOptions())
	pollNow(t, p)
	transmitter.ExpireAccessTokens()
	queue(transmitter)
	if pollNow(t, p) != 1 || transmitter.TokenRequests() != 2 {
		t.Fatal("new token")
	}
}

type knownEndpoint struct {
	mu sync.Mutex
	u  *url.URL
}

func (k *knownEndpoint) get() *url.URL {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.u
}

func (k *knownEndpoint) set(u *url.URL) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.u = u
}

func TestDoesNotPollWhileThePollEndpointIsUnknown(t *testing.T) {
	transmitter := ssftest.New()
	known := &knownEndpoint{}
	p := receiver.NewPoller(transmitter.Client, receiver.FixedToken(ssftest.AccessToken), known.get, processor(t, transmitter), pollerOptions())
	if pollNow(t, p) != 0 || transmitter.PollRequests() != 0 || !p.LastPollAt().IsZero() || p.PendingAckCount(ctx) != 0 {
		t.Fatal("not polled")
	}
	known.set(pollURL(t, transmitter))
	pollNow(t, p)
	if transmitter.PollRequests() != 1 {
		t.Fatal("polled")
	}
}

func TestPollsSoonAfterTheEndpointBecomesKnownInsteadOfWaitingTheInterval(t *testing.T) {
	transmitter := ssftest.New()
	known := &knownEndpoint{}
	options := receiver.DefaultPollerOptions()
	options.Interval = time.Minute
	options.EndpointRetry = 20 * time.Millisecond
	p := receiver.NewPoller(transmitter.Client, receiver.FixedToken(ssftest.AccessToken), known.get, processor(t, transmitter), options)
	p.Start(ctx)
	defer p.Stop(ctx)
	ssftest.During(t, 100*time.Millisecond, "no poll without an endpoint", func() bool { return transmitter.PollRequests() == 0 })
	known.set(pollURL(t, transmitter))
	ssftest.Eventually(t, 2*time.Second, "a poll within the endpoint retry", func() bool { return transmitter.PollRequests() > 0 })
}

func TestWakeUpEndsThePauseAndPollsAtOnce(t *testing.T) {
	transmitter := ssftest.New()
	options := receiver.DefaultPollerOptions()
	options.Interval = time.Minute
	p := pollerWith(t, transmitter, processor(t, transmitter), options)
	p.Start(ctx)
	defer p.Stop(ctx)
	ssftest.Eventually(t, 2*time.Second, "the first poll", func() bool { return transmitter.PollRequests() == 1 })
	ssftest.During(t, 100*time.Millisecond, "the pause", func() bool { return transmitter.PollRequests() == 1 })
	p.WakeUp()
	ssftest.Eventually(t, 2*time.Second, "the second poll", func() bool { return transmitter.PollRequests() == 2 })
}

func TestWakeUpDoesNothingWhileThePollerIsNotRunning(t *testing.T) {
	transmitter := ssftest.New()
	poller(t, transmitter, &recorder{}).WakeUp()
	ssftest.During(t, 100*time.Millisecond, "no poll", func() bool { return transmitter.PollRequests() == 0 })
}

func TestReportsFailedPollRequest(t *testing.T) {
	transmitter := ssftest.New()
	p := poller(t, transmitter, &recorder{})
	transmitter.SetAvailable(false)
	_, err := p.PollNow(ctx)
	var pollError *receiver.PollError
	if !errors.As(err, &pollError) || !strings.Contains(err.Error(), "503") {
		t.Fatalf("%v", err)
	}
	if p.LastPollAt().IsZero() || !p.LastSuccessfulPollAt().IsZero() || !strings.Contains(p.LastPollError(), "503") {
		t.Fatal("state")
	}
	transmitter.SetAvailable(true)
	pollNow(t, p)
	if p.LastPollError() != "" {
		t.Fatal("recovered")
	}
}

func TestAcknowledgementsWaitInTheStoreUntilARequestCarriedThem(t *testing.T) {
	transmitter := ssftest.New()
	store := receiver.NewInMemoryPollAckStore()
	options := pollerOptions()
	options.AckStore = store
	options.Transmitter = transmitter.Issuer()
	p := pollerWith(t, transmitter, processor(t, transmitter), options)
	jti := queue(transmitter)
	pollNow(t, p)
	if acked := transmitter.AcknowledgedSets(); len(acked) != 1 || acked[0] != jti {
		t.Fatal("acknowledged")
	}
	if size, _ := store.Size(ctx, transmitter.Issuer()); size != 0 {
		t.Fatal("empty")
	}
	// an acknowledgement recorded by hand rides on the next request
	_ = store.Record(ctx, transmitter.Issuer(), receiver.Ack("manual"))
	if p.PendingAckCount(ctx) != 1 {
		t.Fatal("pending")
	}
	transmitter.SetAvailable(false)
	if _, err := p.PollNow(ctx); err == nil {
		t.Fatal("failed")
	}
	if p.PendingAckCount(ctx) != 1 {
		t.Fatal("kept after a failed request")
	}
	transmitter.SetAvailable(true)
	pollNow(t, p)
	if p.PendingAckCount(ctx) != 0 {
		t.Fatal("delivered")
	}
	if acks := ssf.Strings(transmitter.LastPollRequest()["ack"]); len(acks) != 1 || acks[0] != "manual" {
		t.Fatalf("delivered with the fetch: %v", transmitter.LastPollRequest())
	}
}

func TestAcknowledgementsAreSentInBatches(t *testing.T) {
	transmitter := ssftest.New()
	store := receiver.NewInMemoryPollAckStore()
	options := pollerOptions()
	options.AckStore = store
	options.MaxAckBatch = 2
	options.Transmitter = transmitter.Issuer()
	p := pollerWith(t, transmitter, processor(t, transmitter), options)
	for _, jti := range []string{"a", "b", "c"} {
		_ = store.Record(ctx, transmitter.Issuer(), receiver.Ack(jti))
	}
	pollNow(t, p)
	if acks := ssf.Strings(transmitter.LastPollRequest()["ack"]); len(acks) != 1 {
		t.Fatalf("two with the fetch, the third with the acknowledging request: %v", acks)
	}
	if p.PendingAckCount(ctx) != 0 {
		t.Fatal("all delivered")
	}
}

type gauge struct {
	receiver.NoopMetrics
	mu     sync.Mutex
	values []int
}

func (g *gauge) PendingAcksChanged(_ string, pending int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.values = append(g.values, pending)
}

func TestPendingAcknowledgementsAreAGauge(t *testing.T) {
	transmitter := ssftest.New()
	g := &gauge{}
	options := pollerOptions()
	options.Metrics = g
	p := pollerWith(t, transmitter, processor(t, transmitter), options)
	queue(transmitter)
	pollNow(t, p)
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.values) != 2 || g.values[0] != 1 || g.values[1] != 0 {
		t.Fatalf("%v", g.values)
	}
}

func TestStopFlushesThePendingAcknowledgements(t *testing.T) {
	transmitter := ssftest.New()
	store := receiver.NewInMemoryPollAckStore()
	options := receiver.DefaultPollerOptions()
	options.AckStore = store
	options.Transmitter = transmitter.Issuer()
	options.Interval = time.Minute
	p := pollerWith(t, transmitter, processor(t, transmitter), options)
	p.Start(ctx)
	ssftest.Eventually(t, 2*time.Second, "the first poll", func() bool { return transmitter.PollRequests() == 1 })
	_ = store.Record(ctx, transmitter.Issuer(), receiver.Ack("owed"))
	p.Stop(ctx)
	if acks := ssf.Strings(transmitter.LastPollRequest()["ack"]); len(acks) != 1 || acks[0] != "owed" {
		t.Fatalf("%v", transmitter.LastPollRequest())
	}
	if size, _ := store.Size(ctx, transmitter.Issuer()); size != 0 {
		t.Fatal("flushed")
	}
}

func TestLongPollIsHeldUntilASetArrives(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetLongPollHold(10 * time.Second)
	r := &recorder{}
	options := receiver.DefaultPollerOptions()
	options.LongPollingHold = 10 * time.Second
	options.Interval = time.Minute
	p := pollerWith(t, transmitter, processor(t, transmitter, r), options)
	if !p.IsLongPolling() {
		t.Fatal("long polling")
	}
	p.Start(ctx)
	defer p.Stop(ctx)
	ssftest.Eventually(t, 2*time.Second, "the held request", func() bool { return transmitter.PollRequests() == 1 })
	if transmitter.LastPollRequest()["returnImmediately"] != false {
		t.Fatal("held")
	}
	ssftest.During(t, 150*time.Millisecond, "held", func() bool { return r.count.Load() == 0 })
	queue(transmitter)
	ssftest.Eventually(t, 2*time.Second, "the SET", func() bool { return r.count.Load() == 1 })
	ssftest.Eventually(t, 2*time.Second, "the acknowledgement with the next held request", func() bool { return len(transmitter.AcknowledgedSets()) == 1 })
}

func TestLongPollAgainstATransmitterThatAnswersAtOnceWaitsTheInterval(t *testing.T) {
	transmitter := ssftest.New()
	options := receiver.DefaultPollerOptions()
	options.LongPollingHold = 10 * time.Second
	options.Interval = time.Minute
	p := pollerWith(t, transmitter, processor(t, transmitter), options)
	p.Start(ctx)
	defer p.Stop(ctx)
	ssftest.Eventually(t, 2*time.Second, "the first poll", func() bool { return transmitter.PollRequests() == 1 })
	ssftest.During(t, 300*time.Millisecond, "no tight loop", func() bool { return transmitter.PollRequests() == 1 })
}

func TestStopCancelsAHeldLongPoll(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetLongPollHold(30 * time.Second)
	options := receiver.DefaultPollerOptions()
	options.LongPollingHold = 30 * time.Second
	p := pollerWith(t, transmitter, processor(t, transmitter), options)
	p.Start(ctx)
	ssftest.Eventually(t, 2*time.Second, "the held request", func() bool { return transmitter.PollRequests() == 1 })
	started := time.Now()
	p.Stop(ctx)
	if time.Since(started) > 2*time.Second || p.IsRunning() {
		t.Fatal("stop returned before the hold elapsed")
	}
}

func TestPollNowAsksForAnImmediateAnswerEvenWhenLongPolling(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetLongPollHold(30 * time.Second)
	options := receiver.DefaultPollerOptions()
	options.LongPollingHold = 30 * time.Second
	p := pollerWith(t, transmitter, processor(t, transmitter), options)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pollNow(t, p)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("held")
	}
	if transmitter.LastPollRequest()["returnImmediately"] != true {
		t.Fatal("immediate")
	}
}

// SsfPollerRateLimitTests

// rateLimiting answers the poll endpoint with a canned response, everything else goes to the
// transmitter.
type rateLimiting struct {
	next       http.RoundTripper
	status     int
	retryAfter string
}

func (r *rateLimiting) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, "/poll") {
		response := &http.Response{StatusCode: r.status, Header: http.Header{}, Body: http.NoBody, Request: request}
		if r.retryAfter != "" {
			response.Header.Set("Retry-After", r.retryAfter)
		}
		return response, nil
	}
	return r.next.RoundTrip(request)
}

func pausedAfter(t *testing.T, status int, retryAfter string, options receiver.PollerOptions) time.Duration {
	t.Helper()
	transmitter := ssftest.New()
	client := &http.Client{Transport: &rateLimiting{next: transmitter.Client.Transport, status: status, retryAfter: retryAfter}}
	p := receiver.NewPoller(client, receiver.FixedToken(ssftest.AccessToken), receiver.FixedPollEndpoint(pollURL(t, transmitter)), processor(t, transmitter), options)
	if _, err := p.PollNow(ctx); err == nil {
		t.Fatal("failed")
	}
	until := p.PausedUntil()
	if until.IsZero() {
		return 0
	}
	return time.Until(until)
}

func TestPausesForRetryAfter(t *testing.T) {
	if pause := pausedAfter(t, 429, "120", pollerOptions()); pause <= 110*time.Second || pause > 120*time.Second {
		t.Fatalf("%v", pause)
	}
	if pause := pausedAfter(t, 503, "60", pollerOptions()); pause <= 50*time.Second {
		t.Fatalf("%v", pause)
	}
	// a date instead of seconds is treated like no header
	if pause := pausedAfter(t, 429, "Wed, 21 Oct 2026 07:28:00 GMT", pollerOptions()); pause != 0 {
		t.Fatalf("%v", pause)
	}
}

func TestPollsAgainAtTheRegularIntervalAfter429WithoutRetryAfterByDefault(t *testing.T) {
	if pause := pausedAfter(t, 429, "", pollerOptions()); pause != 0 {
		t.Fatalf("%v", pause)
	}
}

func TestPausesForTheFallbackAfter429WithoutRetryAfter(t *testing.T) {
	options := pollerOptions()
	options.RateLimitFallback = 90 * time.Second
	if pause := pausedAfter(t, 429, "", options); pause <= 80*time.Second {
		t.Fatalf("%v", pause)
	}
}

func TestFallbackDoesNotApplyTo503WithoutRetryAfter(t *testing.T) {
	options := pollerOptions()
	options.RateLimitFallback = 90 * time.Second
	if pause := pausedAfter(t, 503, "", options); pause != 0 {
		t.Fatalf("%v", pause)
	}
}

func TestPauseIsCappedAtTheMaximum(t *testing.T) {
	options := pollerOptions()
	options.MaxPause = 300 * time.Second
	if pause := pausedAfter(t, 429, "3600", options); pause > 300*time.Second || pause <= 290*time.Second {
		t.Fatalf("%v", pause)
	}
}

func TestPausedPollerSkipsPollsUntilThePauseIsOver(t *testing.T) {
	transmitter := ssftest.New()
	client := &http.Client{Transport: &rateLimiting{next: transmitter.Client.Transport, status: 429, retryAfter: "60"}}
	p := receiver.NewPoller(client, receiver.FixedToken(ssftest.AccessToken), receiver.FixedPollEndpoint(pollURL(t, transmitter)), processor(t, transmitter), pollerOptions())
	if _, err := p.PollNow(ctx); err == nil {
		t.Fatal("failed")
	}
	if pollNow(t, p) != 0 {
		t.Fatal("skipped while paused")
	}
}

func TestInMemoryPollAckStoreKeepsAcknowledgementsAndErrorsInOrderPerIssuer(t *testing.T) {
	store := receiver.NewInMemoryPollAckStore()
	_ = store.Record(ctx, "a", receiver.Ack("1"))
	_ = store.Record(ctx, "a", receiver.AckError("2", receiver.InvalidRequest, "bad"))
	_ = store.Record(ctx, "b", receiver.Ack("3"))
	pending, _ := store.Pending(ctx, "a", 10)
	if len(pending) != 2 || pending[0].JTI != "1" || pending[1].JTI != "2" || !pending[1].IsError() {
		t.Fatalf("%v", pending)
	}
	if limited, _ := store.Pending(ctx, "a", 1); len(limited) != 1 {
		t.Fatal("limit")
	}
	if size, _ := store.Size(ctx, "b"); size != 1 {
		t.Fatal("b")
	}
	if size, _ := store.Size(ctx, "c"); size != 0 {
		t.Fatal("c")
	}
	// recording the same SET again changes nothing
	_ = store.Record(ctx, "a", receiver.AckError("1", receiver.InvalidRequest, ""))
	pending, _ = store.Pending(ctx, "a", 10)
	if len(pending) != 2 || pending[0].IsError() {
		t.Fatal("unchanged")
	}
	// removes what the transmitter received
	_ = store.Remove(ctx, "a", []string{"1", "x"})
	pending, _ = store.Pending(ctx, "a", 10)
	if len(pending) != 1 || pending[0].JTI != "2" {
		t.Fatal("removed")
	}
	_ = store.Remove(ctx, "unknown", []string{"1"})
}

func TestPollerRefusesPollEndpointThePolicyForbids(t *testing.T) {
	transmitter := ssftest.New()
	insecure, _ := url.Parse("http://transmitter.example/realms/test/ssf/poll")
	p := receiver.NewPoller(transmitter.Client, receiver.FixedToken(ssftest.AccessToken), receiver.FixedPollEndpoint(insecure), processor(t, transmitter, &recorder{}), pollerOptions())
	if _, err := p.PollNow(ctx); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("%v", err)
	}
}
