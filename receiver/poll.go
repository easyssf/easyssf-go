package receiver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
)

// Poll delivery (RFC 8936): the poller and the acknowledgements it owes the transmitter; a port
// of poll.rs of the Rust port and of org.easyssf.receiver.poll.

// PendingAck is what the poller owes the transmitter for a SET it fetched (RFC 8936, section
// 2.2): an acknowledgement that the SET was received and handled, or an error that it was
// rejected, which goes into the setErrs member of the next poll request.
type PendingAck struct {
	// JTI is the identifier of the SET.
	JTI string
	// Error is the error code of a rejected SET (invalid_request, ...), "" for an
	// acknowledgement.
	Error ErrorCode
	// Description describes the error.
	Description string
}

// Ack is the acknowledgement of a handled SET.
func Ack(jti string) PendingAck { return PendingAck{JTI: jti} }

// AckError is the report of a rejected SET.
func AckError(jti string, code ErrorCode, description string) PendingAck {
	return PendingAck{JTI: jti, Error: code, Description: description}
}

// IsError reports whether this reports an error rather than acknowledging the SET.
func (a PendingAck) IsError() bool { return a.Error != "" }

// PollAckStore keeps the acknowledgements and error reports the poller owes a transmitter until
// a poll request has carried them (RFC 8936, section 2.4: they ride on the next request). The
// InMemoryPollAckStore loses them when the application stops, so a SET handled but not yet
// acknowledged is delivered again after a restart and skipped as a duplicate. A durable
// implementation, such as the store of receiver/sqlstore, acknowledges it with the first poll
// after the restart instead.
//
// Entries are kept per transmitter, identified by its issuer, because a jti is only unique per
// issuer and a store may serve several transmitters.
type PollAckStore interface {
	// Record records an acknowledgement or error report. Recording the same jti again does
	// nothing.
	Record(ctx context.Context, issuer string, ack PendingAck) error
	// Pending lists the acknowledgements and error reports waiting for the transmitter, oldest
	// first, at most limit.
	Pending(ctx context.Context, issuer string, limit int) ([]PendingAck, error)
	// Remove removes entries the transmitter has received.
	Remove(ctx context.Context, issuer string, jtis []string) error
	// Size is the number of entries waiting for the transmitter.
	Size(ctx context.Context, issuer string) (int, error)
}

// InMemoryPollAckStore is a PollAckStore that keeps the pending acknowledgements in memory, in
// the order they were recorded. Lost when the application stops; the default of the poller.
type InMemoryPollAckStore struct {
	mu      sync.Mutex
	pending map[string][]PendingAck
}

// NewInMemoryPollAckStore is an empty store.
func NewInMemoryPollAckStore() *InMemoryPollAckStore {
	return &InMemoryPollAckStore{pending: map[string][]PendingAck{}}
}

// Record implements PollAckStore.
func (s *InMemoryPollAckStore) Record(_ context.Context, issuer string, ack PendingAck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.pending[issuer] {
		if existing.JTI == ack.JTI {
			return nil
		}
	}
	s.pending[issuer] = append(s.pending[issuer], ack)
	return nil
}

// Pending implements PollAckStore.
func (s *InMemoryPollAckStore) Pending(_ context.Context, issuer string, limit int) ([]PendingAck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acks := s.pending[issuer]
	if limit >= 0 && len(acks) > limit {
		acks = acks[:limit]
	}
	return append([]PendingAck(nil), acks...), nil
}

// Remove implements PollAckStore.
func (s *InMemoryPollAckStore) Remove(_ context.Context, issuer string, jtis []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := map[string]bool{}
	for _, jti := range jtis {
		removed[jti] = true
	}
	kept := s.pending[issuer][:0]
	for _, ack := range s.pending[issuer] {
		if !removed[ack.JTI] {
			kept = append(kept, ack)
		}
	}
	s.pending[issuer] = kept
	return nil
}

// Size implements PollAckStore.
func (s *InMemoryPollAckStore) Size(_ context.Context, issuer string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending[issuer]), nil
}

// PollEndpoint supplies the poll endpoint, nil as long as it is not known: the stream is still
// being registered.
type PollEndpoint func() *url.URL

// FixedPollEndpoint is a PollEndpoint that is known in advance.
func FixedPollEndpoint(u *url.URL) PollEndpoint { return func() *url.URL { return u } }

// PollerOptions say how a Poller polls. Read when the poller works, so configure them before
// Start. Start from DefaultPollerOptions.
type PollerOptions struct {
	// AckStore keeps the acknowledgements until a poll request carried them; an
	// InMemoryPollAckStore by default.
	AckStore PollAckStore
	// Policy checks the poll endpoint of the stream and decides which redirects are followed;
	// the strict one (https, or http on loopback) by default.
	Policy URIPolicy
	// MaxAckBatch is the most acknowledgements and error reports one request carries, the rest
	// goes with the next one; 1000 by default.
	MaxAckBatch int
	// Metrics records the polls. Nothing by default.
	Metrics Metrics
	// Interval is the time between two polls, 30 seconds by default. With long polling, the
	// pause after a failed request or after a transmitter answered an empty long poll at once.
	Interval time.Duration
	// InitialDelay is how long Start waits before the first poll, nothing by default.
	InitialDelay time.Duration
	// EndpointRetry is how soon the poller looks again while the poll endpoint of the stream is
	// not known yet, one second by default; never longer than the interval.
	EndpointRetry time.Duration
	// LongPollingHold switches to long polling (RFC 8936, section 2.5) when positive: the first
	// request of a poll asks the transmitter to hold it until SETs are available
	// (returnImmediately: false), and a running poller sends the next request as soon as a
	// response was handled. The value is how long the transmitter holds a request, part of the
	// agreement with it (section 2.2); the request waits that long plus LongPollMargin for the
	// response. Zero, the default, is short polling.
	LongPollingHold time.Duration
	// FlushOnStop says whether Stop sends the pending acknowledgements with a last request, so
	// that the transmitter does not deliver the SETs again after a restart; true by default.
	FlushOnStop bool
	// MaxEvents is the maximum number of SETs fetched with one request, 100 by default.
	MaxEvents int
	// Transmitter is the issuer of the transmitter that is polled, for the metrics and as the
	// key of its acknowledgements in the AckStore; the poll endpoint if "".
	Transmitter string
	// RateLimitFallback is how long to pause polling after a 429 Too Many Requests without a
	// Retry-After header; zero, the default, polls again at the regular interval.
	RateLimitFallback time.Duration
	// MaxPause is the longest pause a Retry-After header or the rate limit fallback can cause,
	// 5 minutes by default.
	MaxPause time.Duration
	// Timeout is how long a request that is answered immediately waits for the response;
	// DefaultHTTPTimeout if zero.
	Timeout time.Duration
	// MaxResponseSize is the largest poll response read, in bytes; DefaultMaxResponseSize if
	// zero. MaxEvents SETs must fit.
	MaxResponseSize int64
	// Clock is the clock the pauses the transmitter asks for are measured by.
	Clock Clock
	// Log is where the poller logs; discarded if nil.
	Log *slog.Logger
}

// DefaultPollerOptions are the defaults: short polling every 30 seconds, 100 SETs and 1000
// acknowledgements per request, a flush on stop, pauses of at most 5 minutes.
func DefaultPollerOptions() PollerOptions {
	return PollerOptions{
		MaxAckBatch:   1000,
		Interval:      30 * time.Second,
		EndpointRetry: time.Second,
		FlushOnStop:   true,
		MaxEvents:     100,
		MaxPause:      5 * time.Minute,
		Clock:         SystemClock,
	}
}

// PollError says that a poll request failed.
type PollError struct {
	Message string
	Cause   error
}

func (e *PollError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Unwrap is the cause.
func (e *PollError) Unwrap() error { return e.Cause }

const (
	maxRequestsPerPoll = 100
	// LongPollMargin is how much longer than the hold time of the transmitter a long poll waits
	// for the response.
	LongPollMargin = 10 * time.Second
	// a long poll that comes back empty faster than this was not held: the transmitter does not
	// support long polling, and the poller waits the interval before the next request
	minHold = time.Second
)

type pollResult struct {
	fetched         int
	skipped         bool
	endpointUnknown bool
}

// Poller fetches SETs from the poll endpoint of the transmitter (RFC 8936).
//
// A SET is acknowledged once it was handled. An invalid SET is reported as an error to the
// transmitter. A SET that could not be handled is neither acknowledged nor reported, the
// transmitter delivers it again with a later poll. Acknowledgements and error reports ride on
// the next poll request (section 2.4) and wait in the PollAckStore until that request succeeded.
//
// By default the poller polls at a fixed interval and asks the transmitter to answer right away
// (returnImmediately: true, short polling). With long polling (PollerOptions.LongPollingHold) it
// keeps one request outstanding instead. A backlog is fetched with immediate requests in both
// modes.
//
// Until the poll endpoint of the stream is known, typically because the StreamRegistrar is
// still registering the stream when the poller starts, the poller looks again every
// EndpointRetry rather than waiting the interval. WakeUp ends the pause between two polls
// altogether; Transmitter.Start arranges for it when the stream is registered, so that the first
// poll follows the registration at once.
type Poller struct {
	client     *http.Client
	authorizer Authorizer
	endpoint   PollEndpoint
	processor  *Processor
	options    PollerOptions
	log        *slog.Logger

	polling sync.Mutex // held while a poll runs

	mu                   sync.Mutex
	pausedUntil          time.Time
	lastPollAt           time.Time
	lastSuccessfulPollAt time.Time
	lastPollError        string
	cancel               context.CancelFunc
	done                 chan struct{}
	ended                <-chan struct{} // the Done of the context the goroutine runs with
	wake                 chan struct{}
}

// NewPoller is a poller that fetches from endpoint (which supplies nil as long as the endpoint
// is not known), calls the transmitter with client (http.DefaultClient if nil), authorizes the
// requests with authorizer (a TokenProvider, BearerToken, StaticHeaders, ...; none if nil) and
// processes the SETs with processor. It panics if an option is out of range: interval, max
// events, max ack batch, max pause and endpoint retry must be positive.
func NewPoller(client *http.Client, authorizer Authorizer, endpoint PollEndpoint, processor *Processor, options PollerOptions) *Poller {
	if options.Interval <= 0 || options.MaxEvents <= 0 || options.MaxAckBatch <= 0 || options.MaxPause <= 0 || options.EndpointRetry <= 0 {
		panic("receiver: PollerOptions interval, max events, max ack batch, max pause and endpoint retry must be positive")
	}
	if options.LongPollingHold < 0 {
		panic("receiver: PollerOptions.LongPollingHold must not be negative")
	}
	if options.AckStore == nil {
		options.AckStore = NewInMemoryPollAckStore()
	}
	if options.Metrics == nil {
		options.Metrics = NoopMetrics{}
	}
	if options.Clock == nil {
		options.Clock = SystemClock
	}
	if authorizer == nil {
		authorizer = NoAuthorization{}
	}
	return &Poller{client: orDefault(client), authorizer: authorizer, endpoint: endpoint, processor: processor, options: options,
		log: orDiscard(options.Log), wake: make(chan struct{}, 1)}
}

// Options say how the poller polls.
func (p *Poller) Options() PollerOptions { return p.options }

// IsLongPolling reports whether the poller long polls.
func (p *Poller) IsLongPolling() bool { return p.options.LongPollingHold > 0 }

// Start starts polling the transmitter in a goroutine of its own: periodically, or with one
// request always outstanding when long polling, until ctx is cancelled or Stop is called.
// Without it, SETs are only fetched by calling PollNow. Calling it again while running has no
// effect; once ctx was cancelled, Start starts it again, also while the goroutine of the
// earlier Start is still on its way out.
func (p *Poller) Start(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil && !closed(p.ended) {
		return
	}
	ctx, p.cancel = context.WithCancel(ctx)
	p.done = make(chan struct{})
	p.ended = ctx.Done()
	go p.run(ctx, p.done)
}

// Stop stops polling: ends the polling goroutine, cancelling an outstanding long poll, and
// sends the pending acknowledgements with a last request (with ctx) unless FlushOnStop says
// otherwise. The acknowledgements are sent also when the goroutine ended before, because the
// context of Start was cancelled.
func (p *Poller) Stop(ctx context.Context) {
	p.mu.Lock()
	cancel, done := p.cancel, p.done
	p.cancel, p.done, p.ended = nil, nil, nil
	p.mu.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			// a handler is still running; the goroutine ends once it returns, as its context
			// is cancelled
			p.log.Warn("The polling goroutine is still handling a SET; it ends after the handlers return")
		}
	}
	if p.options.FlushOnStop {
		p.flushAcks(ctx)
	}
}

// IsRunning reports whether the polling goroutine runs.
func (p *Poller) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cancel != nil
}

// WakeUp ends the pause between two polls, so that the next poll runs now, on the poller's
// goroutine and with its error handling. Does nothing while the poller is not running; PollNow
// polls on the caller's goroutine regardless.
func (p *Poller) WakeUp() {
	if !p.IsRunning() {
		return
	}
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// LastPollAt is when the transmitter was last polled, zero if it was not polled yet.
func (p *Poller) LastPollAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastPollAt
}

// LastSuccessfulPollAt is when the transmitter was last polled successfully, zero if never.
func (p *Poller) LastSuccessfulPollAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastSuccessfulPollAt
}

// LastPollError is why the last poll failed, "" if it succeeded or none was made yet.
func (p *Poller) LastPollError() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastPollError
}

// PausedUntil is until when the transmitter asked not to be polled, zero if it did not.
func (p *Poller) PausedUntil() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pausedUntil.After(p.options.Clock()) {
		return p.pausedUntil
	}
	return time.Time{}
}

// PendingAckCount is the number of acknowledgements and error reports waiting for the next poll
// request.
func (p *Poller) PendingAckCount(ctx context.Context) int {
	key := p.ackKey()
	if key == "" {
		return 0
	}
	size, err := p.options.AckStore.Size(ctx, key)
	if err != nil {
		return 0
	}
	return size
}

// PollNow fetches and processes the SETs that are available at the transmitter and acknowledges
// them, with the request answered immediately whether or not long polling is on. One poll runs
// at a time: a call while another is in progress returns right away.
//
// It returns the number of SETs fetched, 0 as well if the poll endpoint is not known yet, the
// transmitter asked to slow down or a poll is in progress.
func (p *Poller) PollNow(ctx context.Context) (int, error) {
	if !p.polling.TryLock() {
		p.log.Debug("Not polling, a poll is in progress")
		return 0, nil
	}
	defer p.polling.Unlock()
	result, err := p.poll(ctx, false)
	return result.fetched, err
}

func (p *Poller) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	// the goroutine clears its own state when the context of Start ends, so that IsRunning
	// tells the truth and Start works again; not when Stop took the state already
	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.done == done {
			p.cancel, p.done, p.ended = nil, nil, nil
		}
	}()
	options := p.options
	if options.InitialDelay > 0 {
		select {
		case <-time.After(options.InitialDelay):
		case <-ctx.Done():
			return
		}
	}
	for ctx.Err() == nil {
		// a wake-up during a poll is not kept: a registration that completes meanwhile is
		// picked up by the endpoint retry
		select {
		case <-p.wake:
		default:
		}
		started := time.Now()
		result, err := p.pollLocked(ctx)
		if ctx.Err() != nil {
			return
		}
		pause := options.Interval
		switch {
		case err != nil:
			p.log.Warn("Could not poll the SSF transmitter", "error", err)
		case result.endpointUnknown:
			// the stream is still being registered: look again soon
			pause = min(options.EndpointRetry, options.Interval)
		case result.skipped:
			pause = p.pauseWhileSkipped()
		case p.IsLongPolling():
			held := result.fetched > 0 || time.Since(started) >= minHold
			if held {
				pause = 0
			}
		}
		if pause > 0 {
			select {
			case <-time.After(pause):
			case <-p.wake:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (p *Poller) pollLocked(ctx context.Context) (pollResult, error) {
	if !p.polling.TryLock() {
		return pollResult{skipped: true}, nil
	}
	defer p.polling.Unlock()
	return p.poll(ctx, p.IsLongPolling())
}

func (p *Poller) pauseWhileSkipped() time.Duration {
	if until := p.PausedUntil(); !until.IsZero() {
		if untilResume := until.Sub(p.options.Clock()); untilResume > p.options.Interval {
			return untilResume
		}
	}
	return p.options.Interval
}

func (p *Poller) poll(ctx context.Context, hold bool) (pollResult, error) {
	endpoint := p.endpoint()
	if endpoint == nil {
		p.log.Debug("Not polling, the poll endpoint of the SSF stream is not known yet")
		return pollResult{skipped: true, endpointUnknown: true}, nil
	}
	if until := p.PausedUntil(); !until.IsZero() {
		p.log.Debug("Not polling, the SSF transmitter asked to wait", "until", until)
		return pollResult{skipped: true}, nil
	}
	p.mu.Lock()
	p.lastPollAt = p.options.Clock()
	p.mu.Unlock()
	key := p.ackKeyFor(endpoint)
	result, err := p.pollRequests(ctx, endpoint, key, hold)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.lastPollError = err.Error()
	} else {
		p.lastSuccessfulPollAt = p.options.Clock()
		p.lastPollError = ""
	}
	return result, err
}

func (p *Poller) pollRequests(ctx context.Context, endpoint *url.URL, key string, hold bool) (pollResult, error) {
	fetched := 0
	moreAvailable := true
	for request := 0; moreAvailable && request < maxRequestsPerPoll; request++ {
		// only the first request of a poll is held, a backlog is fetched right away
		response, err := p.request(ctx, endpoint, key, p.options.MaxEvents, !(hold && request == 0))
		if err != nil {
			return pollResult{}, err
		}
		sets := setsOf(response)
		for _, set := range sets {
			p.process(ctx, key, set.jti, set.encoded)
		}
		fetched += len(sets)
		more, _ := response["moreAvailable"].(bool)
		moreAvailable = more && len(sets) > 0
	}
	if size, err := p.options.AckStore.Size(ctx, key); !hold && err == nil && size > 0 {
		// acknowledge right away instead of with the next poll; a long poll sends its next
		// request at once anyway
		response, err := p.request(ctx, endpoint, key, 0, true)
		if err != nil {
			return pollResult{}, err
		}
		sets := setsOf(response)
		for _, set := range sets {
			p.process(ctx, key, set.jti, set.encoded)
		}
		fetched += len(sets)
	}
	return pollResult{fetched: fetched}, nil
}

func (p *Poller) process(ctx context.Context, key, jti, encodedSET string) {
	var ack *PendingAck
	var err error
	// RFC 8936, section 2.3: the member name of a SET in sets is its jti, and the receiver
	// acknowledges by that name. A SET filed under another jti is not handled: an
	// acknowledgement by the name would clear a different SET at the transmitter
	if actual := ssf.StringMember(UnverifiedPayload(encodedSET), "jti"); actual != "" && actual != jti {
		err = Rejected(InvalidRequest, "The SET is listed under the jti %s but carries the jti %s", jti, actual)
	} else {
		_, err = p.processor.Process(ctx, encodedSET, ssf.Poll)
	}
	switch {
	case err == nil:
		a := Ack(jti)
		ack = &a
	case RejectionOf(err) != nil:
		rejected := RejectionOf(err)
		p.log.Warn("Rejecting polled SET", "jti", jti, "code", string(rejected.Code), "description", rejected.Description)
		a := AckError(jti, rejected.Code, rejected.Description)
		ack = &a
	case errors.Is(err, ErrInProgress):
		// another instance is on it, the transmitter delivers the SET again
		p.log.Debug("Not acknowledging polled SET, another instance is handling it", "jti", jti)
	default:
		// not acknowledged, the transmitter delivers the SET again
		p.log.Warn("Could not process polled SET", "jti", jti, "error", err)
	}
	if ack == nil {
		return
	}
	if err := p.options.AckStore.Record(ctx, key, *ack); err != nil {
		p.log.Warn("Could not record the acknowledgement of the polled SET", "jti", jti, "error", err)
	}
	p.reportPending(ctx, key)
}

func (p *Poller) reportPending(ctx context.Context, key string) {
	if size, err := p.options.AckStore.Size(ctx, key); err == nil {
		p.options.Metrics.PendingAcksChanged(p.options.Transmitter, size)
	}
}

// request sends one poll request with the pending acknowledgements and returns the parsed
// response body. Every poll request goes through it, the one that flushes the acknowledgements
// on Stop included, so the endpoint is checked here.
func (p *Poller) request(ctx context.Context, endpoint *url.URL, key string, maxEvents int, returnImmediately bool) (ssf.Claims, error) {
	options := p.options
	// the endpoint of a registered stream comes from the transmitter and may change: checked
	// like a configured one, the receiver's token must not go to http
	if err := options.Policy.CheckEndpoint(endpoint, "the poll endpoint of the SSF stream"); err != nil {
		return nil, err
	}
	pending, err := options.AckStore.Pending(ctx, key, options.MaxAckBatch)
	if err != nil {
		return nil, &PollError{Message: "Could not read the pending acknowledgements", Cause: err}
	}
	var acks []any
	errs := map[string]any{}
	for _, ack := range pending {
		if ack.IsError() {
			report := map[string]any{"err": string(ack.Error)}
			if ack.Description != "" {
				report["description"] = ack.Description
			}
			errs[ack.JTI] = report
		} else {
			acks = append(acks, ack.JTI)
		}
	}
	body := map[string]any{"maxEvents": maxEvents, "returnImmediately": returnImmediately}
	if len(acks) > 0 {
		body["ack"] = acks
	}
	if len(errs) > 0 {
		body["setErrs"] = errs
	}
	jsonBody, _ := json.Marshal(body)
	timeout := options.Timeout
	if !returnImmediately && options.LongPollingHold > 0 {
		timeout = options.LongPollingHold + LongPollMargin
	}
	started := time.Now()
	// not retried: the poller has its interval, and a 429 or 503 pauses it below
	response, err := exchange(WithEndpoint(ctx, EndpointPoll), p.client, p.authorizer, p.options.Policy, RetryOptions{}, timeout, options.MaxResponseSize, http.MethodPost, endpoint, jsonBody)
	if err != nil {
		options.Metrics.PollCompleted(options.Transmitter, time.Since(started), false)
		return nil, &PollError{Message: fmt.Sprintf("Poll request to %s failed", endpoint), Cause: err}
	}
	if !response.successful() {
		options.Metrics.PollCompleted(options.Transmitter, time.Since(started), false)
		p.pauseIfAsked(response)
		return nil, &PollError{Message: fmt.Sprintf("Poll request to %s failed with status %d", endpoint, response.status)}
	}
	parsed := ssf.Claims{}
	if len(strings.TrimSpace(string(response.body))) > 0 {
		var value any
		if err := json.Unmarshal(response.body, &value); err != nil {
			options.Metrics.PollCompleted(options.Transmitter, time.Since(started), false)
			return nil, &PollError{Message: fmt.Sprintf("Poll request to %s failed: the response is not JSON", endpoint), Cause: err}
		}
		if object := ssf.Object(value); object != nil {
			parsed = object
		}
	}
	if len(pending) > 0 {
		jtis := make([]string, 0, len(pending))
		for _, ack := range pending {
			jtis = append(jtis, ack.JTI)
		}
		if err := options.AckStore.Remove(ctx, key, jtis); err != nil {
			p.log.Warn("Could not remove the delivered acknowledgements", "error", err)
		}
		p.reportPending(ctx, key)
	}
	options.Metrics.PollCompleted(options.Transmitter, time.Since(started), true)
	return parsed, nil
}

// flushAcks sends the pending acknowledgements with a request that asks for no SETs, best
// effort.
func (p *Poller) flushAcks(ctx context.Context) {
	endpoint := p.endpoint()
	if endpoint == nil {
		return
	}
	key := p.ackKeyFor(endpoint)
	if size, err := p.options.AckStore.Size(ctx, key); err != nil || size == 0 {
		return
	}
	if !p.polling.TryLock() {
		return
	}
	defer p.polling.Unlock()
	if _, err := p.request(ctx, endpoint, key, 0, true); err != nil {
		p.log.Debug("Could not acknowledge the pending SETs before stopping, they are sent with the next poll", "error", err)
		return
	}
	p.log.Debug("Acknowledged the pending SETs before stopping")
}

func (p *Poller) ackKey() string {
	if p.options.Transmitter != "" {
		return p.options.Transmitter
	}
	if endpoint := p.endpoint(); endpoint != nil {
		return endpoint.String()
	}
	return ""
}

func (p *Poller) ackKeyFor(endpoint *url.URL) string {
	if p.options.Transmitter != "" {
		return p.options.Transmitter
	}
	return endpoint.String()
}

// pauseIfAsked honours a Retry-After header in seconds on 429 and 503 (RFC 9110, section
// 10.2.3), and the rate limit fallback on a 429 without one; a date instead of seconds is
// treated like no header.
func (p *Poller) pauseIfAsked(response *httpResponse) {
	options := p.options
	var pause time.Duration
	if response.status == http.StatusTooManyRequests || response.status == http.StatusServiceUnavailable {
		if seconds, err := strconv.ParseInt(strings.TrimSpace(response.header.Get("Retry-After")), 10, 64); err == nil && seconds >= 0 {
			pause = time.Duration(seconds) * time.Second
		}
	}
	if pause == 0 && response.status == http.StatusTooManyRequests {
		pause = options.RateLimitFallback
	}
	if pause <= 0 {
		return
	}
	if pause > options.MaxPause {
		pause = options.MaxPause
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pausedUntil = options.Clock().Add(pause)
}

type polledSET struct{ jti, encoded string }

// setsOf are the SETs of a poll response by jti, in the order of their jti so that the order is
// deterministic.
func setsOf(response ssf.Claims) []polledSET {
	sets := ssf.ObjectMember(response, "sets")
	result := make([]polledSET, 0, len(sets))
	for _, jti := range sortedKeys(sets) {
		result = append(result, polledSET{jti: jti, encoded: stringOf(sets[jti])})
	}
	return result
}

func sortedKeys(object ssf.Claims) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
