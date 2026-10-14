package conformance

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// RunStatus is where a Run stands.
type RunStatus string

const (
	RunStarting      RunStatus = "STARTING"
	RunRunning       RunStatus = "RUNNING"
	RunFinished      RunStatus = "FINISHED"
	RunRefusedStream RunStatus = "REFUSED_STREAM"
	RunFailed        RunStatus = "FAILED"
	RunStopped       RunStatus = "STOPPED"
)

// LogEntry is a line of the log of a run.
type LogEntry struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

// ReceivedSet is a SET a run received, and what became of it.
type ReceivedSet struct {
	Time    time.Time `json:"time"`
	JTI     string    `json:"jti"`
	Events  []string  `json:"events"`
	Outcome string    `json:"outcome"`
}

// Run is one test run: a receiver assembled from the receiver package that creates its stream at
// the emulated transmitter, plays the operations of its Scenario, accepts the events the
// transmitter delivers and deletes the stream once no more arrive.
//
// Every run has its own receiver (keys, access token, de-duplication), since every test of the
// suite emulates a new transmitter under the same issuer.
type Run struct {
	id           string
	scenario     Scenario
	issuer       string
	delivery     ssf.DeliveryMethod
	settings     ReceiverSettings
	log          *slog.Logger
	metadata     *receiver.MetadataResolver
	streams      *receiver.StreamClient
	verifier     *receiver.JWTVerifier
	processor    *receiver.Processor
	push         *receiver.PushHandler
	poller       *receiver.Poller
	verification *receiver.StreamVerification
	pushHeader   string
	startedAt    time.Time
	idleTimeout  time.Duration

	mu            sync.Mutex
	status        RunStatus
	stream        *ssf.StreamConfiguration
	streamDeleted bool
	lastActivity  time.Time
	entries       []LogEntry
	received      []ReceivedSet
	verified      int
	rejected      int
	cancel        context.CancelFunc
	done          chan struct{}
}

// NewRun is a run of the scenario against the emulated transmitter with the given issuer (the
// test instance of the suite), asking for the delivery method, calling the suite with client.
func NewRun(id string, scenario Scenario, issuer string, delivery ssf.DeliveryMethod, settings ReceiverSettings, client *http.Client, log *slog.Logger) (*Run, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	log = log.With("run", id)
	run := &Run{id: id, scenario: scenario, issuer: issuer, delivery: delivery, settings: settings, log: log,
		startedAt: time.Now(), lastActivity: time.Now(), idleTimeout: settings.IdleTimeout, status: RunStarting}
	metadata, err := receiver.NewMetadataResolver(issuer, nil, client, receiver.URIPolicy{}, log)
	if err != nil {
		return nil, err
	}
	metadata.Timeout = 30 * time.Second
	run.metadata = metadata
	tokens := run.tokenProvider(client)
	run.streams = receiver.NewStreamClient(metadata, client, receiver.BearerToken(tokens))
	run.streams.Timeout = 30 * time.Second
	verification := receiver.NewStreamVerification(run.StreamID)
	verification.Log = log
	keys := receiver.NewResolvedHTTPJWKSetSource(client, func(ctx context.Context) (*url.URL, error) {
		resolved, err := metadata.Resolve(ctx)
		if err != nil {
			return nil, err
		}
		if resolved.JWKSURI() == nil {
			return nil, receiver.Unavailable(nil, "the transmitter metadata has no jwks_uri")
		}
		return resolved.JWKSURI(), nil
	})
	keys.Timeout = 30 * time.Second
	options := receiver.DefaultVerifierOptions()
	// the audience of the stream once it is created, any before
	options.ExpectedAudiencesProvider = func() ([]string, error) {
		if stream := run.Stream(); stream != nil {
			return stream.Audience(), nil
		}
		return nil, nil
	}
	if run.verifier, err = receiver.NewJWTVerifier(issuer, keys, options); err != nil {
		return nil, err
	}
	run.processor = receiver.NewProcessor(&recordingVerifier{run: run}, receiver.NewInMemoryJTIDedupStore(10_000, 0, nil), receiver.ProcessorOptions{
		Log: log,
		StreamVerifications: func(string) func(*receiver.Context) error {
			return func(event *receiver.Context) error {
				err := verification.Check(event)
				if rejected := receiver.RejectionOf(err); rejected != nil {
					run.mu.Lock()
					run.rejected++
					run.mu.Unlock()
					run.record(event.EventToken().JTI(), []string{"SsfStreamVerification"}, fmt.Sprintf("rejected with %s: %s", rejected.Code, rejected.Description))
				}
				return err
			}
		},
	}).AddHandler(receiver.HandlerFunc(run.recordHandledSet))
	run.verification = verification
	secret := make([]byte, 24)
	_, _ = rand.Read(secret)
	run.pushHeader = "Bearer " + base64.RawURLEncoding.EncodeToString(secret)
	run.push = receiver.NewPushHandler(run.processor, run.pushHeader)
	if delivery == ssf.Poll {
		pollerOptions := receiver.DefaultPollerOptions()
		pollerOptions.Interval = settings.PollInterval
		pollerOptions.EndpointRetry = min(settings.PollInterval, time.Second)
		pollerOptions.Transmitter = issuer
		pollerOptions.Timeout = 30 * time.Second
		pollerOptions.Log = log
		run.poller = receiver.NewPoller(client, receiver.BearerToken(tokens), func() *url.URL {
			run.mu.Lock()
			defer run.mu.Unlock()
			if run.stream == nil || run.streamDeleted {
				return nil
			}
			return run.stream.DeliveryEndpointURL()
		}, run.processor, pollerOptions)
	}
	return run, nil
}

func (r *Run) tokenProvider(client *http.Client) receiver.TokenProvider {
	auth := r.settings.Auth
	if auth.Mode == AuthStatic {
		return receiver.FixedToken(auth.AccessToken)
	}
	return &lazyClientCredentials{run: r, client: client}
}

// lazyClientCredentials obtains tokens at the token endpoint of the emulated authorization
// server, which lives next to the transmitter (<issuer>/token); it is looked up with the first
// call, so that a run can start while the suite is down.
type lazyClientCredentials struct {
	run      *Run
	client   *http.Client
	mu       sync.Mutex
	delegate *receiver.ClientCredentialsTokenProvider
}

func (p *lazyClientCredentials) AccessToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	delegate := p.delegate
	p.mu.Unlock()
	if delegate == nil {
		metadata, err := p.run.metadata.Resolve(ctx)
		if err != nil {
			return "", err
		}
		tokenURL, err := url.Parse(metadata.Issuer() + "/token")
		if err != nil {
			return "", err
		}
		auth := p.run.settings.Auth
		options := receiver.DefaultClientCredentialsOptions()
		options.Scopes = auth.Scopes
		options.AuthenticateWithRequestBody = auth.AuthenticateWithRequestBody
		options.Timeout = 30 * time.Second
		delegate = receiver.NewClientCredentialsTokenProvider(p.client, tokenURL, auth.ClientID, auth.ClientSecret, options)
		p.mu.Lock()
		p.delegate = delegate
		p.mu.Unlock()
	}
	return delegate.AccessToken(ctx)
}

func (p *lazyClientCredentials) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.delegate != nil {
		p.delegate.Invalidate()
	}
}

// recordingVerifier records the SETs the verifier rejects.
type recordingVerifier struct{ run *Run }

func (v *recordingVerifier) Verify(ctx context.Context, encodedSET string) (*ssf.EventToken, error) {
	token, err := v.run.verifier.Verify(ctx, encodedSET)
	if rejected := receiver.RejectionOf(err); rejected != nil {
		jti := ssf.StringMember(receiver.UnverifiedPayload(encodedSET), "jti")
		if jti == "" {
			jti = "?"
		}
		v.run.record(jti, nil, fmt.Sprintf("rejected with %s: %s", rejected.Code, rejected.Description))
	}
	return token, err
}

// ID is the id of the run.
func (r *Run) ID() string { return r.id }

// Scenario is the scenario the run plays.
func (r *Run) Scenario() Scenario { return r.scenario }

// Issuer is the issuer of the emulated transmitter.
func (r *Run) Issuer() string { return r.issuer }

// Delivery is the delivery method the run asks for.
func (r *Run) Delivery() ssf.DeliveryMethod { return r.delivery }

// StartedAt is when the run started.
func (r *Run) StartedAt() time.Time { return r.startedAt }

// Status is where the run stands.
func (r *Run) Status() RunStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// Stream is the stream of the run, nil before it was created.
func (r *Run) Stream() *ssf.StreamConfiguration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stream
}

// StreamID is the identifier of the stream, "" before it was created.
func (r *Run) StreamID() string {
	if stream := r.Stream(); stream != nil {
		return stream.StreamID()
	}
	return ""
}

// Log is what the run did so far.
func (r *Run) Log() []LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]LogEntry{}, r.entries...)
}

// ReceivedSets are the SETs the run received.
func (r *Run) ReceivedSets() []ReceivedSet {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ReceivedSet{}, r.received...)
}

// IsActive reports whether the run is starting or running.
func (r *Run) IsActive() bool {
	status := r.Status()
	return status == RunStarting || status == RunRunning
}

// SetIdleTimeout overrides the idle timeout of the settings for this run, before Start.
func (r *Run) SetIdleTimeout(timeout time.Duration) { r.idleTimeout = timeout }

// Start starts the run in a goroutine of its own.
func (r *Run) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, r.cancel = context.WithCancel(ctx)
	r.done = make(chan struct{})
	go r.run(ctx, r.done)
}

// Stop ends the run: the stream is deleted. It returns once the run ended.
func (r *Run) Stop() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// Wait returns once the run ended.
func (r *Run) Wait() {
	r.mu.Lock()
	done := r.done
	r.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Push handles a SET the transmitter pushed to this run.
func (r *Run) Push(ctx context.Context, authorizationHeader string, body []byte) receiver.PushResponse {
	r.touch()
	return r.push.Handle(ctx, authorizationHeader, body)
}

func (r *Run) touch() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastActivity = time.Now()
}

func (r *Run) setStatus(status RunStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = status
}

func (r *Run) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	r.setStatus(RunRunning)
	// the cleanup must not be cancelled with the run
	cleanup := context.WithoutCancel(ctx)
	err := r.execute(ctx)
	switch {
	case err == nil:
		if r.Status() == RunRunning {
			r.setStatus(RunFinished)
		}
	case errors.Is(err, context.Canceled):
		r.logf("Run stopped")
		r.setStatus(RunStopped)
	default:
		r.logf("Run failed: %v", err)
		r.log.Error("Conformance run failed", "error", err)
		r.setStatus(RunFailed)
	}
	if r.poller != nil {
		r.poller.Stop(cleanup)
	}
	r.deleteStream(cleanup)
}

func (r *Run) execute(ctx context.Context) error {
	r.logf("Scenario %s with %s delivery against %s", r.scenario, r.delivery, r.issuer)
	metadata, err := r.metadata.Resolve(ctx)
	if err != nil {
		return err
	}
	r.logf("Transmitter metadata: jwks_uri %v, configuration_endpoint %v", metadata.JWKSURI(), metadata.ConfigurationEndpoint())
	desired := r.desiredStream("easyssf conformance run " + r.id)
	stream, err := r.streams.CreateStream(ctx, desired)
	var mismatch *receiver.IssuerMismatchError
	if errors.As(err, &mismatch) {
		r.logf("Refusing the stream: %v", err)
		r.mu.Lock()
		r.stream = mismatch.Stream
		r.mu.Unlock()
		r.deleteStream(context.WithoutCancel(ctx))
		r.setStatus(RunRefusedStream)
		return nil
	}
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.stream = stream
	r.mu.Unlock()
	endpoint := ""
	if u := stream.DeliveryEndpointURL(); u != nil {
		endpoint = u.String()
	}
	r.logf("Created stream %s: audience %v, delivery %s %s, events delivered %v", stream.StreamID(), stream.Audience(), stream.DeliveryMethodURI(), endpoint, aliases(stream.EventsDelivered()))
	if r.poller != nil {
		r.poller.Start(ctx)
	}
	if r.scenario == CreateDelete {
		return nil
	}
	read, err := r.streams.Stream(ctx, stream.StreamID())
	if err != nil {
		return err
	}
	r.logf("Read stream configuration: events requested %v", aliases(read.EventsRequested()))
	status, err := r.streams.Status(ctx, stream.StreamID())
	if err != nil {
		return err
	}
	r.logf("Read stream status: %s", status.Status)
	if r.scenario == StreamManagement {
		updated, err := r.streams.UpdateStream(ctx, stream.StreamID(), ssf.Claims{"description": desired.Description() + " (updated)"})
		if err != nil {
			return err
		}
		r.logf("Updated stream: description '%s'", updated.Description())
		replaced, err := r.streams.ReplaceStream(ctx, stream.StreamID(), r.desiredStream(desired.Description()+" (replaced)"))
		if err != nil {
			return err
		}
		r.logf("Replaced stream: description '%s'", replaced.Description())
	}
	if err := r.verifyStream(ctx); err != nil {
		return err
	}
	if r.scenario == StatusUpdate {
		paused, err := r.streams.UpdateStatus(ctx, stream.StreamID(), ssf.StreamPaused, "conformance run")
		if err != nil {
			return err
		}
		r.logf("Pausing the stream: %s", paused.Status)
		if err := sleep(ctx, 3*time.Second); err != nil {
			return err
		}
		enabled, err := r.streams.UpdateStatus(ctx, stream.StreamID(), ssf.StreamEnabled, "conformance run")
		if err != nil {
			return err
		}
		r.logf("Enabling the stream: %s", enabled.Status)
	}
	if r.scenario == RemoveSubject {
		if err := r.streams.RemoveSubject(ctx, stream.StreamID(), r.settings.SubjectToRemove); err != nil {
			return err
		}
		r.logf("Removed subject %v from the stream", r.settings.SubjectToRemove)
	}
	idle := r.idleTimeout
	r.logf("Accepting events until none arrived for %s", idle)
	phaseStart := time.Now()
	for {
		if err := sleep(ctx, 500*time.Millisecond); err != nil {
			return err
		}
		now := time.Now()
		r.mu.Lock()
		latest := r.lastActivity
		r.mu.Unlock()
		if latest.Before(phaseStart) {
			latest = phaseStart
		}
		if now.Sub(latest) > idle {
			r.logf("No event for %s", idle)
			return nil
		}
		if now.Sub(r.startedAt) > r.settings.MaxDuration {
			r.logf("Maximum run duration reached")
			return nil
		}
	}
}

// verifyStream asks for a verification event and waits for it, requesting again after a
// rejected one, at most three times; without any event it goes on.
func (r *Run) verifyStream(ctx context.Context) error {
	timeout := r.settings.VerificationTimeout
	for attempt := 1; attempt <= 3; attempt++ {
		r.mu.Lock()
		verifiedBefore, rejectedBefore := r.verified, r.rejected
		r.mu.Unlock()
		state, err := r.verification.RequestVerification(ctx, r.streams, r.StreamID())
		if err != nil {
			return err
		}
		r.logf("Requested stream verification with state %s", state)
		deadline := time.Now().Add(timeout)
		rejectedAgain := false
		for time.Now().Before(deadline) {
			r.mu.Lock()
			verified, rejected := r.verified, r.rejected
			r.mu.Unlock()
			if verified > verifiedBefore {
				return nil
			}
			if rejected > rejectedBefore {
				r.logf("Rejected a verification event, requesting the verification again")
				rejectedAgain = true
				break
			}
			if err := sleep(ctx, 200*time.Millisecond); err != nil {
				return err
			}
		}
		if !rejectedAgain {
			r.logf("No verification event within %s, going on without it", timeout)
			return nil
		}
	}
	return nil
}

func (r *Run) desiredStream(description string) *ssf.StreamConfiguration {
	if r.delivery == ssf.Poll {
		return ssf.PollStream(r.settings.EventsRequested, description)
	}
	pushURL, _ := url.Parse(r.settings.PushURL)
	return ssf.PushStream(pushURL, r.pushHeader, r.settings.EventsRequested, description)
}

func (r *Run) deleteStream(ctx context.Context) {
	r.mu.Lock()
	streamID := ""
	if r.stream != nil {
		streamID = r.stream.StreamID()
	}
	if streamID == "" || r.streamDeleted {
		r.mu.Unlock()
		return
	}
	r.streamDeleted = true
	r.mu.Unlock()
	deleteCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := r.streams.DeleteStream(deleteCtx, streamID); err != nil {
		r.logf("Could not delete stream %s: %v", streamID, err)
		return
	}
	r.logf("Deleted stream %s", streamID)
}

func (r *Run) recordHandledSet(_ context.Context, event *receiver.Context) error {
	token := event.EventToken()
	if event.HasEvent(eventtypes.SSFStreamVerification) {
		state := "no state (initiated by the transmitter)"
		if s := event.Event(eventtypes.SSFStreamVerification)["state"]; s != nil {
			state = fmt.Sprintf("state %v", s)
		}
		r.logf("Verification event %s accepted, %s", token.JTI(), state)
		r.mu.Lock()
		r.verified++
		r.mu.Unlock()
	}
	r.record(token.JTI(), aliases(event.EventTypes()), "accepted")
	return nil
}

func (r *Run) record(jti string, events []string, outcome string) {
	if events == nil {
		events = []string{}
	}
	r.mu.Lock()
	r.lastActivity = time.Now()
	r.received = append(r.received, ReceivedSet{Time: r.lastActivity, JTI: jti, Events: events, Outcome: outcome})
	r.mu.Unlock()
	r.logf("SET %s %v: %s", jti, events, outcome)
}

func (r *Run) logf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	r.mu.Lock()
	r.entries = append(r.entries, LogEntry{Time: time.Now(), Message: message})
	r.mu.Unlock()
	r.log.Info(message)
}

func aliases(eventTypes []string) []string {
	result := make([]string, 0, len(eventTypes))
	for _, eventType := range eventTypes {
		result = append(result, eventtypes.AliasOf(eventType))
	}
	sort.Strings(result)
	return result
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// Runner starts and keeps the current Run. There is at most one run at a time, since the
// suite's tests run one after another and the push endpoint belongs to the current run.
type Runner struct {
	settings ReceiverSettings
	client   *http.Client
	log      *slog.Logger
	ids      atomic.Int64
	mu       sync.Mutex
	current  *Run
}

// NewRunner is a runner with the settings, calling the suite with client.
func NewRunner(settings ReceiverSettings, client *http.Client, log *slog.Logger) *Runner {
	return &Runner{settings: settings, client: client, log: log}
}

// Settings are the settings of the receiver under test.
func (r *Runner) Settings() ReceiverSettings { return r.settings }

// Start starts a run, stopping the current one if it is still active. issuer is the issuer of
// the emulated transmitter, "" for the configured one; delivery 0 for the configured one;
// idleTimeout 0 for the configured one.
func (r *Runner) Start(ctx context.Context, scenario Scenario, issuer string, delivery ssf.DeliveryMethod, idleTimeout time.Duration) (*Run, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if issuer == "" {
		issuer = r.settings.Issuer
		if issuer == "" {
			return nil, errors.New("the transmitter issuer must be set when no issuer is given for the run")
		}
	}
	if delivery == 0 {
		delivery = r.settings.Delivery
	}
	if r.current != nil && r.current.IsActive() {
		r.current.Stop()
	}
	run, err := NewRun(fmt.Sprint(r.ids.Add(1)), scenario, issuer, delivery, r.settings, r.client, r.log)
	if err != nil {
		return nil, err
	}
	if idleTimeout > 0 {
		run.SetIdleTimeout(idleTimeout)
	}
	r.current = run
	run.Start(ctx)
	return run, nil
}

// Current is the current run, nil if none was started yet.
func (r *Runner) Current() *Run {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}
