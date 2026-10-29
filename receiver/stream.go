package receiver

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// Stream management (SSF 1.0, section 8.1): the client of the management API, the stream of
// the receiver, its registration and the verification events; a port of stream.rs of the Rust
// port and of org.easyssf.receiver.stream.

// StreamError says that a call to the stream management API of the transmitter failed: the
// transmitter could not be called, or answered with an error status.
type StreamError struct {
	// Message says what failed.
	Message string
	// Status is the HTTP status the transmitter answered with, 0 if it did not answer.
	Status int
	// Cause is the underlying error, if any.
	Cause error
}

func (e *StreamError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Unwrap is the cause.
func (e *StreamError) Unwrap() error { return e.Cause }

// StreamStatusOf is the HTTP status a failed call to the stream management API was answered
// with, 0 if err is not a StreamError or the transmitter did not answer.
func StreamStatusOf(err error) int {
	var streamError *StreamError
	if errors.As(err, &streamError) {
		return streamError.Status
	}
	return 0
}

// IssuerMismatchError says that the transmitter created a stream whose issuer is not the issuer
// the transmitter metadata was obtained from (SSF 1.0, section 8.1.1.1). Such a stream must not
// be used.
type IssuerMismatchError struct {
	// ExpectedIssuer is the issuer of the transmitter.
	ExpectedIssuer string
	// Stream is the stream the transmitter created, for example to delete it.
	Stream *ssf.StreamConfiguration
}

func (e *IssuerMismatchError) Error() string {
	return fmt.Sprintf("The transmitter created stream %s with the issuer %q instead of %q", e.Stream.StreamID(), e.Stream.Issuer(), e.ExpectedIssuer)
}

func streamCall(status int, cause error, format string, args ...any) error {
	return &StreamError{Message: fmt.Sprintf(format, args...), Status: status, Cause: cause}
}

// StreamClient calls the stream management API of one transmitter (SSF 1.0, section 8.1):
// configuration, status, subjects and verification. The endpoints are discovered from the
// transmitter metadata.
type StreamClient struct {
	// Timeout is how long a call waits for the response; DefaultHTTPTimeout if zero.
	Timeout time.Duration
	// Retry says how a failed call is tried again; not at all if zero.
	Retry RetryOptions

	metadata   *MetadataResolver
	client     *http.Client
	authorizer Authorizer
}

// NewStreamClient is a client that calls the transmitter with client (http.DefaultClient if
// nil), authorizes its calls with authorizer (a TokenProvider such as FixedToken or
// ClientCredentialsTokenProvider, BearerToken over another one, StaticHeaders, ...; none if
// nil) and finds the endpoints with metadata.
func NewStreamClient(metadata *MetadataResolver, client *http.Client, authorizer Authorizer) *StreamClient {
	if authorizer == nil {
		authorizer = NoAuthorization{}
	}
	return &StreamClient{metadata: metadata, client: orDefault(client), authorizer: authorizer}
}

// Streams lists the streams of this receiver (GET configuration_endpoint).
func (c *StreamClient) Streams(ctx context.Context) ([]*ssf.StreamConfiguration, error) {
	endpoint, err := c.configurationEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	body, err := c.exchange(WithEndpoint(ctx, EndpointConfiguration), http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, nil
	}
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, streamCall(0, err, "The transmitter returned an invalid list of streams")
	}
	switch value := parsed.(type) {
	case []any:
		streams := make([]*ssf.StreamConfiguration, 0, len(value))
		for _, element := range value {
			if claims := ssf.Object(element); claims != nil {
				streams = append(streams, ssf.NewStreamConfiguration(claims))
			}
		}
		return streams, nil
	case map[string]any:
		return []*ssf.StreamConfiguration{ssf.NewStreamConfiguration(value)}, nil
	}
	return nil, streamCall(0, nil, "The transmitter returned an invalid list of streams")
}

// Stream reads the stream with the given identifier (GET configuration_endpoint?stream_id=).
func (c *StreamClient) Stream(ctx context.Context, streamID string) (*ssf.StreamConfiguration, error) {
	endpoint, err := c.configurationEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	body, err := c.exchange(WithEndpoint(ctx, EndpointConfiguration), http.MethodGet, withStreamIDQuery(endpoint, streamID), nil)
	if err != nil {
		return nil, err
	}
	return parseStream(body)
}

// CreateStream creates a stream (POST configuration_endpoint), see ssf.PushStream and
// ssf.PollStream. It returns an IssuerMismatchError if the transmitter created the stream with
// another issuer than its own; the stream must not be used then.
func (c *StreamClient) CreateStream(ctx context.Context, stream *ssf.StreamConfiguration) (*ssf.StreamConfiguration, error) {
	endpoint, err := c.configurationEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	body, err := c.exchange(WithEndpoint(ctx, EndpointConfiguration), http.MethodPost, endpoint, stream.Claims())
	if err != nil {
		return nil, err
	}
	created, err := parseStream(body)
	if err != nil {
		return nil, err
	}
	if created.Issuer() != c.metadata.Issuer() {
		return nil, &IssuerMismatchError{ExpectedIssuer: c.metadata.Issuer(), Stream: created}
	}
	return created, nil
}

// UpdateStream updates the given members of a stream (PATCH configuration_endpoint), the
// others are left as they are.
func (c *StreamClient) UpdateStream(ctx context.Context, streamID string, changes ssf.Claims) (*ssf.StreamConfiguration, error) {
	endpoint, err := c.configurationEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	body, err := c.exchange(WithEndpoint(ctx, EndpointConfiguration), http.MethodPatch, endpoint, withStreamID(changes, streamID))
	if err != nil {
		return nil, err
	}
	return parseStream(body)
}

// ReplaceStream replaces the configuration of a stream (PUT configuration_endpoint).
func (c *StreamClient) ReplaceStream(ctx context.Context, streamID string, stream *ssf.StreamConfiguration) (*ssf.StreamConfiguration, error) {
	endpoint, err := c.configurationEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	body, err := c.exchange(WithEndpoint(ctx, EndpointConfiguration), http.MethodPut, endpoint, withStreamID(stream.Claims(), streamID))
	if err != nil {
		return nil, err
	}
	return parseStream(body)
}

// DeleteStream deletes a stream (DELETE configuration_endpoint?stream_id=).
func (c *StreamClient) DeleteStream(ctx context.Context, streamID string) error {
	endpoint, err := c.configurationEndpoint(ctx)
	if err != nil {
		return err
	}
	_, err = c.exchange(WithEndpoint(ctx, EndpointConfiguration), http.MethodDelete, withStreamIDQuery(endpoint, streamID), nil)
	return err
}

// Status reads the status of a stream (GET status_endpoint).
func (c *StreamClient) Status(ctx context.Context, streamID string) (*ssf.StreamStatus, error) {
	endpoint, err := c.endpoint(ctx, (*ssf.TransmitterMetadata).StatusEndpoint, "status_endpoint")
	if err != nil {
		return nil, err
	}
	body, err := c.exchange(WithEndpoint(ctx, EndpointStatus), http.MethodGet, withStreamIDQuery(endpoint, streamID), nil)
	if err != nil {
		return nil, err
	}
	return parseStatus(body)
}

// UpdateStatus enables, pauses or disables a stream (POST status_endpoint): status is
// ssf.StreamEnabled, ssf.StreamPaused or ssf.StreamDisabled, reason optional.
func (c *StreamClient) UpdateStatus(ctx context.Context, streamID, status, reason string) (*ssf.StreamStatus, error) {
	endpoint, err := c.endpoint(ctx, (*ssf.TransmitterMetadata).StatusEndpoint, "status_endpoint")
	if err != nil {
		return nil, err
	}
	body := ssf.Claims{"status": status}
	if reason != "" {
		body["reason"] = reason
	}
	response, err := c.exchange(WithEndpoint(ctx, EndpointStatus), http.MethodPost, endpoint, withStreamID(body, streamID))
	if err != nil {
		return nil, err
	}
	return parseStatus(response)
}

// AddSubject asks the transmitter to send events about the subject (a subject identifier, see
// ssf.IssSub and friends); verified tells whether the receiver has verified the subject (POST
// add_subject_endpoint).
func (c *StreamClient) AddSubject(ctx context.Context, streamID string, subject ssf.Claims, verified bool) error {
	endpoint, err := c.endpoint(ctx, (*ssf.TransmitterMetadata).AddSubjectEndpoint, "add_subject_endpoint")
	if err != nil {
		return err
	}
	_, err = c.exchange(WithEndpoint(ctx, EndpointAddSubject), http.MethodPost, endpoint, withStreamID(ssf.Claims{"subject": subject, "verified": verified}, streamID))
	return err
}

// RemoveSubject asks the transmitter to no longer send events about the subject (POST
// remove_subject_endpoint).
func (c *StreamClient) RemoveSubject(ctx context.Context, streamID string, subject ssf.Claims) error {
	endpoint, err := c.endpoint(ctx, (*ssf.TransmitterMetadata).RemoveSubjectEndpoint, "remove_subject_endpoint")
	if err != nil {
		return err
	}
	_, err = c.exchange(WithEndpoint(ctx, EndpointRemoveSubject), http.MethodPost, endpoint, withStreamID(ssf.Claims{"subject": subject}, streamID))
	return err
}

// RequestVerification asks the transmitter to send a verification event on the stream (POST
// verification_endpoint, SSF 1.0, section 8.1.4.1); state, if not "", is echoed in the event.
func (c *StreamClient) RequestVerification(ctx context.Context, streamID, state string) error {
	endpoint, err := c.endpoint(ctx, (*ssf.TransmitterMetadata).VerificationEndpoint, "verification_endpoint")
	if err != nil {
		return err
	}
	body := ssf.Claims{}
	if state != "" {
		body["state"] = state
	}
	_, err = c.exchange(WithEndpoint(ctx, EndpointVerification), http.MethodPost, endpoint, withStreamID(body, streamID))
	return err
}

func (c *StreamClient) configurationEndpoint(ctx context.Context) (*url.URL, error) {
	return c.endpoint(ctx, (*ssf.TransmitterMetadata).ConfigurationEndpoint, "configuration_endpoint")
}

func (c *StreamClient) endpoint(ctx context.Context, endpoint func(*ssf.TransmitterMetadata) *url.URL, name string) (*url.URL, error) {
	metadata, err := c.metadata.Resolve(ctx)
	if err != nil {
		return nil, streamCall(0, err, "%v", err)
	}
	u := endpoint(metadata)
	if u == nil {
		return nil, streamCall(0, nil, "The SSF transmitter metadata has no %s", name)
	}
	return u, nil
}

// exchange calls the endpoint and returns the body of a successful response.
func (c *StreamClient) exchange(ctx context.Context, method string, u *url.URL, body ssf.Claims) ([]byte, error) {
	var jsonBody []byte
	if body != nil {
		jsonBody, _ = json.Marshal(body)
	}
	response, err := exchange(ctx, c.client, c.authorizer, c.metadata.Policy(), c.Retry, c.Timeout, method, u, jsonBody)
	if err != nil {
		return nil, streamCall(0, err, "%s %s failed", method, u)
	}
	if !response.successful() {
		return nil, streamCall(response.status, nil, "%s %s failed with status %d: %s", method, u, response.status, string(response.body))
	}
	return response.body, nil
}

func parseStream(body []byte) (*ssf.StreamConfiguration, error) {
	claims, err := parseObject(body)
	if err != nil {
		return nil, err
	}
	return ssf.NewStreamConfiguration(claims), nil
}

func parseStatus(body []byte) (*ssf.StreamStatus, error) {
	claims, err := parseObject(body)
	if err != nil {
		return nil, err
	}
	return &ssf.StreamStatus{StreamID: ssf.StringMember(claims, "stream_id"), Status: ssf.StringMember(claims, "status"), Reason: ssf.StringMember(claims, "reason")}, nil
}

func parseObject(body []byte) (ssf.Claims, error) {
	claims, err := ssf.ParseClaims(body)
	if err != nil {
		return nil, streamCall(0, err, "The transmitter returned an invalid response")
	}
	return claims, nil
}

func withStreamIDQuery(endpoint *url.URL, streamID string) *url.URL {
	u := *endpoint
	query := u.Query()
	query.Set("stream_id", streamID)
	u.RawQuery = query.Encode()
	return &u
}

func withStreamID(body ssf.Claims, streamID string) ssf.Claims {
	withID := ssf.Claims{"stream_id": streamID}
	for name, value := range body {
		withID[name] = value
	}
	return withID
}

// ReceiverStream holds the configuration of the stream this receiver gets its events from, once
// it is known: after the StreamRegistrar has registered or looked up the stream at the
// transmitter. Safe for concurrent use.
type ReceiverStream struct {
	mu            sync.RWMutex
	configuration *ssf.StreamConfiguration
}

// NewReceiverStream is a stream that is not known yet.
func NewReceiverStream() *ReceiverStream { return &ReceiverStream{} }

// Configuration is the configuration of the stream, nil as long as it is not known.
func (s *ReceiverStream) Configuration() *ssf.StreamConfiguration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configuration
}

// SetConfiguration sets the configuration once the stream is known.
func (s *ReceiverStream) SetConfiguration(configuration *ssf.StreamConfiguration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configuration = configuration
}

// StreamID is the identifier of the stream, "" as long as it is not known.
func (s *ReceiverStream) StreamID() string {
	if configuration := s.Configuration(); configuration != nil {
		return configuration.StreamID()
	}
	return ""
}

// Audience is the audiences of the SETs of the stream, empty as long as they are not known.
func (s *ReceiverStream) Audience() []string {
	if configuration := s.Configuration(); configuration != nil {
		return configuration.Audience()
	}
	return nil
}

// PollEndpointURL is the poll endpoint of a stream with poll delivery, nil as long as the stream
// is not known or it is delivered otherwise.
func (s *ReceiverStream) PollEndpointURL() *url.URL {
	configuration := s.Configuration()
	if configuration == nil || configuration.DeliveryMethodURI() != ssf.PollURI {
		return nil
	}
	return configuration.DeliveryEndpointURL()
}

// StreamVerification validates stream verification events (SSF 1.0, section 8.1.4.1) and keeps
// track of the verifications this receiver requested.
//
// A verification event has to be about the stream of the receiver: its sub_id is an opaque
// identifier with the identifier of the stream. If it echoes a state, that has to be a state the
// receiver sent with a verification request that was not answered yet. An event without state
// was initiated by the transmitter and is accepted.
type StreamVerification struct {
	// RejectUnrequestedState rejects a verification event with a state when the receiver is not
	// waiting for the answer to a verification request. By default such an event is accepted,
	// since some transmitters add a state to the verification events they initiate themselves.
	RejectUnrequestedState bool
	// Log is where accepted unrequested states are logged; discarded if nil.
	Log *slog.Logger

	streamID func() string
	mu       sync.Mutex
	pending  map[string]struct{}
}

// NewStreamVerification is a verification for the stream streamID tells the identifier of, ""
// as long as it is not known; the subject of verification events is not checked while it is
// unknown. nil never knows the stream.
func NewStreamVerification(streamID func() string) *StreamVerification {
	if streamID == nil {
		streamID = func() string { return "" }
	}
	return &StreamVerification{streamID: streamID, pending: map[string]struct{}{}}
}

// NewState creates a state for a verification request and remembers it until the verification
// event that echoes it arrived.
func (v *StreamVerification) NewState() string {
	state := randomHex(16)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.pending[state] = struct{}{}
	return state
}

// RequestVerification asks the transmitter to send a verification event on the stream through
// client; it returns the state the verification event has to echo.
func (v *StreamVerification) RequestVerification(ctx context.Context, client *StreamClient, streamID string) (string, error) {
	state := v.NewState()
	if err := client.RequestVerification(ctx, streamID, state); err != nil {
		v.mu.Lock()
		delete(v.pending, state)
		v.mu.Unlock()
		return "", err
	}
	return state, nil
}

// IsPending reports whether a verification request was sent that has not been answered yet.
func (v *StreamVerification) IsPending() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.pending) > 0
}

// Check validates the verification event of a SET, if it has one: a RejectedError with
// InvalidRequest if the event is about another stream, with InvalidState if it echoes a state
// that is not expected. The processor calls it through ProcessorOptions.StreamVerifications.
func (v *StreamVerification) Check(event *Context) error {
	if !event.HasEvent(eventtypes.SSFStreamVerification) {
		return nil
	}
	if expected := v.streamID(); expected != "" {
		// SSF 1.0 8.1.4.1: the sub_id of a verification event is opaque and names the stream
		subjectID := event.EventToken().SubjectID()
		if ssf.StringMember(subjectID, "format") != ssf.FormatOpaque || ssf.StringMember(subjectID, "id") != expected {
			return Rejected(InvalidRequest, "The verification event is not about the stream of this receiver")
		}
	}
	state := stringOf(event.Event(eventtypes.SSFStreamVerification)["state"])
	if state == "" {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.pending[state]; ok {
		delete(v.pending, state)
		return nil
	}
	if len(v.pending) > 0 || v.RejectUnrequestedState {
		return Rejected(InvalidState, "The state of the verification event is not the one this receiver sent")
	}
	orDiscard(v.Log).Debug("Accepting a verification event with a state although no verification was requested")
	return nil
}

// stringOf is a JSON value as text: a string as it is, nil as "", anything else as its JSON.
func stringOf(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	}
	text, _ := json.Marshal(value)
	return string(text)
}

func randomHex(bytes int) string {
	b := make([]byte, bytes)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// StreamRegistrarState is where the registration of a StreamRegistrar stands.
type StreamRegistrarState int

const (
	// StreamNotStarted: Start was not called yet.
	StreamNotStarted StreamRegistrarState = iota
	// StreamRegistering: the stream is being looked up or registered, with retries while the
	// transmitter cannot be reached.
	StreamRegistering
	// StreamRegistered: the stream is known and matches what the receiver wants.
	StreamRegistered
	// StreamFailed: the stream cannot be used, see StreamRegistrar.LastError. Not retried.
	StreamFailed
)

// String is the lowercase name: not_started, registering, registered, failed.
func (s StreamRegistrarState) String() string {
	switch s {
	case StreamRegistering:
		return "registering"
	case StreamRegistered:
		return "registered"
	case StreamFailed:
		return "failed"
	}
	return "not_started"
}

// MaxStreamRetryDelay is the longest delay between two attempts to register the stream.
const MaxStreamRetryDelay = 30 * time.Second

// StreamRegistrar makes the stream of this receiver known after Start, without holding the
// startup of the application up: the transmitter is called in the background and retried until
// it answers.
//
// Either looks up a stream that was created at the transmitter by its identifier
// (NewStreamRegistrarForExistingStream), or manages the stream itself
// (NewStreamRegistrarForManagedStream): it reuses the stream the receiver already has at the
// transmitter, brings it in line with the desired configuration, or creates it.
//
// Listeners (AddListener) learn when the stream is registered; Transmitter.Start uses that to
// have the poller fetch right away instead of an interval later. Set the exported fields before
// Start.
type StreamRegistrar struct {
	// DeleteOnShutdown deletes a stream this receiver manages at the transmitter when it stops.
	DeleteOnShutdown bool
	// InitialRetryDelay is the delay before the first retry, doubled up to MaxStreamRetryDelay;
	// one second if zero.
	InitialRetryDelay time.Duration
	// Log is where the registrar logs; discarded if nil.
	Log *slog.Logger

	client     *StreamClient
	stream     *ReceiverStream
	existingID string
	desired    *ssf.StreamConfiguration

	mu        sync.Mutex
	state     StreamRegistrarState
	lastError string
	listeners []func(*ssf.StreamConfiguration)
	cancel    context.CancelFunc
	done      chan struct{}
	ended     <-chan struct{} // the Done of the context the goroutine runs with
}

// NewStreamRegistrarForExistingStream looks up the stream with the given identifier and makes
// it known through stream.
func NewStreamRegistrarForExistingStream(client *StreamClient, stream *ReceiverStream, streamID string) *StreamRegistrar {
	return &StreamRegistrar{client: client, stream: stream, existingID: streamID}
}

// NewStreamRegistrarForManagedStream discovers, updates or creates the stream the receiver
// wants (ssf.PushStream, ssf.PollStream) and makes it known through stream.
func NewStreamRegistrarForManagedStream(client *StreamClient, stream *ReceiverStream, desired *ssf.StreamConfiguration) *StreamRegistrar {
	return &StreamRegistrar{client: client, stream: stream, desired: desired}
}

// Stream is where the registered stream is made known.
func (r *StreamRegistrar) Stream() *ReceiverStream { return r.stream }

// Current is the stream as the transmitter last returned it, nil before registration.
func (r *StreamRegistrar) Current() *ssf.StreamConfiguration { return r.stream.Configuration() }

// AddListener adds a listener that is told whenever Register succeeded, on the goroutine that
// registered the stream.
func (r *StreamRegistrar) AddListener(listener func(*ssf.StreamConfiguration)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listeners = append(r.listeners, listener)
}

// State is where the registration stands.
func (r *StreamRegistrar) State() StreamRegistrarState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// LastError is why the last attempt to look up or register the stream failed, "" if it
// succeeded or none was made yet.
func (r *StreamRegistrar) LastError() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastError
}

// IsRunning reports whether the background registration runs.
func (r *StreamRegistrar) IsRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cancel != nil
}

// Start starts looking up or registering the stream in the background; it returns at once.
// Cancelling ctx or calling Stop ends the retries. Calling it again while running has no
// effect; once ctx was cancelled, Start starts them again, also while the goroutine of the
// earlier Start is still on its way out.
func (r *StreamRegistrar) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil && !closed(r.ended) {
		return
	}
	r.state = StreamRegistering
	ctx, r.cancel = context.WithCancel(ctx)
	r.done = make(chan struct{})
	r.ended = ctx.Done()
	go r.registerWithRetries(ctx, r.done)
}

// closed reports whether the channel is closed, false for nil.
func closed(c <-chan struct{}) bool {
	select {
	case <-c:
		return c != nil
	default:
		return false
	}
}

// Stop stops the background registration and, if DeleteOnShutdown says so, deletes a stream the
// receiver manages, with ctx.
func (r *StreamRegistrar) Stop(ctx context.Context) {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel, r.done, r.ended = nil, nil, nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	if r.DeleteOnShutdown && r.desired != nil {
		if streamID := r.stream.StreamID(); streamID != "" {
			if err := r.client.DeleteStream(ctx, streamID); err != nil {
				r.log().Warn("Could not delete SSF stream", "stream", streamID, "error", err)
			} else {
				r.log().Info("Deleted SSF stream", "stream", streamID)
			}
		}
	}
}

func (r *StreamRegistrar) log() *slog.Logger { return orDiscard(r.Log) }

func (r *StreamRegistrar) registerWithRetries(ctx context.Context, done chan struct{}) {
	defer close(done)
	// the goroutine clears its own state when the context of Start ends, so that IsRunning
	// tells the truth and Start works again; not when Stop took the state already
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.done == done {
			r.cancel, r.done, r.ended = nil, nil, nil
		}
	}()
	delay := r.InitialRetryDelay
	if delay <= 0 {
		delay = time.Second
	}
	for {
		_, err := r.Register(ctx)
		if err == nil {
			return
		}
		var mismatch *IssuerMismatchError
		if errors.As(err, &mismatch) {
			// trying again would only create another stream that must not be used
			r.log().Error("Not using the SSF stream", "error", err)
			r.setState(StreamFailed, err.Error())
			if streamID := mismatch.Stream.StreamID(); streamID != "" {
				if err := r.client.DeleteStream(ctx, streamID); err != nil {
					r.log().Warn("Could not delete SSF stream", "stream", streamID, "error", err)
				}
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		r.setState(StreamRegistering, err.Error())
		r.log().Warn("Could not set up the SSF stream, trying again", "retry_in", delay, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay *= 2; delay > MaxStreamRetryDelay {
			delay = MaxStreamRetryDelay
		}
	}
}

func (r *StreamRegistrar) setState(state StreamRegistrarState, lastError string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state, r.lastError = state, lastError
}

// Register looks up or registers the stream once, on the caller's goroutine, and makes it known.
func (r *StreamRegistrar) Register(ctx context.Context) (*ssf.StreamConfiguration, error) {
	var stream *ssf.StreamConfiguration
	var action string
	var err error
	if r.desired == nil {
		stream, err = r.client.Stream(ctx, r.existingID)
		action = "Using"
	} else {
		stream, action, err = r.registerManaged(ctx)
	}
	if err != nil {
		return nil, err
	}
	r.stream.SetConfiguration(stream)
	delivered := make([]string, 0, len(stream.EventsDelivered()))
	for _, event := range stream.EventsDelivered() {
		delivered = append(delivered, eventtypes.AliasOf(event))
	}
	endpoint := ""
	if u := stream.DeliveryEndpointURL(); u != nil {
		endpoint = u.String()
	}
	r.log().Info(action+" SSF stream", "stream", stream.StreamID(), "delivery", stream.DeliveryMethodURI(),
		"endpoint", endpoint, "events", delivered, "audience", stream.Audience())
	r.mu.Lock()
	r.state, r.lastError = StreamRegistered, ""
	listeners := append([]func(*ssf.StreamConfiguration){}, r.listeners...)
	r.mu.Unlock()
	for _, listener := range listeners {
		listener(stream)
	}
	return stream, nil
}

func (r *StreamRegistrar) registerManaged(ctx context.Context) (*ssf.StreamConfiguration, string, error) {
	streams, err := r.client.Streams(ctx)
	if err != nil {
		return nil, "", err
	}
	for _, existing := range streams {
		if !hasDesiredDelivery(existing, r.desired) {
			continue
		}
		if hasDesiredEvents(existing, r.desired) {
			return existing, "Using existing", nil
		}
		updated, err := r.client.UpdateStream(ctx, existing.StreamID(), changesFor(r.desired))
		return updated, "Updated", err
	}
	created, err := r.client.CreateStream(ctx, r.desired)
	if err == nil {
		return created, "Created", nil
	}
	// the transmitter allows a single stream per receiver and it is configured differently
	if StreamStatusOf(err) == http.StatusConflict && len(streams) == 1 {
		updated, err := r.client.UpdateStream(ctx, streams[0].StreamID(), changesFor(r.desired))
		return updated, "Updated", err
	}
	return nil, "", err
}

func hasDesiredEvents(stream, desired *ssf.StreamConfiguration) bool {
	resolved := func(events []string) []string {
		set := map[string]struct{}{}
		for _, event := range events {
			set[eventtypes.Resolve(event)] = struct{}{}
		}
		keys := make([]string, 0, len(set))
		for key := range set {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return keys
	}
	have, want := resolved(stream.EventsRequested()), resolved(desired.EventsRequested())
	if len(have) != len(want) {
		return false
	}
	for i := range have {
		if have[i] != want[i] {
			return false
		}
	}
	return true
}

func hasDesiredDelivery(stream, desired *ssf.StreamConfiguration) bool {
	if stream.DeliveryMethodURI() != desired.DeliveryMethodURI() {
		return false
	}
	if stream.DeliveryMethodURI() == ssf.PollURI {
		return true
	}
	have, want := stream.DeliveryEndpointURL(), desired.DeliveryEndpointURL()
	if have == nil || want == nil {
		return have == want
	}
	return have.String() == want.String()
}

func changesFor(desired *ssf.StreamConfiguration) ssf.Claims {
	requested := make([]any, 0, len(desired.EventsRequested()))
	for _, event := range desired.EventsRequested() {
		requested = append(requested, event)
	}
	changes := ssf.Claims{"delivery": desired.Claims()["delivery"], "events_requested": requested}
	if description := desired.Description(); description != "" {
		changes["description"] = description
	}
	return changes
}
