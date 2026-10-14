package receiver

import (
	"context"
	"errors"
	"net/http"

	"github.com/easyssf/easyssf-go/ssf"
)

// Stream management (SSF 1.0, section 8): the management API client and the registrar that
// looks the receiver's stream up, or reuses, updates or creates it. SKETCH: the shapes are here,
// the bodies are a port of stream.rs of the Rust port (SsfStreamClient, SsfReceiverStream,
// SsfStreamVerification, SsfStreamRegistrar) still to do.

// ErrNotImplemented marks what the sketch leaves to port.
var ErrNotImplemented = errors.New("easyssf-go: not implemented yet in this sketch")

// TokenProvider provides the access token the receiver authenticates with when it calls the
// stream management and poll endpoints of the transmitter. Implement it to obtain the token in
// another way than the built-in ones: a fixed token (FixedToken) or the client credentials grant
// (to port from transmitter.rs: ClientCredentialsSsfTransmitterTokenProvider).
type TokenProvider interface {
	// AccessToken is a token to send as bearer token, "" for none. forceRefresh asks for a new
	// token after a 401.
	AccessToken(ctx context.Context, forceRefresh bool) (string, error)
}

// FixedToken is a TokenProvider with a token configured out of band.
type FixedToken string

// AccessToken implements TokenProvider.
func (t FixedToken) AccessToken(context.Context, bool) (string, error) { return string(t), nil }

// NoToken is a TokenProvider for transmitters whose endpoints need no authentication.
type NoToken struct{}

// AccessToken implements TokenProvider.
func (NoToken) AccessToken(context.Context, bool) (string, error) { return "", nil }

// StreamClient calls the stream management endpoints of one transmitter (SSF 1.0, section 8.1):
// configuration, status, subjects and verification.
type StreamClient struct {
	metadata *MetadataResolver
	client   *http.Client
	tokens   TokenProvider
}

// NewStreamClient is a client over the transmitter's metadata.
func NewStreamClient(metadata *MetadataResolver, client *http.Client, tokens TokenProvider) *StreamClient {
	return &StreamClient{metadata: metadata, client: orDefault(client), tokens: tokens}
}

// GetStreams lists the streams of this receiver (GET configuration_endpoint).
func (c *StreamClient) GetStreams(ctx context.Context) ([]*ssf.StreamConfiguration, error) {
	return nil, ErrNotImplemented
}

// GetStream reads one stream (GET configuration_endpoint?stream_id=).
func (c *StreamClient) GetStream(ctx context.Context, streamID string) (*ssf.StreamConfiguration, error) {
	return nil, ErrNotImplemented
}

// CreateStream creates a stream (POST configuration_endpoint).
func (c *StreamClient) CreateStream(ctx context.Context, stream *ssf.StreamConfiguration) (*ssf.StreamConfiguration, error) {
	return nil, ErrNotImplemented
}

// UpdateStream replaces a stream (PUT configuration_endpoint).
func (c *StreamClient) UpdateStream(ctx context.Context, stream *ssf.StreamConfiguration) (*ssf.StreamConfiguration, error) {
	return nil, ErrNotImplemented
}

// DeleteStream deletes a stream (DELETE configuration_endpoint?stream_id=).
func (c *StreamClient) DeleteStream(ctx context.Context, streamID string) error {
	return ErrNotImplemented
}

// GetStatus reads the status of a stream (GET status_endpoint).
func (c *StreamClient) GetStatus(ctx context.Context, streamID string) (*ssf.StreamStatus, error) {
	return nil, ErrNotImplemented
}

// UpdateStatus sets the status of a stream (POST status_endpoint).
func (c *StreamClient) UpdateStatus(ctx context.Context, status ssf.StreamStatus) (*ssf.StreamStatus, error) {
	return nil, ErrNotImplemented
}

// AddSubject adds a subject to a stream (POST add_subject_endpoint).
func (c *StreamClient) AddSubject(ctx context.Context, streamID string, subject ssf.Claims, verified bool) error {
	return ErrNotImplemented
}

// RemoveSubject removes a subject from a stream (POST remove_subject_endpoint).
func (c *StreamClient) RemoveSubject(ctx context.Context, streamID string, subject ssf.Claims) error {
	return ErrNotImplemented
}

// RequestVerification asks for a verification event with the given state (POST
// verification_endpoint, SSF 1.0, section 8.1.4.1).
func (c *StreamClient) RequestVerification(ctx context.Context, streamID, state string) error {
	return ErrNotImplemented
}

// ReceiverStream is the stream the receiver wants at the transmitter, from its configuration:
// the delivery (push with the endpoint and authorization header, or poll), the events requested
// and the description.
type ReceiverStream struct {
	Wanted *ssf.StreamConfiguration
	// ID is the stream to look up instead of creating one, "" to reuse or create by delivery.
	ID string
	// Management is StreamManagementNone or StreamManagementReceiver.
	Management string
	// DeleteOnShutdown deletes a stream the receiver created when it stops.
	DeleteOnShutdown bool
}

// StreamRegistrarState is where the registrar is.
type StreamRegistrarState int

const (
	// StreamNotStarted: Start was not called.
	StreamNotStarted StreamRegistrarState = iota
	// StreamRegistering: the transmitter is being contacted, with retries.
	StreamRegistering
	// StreamRegistered: the stream is known and current.
	StreamRegistered
	// StreamFailed: registration gave up; Health reports it.
	StreamFailed
)

// StreamRegistrar looks the stream up or registers it in the background with retries, and
// exposes the result: the audience the SETs carry and the poll endpoint. SKETCH.
type StreamRegistrar struct {
	client   *StreamClient
	wanted   ReceiverStream
	current  *ssf.StreamConfiguration
	state    StreamRegistrarState
	listener func(*ssf.StreamConfiguration)
}

// NewStreamRegistrar registers wanted through client; listener, if not nil, sees every
// configuration the transmitter returns.
func NewStreamRegistrar(client *StreamClient, wanted ReceiverStream, listener func(*ssf.StreamConfiguration)) *StreamRegistrar {
	return &StreamRegistrar{client: client, wanted: wanted, listener: listener}
}

// Start begins registering in the background; it returns at once. ctx cancels the retries.
func (r *StreamRegistrar) Start(ctx context.Context) { r.state = StreamRegistering }

// Stop ends the background work and, if configured, deletes the stream.
func (r *StreamRegistrar) Stop(ctx context.Context) error { return nil }

// State is where the registrar is.
func (r *StreamRegistrar) State() StreamRegistrarState { return r.state }

// Current is the stream as the transmitter last returned it, nil before registration.
func (r *StreamRegistrar) Current() *ssf.StreamConfiguration { return r.current }

// StreamVerification tracks the state of a requested verification event (SSF 1.0, section
// 8.1.4.1): it hands out a state, and Check rejects a verification event whose state is not the
// pending one with InvalidState. SKETCH.
type StreamVerification struct{}

// Check validates a stream verification event; the processor calls it through
// ProcessorOptions.StreamVerifications.
func (v *StreamVerification) Check(event *Context) error { return nil }
