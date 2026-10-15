package receiver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// Receiver assembles the parts for every configured transmitter from a Config (the Spring Boot
// auto-configuration, the .NET AddSsfReceiver and the Rust SsfReceiver): metadata resolution,
// JWK Set source, verifier, token provider, stream client, dedup store, processor with the
// handlers, the push handler, token revocation, session termination, and per transmitter the
// stream registrar and the poller. Start runs the stream registration and polling in the
// background, Health reports what the receiver knows.
type Receiver struct {
	config       Config
	log          *slog.Logger
	client       *http.Client
	transmitters []*Transmitter
	byIssuer     map[string]*Transmitter
	processor    *Processor
	push         *PushHandler
	dedup        JTIDedupStore
	revocations  TokenRevocationStore
	acks         PollAckStore
	metrics      Metrics
	mu           sync.Mutex
	started      bool
}

// Option customizes a Receiver under construction.
type Option func(*options)

type options struct {
	log         *slog.Logger
	client      *http.Client
	clock       Clock
	metrics     Metrics
	handlers    []Handler
	dedup       JTIDedupStore
	revocations TokenRevocationStore
	acks        PollAckStore
	terminator  SessionTerminator
	customizers []func(*Transmitter)
}

// WithLogger logs with the given logger; discarded by default.
func WithLogger(log *slog.Logger) Option { return func(o *options) { o.log = log } }

// WithHTTPClient calls the transmitter with the given client; the TestTransmitter of ssftest
// hands one out that answers in-process. A client without a Timeout by default: the timeout of
// easyssf.receiver.http applies per call, so that a long poll can wait longer than the other
// calls. A Timeout on the given client caps every call, long polls included.
func WithHTTPClient(client *http.Client) Option { return func(o *options) { o.client = client } }

// WithClock replaces the system clock, for tests.
func WithClock(clock Clock) Option { return func(o *options) { o.clock = clock } }

// WithMetrics records what the receiver does.
func WithMetrics(metrics Metrics) Option { return func(o *options) { o.metrics = metrics } }

// WithHandler adds handlers, called in order for every verified SET.
func WithHandler(handlers ...Handler) Option {
	return func(o *options) { o.handlers = append(o.handlers, handlers...) }
}

// WithDedupStore replaces the in-memory dedup store, for example with the one of
// receiver/sqlstore, which is shared between instances.
func WithDedupStore(store JTIDedupStore) Option { return func(o *options) { o.dedup = store } }

// WithTokenRevocationStore replaces the in-memory revocation store.
func WithTokenRevocationStore(store TokenRevocationStore) Option {
	return func(o *options) { o.revocations = store }
}

// WithPollAckStore replaces the in-memory store of the acknowledgements a poller owes.
func WithPollAckStore(store PollAckStore) Option { return func(o *options) { o.acks = store } }

// WithSessionTerminator ends the server-side sessions of the application when a session event
// arrives, see SessionTerminationHandler and easyssf.receiver.session-termination.
func WithSessionTerminator(terminator SessionTerminator) Option {
	return func(o *options) { o.terminator = terminator }
}

// WithTransmitterCustomizer replaces parts of any transmitter before the receiver is assembled,
// for example the Keys of the one named "okta". Called for every transmitter, the default one
// included; Transmitter.Name tells which.
func WithTransmitterCustomizer(customize func(*Transmitter)) Option {
	return func(o *options) { o.customizers = append(o.customizers, customize) }
}

// New validates the configuration and assembles a receiver. Nothing is started and the
// transmitter is not contacted: call Start for that. The push handler works at once.
func New(config Config, opts ...Option) (*Receiver, error) {
	if !config.Enabled {
		return nil, ErrDisabled
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	// the aliases take effect only now, after the whole configuration passed: Validate itself
	// changes nothing
	for alias, uri := range config.EventAliases {
		if err := eventtypes.RegisterAlias(alias, uri); err != nil {
			return nil, err
		}
	}
	o := options{clock: SystemClock, metrics: NoopMetrics{}}
	for _, opt := range opts {
		opt(&o)
	}
	log := orDiscard(o.log)
	client := o.client
	if client == nil {
		client = &http.Client{}
	}
	if userAgent := strings.TrimSpace(config.HTTP.UserAgent); userAgent != "" {
		copied := *client
		copied.Transport = &userAgentTransport{next: client.Transport, userAgent: userAgent}
		client = &copied
	}
	r := &Receiver{config: config, log: log, client: client, byIssuer: map[string]*Transmitter{}, metrics: o.metrics}

	if config.Dedup.Enabled {
		r.dedup = o.dedup
		if r.dedup == nil {
			r.dedup = NewInMemoryJTIDedupStore(config.Dedup.Capacity, config.Dedup.Lease.Std(), o.clock)
		}
	}
	r.revocations = o.revocations
	if r.revocations == nil {
		r.revocations = NewInMemoryTokenRevocationStore(config.Revocation.TTL.Std(), o.clock)
	}
	r.acks = o.acks
	if r.acks == nil {
		r.acks = NewInMemoryPollAckStore()
	}

	// the issuer of a SET selects the transmitter that verifies it; the transmitters are built
	// after the processor, as their pollers need it, and before anything runs
	verifiers := map[string]Verifier{}
	processorOptions := ProcessorOptions{
		Metrics:                  o.metrics,
		Log:                      log,
		UnderstoodSubjectMembers: nonEmpty(config.UnderstoodSubjectMembers, ssf.Members),
		CriticalSubjectMembers:   r.criticalSubjectMembers,
		StreamVerifications:      r.streamVerification,
	}
	if config.Dedup.Enabled {
		// a handler may run longer than the lease: the claim is renewed meanwhile
		processorOptions.ClaimRenewal = config.Dedup.Lease.Std() / 3
	}
	r.processor = NewProcessor(NewIssuerRoutingVerifier(verifiers), r.dedup, processorOptions)
	if config.Revocation.Enabled {
		r.processor.AddHandler(NewTokenRevocationHandler(r.revocations,
			nonEmpty(config.Revocation.SessionEventTypes, DefaultSessionEventTypes), config.Revocation.UserEventTypes, log))
	}
	if config.SessionTermination.Enabled && o.terminator != nil {
		r.processor.AddHandler(NewSessionTerminationHandler(o.terminator,
			nonEmpty(config.SessionTermination.SessionEventTypes, DefaultSessionEventTypes),
			nonEmpty(config.SessionTermination.UserEventTypes, DefaultSessionTerminationUserEventTypes), log))
	}
	r.processor.AddHandler(o.handlers...)

	all := config.AllTransmitters()
	for _, name := range config.TransmitterNames() {
		transmitter, err := r.buildTransmitter(name, all[name], o)
		if err != nil {
			return nil, fmt.Errorf("transmitter %s: %w", name, err)
		}
		for _, customize := range o.customizers {
			customize(transmitter)
		}
		if _, seen := r.byIssuer[transmitter.Issuer]; seen {
			return nil, fmt.Errorf("%s.transmitters: two transmitters have the issuer %s", ConfigurationSection, transmitter.Issuer)
		}
		r.transmitters = append(r.transmitters, transmitter)
		r.byIssuer[transmitter.Issuer] = transmitter
		verifiers[transmitter.Issuer] = transmitter.Verifier
	}

	// with one transmitter the header is checked before the SET is even parsed
	if len(r.transmitters) == 1 {
		r.push = NewPushHandler(r.processor, r.transmitters[0].PushAuthorizationHeader)
	} else {
		r.push = NewPushHandlerByIssuer(r.processor, r.pushAuthorizationHeader)
	}
	return r, nil
}

func (r *Receiver) describe(name, issuer string) string {
	if name == DefaultTransmitterName {
		return issuer
	}
	return fmt.Sprintf("'%s' (%s)", name, issuer)
}

// buildTransmitter builds every part of the transmitter from its configuration, as
// SsfTransmitterFactory does in .NET and transmitter_builder in Rust.
func (r *Receiver) buildTransmitter(name string, config TransmitterConfig, o options) (*Transmitter, error) {
	prefix := config.prefix(name)
	issuer := strings.TrimSpace(config.TransmitterIssuer)
	policy := config.URIPolicy()
	timeout := r.config.HTTP.Timeout.Std()
	var metadataURL *url.URL
	if config.TransmitterMetadataURL != "" {
		u, err := url.Parse(config.TransmitterMetadataURL)
		if err != nil {
			return nil, err
		}
		metadataURL = u
	}
	metadata, err := NewMetadataResolver(issuer, metadataURL, r.client, policy, r.log)
	if err != nil {
		return nil, err
	}
	metadata.Timeout = timeout
	metadata.Retry = r.config.HTTP.Retry.Options()
	// the configured headers go with every call, also those for metadata and keys that need no
	// token
	var headers Authorizer = NoAuthorization{}
	if len(config.Headers) > 0 {
		headers = StaticHeaders(config.Headers)
		metadata.Authorizer = headers
	}
	urls := make([]string, 0, len(metadata.MetadataURLs()))
	for _, u := range metadata.MetadataURLs() {
		urls = append(urls, u.String())
	}
	r.log.Info("SSF transmitter: metadata is resolved from", "transmitter", r.describe(name, issuer), "metadata_urls", urls)
	if config.AllowInsecureHTTP {
		r.log.Warn(prefix+"allow-insecure-http is on, the SSF transmitter is used without TLS. For development only", "transmitter", r.describe(name, issuer))
	}

	tokens := r.tokenProvider(config, timeout, o)
	authorizer := Authorizers{headers, BearerToken(tokens)}
	stream := NewReceiverStream()
	streamClient := NewStreamClient(metadata, r.client, authorizer)
	streamClient.Timeout = timeout
	streamClient.Retry = r.config.HTTP.Retry.Options()
	verification := NewStreamVerification(stream.StreamID)
	verification.Log = r.log

	transmitter := &Transmitter{Name: name, Issuer: issuer, Config: config, Metadata: metadata, Tokens: tokens, Authorizer: authorizer,
		StreamClient: streamClient, Stream: stream, Verification: verification, AutoStartPolling: config.Poll.AutoStartup,
		PushAuthorizationHeader: strings.TrimSpace(config.Push.ExpectedAuthHeader)}

	// the keys
	if config.TransmitterJWKSURL != "" {
		u, err := url.Parse(config.TransmitterJWKSURL)
		if err != nil {
			return nil, err
		}
		source := NewHTTPJWKSetSource(r.client, u)
		source.Clock, source.Timeout = o.clock, timeout
		source.Authorizer, source.Retry, source.Policy = metadata.Authorizer, metadata.Retry, policy
		transmitter.Keys = source
	} else {
		source := NewResolvedHTTPJWKSetSource(r.client, func(ctx context.Context) (*url.URL, error) {
			resolved, err := metadata.Resolve(ctx)
			if err != nil {
				return nil, err
			}
			if resolved.JWKSURI() == nil {
				return nil, Unavailable(nil, "the SSF transmitter metadata of %s has no jwks_uri, configure %stransmitter-jwks-url", issuer, prefix)
			}
			return resolved.JWKSURI(), nil
		})
		source.Clock, source.Timeout = o.clock, timeout
		source.Authorizer, source.Retry, source.Policy = metadata.Authorizer, metadata.Retry, policy
		transmitter.Keys = source
	}

	// the verifier: the audience is the configured one; without one, the audience of the stream
	// once it is registered, and SETs are left unverified (transmitter unavailable) until it is;
	// without a registered stream, any, which the validation allows only with
	// set-validation.allow-any-audience
	verifierOptions := DefaultVerifierOptions()
	verifierOptions.Clock = o.clock
	verifierOptions.MinRSAKeySize = config.SetValidation.MinRSAKeySize
	verifierOptions.RequireTypeHeader = config.SetValidation.RequireTypeHeader
	verifierOptions.ClockSkew = config.SetValidation.ClockSkew.Std()
	verifierOptions.SubjectCompatibility, _ = config.SubjectCompatibility()
	verifierOptions.AcceptedAlgorithms = nil
	for _, algorithm := range config.EffectiveAcceptedAlgorithms() {
		supported, _ := SupportedAlgorithm(algorithm)
		verifierOptions.AcceptedAlgorithms = append(verifierOptions.AcceptedAlgorithms, jose.SignatureAlgorithm(supported))
	}
	if audience := strings.TrimSpace(config.ExpectedAudience); audience != "" {
		verifierOptions.ExpectedAudiences = []string{audience}
	} else if config.RegistersStream() {
		anyAudience := config.SetValidation.AllowAnyAudience
		described := r.describe(name, issuer)
		verifierOptions.ExpectedAudiencesProvider = func() ([]string, error) {
			if stream.Configuration() == nil {
				return nil, Unavailable(nil, "the stream at %s is not registered yet, so the audience of SETs cannot be checked", described)
			}
			audience := stream.Audience()
			if len(audience) == 0 && !anyAudience {
				return nil, Rejected(InvalidAudience, "The stream at %s has no audience (aud), set %[2]sexpected-audience or %[2]sset-validation.allow-any-audience", described, prefix)
			}
			return audience, nil
		}
	} else {
		r.log.Warn(prefix+"expected-audience is not set, SETs that the transmitter issued for other receivers are accepted as well", "transmitter", r.describe(name, issuer))
	}
	if transmitter.Verifier, err = NewJWTVerifier(issuer, transmitter.Keys, verifierOptions); err != nil {
		return nil, err
	}

	// the stream
	if config.RegistersStream() {
		if config.Stream.Management == StreamManagementReceiver {
			transmitter.Registrar = NewStreamRegistrarForManagedStream(streamClient, stream, desiredStream(config))
			transmitter.Registrar.DeleteOnShutdown = config.Stream.DeleteOnShutdown
		} else {
			transmitter.Registrar = NewStreamRegistrarForExistingStream(streamClient, stream, strings.TrimSpace(config.Stream.ID))
		}
		transmitter.Registrar.Log = r.log
	}

	// the poller
	if delivery, _ := config.Delivery(); delivery == ssf.Poll {
		poll := config.Poll
		pollerOptions := DefaultPollerOptions()
		pollerOptions.AckStore = r.acks
		pollerOptions.Metrics = r.metrics
		pollerOptions.Transmitter = issuer
		pollerOptions.Interval = poll.Interval.Std()
		pollerOptions.InitialDelay = poll.InitialDelay.Std()
		pollerOptions.MaxEvents = poll.MaxEvents
		if poll.LongPolling {
			pollerOptions.LongPollingHold = poll.LongPollingHold.Std()
		}
		pollerOptions.RateLimitFallback = poll.RateLimit.FallbackBackoff.Std()
		pollerOptions.MaxPause = poll.RateLimit.MaxBackoff.Std()
		pollerOptions.Timeout = timeout
		pollerOptions.Policy = policy
		pollerOptions.Clock = o.clock
		pollerOptions.Log = r.log
		var endpoint PollEndpoint
		if poll.EndpointURL != "" {
			u, err := url.Parse(poll.EndpointURL)
			if err != nil {
				return nil, err
			}
			endpoint = FixedPollEndpoint(u)
		} else {
			endpoint = stream.PollEndpointURL
		}
		transmitter.Poller = NewPoller(r.client, authorizer, endpoint, r.processor, pollerOptions)
	}
	return transmitter, nil
}

func (r *Receiver) tokenProvider(config TransmitterConfig, timeout time.Duration, o options) TokenProvider {
	if token := strings.TrimSpace(config.TransmitterAccessToken); token != "" {
		return FixedToken(token)
	}
	if config.OAuth2.TokenURI == "" {
		return NoToken{}
	}
	tokenURL, err := url.Parse(config.OAuth2.TokenURI)
	if err != nil {
		return NoToken{} // the validation reported it
	}
	options := DefaultClientCredentialsOptions()
	options.Policy = config.URIPolicy()
	options.Scopes = config.OAuth2.Scopes
	options.AuthenticateWithRequestBody, _ = config.OAuth2.AuthenticatesWithRequestBody()
	options.ExpirySafetyWindow = config.OAuth2.ExpirySafetyWindow.Std()
	options.AdditionalParameters = config.OAuth2.AdditionalParameters
	options.Timeout = timeout
	options.Clock = o.clock
	return NewClientCredentialsTokenProvider(r.client, tokenURL, config.OAuth2.ClientID, config.OAuth2.ClientSecret, options)
}

// desiredStream is the stream the receiver wants at the transmitter, from its configuration.
func desiredStream(config TransmitterConfig) *ssf.StreamConfiguration {
	events := config.Stream.EventsRequested
	if delivery, _ := config.Delivery(); delivery == ssf.Poll {
		return ssf.PollStream(events, config.Stream.Description)
	}
	endpoint, _ := url.Parse(config.Push.DeliveryEndpointURL) // validated
	return ssf.PushStream(endpoint, strings.TrimSpace(config.Push.ExpectedAuthHeader), events, config.Stream.Description)
}

func (r *Receiver) criticalSubjectMembers(issuer string) []string {
	if transmitter := r.byIssuer[issuer]; transmitter != nil {
		return transmitter.CriticalSubjectMembers()
	}
	return nil
}

func (r *Receiver) streamVerification(issuer string) func(*Context) error {
	if transmitter := r.byIssuer[issuer]; transmitter != nil && transmitter.Verification != nil {
		return transmitter.Verification.Check
	}
	return nil
}

func (r *Receiver) pushAuthorizationHeader(issuer string) string {
	if transmitter := r.byIssuer[issuer]; transmitter != nil {
		return transmitter.PushAuthorizationHeader
	}
	return ""
}

func nonEmpty(values, fallback []string) []string {
	if len(values) == 0 {
		return fallback
	}
	return values
}

// userAgentTransport sets the User-Agent header of every request that has none.
type userAgentTransport struct {
	next      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("User-Agent") == "" {
		r = r.Clone(r.Context())
		r.Header.Set("User-Agent", t.userAgent)
	}
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(r)
}

// Config is the configuration the receiver was built from.
func (r *Receiver) Config() Config { return r.config }

// Transmitters are the configured transmitters, the default one first, then by name.
func (r *Receiver) Transmitters() []*Transmitter { return r.transmitters }

// Transmitter is the transmitter with the given name, nil if there is none.
func (r *Receiver) Transmitter(name string) *Transmitter {
	for _, transmitter := range r.transmitters {
		if transmitter.Name == name {
			return transmitter
		}
	}
	return nil
}

// TransmitterByIssuer is the transmitter with the given issuer, nil if there is none.
func (r *Receiver) TransmitterByIssuer(issuer string) *Transmitter { return r.byIssuer[issuer] }

// NameOf is the short name of a transmitter, for labels such as metric tags, where its issuer
// would be long: the name of the transmitter with the given issuer, or the issuer itself if no
// transmitter has it.
func (r *Receiver) NameOf(issuer string) string {
	if transmitter := r.byIssuer[issuer]; transmitter != nil {
		return transmitter.Name
	}
	return issuer
}

// Processor is the processor every SET goes through, for a framework without an http.Handler
// adapter, or to process SETs received another way.
func (r *Receiver) Processor() *Processor { return r.processor }

// PushHandler is the push endpoint, an http.Handler; mount it at PushEndpointPath.
func (r *Receiver) PushHandler() *PushHandler { return r.push }

// PushEndpointPath is where PushHandler should be mounted, easyssf.receiver.push.endpoint-path.
func (r *Receiver) PushEndpointPath() string { return r.config.Push.EndpointPath }

// TokenRevocationStore is the store the session-revoked events fill. Give it to
// RevocationMiddleware.
func (r *Receiver) TokenRevocationStore() TokenRevocationStore { return r.revocations }

// JTIDedupStore is the de-duplication store, nil if de-duplication is off.
func (r *Receiver) JTIDedupStore() JTIDedupStore { return r.dedup }

// PollAckStore is the store of the acknowledgements the pollers owe.
func (r *Receiver) PollAckStore() PollAckStore { return r.acks }

// Metrics is what the receiver records with.
func (r *Receiver) Metrics() Metrics { return r.metrics }

// Start registers the streams and starts polling in the background, for every transmitter
// configured for it; it returns at once. Cancelling ctx or calling Stop ends the work.
func (r *Receiver) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return
	}
	r.started = true
	names := make([]string, 0, len(r.transmitters))
	for _, transmitter := range r.transmitters {
		transmitter.Start(ctx)
		names = append(names, transmitter.String())
	}
	r.log.Info("SSF receiver started", "count", len(r.transmitters), "transmitters", names)
}

// Stop ends the background work: pollers send the acknowledgements they owe, registrars delete
// streams configured for it; both with ctx.
func (r *Receiver) Stop(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return
	}
	r.started = false
	for _, transmitter := range r.transmitters {
		transmitter.Stop(ctx)
	}
}

// HealthStatus is whether the receiver is in contact with its transmitters.
type HealthStatus string

const (
	// HealthHealthy: every transmitter was reached, that is its metadata was retrieved (push)
	// or the last poll succeeded (poll), and its stream, if it is looked up or managed, is
	// registered.
	HealthHealthy HealthStatus = "healthy"
	// HealthDegraded: no contact with a transmitter yet. The application starts without it.
	HealthDegraded HealthStatus = "degraded"
	// HealthUnhealthy: a last poll failed, or a stream cannot be used.
	HealthUnhealthy HealthStatus = "unhealthy"
)

func (s HealthStatus) worse(other HealthStatus) HealthStatus {
	if s == HealthUnhealthy || other == HealthUnhealthy {
		return HealthUnhealthy
	}
	if s == HealthDegraded || other == HealthDegraded {
		return HealthDegraded
	}
	return HealthHealthy
}

// ReceiverHealth is the health of the receiver, see Receiver.Health. It marshals to JSON for a
// health endpoint.
type ReceiverHealth struct {
	// Status is the worst status of the transmitters.
	Status HealthStatus `json:"status"`
	// Description says what the status means.
	Description string `json:"description"`
	// Transmitters is the health of every transmitter.
	Transmitters []TransmitterHealth `json:"transmitters"`
}

// TransmitterHealth is the health of one transmitter.
type TransmitterHealth struct {
	Status HealthStatus `json:"status"`
	Name   string       `json:"name"`
	Issuer string       `json:"issuer"`
	// Delivery is push or poll.
	Delivery string `json:"delivery"`
	// MetadataResolved says whether the metadata was retrieved.
	MetadataResolved bool `json:"metadataResolved"`
	// JWKSURI is the JWK Set location from the metadata, "" if unknown.
	JWKSURI string `json:"jwksUri,omitempty"`
	// StreamID is the identifier of the stream, once known.
	StreamID string `json:"streamId,omitempty"`
	// StreamRegistration is the state of the stream registration, "" if the stream is neither
	// looked up nor managed.
	StreamRegistration string `json:"streamRegistration,omitempty"`
	// StreamRegistrationError is why the stream registration failed.
	StreamRegistrationError string `json:"streamRegistrationError,omitempty"`
	// LastPollAt is when the transmitter was last polled.
	LastPollAt time.Time `json:"lastPollAt,omitzero"`
	// LastSuccessfulPollAt is when the transmitter was last polled successfully.
	LastSuccessfulPollAt time.Time `json:"lastSuccessfulPollAt,omitzero"`
	// PollError is why the last poll failed.
	PollError string `json:"pollError,omitempty"`
	// PendingAcks is the number of acknowledgements and error reports waiting for the next poll
	// request.
	PendingAcks int `json:"pendingAcks"`
	// PausedUntil is until when the transmitter asked not to be polled.
	PausedUntil time.Time `json:"pausedUntil,omitzero"`
}

// Health is the health of the receiver as of now, from what it already knows; no transmitter is
// called. ctx is for the stores.
func (r *Receiver) Health(ctx context.Context) ReceiverHealth {
	health := ReceiverHealth{Status: HealthHealthy}
	for _, transmitter := range r.transmitters {
		h := transmitter.Health(ctx)
		health.Status = health.Status.worse(h.Status)
		health.Transmitters = append(health.Transmitters, h)
	}
	switch health.Status {
	case HealthHealthy:
		health.Description = "In contact with the SSF transmitter(s)"
	case HealthUnhealthy:
		health.Description = "An SSF transmitter cannot be polled or its stream cannot be used"
	default:
		health.Description = "No contact with an SSF transmitter yet"
	}
	return health
}

// Health is the health of the transmitter as of now, from what the receiver already knows.
func (t *Transmitter) Health(ctx context.Context) TransmitterHealth {
	health := TransmitterHealth{Status: HealthDegraded, Name: t.Name, Issuer: t.Issuer, Delivery: "push"}
	if t.Metadata != nil {
		if metadata := t.Metadata.Resolved(); metadata != nil {
			health.Status = HealthHealthy
			health.MetadataResolved = true
			if metadata.JWKSURI() != nil {
				health.JWKSURI = metadata.JWKSURI().String()
			}
		}
	}
	if t.Stream != nil {
		health.StreamID = t.Stream.StreamID()
	}
	if t.Registrar != nil {
		state := t.Registrar.State()
		health.StreamRegistration = state.String()
		health.StreamRegistrationError = t.Registrar.LastError()
		switch state {
		case StreamFailed:
			health.Status = HealthUnhealthy
		case StreamRegistered:
		default:
			health.Status = HealthDegraded
		}
	}
	if t.Poller != nil {
		health.Delivery = "poll"
		health.PendingAcks = t.Poller.PendingAckCount(ctx)
		health.LastPollAt = t.Poller.LastPollAt()
		health.LastSuccessfulPollAt = t.Poller.LastSuccessfulPollAt()
		health.PollError = t.Poller.LastPollError()
		health.PausedUntil = t.Poller.PausedUntil()
		if health.PollError != "" {
			health.Status = HealthUnhealthy
		} else if health.LastSuccessfulPollAt.IsZero() && health.Status != HealthUnhealthy {
			health.Status = HealthDegraded
		}
	}
	return health
}
