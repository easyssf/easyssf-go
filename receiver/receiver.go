package receiver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/go-jose/go-jose/v4"

	"github.com/easyssf/easyssf-go/ssf"
)

// Receiver assembles the parts for every configured transmitter from a Config (the Spring Boot
// auto-configuration, the .NET AddSsfReceiver and the Rust SsfReceiver): metadata resolution,
// JWK Set source, verifier, dedup store, processor with the handlers, the push handler, token
// revocation, and per transmitter the stream registrar and the poller.
type Receiver struct {
	config       Config
	log          *slog.Logger
	client       *http.Client
	transmitters map[string]*Transmitter
	processor    *Processor
	push         *PushHandler
	dedup        JTIDedupStore
	revocations  TokenRevocationStore
	acks         PollAckStore
	mu           sync.Mutex
	cancel       context.CancelFunc
}

// Transmitter is one transmitter as the receiver sees it: its settings, the metadata resolver,
// the verifier and, when configured, the stream registrar and the poller.
type Transmitter struct {
	Name      string
	Config    TransmitterConfig
	Metadata  *MetadataResolver
	Keys      JWKSetSource
	Verifier  *JWTVerifier
	Registrar *StreamRegistrar
	Poller    *Poller
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
	customize   func(*Transmitter)
}

// WithLogger logs with the given logger; discarded by default.
func WithLogger(log *slog.Logger) Option { return func(o *options) { o.log = log } }

// WithHTTPClient calls the transmitter with the given client; the TestTransmitter of ssftest
// hands one out that answers in-process. http.DefaultClient with the configured timeout by
// default.
func WithHTTPClient(client *http.Client) Option { return func(o *options) { o.client = client } }

// WithClock replaces the system clock, for tests.
func WithClock(clock Clock) Option { return func(o *options) { o.clock = clock } }

// WithMetrics records what the receiver does.
func WithMetrics(metrics Metrics) Option { return func(o *options) { o.metrics = metrics } }

// WithHandler adds handlers, called in order for every verified SET.
func WithHandler(handlers ...Handler) Option {
	return func(o *options) { o.handlers = append(o.handlers, handlers...) }
}

// WithDedupStore replaces the in-memory dedup store, for example with one on a database that is
// shared between instances.
func WithDedupStore(store JTIDedupStore) Option { return func(o *options) { o.dedup = store } }

// WithTokenRevocationStore replaces the in-memory revocation store.
func WithTokenRevocationStore(store TokenRevocationStore) Option {
	return func(o *options) { o.revocations = store }
}

// WithPollAckStore replaces the in-memory poll acknowledgement store.
func WithPollAckStore(store PollAckStore) Option { return func(o *options) { o.acks = store } }

// WithTransmitterCustomizer replaces parts of any transmitter before the receiver is built, for
// example the JWKSetSource of the one named "okta".
func WithTransmitterCustomizer(customize func(*Transmitter)) Option {
	return func(o *options) { o.customize = customize }
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
	o := options{clock: SystemClock, metrics: NoopMetrics{}}
	for _, opt := range opts {
		opt(&o)
	}
	log := orDiscard(o.log)
	client := o.client
	if client == nil {
		client = &http.Client{Timeout: config.HTTP.Timeout.Std()}
	}
	r := &Receiver{config: config, log: log, client: client, transmitters: map[string]*Transmitter{}}

	if config.Dedup.Enabled {
		r.dedup = o.dedup
		if r.dedup == nil {
			r.dedup = NewInMemoryJTIDedupStore(config.Dedup.Capacity, config.Dedup.Lease.Std(), o.clock)
		}
	}
	r.revocations = o.revocations
	if r.revocations == nil && config.Revocation.Enabled {
		r.revocations = NewInMemoryTokenRevocationStore(config.Revocation.TTL.Std(), o.clock)
	}
	r.acks = o.acks
	if r.acks == nil {
		r.acks = NewInMemoryPollAckStore()
	}

	verifiers := map[string]Verifier{}
	authHeaders := map[string]string{}
	names := make([]string, 0)
	for name := range config.AllTransmitters() {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		transmitter, err := r.buildTransmitter(name, config.AllTransmitters()[name], o)
		if err != nil {
			return nil, fmt.Errorf("transmitter %s: %w", name, err)
		}
		if o.customize != nil {
			o.customize(transmitter)
		}
		r.transmitters[name] = transmitter
		verifiers[transmitter.Config.TransmitterIssuer] = transmitter.Verifier
		authHeaders[transmitter.Config.TransmitterIssuer] = transmitter.Config.Push.ExpectedAuthHeader
	}

	var verifier Verifier = NewIssuerRoutingVerifier(verifiers)
	if len(verifiers) == 1 {
		for _, only := range verifiers {
			verifier = only
		}
	}
	r.processor = NewProcessor(verifier, r.dedup, ProcessorOptions{
		Metrics:                  o.metrics,
		Log:                      log,
		UnderstoodSubjectMembers: nonEmpty(config.UnderstoodSubjectMembers, ssf.Members),
		CriticalSubjectMembers:   r.criticalSubjectMembers,
		ClaimRenewal:             config.Dedup.Lease.Std() / 3,
	})
	if r.revocations != nil && config.Revocation.Enabled {
		r.processor.AddHandler(NewTokenRevocationHandler(r.revocations,
			nonEmpty(config.Revocation.SessionEventTypes, DefaultSessionEventTypes), config.Revocation.UserEventTypes, log))
	}
	r.processor.AddHandler(o.handlers...)
	r.push = NewPushHandlerByIssuer(r.processor, func(issuer string) string { return authHeaders[issuer] })
	return r, nil
}

func (r *Receiver) buildTransmitter(name string, config TransmitterConfig, o options) (*Transmitter, error) {
	policy := config.URIPolicy()
	var metadataURL *url.URL
	if config.TransmitterMetadataURL != "" {
		u, err := url.Parse(config.TransmitterMetadataURL)
		if err != nil {
			return nil, err
		}
		metadataURL = u
	}
	metadata, err := NewMetadataResolver(config.TransmitterIssuer, metadataURL, r.client, policy, r.log)
	if err != nil {
		return nil, err
	}
	var keys JWKSetSource
	if config.TransmitterJWKSURL != "" {
		u, err := url.Parse(config.TransmitterJWKSURL)
		if err != nil {
			return nil, err
		}
		source := NewHTTPJWKSetSource(r.client, u)
		source.Clock = o.clock
		keys = source
	} else {
		source := NewResolvedHTTPJWKSetSource(r.client, func(ctx context.Context) (*url.URL, error) {
			resolved, err := metadata.Resolve(ctx)
			if err != nil {
				return nil, err
			}
			if resolved.JWKSURI() == nil {
				return nil, Unavailable(nil, "the metadata of %s names no jwks_uri", config.TransmitterIssuer)
			}
			return resolved.JWKSURI(), nil
		})
		source.Clock = o.clock
		keys = source
	}
	options := DefaultVerifierOptions()
	options.Clock = o.clock
	options.MinRSAKeySize = config.SetValidation.MinRSAKeySize
	options.RequireTypeHeader = config.SetValidation.RequireTypeHeader
	options.ClockSkew = config.SetValidation.ClockSkew.Std()
	options.SubjectCompatibility, _ = config.SubjectCompatibility()
	options.AcceptedAlgorithms = nil
	for _, name := range config.EffectiveAcceptedAlgorithms() {
		algorithm, _ := SupportedAlgorithm(name)
		options.AcceptedAlgorithms = append(options.AcceptedAlgorithms, jose.SignatureAlgorithm(algorithm))
	}
	transmitter := &Transmitter{Name: name, Config: config, Metadata: metadata, Keys: keys}
	if audience := strings.TrimSpace(config.ExpectedAudience); audience != "" {
		options.ExpectedAudiences = []string{audience}
	} else if config.RegistersStream() && !config.SetValidation.AllowAnyAudience {
		// the audience is learned from the stream; until it is registered, no SET is accepted
		options.ExpectedAudiencesProvider = func() ([]string, error) {
			if transmitter.Registrar == nil || transmitter.Registrar.Current() == nil {
				return nil, Unavailable(nil, "the stream at %s is not registered yet, so the audience of its SETs is unknown", config.TransmitterIssuer)
			}
			return transmitter.Registrar.Current().Audience(), nil
		}
	}
	transmitter.Verifier, err = NewJWTVerifier(config.TransmitterIssuer, keys, options)
	if err != nil {
		return nil, err
	}
	// SKETCH: the registrar and the poller are built here once stream.go and poll.go are
	// ported; the config has everything they need (config.Stream, config.Poll, config.OAuth2).
	return transmitter, nil
}

func (r *Receiver) criticalSubjectMembers(issuer string) []string {
	for _, transmitter := range r.transmitters {
		if transmitter.Config.TransmitterIssuer == issuer {
			if metadata := transmitter.Metadata.Resolved(); metadata != nil {
				return metadata.CriticalSubjectMembers()
			}
		}
	}
	return nil
}

func nonEmpty(values, fallback []string) []string {
	if len(values) == 0 {
		return fallback
	}
	return values
}

// Config is the configuration the receiver was built from.
func (r *Receiver) Config() Config { return r.config }

// Transmitters are the configured transmitters by name.
func (r *Receiver) Transmitters() map[string]*Transmitter { return r.transmitters }

// Processor is the processor every SET goes through, for a framework without an http.Handler
// adapter, or to process SETs received another way.
func (r *Receiver) Processor() *Processor { return r.processor }

// PushHandler is the push endpoint, an http.Handler; mount it at Config.Push.EndpointPath.
func (r *Receiver) PushHandler() *PushHandler { return r.push }

// PushEndpointPath is where PushHandler should be mounted.
func (r *Receiver) PushEndpointPath() string { return r.config.Push.EndpointPath }

// TokenRevocationStore is the store the session-revoked events fill, nil if revocation is
// disabled. Give it to RevocationMiddleware.
func (r *Receiver) TokenRevocationStore() TokenRevocationStore { return r.revocations }

// Start registers the streams and starts polling in the background, for every transmitter
// configured for it; it returns at once. Stop ends the work.
func (r *Receiver) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, r.cancel = context.WithCancel(ctx)
	for _, transmitter := range r.transmitters {
		if transmitter.Registrar != nil {
			transmitter.Registrar.Start(ctx)
		}
		if transmitter.Poller != nil && transmitter.Config.Poll.AutoStartup {
			transmitter.Poller.Start(ctx)
		}
	}
	r.log.Info("SSF receiver started", "transmitters", len(r.transmitters))
}

// Stop ends the background work: pollers send the acknowledgements they owe, registrars delete
// streams configured for it.
func (r *Receiver) Stop(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel == nil {
		return
	}
	for _, transmitter := range r.transmitters {
		if transmitter.Poller != nil {
			transmitter.Poller.Stop(ctx)
		}
		if transmitter.Registrar != nil {
			_ = transmitter.Registrar.Stop(ctx)
		}
	}
	r.cancel()
	r.cancel = nil
}

// HealthStatus is the health of the receiver, for a health endpoint.
type HealthStatus string

const (
	// HealthUp: every transmitter is usable.
	HealthUp HealthStatus = "up"
	// HealthDegraded: a transmitter's metadata is not resolved yet or its stream registration
	// failed; push delivery may still work.
	HealthDegraded HealthStatus = "degraded"
)

// Health reports whether the transmitters are usable. SKETCH: once the registrar and the poller
// exist, their states feed in, as in SsfReceiverHealth of the Rust port.
func (r *Receiver) Health() HealthStatus {
	for _, transmitter := range r.transmitters {
		if transmitter.Registrar != nil && transmitter.Registrar.State() == StreamFailed {
			return HealthDegraded
		}
	}
	return HealthUp
}
