package receiver

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// Configuration of the receiver, the keys of the Spring Boot starter and the .NET options in
// kebab-case under easyssf.receiver, as in the Rust port. The structs carry json, yaml and
// mapstructure tags so that encoding/json, yaml.v3, koanf and viper all bind them; durations are
// strings such as "30s" or "24h". A zero Config is not usable: start from DefaultConfig, bind
// over it, then Validate.

// ConfigurationSection is the key the settings are bound from.
const ConfigurationSection = "easyssf.receiver"

// Duration is a time.Duration that binds from "30s" / "24h" strings in JSON, YAML and
// mapstructure (through encoding.TextUnmarshaler).
type Duration time.Duration

// D is a Duration.
func D(d time.Duration) Duration { return Duration(d) }

// Std is the time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// String formats like time.Duration.
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalText parses "30s", "5m", "24h".
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(strings.TrimSpace(string(text)))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// MarshalText formats like time.Duration.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// Config is the configuration of the receiver, bound from easyssf.receiver.
type Config struct {
	// Enabled says whether the SSF receiver is enabled.
	Enabled bool `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	// TransmitterConfig holds the settings of the default transmitter, flattened: the keys sit
	// directly under easyssf.receiver.
	TransmitterConfig `json:",inline" yaml:",inline" mapstructure:",squash"`
	// EventAliases are aliases for event type URIs, e.g. AcmeLogin =
	// https://events.acme.example/login, usable wherever an event type is named. They add to
	// the built-in aliases and cannot redefine one.
	EventAliases map[string]string `json:"event-aliases" yaml:"event-aliases" mapstructure:"event-aliases"`
	// UnderstoodSubjectMembers are the members of a complex subject the application interprets.
	// A SET with a member a transmitter declared critical (critical_subject_members) that is not
	// listed here is rejected. Empty, the default, means the members ssf.Subject gives access to.
	UnderstoodSubjectMembers []string `json:"understood-subject-members" yaml:"understood-subject-members" mapstructure:"understood-subject-members"`
	// Transmitters are further transmitters by name, each with the settings of a transmitter.
	// The settings at easyssf.receiver configure the transmitter named "default".
	Transmitters map[string]TransmitterConfig `json:"transmitters" yaml:"transmitters" mapstructure:"transmitters"`
	// HTTP configures outbound HTTP calls to the transmitter.
	HTTP HTTPConfig `json:"http" yaml:"http" mapstructure:"http"`
	// Dedup configures the de-duplication of SETs by jti.
	Dedup DedupConfig `json:"dedup" yaml:"dedup" mapstructure:"dedup"`
	// Revocation configures the revocation of access tokens and sessions by security events.
	Revocation RevocationConfig `json:"revocation" yaml:"revocation" mapstructure:"revocation"`
}

// DefaultTransmitterName is the name of the transmitter configured at easyssf.receiver.
const DefaultTransmitterName = "default"

// TransmitterConfig holds the settings of one transmitter.
type TransmitterConfig struct {
	// TransmitterIssuer is the issuer of the transmitter, the iss claim of its SETs. Required.
	TransmitterIssuer string `json:"transmitter-issuer" yaml:"transmitter-issuer" mapstructure:"transmitter-issuer"`
	// TransmitterMetadataURL is where the transmitter publishes its metadata, if not at the
	// locations derived from the issuer.
	TransmitterMetadataURL string `json:"transmitter-metadata-url" yaml:"transmitter-metadata-url" mapstructure:"transmitter-metadata-url"`
	// TransmitterJWKSURL is where the transmitter publishes its keys, if not in its metadata.
	TransmitterJWKSURL string `json:"transmitter-jwks-url" yaml:"transmitter-jwks-url" mapstructure:"transmitter-jwks-url"`
	// AllowInsecureHTTP accepts http for the issuer and the endpoints on hosts other than
	// loopback. For development only.
	AllowInsecureHTTP bool `json:"allow-insecure-http" yaml:"allow-insecure-http" mapstructure:"allow-insecure-http"`
	// ExpectedAudience is the audience the SETs must be addressed to, this receiver. Learned
	// from the stream when the receiver registers or looks it up.
	ExpectedAudience string `json:"expected-audience" yaml:"expected-audience" mapstructure:"expected-audience"`
	// DeliveryMethod is "push" (the default) or "poll".
	DeliveryMethod string `json:"delivery-method" yaml:"delivery-method" mapstructure:"delivery-method"`
	// TransmitterAccessToken is a fixed bearer token for the management and poll endpoints,
	// instead of the client credentials grant of OAuth2.
	TransmitterAccessToken string `json:"transmitter-access-token" yaml:"transmitter-access-token" mapstructure:"transmitter-access-token"`
	// OAuth2 obtains access tokens for the management and poll endpoints.
	OAuth2 OAuth2Config `json:"oauth2" yaml:"oauth2" mapstructure:"oauth2"`
	// Stream configures the stream at the transmitter.
	Stream StreamConfig `json:"stream" yaml:"stream" mapstructure:"stream"`
	// Poll configures poll delivery.
	Poll PollConfig `json:"poll" yaml:"poll" mapstructure:"poll"`
	// SetValidation configures how SETs are verified.
	SetValidation SetValidationConfig `json:"set-validation" yaml:"set-validation" mapstructure:"set-validation"`
	// Push configures push delivery.
	Push PushConfig `json:"push" yaml:"push" mapstructure:"push"`
}

// OAuth2Config is the client credentials grant for the transmitter's endpoints.
type OAuth2Config struct {
	TokenURI                   string            `json:"token-uri" yaml:"token-uri" mapstructure:"token-uri"`
	ClientID                   string            `json:"client-id" yaml:"client-id" mapstructure:"client-id"`
	ClientSecret               string            `json:"client-secret" yaml:"client-secret" mapstructure:"client-secret"`
	Scopes                     []string          `json:"scopes" yaml:"scopes" mapstructure:"scopes"`
	ClientAuthenticationMethod string            `json:"client-authentication-method" yaml:"client-authentication-method" mapstructure:"client-authentication-method"`
	ExpirySafetyWindow         Duration          `json:"expiry-safety-window" yaml:"expiry-safety-window" mapstructure:"expiry-safety-window"`
	AdditionalParameters       map[string]string `json:"additional-parameters" yaml:"additional-parameters" mapstructure:"additional-parameters"`
}

// Stream management modes.
const (
	// StreamManagementNone: the receiver does not touch the stream; the transmitter is
	// configured out of band.
	StreamManagementNone = "none"
	// StreamManagementReceiver: the receiver reuses, updates or creates the stream it wants.
	StreamManagementReceiver = "receiver"
)

// StreamConfig configures the stream at the transmitter.
type StreamConfig struct {
	// Management is "none" (the default) or "receiver".
	Management string `json:"management" yaml:"management" mapstructure:"management"`
	// ID is the stream to look up, if the transmitter assigned one out of band.
	ID string `json:"id" yaml:"id" mapstructure:"id"`
	// EventsRequested are the event types to request (alias or URI).
	EventsRequested []string `json:"events-requested" yaml:"events-requested" mapstructure:"events-requested"`
	// Description is the description of the stream.
	Description string `json:"description" yaml:"description" mapstructure:"description"`
	// DeleteOnShutdown deletes a stream the receiver created when it shuts down.
	DeleteOnShutdown bool `json:"delete-on-shutdown" yaml:"delete-on-shutdown" mapstructure:"delete-on-shutdown"`
}

// PollConfig configures poll delivery (RFC 8936).
type PollConfig struct {
	EndpointURL     string          `json:"endpoint-url" yaml:"endpoint-url" mapstructure:"endpoint-url"`
	AutoStartup     bool            `json:"auto-startup" yaml:"auto-startup" mapstructure:"auto-startup"`
	Interval        Duration        `json:"interval" yaml:"interval" mapstructure:"interval"`
	InitialDelay    Duration        `json:"initial-delay" yaml:"initial-delay" mapstructure:"initial-delay"`
	MaxEvents       int             `json:"max-events" yaml:"max-events" mapstructure:"max-events"`
	LongPolling     bool            `json:"long-polling" yaml:"long-polling" mapstructure:"long-polling"`
	LongPollingHold Duration        `json:"long-polling-hold" yaml:"long-polling-hold" mapstructure:"long-polling-hold"`
	RateLimit       RateLimitConfig `json:"rate-limit" yaml:"rate-limit" mapstructure:"rate-limit"`
}

// RateLimitConfig is how the poller backs off on 429 and Retry-After.
type RateLimitConfig struct {
	FallbackBackoff Duration `json:"fallback-backoff" yaml:"fallback-backoff" mapstructure:"fallback-backoff"`
	MaxBackoff      Duration `json:"max-backoff" yaml:"max-backoff" mapstructure:"max-backoff"`
}

// SetValidationConfig configures how SETs are verified.
type SetValidationConfig struct {
	// AcceptedAlgorithms are the JWS algorithms accepted; RS256 while empty.
	AcceptedAlgorithms []string `json:"accepted-algorithms" yaml:"accepted-algorithms" mapstructure:"accepted-algorithms"`
	// MinRSAKeySize is the minimum RSA key size in bits, 0 for any.
	MinRSAKeySize int `json:"min-rsa-key-size" yaml:"min-rsa-key-size" mapstructure:"min-rsa-key-size"`
	// RequireTypeHeader requires the typ header of secevent+jwt.
	RequireTypeHeader bool `json:"require-type-header" yaml:"require-type-header" mapstructure:"require-type-header"`
	// SubjectCompatibility is "strict" (the default) or "legacy".
	SubjectCompatibility string `json:"subject-compatibility" yaml:"subject-compatibility" mapstructure:"subject-compatibility"`
	// ClockSkew is how far in the future a SET may be issued.
	ClockSkew Duration `json:"clock-skew" yaml:"clock-skew" mapstructure:"clock-skew"`
	// AllowAnyAudience accepts SETs the transmitter issued for other receivers as well.
	AllowAnyAudience bool `json:"allow-any-audience" yaml:"allow-any-audience" mapstructure:"allow-any-audience"`
}

// PushConfig configures push delivery (RFC 8935).
type PushConfig struct {
	// ExpectedAuthHeader is the Authorization header the transmitter has to send, for example
	// "Bearer <secret>". Recommended.
	ExpectedAuthHeader string `json:"expected-auth-header" yaml:"expected-auth-header" mapstructure:"expected-auth-header"`
	// DeliveryEndpointURL is the URL under which the transmitter reaches the push endpoint of
	// this application, for a stream the receiver registers.
	DeliveryEndpointURL string `json:"delivery-endpoint-url" yaml:"delivery-endpoint-url" mapstructure:"delivery-endpoint-url"`
	// EndpointPath is where the push endpoint is mounted, /ssf/push by default.
	EndpointPath string `json:"endpoint-path" yaml:"endpoint-path" mapstructure:"endpoint-path"`
}

// HTTPConfig configures the calls to the transmitter.
type HTTPConfig struct {
	Timeout   Duration `json:"timeout" yaml:"timeout" mapstructure:"timeout"`
	UserAgent string   `json:"user-agent" yaml:"user-agent" mapstructure:"user-agent"`
}

// DedupConfig configures the de-duplication of SETs.
type DedupConfig struct {
	Enabled   bool     `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	Capacity  int      `json:"capacity" yaml:"capacity" mapstructure:"capacity"`
	Retention Duration `json:"retention" yaml:"retention" mapstructure:"retention"`
	Lease     Duration `json:"lease" yaml:"lease" mapstructure:"lease"`
}

// RevocationConfig configures the revocation of tokens and sessions, see revocation.go.
type RevocationConfig struct {
	Enabled           bool     `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	SessionEventTypes []string `json:"session-event-types" yaml:"session-event-types" mapstructure:"session-event-types"`
	UserEventTypes    []string `json:"user-event-types" yaml:"user-event-types" mapstructure:"user-event-types"`
	TTL               Duration `json:"ttl" yaml:"ttl" mapstructure:"ttl"`
}

// DefaultTransmitterConfig are the defaults of a transmitter, the ones of the Java starter.
func DefaultTransmitterConfig() TransmitterConfig {
	return TransmitterConfig{
		DeliveryMethod: "push",
		OAuth2:         OAuth2Config{ClientAuthenticationMethod: "client_secret_basic", ExpirySafetyWindow: D(30 * time.Second)},
		Stream:         StreamConfig{Management: StreamManagementNone},
		Poll: PollConfig{AutoStartup: true, Interval: D(10 * time.Second), MaxEvents: 100, LongPollingHold: D(30 * time.Second),
			RateLimit: RateLimitConfig{MaxBackoff: D(5 * time.Minute)}},
		SetValidation: SetValidationConfig{MinRSAKeySize: 2048, RequireTypeHeader: true, SubjectCompatibility: "strict", ClockSkew: D(time.Minute)},
		Push:          PushConfig{EndpointPath: "/ssf/push"},
	}
}

// DefaultConfig are the defaults of the receiver.
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		TransmitterConfig: DefaultTransmitterConfig(),
		HTTP:              HTTPConfig{Timeout: D(10 * time.Second)},
		Dedup:             DedupConfig{Enabled: true, Capacity: 10_000, Retention: D(24 * time.Hour), Lease: D(DefaultDedupLease)},
		Revocation:        RevocationConfig{Enabled: true, TTL: D(24 * time.Hour)},
	}
}

// ConfigError lists what is wrong with a Config, one failure per line, each prefixed with the
// key of the setting.
type ConfigError struct{ Failures []string }

func (e *ConfigError) Error() string {
	return "the SSF receiver configuration is invalid:\n  " + strings.Join(e.Failures, "\n  ")
}

// AllTransmitters are the transmitters by name: "default" for the settings at easyssf.receiver,
// if it names an issuer, and the ones under transmitters.
func (c *Config) AllTransmitters() map[string]TransmitterConfig {
	all := map[string]TransmitterConfig{}
	if strings.TrimSpace(c.TransmitterIssuer) != "" {
		all[DefaultTransmitterName] = c.TransmitterConfig
	}
	for name, transmitter := range c.Transmitters {
		all[name] = transmitter
	}
	return all
}

// Validate checks the configuration the way New does when it builds the parts, and returns
// everything that is wrong at once as a ConfigError.
func (c *Config) Validate() error {
	var failures []string
	if !c.Enabled {
		return nil
	}
	transmitters := c.AllTransmitters()
	if len(transmitters) == 0 {
		failures = append(failures, ConfigurationSection+".transmitter-issuer: The issuer of the SSF transmitter must be configured")
	}
	for name, transmitter := range transmitters {
		failures = append(failures, transmitter.Validate(name)...)
	}
	for alias, uri := range c.EventAliases {
		if err := eventtypes.RegisterAlias(alias, uri); err != nil {
			failures = append(failures, fmt.Sprintf("%s.event-aliases.%s: %v", ConfigurationSection, alias, err))
		}
	}
	if c.HTTP.Timeout <= 0 {
		failures = append(failures, ConfigurationSection+".http.timeout: must be positive")
	}
	if c.Dedup.Enabled && (c.Dedup.Capacity < 1 || c.Dedup.Lease <= 0 || c.Dedup.Retention <= 0) {
		failures = append(failures, ConfigurationSection+".dedup: capacity must be at least 1, lease and retention positive")
	}
	if c.Revocation.Enabled && c.Revocation.TTL <= 0 {
		failures = append(failures, ConfigurationSection+".revocation.ttl: must be positive")
	}
	if len(failures) > 0 {
		return &ConfigError{Failures: failures}
	}
	return nil
}

func (t *TransmitterConfig) prefix(name string) string {
	if name == DefaultTransmitterName {
		return ConfigurationSection + "."
	}
	return ConfigurationSection + ".transmitters." + name + "."
}

// URIPolicy is the policy the transmitter's URLs are held to.
func (t *TransmitterConfig) URIPolicy() URIPolicy {
	return URIPolicy{AllowInsecureHTTP: t.AllowInsecureHTTP}
}

// Delivery is the configured delivery method; ok is false for an unknown name.
func (t *TransmitterConfig) Delivery() (ssf.DeliveryMethod, bool) {
	switch strings.ToLower(strings.TrimSpace(t.DeliveryMethod)) {
	case "", "push":
		return ssf.Push, true
	case "poll":
		return ssf.Poll, true
	}
	return 0, false
}

// RegistersStream says whether the receiver looks the stream up or registers it, and learns the
// audience from it.
func (t *TransmitterConfig) RegistersStream() bool {
	return t.Stream.Management == StreamManagementReceiver || strings.TrimSpace(t.Stream.ID) != ""
}

// SubjectCompatibility is the configured mode; ok is false for an unknown name.
func (t *TransmitterConfig) SubjectCompatibility() (ssf.SubjectCompatibilityMode, bool) {
	switch strings.ToLower(strings.TrimSpace(t.SetValidation.SubjectCompatibility)) {
	case "", "strict":
		return ssf.Strict, true
	case "legacy":
		return ssf.Legacy, true
	}
	return 0, false
}

// EffectiveAcceptedAlgorithms are the accepted algorithms, RS256 while none are configured.
func (t *TransmitterConfig) EffectiveAcceptedAlgorithms() []string {
	if len(t.SetValidation.AcceptedAlgorithms) == 0 {
		return []string{"RS256"}
	}
	return t.SetValidation.AcceptedAlgorithms
}

// Validate checks the settings of the transmitter named name. Returns what is wrong, empty if
// the settings are usable.
func (t *TransmitterConfig) Validate(name string) []string {
	prefix := t.prefix(name)
	var failures []string
	if strings.TrimSpace(t.TransmitterIssuer) == "" {
		return []string{prefix + "transmitter-issuer: The issuer of the SSF transmitter must be configured"}
	}
	policy := t.URIPolicy()
	if _, err := policy.CheckIssuer(t.TransmitterIssuer); err != nil {
		failures = append(failures, prefix+"transmitter-issuer: "+err.Error())
	}
	for _, endpoint := range []struct{ key, value, description string }{
		{"transmitter-metadata-url", t.TransmitterMetadataURL, "transmitter metadata URL"},
		{"transmitter-jwks-url", t.TransmitterJWKSURL, "the JWK Set URL"},
	} {
		if endpoint.value == "" {
			continue
		}
		u, err := url.Parse(endpoint.value)
		if err == nil {
			err = policy.CheckEndpoint(u, endpoint.description)
		}
		if err != nil {
			failures = append(failures, prefix+endpoint.key+": "+err.Error())
		}
	}
	for _, algorithm := range t.EffectiveAcceptedAlgorithms() {
		if _, ok := SupportedAlgorithm(algorithm); !ok {
			failures = append(failures, prefix+"set-validation.accepted-algorithms: Not an asymmetric signature algorithm: "+algorithm)
		}
	}
	if _, ok := t.Delivery(); !ok {
		failures = append(failures, prefix+"delivery-method: must be push or poll")
	}
	if _, ok := t.SubjectCompatibility(); !ok {
		failures = append(failures, prefix+"set-validation.subject-compatibility: must be strict or legacy")
	}
	if strings.TrimSpace(t.ExpectedAudience) == "" && !t.RegistersStream() && !t.SetValidation.AllowAnyAudience {
		failures = append(failures, fmt.Sprintf("%[1]sexpected-audience: The audience of the SETs must be known: set %[1]sexpected-audience, "+
			"or let the receiver look the stream up (%[1]sstream.management = \"receiver\" or %[1]sstream.id), or set "+
			"%[1]sset-validation.allow-any-audience = true to accept SETs the transmitter issued for other receivers as well", prefix))
	}
	if strings.TrimSpace(t.TransmitterAccessToken) == "" && t.OAuth2.TokenURI != "" &&
		(strings.TrimSpace(t.OAuth2.ClientID) == "" || strings.TrimSpace(t.OAuth2.ClientSecret) == "") {
		failures = append(failures, fmt.Sprintf("%[1]soauth2.client-id: %[1]soauth2.client-id and %[1]soauth2.client-secret are required to obtain access tokens from %[1]soauth2.token-uri", prefix))
	}
	delivery, _ := t.Delivery()
	if t.Stream.Management == StreamManagementReceiver && delivery == ssf.Push && t.Push.DeliveryEndpointURL == "" {
		failures = append(failures, prefix+"push.delivery-endpoint-url: A stream managed by the receiver needs the URL under which the transmitter reaches the push endpoint of this application")
	}
	if delivery == ssf.Poll {
		if t.Poll.EndpointURL == "" && !t.RegistersStream() {
			failures = append(failures, fmt.Sprintf("%[1]spoll.endpoint-url: POLL delivery needs the poll endpoint of the stream: set %[1]spoll.endpoint-url, %[1]sstream.id or %[1]sstream.management = \"receiver\"", prefix))
		}
		if t.Poll.Interval <= 0 || t.Poll.MaxEvents < 1 || t.Poll.RateLimit.MaxBackoff <= 0 || (t.Poll.LongPolling && t.Poll.LongPollingHold <= 0) {
			failures = append(failures, prefix+"poll: interval, long-polling-hold and rate-limit.max-backoff must be positive, max-events at least 1")
		}
	}
	return failures
}

// ErrDisabled says that the receiver is disabled by configuration.
var ErrDisabled = errors.New("the SSF receiver is disabled (easyssf.receiver.enabled = false)")
