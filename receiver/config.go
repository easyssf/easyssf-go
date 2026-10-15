package receiver

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
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
	// SessionTermination configures the termination of server-side sessions by security events.
	SessionTermination SessionTerminationConfig `json:"session-termination" yaml:"session-termination" mapstructure:"session-termination"`
	// Data configures the database stores of receiver/sqlstore, when the application uses them.
	Data DataConfig `json:"data" yaml:"data" mapstructure:"data"`
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
	// Headers are sent with every call to the transmitter besides the bearer token: an API key,
	// a tenant, whatever the transmitter wants. Headers for particular endpoints only are set
	// with an EndpointHeaders Authorizer through WithTransmitterCustomizer.
	Headers map[string]string `json:"headers" yaml:"headers" mapstructure:"headers"`
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
	// TokenURI is the token endpoint to obtain access tokens from with the client credentials
	// grant.
	TokenURI string `json:"token-uri" yaml:"token-uri" mapstructure:"token-uri"`
	// ClientID is the client id of this receiver.
	ClientID string `json:"client-id" yaml:"client-id" mapstructure:"client-id"`
	// ClientSecret is the client secret of this receiver.
	ClientSecret string `json:"client-secret" yaml:"client-secret" mapstructure:"client-secret"`
	// Scopes are the scopes to request.
	Scopes []string `json:"scopes" yaml:"scopes" mapstructure:"scopes"`
	// ClientAuthenticationMethod is how the client authenticates at the token endpoint (RFC
	// 6749, section 2.3.1): client_secret_basic (also "basic", the default) or
	// client_secret_post (also "post").
	ClientAuthenticationMethod string `json:"client-authentication-method" yaml:"client-authentication-method" mapstructure:"client-authentication-method"`
	// ExpirySafetyWindow is how long before its expiry an access token is renewed; never more
	// than a quarter of the token's lifetime.
	ExpirySafetyWindow Duration `json:"expiry-safety-window" yaml:"expiry-safety-window" mapstructure:"expiry-safety-window"`
	// AdditionalParameters are form parameters to send with the token request in addition to
	// the grant.
	AdditionalParameters map[string]string `json:"additional-parameters" yaml:"additional-parameters" mapstructure:"additional-parameters"`
}

// AuthenticatesWithRequestBody says whether the client credentials are sent in the request
// body (client_secret_post) rather than with HTTP basic authentication; ok is false for an
// unknown method.
func (c *OAuth2Config) AuthenticatesWithRequestBody() (post bool, ok bool) {
	switch strings.ToLower(strings.TrimSpace(c.ClientAuthenticationMethod)) {
	case "", "basic", "client_secret_basic":
		return false, true
	case "post", "client_secret_post":
		return true, true
	}
	return false, false
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
	// EndpointURL is the poll endpoint of the stream, if the stream is not looked up or
	// registered by the receiver.
	EndpointURL string `json:"endpoint-url" yaml:"endpoint-url" mapstructure:"endpoint-url"`
	// AutoStartup says whether polling starts with the receiver; true by default.
	AutoStartup bool `json:"auto-startup" yaml:"auto-startup" mapstructure:"auto-startup"`
	// Interval is the time between two polls, 10 seconds by default.
	Interval Duration `json:"interval" yaml:"interval" mapstructure:"interval"`
	// InitialDelay is how long the first poll waits after the start.
	InitialDelay Duration `json:"initial-delay" yaml:"initial-delay" mapstructure:"initial-delay"`
	// MaxEvents is the maximum number of SETs fetched with one request, 100 by default.
	MaxEvents int `json:"max-events" yaml:"max-events" mapstructure:"max-events"`
	// LongPolling asks the transmitter to hold a request until SETs are available (RFC 8936,
	// section 2.5).
	LongPolling bool `json:"long-polling" yaml:"long-polling" mapstructure:"long-polling"`
	// LongPollingHold is how long the transmitter holds a request, 30 seconds by default.
	LongPollingHold Duration `json:"long-polling-hold" yaml:"long-polling-hold" mapstructure:"long-polling-hold"`
	// RateLimit is how the poller backs off on 429 and Retry-After.
	RateLimit RateLimitConfig `json:"rate-limit" yaml:"rate-limit" mapstructure:"rate-limit"`
}

// RateLimitConfig is how the poller backs off on 429 and Retry-After.
type RateLimitConfig struct {
	// FallbackBackoff is how long to pause after a 429 without a Retry-After header; zero
	// polls again at the regular interval.
	FallbackBackoff Duration `json:"fallback-backoff" yaml:"fallback-backoff" mapstructure:"fallback-backoff"`
	// MaxBackoff is the longest pause a Retry-After header or the fallback can cause, 5
	// minutes by default.
	MaxBackoff Duration `json:"max-backoff" yaml:"max-backoff" mapstructure:"max-backoff"`
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
	// Timeout is how long a call to the transmitter waits for its response, 5 seconds by
	// default. A long poll waits for its hold time plus a margin regardless.
	Timeout Duration `json:"timeout" yaml:"timeout" mapstructure:"timeout"`
	// UserAgent is the User-Agent header to send with calls to the transmitter; Go's default
	// when empty.
	UserAgent string `json:"user-agent" yaml:"user-agent" mapstructure:"user-agent"`
	// Retry is how a management, metadata or JWK Set call that fails with a connection error or
	// 408, 429, 500, 502, 503 or 504 is tried again. Poll requests are not retried, the poller
	// has its interval.
	Retry RetryConfig `json:"retry" yaml:"retry" mapstructure:"retry"`
}

// RetryConfig configures the retries of calls to the transmitter, see RetryOptions.
type RetryConfig struct {
	// MaxRetries is how many times a failed call is tried again, 2 by default; 0 never.
	MaxRetries int `json:"max-retries" yaml:"max-retries" mapstructure:"max-retries"`
	// InitialBackoff is the delay before the first retry, a quarter of a second by default; it
	// doubles with every retry.
	InitialBackoff Duration `json:"initial-backoff" yaml:"initial-backoff" mapstructure:"initial-backoff"`
	// MaxBackoff is the longest delay between two tries, also for a Retry-After header, 5
	// seconds by default.
	MaxBackoff Duration `json:"max-backoff" yaml:"max-backoff" mapstructure:"max-backoff"`
}

// Options are the RetryOptions of the configuration.
func (c RetryConfig) Options() RetryOptions {
	return RetryOptions{MaxRetries: c.MaxRetries, InitialBackoff: c.InitialBackoff.Std(), MaxBackoff: c.MaxBackoff.Std()}
}

// DedupConfig configures the de-duplication of SETs.
type DedupConfig struct {
	// Enabled says whether SETs that were already processed are skipped.
	Enabled bool `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	// Capacity is the number of SET identifiers the in-memory store remembers.
	Capacity int `json:"capacity" yaml:"capacity" mapstructure:"capacity"`
	// Retention is how long a durable store remembers a processed SET, 7 days by default. Has
	// to cover the time the transmitter keeps trying to deliver a SET.
	Retention Duration `json:"retention" yaml:"retention" mapstructure:"retention"`
	// Lease is how long a SET counts as being handled by the instance that claimed it without
	// renewing the claim, which it does every third of this time while its handlers run.
	Lease Duration `json:"lease" yaml:"lease" mapstructure:"lease"`
}

// RevocationConfig configures the revocation of tokens and sessions, see revocation.go.
type RevocationConfig struct {
	// Enabled says whether revocations are recorded.
	Enabled bool `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	// SessionEventTypes (alias or URI) revoke the session they name, or all tokens of the user
	// issued up to the event if they name none; CaepSessionRevoked when empty.
	SessionEventTypes []string `json:"session-event-types" yaml:"session-event-types" mapstructure:"session-event-types"`
	// UserEventTypes (alias or URI) revoke all tokens of the user they name; none by default.
	UserEventTypes []string `json:"user-event-types" yaml:"user-event-types" mapstructure:"user-event-types"`
	// TTL is how long a revocation is remembered, at least the maximum lifetime of the access
	// tokens and sessions it guards; 24 hours by default.
	TTL Duration `json:"ttl" yaml:"ttl" mapstructure:"ttl"`
}

// SessionTerminationConfig configures the termination of server-side sessions by security
// events, through the SessionTerminator given with WithSessionTerminator. Without one, nothing
// is terminated.
type SessionTerminationConfig struct {
	// Enabled says whether local sessions are terminated when a matching event is received and
	// a session terminator is given.
	Enabled bool `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	// SessionEventTypes (alias or URI) terminate the sessions identified by the event's subject
	// (session id and / or user); CaepSessionRevoked when empty.
	SessionEventTypes []string `json:"session-event-types" yaml:"session-event-types" mapstructure:"session-event-types"`
	// UserEventTypes (alias or URI) terminate all sessions of the user identified by the
	// event's subject; CaepCredentialChange when empty.
	UserEventTypes []string `json:"user-event-types" yaml:"user-event-types" mapstructure:"user-event-types"`
	// ScimAttributeClaims are the attributes of the scim subject of a SCIM Event (RFC 9967) and
	// the claim of the logged-in user each is compared with, e.g. externalId: sub; the
	// DefaultScimAttributeClaims when empty.
	ScimAttributeClaims map[string]string `json:"scim-attribute-claims" yaml:"scim-attribute-claims" mapstructure:"scim-attribute-claims"`
}

// EffectiveScimAttributeClaims are the attribute-claim pairs a scim subject is matched by: the
// configured ones, sorted by attribute, or DefaultScimAttributeClaims if none are configured.
func (c *SessionTerminationConfig) EffectiveScimAttributeClaims() [][2]string {
	if len(c.ScimAttributeClaims) == 0 {
		return DefaultScimAttributeClaims
	}
	pairs := make([][2]string, 0, len(c.ScimAttributeClaims))
	for attribute, claim := range c.ScimAttributeClaims {
		pairs = append(pairs, [2]string{attribute, claim})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
	return pairs
}

// Schema initialization modes of DataConfig.
const (
	// SchemaEmbedded creates the tables only in an embedded database (SQLite), which has no
	// migration tool of its own. The default.
	SchemaEmbedded = "embedded"
	// SchemaAlways creates a missing table and adds the columns of this release to a table of
	// an older one.
	SchemaAlways = "always"
	// SchemaNever never touches the tables: the application creates them with the SQL that
	// ships with the stores. A missing or outdated table fails the start with the statements
	// to run.
	SchemaNever = "never"
)

// DataConfig configures the database stores of receiver/sqlstore, which keep processed SETs,
// revocations and the acknowledgements a poller owes in the database of the application,
// shared by all its instances.
type DataConfig struct {
	// Enabled says whether the database stores are used. false keeps the state of the receiver
	// in memory although the stores were added, for example in a test environment.
	Enabled bool `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	// InitializeSchema says when to create the tables if they do not exist: SchemaEmbedded (the
	// default), SchemaAlways or SchemaNever.
	InitializeSchema string `json:"initialize-schema" yaml:"initialize-schema" mapstructure:"initialize-schema"`
	// TablePrefix is the prefix of the names of the tables, EASYSSF_ by default. Letters,
	// digits, _ and . (for a schema) only.
	TablePrefix string `json:"table-prefix" yaml:"table-prefix" mapstructure:"table-prefix"`
	// CleanupInterval is how often expired rows are purged. The stores also purge when they are
	// written to; zero turns the periodic cleanup off. 15 minutes by default.
	CleanupInterval Duration `json:"cleanup-interval" yaml:"cleanup-interval" mapstructure:"cleanup-interval"`
	// AckRetention is how long the store keeps an acknowledgement a polling receiver owes its
	// transmitter if no poll request manages to deliver it. 7 days by default.
	AckRetention Duration `json:"ack-retention" yaml:"ack-retention" mapstructure:"ack-retention"`
	// AckDeleteBatchSize is how many acknowledgements one DELETE of the store removes at once;
	// databases limit the parameters of a statement. 100 by default.
	AckDeleteBatchSize int `json:"ack-delete-batch-size" yaml:"ack-delete-batch-size" mapstructure:"ack-delete-batch-size"`
}

// SchemaInitialization is the configured mode; ok is false for an unknown name.
func (c *DataConfig) SchemaInitialization() (mode string, ok bool) {
	switch strings.ToLower(strings.TrimSpace(c.InitializeSchema)) {
	case "", SchemaEmbedded:
		return SchemaEmbedded, true
	case SchemaAlways:
		return SchemaAlways, true
	case SchemaNever:
		return SchemaNever, true
	}
	return "", false
}

// ValidTablePrefix reports whether a table prefix consists of letters, digits, '_' and '.' only.
func ValidTablePrefix(prefix string) bool {
	for _, c := range prefix {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
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
		Enabled:            true,
		TransmitterConfig:  DefaultTransmitterConfig(),
		HTTP:               HTTPConfig{Timeout: D(DefaultHTTPTimeout), Retry: RetryConfig{MaxRetries: 2, InitialBackoff: D(250 * time.Millisecond), MaxBackoff: D(5 * time.Second)}},
		Dedup:              DedupConfig{Enabled: true, Capacity: 10_000, Retention: D(7 * 24 * time.Hour), Lease: D(DefaultDedupLease)},
		Revocation:         RevocationConfig{Enabled: true, TTL: D(24 * time.Hour)},
		SessionTermination: SessionTerminationConfig{Enabled: true},
		Data: DataConfig{Enabled: true, InitializeSchema: SchemaEmbedded, TablePrefix: "EASYSSF_", CleanupInterval: D(15 * time.Minute),
			AckRetention: D(7 * 24 * time.Hour), AckDeleteBatchSize: 100},
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

// TransmitterNames are the names of the configured transmitters, sorted, "default" first.
func (c *Config) TransmitterNames() []string {
	all := c.AllTransmitters()
	names := make([]string, 0, len(all))
	for name := range all {
		if name != DefaultTransmitterName {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if _, ok := all[DefaultTransmitterName]; ok {
		names = append([]string{DefaultTransmitterName}, names...)
	}
	return names
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
		failures = append(failures, ConfigurationSection+".transmitter-issuer: The issuer of the SSF transmitter must be configured, or transmitters under "+
			ConfigurationSection+".transmitters. Set "+ConfigurationSection+".enabled = false to switch the receiver off")
	}
	if _, named := c.Transmitters[DefaultTransmitterName]; named && strings.TrimSpace(c.TransmitterIssuer) != "" {
		failures = append(failures, fmt.Sprintf("%[1]s.transmitters.%[2]s: The transmitter named '%[2]s' is the one configured at %[1]s, "+
			"it cannot be configured under %[1]s.transmitters as well", ConfigurationSection, DefaultTransmitterName))
	}
	byIssuer := map[string]string{}
	for _, name := range c.TransmitterNames() {
		transmitter := transmitters[name]
		if strings.TrimSpace(name) == "" {
			failures = append(failures, fmt.Sprintf("%[1]s.transmitters: A transmitter under %[1]s.transmitters needs a name", ConfigurationSection))
		}
		failures = append(failures, transmitter.Validate(name)...)
		if issuer := strings.TrimSpace(transmitter.TransmitterIssuer); issuer != "" {
			if other, seen := byIssuer[issuer]; seen {
				failures = append(failures, fmt.Sprintf("%s.transmitters: The transmitters '%s' and '%s' have the same issuer %s", ConfigurationSection, name, other, issuer))
			}
			byIssuer[issuer] = name
		}
	}
	if path := c.Push.EndpointPath; strings.TrimSpace(path) == "" || !strings.HasPrefix(path, "/") {
		failures = append(failures, fmt.Sprintf("%s.push.endpoint-path: The path of the push endpoint must start with '/' (value: '%s')", ConfigurationSection, path))
	}
	for alias, uri := range c.EventAliases {
		if err := eventtypes.RegisterAlias(alias, uri); err != nil {
			failures = append(failures, fmt.Sprintf("%s.event-aliases.%s: %v", ConfigurationSection, alias, err))
		}
	}
	if c.HTTP.Timeout <= 0 {
		failures = append(failures, ConfigurationSection+".http.timeout: must be positive")
	}
	if c.HTTP.Retry.MaxRetries < 0 || c.HTTP.Retry.InitialBackoff < 0 || c.HTTP.Retry.MaxBackoff < 0 {
		failures = append(failures, ConfigurationSection+".http.retry: max-retries, initial-backoff and max-backoff must not be negative")
	}
	if c.Dedup.Enabled && (c.Dedup.Capacity < 1 || c.Dedup.Lease <= 0 || c.Dedup.Retention <= 0) {
		failures = append(failures, ConfigurationSection+".dedup: capacity must be at least 1, lease and retention positive")
	}
	if c.Revocation.Enabled && c.Revocation.TTL <= 0 {
		failures = append(failures, ConfigurationSection+".revocation.ttl: must be positive")
	}
	if !ValidTablePrefix(c.Data.TablePrefix) {
		failures = append(failures, fmt.Sprintf("%s.data.table-prefix: may only consist of letters, digits, '_' and '.' (value: '%s')", ConfigurationSection, c.Data.TablePrefix))
	}
	if _, ok := c.Data.SchemaInitialization(); !ok {
		failures = append(failures, ConfigurationSection+".data.initialize-schema: must be embedded, always or never")
	}
	if c.Data.AckRetention <= 0 || c.Data.AckDeleteBatchSize < 1 {
		failures = append(failures, ConfigurationSection+".data: ack-retention and ack-delete-batch-size must be positive")
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
		{"oauth2.token-uri", t.OAuth2.TokenURI, "the token endpoint"},
		{"poll.endpoint-url", t.Poll.EndpointURL, "the poll endpoint"},
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
	if _, ok := t.OAuth2.AuthenticatesWithRequestBody(); !ok {
		failures = append(failures, prefix+"oauth2.client-authentication-method: must be client_secret_basic or client_secret_post")
	}
	if t.OAuth2.TokenURI != "" {
		if u, err := url.Parse(t.OAuth2.TokenURI); err != nil || !u.IsAbs() || u.Host == "" {
			failures = append(failures, prefix+"oauth2.token-uri: must be an absolute URI with a host: "+t.OAuth2.TokenURI)
		}
	}
	if t.Poll.EndpointURL != "" {
		if u, err := url.Parse(t.Poll.EndpointURL); err != nil || !u.IsAbs() || u.Host == "" {
			failures = append(failures, prefix+"poll.endpoint-url: must be an absolute URI with a host: "+t.Poll.EndpointURL)
		}
	}
	if t.Push.DeliveryEndpointURL != "" {
		if u, err := url.Parse(t.Push.DeliveryEndpointURL); err != nil || !u.IsAbs() || u.Host == "" {
			failures = append(failures, prefix+"push.delivery-endpoint-url: must be an absolute URI with a host: "+t.Push.DeliveryEndpointURL)
		}
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
