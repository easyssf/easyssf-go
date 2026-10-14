package receiver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
)

// The transmitter as the receiver sees it: its metadata, how it is reached and what its URLs
// must look like, the access token to call it with, and everything the receiver holds for it
// (a port of transmitter.rs of the Rust port and of org.easyssf.receiver.transmitter).

// WellKnownPath is where a transmitter publishes its metadata (SSF 1.0, section 7.2).
const WellKnownPath = "/.well-known/ssf-configuration"

// DefaultHTTPTimeout is how long a call to the transmitter waits for its response when nothing
// else is configured: 5 seconds, as in the Java library. A long poll waits for its hold time plus
// a margin instead.
const DefaultHTTPTimeout = 5 * time.Second

// maxResponseSize bounds what the receiver reads from the transmitter: metadata, JWK Sets and
// poll responses are small, and an endpoint must not be able to exhaust the receiver's memory.
const maxResponseSize = 4 << 20

// URIPolicy says what the issuer of a transmitter and the endpoints it publishes must look like.
// SSF requires https and an issuer without query or fragment. Loopback addresses (localhost,
// 127.0.0.1, ::1) may use http, so that a transmitter on the developer's machine works;
// AllowInsecureHTTP extends that to every host, for test setups only: the metadata of the
// transmitter decides where keys come from, and without TLS anyone on the path can change it.
type URIPolicy struct {
	AllowInsecureHTTP bool
}

// IsInsecure reports whether the URL uses plain http.
func IsInsecure(u *url.URL) bool { return strings.EqualFold(u.Scheme, "http") }

// IsLoopback reports whether the host of the URL is a loopback address.
func IsLoopback(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasPrefix(host, "127.") ||
		host == "::1" || host == "0:0:0:0:0:0:0:1"
}

// CheckIssuer checks the issuer of a transmitter and returns it as a URL.
func (p URIPolicy) CheckIssuer(issuer string) (*url.URL, error) {
	u, err := parseAbsolute(issuer, "transmitter issuer")
	if err != nil {
		return nil, err
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("transmitter issuer must not have a query or fragment: %s", issuer)
	}
	return u, p.checkScheme(u, "transmitter issuer")
}

// CheckEndpoint checks an endpoint of the transmitter: its metadata, JWK Set, stream management
// or poll endpoint. description says what the endpoint is, for the message.
func (p URIPolicy) CheckEndpoint(u *url.URL, description string) error {
	if _, err := parseAbsolute(u.String(), description); err != nil {
		return err
	}
	if u.Fragment != "" {
		return fmt.Errorf("%s must not have a fragment: %s", description, u)
	}
	return p.checkScheme(u, description)
}

func (p URIPolicy) checkScheme(u *url.URL, description string) error {
	scheme := strings.ToLower(u.Scheme)
	if scheme == "https" || (scheme == "http" && (p.AllowInsecureHTTP || IsLoopback(u))) {
		return nil
	}
	return fmt.Errorf("%s must use https: %s", description, u)
}

func parseAbsolute(value, description string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid URI: %s (%w)", description, value, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("%s must be an absolute URI with a host: %s", description, value)
	}
	return u, nil
}

// DeriveMetadataURLs derives the metadata locations for an issuer. SSF 1.0 (section 7.2) inserts
// /.well-known/ssf-configuration between the host and the path of the issuer. Transmitters that
// grew out of OpenID providers tend to append it to the issuer instead, so that location is used
// as a fallback.
func DeriveMetadataURLs(issuer string) ([]*url.URL, error) {
	u, err := parseAbsolute(issuer, "transmitter issuer")
	if err != nil {
		return nil, err
	}
	base := u.Scheme + "://" + u.Host
	path := strings.TrimRight(u.Path, "/")
	var urls []*url.URL
	for _, candidate := range []string{base + WellKnownPath + path, base + path + WellKnownPath} {
		if len(urls) > 0 && urls[0].String() == candidate {
			continue
		}
		parsed, err := url.Parse(candidate)
		if err != nil {
			return nil, fmt.Errorf("cannot derive the metadata location of %s: %w", issuer, err)
		}
		urls = append(urls, parsed)
	}
	return urls, nil
}

// MetadataResolver resolves the TransmitterMetadata of the transmitter. The metadata is fetched
// on first use and cached once it was retrieved successfully, so a receiver can start even when
// the transmitter is not reachable.
type MetadataResolver struct {
	// Timeout is how long a fetch waits for the response; DefaultHTTPTimeout if zero.
	Timeout time.Duration

	issuer   string
	urls     []*url.URL
	client   *http.Client
	policy   URIPolicy
	log      *slog.Logger
	mu       sync.Mutex
	metadata *ssf.TransmitterMetadata
	warned   bool
}

// NewMetadataResolver is a resolver for the metadata of the transmitter with the given issuer,
// at metadataURL or, if nil, at the locations derived from the issuer. It fails if the issuer or
// the metadata URL is not acceptable to the policy. A nil client is http.DefaultClient.
func NewMetadataResolver(issuer string, metadataURL *url.URL, client *http.Client, policy URIPolicy, log *slog.Logger) (*MetadataResolver, error) {
	if _, err := policy.CheckIssuer(issuer); err != nil {
		return nil, err
	}
	var urls []*url.URL
	if metadataURL != nil {
		if err := policy.CheckEndpoint(metadataURL, "transmitter metadata URL"); err != nil {
			return nil, err
		}
		urls = []*url.URL{metadataURL}
	} else {
		var err error
		if urls, err = DeriveMetadataURLs(issuer); err != nil {
			return nil, err
		}
	}
	return &MetadataResolver{issuer: issuer, urls: urls, client: orDefault(client), policy: policy, log: orDiscard(log)}, nil
}

// Issuer is the issuer of the transmitter.
func (r *MetadataResolver) Issuer() string { return r.issuer }

// MetadataURLs are the locations the metadata is looked up at, in order.
func (r *MetadataResolver) MetadataURLs() []*url.URL { return r.urls }

// Resolved is the metadata if it was retrieved already, without retrieving it.
func (r *MetadataResolver) Resolved() *ssf.TransmitterMetadata {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.metadata
}

// Resolve is the metadata, fetched on first use. Concurrent callers wait for one fetch.
func (r *MetadataResolver) Resolve(ctx context.Context) (*ssf.TransmitterMetadata, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.metadata != nil {
		return r.metadata, nil
	}
	var failures []string
	for _, u := range r.urls {
		metadata, err := r.fetch(ctx, u)
		if err == nil {
			r.log.Info("Resolved SSF transmitter metadata", "transmitter", r.issuer, "url", u.String())
			r.metadata = metadata
			return metadata, nil
		}
		r.log.Debug("Could not resolve SSF transmitter metadata", "url", u.String(), "error", err)
		failures = append(failures, u.String()+": "+err.Error())
	}
	return nil, Unavailable(nil, "could not resolve SSF transmitter metadata from %s", strings.Join(failures, "; "))
}

func (r *MetadataResolver) fetch(ctx context.Context, u *url.URL) (*ssf.TransmitterMetadata, error) {
	body, err := getJSON(ctx, r.client, r.Timeout, u, "application/json")
	if err != nil {
		return nil, err
	}
	claims, err := ssf.ParseClaims(body)
	if err != nil {
		return nil, fmt.Errorf("the metadata is not JSON: %w", err)
	}
	if issuer := ssf.StringMember(claims, "issuer"); issuer != r.issuer {
		return nil, fmt.Errorf("SSF transmitter metadata issuer %q does not match the configured transmitter issuer %q", issuer, r.issuer)
	}
	var jwksURI *url.URL
	if value := ssf.StringMember(claims, "jwks_uri"); value != "" {
		if jwksURI, err = url.Parse(value); err != nil {
			return nil, fmt.Errorf("jwks_uri is not a valid URL: %w", err)
		}
	}
	metadata := ssf.NewTransmitterMetadata(r.issuer, jwksURI, claims)
	return metadata, r.checkEndpoints(metadata)
}

// The metadata controls where keys and stream operations come from, so its endpoints are held
// to the same standard as the issuer.
func (r *MetadataResolver) checkEndpoints(metadata *ssf.TransmitterMetadata) error {
	endpoints := []struct {
		url  *url.URL
		name string
	}{
		{metadata.JWKSURI(), "jwks_uri"},
		{metadata.ConfigurationEndpoint(), "configuration_endpoint"},
		{metadata.StatusEndpoint(), "status_endpoint"},
		{metadata.AddSubjectEndpoint(), "add_subject_endpoint"},
		{metadata.RemoveSubjectEndpoint(), "remove_subject_endpoint"},
		{metadata.VerificationEndpoint(), "verification_endpoint"},
	}
	var insecure []string
	for _, endpoint := range endpoints {
		if endpoint.url == nil {
			continue
		}
		if err := r.policy.CheckEndpoint(endpoint.url, "SSF transmitter metadata "+endpoint.name); err != nil {
			return err
		}
		if IsInsecure(endpoint.url) && !IsLoopback(endpoint.url) {
			insecure = append(insecure, endpoint.name+" "+endpoint.url.String())
		}
	}
	if len(insecure) > 0 && r.policy.AllowInsecureHTTP && !r.warned {
		r.warned = true
		r.log.Warn("The SSF transmitter publishes endpoints without TLS, accepted because insecure http is allowed. For development only",
			"transmitter", r.issuer, "endpoints", insecure)
	}
	return nil
}

// httpResponse is what a call to the transmitter answered with, whatever the status.
type httpResponse struct {
	status int
	header http.Header
	body   []byte
}

func (r *httpResponse) successful() bool { return r.status >= 200 && r.status < 300 }

// send performs one request and returns the response whatever its status; an error means no
// response was received. The body is bounded by maxResponseSize. The request waits timeout
// (DefaultHTTPTimeout if zero) unless ctx has an earlier deadline.
func send(ctx context.Context, client *http.Client, timeout time.Duration, method string, u *url.URL, headers map[string]string, body []byte) (*httpResponse, error) {
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize))
	if err != nil {
		return nil, err
	}
	return &httpResponse{status: response.StatusCode, header: response.Header, body: data}, nil
}

// getJSON performs a GET and returns the body of a 2xx response.
func getJSON(ctx context.Context, client *http.Client, timeout time.Duration, u *url.URL, accept string) ([]byte, error) {
	response, err := send(ctx, client, timeout, http.MethodGet, u, map[string]string{"Accept": accept}, nil)
	if err != nil {
		return nil, err
	}
	if !response.successful() {
		return nil, fmt.Errorf("the transmitter answered with status %d", response.status)
	}
	return response.body, nil
}

// exchange calls an endpoint of the transmitter with the bearer token of the provider, a JSON
// body if not nil, and tries once more with a new token when the transmitter answers 401: the
// access token expired or was revoked. The response comes back whatever its status; an error
// means the token could not be obtained or no response was received.
func exchange(ctx context.Context, client *http.Client, tokens TokenProvider, timeout time.Duration, method string, u *url.URL, jsonBody []byte) (*httpResponse, error) {
	response, err := sendAuthenticated(ctx, client, tokens, timeout, method, u, jsonBody)
	if err != nil {
		return nil, err
	}
	if response.status == http.StatusUnauthorized {
		if invalidator, ok := tokens.(TokenInvalidator); ok {
			invalidator.Invalidate()
		}
		return sendAuthenticated(ctx, client, tokens, timeout, method, u, jsonBody)
	}
	return response, nil
}

func sendAuthenticated(ctx context.Context, client *http.Client, tokens TokenProvider, timeout time.Duration, method string, u *url.URL, jsonBody []byte) (*httpResponse, error) {
	headers := map[string]string{"Accept": "application/json"}
	if tokens != nil {
		token, err := tokens.AccessToken(ctx)
		if err != nil {
			return nil, err
		}
		if token != "" {
			headers["Authorization"] = "Bearer " + token
		}
	}
	if jsonBody != nil {
		headers["Content-Type"] = "application/json"
	}
	return send(ctx, client, timeout, method, u, headers, jsonBody)
}

// TokenProvider provides the access token the receiver authenticates with when it calls the
// stream management and poll endpoints of the transmitter. Implement it to obtain the token in
// another way than the built-in ones: NoToken, FixedToken and ClientCredentialsTokenProvider.
// A provider that also implements TokenInvalidator is told when the transmitter rejected the
// token.
type TokenProvider interface {
	// AccessToken is the token to send as bearer token, "" to call the transmitter without
	// authentication. A TransmitterUnavailableError says the token could not be obtained.
	AccessToken(ctx context.Context) (string, error)
}

// TokenInvalidator is implemented by a TokenProvider that caches tokens: Invalidate is called
// when the transmitter rejected the access token (HTTP 401), so that the next AccessToken is a
// new one.
type TokenInvalidator interface {
	Invalidate()
}

// FixedToken is a TokenProvider that always sends the same token, for transmitters that hand out
// long-lived tokens.
type FixedToken string

// AccessToken implements TokenProvider.
func (t FixedToken) AccessToken(context.Context) (string, error) { return string(t), nil }

// NoToken is a TokenProvider for transmitters whose endpoints need no authentication.
type NoToken struct{}

// AccessToken implements TokenProvider.
func (NoToken) AccessToken(context.Context) (string, error) { return "", nil }

// ClientCredentialsOptions say how a ClientCredentialsTokenProvider obtains tokens. Start from
// DefaultClientCredentialsOptions.
type ClientCredentialsOptions struct {
	// Scopes are the scopes to request, none by default.
	Scopes []string
	// AuthenticateWithRequestBody sends the client credentials in the request body
	// (client_secret_post) instead of with HTTP basic authentication (client_secret_basic,
	// RFC 6749, section 2.3.1).
	AuthenticateWithRequestBody bool
	// ExpirySafetyWindow is how long before its expiry a token is renewed, 30 seconds by
	// default; never more than a quarter of the token's lifetime.
	ExpirySafetyWindow time.Duration
	// AdditionalParameters are form parameters to send with the token request in addition to
	// the grant, for extensions of the token endpoint; grant_type and scope are not replaced.
	AdditionalParameters map[string]string
	// Timeout is how long the token request waits; DefaultHTTPTimeout if zero.
	Timeout time.Duration
	// Clock is the clock the expiry is measured by.
	Clock Clock
}

// DefaultClientCredentialsOptions are the defaults: basic authentication, a 30 second safety
// window.
func DefaultClientCredentialsOptions() ClientCredentialsOptions {
	return ClientCredentialsOptions{ExpirySafetyWindow: 30 * time.Second, Clock: SystemClock}
}

// ClientCredentialsTokenProvider is a TokenProvider that obtains access tokens with the OAuth2
// client credentials grant (RFC 6749, section 4.4) and caches them until shortly before they
// expire.
type ClientCredentialsTokenProvider struct {
	client       *http.Client
	tokenURL     *url.URL
	clientID     string
	clientSecret string
	options      ClientCredentialsOptions
	mu           sync.Mutex
	cached       string
	expiresAt    time.Time
}

// NewClientCredentialsTokenProvider is a provider that requests tokens at tokenURL for the
// client. A nil client is http.DefaultClient.
func NewClientCredentialsTokenProvider(client *http.Client, tokenURL *url.URL, clientID, clientSecret string, options ClientCredentialsOptions) *ClientCredentialsTokenProvider {
	if options.Clock == nil {
		options.Clock = SystemClock
	}
	return &ClientCredentialsTokenProvider{client: orDefault(client), tokenURL: tokenURL, clientID: clientID, clientSecret: clientSecret, options: options}
}

// AccessToken implements TokenProvider.
func (p *ClientCredentialsTokenProvider) AccessToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cached != "" && p.options.Clock().Before(p.expiresAt) {
		return p.cached, nil
	}
	token, expiresAt, err := p.requestToken(ctx)
	if err != nil {
		return "", err
	}
	p.cached, p.expiresAt = token, expiresAt
	return token, nil
}

// Invalidate implements TokenInvalidator: the next AccessToken requests a new token.
func (p *ClientCredentialsTokenProvider) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cached = ""
}

func (p *ClientCredentialsTokenProvider) requestToken(ctx context.Context) (string, time.Time, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if len(p.options.Scopes) > 0 {
		form.Set("scope", strings.Join(p.options.Scopes, " "))
	}
	for name, value := range p.options.AdditionalParameters {
		if name != "grant_type" && name != "scope" {
			form.Set(name, value)
		}
	}
	headers := map[string]string{"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
	if p.options.AuthenticateWithRequestBody {
		form.Set("client_id", p.clientID)
		form.Set("client_secret", p.clientSecret)
	} else {
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(p.clientID)+":"+url.QueryEscape(p.clientSecret)))
	}
	response, err := send(ctx, p.client, p.options.Timeout, http.MethodPost, p.tokenURL, headers, []byte(form.Encode()))
	if err != nil {
		return "", time.Time{}, Unavailable(err, "could not obtain an access token for the SSF transmitter from %s", p.tokenURL)
	}
	if !response.successful() {
		return "", time.Time{}, Unavailable(nil, "could not obtain an access token for the SSF transmitter from %s: the token endpoint answered with status %d", p.tokenURL, response.status)
	}
	var body struct {
		AccessToken string      `json:"access_token"`
		ExpiresIn   json.Number `json:"expires_in"`
	}
	if err := json.Unmarshal(response.body, &body); err != nil {
		return "", time.Time{}, Unavailable(err, "could not obtain an access token for the SSF transmitter from %s", p.tokenURL)
	}
	if strings.TrimSpace(body.AccessToken) == "" {
		return "", time.Time{}, Unavailable(nil, "the token response of %s has no access_token", p.tokenURL)
	}
	expiresIn := int64(60)
	if n, err := body.ExpiresIn.Int64(); err == nil && n > 0 {
		expiresIn = n
	} else if f, err := body.ExpiresIn.Float64(); err == nil && f > 0 {
		expiresIn = int64(f)
	}
	// renew ahead of the expiry, but still use a short-lived token for most of its lifetime
	window := p.options.ExpirySafetyWindow
	if quarter := time.Duration(expiresIn/4) * time.Second; window > quarter {
		window = quarter
	}
	return body.AccessToken, p.options.Clock().Add(time.Duration(expiresIn) * time.Second).Add(-window), nil
}

// Transmitter is one transmitter as the receiver holds it: its settings, how its SETs are
// verified, how it is called, the stream of the receiver at it, and the background work for it.
// Receiver.New builds one per configured transmitter; WithTransmitterCustomizer replaces parts
// before the receiver is assembled, and an application that assembles a receiver by hand fills
// one in directly.
type Transmitter struct {
	// Name is the name of the transmitter, DefaultTransmitterName for an unnamed one.
	Name string
	// Issuer is the issuer of the transmitter, the iss of its SETs.
	Issuer string
	// Config are the settings the transmitter was built from, zero if it was not.
	Config TransmitterConfig
	// Metadata resolves the metadata of the transmitter.
	Metadata *MetadataResolver
	// Keys supplies the JWK Set the SETs are verified against.
	Keys JWKSetSource
	// Verifier verifies the SETs of the transmitter.
	Verifier Verifier
	// Tokens authenticates the receiver at the transmitter; nil if the transmitter is not
	// called.
	Tokens TokenProvider
	// StreamClient calls the stream management API; nil if the transmitter is not called.
	StreamClient *StreamClient
	// Stream holds the stream of the receiver at the transmitter once it is known.
	Stream *ReceiverStream
	// Verification validates verification events of the transmitter; one that checks the
	// identifier of Stream by default.
	Verification *StreamVerification
	// Registrar looks the stream up or registers it; nil if the stream is neither looked up
	// nor managed.
	Registrar *StreamRegistrar
	// Poller polls the transmitter; nil with push delivery.
	Poller *Poller
	// AutoStartPolling says whether Start starts the Poller; poll.auto-startup.
	AutoStartPolling bool
	// PushAuthorizationHeader is the Authorization header the transmitter has to send to the
	// push endpoint, "" if none is expected.
	PushAuthorizationHeader string
}

// String is the name and issuer.
func (t *Transmitter) String() string { return fmt.Sprintf("%s (%s)", t.Name, t.Issuer) }

// Start starts the background work: looking up or registering the stream, and polling. The
// first poll follows the registration at once: the registrar wakes the poller.
func (t *Transmitter) Start(ctx context.Context) {
	if t.Registrar != nil {
		if t.Poller != nil {
			poller := t.Poller
			t.Registrar.AddListener(func(*ssf.StreamConfiguration) { poller.WakeUp() })
		}
		t.Registrar.Start(ctx)
	}
	if t.Poller != nil && t.AutoStartPolling {
		t.Poller.Start(ctx)
	}
}

// Stop stops the background work and sends the acknowledgements the poller owes.
func (t *Transmitter) Stop(ctx context.Context) {
	if t.Poller != nil {
		t.Poller.Stop(ctx)
	}
	if t.Registrar != nil {
		t.Registrar.Stop(ctx)
	}
}

// CriticalSubjectMembers are the critical_subject_members the transmitter declares in its
// metadata, empty if none or the metadata is not resolved yet: a SET of the transmitter was
// verified with its keys before, so the metadata is the resolved one.
func (t *Transmitter) CriticalSubjectMembers() []string {
	if t.Metadata == nil {
		return nil
	}
	if metadata := t.Metadata.Resolved(); metadata != nil {
		return metadata.CriticalSubjectMembers()
	}
	return nil
}

func orDefault(client *http.Client) *http.Client {
	if client == nil {
		return http.DefaultClient
	}
	return client
}

func orDiscard(log *slog.Logger) *slog.Logger {
	if log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return log
}
