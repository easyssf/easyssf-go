package receiver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/easyssf/easyssf-go/ssf"
)

// The transmitter: its metadata, how it is reached and what its URLs must look like. The token
// provider for the client credentials grant and the Transmitter type that assembles verifier,
// stream and poller of one transmitter are to follow (see transmitter.rs of the Rust port).

// WellKnownPath is where a transmitter publishes its metadata (SSF 1.0, section 7.2).
const WellKnownPath = "/.well-known/ssf-configuration"

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
	issuer   string
	urls     []*url.URL
	client   *http.Client
	policy   URIPolicy
	log      *slog.Logger
	mu       sync.Mutex
	metadata *ssf.TransmitterMetadata
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
	body, err := getJSON(ctx, r.client, u, "application/json")
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
	if len(insecure) > 0 {
		r.log.Warn("The SSF transmitter publishes endpoints without TLS, accepted because insecure http is allowed. For development only",
			"transmitter", r.issuer, "endpoints", insecure)
	}
	return nil
}

// getJSON performs a GET and returns the body of a 2xx response, bounded by maxResponseSize.
func getJSON(ctx context.Context, client *http.Client, u *url.URL, accept string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", accept)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("the transmitter answered with status %d", response.StatusCode)
	}
	return body, nil
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
