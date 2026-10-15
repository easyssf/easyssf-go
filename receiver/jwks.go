package receiver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// JWKSetSource supplies the JWK Set the SETs of a transmitter are verified against.
type JWKSetSource interface {
	// JWKSet is the current JWK Set. refresh asks for a fetch because a SET names a key that is
	// not in the cached set; a source may rate limit that. A TransmitterUnavailableError says
	// the keys could not be obtained right now.
	JWKSet(ctx context.Context, refresh bool) (*jose.JSONWebKeySet, error)
}

// StaticJWKSet is a JWKSetSource over keys known in advance.
type StaticJWKSet jose.JSONWebKeySet

// JWKSet is the keys.
func (s *StaticJWKSet) JWKSet(context.Context, bool) (*jose.JSONWebKeySet, error) {
	return (*jose.JSONWebKeySet)(s), nil
}

// JWKSetURLResolver resolves the location of the JWK Set on first use, for example from the
// transmitter metadata.
type JWKSetURLResolver func(ctx context.Context) (*url.URL, error)

// HTTPJWKSetSource is a JWKSetSource that fetches the JWK Set over HTTP and caches it. The
// location is resolved on first use, so a transmitter that is not reachable does not prevent the
// receiver from starting. The JWK Set is fetched again after CacheLifetime, and when a SET is
// signed with a key that is not in it, at most once per RefreshRateLimit, so that bogus SETs
// cannot make the receiver flood the transmitter.
type HTTPJWKSetSource struct {
	// CacheLifetime is how long a fetched JWK Set is used before it is fetched again; five
	// minutes by default.
	CacheLifetime time.Duration
	// RefreshRateLimit is how soon after a fetch the JWK Set may be fetched again because a
	// SET names a key that is not in it; 30 seconds by default.
	RefreshRateLimit time.Duration
	// Clock is the clock the cache ages by; the system clock by default.
	Clock Clock
	// Timeout is how long a fetch waits for the response; DefaultHTTPTimeout if zero.
	Timeout time.Duration
	// Authorizer adds what the fetch needs, for example an API key; nothing if nil.
	Authorizer Authorizer
	// Retry says how a failed fetch is tried again; not at all if zero.
	Retry RetryOptions
	// Policy decides which redirects of the JWK Set URL are followed; the strict one (https, or
	// http on loopback) by default.
	Policy URIPolicy

	client  *http.Client
	fixed   *url.URL
	resolve JWKSetURLResolver

	mu        sync.Mutex
	url       *url.URL
	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
}

// NewHTTPJWKSetSource fetches the JWK Set at a known location. A nil client is
// http.DefaultClient.
func NewHTTPJWKSetSource(client *http.Client, u *url.URL) *HTTPJWKSetSource {
	return &HTTPJWKSetSource{CacheLifetime: 5 * time.Minute, RefreshRateLimit: 30 * time.Second, Clock: SystemClock,
		client: orDefault(client), fixed: u}
}

// NewResolvedHTTPJWKSetSource fetches the JWK Set at a location resolved on first use.
func NewResolvedHTTPJWKSetSource(client *http.Client, resolve JWKSetURLResolver) *HTTPJWKSetSource {
	source := NewHTTPJWKSetSource(client, nil)
	source.resolve = resolve
	return source
}

func (s *HTTPJWKSetSource) needsFetch(now time.Time, refresh bool) bool {
	if s.keys == nil {
		return true
	}
	age := now.Sub(s.fetchedAt)
	return age >= s.CacheLifetime || (refresh && age >= s.RefreshRateLimit)
}

// JWKSet implements JWKSetSource. Concurrent callers wait for one fetch.
func (s *HTTPJWKSetSource) JWKSet(ctx context.Context, refresh bool) (*jose.JSONWebKeySet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Clock()
	if !s.needsFetch(now, refresh) {
		return s.keys, nil
	}
	if s.url == nil {
		if s.fixed != nil {
			s.url = s.fixed
		} else {
			u, err := s.resolve(ctx)
			if err != nil {
				return nil, err
			}
			s.url = u
		}
	}
	body, err := getJSON(WithEndpoint(ctx, EndpointJWKS), s.client, s.Authorizer, s.Policy, s.Retry, s.Timeout, s.url, "application/jwk-set+json, application/json")
	if err != nil {
		return nil, Unavailable(err, "could not retrieve the keys to verify the SET from %s", s.url)
	}
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, Unavailable(err, "the JWK Set endpoint %s did not answer with a JWK Set", s.url)
	}
	s.keys = &keys
	s.fetchedAt = s.Clock()
	return s.keys, nil
}
