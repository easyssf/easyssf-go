package receiver

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Authorizer adds what a request to the transmitter needs to be accepted: the bearer token of a
// TokenProvider (BearerToken), fixed headers such as an API key (StaticHeaders), headers for
// particular endpoints (EndpointHeaders), or anything else, chained with Authorizers. Every call
// of the receiver to the transmitter goes through one: metadata, JWK Set, stream management and
// poll requests. The endpoint a request is for is in its context, see EndpointOf.
//
// An Authorizer that also implements TokenInvalidator is told when the transmitter rejected a
// request with 401, and the request is sent once more.
type Authorizer interface {
	Authorize(ctx context.Context, r *http.Request) error
}

// AuthorizerFunc is an Authorizer written as a function.
type AuthorizerFunc func(ctx context.Context, r *http.Request) error

// Authorize implements Authorizer.
func (f AuthorizerFunc) Authorize(ctx context.Context, r *http.Request) error { return f(ctx, r) }

// Endpoint names the endpoint of the transmitter a request is for, for an Authorizer that treats
// endpoints differently.
type Endpoint string

// The endpoints a request can be for.
const (
	// EndpointMetadata: the transmitter configuration metadata.
	EndpointMetadata Endpoint = "metadata"
	// EndpointJWKS: the JWK Set.
	EndpointJWKS Endpoint = "jwks"
	// EndpointToken: the token endpoint of the client credentials grant.
	EndpointToken Endpoint = "token"
	// EndpointConfiguration: the configuration endpoint of the stream management API.
	EndpointConfiguration Endpoint = "configuration"
	// EndpointStatus: the status endpoint.
	EndpointStatus Endpoint = "status"
	// EndpointAddSubject: the add subject endpoint.
	EndpointAddSubject Endpoint = "add_subject"
	// EndpointRemoveSubject: the remove subject endpoint.
	EndpointRemoveSubject Endpoint = "remove_subject"
	// EndpointVerification: the verification endpoint.
	EndpointVerification Endpoint = "verification"
	// EndpointPoll: the poll endpoint of the stream.
	EndpointPoll Endpoint = "poll"
)

type endpointKey struct{}

// WithEndpoint marks the context of a request with the endpoint it is for.
func WithEndpoint(ctx context.Context, endpoint Endpoint) context.Context {
	return context.WithValue(ctx, endpointKey{}, endpoint)
}

// EndpointOf is the endpoint the request of the context is for, "" if unknown.
func EndpointOf(ctx context.Context) Endpoint {
	endpoint, _ := ctx.Value(endpointKey{}).(Endpoint)
	return endpoint
}

// NoAuthorization is an Authorizer that changes nothing: for transmitters whose endpoints need
// no authentication.
type NoAuthorization struct{}

// Authorize implements Authorizer.
func (NoAuthorization) Authorize(context.Context, *http.Request) error { return nil }

// bearerToken sends the token of a TokenProvider as bearer token.
type bearerToken struct{ provider TokenProvider }

// BearerToken is an Authorizer that sends the access token of the provider as bearer token
// (RFC 6750); none if the provider gives "". It passes an Invalidate of the provider on.
func BearerToken(provider TokenProvider) Authorizer {
	if provider == nil {
		return NoAuthorization{}
	}
	if authorizer, ok := provider.(Authorizer); ok {
		return authorizer
	}
	return &bearerToken{provider: provider}
}

func (b *bearerToken) Authorize(ctx context.Context, r *http.Request) error {
	token, err := b.provider.AccessToken(ctx)
	if err != nil {
		return err
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return nil
}

func (b *bearerToken) Invalidate() {
	if invalidator, ok := b.provider.(TokenInvalidator); ok {
		invalidator.Invalidate()
	}
}

// Authorize implements Authorizer: the fixed token as bearer token.
func (t FixedToken) Authorize(_ context.Context, r *http.Request) error {
	if t != "" {
		r.Header.Set("Authorization", "Bearer "+string(t))
	}
	return nil
}

// Authorize implements Authorizer: nothing.
func (NoToken) Authorize(context.Context, *http.Request) error { return nil }

// Authorize implements Authorizer: the current access token as bearer token.
func (p *ClientCredentialsTokenProvider) Authorize(ctx context.Context, r *http.Request) error {
	token, err := p.AccessToken(ctx)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// StaticHeaders is an Authorizer that sets fixed headers on every request, for example an API
// key the transmitter wants besides, or instead of, a bearer token.
type StaticHeaders map[string]string

// Authorize implements Authorizer.
func (h StaticHeaders) Authorize(_ context.Context, r *http.Request) error {
	for name, value := range h {
		r.Header.Set(name, value)
	}
	return nil
}

// EndpointHeaders is an Authorizer that sets headers on the requests to particular endpoints
// only, by Endpoint.
type EndpointHeaders map[Endpoint]map[string]string

// Authorize implements Authorizer.
func (h EndpointHeaders) Authorize(ctx context.Context, r *http.Request) error {
	for name, value := range h[EndpointOf(ctx)] {
		r.Header.Set(name, value)
	}
	return nil
}

// Authorizers is an Authorizer that applies several in order; an Invalidate reaches every one
// that implements TokenInvalidator.
type Authorizers []Authorizer

// Authorize implements Authorizer.
func (a Authorizers) Authorize(ctx context.Context, r *http.Request) error {
	for _, authorizer := range a {
		if authorizer == nil {
			continue
		}
		if err := authorizer.Authorize(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// Invalidate implements TokenInvalidator.
func (a Authorizers) Invalidate() {
	for _, authorizer := range a {
		if invalidator, ok := authorizer.(TokenInvalidator); ok {
			invalidator.Invalidate()
		}
	}
}

func invalidate(authorizer Authorizer) bool {
	if invalidator, ok := authorizer.(TokenInvalidator); ok {
		invalidator.Invalidate()
		return true
	}
	return false
}

// RetryOptions say how a call to the transmitter that fails for a reason that may pass is
// tried again: a connection error, or a response with one of the RetryableStatuses. The delay
// starts at InitialBackoff, doubles up to MaxBackoff, and follows a Retry-After header in
// seconds when the transmitter sends one. Management, metadata and JWK Set calls retry; poll
// requests do not, the poller has its interval and honours Retry-After itself. Start from
// DefaultRetryOptions; a zero value does not retry.
type RetryOptions struct {
	// MaxRetries is how many times a failed call is tried again; 0 never.
	MaxRetries int
	// InitialBackoff is the delay before the first retry.
	InitialBackoff time.Duration
	// MaxBackoff is the longest delay between two tries.
	MaxBackoff time.Duration
	// RetryableStatuses are the HTTP statuses that are tried again; 408, 429, 500, 502, 503
	// and 504 if nil.
	RetryableStatuses []int
}

// DefaultRetryOptions are the defaults: two retries, a quarter of a second doubling up to five
// seconds, on 408, 429, 500, 502, 503 and 504.
func DefaultRetryOptions() RetryOptions {
	return RetryOptions{MaxRetries: 2, InitialBackoff: 250 * time.Millisecond, MaxBackoff: 5 * time.Second}
}

var defaultRetryableStatuses = []int{http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
	http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout}

func (o RetryOptions) retryable(status int) bool {
	statuses := o.RetryableStatuses
	if statuses == nil {
		statuses = defaultRetryableStatuses
	}
	for _, candidate := range statuses {
		if candidate == status {
			return true
		}
	}
	return false
}

// retrying runs the call and tries it again per the options; the last response or error is
// returned.
func retrying(ctx context.Context, options RetryOptions, call func(ctx context.Context) (*httpResponse, error)) (*httpResponse, error) {
	delay := options.InitialBackoff
	if delay <= 0 {
		delay = 250 * time.Millisecond
	}
	for attempt := 0; ; attempt++ {
		response, err := call(ctx)
		if attempt >= options.MaxRetries || ctx.Err() != nil {
			return response, err
		}
		if err == nil && !options.retryable(response.status) {
			return response, nil
		}
		if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, ErrResponseTooLarge)) {
			return nil, err
		}
		wait := delay
		if response != nil {
			if after, ok := retryAfter(response); ok {
				wait = after
			}
		}
		if options.MaxBackoff > 0 && wait > options.MaxBackoff {
			wait = options.MaxBackoff
		}
		select {
		case <-ctx.Done():
			return response, err
		case <-time.After(wait):
		}
		if delay *= 2; options.MaxBackoff > 0 && delay > options.MaxBackoff {
			delay = options.MaxBackoff
		}
	}
}

// retryAfter reads a Retry-After header in seconds (RFC 9110, section 10.2.3); a date is
// treated like no header.
func retryAfter(response *httpResponse) (time.Duration, bool) {
	seconds, err := strconv.ParseInt(strings.TrimSpace(response.header.Get("Retry-After")), 10, 64)
	if err != nil || seconds < 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}
