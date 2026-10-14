package receiver_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/caep"
	"github.com/easyssf/easyssf-go/ssftest"
)

// flakyTransport fails the first `failures` requests with the status, or a connection error
// if the status is 0, and records every request that reaches it.
type flakyTransport struct {
	next     http.RoundTripper
	status   int
	failures int
	headers  http.Header

	mu       sync.Mutex
	attempts int
	requests []*http.Request
}

func (f *flakyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.attempts++
	f.requests = append(f.requests, r.Clone(r.Context()))
	attempt := f.attempts
	f.mu.Unlock()
	if attempt <= f.failures {
		if f.status == 0 {
			return nil, errors.New("connection refused")
		}
		return &http.Response{StatusCode: f.status, Header: f.headers.Clone(), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}
	return f.next.RoundTrip(r)
}

func (f *flakyTransport) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}

func flaky(transmitter *ssftest.TestTransmitter, status, failures int) (*flakyTransport, *http.Client) {
	transport := &flakyTransport{next: transmitter.Client.Transport, status: status, failures: failures, headers: http.Header{}}
	return transport, &http.Client{Transport: transport}
}

func quickRetry() receiver.RetryOptions {
	return receiver.RetryOptions{MaxRetries: 2, InitialBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}
}

func TestRetriesManagementCallThatFailsWith503(t *testing.T) {
	transmitter := ssftest.New()
	transport, client := flaky(transmitter, http.StatusServiceUnavailable, 2)
	metadata, _ := receiver.NewMetadataResolver(transmitter.Issuer(), nil, transmitter.Client, receiver.URIPolicy{}, nil)
	streams := receiver.NewStreamClient(metadata, client, receiver.FixedToken(ssftest.AccessToken))
	streams.Retry = quickRetry()
	if _, err := streams.Streams(ctx); err != nil {
		t.Fatal(err)
	}
	if transport.count() != 3 {
		t.Fatalf("%d attempts", transport.count())
	}
}

func TestRetriesManagementCallThatFailsWithConnectionError(t *testing.T) {
	transmitter := ssftest.New()
	transport, client := flaky(transmitter, 0, 1)
	metadata, _ := receiver.NewMetadataResolver(transmitter.Issuer(), nil, transmitter.Client, receiver.URIPolicy{}, nil)
	streams := receiver.NewStreamClient(metadata, client, receiver.FixedToken(ssftest.AccessToken))
	streams.Retry = quickRetry()
	if _, err := streams.Streams(ctx); err != nil {
		t.Fatal(err)
	}
	if transport.count() != 2 {
		t.Fatalf("%d attempts", transport.count())
	}
}

func TestGivesUpAfterMaxRetries(t *testing.T) {
	transmitter := ssftest.New()
	transport, client := flaky(transmitter, http.StatusBadGateway, 10)
	metadata, _ := receiver.NewMetadataResolver(transmitter.Issuer(), nil, transmitter.Client, receiver.URIPolicy{}, nil)
	streams := receiver.NewStreamClient(metadata, client, receiver.FixedToken(ssftest.AccessToken))
	streams.Retry = quickRetry()
	_, err := streams.Streams(ctx)
	var streamErr *receiver.StreamError
	if !errors.As(err, &streamErr) || streamErr.Status != http.StatusBadGateway {
		t.Fatalf("%v", err)
	}
	if transport.count() != 3 {
		t.Fatalf("%d attempts", transport.count())
	}
}

func TestDoesNotRetryClientErrors(t *testing.T) {
	transmitter := ssftest.New()
	transport, client := flaky(transmitter, http.StatusBadRequest, 10)
	metadata, _ := receiver.NewMetadataResolver(transmitter.Issuer(), nil, transmitter.Client, receiver.URIPolicy{}, nil)
	streams := receiver.NewStreamClient(metadata, client, receiver.FixedToken(ssftest.AccessToken))
	streams.Retry = quickRetry()
	if _, err := streams.Streams(ctx); err == nil {
		t.Fatal("expected the 400")
	}
	if transport.count() != 1 {
		t.Fatalf("%d attempts", transport.count())
	}
}

func TestDoesNotRetryWithoutRetryOptions(t *testing.T) {
	transmitter := ssftest.New()
	transport, client := flaky(transmitter, http.StatusServiceUnavailable, 1)
	metadata, _ := receiver.NewMetadataResolver(transmitter.Issuer(), nil, transmitter.Client, receiver.URIPolicy{}, nil)
	streams := receiver.NewStreamClient(metadata, client, receiver.FixedToken(ssftest.AccessToken))
	if _, err := streams.Streams(ctx); err == nil {
		t.Fatal("expected the 503")
	}
	if transport.count() != 1 {
		t.Fatalf("%d attempts", transport.count())
	}
}

func TestRetryWaitsForRetryAfterCappedAtMaxBackoff(t *testing.T) {
	transmitter := ssftest.New()
	transport, client := flaky(transmitter, http.StatusTooManyRequests, 1)
	transport.headers.Set("Retry-After", "3600")
	metadata, _ := receiver.NewMetadataResolver(transmitter.Issuer(), nil, transmitter.Client, receiver.URIPolicy{}, nil)
	streams := receiver.NewStreamClient(metadata, client, receiver.FixedToken(ssftest.AccessToken))
	streams.Retry = receiver.RetryOptions{MaxRetries: 1, InitialBackoff: time.Millisecond, MaxBackoff: 20 * time.Millisecond}
	started := time.Now()
	if _, err := streams.Streams(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("waited %v", elapsed)
	}
}

func TestRetryStopsWhenTheContextIsCancelled(t *testing.T) {
	transmitter := ssftest.New()
	transport, client := flaky(transmitter, http.StatusServiceUnavailable, 10)
	metadata, _ := receiver.NewMetadataResolver(transmitter.Issuer(), nil, transmitter.Client, receiver.URIPolicy{}, nil)
	streams := receiver.NewStreamClient(metadata, client, receiver.FixedToken(ssftest.AccessToken))
	streams.Retry = receiver.RetryOptions{MaxRetries: 10, InitialBackoff: time.Hour, MaxBackoff: time.Hour}
	cancelled, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := streams.Streams(cancelled); err == nil {
		t.Fatal("expected an error")
	}
	if transport.count() != 1 {
		t.Fatalf("%d attempts", transport.count())
	}
}

func TestMetadataAndKeysAreFetchedAgainAfterTransientFailure(t *testing.T) {
	transmitter := ssftest.New()
	transport, client := flaky(transmitter, http.StatusGatewayTimeout, 1)
	metadata, _ := receiver.NewMetadataResolver(transmitter.Issuer(), nil, client, receiver.URIPolicy{}, nil)
	metadata.Retry = quickRetry()
	resolved, err := metadata.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if transport.count() != 2 {
		t.Fatalf("%d attempts", transport.count())
	}
	keys := receiver.NewHTTPJWKSetSource(client, resolved.JWKSURI())
	keys.Retry = quickRetry()
	transport.mu.Lock()
	transport.attempts, transport.failures = 0, 1
	transport.mu.Unlock()
	if _, err := keys.JWKSet(ctx, false); err != nil {
		t.Fatal(err)
	}
	if transport.count() != 2 {
		t.Fatalf("%d attempts", transport.count())
	}
}

func TestStaticHeadersAreSentWithEveryCall(t *testing.T) {
	transmitter := ssftest.New()
	transport, client := flaky(transmitter, 0, 0)
	metadata, _ := receiver.NewMetadataResolver(transmitter.Issuer(), nil, client, receiver.URIPolicy{}, nil)
	metadata.Authorizer = receiver.StaticHeaders{"X-Api-Key": "k3y"}
	streams := receiver.NewStreamClient(metadata, client, receiver.Authorizers{
		receiver.StaticHeaders{"X-Api-Key": "k3y"}, receiver.FixedToken(ssftest.AccessToken)})
	if _, err := streams.Streams(ctx); err != nil {
		t.Fatal(err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.requests) != 2 {
		t.Fatalf("%d requests", len(transport.requests))
	}
	for _, request := range transport.requests {
		if request.Header.Get("X-Api-Key") != "k3y" {
			t.Fatalf("%s %s lacks the header", request.Method, request.URL)
		}
	}
	if auth := transport.requests[1].Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("%q", auth)
	}
}

func TestEndpointHeadersReachOnlyTheirEndpoint(t *testing.T) {
	transmitter := ssftest.New()
	transport, client := flaky(transmitter, 0, 0)
	metadata, _ := receiver.NewMetadataResolver(transmitter.Issuer(), nil, client, receiver.URIPolicy{}, nil)
	streams := receiver.NewStreamClient(metadata, client, receiver.Authorizers{
		receiver.EndpointHeaders{receiver.EndpointStatus: {"X-Status": "yes"}}, receiver.FixedToken(ssftest.AccessToken)})
	created, err := streams.CreateStream(ctx, pushStream("CaepSessionRevoked"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := streams.Status(ctx, created.StreamID()); err != nil {
		t.Fatal(err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	var withHeader []string
	for _, request := range transport.requests {
		if request.Header.Get("X-Status") != "" {
			withHeader = append(withHeader, request.URL.Path)
		}
	}
	if len(withHeader) != 1 || !strings.HasSuffix(withHeader[0], "/ssf/status") {
		t.Fatalf("%v", withHeader)
	}
}

func TestAuthorizerChainInvalidatesTheTokenOn401(t *testing.T) {
	transmitter := ssftest.New()
	streams := receiver.NewStreamClient(metadataResolver(t, transmitter), transmitter.Client, receiver.Authorizers{
		receiver.StaticHeaders{"X-Tenant": "acme"}, receiver.BearerToken(tokenProvider(t, transmitter))})
	if _, err := streams.Streams(ctx); err != nil {
		t.Fatal(err)
	}
	transmitter.ExpireAccessTokens()
	if _, err := streams.Streams(ctx); err != nil {
		t.Fatal(err)
	}
	if transmitter.TokenRequests() != 2 {
		t.Fatalf("%d token requests", transmitter.TokenRequests())
	}
}

func TestAuthorizerFuncSeesTheEndpoint(t *testing.T) {
	transmitter := ssftest.New()
	var seen []receiver.Endpoint
	var mu sync.Mutex
	record := receiver.AuthorizerFunc(func(ctx context.Context, r *http.Request) error {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, receiver.EndpointOf(ctx))
		return nil
	})
	metadata, _ := receiver.NewMetadataResolver(transmitter.Issuer(), nil, transmitter.Client, receiver.URIPolicy{}, nil)
	metadata.Authorizer = record
	streams := receiver.NewStreamClient(metadata, transmitter.Client, receiver.Authorizers{record, receiver.FixedToken(ssftest.AccessToken)})
	if _, err := streams.Streams(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != receiver.EndpointMetadata || seen[1] != receiver.EndpointConfiguration {
		t.Fatalf("%v", seen)
	}
}

func TestConfiguredHeadersAreSentToTheTransmitter(t *testing.T) {
	transmitter := ssftest.New()
	transport, client := flaky(transmitter, 0, 0)
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = transmitter.Issuer()
	config.TransmitterAccessToken = ssftest.AccessToken
	config.Headers = map[string]string{"X-Api-Key": "k3y"}
	config.ExpectedAudience = ssftest.Audience
	config.Push.ExpectedAuthHeader = "Bearer s3cr3t"
	rcv, err := receiver.New(config, receiver.WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rcv.Transmitters()[0].StreamClient.Streams(ctx); err != nil {
		t.Fatal(err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	for _, request := range transport.requests {
		if request.Header.Get("X-Api-Key") != "k3y" {
			t.Fatalf("%s lacks the header", request.URL)
		}
	}
}

func TestAcceptsSETBuiltWithTheBuilderAndSignedWithTheSigner(t *testing.T) {
	transmitter := ssftest.New()
	claims, err := ssf.NewSET(transmitter.Issuer()).
		Audience(ssftest.Audience).
		Subject(ssf.Complex(ssf.IssSub(transmitter.Issuer(), "alice"), ssf.Opaque("session-1"))).
		Event("CaepSessionRevoked", caep.NewPayload().EventTimestamp(time.Now()).InitiatingEntity("admin").ReasonAdmin("en", "Policy").Build()).
		Claims()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := transmitter.Signer().Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := verifier(t, transmitter).Verify(ctx, encoded)
	if err != nil {
		t.Fatal(err)
	}
	events := caep.InToken(token)
	if len(events) != 1 || events[0].Kind() != caep.SessionRevoked || events[0].InitiatingEntity() != "admin" || events[0].ReasonAdmin()["en"] != "Policy" {
		t.Fatalf("%v", token.Claims())
	}
}
