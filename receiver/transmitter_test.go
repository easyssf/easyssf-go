package receiver_test

// SsfTransmittersTests and SsfTransmitterTests of the Java library.

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssftest"
)

func TestInsertsWellKnownPathBetweenHostAndIssuerPath(t *testing.T) {
	urls, err := receiver.DeriveMetadataURLs("https://idp.example/realms/demo/")
	if err != nil || len(urls) != 2 || urls[0].String() != "https://idp.example/.well-known/ssf-configuration/realms/demo" ||
		urls[1].String() != "https://idp.example/realms/demo/.well-known/ssf-configuration" {
		t.Fatalf("%v %v", urls, err)
	}
	urls, _ = receiver.DeriveMetadataURLs("https://idp.example")
	if len(urls) != 1 || urls[0].String() != "https://idp.example/.well-known/ssf-configuration" {
		t.Fatalf("%v", urls)
	}
	for _, relative := range []string{"/realms/demo", "idp.example"} {
		if _, err := receiver.DeriveMetadataURLs(relative); err == nil {
			t.Fatal(relative)
		}
	}
}

func TestURIPolicyRequiresHTTPSExceptOnLoopback(t *testing.T) {
	policy := receiver.URIPolicy{}
	if u, err := policy.CheckIssuer("https://idp.example/realms/demo"); err != nil || u.Path != "/realms/demo" {
		t.Fatal(err)
	}
	if _, err := policy.CheckIssuer("http://idp.example/realms/demo"); err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("%v", err)
	}
	for _, issuer := range []string{"http://localhost:8080/realms/demo", "http://127.0.0.1:8080/x", "http://[::1]:8080/x", "http://app.localhost/x"} {
		if _, err := policy.CheckIssuer(issuer); err != nil {
			t.Fatal(issuer)
		}
	}
	insecure := receiver.URIPolicy{AllowInsecureHTTP: true}
	if _, err := insecure.CheckIssuer("http://idp.example/realms/demo"); err != nil {
		t.Fatal(err)
	}
	if _, err := insecure.CheckIssuer("ftp://idp.example/realms/demo"); err == nil {
		t.Fatal("ftp")
	}
	for _, bad := range []string{"https://idp.example/x?y=1", "https://idp.example/x#frag", "https://", "mailto:alice@example.com", "not a uri"} {
		if _, err := policy.CheckIssuer(bad); err == nil {
			t.Fatal(bad)
		}
	}
	// endpoints follow the same rules but may have a query
	endpoint := func(raw string) *url.URL { u, _ := url.Parse(raw); return u }
	if err := policy.CheckEndpoint(endpoint("https://idp.example/jwks?x=1"), "The JWK Set URL"); err != nil {
		t.Fatal(err)
	}
	if err := policy.CheckEndpoint(endpoint("https://idp.example/jwks#f"), "The JWK Set URL"); err == nil || !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("%v", err)
	}
	if err := policy.CheckEndpoint(endpoint("http://idp.example/jwks"), "The JWK Set URL"); err == nil {
		t.Fatal("http")
	}
	if err := policy.CheckEndpoint(endpoint("http://localhost/jwks"), "The JWK Set URL"); err != nil {
		t.Fatal(err)
	}
}

func transmitterNamed(t *testing.T, name string, test *ssftest.TestTransmitter, header string) *receiver.Transmitter {
	t.Helper()
	return &receiver.Transmitter{Name: name, Issuer: test.Issuer(), Metadata: metadataResolver(t, test), Verifier: verifier(t, test), PushAuthorizationHeader: header}
}

func two(t *testing.T) (*ssftest.TestTransmitter, *ssftest.TestTransmitter, *receiver.Receiver) {
	t.Helper()
	first := ssftest.WithMetadata(ssftest.MetadataSSF, "first.example")
	second := ssftest.WithMetadata(ssftest.MetadataSSF, "second.example")
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = first.Issuer()
	config.ExpectedAudience = ssftest.Audience
	config.Push.ExpectedAuthHeader = "Bearer first"
	other := receiver.DefaultTransmitterConfig()
	other.TransmitterIssuer = second.Issuer()
	other.ExpectedAudience = ssftest.Audience
	config.Transmitters = map[string]receiver.TransmitterConfig{"second": other}
	rcv, err := receiver.New(config, receiver.WithHTTPClient(ssftest.ClientFor(first, second)))
	if err != nil {
		t.Fatal(err)
	}
	return first, second, rcv
}

func TestVerifiesSetsOfEveryTransmitterByIssuer(t *testing.T) {
	first, second, rcv := two(t)
	r := &recorder{}
	rcv.Processor().AddHandler(r)
	push := rcv.PushHandler()
	set := []byte(first.Set("CaepSessionRevoked", alice(first)))
	if push.Handle(ctx, "", set).Status != 401 || push.Handle(ctx, "Bearer first", set).Status != 202 {
		t.Fatal("first")
	}
	set = []byte(second.Set("CaepSessionRevoked", ssf.IssSub(second.Issuer(), "bob")))
	if push.Handle(ctx, "", set).Status != 202 {
		t.Fatal("the second expects no header")
	}
	if r.count.Load() != 2 {
		t.Fatal("both handled")
	}
	claims := first.SetClaims("CaepSessionRevoked", alice(first))
	claims["iss"] = "https://unknown.example"
	if response := push.Handle(ctx, "", []byte(first.SignSET(claims))); response.Status != 400 || errorCode(t, response) != "invalid_issuer" {
		t.Fatalf("%+v", response)
	}
}

func TestLooksUpTransmittersByNameAndIssuer(t *testing.T) {
	first, second, rcv := two(t)
	if rcv.Transmitter("second").Issuer != second.Issuer() || rcv.TransmitterByIssuer(first.Issuer()).Name != "default" || rcv.Transmitter("third") != nil {
		t.Fatal("lookup")
	}
	if rcv.NameOf(second.Issuer()) != "second" || rcv.NameOf("https://unknown.example") != "https://unknown.example" {
		t.Fatal("name_of")
	}
	if rcv.TransmitterByIssuer(first.Issuer()).PushAuthorizationHeader != "Bearer first" || rcv.TransmitterByIssuer(second.Issuer()).PushAuthorizationHeader != "" {
		t.Fatal("headers")
	}
	if len(rcv.TransmitterByIssuer(first.Issuer()).CriticalSubjectMembers()) != 0 {
		t.Fatal("metadata not resolved yet")
	}
	if len(rcv.Transmitters()) != 2 || rcv.Transmitters()[0].Name != "default" || rcv.Transmitters()[0].String() != "default ("+first.Issuer()+")" {
		t.Fatal("default first")
	}
}

func TestRejectsDuplicateIssuers(t *testing.T) {
	test := ssftest.New()
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = test.Issuer()
	config.ExpectedAudience = ssftest.Audience
	same := receiver.DefaultTransmitterConfig()
	same.TransmitterIssuer = test.Issuer()
	same.ExpectedAudience = ssftest.Audience
	config.Transmitters = map[string]receiver.TransmitterConfig{"y": same}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "same issuer") {
		t.Fatalf("%v", err)
	}
	config.Transmitters = map[string]receiver.TransmitterConfig{"default": same}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "transmitters.default") {
		t.Fatalf("%v", err)
	}
	// the default transmitter is not needed when others are configured
	config.TransmitterIssuer = ""
	config.Transmitters = map[string]receiver.TransmitterConfig{"okta": same}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	rcv, err := receiver.New(config, receiver.WithHTTPClient(test.Client))
	if err != nil || len(rcv.Transmitters()) != 1 || rcv.Transmitters()[0].Name != "okta" {
		t.Fatalf("%v", err)
	}
}

func TestPollerFetchesAsSoonAsTheStreamIsRegistered(t *testing.T) {
	test := ssftest.New()
	resolver := metadataResolver(t, test)
	tokens := receiver.FixedToken(ssftest.AccessToken)
	client := receiver.NewStreamClient(resolver, test.Client, tokens)
	stream := receiver.NewReceiverStream()
	registrar := receiver.NewStreamRegistrarForManagedStream(client, stream, ssf.PollStream([]string{"CaepSessionRevoked"}, ""))
	options := receiver.DefaultPollerOptions()
	options.Interval, options.EndpointRetry = time.Minute, time.Minute
	poller := receiver.NewPoller(test.Client, tokens, stream.PollEndpointURL, processor(t, test), options)
	built := transmitterNamed(t, "default", test, "")
	built.Stream, built.Registrar, built.Poller, built.AutoStartPolling = stream, registrar, poller, true
	built.Start(ctx)
	// the poller looked once without an endpoint and would wait a minute; the registration wakes it
	ssftest.Eventually(t, 5*time.Second, "a poll right after the registration", func() bool { return test.PollRequests() >= 1 })
	built.Stop(ctx)
	if built.Poller.IsRunning() || built.Registrar.IsRunning() {
		t.Fatal("stopped")
	}
}

func TestClientCredentialsTokenIsCachedUntilShortlyBeforeItExpires(t *testing.T) {
	test := ssftest.New()
	clock := newTestClock()
	tokenURL, _ := url.Parse(test.TokenURL())
	options := receiver.DefaultClientCredentialsOptions()
	options.Clock = clock.Now
	options.Scopes = []string{"ssf.read"}
	provider := receiver.NewClientCredentialsTokenProvider(test.Client, tokenURL, ssftest.ClientID, ssftest.ClientSecret, options)
	token, err := provider.AccessToken(ctx)
	if err != nil || token != ssftest.AccessToken {
		t.Fatalf("%q %v", token, err)
	}
	// the transmitter issues tokens for 300 seconds, renewed 30 seconds ahead
	clock.Advance(260 * time.Second)
	_, _ = provider.AccessToken(ctx)
	if test.TokenRequests() != 1 {
		t.Fatal("cached")
	}
	clock.Advance(20 * time.Second)
	_, _ = provider.AccessToken(ctx)
	if test.TokenRequests() != 2 {
		t.Fatal("renewed ahead of the expiry")
	}
	provider.Invalidate()
	_, _ = provider.AccessToken(ctx)
	if test.TokenRequests() != 3 {
		t.Fatal("invalidated")
	}
	// client_secret_post and wrong credentials
	options.AuthenticateWithRequestBody = true
	post := receiver.NewClientCredentialsTokenProvider(test.Client, tokenURL, ssftest.ClientID, ssftest.ClientSecret, options)
	if _, err := post.AccessToken(ctx); err != nil {
		t.Fatal(err)
	}
	wrong := receiver.NewClientCredentialsTokenProvider(test.Client, tokenURL, ssftest.ClientID, "nope", options)
	if _, err := wrong.AccessToken(ctx); !receiver.IsTransmitterUnavailable(err) {
		t.Fatalf("%v", err)
	}
}
