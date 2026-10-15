package receiver_test

// The configured receiver: SsfReceiverOptionsValidator, SsfTransmitterFactory and the hosting
// integration tests of the .NET port.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
	"github.com/easyssf/easyssf-go/ssftest"
)

func pushConfig(transmitter *ssftest.TestTransmitter) receiver.Config {
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = transmitter.Issuer()
	config.ExpectedAudience = ssftest.Audience
	config.Push.ExpectedAuthHeader = secret
	return config
}

func TestConfigBindsFromJSONWithDefaultsAndKebabCaseKeys(t *testing.T) {
	config := receiver.DefaultConfig()
	err := json.Unmarshal([]byte(`{
		"transmitter-issuer": "https://idp.example/realms/demo",
		"delivery-method": "poll",
		"event-aliases": {"AcmeLoginCfg": "https://events.acme.example/login"},
		"oauth2": {"token-uri": "https://idp.example/token", "client-id": "app", "client-secret": "secret", "scopes": ["ssf.read"], "client-authentication-method": "post"},
		"stream": {"management": "receiver", "events-requested": ["CaepSessionRevoked"]},
		"poll": {"interval": "10s", "long-polling": true, "rate-limit": {"fallback-backoff": "2m"}},
		"set-validation": {"accepted-algorithms": ["RS256", "PS256"], "subject-compatibility": "legacy"},
		"dedup": {"lease": "90s"},
		"revocation": {"ttl": "48h"},
		"session-termination": {"scim-attribute-claims": {"userName": "sub"}},
		"data": {"initialize-schema": "always", "table-prefix": "app.ssf_"},
		"transmitters": {"okta": {"transmitter-issuer": "https://okta.example", "expected-audience": "app"}}
	}`), &config)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _ := config.Delivery()
	post, _ := config.OAuth2.AuthenticatesWithRequestBody()
	if delivery != ssf.Poll || config.OAuth2.Scopes[0] != "ssf.read" || !post || config.Stream.Management != receiver.StreamManagementReceiver ||
		config.Poll.Interval.Std() != 10*time.Second || !config.Poll.LongPolling || config.Poll.LongPollingHold.Std() != 30*time.Second ||
		config.Poll.RateLimit.FallbackBackoff.Std() != 2*time.Minute || len(config.EffectiveAcceptedAlgorithms()) != 2 ||
		config.Dedup.Lease.Std() != 90*time.Second || config.Revocation.TTL.Std() != 48*time.Hour || config.Push.EndpointPath != "/ssf/push" ||
		config.Transmitters["okta"].TransmitterIssuer != "https://okta.example" || len(config.AllTransmitters()) != 2 ||
		config.SessionTermination.EffectiveScimAttributeClaims()[0] != [2]string{"userName", "sub"} || config.Data.TablePrefix != "app.ssf_" {
		t.Fatalf("%+v", config)
	}
	if mode, _ := config.SubjectCompatibility(); mode != ssf.Legacy {
		t.Fatal("legacy")
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if eventtypes.Resolve("AcmeLoginCfg") != "AcmeLoginCfg" {
		t.Fatal("Validate registers nothing")
	}
	if _, err := receiver.New(config); err != nil {
		t.Fatal(err)
	}
	if eventtypes.Resolve("AcmeLoginCfg") != "https://events.acme.example/login" {
		t.Fatal("New registers the aliases")
	}
	if names := config.TransmitterNames(); len(names) != 2 || names[0] != "default" || names[1] != "okta" {
		t.Fatalf("%v", names)
	}
}

func TestValidationReportsEveryFailure(t *testing.T) {
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = "http://idp.example"
	config.Push.EndpointPath = "ssf"
	config.Dedup.Capacity = 0
	config.OAuth2.TokenURI = "https://idp.example/token"
	config.SetValidation.AcceptedAlgorithms = []string{"HS256"}
	config.Data.TablePrefix = "bad prefix"
	config.Data.InitializeSchema = "sometimes"
	err := config.Validate()
	if err == nil {
		t.Fatal("invalid")
	}
	for _, expected := range []string{"transmitter-issuer", "https", "expected-audience", "oauth2.client-id", "accepted-algorithms", "push.endpoint-path", "dedup", "data.table-prefix", "data.initialize-schema"} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("missing %q in %v", expected, err)
		}
	}
	// poll without an endpoint
	poll := receiver.DefaultConfig()
	poll.TransmitterIssuer = "https://idp.example"
	poll.DeliveryMethod = "poll"
	poll.ExpectedAudience = "a"
	if err := poll.Validate(); err == nil || !strings.Contains(err.Error(), "poll.endpoint-url") {
		t.Fatalf("%v", err)
	}
	// a managed push stream needs the delivery endpoint
	managed := receiver.DefaultConfig()
	managed.TransmitterIssuer = "https://idp.example"
	managed.Stream.Management = receiver.StreamManagementReceiver
	if err := managed.Validate(); err == nil || !strings.Contains(err.Error(), "push.delivery-endpoint-url") {
		t.Fatalf("%v", err)
	}
}

func TestBuildsAPushReceiverAndHandlesSetsEndToEnd(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	rcv, err := receiver.New(pushConfig(transmitter), receiver.WithHTTPClient(transmitter.Client), receiver.WithHandler(receiver.ForEvent("CaepSessionRevoked", r)))
	if err != nil {
		t.Fatal(err)
	}
	rcv.Start(ctx)
	defer rcv.Stop(ctx)
	if rcv.PushEndpointPath() != "/ssf/push" || len(rcv.Transmitters()) != 1 {
		t.Fatal("defaults")
	}
	push := rcv.PushHandler()
	set := []byte(transmitter.Set("CaepSessionRevoked", ssf.Complex(alice(transmitter), ssf.Opaque("s1"))))
	if push.Handle(ctx, "", set).Status != 401 || push.Handle(ctx, secret, set).Status != 202 || r.count.Load() != 1 {
		t.Fatal("handled")
	}
	// the built-in revocation handler filled the store
	if !revoked(t, rcv.TokenRevocationStore(), receiver.TokenClaims{Issuer: transmitter.Issuer(), Subject: "alice", SessionID: "s1", IssuedAt: time.Now()}) {
		t.Fatal("revoked")
	}
	// a duplicate is accepted but not handled again
	if push.Handle(ctx, secret, set).Status != 202 || r.count.Load() != 1 {
		t.Fatal("duplicate")
	}
	health := rcv.Health(ctx)
	if health.Status != receiver.HealthHealthy || health.Transmitters[0].Delivery != "push" || !health.Transmitters[0].MetadataResolved {
		t.Fatalf("%+v", health)
	}
}

func TestHealthIsDegradedUntilTheTransmitterWasReached(t *testing.T) {
	transmitter := ssftest.WithMetadata(ssftest.MetadataNone, "")
	rcv, err := receiver.New(pushConfig(transmitter), receiver.WithHTTPClient(transmitter.Client))
	if err != nil {
		t.Fatal(err)
	}
	health := rcv.Health(ctx)
	if health.Status != receiver.HealthDegraded || health.Transmitters[0].MetadataResolved || health.Transmitters[0].Name != "default" {
		t.Fatalf("%+v", health)
	}
	// a SET cannot be verified without the keys: 503, the transmitter delivers it again
	set := []byte(transmitter.Set("CaepSessionRevoked", alice(transmitter)))
	if rcv.PushHandler().Handle(ctx, secret, set).Status != 503 {
		t.Fatal("503")
	}
}

func TestPollingReceiverRegistersItsStreamAndPolls(t *testing.T) {
	transmitter := ssftest.New()
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = transmitter.Issuer()
	config.DeliveryMethod = "poll"
	config.OAuth2 = receiver.OAuth2Config{TokenURI: transmitter.TokenURL(), ClientID: ssftest.ClientID, ClientSecret: ssftest.ClientSecret}
	config.Stream.Management = receiver.StreamManagementReceiver
	config.Poll.Interval = receiver.D(100 * time.Millisecond)
	r := &recorder{}
	rcv, err := receiver.New(config, receiver.WithHTTPClient(transmitter.Client), receiver.WithHandler(r))
	if err != nil {
		t.Fatal(err)
	}
	rcv.Start(ctx)
	ssftest.Eventually(t, 5*time.Second, "the stream", func() bool { return len(transmitter.Streams()) > 0 })
	stream := transmitter.Streams()[0]
	if ssf.StringMember(ssf.ObjectMember(stream, "delivery"), "method") != ssf.PollURI {
		t.Fatal("poll stream")
	}
	// the audience of the stream is the audience the verifier expects
	audience := ssf.Audiences(stream["aud"])[0]
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	claims["aud"] = audience
	transmitter.QueueSet(transmitter.SignSET(claims))
	ssftest.Eventually(t, 5*time.Second, "the SET", func() bool { return r.count.Load() == 1 })
	ssftest.Eventually(t, 5*time.Second, "the acknowledgement", func() bool { return len(transmitter.AcknowledgedSets()) == 1 })
	// a SET for another audience is reported
	transmitter.QueueSet(transmitter.Set("CaepSessionRevoked", ssf.IssSub(transmitter.Issuer(), "bob")))
	ssftest.Eventually(t, 5*time.Second, "the error report", func() bool { return len(transmitter.ReportedErrors()) == 1 })
	if transmitter.ReportedErrors()[0].Code != "invalid_audience" {
		t.Fatal("invalid_audience")
	}
	health := rcv.Health(ctx)
	if health.Status != receiver.HealthHealthy || health.Transmitters[0].Delivery != "poll" || health.Transmitters[0].StreamID == "" || health.Transmitters[0].LastSuccessfulPollAt.IsZero() {
		t.Fatalf("%+v", health)
	}
	rcv.Stop(ctx)
	if rcv.Transmitters()[0].Poller.IsRunning() {
		t.Fatal("stopped")
	}
}

func TestSetsAreLeftForRedeliveryUntilTheStreamTellsTheAudience(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.SetAvailable(false)
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = transmitter.Issuer()
	config.TransmitterAccessToken = ssftest.AccessToken
	config.Stream.Management = receiver.StreamManagementReceiver
	config.Push.DeliveryEndpointURL = "https://app.example/ssf/push"
	rcv, err := receiver.New(config, receiver.WithHTTPClient(transmitter.Client))
	if err != nil {
		t.Fatal(err)
	}
	push := rcv.PushHandler()
	set := []byte(transmitter.Set("CaepSessionRevoked", alice(transmitter)))
	if push.Handle(ctx, "", set).Status != 503 {
		t.Fatal("the stream is not registered yet")
	}
	transmitter.SetAvailable(true)
	rcv.Start(ctx)
	defer rcv.Stop(ctx)
	ssftest.Eventually(t, 5*time.Second, "the stream", func() bool { return len(transmitter.Streams()) > 0 })
	if push.Handle(ctx, "", set).Status != 400 {
		t.Fatal("wrong audience now that the stream tells it")
	}
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	claims["aud"] = ssf.Audiences(transmitter.Streams()[0]["aud"])[0]
	if push.Handle(ctx, "", []byte(transmitter.SignSET(claims))).Status != 202 {
		t.Fatal("accepted")
	}
}

func TestCustomizerReplacesPartsBeforeTheTransmitterIsBuilt(t *testing.T) {
	transmitter := ssftest.New()
	var seen []string
	rcv, err := receiver.New(pushConfig(transmitter), receiver.WithHTTPClient(transmitter.Client),
		receiver.WithTransmitterCustomizer(func(t *receiver.Transmitter) {
			seen = append(seen, t.Name)
			t.PushAuthorizationHeader = "Bearer custom"
		}))
	if err != nil || len(seen) != 1 || seen[0] != "default" {
		t.Fatalf("%v %v", seen, err)
	}
	set := []byte(transmitter.Set("CaepSessionRevoked", alice(transmitter)))
	if rcv.PushHandler().Handle(ctx, "Bearer custom", set).Status != 202 {
		t.Fatal("custom header")
	}
}

func TestSessionTerminatorIsCalledForSessionEvents(t *testing.T) {
	transmitter := ssftest.New()
	var terminated []*ssf.Subject
	terminator := receiver.SessionTerminatorFunc(func(_ context.Context, subject *ssf.Subject) (int, error) {
		terminated = append(terminated, subject)
		return 1, nil
	})
	rcv, err := receiver.New(pushConfig(transmitter), receiver.WithHTTPClient(transmitter.Client), receiver.WithSessionTerminator(terminator))
	if err != nil {
		t.Fatal(err)
	}
	set := []byte(transmitter.Set("CaepSessionRevoked", ssf.Complex(alice(transmitter), ssf.Opaque("s1"))))
	if rcv.PushHandler().Handle(ctx, secret, set).Status != 202 || len(terminated) != 1 || terminated[0].SessionID() != "s1" {
		t.Fatal("terminated")
	}
}

func TestUserAgentIsSentWhenConfigured(t *testing.T) {
	transmitter := ssftest.New()
	config := pushConfig(transmitter)
	config.HTTP.UserAgent = "my-app/1.0"
	rcv, err := receiver.New(config, receiver.WithHTTPClient(transmitter.Client))
	if err != nil {
		t.Fatal(err)
	}
	rcv.PushHandler().Handle(ctx, secret, []byte(transmitter.Set("CaepSessionRevoked", alice(transmitter))))
	if transmitter.LastUserAgent() != "my-app/1.0" {
		t.Fatalf("%q", transmitter.LastUserAgent())
	}
}

func TestFailedValidationRegistersNoAliasSoALaterConfigurationMayMapItDifferently(t *testing.T) {
	invalid := receiver.DefaultConfig()
	invalid.TransmitterIssuer = "https://idp.example"
	invalid.ExpectedAudience = "app"
	invalid.EventAliases = map[string]string{"PurityTestAlias": "urn:acme:a"}
	invalid.Push.EndpointPath = "no-slash"
	if err := invalid.Validate(); err == nil {
		t.Fatal("invalid")
	}
	if eventtypes.Resolve("PurityTestAlias") != "PurityTestAlias" {
		t.Fatal("a failed validation registered the alias")
	}
	later := receiver.DefaultConfig()
	later.TransmitterIssuer = "https://idp.example"
	later.ExpectedAudience = "app"
	later.EventAliases = map[string]string{"PurityTestAlias": "urn:acme:b"}
	if err := later.Validate(); err != nil {
		t.Fatal(err)
	}
	if eventtypes.Resolve("PurityTestAlias") != "PurityTestAlias" {
		t.Fatal("a passed validation registered the alias")
	}
	if err := eventtypes.RegisterAlias("PurityTestAlias", "urn:acme:b"); err != nil {
		t.Fatal(err)
	}
	conflicting := later
	conflicting.EventAliases = map[string]string{"PurityTestAlias": "urn:acme:c"}
	if err := conflicting.Validate(); err == nil || !strings.Contains(err.Error(), "event-aliases.PurityTestAlias") {
		t.Fatalf("%v", err)
	}
}
