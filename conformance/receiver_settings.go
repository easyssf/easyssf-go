package conformance

import (
	"time"

	"github.com/easyssf/easyssf-go/ssf"
)

// AuthMode is how the receiver authenticates at the emulated transmitter, the Authentication
// Variant of the test plan.
type AuthMode string

const (
	// AuthDynamic obtains an access token with the client credentials grant from the token
	// endpoint of the emulated transmitter.
	AuthDynamic AuthMode = "dynamic"
	// AuthStatic sends the configured access token.
	AuthStatic AuthMode = "static"
)

// ReceiverSettings are the settings of a receiver under test: the transmitter to use, how to
// authenticate at it, the delivery, the stream and the limits of a run; cts.* of the Java
// receiver. Start from DefaultReceiverSettings.
type ReceiverSettings struct {
	// Issuer is the issuer of the emulated transmitter: the URL of the test instance in the
	// conformance suite, with its alias, e.g. https://localhost.emobix.co.uk:8443/test/a/easyssf-receiver.
	Issuer string
	// Auth is how the receiver authenticates.
	Auth AuthSettings
	// Delivery is push or poll, the SSF Delivery Mode of the test plan.
	Delivery ssf.DeliveryMethod
	// PushURL is the URL under which the conformance suite reaches the push endpoint of the
	// receiver under test. Must be https.
	PushURL string
	// PollInterval is how often the transmitter is polled with poll delivery.
	PollInterval time.Duration
	// EventsRequested are the event types (alias or URI) the stream requests.
	EventsRequested []string
	// SubjectToRemove is the subject the remove-subject scenario removes from the stream, e.g.
	// one of the subjects listed in the SSF valid SubjectId field of the test plan.
	SubjectToRemove ssf.Claims
	// VerificationTimeout is how long to wait for the verification event before going on
	// without it.
	VerificationTimeout time.Duration
	// IdleTimeout: the stream is deleted once no SET arrived for this long. Has to exceed the
	// pauses the tests make between events (20 seconds in the access token expiry test, 15
	// seconds in the transmitter-initiated status change test).
	IdleTimeout time.Duration
	// MaxDuration: a run ends at the latest after this time.
	MaxDuration time.Duration
}

// AuthSettings are the client credentials of the receiver at the emulated transmitter, as
// configured in the test plan (client.client_id, client.client_secret, client.scope), or the
// static access token (ssf.transmitter.access_token).
type AuthSettings struct {
	Mode         AuthMode
	ClientID     string
	ClientSecret string
	Scopes       []string
	// AuthenticateWithRequestBody sends the credentials in the body (client_secret_post)
	// instead of with basic authentication, the Client Authentication Type of the test plan.
	AuthenticateWithRequestBody bool
	AccessToken                 string
}

// DefaultReceiverSettings are the settings of the suite configurations in suite-config/: the
// client easyssf-receiver, push delivery, the three CAEP events, foo@example.com to remove.
func DefaultReceiverSettings() ReceiverSettings {
	return ReceiverSettings{
		Auth:                AuthSettings{Mode: AuthDynamic, ClientID: "easyssf-receiver", ClientSecret: "easyssf-receiver-secret", Scopes: []string{"ssf.read", "ssf.manage"}},
		Delivery:            ssf.Push,
		PushURL:             "https://localhost:9443/ssf/push",
		PollInterval:        time.Second,
		EventsRequested:     []string{"CaepSessionRevoked", "CaepCredentialChange", "CaepDeviceComplianceChange"},
		SubjectToRemove:     ssf.Email("foo@example.com"),
		VerificationTimeout: 30 * time.Second,
		IdleTimeout:         30 * time.Second,
		MaxDuration:         5 * time.Minute,
	}
}
