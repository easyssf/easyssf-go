// A resource server: every request to the API needs an access token of the identity provider.
// The SSF receiver adds the push endpoint and rejects the access tokens of sessions the identity
// provider revoked. The identity provider is both the issuer of the access tokens and the SSF
// transmitter: any transmitter that supports CAEP session-revoked events does; the defaults fit
// the Keycloak of examples/keycloak. The Go port of the Spring Boot example-resource-server.
//
//	go run ./examples/resource-server          # PUSH stream of the client example-resource-server
//	go run ./examples/resource-server -poll    # POLL stream of the client example-poll-receiver
//
// SSF_TRANSMITTER_ISSUER, SSF_TOKEN_URI, SSF_CLIENT_ID, SSF_CLIENT_SECRET and SSF_PUSH_URL
// override the defaults. The application contains no SSF code apart from the receiver
// configuration in main and the handler that logs the events; auth.go validates the access
// tokens, which Spring Security does for the Java example.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// receiverConfig is the receiver configuration: the application registers its own stream on
// startup with the client credentials of its OAuth2 client, the transmitter assigns the
// audience. The defaults are the clients of the realm in examples/keycloak.
func receiverConfig(poll bool) receiver.Config {
	issuer := env("SSF_TRANSMITTER_ISSUER", "http://localhost:8080/realms/ssf-demo")
	clientID, clientSecret := "example-resource-server", "example-resource-server-secret" //nolint:gosec // the demo realm's secret
	if poll {
		// the poll profile: a second client, with a POLL stream the application polls
		clientID, clientSecret = "example-poll-receiver", "example-poll-receiver-secret" //nolint:gosec // the demo realm's secret
	}
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = issuer
	// a transmitter on plain http, as the compose setup is, is accepted for development only
	config.AllowInsecureHTTP = strings.HasPrefix(issuer, "http://")
	config.Stream.Management = receiver.StreamManagementReceiver
	config.Stream.EventsRequested = []string{"CaepSessionRevoked"}
	config.Stream.Description = "example-resource-server"
	// how the transmitter reaches the push endpoint; a transmitter may restrict the push URLs
	// it accepts for a client. The stream is created with this authorization header, the
	// transmitter sends it with every SET
	config.Push.DeliveryEndpointURL = env("SSF_PUSH_URL", "http://host.docker.internal:8081/ssf/push")
	config.Push.ExpectedAuthHeader = "Bearer example-resource-server-push-secret"
	config.OAuth2 = receiver.OAuth2Config{
		TokenURI:     env("SSF_TOKEN_URI", issuer+"/protocol/openid-connect/token"),
		ClientID:     env("SSF_CLIENT_ID", clientID),
		ClientSecret: env("SSF_CLIENT_SECRET", clientSecret),
		Scopes:       []string{"ssf.read", "ssf.manage"},
	}
	// at least the lifetime of an access token (5 minutes in the compose setup)
	config.Revocation.TTL = receiver.D(10 * time.Minute)
	if poll {
		config.DeliveryMethod = "poll"
		config.Stream.Description = "example-resource-server (poll)"
		config.Poll.Interval = receiver.D(2 * time.Second)
	}
	return config
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	poll := flag.Bool("poll", false, "the poll profile: register a POLL stream and poll for events")
	listen := flag.String("listen", ":8081", "address to listen on")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := receiverConfig(*poll)

	// the application's own handler, on top of the built-in revocation of access tokens: logs
	// every event
	audit := receiver.HandlerFunc(func(ctx context.Context, event *receiver.Context) error {
		for _, eventType := range event.EventTypes() {
			subject := event.SubjectFor(eventType)
			log.Info("Security event", "event", eventtypes.AliasOf(eventType), "user", subject.Sub(), "session", subject.SessionID(),
				"delivery", event.DeliveryMethod().String(), "idempotency-key", event.IdempotencyKey())
		}
		return nil
	})

	// the receiver: the push endpoint, the stream at the transmitter, the revocation store and
	// the handler that revokes the access tokens
	rcv, err := receiver.New(config, receiver.WithLogger(log), receiver.WithHandler(audit))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	rcv.Start(ctx)
	defer rcv.Stop(context.Background())

	// validates the access tokens with the keys of the transmitter and leaves their claims on
	// the request; the revocation middleware then rejects the tokens of revoked sessions and
	// users
	accessTokens := &AccessTokens{issuer: config.TransmitterIssuer, keys: rcv.Transmitters()[0].Keys}
	revocation := receiver.RevocationMiddleware(rcv.TokenRevocationStore(), tokenClaims)
	mux := http.NewServeMux()
	mux.Handle("GET /api/me", accessTokens.RequireAccessToken(revocation(http.HandlerFunc(me))))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		health := rcv.Health(r.Context())
		w.Header().Set("Content-Type", "application/json")
		if health.Status == receiver.HealthUnhealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(health)
	})
	// the push endpoint the transmitter delivers to, at easyssf.receiver.push.endpoint-path
	mux.Handle("POST "+rcv.PushEndpointPath(), rcv.PushHandler())

	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Info("The example resource server listens", "addr", *listen, "push", rcv.PushEndpointPath(), "poll", *poll)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
