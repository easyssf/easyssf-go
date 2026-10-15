// A resource server: every request to the API needs an access token issued by Keycloak. The SSF
// receiver adds the push endpoint and rejects the access tokens of sessions that were revoked in
// Keycloak. Keycloak is both the issuer of the access tokens and the SSF transmitter; run it from
// examples/keycloak. The Go port of the Spring Boot example-resource-server.
//
//	go run ./examples/resource-server          # PUSH stream of the client example-resource-server
//	go run ./examples/resource-server -poll    # POLL stream of the client example-poll-receiver
//
// KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_SECRET, KEYCLOAK_POLL_CLIENT_SECRET and SSF_PUSH_URL override
// the defaults, which fit the compose setup. The application contains no SSF code apart from the
// receiver configuration in main and the handler that logs the events; auth.go validates the
// access tokens, which Spring Security does for the Java example.
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

// keycloakConfig is the receiver configuration for the Keycloak of examples/keycloak: the
// application registers its own stream on startup with the service account of its client,
// Keycloak assigns the audience.
func keycloakConfig(issuer string, poll bool) receiver.Config {
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = issuer
	config.AllowInsecureHTTP = true // the Keycloak of the compose setup speaks http
	config.Stream.Management = receiver.StreamManagementReceiver
	config.Stream.EventsRequested = []string{"CaepSessionRevoked"}
	config.Stream.Description = "example-resource-server"
	// how Keycloak (in Docker) reaches the push endpoint, must be allowed by ssf.validPushUrls
	// of the client; the stream is created with this authorization header, Keycloak sends it
	// with every SET
	config.Push.DeliveryEndpointURL = env("SSF_PUSH_URL", "http://host.docker.internal:8081/ssf/push")
	config.Push.ExpectedAuthHeader = "Bearer example-resource-server-push-secret"
	config.OAuth2 = receiver.OAuth2Config{TokenURI: issuer + "/protocol/openid-connect/token", ClientID: "example-resource-server",
		ClientSecret: env("KEYCLOAK_CLIENT_SECRET", "example-resource-server-secret"), Scopes: []string{"ssf.read", "ssf.manage"}}
	// at least the access token lifespan of the realm (5 minutes by default)
	config.Revocation.TTL = receiver.D(10 * time.Minute)
	if poll {
		// the poll profile: instead of a PUSH stream for its own client, the application uses
		// the client example-poll-receiver, registers a POLL stream for it and polls Keycloak
		config.DeliveryMethod = "poll"
		config.Stream.Description = "example-resource-server (poll)"
		config.Poll.Interval = receiver.D(2 * time.Second)
		config.OAuth2.ClientID = "example-poll-receiver"
		config.OAuth2.ClientSecret = env("KEYCLOAK_POLL_CLIENT_SECRET", "example-poll-receiver-secret")
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
	config := keycloakConfig(env("KEYCLOAK_ISSUER", "http://localhost:8080/realms/ssf-demo"), *poll)

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

	// the receiver: the push endpoint, the stream at Keycloak, the revocation store and the
	// handler that revokes the access tokens
	rcv, err := receiver.New(config, receiver.WithLogger(log), receiver.WithHandler(audit))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	rcv.Start(ctx)
	defer rcv.Stop(context.Background())

	// validates the access tokens of Keycloak with the keys of the transmitter and leaves their
	// claims on the request; the revocation middleware then rejects the tokens of revoked
	// sessions and users
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
	// the push endpoint Keycloak delivers to, at easyssf.receiver.push.endpoint-path
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
