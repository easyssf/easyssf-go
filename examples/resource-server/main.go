// A resource server that receives CAEP events from a transmitter over push and rejects access
// tokens of revoked sessions: the Go port of the Spring Boot example-resource-server. Configure
// it with environment variables and run it against the Keycloak compose setup of the Java
// repository (examples/keycloak), or against the in-process test transmitter with -demo.
//
//	SSF_TRANSMITTER_ISSUER=http://localhost:8080/realms/ssf-demo \
//	SSF_EXPECTED_AUDIENCE=http://localhost:8081 \
//	SSF_PUSH_SECRET=s3cr3t go run ./examples/resource-server
package main

import (
	"context"
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
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssftest"
)

func main() {
	demo := flag.Bool("demo", false, "use the in-process test transmitter and push one event to yourself")
	listen := flag.String("listen", ":8081", "address to listen on")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := receiver.DefaultConfig()
	config.TransmitterIssuer = os.Getenv("SSF_TRANSMITTER_ISSUER")
	config.ExpectedAudience = os.Getenv("SSF_EXPECTED_AUDIENCE")
	config.AllowInsecureHTTP = true // the Keycloak of the compose setup speaks http
	if secret := os.Getenv("SSF_PUSH_SECRET"); secret != "" {
		config.Push.ExpectedAuthHeader = "Bearer " + secret
	}
	options := []receiver.Option{receiver.WithLogger(log)}

	var transmitter *ssftest.TestTransmitter
	if *demo {
		transmitter = ssftest.New()
		config.TransmitterIssuer = transmitter.Issuer()
		config.ExpectedAudience = ssftest.Audience
		config.Push.ExpectedAuthHeader = "Bearer demo"
		options = append(options, receiver.WithHTTPClient(transmitter.Client))
	}

	// reacting to an event is a function
	options = append(options, receiver.WithHandler(receiver.ForEventFunc("CaepSessionRevoked",
		func(ctx context.Context, event *receiver.Context) error {
			subject := event.Subject()
			log.Info("session revoked, ending what we hold", "sub", subject.Sub(), "sid", subject.SessionID(),
				"idempotency-key", event.IdempotencyKey())
			return nil
		})))

	rcv, err := receiver.New(config, options...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	rcv.Start(ctx) // registers the stream, starts polling, once stream.go and poll.go are ported
	defer rcv.Stop(context.Background())

	mux := http.NewServeMux()
	mux.Handle("POST "+rcv.PushEndpointPath(), rcv.PushHandler())
	// after the middleware that validates the access token and leaves its claims on the request
	revocation := receiver.RevocationMiddleware(rcv.TokenRevocationStore(), tokenClaims)
	mux.Handle("GET /api/orders", revocation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `[{"id": 1, "item": "coffee"}]`)
	})))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"status": %q}`+"\n", rcv.Health())
	})

	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if transmitter != nil {
		go pushDemoEvent(log, transmitter, *listen, rcv.PushEndpointPath())
	}
	log.Info("listening", "addr", *listen, "push", rcv.PushEndpointPath())
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// tokenClaims reads the claims the access token middleware left: here, for the example, from a
// header, so that the revocation can be tried with curl. A real server reads the validated JWT.
func tokenClaims(r *http.Request) (receiver.TokenClaims, bool) {
	if r.Header.Get("X-Token-Sub") == "" {
		return receiver.TokenClaims{}, false
	}
	return receiver.TokenClaims{Issuer: r.Header.Get("X-Token-Iss"), Subject: r.Header.Get("X-Token-Sub"),
		SessionID: r.Header.Get("X-Token-Sid"), IssuedAt: time.Now()}, true
}

func pushDemoEvent(log *slog.Logger, transmitter *ssftest.TestTransmitter, listen, path string) {
	time.Sleep(300 * time.Millisecond)
	set := transmitter.Set("CaepSessionRevoked", ssf.Complex(ssf.IssSub(transmitter.Issuer(), "alice"), ssf.Opaque("session-1")))
	request, _ := http.NewRequest(http.MethodPost, "http://localhost"+listen+path, strings.NewReader(set))
	request.Header.Set("Authorization", "Bearer demo")
	request.Header.Set("Content-Type", "application/secevent+jwt")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Error("demo push failed", "error", err)
		return
	}
	defer response.Body.Close()
	log.Info("demo SET pushed", "status", response.StatusCode,
		"try", fmt.Sprintf("curl -H 'X-Token-Iss: %s' -H 'X-Token-Sub: alice' -H 'X-Token-Sid: session-1' http://localhost%s/api/orders", transmitter.Issuer(), listen))
}
