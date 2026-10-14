// Mirrors the users of a SCIM service provider into a local directory from the SCIM Events (RFC
// 9967) the provider transmits over SSF: the Go port of the Spring Boot example-scim-provisioning.
// The receiver polls the transmitter and hands the events to ScimProvisioningHandler; the
// directory is published at /users.
//
// Keycloak does not emit SCIM Events, so the example brings its own transmitter: the in-process
// TestTransmitter of ssftest, which DemoScimProvider feeds with the life of two users and with
// the requests to /demo/scim. Against a real SCIM service provider, the receiver configuration is
// all that changes; the handler and the directory stay as they are.
//
//	go run ./examples/scim-provisioning                      # plays the life of two users
//	go run ./examples/scim-provisioning -autoplay=false      # starts with an empty directory
//	curl -s localhost:8083/users
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
	"syscall"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssftest"
)

// Application is the receiver against the transmitter, the directory and the HTTP API.
type Application struct {
	// Handler serves /users, and /demo/scim with the demo.
	Handler http.Handler
	// Receiver is the receiver.
	Receiver *receiver.Receiver
	// Directory is the directory the events are mirrored into.
	Directory *UserDirectory
	// Demo is the demo SCIM service provider, nil without the demo.
	Demo *DemoScimProvider
}

// receiverConfig is the configuration of the receiver: it registers its own POLL stream on
// startup and asks for the SCIM Events it mirrors; the transmitter assigns the audience of the
// SETs.
func receiverConfig(transmitter *ssftest.TestTransmitter) receiver.Config {
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = transmitter.Issuer()
	config.TransmitterAccessToken = ssftest.AccessToken
	config.DeliveryMethod = "poll"
	config.Poll.Interval = receiver.D(2 * time.Second)
	config.Poll.InitialDelay = receiver.D(time.Second)
	config.Stream.Management = receiver.StreamManagementReceiver
	config.Stream.EventsRequested = []string{"ScimFeedAdd", "ScimFeedRemove", "ScimProvCreateFull", "ScimProvCreateNotice", "ScimProvPatchFull",
		"ScimProvPatchNotice", "ScimProvPutFull", "ScimProvPutNotice", "ScimProvDelete", "ScimProvActivate", "ScimProvDeactivate"}
	config.Stream.Description = "example-scim-provisioning"
	return config
}

// build assembles the application against transmitter; demo adds the demo service provider.
func build(transmitter *ssftest.TestTransmitter, config receiver.Config, demo bool, log *slog.Logger) (*Application, error) {
	directory := NewUserDirectory()
	rcv, err := receiver.New(config,
		receiver.WithLogger(log),
		// the transmitter answers in-process
		receiver.WithHTTPClient(transmitter.Client),
		// mirrors the SCIM Events into the directory
		receiver.WithHandler(receiver.Scim(NewScimProvisioningHandler(directory, log))))
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, directory.All()) })
	mux.HandleFunc("GET /users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if user, ok := directory.Find(r.PathValue("id")); ok {
			writeJSON(w, http.StatusOK, user)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, rcv.Health(r.Context())) })
	application := &Application{Handler: mux, Receiver: rcv, Directory: directory}
	if demo {
		application.Demo = NewDemoScimProvider(transmitter, log)
		mux.Handle("/demo/scim/", application.Demo.Handler())
	}
	return application, nil
}

func main() {
	listen := flag.String("listen", ":8083", "address to listen on")
	autoplay := flag.Bool("autoplay", true, "play the life of two users on startup")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// the transmitter starts before the application: the receiver needs its issuer
	transmitter := ssftest.New()
	application, err := build(transmitter, receiverConfig(transmitter), true, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	application.Receiver.Start(ctx)
	defer application.Receiver.Stop(context.Background())
	if *autoplay {
		go application.Demo.Play()
	} else {
		log.Info("The demo SCIM service provider waits for requests to /demo/scim, autoplay is off")
	}

	server := &http.Server{Addr: *listen, Handler: application.Handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Info("The SCIM provisioning example listens", "addr", *listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
