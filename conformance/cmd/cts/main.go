// The receiver under test for the OpenID conformance suite, run by hand against a suite of your
// own: the CtsApplication of the Java library. It serves the API of conformance.Handler over
// https with the certificate of the module (or the one named by CTS_TLS_CERTIFICATE and
// CTS_TLS_KEY), trusts the certificate of the suite in CTS_SUITE_CERTIFICATE (or any, with
// CTS_TRUST_ALL=true), and takes its settings from CTS_* variables: CTS_TRANSMITTER_ISSUER,
// CTS_AUTH_MODE (dynamic|static), CTS_CLIENT_ID, CTS_CLIENT_SECRET, CTS_CLIENT_AUTH (basic|post),
// CTS_ACCESS_TOKEN, CTS_DELIVERY (push|poll), CTS_PUSH_URL, CTS_RUN_IDLE_TIMEOUT.
//
//	go run ./cmd/cts            # from the conformance module
//	curl -sk -X POST https://localhost:9443/cts/runs/auto
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/easyssf/easyssf-go/conformance"
	"github.com/easyssf/easyssf-go/ssf"
)

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func main() {
	listen := flag.String("listen", ":9443", "address to listen on")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	settings := conformance.DefaultReceiverSettings()
	settings.Issuer = env("CTS_TRANSMITTER_ISSUER", "https://localhost.emobix.co.uk:8443/test/a/easyssf-receiver-go-test")
	settings.Auth.Mode = conformance.AuthMode(env("CTS_AUTH_MODE", string(conformance.AuthDynamic)))
	settings.Auth.ClientID = env("CTS_CLIENT_ID", settings.Auth.ClientID)
	settings.Auth.ClientSecret = env("CTS_CLIENT_SECRET", settings.Auth.ClientSecret)
	settings.Auth.AuthenticateWithRequestBody = env("CTS_CLIENT_AUTH", "basic") == "post"
	settings.Auth.AccessToken = env("CTS_ACCESS_TOKEN", "")
	if env("CTS_DELIVERY", "push") == "poll" {
		settings.Delivery = ssf.Poll
	}
	settings.PushURL = env("CTS_PUSH_URL", "https://localhost:9443/ssf/push")
	if idle, err := time.ParseDuration(env("CTS_RUN_IDLE_TIMEOUT", "30s")); err == nil {
		settings.IdleTimeout = idle
	}

	// the certificate of a locally running suite, trusted for any host name: it is issued for
	// localhost, not localhost.emobix.co.uk
	var trusted *x509.Certificate
	if file := env("CTS_SUITE_CERTIFICATE", "certs/conformance-suite.pem"); file != "" {
		if data, err := os.ReadFile(file); err == nil {
			if block, _ := pem.Decode(data); block != nil {
				trusted, _ = x509.ParseCertificate(block.Bytes)
			}
		}
		if trusted == nil {
			log.Warn("No certificate of the conformance suite, the system roots are used; run fetch-suite-certificate.sh for a local suite", "file", file)
		}
	}
	client := conformance.NewHTTPClient(trusted, env("CTS_TRUST_ALL", "false") == "true", false)
	runner := conformance.NewRunner(settings, client, log)
	modules := conformance.NewSuiteModules(settings, client)

	tlsConfig, err := conformance.ReceiverTLSConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if certFile, keyFile := env("CTS_TLS_CERTIFICATE", ""), env("CTS_TLS_KEY", ""); certFile != "" && keyFile != "" {
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	server := &http.Server{Addr: *listen, Handler: conformance.Handler(runner, modules), TLSConfig: tlsConfig, ReadHeaderTimeout: 10 * time.Second}
	log.Info("The receiver under test listens", "addr", *listen, "issuer", settings.Issuer, "delivery", settings.Delivery.String(), "push_url", settings.PushURL)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
