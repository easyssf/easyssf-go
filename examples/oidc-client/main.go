// A web application that logs users in with Keycloak: the Go port of the Spring Boot
// example-oidc-client. The SSF receiver adds the push endpoint and ends the local session of a
// user when Keycloak reports that their session was revoked or their credentials changed.
// Keycloak is both the identity provider and the SSF transmitter; run it from the Keycloak
// compose setup of the Java repository (see examples/README.md).
//
//	KEYCLOAK_ISSUER=http://localhost:8080/realms/ssf-demo \
//	KEYCLOAK_CLIENT_SECRET=example-oidc-client-secret \
//	SSF_PUSH_URL=http://host.docker.internal:8082/ssf/push go run ./examples/oidc-client
//
// The application contains no SSF code apart from the receiver configuration in main and the
// session store that implements receiver.SessionTerminator; oidc.go is the login, which Spring
// Security does for the Java example.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
)

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":8082", "address to listen on")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	issuer := env("KEYCLOAK_ISSUER", "http://localhost:8080/realms/ssf-demo")
	clientSecret := env("KEYCLOAK_CLIENT_SECRET", "example-oidc-client-secret")
	baseURL := strings.TrimSuffix(env("BASE_URL", "http://localhost:8082"), "/")

	// Keycloak is both the identity provider and the SSF transmitter; the application registers
	// its own PUSH stream on startup, Keycloak assigns the audience, and the service account of
	// the client manages the stream
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = issuer
	config.AllowInsecureHTTP = true // the Keycloak of the compose setup speaks http
	config.Stream.Management = receiver.StreamManagementReceiver
	config.Stream.EventsRequested = []string{"CaepSessionRevoked", "CaepCredentialChange"}
	config.Stream.Description = "example-oidc-client"
	// how Keycloak (in Docker) reaches the push endpoint, must be allowed by ssf.validPushUrls
	// of the client
	config.Push.DeliveryEndpointURL = env("SSF_PUSH_URL", "http://host.docker.internal:8082/ssf/push")
	// the stream is created with this authorization header, Keycloak sends it with every SET
	config.Push.ExpectedAuthHeader = "Bearer example-oidc-client-push-secret"
	config.OAuth2 = receiver.OAuth2Config{TokenURI: issuer + "/protocol/openid-connect/token", ClientID: "example-oidc-client",
		ClientSecret: clientSecret, Scopes: []string{"ssf.read", "ssf.manage"}}
	// which events end local sessions (these are the defaults); the TTL of the revocations has
	// to cover the lifetime of the local sessions
	config.SessionTermination.SessionEventTypes = []string{"CaepSessionRevoked"}
	config.SessionTermination.UserEventTypes = []string{"CaepCredentialChange"}
	config.Revocation.UserEventTypes = []string{"CaepCredentialChange"}
	config.Revocation.TTL = receiver.D(14 * 24 * time.Hour)

	sessions := NewSessions()
	rcv, err := receiver.New(config, receiver.WithLogger(log),
		// ends the local sessions of the subject as the event arrives
		receiver.WithSessionTerminator(sessions))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	rcv.Start(ctx)
	defer rcv.Stop(context.Background())

	oidc := NewOIDC(OIDCConfig{Issuer: issuer, ClientID: "example-oidc-client", ClientSecret: clientSecret,
		Scopes: []string{"openid", "profile", "email"}, RedirectURL: baseURL + "/login/oauth2/code/keycloak"})
	app := &app{sessions: sessions, oidc: oidc, baseURL: baseURL, accountConsole: strings.TrimSuffix(issuer, "/") + "/account", log: log}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", app.home)
	mux.HandleFunc("GET /login", app.login)
	mux.HandleFunc("GET /login/oauth2/code/keycloak", app.callback)
	mux.HandleFunc("GET /auth/check", app.check)
	mux.HandleFunc("POST /logout", app.logout)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rcv.Health(r.Context()))
	})
	// the push endpoint Keycloak delivers to, at easyssf.receiver.push.endpoint-path
	mux.Handle("POST "+rcv.PushEndpointPath(), rcv.PushHandler())
	// flushes a session whose user or Keycloak session an event revoked after the login
	handler := sessions.RevocationCheck(rcv.TokenRevocationStore())(mux)

	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Info("The example OIDC client listens", "addr", *listen, "base_url", baseURL)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type app struct {
	sessions       *Sessions
	oidc           *OIDC
	baseURL        string
	accountConsole string
	log            *slog.Logger
}

// home is the page, for a logged-in user; the login otherwise.
func (a *app) home(w http.ResponseWriter, r *http.Request) {
	session := a.sessions.Get(r)
	if session == nil || session.User == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, page(session, a.accountConsole))
}

// login starts the login: remembers state, nonce and PKCE verifier in the session and sends the
// browser to Keycloak.
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	session := a.sessions.Get(r)
	if session == nil {
		session = a.sessions.Start(w)
	}
	authorizationURL, state, err := a.oidc.StartLogin(r.Context())
	if err != nil {
		a.log.Warn("Could not start the login with Keycloak", "error", err)
		loginFailed(w, err.Error())
		return
	}
	session.Login = state
	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

// callback is the redirect URI: exchanges the code, validates the ID token and records the login
// for the revocation check.
func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	session := a.sessions.Get(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	user, err := a.oidc.FinishLogin(r.Context(), session.Login, r.URL.Query())
	if err != nil {
		// the login page only says that the login failed, the reason is in the log
		a.log.Warn("Login with Keycloak failed", "error", err)
		loginFailed(w, err.Error())
		return
	}
	session.Login = nil
	session.User = user
	session.LoggedInAt = time.Now()
	// a fresh session id for the logged-in session
	a.sessions.CycleID(w, session)
	a.log.Info("Logged in", "user", user.Username, "subject", user.Subject, "sid", user.SID)
	http.Redirect(w, r, "/", http.StatusFound)
}

// check lets the page find out whether its local session still exists. The check does not call
// Keycloak: the receiver ends the local session when Keycloak reports the end of the Keycloak
// session, so the request either arrives in the session (200) or without one (401).
func (a *app) check(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	session := a.sessions.Get(r)
	if session == nil || session.User == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"user": session.User.Username, "sid": session.User.SID, "localSession": session.ID,
		"checkedAt": time.Now().UTC().Format(time.RFC3339)})
}

// logout logs the user out of the application and of Keycloak (RP-initiated logout).
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	session := a.sessions.Get(r)
	if session == nil || r.FormValue("_csrf") != session.CSRF {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	user := session.User
	a.sessions.End(w, session)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	a.log.Info("Logged out, ending the Keycloak session as well", "user", user.Username)
	logoutURL, err := a.oidc.LogoutURL(r.Context(), user, a.baseURL+"/")
	if err != nil || logoutURL == "" {
		if err != nil {
			a.log.Warn("Could not log out of Keycloak", "error", err)
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

func loginFailed(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Login failed</title></head><body><h1>Login failed</h1><p>%s</p><p><a href="/login">Try again</a></p></body></html>`, html.EscapeString(reason))
}

// page is the home page: who is logged in, and a script that polls /auth/check to show the
// moment the receiver ends the session.
func page(session *Session, accountConsole string) string {
	user := session.User
	return fmt.Sprintf(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Example OIDC client</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}code{background:#eee;padding:.1rem .3rem}#status{margin-top:1rem;padding:1rem;border:1px solid #ccc}</style></head>
<body>
<h1>Example OIDC client</h1>
<p>Logged in as <strong>%[1]s</strong> (subject <code>%[2]s</code>, Keycloak session <code>%[3]s</code>, local session <code>%[4]s</code>).</p>
<p>End the Keycloak session in the <a href="%[5]s" target="_blank">account console</a> (Sessions, sign out) or change the password there: Keycloak sends a SET to this application, which ends the local session. The box below notices within a few seconds.</p>
<form method="post" action="/logout"><input type="hidden" name="_csrf" value="%[6]s"><button type="submit">Log out</button></form>
<div id="status">Checking the session …</div>
<script>
async function check() {
  const box = document.getElementById('status');
  try {
    const response = await fetch('/auth/check', {cache: 'no-store'});
    if (response.status === 401) { box.textContent = 'The local session was ended by a security event. Reload to log in again.'; box.style.borderColor = 'red'; return; }
    const info = await response.json();
    box.textContent = 'Session alive, checked at ' + info.checkedAt;
  } catch (e) { box.textContent = 'Check failed: ' + e; }
  setTimeout(check, 3000);
}
check();
</script>
</body></html>`, html.EscapeString(user.Username), html.EscapeString(user.Subject), html.EscapeString(user.SID), html.EscapeString(session.ID),
		html.EscapeString(accountConsole), html.EscapeString(session.CSRF))
}
