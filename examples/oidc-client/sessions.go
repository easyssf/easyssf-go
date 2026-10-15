package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
)

// Sessions are the local sessions of the application, in memory, keyed by the id in the
// session cookie: what a session store of the framework would be. An application keeps whatever
// it keeps per session; this one keeps the logged-in user with the claims of the ID token, which
// the receiver matches the subjects of events against.
type Sessions struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

// Session is one local session.
type Session struct {
	// ID is the id in the cookie.
	ID string
	// User is the logged-in user, nil before the login.
	User *LoggedInUser
	// LoggedInAt is when the login completed, for the revocation check.
	LoggedInAt time.Time
	// CSRF is the token the logout form has to carry.
	CSRF string
	// Login holds state, nonce and PKCE verifier while a login is in progress.
	Login *LoginState
}

const cookieName = "SESSION"

// NewSessions is an empty session store.
func NewSessions() *Sessions { return &Sessions{sessions: map[string]*Session{}} }

// Get is the session of the request, nil if it has none.
func (s *Sessions) Get(r *http.Request) *Session {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[cookie.Value]
}

// Start starts a session and sets its cookie.
func (s *Sessions) Start(w http.ResponseWriter) *Session {
	session := &Session{ID: randomHex(16), CSRF: randomHex(16)}
	s.mu.Lock()
	s.sessions[session.ID] = session
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: session.ID, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode}) //nolint:gosec // not Secure: the example runs on plain http://localhost
	return session
}

// CycleID gives the session a fresh id for the logged-in session, as frameworks do after a
// login.
func (s *Sessions) CycleID(w http.ResponseWriter, session *Session) {
	s.mu.Lock()
	delete(s.sessions, session.ID)
	session.ID = randomHex(16)
	s.sessions[session.ID] = session
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: session.ID, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode}) //nolint:gosec // not Secure: the example runs on plain http://localhost
}

// End ends the session and clears its cookie.
func (s *Sessions) End(w http.ResponseWriter, session *Session) {
	s.mu.Lock()
	delete(s.sessions, session.ID)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode}) //nolint:gosec // not Secure: the example runs on plain http://localhost
}

// TerminateSessions implements receiver.SessionTerminator: ends the sessions whose user the
// subject of the event names, as the event arrives. receiver.SubjectMatches compares the subject
// with the claims of the ID token the user logged in with.
func (s *Sessions) TerminateSessions(_ context.Context, subject *ssf.Subject) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	terminated := 0
	for id, session := range s.sessions {
		if session.User != nil && receiver.SubjectMatches(subject, session.User.Claims, session.User.Username) {
			delete(s.sessions, id)
			terminated++
		}
	}
	return terminated, nil
}

// RevocationCheck is middleware that ends a session whose user or Keycloak session an event
// revoked after the login, on its next request: the counterpart of the session revocation
// layers of the other ports, for a session store the receiver cannot reach otherwise. Both the
// terminator and this check are in place here, to show both; one suffices.
func (s *Sessions) RevocationCheck(store receiver.TokenRevocationStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if session := s.Get(r); session != nil && session.User != nil {
				claims := receiver.TokenClaims{Issuer: session.User.Issuer, Subject: session.User.Subject, SessionID: session.User.SID, IssuedAt: session.LoggedInAt}
				if revoked, err := receiver.IsRevoked(r.Context(), store, claims); err == nil && revoked {
					s.End(w, session)
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func randomHex(bytes int) string {
	b := make([]byte, bytes)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
