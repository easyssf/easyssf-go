package receiver

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// Token revocation: what session-revoked events revoke, for resource servers to check.

// TokenClaims are the claims of an access token or session the revocation check reads.
type TokenClaims struct {
	// Issuer is the iss claim; a token without one is not revoked.
	Issuer string
	// Subject is the sub claim.
	Subject string
	// SessionID is the sid claim.
	SessionID string
	// IssuedAt is the iat claim, or the time a session was established; zero if unknown.
	IssuedAt time.Time
}

// TokenRevocationStore remembers which sessions and subjects were revoked, so that their access
// tokens can be rejected. Implement it on top of a shared store to share revocations between
// the instances of a resource server, since a SET is pushed to only one of them.
//
// Sessions and subjects are scoped to the issuer of their tokens: a subject alice of one issuer
// is not the subject alice of another. Events name that issuer in an iss_sub identifier; for
// identifiers without one, the transmitter that sent the event is taken to be the issuer.
//
// Revocations only need to be kept for as long as an access token issued before the revocation
// can still be valid, i.e. for the maximum access token lifetime.
type TokenRevocationStore interface {
	// RevokeSession revokes all access tokens bound to the given session (the sid claim).
	RevokeSession(ctx context.Context, issuer, sessionID string) error
	// RevokeSubject revokes all access tokens of the given subject (the sub claim) that were
	// issued at or before revokedAt.
	RevokeSubject(ctx context.Context, issuer, subject string, revokedAt time.Time) error
	// IsSessionRevoked reports whether the session was revoked.
	IsSessionRevoked(ctx context.Context, issuer, sessionID string) (bool, error)
	// SubjectRevokedAt is the time up to which the tokens of the given subject are revoked: the
	// time of the most recent revocation, zero if the subject is not revoked.
	SubjectRevokedAt(ctx context.Context, issuer, subject string) (time.Time, error)
}

// IsRevoked reports whether an access token was revoked: it is bound to a revoked session, or it
// belongs to a revoked subject and was issued at or before the revocation. A token without an
// issuer is not revoked.
func IsRevoked(ctx context.Context, store TokenRevocationStore, claims TokenClaims) (bool, error) {
	if claims.Issuer == "" {
		return false, nil
	}
	if claims.SessionID != "" {
		revoked, err := store.IsSessionRevoked(ctx, claims.Issuer, claims.SessionID)
		if err != nil || revoked {
			return revoked, err
		}
	}
	if claims.Subject == "" {
		return false, nil
	}
	revokedAt, err := store.SubjectRevokedAt(ctx, claims.Issuer, claims.Subject)
	if err != nil || revokedAt.IsZero() {
		return false, err
	}
	return claims.IssuedAt.IsZero() || !claims.IssuedAt.After(revokedAt), nil
}

type scoped struct{ issuer, id string }

type subjectRevocation struct{ revokedAt, expiresAt time.Time }

// InMemoryTokenRevocationStore is a TokenRevocationStore that keeps revocations in memory for a
// fixed time. Its content is lost on restart and not shared between instances.
type InMemoryTokenRevocationStore struct {
	ttl      time.Duration
	clock    Clock
	mu       sync.Mutex
	sessions map[scoped]time.Time // expiry
	subjects map[scoped]subjectRevocation
}

// NewInMemoryTokenRevocationStore keeps revocations for ttl (24 hours if zero), the maximum
// lifetime of an access token, by clock (the system clock if nil).
func NewInMemoryTokenRevocationStore(ttl time.Duration, clock Clock) *InMemoryTokenRevocationStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if clock == nil {
		clock = SystemClock
	}
	return &InMemoryTokenRevocationStore{ttl: ttl, clock: clock, sessions: map[scoped]time.Time{}, subjects: map[scoped]subjectRevocation{}}
}

func (s *InMemoryTokenRevocationStore) purge(now time.Time) {
	for key, expiry := range s.sessions {
		if !expiry.After(now) {
			delete(s.sessions, key)
		}
	}
	for key, revocation := range s.subjects {
		if !revocation.expiresAt.After(now) {
			delete(s.subjects, key)
		}
	}
}

// RevokeSession implements TokenRevocationStore.
func (s *InMemoryTokenRevocationStore) RevokeSession(_ context.Context, issuer, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	s.purge(now)
	s.sessions[scoped{issuer, sessionID}] = now.Add(s.ttl)
	return nil
}

// RevokeSubject implements TokenRevocationStore.
func (s *InMemoryTokenRevocationStore) RevokeSubject(_ context.Context, issuer, subject string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	s.purge(now)
	key := scoped{issuer, subject}
	if existing, ok := s.subjects[key]; ok && existing.revokedAt.After(revokedAt) {
		revokedAt = existing.revokedAt
	}
	s.subjects[key] = subjectRevocation{revokedAt: revokedAt, expiresAt: now.Add(s.ttl)}
	return nil
}

// IsSessionRevoked implements TokenRevocationStore.
func (s *InMemoryTokenRevocationStore) IsSessionRevoked(_ context.Context, issuer, sessionID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.sessions[scoped{issuer, sessionID}]
	return ok && expiry.After(s.clock()), nil
}

// SubjectRevokedAt implements TokenRevocationStore.
func (s *InMemoryTokenRevocationStore) SubjectRevokedAt(_ context.Context, issuer, subject string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	revocation, ok := s.subjects[scoped{issuer, subject}]
	if !ok || !revocation.expiresAt.After(s.clock()) {
		return time.Time{}, nil
	}
	return revocation.revokedAt, nil
}

// DefaultSessionEventTypes are the event types that revoke sessions by default.
var DefaultSessionEventTypes = []string{"CaepSessionRevoked"}

// TokenRevocationHandler records the session or subject of revocation events (by default CAEP
// session-revoked) in the TokenRevocationStore.
//
// A session event that names a session revokes the tokens of that session; one that only names a
// user revokes all tokens of that user issued up to the time of the event. A user event (none by
// default, CaepCredentialChange for an application whose sessions are cookies) always revokes
// all tokens of the user.
type TokenRevocationHandler struct {
	store             TokenRevocationStore
	sessionEventTypes []string
	userEventTypes    []string
	log               *slog.Logger
}

// NewTokenRevocationHandler is a handler for the given event types (alias or URI):
// sessionEventTypes (DefaultSessionEventTypes if nil) revoke the session they name, or all tokens
// of the user if they name none; userEventTypes revoke all tokens of the user they name, whether
// or not the event names a session.
func NewTokenRevocationHandler(store TokenRevocationStore, sessionEventTypes, userEventTypes []string, log *slog.Logger) *TokenRevocationHandler {
	if sessionEventTypes == nil {
		sessionEventTypes = DefaultSessionEventTypes
	}
	return &TokenRevocationHandler{store: store, sessionEventTypes: resolveAll(sessionEventTypes), userEventTypes: resolveAll(userEventTypes), log: orDiscard(log)}
}

func resolveAll(types []string) []string {
	resolved := make([]string, 0, len(types))
	for _, t := range types {
		resolved = append(resolved, eventtypes.Resolve(t))
	}
	return resolved
}

// Handle implements Handler.
func (h *TokenRevocationHandler) Handle(ctx context.Context, event *Context) error {
	for _, eventType := range h.sessionEventTypes {
		if event.HasEvent(eventType) {
			if err := h.revoke(ctx, event, eventType, false); err != nil {
				return err
			}
		}
	}
	for _, eventType := range h.userEventTypes {
		if event.HasEvent(eventType) {
			if err := h.revoke(ctx, event, eventType, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *TokenRevocationHandler) revoke(ctx context.Context, event *Context, eventType string, userEvent bool) error {
	subject := event.SubjectFor(eventType)
	if userEvent {
		subject = subject.WithoutSession()
	}
	revokedAt := event.EventTimestamp(eventType)
	alias := eventtypes.AliasOf(eventType)
	transmitter := event.EventToken().Issuer()
	switch {
	case subject.SessionID() != "":
		issuer := subject.Session().Issuer()
		if issuer == "" && subject.User() != nil {
			issuer = subject.User().Issuer()
		}
		if issuer == "" {
			issuer = transmitter
		}
		if err := h.store.RevokeSession(ctx, issuer, subject.SessionID()); err != nil {
			return err
		}
		h.log.Info("revoked access tokens of session", "event", alias, "session", subject.SessionID(), "issuer", issuer)
	case subject.Sub() != "":
		issuer := subject.UserIdentifier().Issuer()
		if issuer == "" {
			issuer = transmitter
		}
		if err := h.store.RevokeSubject(ctx, issuer, subject.Sub(), revokedAt); err != nil {
			return err
		}
		h.log.Info("revoked access tokens of subject", "event", alias, "subject", subject.Sub(), "issuer", issuer)
	case subject.OpaqueID() != "":
		// an opaque identifier does not tell whether it names a session or a user
		if err := h.store.RevokeSession(ctx, transmitter, subject.OpaqueID()); err != nil {
			return err
		}
		if err := h.store.RevokeSubject(ctx, transmitter, subject.OpaqueID(), revokedAt); err != nil {
			return err
		}
		h.log.Info("revoked access tokens of session or subject", "event", alias, "id", subject.OpaqueID(), "issuer", transmitter)
	default:
		h.log.Warn("event has no subject that identifies a session or user by sid or sub, no tokens were revoked",
			"event", alias, "jti", event.EventToken().JTI())
	}
	return nil
}

// TokenClaimsExtractor reads the claims of the access token a request carries, as left on the
// request by the middleware that validated it; ok is false for a request without a token.
type TokenClaimsExtractor func(r *http.Request) (claims TokenClaims, ok bool)

// RevocationMiddleware rejects requests whose access token was revoked with 401 Unauthorized.
// Mount it after the middleware that validates the access token and leaves its claims on the
// request. A store error answers 503.
func RevocationMiddleware(store TokenRevocationStore, extract TokenClaimsExtractor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if claims, ok := extract(r); ok {
				revoked, err := IsRevoked(r.Context(), store, claims)
				if err != nil {
					http.Error(w, "revocation check failed", http.StatusServiceUnavailable)
					return
				}
				if revoked {
					w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="The token was revoked"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
