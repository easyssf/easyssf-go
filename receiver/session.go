package receiver

import (
	"context"
	"log/slog"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// Session termination: ending server-side sessions as the event arrives, for applications whose
// sessions are not access tokens (an OIDC client with a session cookie, say). SKETCH of
// session.rs of the Rust port: the terminator interface and the handler that drives it; the
// SCIM attribute mapping (session-termination.scim-attribute-claims) is still to port.

// SessionTerminator ends the server-side sessions an event names. Implement it over the session
// store of the application.
type SessionTerminator interface {
	// TerminateSession ends the session with the given id at the issuer.
	TerminateSession(ctx context.Context, issuer, sessionID string) error
	// TerminateSessionsOfSubject ends all sessions of the subject at the issuer.
	TerminateSessionsOfSubject(ctx context.Context, issuer, subject string) error
}

// SessionTerminationHandler calls the SessionTerminator for session events (DefaultSessionEventTypes
// if nil) and user events (none by default), like TokenRevocationHandler does for the
// TokenRevocationStore.
type SessionTerminationHandler struct {
	terminator        SessionTerminator
	sessionEventTypes []string
	userEventTypes    []string
	log               *slog.Logger
}

// NewSessionTerminationHandler is the handler.
func NewSessionTerminationHandler(terminator SessionTerminator, sessionEventTypes, userEventTypes []string, log *slog.Logger) *SessionTerminationHandler {
	if sessionEventTypes == nil {
		sessionEventTypes = DefaultSessionEventTypes
	}
	return &SessionTerminationHandler{terminator: terminator, sessionEventTypes: resolveAll(sessionEventTypes),
		userEventTypes: resolveAll(userEventTypes), log: orDiscard(log)}
}

// Handle implements Handler.
func (h *SessionTerminationHandler) Handle(ctx context.Context, event *Context) error {
	for _, eventType := range h.sessionEventTypes {
		if event.HasEvent(eventType) {
			if err := h.terminate(ctx, event, event.SubjectFor(eventType), eventType); err != nil {
				return err
			}
		}
	}
	for _, eventType := range h.userEventTypes {
		if event.HasEvent(eventType) {
			if err := h.terminate(ctx, event, event.SubjectFor(eventType).WithoutSession(), eventType); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *SessionTerminationHandler) terminate(ctx context.Context, event *Context, subject *ssf.Subject, eventType string) error {
	transmitter := event.EventToken().Issuer()
	issuer := subject.Issuer()
	if issuer == "" {
		issuer = transmitter
	}
	switch {
	case subject.SessionID() != "":
		return h.terminator.TerminateSession(ctx, issuer, subject.SessionID())
	case subject.Sub() != "":
		return h.terminator.TerminateSessionsOfSubject(ctx, issuer, subject.Sub())
	case subject.OpaqueID() != "":
		if err := h.terminator.TerminateSession(ctx, transmitter, subject.OpaqueID()); err != nil {
			return err
		}
		return h.terminator.TerminateSessionsOfSubject(ctx, transmitter, subject.OpaqueID())
	}
	h.log.Warn("event names no session or user to terminate", "event", eventtypes.AliasOf(eventType), "jti", event.EventToken().JTI())
	return nil
}
