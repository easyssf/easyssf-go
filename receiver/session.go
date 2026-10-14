package receiver

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
	"github.com/easyssf/easyssf-go/ssf/scim"
)

// Session termination: ending the local sessions of the subject of an event, for applications
// whose sessions are not access tokens (an OIDC client with a session cookie, say), and matching
// the subject of an event with the claims of a logged-in user; a port of session.rs of the Rust
// port and of org.easyssf.receiver.session.

// SessionTerminator terminates the local sessions of a subject. Implement it over the session
// store of the application; SubjectMatches tells which sessions belong to the subject.
type SessionTerminator interface {
	// TerminateSessions terminates the sessions that belong to the given subject: the session
	// with the subject's session identifier if it has one, otherwise all sessions of its user.
	// Returns the number of terminated sessions.
	TerminateSessions(ctx context.Context, subject *ssf.Subject) (int, error)
}

// SessionTerminatorFunc is a SessionTerminator written as a function.
type SessionTerminatorFunc func(ctx context.Context, subject *ssf.Subject) (int, error)

// TerminateSessions implements SessionTerminator.
func (f SessionTerminatorFunc) TerminateSessions(ctx context.Context, subject *ssf.Subject) (int, error) {
	return f(ctx, subject)
}

// DefaultSessionTerminationUserEventTypes are the event types that terminate all sessions of
// their subject's user by default: CaepCredentialChange.
var DefaultSessionTerminationUserEventTypes = []string{"CaepCredentialChange"}

// SessionTerminationHandler terminates local sessions in reaction to security events.
//
// Session events (by default CAEP session-revoked) terminate the session named by the event, or
// all sessions of its user if it names no session. User events (by default CAEP
// credential-change) always terminate all sessions of the user.
type SessionTerminationHandler struct {
	terminator        SessionTerminator
	sessionEventTypes []string
	userEventTypes    []string
	log               *slog.Logger
}

// NewSessionTerminationHandler is a handler for the given event types (alias or URI):
// sessionEventTypes (DefaultSessionEventTypes if nil) and userEventTypes
// (DefaultSessionTerminationUserEventTypes if nil).
func NewSessionTerminationHandler(terminator SessionTerminator, sessionEventTypes, userEventTypes []string, log *slog.Logger) *SessionTerminationHandler {
	if sessionEventTypes == nil {
		sessionEventTypes = DefaultSessionEventTypes
	}
	if userEventTypes == nil {
		userEventTypes = DefaultSessionTerminationUserEventTypes
	}
	return &SessionTerminationHandler{terminator: terminator, sessionEventTypes: resolveAll(sessionEventTypes),
		userEventTypes: resolveAll(userEventTypes), log: orDiscard(log)}
}

// Handle implements Handler.
func (h *SessionTerminationHandler) Handle(ctx context.Context, event *Context) error {
	for _, eventType := range h.sessionEventTypes {
		if event.HasEvent(eventType) {
			if err := h.terminate(ctx, event, eventType, event.SubjectFor(eventType)); err != nil {
				return err
			}
		}
	}
	for _, eventType := range h.userEventTypes {
		if event.HasEvent(eventType) {
			if err := h.terminate(ctx, event, eventType, event.SubjectFor(eventType).WithoutSession()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *SessionTerminationHandler) terminate(ctx context.Context, event *Context, eventType string, subject *ssf.Subject) error {
	alias := eventtypes.AliasOf(eventType)
	if subject.IsEmpty() {
		h.log.Warn("event has no subject that identifies a session or user, no sessions were terminated",
			"event", alias, "jti", event.EventToken().JTI())
		return nil
	}
	terminated, err := h.terminator.TerminateSessions(ctx, subject)
	if err != nil {
		return err
	}
	h.log.Info("terminated session(s)", "event", alias, "terminated", terminated, "subject", describeSubject(subject))
	return nil
}

func describeSubject(subject *ssf.Subject) string {
	if sessionID := subject.SessionID(); sessionID != "" {
		return "session " + sessionID
	}
	if user := subject.UserIdentifier(); user != nil {
		if value := user.Value(); value != "" {
			return "user " + value
		}
		return "user " + user.Format()
	}
	return "session or subject " + subject.OpaqueID()
}

// DefaultScimAttributeClaims are the attributes of a scim subject and the claims they are
// compared with by default: externalId and id with sub, userName with preferred_username.
var DefaultScimAttributeClaims = [][2]string{{"externalId", "sub"}, {"id", "sub"}, {"userName", "preferred_username"}}

// SubjectMatches decides whether the subject of a security event refers to a user or session
// that is described by claims, typically the claims of the ID token the user logged in with: sid
// for a session, iss and sub, email or phone_number for a user. name is the name of the user,
// compared with the subject of the event if the claims have no sub; "" for none.
//
// An iss_sub identifier names the user at an issuer, so both have to match: claims without an
// iss never match such a subject. A session is matched by its sid and, if the event names the
// issuer of the session or of its user, by that issuer as well.
//
// A scim identifier (RFC 9967) names a resource of a SCIM service provider, whose identifiers an
// OpenID Provider may or may not share; it is matched with the DefaultScimAttributeClaims, see
// SubjectMatchesWith.
func SubjectMatches(subject *ssf.Subject, claims ssf.Claims, name string) bool {
	return SubjectMatchesWith(subject, claims, name, DefaultScimAttributeClaims)
}

// SubjectMatchesWith is SubjectMatches with the attributes of a scim subject (RFC 9967) and the
// claim each is compared with, for example externalId with sub; the subject matches if any pair
// does. A SCIM attribute that is multi-valued, such as emails, matches if any of its values (the
// value of each entry) does. Values compared with the email claim match ignoring case, all
// others exactly.
func SubjectMatchesWith(subject *ssf.Subject, claims ssf.Claims, name string, scimAttributeClaims [][2]string) bool {
	sessionID := claimString(claims, "sid")
	userSubject := claimString(claims, "sub")
	if userSubject == "" {
		userSubject = name
	}
	if session := subject.Session(); session != nil {
		if session.Value() == "" || session.Value() != sessionID {
			return false
		}
		// the session belongs to the issuer the event names, in the session identifier or the
		// user it belongs to; session identifiers are not unique across issuers
		issuer := session.Issuer()
		if issuer == "" && subject.User() != nil {
			issuer = subject.User().Issuer()
		}
		return issuer == "" || issuer == claimString(claims, "iss")
	}
	if user := subject.UserIdentifier(); user != nil {
		return matchesUser(user, claims, userSubject, scimAttributeClaims)
	}
	if opaqueID := subject.OpaqueID(); opaqueID != "" {
		// an opaque identifier does not tell whether it names a session or a user
		return opaqueID == sessionID || opaqueID == userSubject
	}
	return false
}

func matchesUser(user *ssf.SubjectIdentifier, claims ssf.Claims, userSubject string, scimAttributeClaims [][2]string) bool {
	value := user.Value()
	switch user.Format() {
	case ssf.FormatIssSub:
		return value != "" && value == userSubject && user.Issuer() != "" && user.Issuer() == claimString(claims, "iss")
	case ssf.FormatEmail:
		return value != "" && strings.EqualFold(value, claimString(claims, "email"))
	case ssf.FormatOpaque:
		return value != "" && value == userSubject
	case ssf.FormatAliases:
		for _, alias := range user.Aliases() {
			if matchesUser(alias, claims, userSubject, scimAttributeClaims) {
				return true
			}
		}
		return false
	case ssf.FormatSCIM:
		resource := scim.SubjectFromIdentifier(user)
		return resource != nil && matchesScimResource(resource, claims, userSubject, scimAttributeClaims)
	}
	// phone_number, account, did, uri and unknown formats: a claim of the same name
	return value != "" && value == claimString(claims, user.Format())
}

func matchesScimResource(resource *scim.Subject, claims ssf.Claims, userSubject string, scimAttributeClaims [][2]string) bool {
	for _, pair := range scimAttributeClaims {
		attribute, claimName := pair[0], pair[1]
		claimValue := claimString(claims, claimName)
		if claimName == "sub" {
			claimValue = userSubject
		}
		if claimValue == "" {
			continue
		}
		for _, value := range scimAttributeValues(resource, attribute) {
			if (claimName == "email" && strings.EqualFold(value, claimValue)) || value == claimValue {
				return true
			}
		}
	}
	return false
}

// scimAttributeValues are the values of an attribute of a SCIM resource: the string of a
// single-valued attribute, the id resolved from the uri if the resource has no id attribute, or
// the strings and the value members of a multi-valued attribute such as emails.
func scimAttributeValues(resource *scim.Subject, attribute string) []string {
	if attribute == "id" {
		if id := resource.ID(); id != "" {
			return []string{id}
		}
		return nil
	}
	switch value := resource.Claims()[attribute].(type) {
	case string:
		if strings.TrimSpace(value) != "" {
			return []string{value}
		}
	case []any:
		var values []string
		for _, element := range value {
			switch e := element.(type) {
			case string:
				if strings.TrimSpace(e) != "" {
					values = append(values, e)
				}
			case map[string]any:
				if v := ssf.StringMember(e, "value"); v != "" {
					values = append(values, v)
				}
			}
		}
		return values
	}
	return nil
}

// claimString is a claim as text: a string as it is, nil as "", anything else rendered, so that
// a numeric sub still compares.
func claimString(claims ssf.Claims, name string) string {
	switch v := claims[name].(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}
