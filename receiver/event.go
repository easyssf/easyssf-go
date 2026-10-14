package receiver

import (
	"context"
	"sort"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// Context is a verified ssf.EventToken together with convenient, alias-aware access to its events
// and subjects. Passed to every Handler. Immutable, so a handler can hand it to a goroutine.
type Context struct {
	token    *ssf.EventToken
	subject  *ssf.Subject
	delivery ssf.DeliveryMethod
}

// NewContext is the context of a verified SET.
func NewContext(token *ssf.EventToken, delivery ssf.DeliveryMethod) *Context {
	return &Context{token: token, subject: ssf.SubjectFrom(token.SubjectID()), delivery: delivery}
}

// EventToken is the verified SET.
func (c *Context) EventToken() *ssf.EventToken { return c.token }

// DeliveryMethod is how the SET arrived.
func (c *Context) DeliveryMethod() ssf.DeliveryMethod { return c.delivery }

// IdempotencyKey is the key for making the side effects of a handler idempotent, the issuer and
// jti of the SET: a SET is handled at least once, not exactly once (see Handler).
func (c *Context) IdempotencyKey() string { return c.token.IdempotencyKey() }

// EventTypes are the event type URIs contained in the SET, sorted.
func (c *Context) EventTypes() []string {
	types := make([]string, 0, len(c.token.Events()))
	for eventType := range c.token.Events() {
		types = append(types, eventType)
	}
	sort.Strings(types)
	return types
}

// HasEvent reports whether the SET contains an event of the given type, named by alias (such as
// CaepSessionRevoked) or URI.
func (c *Context) HasEvent(aliasOrURI string) bool {
	_, ok := c.token.Events()[eventtypes.Resolve(aliasOrURI)]
	return ok
}

// Event is the payload of the event of the given type (alias or URI), nil if the SET has no such
// event or its payload is not a JSON object.
func (c *Context) Event(aliasOrURI string) ssf.Claims {
	return ssf.Object(c.token.Events()[eventtypes.Resolve(aliasOrURI)])
}

// Subject is the subject of the SET, taken from its top-level sub_id claim; empty if the SET has
// none.
func (c *Context) Subject() *ssf.Subject { return c.subject }

// SubjectFor is the subject of the event of the given type: the top-level sub_id claim of the SET
// or, for transmitters following earlier SSF drafts, the subject member of the event payload.
// SETs without the top-level claim reach a handler only in the ssf.Legacy subject compatibility
// mode of the verifier.
func (c *Context) SubjectFor(aliasOrURI string) *ssf.Subject {
	if !c.subject.IsEmpty() {
		return c.subject
	}
	if legacy := ssf.ObjectMember(c.Event(aliasOrURI), "subject"); legacy != nil {
		return ssf.SubjectFrom(legacy)
	}
	return ssf.EmptySubject()
}

// EventTimestamp is the time the event of the given type occurred: its event_timestamp or, if
// absent, the time the SET was issued.
func (c *Context) EventTimestamp(aliasOrURI string) time.Time {
	if event := c.Event(aliasOrURI); event != nil {
		if ts, ok := ssf.EventTimestamp(event["event_timestamp"]); ok {
			return ts
		}
	}
	return c.token.IssuedAt()
}

// Handler reacts to verified security events. Every handler given to the Processor is invoked
// for every SET.
//
// A SET is handled at least once, not exactly once, so handlers must be idempotent. A SET is
// delivered again if any handler failed, and all handlers run again, possibly on another
// instance of the application; with a shared dedup store a SET is claimed while its handlers run
// and another instance leaves it alone meanwhile, but an instance that dies after a handler's
// side effects and before the success is recorded hands the SET to the next instance after a
// lease. Side effects outside the receiver's stores should be keyed by Context.IdempotencyKey.
//
// An error leaves the SET unacknowledged, the transmitter delivers it again. A panic in a
// handler is recovered by the processor and counts as an error.
type Handler interface {
	Handle(ctx context.Context, event *Context) error
}

// HandlerFunc is a Handler written as a function.
type HandlerFunc func(ctx context.Context, event *Context) error

// Handle implements Handler.
func (f HandlerFunc) Handle(ctx context.Context, event *Context) error { return f(ctx, event) }

// ForEvent calls handler only for SETs with an event of the given type (alias or URI).
func ForEvent(aliasOrURI string, handler Handler) Handler {
	eventType := eventtypes.Resolve(aliasOrURI)
	return HandlerFunc(func(ctx context.Context, event *Context) error {
		if event.HasEvent(eventType) {
			return handler.Handle(ctx, event)
		}
		return nil
	})
}

// ForEventFunc is ForEvent with a function.
func ForEventFunc(aliasOrURI string, handler func(ctx context.Context, event *Context) error) Handler {
	return ForEvent(aliasOrURI, HandlerFunc(handler))
}
