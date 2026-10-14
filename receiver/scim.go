package receiver

import (
	"context"

	"github.com/easyssf/easyssf-go/ssf/scim"
)

// ScimHandler reacts to SCIM Events (RFC 9967) by operation: Scim turns it into a Handler that
// dispatches every SCIM Event of a SET to the method of its operation. Embed NoopScimHandler and
// implement the methods the receiver acts on; SETs without SCIM Events are ignored.
//
// Each event comes with its Subject, the SCIM resource it is about, and the Context of the SET
// for its jti, iss and txn. Like every handler, an implementation has to be idempotent: a SET is
// delivered again if any handler failed. The txn claim identifies the underlying transaction
// across such retransmissions. A handler that also implements ScimEventHandler gets every SCIM
// Event through OnScimEvent instead, for example to refuse events without a SCIM subject, and
// dispatches itself with DispatchScimEvent if it wants to.
type ScimHandler interface {
	// OnFeedAdd: the resource joined the event feed (feed:add).
	OnFeedAdd(ctx context.Context, event *scim.Event, context *Context) error
	// OnFeedRemove: the resource left the event feed (feed:remove).
	OnFeedRemove(ctx context.Context, event *scim.Event, context *Context) error
	// OnCreate: the resource was created (prov:create:notice or prov:create:full).
	OnCreate(ctx context.Context, event *scim.Event, context *Context) error
	// OnPatch: the resource was modified with SCIM PATCH (prov:patch:notice or
	// prov:patch:full).
	OnPatch(ctx context.Context, event *scim.Event, context *Context) error
	// OnPut: the resource was replaced with SCIM PUT (prov:put:notice or prov:put:full).
	OnPut(ctx context.Context, event *scim.Event, context *Context) error
	// OnDelete: the resource was deleted (prov:delete).
	OnDelete(ctx context.Context, event *scim.Event, context *Context) error
	// OnActivate: the resource was activated (prov:activate).
	OnActivate(ctx context.Context, event *scim.Event, context *Context) error
	// OnDeactivate: the resource was deactivated (prov:deactivate).
	OnDeactivate(ctx context.Context, event *scim.Event, context *Context) error
	// OnAsyncResponse: an asynchronous SCIM request completed (misc:asyncresp).
	OnAsyncResponse(ctx context.Context, event *scim.Event, context *Context) error
}

// ScimEventHandler is implemented by a ScimHandler that wants every SCIM Event of a SET through
// one method; it may call DispatchScimEvent afterwards.
type ScimEventHandler interface {
	OnScimEvent(ctx context.Context, event *scim.Event, context *Context) error
}

// NoopScimHandler implements ScimHandler with methods that do nothing; embed it and implement
// the methods the receiver acts on.
type NoopScimHandler struct{}

// OnFeedAdd implements ScimHandler.
func (NoopScimHandler) OnFeedAdd(context.Context, *scim.Event, *Context) error { return nil }

// OnFeedRemove implements ScimHandler.
func (NoopScimHandler) OnFeedRemove(context.Context, *scim.Event, *Context) error { return nil }

// OnCreate implements ScimHandler.
func (NoopScimHandler) OnCreate(context.Context, *scim.Event, *Context) error { return nil }

// OnPatch implements ScimHandler.
func (NoopScimHandler) OnPatch(context.Context, *scim.Event, *Context) error { return nil }

// OnPut implements ScimHandler.
func (NoopScimHandler) OnPut(context.Context, *scim.Event, *Context) error { return nil }

// OnDelete implements ScimHandler.
func (NoopScimHandler) OnDelete(context.Context, *scim.Event, *Context) error { return nil }

// OnActivate implements ScimHandler.
func (NoopScimHandler) OnActivate(context.Context, *scim.Event, *Context) error { return nil }

// OnDeactivate implements ScimHandler.
func (NoopScimHandler) OnDeactivate(context.Context, *scim.Event, *Context) error { return nil }

// OnAsyncResponse implements ScimHandler.
func (NoopScimHandler) OnAsyncResponse(context.Context, *scim.Event, *Context) error { return nil }

// DispatchScimEvent calls the method of handler for the operation of the event; an unknown
// operation is ignored.
func DispatchScimEvent(ctx context.Context, handler ScimHandler, event *scim.Event, context *Context) error {
	switch event.Operation() {
	case scim.FeedAdd:
		return handler.OnFeedAdd(ctx, event, context)
	case scim.FeedRemove:
		return handler.OnFeedRemove(ctx, event, context)
	case scim.Create:
		return handler.OnCreate(ctx, event, context)
	case scim.Patch:
		return handler.OnPatch(ctx, event, context)
	case scim.Put:
		return handler.OnPut(ctx, event, context)
	case scim.Delete:
		return handler.OnDelete(ctx, event, context)
	case scim.Activate:
		return handler.OnActivate(ctx, event, context)
	case scim.Deactivate:
		return handler.OnDeactivate(ctx, event, context)
	case scim.AsyncResponse:
		return handler.OnAsyncResponse(ctx, event, context)
	}
	return nil
}

// Scim turns a ScimHandler into a Handler that gets every SET and dispatches its SCIM Events.
func Scim(handler ScimHandler) Handler {
	return HandlerFunc(func(ctx context.Context, context *Context) error {
		for _, event := range scim.InToken(context.EventToken()) {
			var err error
			if all, ok := handler.(ScimEventHandler); ok {
				err = all.OnScimEvent(ctx, event, context)
			} else {
				err = DispatchScimEvent(ctx, handler, event, context)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}
