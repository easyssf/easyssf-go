package receiver

import (
	"context"

	"github.com/easyssf/easyssf-go/ssf/caep"
)

// CaepHandler reacts to CAEP 1.0 events by kind: Caep turns it into a Handler that dispatches
// every CAEP event of a SET to the method of its kind, and OnOtherCaepEvent for an event type in
// the CAEP namespace this version does not know. Embed NoopCaepHandler and implement the methods
// the receiver acts on; SETs without CAEP events are ignored.
//
// Each event comes with typed access to its payload and with the Context of the SET, whose
// Subject the event is about. The built-in reactions to session-revoked and credential-change,
// ending sessions and rejecting tokens, are SessionTerminationHandler and
// TokenRevocationHandler; this handler is for what the application does on top. Like every
// handler, an implementation has to be idempotent.
//
// A handler that also implements CaepEventHandler gets every CAEP event through OnCaepEvent
// instead, and dispatches itself with DispatchCaepEvent if it wants to.
type CaepHandler interface {
	// OnSessionRevoked: the session was revoked (CaepSessionRevoked).
	OnSessionRevoked(ctx context.Context, event *caep.Event, context *Context) error
	// OnTokenClaimsChange: claims of the token changed (CaepTokenClaimsChange), see
	// caep.Event.Claims.
	OnTokenClaimsChange(ctx context.Context, event *caep.Event, context *Context) error
	// OnCredentialChange: a credential was created, revoked, updated or deleted
	// (CaepCredentialChange), see caep.Event.CredentialType and ChangeType.
	OnCredentialChange(ctx context.Context, event *caep.Event, context *Context) error
	// OnAssuranceLevelChange: the assurance level changed (CaepAssuranceLevelChange), see
	// caep.Event.CurrentLevel and ChangeDirection.
	OnAssuranceLevelChange(ctx context.Context, event *caep.Event, context *Context) error
	// OnDeviceComplianceChange: the compliance status of the device changed
	// (CaepDeviceComplianceChange), see caep.Event.CurrentStatus.
	OnDeviceComplianceChange(ctx context.Context, event *caep.Event, context *Context) error
	// OnSessionEstablished: a session was established (CaepSessionEstablished).
	OnSessionEstablished(ctx context.Context, event *caep.Event, context *Context) error
	// OnSessionPresented: a session was presented (CaepSessionPresented).
	OnSessionPresented(ctx context.Context, event *caep.Event, context *Context) error
	// OnRiskLevelChange: the risk level changed (CaepRiskLevelChange), see
	// caep.Event.CurrentLevel and Principal.
	OnRiskLevelChange(ctx context.Context, event *caep.Event, context *Context) error
	// OnOtherCaepEvent: an event in the CAEP namespace this version of easyssf does not know
	// (caep.Other): the common claims of CAEP section 2 are typed, the rest is in
	// caep.Event.Payload.
	OnOtherCaepEvent(ctx context.Context, event *caep.Event, context *Context) error
}

// CaepEventHandler is implemented by a CaepHandler that wants every CAEP event of a SET through
// one method, to treat all CAEP events alike; it may call DispatchCaepEvent afterwards.
type CaepEventHandler interface {
	OnCaepEvent(ctx context.Context, event *caep.Event, context *Context) error
}

// NoopCaepHandler implements CaepHandler with methods that do nothing; embed it and implement
// the methods the receiver acts on.
type NoopCaepHandler struct{}

// OnSessionRevoked implements CaepHandler.
func (NoopCaepHandler) OnSessionRevoked(context.Context, *caep.Event, *Context) error { return nil }

// OnTokenClaimsChange implements CaepHandler.
func (NoopCaepHandler) OnTokenClaimsChange(context.Context, *caep.Event, *Context) error { return nil }

// OnCredentialChange implements CaepHandler.
func (NoopCaepHandler) OnCredentialChange(context.Context, *caep.Event, *Context) error { return nil }

// OnAssuranceLevelChange implements CaepHandler.
func (NoopCaepHandler) OnAssuranceLevelChange(context.Context, *caep.Event, *Context) error {
	return nil
}

// OnDeviceComplianceChange implements CaepHandler.
func (NoopCaepHandler) OnDeviceComplianceChange(context.Context, *caep.Event, *Context) error {
	return nil
}

// OnSessionEstablished implements CaepHandler.
func (NoopCaepHandler) OnSessionEstablished(context.Context, *caep.Event, *Context) error { return nil }

// OnSessionPresented implements CaepHandler.
func (NoopCaepHandler) OnSessionPresented(context.Context, *caep.Event, *Context) error { return nil }

// OnRiskLevelChange implements CaepHandler.
func (NoopCaepHandler) OnRiskLevelChange(context.Context, *caep.Event, *Context) error { return nil }

// OnOtherCaepEvent implements CaepHandler.
func (NoopCaepHandler) OnOtherCaepEvent(context.Context, *caep.Event, *Context) error { return nil }

// DispatchCaepEvent calls the method of handler for the kind of the event.
func DispatchCaepEvent(ctx context.Context, handler CaepHandler, event *caep.Event, context *Context) error {
	switch event.Kind() {
	case caep.SessionRevoked:
		return handler.OnSessionRevoked(ctx, event, context)
	case caep.TokenClaimsChange:
		return handler.OnTokenClaimsChange(ctx, event, context)
	case caep.CredentialChange:
		return handler.OnCredentialChange(ctx, event, context)
	case caep.AssuranceLevelChange:
		return handler.OnAssuranceLevelChange(ctx, event, context)
	case caep.DeviceComplianceChange:
		return handler.OnDeviceComplianceChange(ctx, event, context)
	case caep.SessionEstablished:
		return handler.OnSessionEstablished(ctx, event, context)
	case caep.SessionPresented:
		return handler.OnSessionPresented(ctx, event, context)
	case caep.RiskLevelChange:
		return handler.OnRiskLevelChange(ctx, event, context)
	}
	return handler.OnOtherCaepEvent(ctx, event, context)
}

// Caep turns a CaepHandler into a Handler that gets every SET and dispatches its CAEP events.
func Caep(handler CaepHandler) Handler {
	return HandlerFunc(func(ctx context.Context, context *Context) error {
		for _, event := range caep.InToken(context.EventToken()) {
			var err error
			if all, ok := handler.(CaepEventHandler); ok {
				err = all.OnCaepEvent(ctx, event, context)
			} else {
				err = DispatchCaepEvent(ctx, handler, event, context)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}
