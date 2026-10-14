package receiver

import (
	"context"

	"github.com/easyssf/easyssf-go/ssf/risc"
)

// RiscHandler reacts to RISC 1.0 events by kind: Risc turns it into a Handler that dispatches
// every RISC event of a SET to the method of its kind, and OnOtherRiscEvent for an event type in
// the RISC namespace this version does not know. Embed NoopRiscHandler and implement the methods
// the receiver acts on; SETs without RISC events are ignored.
//
// Each event comes with the Context of the SET, whose Subject is the account the event is about.
// Like every handler, an implementation has to be idempotent. A handler that also implements
// RiscEventHandler gets every RISC event through OnRiscEvent instead, and dispatches itself with
// DispatchRiscEvent if it wants to.
type RiscHandler interface {
	// OnAccountCredentialChangeRequired: the account has to change its credential.
	OnAccountCredentialChangeRequired(ctx context.Context, event *risc.Event, context *Context) error
	// OnAccountPurged: the account was permanently deleted.
	OnAccountPurged(ctx context.Context, event *risc.Event, context *Context) error
	// OnAccountDisabled: the account was disabled, see risc.Event.Reason.
	OnAccountDisabled(ctx context.Context, event *risc.Event, context *Context) error
	// OnAccountEnabled: the account was enabled again.
	OnAccountEnabled(ctx context.Context, event *risc.Event, context *Context) error
	// OnIdentifierChanged: the identifier of the account changed, see risc.Event.NewValue.
	OnIdentifierChanged(ctx context.Context, event *risc.Event, context *Context) error
	// OnIdentifierRecycled: the identifier was given to someone else.
	OnIdentifierRecycled(ctx context.Context, event *risc.Event, context *Context) error
	// OnCredentialCompromise: a credential was found compromised, see
	// risc.Event.CredentialType.
	OnCredentialCompromise(ctx context.Context, event *risc.Event, context *Context) error
	// OnOptIn: the account takes part in the RISC exchange.
	OnOptIn(ctx context.Context, event *risc.Event, context *Context) error
	// OnOptOutInitiated: the user asked to leave the RISC exchange.
	OnOptOutInitiated(ctx context.Context, event *risc.Event, context *Context) error
	// OnOptOutCancelled: the user withdrew the request to leave.
	OnOptOutCancelled(ctx context.Context, event *risc.Event, context *Context) error
	// OnOptOutEffective: the account left the RISC exchange.
	OnOptOutEffective(ctx context.Context, event *risc.Event, context *Context) error
	// OnRecoveryActivated: the account went through a recovery flow.
	OnRecoveryActivated(ctx context.Context, event *risc.Event, context *Context) error
	// OnRecoveryInformationChanged: the recovery information changed.
	OnRecoveryInformationChanged(ctx context.Context, event *risc.Event, context *Context) error
	// OnSessionsRevoked: all sessions of the account were revoked (deprecated by RISC in
	// favour of CaepSessionRevoked).
	OnSessionsRevoked(ctx context.Context, event *risc.Event, context *Context) error
	// OnOtherRiscEvent: an event in the RISC namespace this version of easyssf does not know
	// (risc.Other); its attributes are in risc.Event.Payload.
	OnOtherRiscEvent(ctx context.Context, event *risc.Event, context *Context) error
}

// RiscEventHandler is implemented by a RiscHandler that wants every RISC event of a SET through
// one method; it may call DispatchRiscEvent afterwards.
type RiscEventHandler interface {
	OnRiscEvent(ctx context.Context, event *risc.Event, context *Context) error
}

// NoopRiscHandler implements RiscHandler with methods that do nothing; embed it and implement
// the methods the receiver acts on.
type NoopRiscHandler struct{}

// OnAccountCredentialChangeRequired implements RiscHandler.
func (NoopRiscHandler) OnAccountCredentialChangeRequired(context.Context, *risc.Event, *Context) error {
	return nil
}

// OnAccountPurged implements RiscHandler.
func (NoopRiscHandler) OnAccountPurged(context.Context, *risc.Event, *Context) error { return nil }

// OnAccountDisabled implements RiscHandler.
func (NoopRiscHandler) OnAccountDisabled(context.Context, *risc.Event, *Context) error { return nil }

// OnAccountEnabled implements RiscHandler.
func (NoopRiscHandler) OnAccountEnabled(context.Context, *risc.Event, *Context) error { return nil }

// OnIdentifierChanged implements RiscHandler.
func (NoopRiscHandler) OnIdentifierChanged(context.Context, *risc.Event, *Context) error { return nil }

// OnIdentifierRecycled implements RiscHandler.
func (NoopRiscHandler) OnIdentifierRecycled(context.Context, *risc.Event, *Context) error { return nil }

// OnCredentialCompromise implements RiscHandler.
func (NoopRiscHandler) OnCredentialCompromise(context.Context, *risc.Event, *Context) error {
	return nil
}

// OnOptIn implements RiscHandler.
func (NoopRiscHandler) OnOptIn(context.Context, *risc.Event, *Context) error { return nil }

// OnOptOutInitiated implements RiscHandler.
func (NoopRiscHandler) OnOptOutInitiated(context.Context, *risc.Event, *Context) error { return nil }

// OnOptOutCancelled implements RiscHandler.
func (NoopRiscHandler) OnOptOutCancelled(context.Context, *risc.Event, *Context) error { return nil }

// OnOptOutEffective implements RiscHandler.
func (NoopRiscHandler) OnOptOutEffective(context.Context, *risc.Event, *Context) error { return nil }

// OnRecoveryActivated implements RiscHandler.
func (NoopRiscHandler) OnRecoveryActivated(context.Context, *risc.Event, *Context) error { return nil }

// OnRecoveryInformationChanged implements RiscHandler.
func (NoopRiscHandler) OnRecoveryInformationChanged(context.Context, *risc.Event, *Context) error {
	return nil
}

// OnSessionsRevoked implements RiscHandler.
func (NoopRiscHandler) OnSessionsRevoked(context.Context, *risc.Event, *Context) error { return nil }

// OnOtherRiscEvent implements RiscHandler.
func (NoopRiscHandler) OnOtherRiscEvent(context.Context, *risc.Event, *Context) error { return nil }

// DispatchRiscEvent calls the method of handler for the kind of the event.
func DispatchRiscEvent(ctx context.Context, handler RiscHandler, event *risc.Event, context *Context) error {
	switch event.Kind() {
	case risc.AccountCredentialChangeRequired:
		return handler.OnAccountCredentialChangeRequired(ctx, event, context)
	case risc.AccountPurged:
		return handler.OnAccountPurged(ctx, event, context)
	case risc.AccountDisabled:
		return handler.OnAccountDisabled(ctx, event, context)
	case risc.AccountEnabled:
		return handler.OnAccountEnabled(ctx, event, context)
	case risc.IdentifierChanged:
		return handler.OnIdentifierChanged(ctx, event, context)
	case risc.IdentifierRecycled:
		return handler.OnIdentifierRecycled(ctx, event, context)
	case risc.CredentialCompromise:
		return handler.OnCredentialCompromise(ctx, event, context)
	case risc.OptIn:
		return handler.OnOptIn(ctx, event, context)
	case risc.OptOutInitiated:
		return handler.OnOptOutInitiated(ctx, event, context)
	case risc.OptOutCancelled:
		return handler.OnOptOutCancelled(ctx, event, context)
	case risc.OptOutEffective:
		return handler.OnOptOutEffective(ctx, event, context)
	case risc.RecoveryActivated:
		return handler.OnRecoveryActivated(ctx, event, context)
	case risc.RecoveryInformationChanged:
		return handler.OnRecoveryInformationChanged(ctx, event, context)
	case risc.SessionsRevoked:
		return handler.OnSessionsRevoked(ctx, event, context)
	}
	return handler.OnOtherRiscEvent(ctx, event, context)
}

// Risc turns a RiscHandler into a Handler that gets every SET and dispatches its RISC events.
func Risc(handler RiscHandler) Handler {
	return HandlerFunc(func(ctx context.Context, context *Context) error {
		for _, event := range risc.InToken(context.EventToken()) {
			var err error
			if all, ok := handler.(RiscEventHandler); ok {
				err = all.OnRiscEvent(ctx, event, context)
			} else {
				err = DispatchRiscEvent(ctx, handler, event, context)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}
