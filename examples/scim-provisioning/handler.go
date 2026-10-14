package main

import (
	"context"
	"log/slog"
	"strings"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
	"github.com/easyssf/easyssf-go/ssf/scim"
)

// ScimProvisioningHandler mirrors the SCIM Events about Users into the UserDirectory. The
// receiver calls it for every verified SET; receiver.Scim dispatches the SCIM Events of the SET
// to the method of their operation.
//
// full events carry the resource (or the patch) as data and are applied directly. notice events
// only name the attributes that changed: the application would fetch the resource from the SCIM
// service provider with a GET of the subject's uri, which this example does not have, so it logs
// them. Like every handler it is idempotent: applying an event twice leaves the directory in the
// same state.
type ScimProvisioningHandler struct {
	receiver.NoopScimHandler
	directory *UserDirectory
	log       *slog.Logger
}

// NewScimProvisioningHandler is a handler that mirrors into directory.
func NewScimProvisioningHandler(directory *UserDirectory, log *slog.Logger) *ScimProvisioningHandler {
	return &ScimProvisioningHandler{directory: directory, log: log}
}

// OnScimEvent implements receiver.ScimEventHandler: only Users with a subject are mirrored.
func (h *ScimProvisioningHandler) OnScimEvent(ctx context.Context, event *scim.Event, context *receiver.Context) error {
	subject := event.Subject()
	if subject == nil || subject.ID() == "" {
		h.log.Warn(alias(event)+" has no SCIM subject, ignored", "jti", context.EventToken().JTI())
		return nil
	}
	if subject.ResourceType() != "Users" {
		h.log.Info(alias(event)+": only Users are mirrored", "uri", subject.URI())
		return nil
	}
	return receiver.DispatchScimEvent(ctx, h, event, context)
}

// OnFeedAdd implements receiver.ScimHandler.
func (h *ScimProvisioningHandler) OnFeedAdd(_ context.Context, event *scim.Event, _ *receiver.Context) error {
	h.log.Info(alias(event)+": joined the feed", "uri", event.Subject().URI())
	return nil
}

// OnFeedRemove implements receiver.ScimHandler.
func (h *ScimProvisioningHandler) OnFeedRemove(_ context.Context, event *scim.Event, _ *receiver.Context) error {
	h.log.Info(alias(event)+": left the feed, the user stays in the directory", "uri", event.Subject().URI())
	return nil
}

// OnCreate implements receiver.ScimHandler.
func (h *ScimProvisioningHandler) OnCreate(_ context.Context, event *scim.Event, _ *receiver.Context) error {
	if !event.IsFull() || event.Data() == nil {
		h.logNotice(event, "created")
		return nil
	}
	user := userOf(event)
	h.log.Info(alias(event) + ": created " + user.String())
	h.directory.Save(user)
	return nil
}

// OnPut implements receiver.ScimHandler.
func (h *ScimProvisioningHandler) OnPut(_ context.Context, event *scim.Event, _ *receiver.Context) error {
	if !event.IsFull() || event.Data() == nil {
		h.logNotice(event, "replaced")
		return nil
	}
	user := userOf(event)
	h.log.Info(alias(event) + ": replaced " + user.String())
	h.directory.Save(user)
	return nil
}

// OnPatch implements receiver.ScimHandler.
func (h *ScimProvisioningHandler) OnPatch(_ context.Context, event *scim.Event, _ *receiver.Context) error {
	if !event.IsFull() || event.Data() == nil {
		h.logNotice(event, "modified")
		return nil
	}
	patched, ok := h.directory.Update(event.Subject().ID(), func(user User) User {
		return applyPatch(user, event.Data(), h.log).WithVersion(event.Version())
	})
	if !ok {
		h.log.Warn(alias(event)+": not in the directory, nothing to patch", "uri", event.Subject().URI())
		return nil
	}
	h.log.Info(alias(event) + ": patched " + patched.String())
	return nil
}

// OnDelete implements receiver.ScimHandler.
func (h *ScimProvisioningHandler) OnDelete(_ context.Context, event *scim.Event, _ *receiver.Context) error {
	if removed, ok := h.directory.Remove(event.Subject().ID()); ok {
		h.log.Info(alias(event) + ": deleted " + removed.String())
	} else {
		h.log.Info(alias(event)+": deleted", "uri", event.Subject().URI())
	}
	return nil
}

// OnActivate implements receiver.ScimHandler.
func (h *ScimProvisioningHandler) OnActivate(_ context.Context, event *scim.Event, _ *receiver.Context) error {
	h.setActive(event, true)
	return nil
}

// OnDeactivate implements receiver.ScimHandler.
func (h *ScimProvisioningHandler) OnDeactivate(_ context.Context, event *scim.Event, _ *receiver.Context) error {
	h.setActive(event, false)
	return nil
}

func (h *ScimProvisioningHandler) setActive(event *scim.Event, active bool) {
	user, ok := h.directory.Update(event.Subject().ID(), func(user User) User {
		return user.WithActive(active).WithVersion(event.Version())
	})
	if !ok {
		h.log.Warn(alias(event)+": not in the directory", "uri", event.Subject().URI())
		return
	}
	what := "deactivated "
	if active {
		what = "activated "
	}
	h.log.Info(alias(event) + ": " + what + user.String())
}

func (h *ScimProvisioningHandler) logNotice(event *scim.Event, what string) {
	h.log.Info(alias(event)+": "+what+"; a notice event has no data, the application would GET the resource from the SCIM service provider",
		"uri", event.Subject().URI(), "attributes", event.Attributes())
}

// applyPatch applies the Operations of a SCIM PatchOp (RFC 7644, section 3.5.2) to the user, as
// far as this application mirrors the attributes: replace and add of a top-level attribute by
// path, or of several attributes with a value object and no path; remove of emails.
func applyPatch(user User, patch ssf.Claims, log *slog.Logger) User {
	operations, _ := patch["Operations"].([]any)
	for _, element := range operations {
		operation := ssf.Object(element)
		if operation == nil {
			continue
		}
		op := strings.ToLower(ssf.StringMember(operation, "op"))
		path := ssf.StringMember(operation, "path")
		value := operation["value"]
		switch op {
		case "add", "replace":
			if path != "" {
				user = user.With(path, value)
			} else if attributes := ssf.Object(value); attributes != nil {
				for attribute, v := range attributes {
					user = user.With(attribute, v)
				}
			}
		case "remove":
			if path == "emails" {
				user = user.With("emails", nil)
			} else {
				log.Debug("remove is not mirrored", "path", path)
			}
		default:
			log.Debug("unknown PatchOp operation", "op", op)
		}
	}
	return user
}

func userOf(event *scim.Event) User {
	subject := event.Subject()
	return UserFromSCIM(subject.ID(), subject.ExternalID(), event.Data(), event.Version())
}

func alias(event *scim.Event) string { return eventtypes.AliasOf(event.EventType()) }
