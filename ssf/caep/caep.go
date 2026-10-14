// Package caep holds the CAEP 1.0 events: the kinds of section 3 and typed access to their
// claims. SKETCH: the common claims of section 2 and the kinds; the per-kind accessors
// (credential_type, change_type, current_level, ...) follow caep.rs of the Rust port.
package caep

import (
	"time"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// Kind is one of the events of CAEP 1.0, section 3, or Other for an event type in the CAEP
// namespace this version does not know. New kinds are added as CAEP defines events, so do not
// switch over them exhaustively; implement the receiver's CAEP handler interface instead.
type Kind int

const (
	// Other is an event type in the CAEP namespace this version does not know, for example one
	// of a later CAEP version. The common claims of CAEP section 2 are still available.
	Other Kind = iota
	SessionRevoked
	TokenClaimsChange
	CredentialChange
	AssuranceLevelChange
	DeviceComplianceChange
	SessionEstablished
	SessionPresented
	RiskLevelChange
)

var known = map[string]Kind{
	eventtypes.CaepSessionRevoked:         SessionRevoked,
	eventtypes.CaepTokenClaimsChange:      TokenClaimsChange,
	eventtypes.CaepCredentialChange:       CredentialChange,
	eventtypes.CaepAssuranceLevelChange:   AssuranceLevelChange,
	eventtypes.CaepDeviceComplianceChange: DeviceComplianceChange,
	eventtypes.CaepSessionEstablished:     SessionEstablished,
	eventtypes.CaepSessionPresented:       SessionPresented,
	eventtypes.CaepRiskLevelChange:        RiskLevelChange,
}

// KindOf is the kind of CAEP event of an event type URI or alias: Other for an unknown event type
// in the CAEP namespace; ok is false if the event type is not a CAEP event.
func KindOf(eventType string) (kind Kind, ok bool) {
	if !eventtypes.IsCaepEvent(eventType) {
		return 0, false
	}
	return known[eventtypes.Resolve(eventType)], true
}

// Event is a CAEP event of a SET: its type, kind and payload, with the common claims of CAEP
// 1.0, section 2, typed.
type Event struct {
	eventType string
	kind      Kind
	payload   ssf.Claims
}

// Of is the CAEP event with the given type and payload; nil if the type is not a CAEP event.
func Of(eventType string, payload ssf.Claims) *Event {
	kind, ok := KindOf(eventType)
	if !ok {
		return nil
	}
	if payload == nil {
		payload = ssf.Claims{}
	}
	return &Event{eventType: eventtypes.Resolve(eventType), kind: kind, payload: payload}
}

// InToken are the CAEP events of a SET, in the order of their event type URIs.
func InToken(token *ssf.EventToken) []*Event {
	var events []*Event
	for eventType, payload := range token.Events() {
		if event := Of(eventType, ssf.Object(payload)); event != nil {
			events = append(events, event)
		}
	}
	return events
}

// EventType is the event type URI.
func (e *Event) EventType() string { return e.eventType }

// Kind is the kind.
func (e *Event) Kind() Kind { return e.kind }

// Payload is the payload as received.
func (e *Event) Payload() ssf.Claims { return e.payload }

// EventTimestamp is the event_timestamp (CAEP 1.0, section 2); ok is false if absent.
func (e *Event) EventTimestamp() (time.Time, bool) {
	return ssf.EventTimestamp(e.payload["event_timestamp"])
}

// InitiatingEntity is the initiating_entity: admin, user, policy or system.
func (e *Event) InitiatingEntity() string { return ssf.StringMember(e.payload, "initiating_entity") }

// ReasonAdmin is the reason_admin by language tag, a plain string under "".
func (e *Event) ReasonAdmin() map[string]string { return localized(e.payload["reason_admin"]) }

// ReasonUser is the reason_user by language tag, a plain string under "".
func (e *Event) ReasonUser() map[string]string { return localized(e.payload["reason_user"]) }

func localized(value any) map[string]string {
	switch v := value.(type) {
	case string:
		return map[string]string{"": v}
	case map[string]any:
		reasons := map[string]string{}
		for tag, reason := range v {
			if s, ok := reason.(string); ok {
				reasons[tag] = s
			}
		}
		return reasons
	}
	return nil
}
