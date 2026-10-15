// Package risc holds the RISC 1.0 events: the kinds of section 2 and typed access to their few
// attributes (the reason of an account-disabled, the new-value of an identifier-changed, the
// credential_type of a credential-compromise). A port of risc.rs of the Rust port and of
// org.easyssf.core.risc.
package risc

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// Kind is one of the events of RISC 1.0, section 2, or Other for an event type in the RISC
// namespace this version does not know. New kinds are added as RISC defines events, so do not
// switch over them exhaustively; implement the receiver's RiscHandler interface instead.
type Kind int

const (
	// Other is an event type in the RISC namespace this version does not know.
	Other Kind = iota
	// AccountCredentialChangeRequired: the account has to change its credential, for example
	// after a leak elsewhere (section 2.1).
	AccountCredentialChangeRequired
	// AccountPurged: the account was permanently deleted (section 2.2).
	AccountPurged
	// AccountDisabled: the account was disabled, see Event.Reason (section 2.3).
	AccountDisabled
	// AccountEnabled: the account was enabled again (section 2.4).
	AccountEnabled
	// IdentifierChanged: the identifier of the subject, an email address or phone number,
	// changed to Event.NewValue (section 2.5).
	IdentifierChanged
	// IdentifierRecycled: the identifier was given to someone else (section 2.6).
	IdentifierRecycled
	// CredentialCompromise: a credential of the subject was found compromised, see
	// Event.CredentialType (section 2.7).
	CredentialCompromise
	// OptIn: the account takes part in the RISC exchange (section 2.8.1).
	OptIn
	// OptOutInitiated: the user asked to leave the RISC exchange (section 2.8.2).
	OptOutInitiated
	// OptOutCancelled: the user withdrew the request to leave (section 2.8.3).
	OptOutCancelled
	// OptOutEffective: the account left the RISC exchange (section 2.8.4).
	OptOutEffective
	// RecoveryActivated: the account went through a recovery flow (section 2.9).
	RecoveryActivated
	// RecoveryInformationChanged: the recovery information of the account changed (section
	// 2.10).
	RecoveryInformationChanged
	// SessionsRevoked: all sessions of the account were revoked (section 2.11). Deprecated by
	// RISC in favour of CAEP's session-revoked, still sent by some transmitters.
	SessionsRevoked
)

// Known are the known kinds and their event type URIs, in the order of the specification.
var Known = []struct {
	Kind      Kind
	EventType string
}{
	{AccountCredentialChangeRequired, eventtypes.RiscAccountCredentialChangeRequired},
	{AccountPurged, eventtypes.RiscAccountPurged},
	{AccountDisabled, eventtypes.RiscAccountDisabled},
	{AccountEnabled, eventtypes.RiscAccountEnabled},
	{IdentifierChanged, eventtypes.RiscIdentifierChanged},
	{IdentifierRecycled, eventtypes.RiscIdentifierRecycled},
	{CredentialCompromise, eventtypes.RiscCredentialCompromise},
	{OptIn, eventtypes.RiscOptIn},
	{OptOutInitiated, eventtypes.RiscOptOutInitiated},
	{OptOutCancelled, eventtypes.RiscOptOutCancelled},
	{OptOutEffective, eventtypes.RiscOptOutEffective},
	{RecoveryActivated, eventtypes.RiscRecoveryActivated},
	{RecoveryInformationChanged, eventtypes.RiscRecoveryInformationChanged},
	{SessionsRevoked, eventtypes.RiscSessionsRevoked},
}

var names = map[Kind]string{ //nolint:gosec // G101: event type names, not credentials
	AccountCredentialChangeRequired: "AccountCredentialChangeRequired", AccountPurged: "AccountPurged",
	AccountDisabled: "AccountDisabled", AccountEnabled: "AccountEnabled", IdentifierChanged: "IdentifierChanged",
	IdentifierRecycled: "IdentifierRecycled", CredentialCompromise: "CredentialCompromise", OptIn: "OptIn",
	OptOutInitiated: "OptOutInitiated", OptOutCancelled: "OptOutCancelled", OptOutEffective: "OptOutEffective",
	RecoveryActivated: "RecoveryActivated", RecoveryInformationChanged: "RecoveryInformationChanged",
	SessionsRevoked: "SessionsRevoked",
}

// EventType is the event type URI of the kind, "" for Other.
func (k Kind) EventType() string {
	for _, known := range Known {
		if known.Kind == k {
			return known.EventType
		}
	}
	return ""
}

// String is the name of the kind: AccountDisabled, ..., Other.
func (k Kind) String() string {
	if name, ok := names[k]; ok {
		return name
	}
	return "Other"
}

// IsOptOutState reports whether this is one of the opt-in and opt-out events of section 2.8,
// which report the participation of the account in the exchange rather than a risk.
func (k Kind) IsOptOutState() bool {
	return k == OptIn || k == OptOutInitiated || k == OptOutCancelled || k == OptOutEffective
}

// KindOf is the kind of RISC event of an event type URI or alias: Other for an unknown event type
// in the RISC namespace; ok is false if the event type is not a RISC event.
func KindOf(eventType string) (kind Kind, ok bool) {
	if !eventtypes.IsRiscEvent(eventType) {
		return 0, false
	}
	uri := eventtypes.Resolve(eventType)
	for _, known := range Known {
		if known.EventType == uri {
			return known.Kind, true
		}
	}
	return Other, true
}

// Event is a RISC 1.0 event of a SET, with typed access to the few attributes RISC defines. Most
// RISC events have no attributes; Payload is the event as received for anything else.
//
// The subject of the event is the sub_id of the SET, Context.Subject in a handler.
type Event struct {
	eventType string
	kind      Kind
	payload   ssf.Claims
}

// Of is the RISC event with the given type (URI or alias) and payload; nil if the type is not a
// RISC event.
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

// InToken are the RISC events of a SET, in the order of their event type URIs.
func InToken(token *ssf.EventToken) []*Event {
	keys := make([]string, 0, len(token.Events()))
	for key := range token.Events() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var events []*Event
	for _, eventType := range keys {
		if event := Of(eventType, ssf.Object(token.Events()[eventType])); event != nil {
			events = append(events, event)
		}
	}
	return events
}

// EventType is the event type URI.
func (e *Event) EventType() string { return e.eventType }

// Kind is the kind of event.
func (e *Event) Kind() Kind { return e.kind }

// Payload is the event payload as received.
func (e *Event) Payload() ssf.Claims { return e.payload }

// Reason is the reason of an AccountDisabled: hijacking or bulk-account.
func (e *Event) Reason() string { return e.string("reason") }

// NewValue is the new-value of an IdentifierChanged, the new identifier.
func (e *Event) NewValue() string { return e.string("new-value") }

// CredentialType is the credential_type of a CredentialCompromise, one of the values of CAEP's
// credential-change (password, pin, x509, ...).
func (e *Event) CredentialType() string { return e.string("credential_type") }

// EventTimestamp is the event_timestamp of a CredentialCompromise, when the transmitter
// discovered the compromise. RISC defines seconds since the epoch; a value that is clearly
// milliseconds is accepted too. ok is false if absent.
func (e *Event) EventTimestamp() (time.Time, bool) {
	return ssf.EventTimestamp(e.payload["event_timestamp"])
}

// ReasonAdmin is the reason_admin of a CredentialCompromise, the reason for administrators. RISC
// leaves the type open; a localizable object as CAEP defines it is returned as its JSON text.
func (e *Event) ReasonAdmin() string { return e.text("reason_admin") }

// ReasonUser is the reason_user of a CredentialCompromise, the reason for the end user.
func (e *Event) ReasonUser() string { return e.text("reason_user") }

func (e *Event) string(name string) string { return ssf.StringMember(e.payload, name) }

// text is a claim as text: a string as it is, anything else as its JSON, "" if absent.
func (e *Event) text(name string) string {
	switch v := e.payload[name].(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		encoded, _ := json.Marshal(v)
		return string(encoded)
	}
}
