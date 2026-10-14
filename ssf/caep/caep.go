// Package caep holds the CAEP 1.0 events: the kinds of section 3 and typed access to their
// claims, the common ones of section 2 (event_timestamp, initiating_entity, reason_admin,
// reason_user) and the event-specific ones (credential_type, change_type, current_level, ...).
// A port of caep.rs of the Rust port and of org.easyssf.core.caep.
package caep

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// Kind is one of the events of CAEP 1.0, section 3, or Other for an event type in the CAEP
// namespace this version does not know. New kinds are added as CAEP defines events, so do not
// switch over them exhaustively; implement the receiver's CaepHandler interface instead.
type Kind int

const (
	// Other is an event type in the CAEP namespace this version does not know, for example one
	// of a later CAEP version. The common claims of CAEP section 2 are still available.
	Other Kind = iota
	// SessionRevoked: the session was revoked (section 3.1).
	SessionRevoked
	// TokenClaimsChange: claims of the token the subject identifies changed (section 3.2).
	TokenClaimsChange
	// CredentialChange: a credential was created, revoked, updated or deleted (section 3.3).
	CredentialChange
	// AssuranceLevelChange: the assurance level of the subject changed (section 3.4).
	AssuranceLevelChange
	// DeviceComplianceChange: the compliance status of the device changed (section 3.5).
	DeviceComplianceChange
	// SessionEstablished: a session was established (section 3.6).
	SessionEstablished
	// SessionPresented: a session was presented to the transmitter (section 3.7).
	SessionPresented
	// RiskLevelChange: the risk level of the subject changed (section 3.8).
	RiskLevelChange
)

// Known are the known kinds and their event type URIs, in the order of the specification.
var Known = []struct {
	Kind      Kind
	EventType string
}{
	{SessionRevoked, eventtypes.CaepSessionRevoked},
	{TokenClaimsChange, eventtypes.CaepTokenClaimsChange},
	{CredentialChange, eventtypes.CaepCredentialChange},
	{AssuranceLevelChange, eventtypes.CaepAssuranceLevelChange},
	{DeviceComplianceChange, eventtypes.CaepDeviceComplianceChange},
	{SessionEstablished, eventtypes.CaepSessionEstablished},
	{SessionPresented, eventtypes.CaepSessionPresented},
	{RiskLevelChange, eventtypes.CaepRiskLevelChange},
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

// String is the name of the kind: SessionRevoked, ..., Other.
func (k Kind) String() string {
	switch k {
	case SessionRevoked:
		return "SessionRevoked"
	case TokenClaimsChange:
		return "TokenClaimsChange"
	case CredentialChange:
		return "CredentialChange"
	case AssuranceLevelChange:
		return "AssuranceLevelChange"
	case DeviceComplianceChange:
		return "DeviceComplianceChange"
	case SessionEstablished:
		return "SessionEstablished"
	case SessionPresented:
		return "SessionPresented"
	case RiskLevelChange:
		return "RiskLevelChange"
	}
	return "Other"
}

// KindOf is the kind of CAEP event of an event type URI or alias: Other for an unknown event type
// in the CAEP namespace; ok is false if the event type is not a CAEP event.
func KindOf(eventType string) (kind Kind, ok bool) {
	if !eventtypes.IsCaepEvent(eventType) {
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

// Event is a CAEP 1.0 event of a SET, with typed access to the claims every CAEP event may carry
// (section 2) and to the event-specific claims of section 3. An accessor returns "" (or an empty
// collection) when the claim is absent, whether because the transmitter left it out or because
// the Kind does not define it. Payload is the event as received, for anything else.
//
// The subject of the event is the sub_id of the SET, Context.Subject in a handler: CAEP does not
// prescribe a subject format.
type Event struct {
	eventType string
	kind      Kind
	payload   ssf.Claims
}

// Of is the CAEP event with the given type (URI or alias) and payload; nil if the type is not a
// CAEP event.
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

// InToken are the CAEP events of a SET, in the order of their event type URIs. CAEP allows one
// event per SET; a SET with several is read like one of each.
func InToken(token *ssf.EventToken) []*Event {
	var events []*Event
	for _, eventType := range sortedKeys(token.Events()) {
		if event := Of(eventType, ssf.Object(token.Events()[eventType])); event != nil {
			events = append(events, event)
		}
	}
	return events
}

func sortedKeys(object ssf.Claims) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// EventType is the event type URI.
func (e *Event) EventType() string { return e.eventType }

// Kind is the kind of event.
func (e *Event) Kind() Kind { return e.kind }

// Payload is the event payload as received.
func (e *Event) Payload() ssf.Claims { return e.payload }

// CAEP section 2: claims every event may carry

// EventTimestamp is the event_timestamp, the time the event occurred. CAEP defines seconds since
// the epoch; a value that is clearly milliseconds is accepted too. ok is false if absent.
func (e *Event) EventTimestamp() (time.Time, bool) {
	return ssf.EventTimestamp(e.payload["event_timestamp"])
}

// InitiatingEntity is the initiating_entity, who invoked the event: admin, user, policy or
// system.
func (e *Event) InitiatingEntity() string { return e.string("initiating_entity") }

// ReasonAdmin is the reason_admin, the reason for administrators, by BCP 47 language tag (en,
// de-CH, ...); empty if absent. A transmitter that sends a plain string instead of the
// localizable object of CAEP gets the key "".
func (e *Event) ReasonAdmin() map[string]string { return Localized(e.payload["reason_admin"]) }

// ReasonUser is the reason_user, the reason for display to the end user, by BCP 47 language tag;
// empty if absent, a plain string under the key "".
func (e *Event) ReasonUser() map[string]string { return Localized(e.payload["reason_user"]) }

// CAEP section 3: event-specific claims

// Claims are the claims of a TokenClaimsChange, each with its new value; nil if absent.
func (e *Event) Claims() ssf.Claims { return ssf.ObjectMember(e.payload, "claims") }

// CredentialType is the credential_type of a CredentialChange: password, pin, x509,
// fido2-platform, fido2-roaming, fido-u2f, verifiable-credential, phone-voice, phone-sms, app
// or a value agreed with the transmitter.
func (e *Event) CredentialType() string { return e.string("credential_type") }

// ChangeType is the change_type of a CredentialChange: create, revoke, update or delete.
func (e *Event) ChangeType() string { return e.string("change_type") }

// FriendlyName is the friendly_name of the credential of a CredentialChange.
func (e *Event) FriendlyName() string { return e.string("friendly_name") }

// X509Issuer is the x509_issuer of an X.509 credential.
func (e *Event) X509Issuer() string { return e.string("x509_issuer") }

// X509Serial is the x509_serial of an X.509 credential.
func (e *Event) X509Serial() string { return e.string("x509_serial") }

// FIDO2AAGUID is the fido2_aaguid, the FIDO2 Authenticator Attestation GUID of the credential.
func (e *Event) FIDO2AAGUID() string { return e.string("fido2_aaguid") }

// Namespace is the namespace of the levels of an AssuranceLevelChange: RFC8176, RFC6711,
// ISO-IEC-29115, NIST-IAL, NIST-AAL, NIST-FAL or a value agreed with the transmitter.
func (e *Event) Namespace() string { return e.string("namespace") }

// CurrentLevel is the current_level: the assurance level of an AssuranceLevelChange in its
// Namespace, or the risk level of a RiskLevelChange (LOW, MEDIUM, HIGH).
func (e *Event) CurrentLevel() string { return e.string("current_level") }

// PreviousLevel is the previous_level of an assurance or risk level change, "" if the
// transmitter does not know the previous level.
func (e *Event) PreviousLevel() string { return e.string("previous_level") }

// ChangeDirection is the change_direction of an AssuranceLevelChange: increase or decrease.
func (e *Event) ChangeDirection() string { return e.string("change_direction") }

// CurrentStatus is the current_status of a DeviceComplianceChange: compliant or not-compliant.
func (e *Event) CurrentStatus() string { return e.string("current_status") }

// PreviousStatus is the previous_status of a DeviceComplianceChange.
func (e *Event) PreviousStatus() string { return e.string("previous_status") }

// FPUA is the fp_ua, the fingerprint of the user agent of a SessionEstablished or
// SessionPresented.
func (e *Event) FPUA() string { return e.string("fp_ua") }

// ACR is the acr, the authentication context class reference of a SessionEstablished, as in an
// ID Token.
func (e *Event) ACR() string { return e.string("acr") }

// AMR is the amr, the authentication methods references of a SessionEstablished, as in an ID
// Token; empty if absent.
func (e *Event) AMR() []string { return ssf.Strings(e.payload["amr"]) }

// ExtID is the ext_id, the external session identifier of a SessionEstablished or
// SessionPresented that correlates it with a broader session, for example a SAML one.
func (e *Event) ExtID() string { return e.string("ext_id") }

// Principal is the principal of a RiskLevelChange, the entity whose risk changed: USER, DEVICE,
// SESSION, TENANT, ORG_UNIT, GROUP or another entity of SSF.
func (e *Event) Principal() string { return e.string("principal") }

// RiskReason is the risk_reason of a RiskLevelChange.
func (e *Event) RiskReason() string { return e.string("risk_reason") }

func (e *Event) string(name string) string { return ssf.StringMember(e.payload, name) }

// Localized reads a localizable claim as CAEP defines it (section 2): an object of texts by BCP
// 47 language tag. A plain string is kept under the key "", other values as their JSON; nil
// gives an empty map.
func Localized(value any) map[string]string {
	switch v := value.(type) {
	case nil:
		return map[string]string{}
	case string:
		return map[string]string{"": v}
	case map[string]any:
		reasons := map[string]string{}
		for tag, reason := range v {
			switch text := reason.(type) {
			case nil:
			case string:
				reasons[tag] = text
			default:
				encoded, _ := json.Marshal(text)
				reasons[tag] = string(encoded)
			}
		}
		return reasons
	}
	encoded, _ := json.Marshal(value)
	return map[string]string{"": string(encoded)}
}
