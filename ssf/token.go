package ssf

import (
	"fmt"
	"time"
)

// EventToken is a verified Security Event Token (SET, RFC 8417) with the SSF profile claims.
// Immutable; pass it by pointer.
type EventToken struct {
	jti       string
	iss       string
	iat       int64
	aud       []string
	events    Claims
	subjectID Claims
	txn       string
	claims    Claims
}

// EventTokenFromClaims builds a token from decoded claims. Lenient: nil if the claims lack a
// non-empty jti, a string iss, a numeric iat or a non-empty events object (RFC 8417, section
// 2.2). The verifier applies the rules that produce error codes; this only shapes the result.
func EventTokenFromClaims(claims Claims) *EventToken {
	jti := StringMember(claims, "jti")
	if jti == "" {
		return nil
	}
	iss, ok := claims["iss"].(string)
	if !ok {
		return nil
	}
	iat, ok := Int64(claims["iat"])
	if !ok {
		return nil
	}
	events := ObjectMember(claims, "events")
	if len(events) == 0 {
		return nil
	}
	subjectID := ObjectMember(claims, "sub_id")
	if len(subjectID) == 0 {
		subjectID = nil
	}
	txn, _ := claims["txn"].(string)
	return &EventToken{
		jti:       jti,
		iss:       iss,
		iat:       iat,
		aud:       Audiences(claims["aud"]),
		events:    events,
		subjectID: subjectID,
		txn:       txn,
		claims:    claims,
	}
}

// JTI is the jti claim, the identifier of the SET, unique per issuer.
func (t *EventToken) JTI() string { return t.jti }

// Issuer is the iss claim, the issuer of the SET (the transmitter).
func (t *EventToken) Issuer() string { return t.iss }

// IssuedAtSeconds is the iat claim, seconds since the epoch.
func (t *EventToken) IssuedAtSeconds() int64 { return t.iat }

// IssuedAt is the iat claim as a point in time.
func (t *EventToken) IssuedAt() time.Time { return time.Unix(t.iat, 0).UTC() }

// Audience is the aud claim, a single value as a list of one, empty if the claim was absent.
func (t *EventToken) Audience() []string { return t.aud }

// Events is the events claim: event payloads keyed by event type URI.
func (t *EventToken) Events() Claims { return t.events }

// SubjectID is the top-level sub_id claim SSF 1.0 requires, nil if absent or empty.
func (t *EventToken) SubjectID() Claims { return t.subjectID }

// Txn is the txn claim, the transaction identifier that groups SETs (RFC 8417, section 2.2), ""
// if absent.
func (t *EventToken) Txn() string { return t.txn }

// Claims are all claims of the SET as received. Do not modify them.
func (t *EventToken) Claims() Claims { return t.claims }

// IdempotencyKey is the key that identifies this SET across deliveries: the issuer and the jti,
// which is only unique per issuer (RFC 8417, section 2.2). A handler that has side effects
// outside the receiver's stores uses it to make them idempotent, because a SET may be handled
// more than once: after a handler failed, or on another instance after the one that handled it
// died before recording the success.
func (t *EventToken) IdempotencyKey() string {
	return fmt.Sprintf("%s::%s", t.iss, t.jti)
}

// SubjectCompatibilityMode is which convention for the subject of a SET a peer follows. SSF 1.0
// requires a top-level sub_id claim in every SET, including those of the CAEP and RISC event types
// defined before it; earlier drafts put the subject into the event payload instead. A receiver
// validates by it, a transmitter would emit by it.
type SubjectCompatibilityMode int

const (
	// Strict is SSF 1.0: a SET without a top-level sub_id is rejected as invalid_request. The
	// default.
	Strict SubjectCompatibilityMode = iota
	// Legacy makes the top-level sub_id optional, for transmitters that follow earlier drafts;
	// the event context then reads the subject member of the event payload.
	Legacy
)

// String is the name used in configuration: "strict" or "legacy".
func (m SubjectCompatibilityMode) String() string {
	if m == Legacy {
		return "legacy"
	}
	return "strict"
}
