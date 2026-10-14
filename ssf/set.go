package ssf

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// SETBuilder assembles the claims of a Security Event Token (RFC 8417, section 2.2) for a
// transmitter or a test: iss, jti, iat, aud, sub_id, txn and events. The builder gives the
// claims; a signer such as ssf/signing turns them into a SET.
//
//	claims, err := ssf.NewSET("https://idp.example").
//		Audience("https://app.example").
//		Subject(ssf.Email("alice@example.com")).
//		Event("CaepSessionRevoked", ssf.Claims{"event_timestamp": time.Now().Unix()}).
//		Claims()
type SETBuilder struct {
	claims Claims
	events Claims
	err    error
}

// NewSET starts a SET of the issuer with a random jti and iat now.
func NewSET(issuer string) *SETBuilder {
	return &SETBuilder{claims: Claims{"iss": issuer, "jti": NewJTI(), "iat": time.Now().Unix()}, events: Claims{}}
}

// NewJTI is a random, 128 bit, hex-encoded SET identifier.
func NewJTI() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// JTI sets the identifier of the SET instead of the random one.
func (b *SETBuilder) JTI(jti string) *SETBuilder { b.claims["jti"] = jti; return b }

// IssuedAt sets iat, in seconds since the epoch, instead of now.
func (b *SETBuilder) IssuedAt(issuedAt time.Time) *SETBuilder {
	b.claims["iat"] = issuedAt.Unix()
	return b
}

// Audience sets aud: one string for one audience, an array for several, as RFC 8417, section
// 2.2 allows both; none removes the claim.
func (b *SETBuilder) Audience(audience ...string) *SETBuilder {
	switch len(audience) {
	case 0:
		delete(b.claims, "aud")
	case 1:
		b.claims["aud"] = audience[0]
	default:
		b.claims["aud"] = append([]string(nil), audience...)
	}
	return b
}

// Subject sets sub_id, a subject identifier or complex subject built with IssSub, Email,
// Complex, ...; nil removes it.
func (b *SETBuilder) Subject(subject Claims) *SETBuilder {
	if subject == nil {
		delete(b.claims, "sub_id")
	} else {
		b.claims["sub_id"] = subject
	}
	return b
}

// Txn sets the transaction identifier (RFC 8417, section 2.2); "" removes it.
func (b *SETBuilder) Txn(txn string) *SETBuilder {
	if txn == "" {
		delete(b.claims, "txn")
	} else {
		b.claims["txn"] = txn
	}
	return b
}

// Event adds an event: eventType is an alias such as "CaepSessionRevoked" or an event type
// URI, payload its claims (an empty object if nil). A SET with several events is allowed by
// RFC 8417 but SSF 1.0, section 6, has a transmitter send one event per SET.
func (b *SETBuilder) Event(eventType string, payload Claims) *SETBuilder {
	if eventType == "" {
		b.err = errors.Join(b.err, errors.New("event type must not be empty"))
		return b
	}
	if payload == nil {
		payload = Claims{}
	}
	b.events[eventtypes.Resolve(eventType)] = payload
	return b
}

// Claim sets any other claim, for example the ones of a profile; nil removes it. The events
// are set with Event.
func (b *SETBuilder) Claim(name string, value any) *SETBuilder {
	if value == nil {
		delete(b.claims, name)
	} else {
		b.claims[name] = value
	}
	return b
}

// Claims are the claims of the SET. An error if iss, jti or iat is missing or no event was
// added: a SET must have an events claim with at least one member (RFC 8417, section 2.2).
func (b *SETBuilder) Claims() (Claims, error) {
	if b.err != nil {
		return nil, b.err
	}
	var missing []string
	for _, name := range []string{"iss", "jti", "iat"} {
		if value, ok := b.claims[name]; !ok || value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("SET lacks %v", missing)
	}
	if len(b.events) == 0 {
		return nil, errors.New("SET has no event")
	}
	claims := make(Claims, len(b.claims)+1)
	for name, value := range b.claims {
		claims[name] = value
	}
	events := make(Claims, len(b.events))
	for eventType, payload := range b.events {
		events[eventType] = payload
	}
	claims["events"] = events
	return claims, nil
}

// MustClaims are the claims of the SET; it panics where Claims returns an error. For tests
// and programs whose SETs are fixed.
func (b *SETBuilder) MustClaims() Claims {
	claims, err := b.Claims()
	if err != nil {
		panic(err)
	}
	return claims
}
