package receiver_test

// SsfCaepEventHandlerTests, SsfRiscEventHandlerTests and SsfScimEventHandlerTests of the Java
// library.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/caep"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
	"github.com/easyssf/easyssf-go/ssf/risc"
	"github.com/easyssf/easyssf-go/ssf/scim"
	"github.com/easyssf/easyssf-go/ssftest"
)

type calls struct {
	mu    sync.Mutex
	calls []string
}

func (c *calls) record(what string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, what)
}

func (c *calls) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	taken := c.calls
	c.calls = nil
	return taken
}

func (c *calls) expect(t *testing.T, expected ...string) {
	t.Helper()
	if taken := c.take(); strings.Join(taken, ",") != strings.Join(expected, ",") {
		t.Fatalf("got %v, expected %v", taken, expected)
	}
}

type caepRecorder struct {
	receiver.NoopCaepHandler
	calls *calls
}

func (r *caepRecorder) OnSessionRevoked(_ context.Context, event *caep.Event, context *receiver.Context) error {
	r.calls.record(fmt.Sprintf("session_revoked:%s:%s", context.Subject().Sub(), event.InitiatingEntity()))
	return nil
}
func (r *caepRecorder) OnTokenClaimsChange(context.Context, *caep.Event, *receiver.Context) error {
	r.calls.record("token_claims_change")
	return nil
}
func (r *caepRecorder) OnCredentialChange(context.Context, *caep.Event, *receiver.Context) error {
	r.calls.record("credential_change")
	return nil
}
func (r *caepRecorder) OnAssuranceLevelChange(context.Context, *caep.Event, *receiver.Context) error {
	r.calls.record("assurance_level_change")
	return nil
}
func (r *caepRecorder) OnDeviceComplianceChange(context.Context, *caep.Event, *receiver.Context) error {
	r.calls.record("device_compliance_change")
	return nil
}
func (r *caepRecorder) OnSessionEstablished(context.Context, *caep.Event, *receiver.Context) error {
	r.calls.record("session_established")
	return nil
}
func (r *caepRecorder) OnSessionPresented(context.Context, *caep.Event, *receiver.Context) error {
	r.calls.record("session_presented")
	return nil
}
func (r *caepRecorder) OnRiskLevelChange(context.Context, *caep.Event, *receiver.Context) error {
	r.calls.record("risk_level_change")
	return nil
}
func (r *caepRecorder) OnOtherCaepEvent(_ context.Context, event *caep.Event, _ *receiver.Context) error {
	r.calls.record("other:" + event.EventType())
	return nil
}

func contextWith(events ssf.Claims) *receiver.Context {
	claims := ssf.Claims{"jti": "1", "iss": "https://t.example", "iat": float64(1), "sub_id": ssf.IssSub(idp, "alice"), "events": events}
	return receiver.NewContext(ssf.EventTokenFromClaims(claims), ssf.Push)
}

func snake(name string) string {
	var b strings.Builder
	for i, c := range name {
		if c >= 'A' && c <= 'Z' && i > 0 {
			b.WriteByte('_')
		}
		b.WriteRune(c | 0x20)
	}
	return b.String()
}

func TestCaepDispatchesEveryKindToItsMethod(t *testing.T) {
	c := &calls{}
	handler := receiver.Caep(&caepRecorder{calls: c})
	for _, known := range caep.Known {
		if err := handler.Handle(ctx, contextWith(ssf.Claims{known.EventType: ssf.Claims{"initiating_entity": "admin"}})); err != nil {
			t.Fatal(err)
		}
		expected := snake(known.Kind.String())
		if known.Kind == caep.SessionRevoked {
			expected = "session_revoked:alice:admin"
		}
		c.expect(t, expected)
	}
	_ = handler.Handle(ctx, contextWith(ssf.Claims{"https://schemas.openid.net/secevent/caep/event-type/future": ssf.Claims{}}))
	c.expect(t, "other:https://schemas.openid.net/secevent/caep/event-type/future")
}

func TestHandlesAllCaepEventsOfASetAndIgnoresOtherSets(t *testing.T) {
	c := &calls{}
	handler := receiver.Caep(&caepRecorder{calls: c})
	_ = handler.Handle(ctx, contextWith(ssf.Claims{eventtypes.CaepCredentialChange: ssf.Claims{}, eventtypes.RiscAccountDisabled: ssf.Claims{}, eventtypes.CaepRiskLevelChange: ssf.Claims{}}))
	c.expect(t, "credential_change", "risk_level_change")
	_ = handler.Handle(ctx, contextWith(ssf.Claims{eventtypes.RiscAccountDisabled: ssf.Claims{}}))
	c.expect(t)
}

func TestCaepSetPassesStrictVerificationAndReachesTheHandler(t *testing.T) {
	transmitter := ssftest.New()
	c := &calls{}
	p := processor(t, transmitter, receiver.Caep(&caepRecorder{calls: c}))
	if _, err := p.Process(ctx, transmitter.Set("CaepSessionRevoked", alice(transmitter)), ssf.Push); err != nil {
		t.Fatal(err)
	}
	c.expect(t, "session_revoked:alice:")
}

type riscRecorder struct {
	receiver.NoopRiscHandler
	calls *calls
}

func (r *riscRecorder) OnRiscEvent(ctx context.Context, event *risc.Event, context *receiver.Context) error {
	r.calls.record(event.Kind().String())
	return receiver.DispatchRiscEvent(ctx, r, event, context)
}
func (r *riscRecorder) OnAccountDisabled(_ context.Context, event *risc.Event, _ *receiver.Context) error {
	r.calls.record("disabled:" + event.Reason())
	return nil
}
func (r *riscRecorder) OnAccountPurged(context.Context, *risc.Event, *receiver.Context) error {
	r.calls.record("purged")
	return nil
}

func TestRiscDispatchesEveryKindToItsMethod(t *testing.T) {
	c := &calls{}
	handler := receiver.Risc(&riscRecorder{calls: c})
	_ = handler.Handle(ctx, contextWith(ssf.Claims{eventtypes.RiscAccountDisabled: ssf.Claims{"reason": "hijacking"}}))
	c.expect(t, "AccountDisabled", "disabled:hijacking")
	for _, known := range risc.Known {
		_ = handler.Handle(ctx, contextWith(ssf.Claims{known.EventType: ssf.Claims{}}))
		if taken := c.take(); taken[0] != known.Kind.String() {
			t.Fatalf("%v", taken)
		}
	}
}

func TestHandlesAllRiscEventsOfASetAndIgnoresOtherSets(t *testing.T) {
	c := &calls{}
	handler := receiver.Risc(&riscRecorder{calls: c})
	_ = handler.Handle(ctx, contextWith(ssf.Claims{eventtypes.CaepSessionRevoked: ssf.Claims{}, eventtypes.RiscAccountPurged: ssf.Claims{}, eventtypes.RiscOptIn: ssf.Claims{}}))
	c.expect(t, "AccountPurged", "purged", "OptIn")
}

func TestRiscSetPassesStrictVerificationAndReachesTheHandler(t *testing.T) {
	transmitter := ssftest.New()
	c := &calls{}
	p := processor(t, transmitter, receiver.Risc(&riscRecorder{calls: c}))
	if _, err := p.Process(ctx, transmitter.Set("RiscAccountPurged", alice(transmitter)), ssf.Push); err != nil {
		t.Fatal(err)
	}
	c.expect(t, "AccountPurged", "purged")
}

type scimRecorder struct {
	receiver.NoopScimHandler
	calls *calls
}

func (r *scimRecorder) OnScimEvent(ctx context.Context, event *scim.Event, context *receiver.Context) error {
	id := ""
	if event.Subject() != nil {
		id = event.Subject().ID()
	}
	r.calls.record(fmt.Sprintf("%s:%s", event.Operation(), id))
	if event.Operation() == scim.Create {
		return r.OnCreate(ctx, event, context)
	}
	return nil
}
func (r *scimRecorder) OnCreate(_ context.Context, event *scim.Event, _ *receiver.Context) error {
	r.calls.record(fmt.Sprintf("create:full=%v", event.IsFull()))
	return nil
}

func TestScimDispatchesEveryOperationToItsMethod(t *testing.T) {
	c := &calls{}
	handler := receiver.Scim(&scimRecorder{calls: c})
	for _, known := range scim.Known {
		claims := ssf.Claims{"jti": "1", "iss": "i", "iat": float64(1), "sub_id": ssf.SCIM("/Users/42", ""), "events": ssf.Claims{known.EventType: ssf.Claims{"data": ssf.Claims{}}}}
		_ = handler.Handle(ctx, receiver.NewContext(ssf.EventTokenFromClaims(claims), ssf.Push))
		taken := c.take()
		if taken[0] != known.Operation.String()+":42" {
			t.Fatalf("%s: %v", known.EventType, taken)
		}
		if known.Operation == scim.Create && taken[1] != fmt.Sprintf("create:full=%v", strings.HasSuffix(known.EventType, ":full")) {
			t.Fatalf("%v", taken)
		}
	}
}

func TestHandlesAllScimEventsOfASetAndIgnoresOtherSets(t *testing.T) {
	c := &calls{}
	handler := receiver.Scim(&scimRecorder{calls: c})
	_ = handler.Handle(ctx, contextWith(ssf.Claims{eventtypes.ScimProvDelete: ssf.Claims{}, eventtypes.CaepSessionRevoked: ssf.Claims{}, eventtypes.ScimFeedRemove: ssf.Claims{}}))
	// the SET's subject is iss_sub, so the events have no SCIM subject; sorted by URI
	c.expect(t, "FeedRemove:", "Delete:")
	_ = handler.Handle(ctx, contextWith(ssf.Claims{eventtypes.CaepSessionRevoked: ssf.Claims{}}))
	c.expect(t)
}

func TestScimSetPassesStrictVerificationAndReachesTheHandler(t *testing.T) {
	transmitter := ssftest.New()
	c := &calls{}
	p := processor(t, transmitter, receiver.Scim(&scimRecorder{calls: c}))
	claims := transmitter.SetClaimsWithPayload("ScimProvCreateFull", ssf.SCIM("/Users/42", ""), ssf.Claims{"data": ssf.Claims{"userName": "alice"}})
	if _, err := p.Process(ctx, transmitter.SignSET(claims), ssf.Push); err != nil {
		t.Fatal(err)
	}
	c.expect(t, "Create:42", "create:full=true")
}
