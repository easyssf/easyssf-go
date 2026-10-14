package receiver_test

// InMemorySsfJtiDedupStoreTests of the Java library.

import (
	"context"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
)

func token(jti string) *ssf.EventToken {
	return ssf.EventTokenFromClaims(ssf.Claims{"jti": jti, "iss": "https://t.example", "iat": float64(1), "events": ssf.Claims{"e": ssf.Claims{}}})
}

func state(t *testing.T, claim receiver.JTIClaim, err error) receiver.JTIClaimState {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return claim.State
}

// claimState claims and returns the state.
func claimState(t *testing.T, store receiver.JTIDedupStore, set *ssf.EventToken) receiver.JTIClaimState {
	t.Helper()
	claim, err := store.Claim(context.Background(), set)
	return state(t, claim, err)
}

func TestClaimInProgressProcessedForget(t *testing.T) {
	store := receiver.NewInMemoryJTIDedupStore(10, 0, nil)
	set := token("1")
	claim, err := store.Claim(ctx, set)
	if state(t, claim, err) != receiver.Granted {
		t.Fatal("first claim is granted")
	}
	if claimState(t, store, set) != receiver.InProgress {
		t.Fatal("second claim is in progress")
	}
	_ = store.Processed(ctx, set, claim)
	if claimState(t, store, set) != receiver.Processed {
		t.Fatal("processed")
	}
	// forgetting a processed SET does nothing: only an in-progress claim is forgotten
	_ = store.Forget(ctx, set, claim)
	if claimState(t, store, set) != receiver.Processed {
		t.Fatal("still processed")
	}
	other := token("2")
	claim, _ = store.Claim(ctx, other)
	_ = store.Forget(ctx, other, claim)
	if claimState(t, store, other) != receiver.Granted || store.Len() != 2 {
		t.Fatal("forgotten SET is claimed anew")
	}
}

func TestAbandonedClaimIsTakenOverAfterTheLease(t *testing.T) {
	clock := newTestClock()
	store := receiver.NewInMemoryJTIDedupStore(10, 60*time.Second, clock.Now)
	set := token("1")
	first, _ := store.Claim(ctx, set)
	clock.Advance(59 * time.Second)
	if claimState(t, store, set) != receiver.InProgress {
		t.Fatal("within the lease")
	}
	clock.Advance(2 * time.Second)
	second, err := store.Claim(ctx, set)
	if state(t, second, err) != receiver.Granted || second.Token == first.Token {
		t.Fatalf("taken over with a token of its own: %+v %+v", first, second)
	}
}

func TestLateHolderCanNeitherCompleteNorForgetTheClaimTakenOverFromIt(t *testing.T) {
	clock := newTestClock()
	store := receiver.NewInMemoryJTIDedupStore(10, 60*time.Second, clock.Now)
	set := token("1")
	first, _ := store.Claim(ctx, set)
	clock.Advance(61 * time.Second)
	second, _ := store.Claim(ctx, set)
	_ = store.Processed(ctx, set, first)
	if claimState(t, store, set) != receiver.InProgress {
		t.Fatal("still held by the second")
	}
	_ = store.Forget(ctx, set, first)
	if claimState(t, store, set) != receiver.InProgress {
		t.Fatal("still held by the second")
	}
	if _, ok, _ := store.Renew(ctx, set, first); ok {
		t.Fatal("the first cannot renew")
	}
	_ = store.Processed(ctx, set, second)
	if claimState(t, store, set) != receiver.Processed {
		t.Fatal("the second completes")
	}
}

func TestRenewedClaimOutlivesTheLease(t *testing.T) {
	clock := newTestClock()
	store := receiver.NewInMemoryJTIDedupStore(10, 60*time.Second, clock.Now)
	set := token("1")
	claim, _ := store.Claim(ctx, set)
	clock.Advance(40 * time.Second)
	renewed, ok, _ := store.Renew(ctx, set, claim)
	if !ok {
		t.Fatal("renewed")
	}
	clock.Advance(40 * time.Second)
	if claimState(t, store, set) != receiver.InProgress {
		t.Fatal("the renewed claim holds")
	}
	_ = store.Processed(ctx, set, renewed)
	if claimState(t, store, set) != receiver.Processed {
		t.Fatal("processed")
	}
}

func TestSuccessOfAnEvictedClaimIsRecorded(t *testing.T) {
	store := receiver.NewInMemoryJTIDedupStore(2, 0, nil)
	first := token("1")
	claim, _ := store.Claim(ctx, first)
	_, _ = store.Claim(ctx, token("2"))
	_, _ = store.Claim(ctx, token("3"))
	if store.Len() != 2 {
		t.Fatal("bounded")
	}
	if claimState(t, store, first) != receiver.Granted {
		t.Fatal("evicted: claimed anew")
	}
	claim2, _ := store.Claim(ctx, token("4"))
	_, _ = store.Claim(ctx, token("5"))
	_ = store.Processed(ctx, token("4"), claim2)
	if claimState(t, store, token("4")) != receiver.Processed {
		t.Fatal("the success of an evicted claim is recorded")
	}
	// the original claim of the first SET was evicted and re-claimed: the old token does not hold
	_ = store.Processed(ctx, first, claim)
	if store.Len() != 2 {
		t.Fatal("bounded")
	}
}

func TestCapacityEvictsTheOldestEntry(t *testing.T) {
	store := receiver.NewInMemoryJTIDedupStore(3, 0, nil)
	for _, jti := range []string{"1", "2", "3"} {
		claim, _ := store.Claim(ctx, token(jti))
		_ = store.Processed(ctx, token(jti), claim)
	}
	if claimState(t, store, token("1")) != receiver.Processed {
		t.Fatal("processed")
	}
	claim, _ := store.Claim(ctx, token("4"))
	_ = store.Processed(ctx, token("4"), claim)
	if store.Len() != 3 {
		t.Fatal("bounded")
	}
	if claimState(t, store, token("1")) != receiver.Granted {
		t.Fatal("the oldest was evicted")
	}
}
