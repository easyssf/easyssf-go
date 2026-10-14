package receiver

import (
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
)

// JTIClaimState is what a store knows about a SET when it is claimed.
type JTIClaimState int

const (
	// Granted: not seen before, or abandoned by a crashed instance: the caller handles the SET.
	Granted JTIClaimState = iota + 1
	// InProgress: another instance is handling the SET right now: neither handle nor
	// acknowledge it.
	InProgress
	// Processed: the SET was handled before: acknowledge it, do not handle it again.
	Processed
)

// JTIClaim is the answer of a JTIDedupStore to a claim and, for a granted claim, the token that
// fences it against a later take-over of the same SET.
type JTIClaim struct {
	State JTIClaimState
	// Token is a value the store chooses for a granted claim, for example the time of the claim.
	Token int64
}

// IsGranted reports whether the claim was granted: the caller handles the SET.
func (c JTIClaim) IsGranted() bool { return c.State == Granted }

// JTIDedupStore remembers which SETs were processed, so that a redelivery of a handled SET is
// skipped and a SET another instance is handling is left alone. It does not make handling exactly
// once: an instance that dies after a handler ran and before Processed hands the SET to the next
// instance after the lease, which is why handlers are idempotent. Implement it to back it with a
// shared or durable store.
//
// A SET is claimed before its handlers run and marked processed once they succeeded. In between
// it is in progress: another instance of the application that receives the same SET then neither
// handles nor acknowledges it, and leaves it to the transmitter's redelivery. An instance that
// crashes mid-processing leaves the claim behind, so a claim older than the store's lease counts
// as abandoned and the next instance takes the SET over.
//
// A granted claim carries a token that fences it: Processed, Forget and Renew only act on the
// claim with that token. An instance whose handlers outlived the lease therefore neither
// completes nor deletes the claim of the instance that took the SET over; the SET belongs to the
// new holder. An instance whose handlers may run longer than the lease renews its claim
// meanwhile.
type JTIDedupStore interface {
	// Claim atomically records that the caller is about to handle the SET, unless it was handled
	// before or is being handled by another instance.
	Claim(ctx context.Context, token *ssf.EventToken) (JTIClaim, error)
	// Processed records that the handlers of a claimed SET succeeded. Does nothing if the claim
	// was taken over meanwhile, because the handlers outlived the lease.
	Processed(ctx context.Context, token *ssf.EventToken, claim JTIClaim) error
	// Forget forgets the given SET again, because handling it failed and it is expected to be
	// delivered once more. Does nothing if the claim was taken over meanwhile.
	Forget(ctx context.Context, token *ssf.EventToken, claim JTIClaim) error
	// Renew extends the claim of a SET whose handlers are still running: its age starts over, so
	// it does not count as abandoned after the lease. It returns the claim to use from now on, as
	// a store may give a renewed claim a new token, and ok false if the claim was taken over, the
	// SET then belongs to the instance that took it over. A store that does not renew returns
	// the claim as it is, which leaves the lease as the bound for the handlers.
	Renew(ctx context.Context, token *ssf.EventToken, claim JTIClaim) (renewed JTIClaim, ok bool, err error)
}

type knownState int

const (
	knownInProgress knownState = iota + 1
	knownProcessed
)

type known struct {
	state   knownState
	since   time.Time
	token   int64
	element *list.Element
}

// InMemoryJTIDedupStore is a JTIDedupStore that remembers a bounded number of SETs in memory,
// evicting the oldest first. Its content is lost on restart and not shared between instances, so
// the in-progress state only matters when the same SET arrives twice while a handler of this
// instance still runs.
type InMemoryJTIDedupStore struct {
	capacity  int
	lease     time.Duration
	clock     Clock
	mu        sync.Mutex
	entries   map[string]*known
	order     *list.List // keys, oldest first
	nextToken int64
}

// DefaultDedupLease is the lease by default: 60 seconds.
const DefaultDedupLease = 60 * time.Second

// NewInMemoryJTIDedupStore is a store that remembers capacity SETs (at least one) and holds a
// claim for lease (DefaultDedupLease if zero), longer than the longest handler, measured by
// clock (the system clock if nil).
func NewInMemoryJTIDedupStore(capacity int, lease time.Duration, clock Clock) *InMemoryJTIDedupStore {
	if capacity < 1 {
		capacity = 1
	}
	if lease <= 0 {
		lease = DefaultDedupLease
	}
	if clock == nil {
		clock = SystemClock
	}
	return &InMemoryJTIDedupStore{capacity: capacity, lease: lease, clock: clock, entries: map[string]*known{}, order: list.New()}
}

// Len is the number of SETs remembered.
func (s *InMemoryJTIDedupStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *InMemoryJTIDedupStore) put(key string, state knownState, token int64) {
	if existing, ok := s.entries[key]; ok {
		s.order.Remove(existing.element)
	}
	s.entries[key] = &known{state: state, since: s.clock(), token: token, element: s.order.PushBack(key)}
	for len(s.entries) > s.capacity {
		oldest := s.order.Front()
		s.order.Remove(oldest)
		delete(s.entries, oldest.Value.(string))
	}
}

func (s *InMemoryJTIDedupStore) grant(key string) JTIClaim {
	s.nextToken++
	s.put(key, knownInProgress, s.nextToken)
	return JTIClaim{State: Granted, Token: s.nextToken}
}

func (k *known) holds(claim JTIClaim) bool {
	return k.state == knownInProgress && k.token == claim.Token
}

// Claim implements JTIDedupStore.
func (s *InMemoryJTIDedupStore) Claim(_ context.Context, token *ssf.EventToken) (JTIClaim, error) {
	key := token.IdempotencyKey()
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.entries[key]
	switch {
	case !ok:
		return s.grant(key), nil
	case existing.state == knownProcessed:
		return JTIClaim{State: Processed}, nil
	case !existing.since.Add(s.lease).After(s.clock()):
		// abandoned: taken over, with a token of its own
		return s.grant(key), nil
	}
	return JTIClaim{State: InProgress}, nil
}

// Processed implements JTIDedupStore.
func (s *InMemoryJTIDedupStore) Processed(_ context.Context, token *ssf.EventToken, claim JTIClaim) error {
	key := token.IdempotencyKey()
	s.mu.Lock()
	defer s.mu.Unlock()
	// the claim may have been evicted meanwhile: record the success anyway
	if existing, ok := s.entries[key]; !ok || existing.holds(claim) {
		s.put(key, knownProcessed, claim.Token)
	}
	return nil
}

// Forget implements JTIDedupStore.
func (s *InMemoryJTIDedupStore) Forget(_ context.Context, token *ssf.EventToken, claim JTIClaim) error {
	key := token.IdempotencyKey()
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.entries[key]; ok && existing.holds(claim) {
		s.order.Remove(existing.element)
		delete(s.entries, key)
	}
	return nil
}

// Renew implements JTIDedupStore.
func (s *InMemoryJTIDedupStore) Renew(_ context.Context, token *ssf.EventToken, claim JTIClaim) (JTIClaim, bool, error) {
	key := token.IdempotencyKey()
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.entries[key]; ok && !existing.holds(claim) {
		return claim, false, nil
	}
	// an evicted claim is restored, as Processed records it as well
	s.put(key, knownInProgress, claim.Token)
	return claim, true, nil
}
