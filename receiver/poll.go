package receiver

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
)

// Poll delivery (RFC 8936). SKETCH: the store and the poller's shape are here; the request
// loop, the acknowledgement and error reporting, Retry-After and the long-polling hold are a
// port of poll.rs of the Rust port (SsfPoller, SsfPollerOptions) still to do.

// PendingAck is an acknowledgement a poller owes the transmitter with its next request: a SET
// it handled (ack) or one it rejected (setErrs, with the error code and description).
type PendingAck struct {
	Issuer      string
	JTI         string
	Error       ErrorCode // "" for an acknowledgement
	Description string
	RecordedAt  time.Time
}

// PollAckStore keeps the acknowledgements a poller owes across restarts and instances, so that
// a SET handled by one instance is acknowledged even if that instance dies before its next poll.
type PollAckStore interface {
	// Record remembers an acknowledgement to send.
	Record(ctx context.Context, ack PendingAck) error
	// Pending lists the acknowledgements owed to the issuer, at most limit.
	Pending(ctx context.Context, issuer string, limit int) ([]PendingAck, error)
	// Sent forgets acknowledgements the transmitter received.
	Sent(ctx context.Context, issuer string, jtis []string) error
}

// InMemoryPollAckStore is a PollAckStore in memory.
type InMemoryPollAckStore struct {
	mu   sync.Mutex
	acks map[string][]PendingAck
}

// NewInMemoryPollAckStore is an empty store.
func NewInMemoryPollAckStore() *InMemoryPollAckStore {
	return &InMemoryPollAckStore{acks: map[string][]PendingAck{}}
}

// Record implements PollAckStore.
func (s *InMemoryPollAckStore) Record(_ context.Context, ack PendingAck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.acks[ack.Issuer] {
		if existing.JTI == ack.JTI {
			s.acks[ack.Issuer][i] = ack
			return nil
		}
	}
	s.acks[ack.Issuer] = append(s.acks[ack.Issuer], ack)
	return nil
}

// Pending implements PollAckStore.
func (s *InMemoryPollAckStore) Pending(_ context.Context, issuer string, limit int) ([]PendingAck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acks := s.acks[issuer]
	if limit > 0 && len(acks) > limit {
		acks = acks[:limit]
	}
	return append([]PendingAck(nil), acks...), nil
}

// Sent implements PollAckStore.
func (s *InMemoryPollAckStore) Sent(_ context.Context, issuer string, jtis []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sent := map[string]bool{}
	for _, jti := range jtis {
		sent[jti] = true
	}
	kept := s.acks[issuer][:0]
	for _, ack := range s.acks[issuer] {
		if !sent[ack.JTI] {
			kept = append(kept, ack)
		}
	}
	s.acks[issuer] = kept
	return nil
}

// PollerOptions say how a Poller polls; the keys of PollConfig.
type PollerOptions struct {
	Interval        time.Duration
	InitialDelay    time.Duration
	MaxEvents       int
	LongPolling     bool
	LongPollingHold time.Duration
	FallbackBackoff time.Duration
	MaxBackoff      time.Duration
	Log             *slog.Logger
}

// PollEndpoint resolves the poll endpoint, which a registered stream assigns; nil while unknown.
type PollEndpoint func() *url.URL

// Poller fetches SETs from the transmitter (RFC 8936), hands them to the Processor, acknowledges
// handled SETs and reports invalid ones with the next request, and backs off on Retry-After.
// Start runs it in a goroutine until ctx is cancelled; Stop sends the acknowledgements it owes.
// SKETCH.
type Poller struct {
	issuer    string
	endpoint  PollEndpoint
	client    *http.Client
	tokens    TokenProvider
	processor *Processor
	acks      PollAckStore
	options   PollerOptions
	cancel    context.CancelFunc
	done      chan struct{}
}

// NewPoller is a poller for one transmitter.
func NewPoller(issuer string, endpoint PollEndpoint, client *http.Client, tokens TokenProvider, processor *Processor, acks PollAckStore, options PollerOptions) *Poller {
	return &Poller{issuer: issuer, endpoint: endpoint, client: orDefault(client), tokens: tokens, processor: processor, acks: acks, options: options}
}

// PollOnce performs one poll request: sends the pending acknowledgements, receives up to
// MaxEvents SETs and processes each with delivery ssf.Poll. Returns how many SETs it received.
func (p *Poller) PollOnce(ctx context.Context) (int, error) {
	_ = ssf.Poll
	return 0, ErrNotImplemented
}

// Start polls in the background until ctx is cancelled or Stop is called.
func (p *Poller) Start(ctx context.Context) {
	ctx, p.cancel = context.WithCancel(ctx)
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		<-ctx.Done()
	}()
}

// Stop ends polling and waits for the loop; it sends the acknowledgements owed first.
func (p *Poller) Stop(ctx context.Context) {
	if p.cancel != nil {
		p.cancel()
		<-p.done
	}
}
