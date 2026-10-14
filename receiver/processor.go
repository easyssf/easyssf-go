package receiver

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// ProcessingOutcome is what happened to a valid SET.
type ProcessingOutcome int

const (
	// Handled: the SET was handled by all handlers.
	Handled ProcessingOutcome = iota + 1
	// Duplicate: the SET was processed before and has been skipped.
	Duplicate
)

// StreamVerificationCheck validates a stream verification event before the handlers see it,
// returning a RejectedError with InvalidState for an unexpected state. Looked up by the issuer
// of the SET; nil for an issuer without a pending verification. See stream.go.
type StreamVerificationCheck func(issuer string) func(event *Context) error

// CriticalSubjectMembers looks up the critical_subject_members a transmitter declares in its
// metadata, by its issuer; empty for an unknown issuer.
type CriticalSubjectMembers func(issuer string) []string

// ProcessorOptions say how a Processor processes SETs beyond verifying, de-duplicating and
// handling them. The zero value is usable.
type ProcessorOptions struct {
	// Metrics records what the processor does. Nothing by default.
	Metrics Metrics
	// Log is where the processor logs; discarded by default.
	Log *slog.Logger
	// StreamVerifications validates stream verification events before the handlers see them.
	// Verification events are accepted unchecked while this is nil.
	StreamVerifications StreamVerificationCheck
	// UnderstoodSubjectMembers are the members of a complex subject the application
	// interprets. A SET whose subject has a member the transmitter declared critical
	// (critical_subject_members of its metadata) that is not among them is rejected as
	// invalid_request, as the SSF specification requires critical members to be interpreted by
	// the receiver. By default the members Subject gives access to, ssf.Members.
	UnderstoodSubjectMembers []string
	// CriticalSubjectMembers are the critical_subject_members a transmitter declares in its
	// metadata, by its issuer. Nothing is critical while this is nil.
	CriticalSubjectMembers CriticalSubjectMembers
	// ClaimRenewal renews the claim of a SET at this interval while its handlers run
	// (JTIDedupStore.Renew), so that a handler that runs longer than the lease of the dedup
	// store does not lose the SET to another instance; a third of the lease is a good
	// interval. 0, the default, turns renewal off: the lease then bounds the handlers. A
	// renewal that finds the claim taken over stops, and the result of the handlers is not
	// recorded, as without renewal after the lease.
	ClaimRenewal time.Duration
}

// Processor processes a received SET independent of how it was delivered: verifies it, skips it
// if it was processed before and hands it to the handlers.
//
// With a JTIDedupStore the SET is claimed while the handlers run. A ClaimRenewal keeps the claim
// alive while a handler runs longer than the store's lease; without it the lease bounds the
// handlers.
type Processor struct {
	verifier Verifier
	dedup    JTIDedupStore
	handlers []Handler
	options  ProcessorOptions
	log      *slog.Logger
	metrics  Metrics
}

// NewProcessor is a processor without handlers; add them with AddHandler. dedup may be nil, the
// processor then processes duplicates.
func NewProcessor(verifier Verifier, dedup JTIDedupStore, options ProcessorOptions) *Processor {
	if options.Metrics == nil {
		options.Metrics = NoopMetrics{}
	}
	if options.UnderstoodSubjectMembers == nil {
		options.UnderstoodSubjectMembers = ssf.Members
	}
	return &Processor{verifier: verifier, dedup: dedup, options: options, log: orDiscard(options.Log), metrics: options.Metrics}
}

// AddHandler adds a handler; every handler is called, in order, for every verified SET.
func (p *Processor) AddHandler(handlers ...Handler) *Processor {
	p.handlers = append(p.handlers, handlers...)
	return p
}

// HandlerCount is the number of handlers.
func (p *Processor) HandlerCount() int { return len(p.handlers) }

// Process verifies and handles the given SET, in JWS compact serialization. It returns a
// RejectedError, a TransmitterUnavailableError, ErrInProgress, a HandlingError or a StoreError.
func (p *Processor) Process(ctx context.Context, encodedSET string, delivery ssf.DeliveryMethod) (ProcessingOutcome, error) {
	unverifiedIssuer := UnverifiedIssuer(encodedSET)
	token, err := p.verify(ctx, encodedSET)
	if err != nil {
		outcome := OutcomeInvalid
		if IsTransmitterUnavailable(err) {
			outcome = OutcomeUnavailable
		}
		p.metrics.SetReceived(unverifiedIssuer, delivery, outcome)
		return 0, err
	}
	issuer := token.Issuer()
	event := NewContext(token, delivery)
	var claim JTIClaim
	if p.dedup != nil {
		claim, err = p.dedup.Claim(ctx, token)
		if err != nil {
			return 0, &StoreError{Cause: err}
		}
		switch claim.State {
		case Processed:
			p.log.Debug("Skipping SET, it was processed before", "jti", token.JTI())
			p.metrics.SetReceived(issuer, delivery, OutcomeDuplicate)
			return Duplicate, nil
		case InProgress:
			p.log.Debug("Leaving SET for a redelivery, another instance is handling it", "jti", token.JTI())
			p.metrics.SetReceived(issuer, delivery, OutcomeInProgress)
			return 0, ErrInProgress
		}
	}
	aliases := make([]string, 0, len(event.EventTypes()))
	for _, eventType := range event.EventTypes() {
		aliases = append(aliases, eventtypes.AliasOf(eventType))
	}
	p.log.Debug("Received SET", "jti", token.JTI(), "delivery", delivery.String(), "events", aliases)
	if event.HasEvent(eventtypes.SSFStreamVerification) {
		p.log.Info("Received stream verification event", "transmitter", issuer)
	}

	renewal := p.startRenewal(ctx, token, claim)
	// every handler runs, also after one failed: a failing handler must not keep the others
	// from reacting to the event
	failed := 0
	var first error
	for _, handler := range p.handlers {
		if err := p.handle(ctx, handler, event); err != nil {
			p.log.Error("An event handler failed", "jti", token.JTI(), "handler", fmt.Sprintf("%T", handler), "error", err)
			failed++
			if first == nil {
				first = err
			}
		}
	}
	// the claim as last renewed; a taken-over one no longer belongs to this instance, so the
	// outcome of the handlers is not recorded
	claim, owned := renewal.stop()

	if first != nil {
		if p.dedup != nil && owned {
			if err := p.dedup.Forget(ctx, token, claim); err != nil {
				return 0, &StoreError{Cause: err}
			}
		}
		p.metrics.SetReceived(issuer, delivery, OutcomeFailed)
		return 0, &HandlingError{Failed: failed, First: first}
	}
	if p.dedup != nil && owned {
		if err := p.dedup.Processed(ctx, token, claim); err != nil {
			return 0, &StoreError{Cause: err}
		}
	}
	p.metrics.SetReceived(issuer, delivery, OutcomeHandled)
	for _, eventType := range event.EventTypes() {
		p.metrics.EventHandled(issuer, eventType, delivery)
	}
	return Handled, nil
}

func (p *Processor) handle(ctx context.Context, handler Handler, event *Context) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("handler panicked: %v", recovered)
		}
	}()
	return handler.Handle(ctx, event)
}

func (p *Processor) verify(ctx context.Context, encodedSET string) (*ssf.EventToken, error) {
	token, err := p.verifier.Verify(ctx, encodedSET)
	if err != nil {
		return nil, err
	}
	event := NewContext(token, ssf.Push)
	if p.options.StreamVerifications != nil {
		if check := p.options.StreamVerifications(token.Issuer()); check != nil {
			if err := check(event); err != nil {
				return nil, err
			}
		}
	}
	return token, p.checkCriticalSubjectMembers(event)
}

func (p *Processor) checkCriticalSubjectMembers(event *Context) error {
	if p.options.CriticalSubjectMembers == nil {
		return nil
	}
	critical := p.options.CriticalSubjectMembers(event.EventToken().Issuer())
	if len(critical) == 0 {
		return nil
	}
	present := event.Subject().MemberNames()
	var notUnderstood []string
	for _, member := range critical {
		if containsString(present, member) && !containsString(p.options.UnderstoodSubjectMembers, member) {
			notUnderstood = append(notUnderstood, member)
		}
	}
	if len(notUnderstood) == 0 {
		return nil
	}
	return Rejected(InvalidRequest, "The subject has the members %v which the transmitter declared critical and this receiver does not understand", notUnderstood)
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// claimRenewal renews a claim in the background while the handlers run.
type claimRenewal struct {
	claim  JTIClaim
	owned  bool
	cancel context.CancelFunc
	done   chan struct{}
}

func (p *Processor) startRenewal(ctx context.Context, token *ssf.EventToken, claim JTIClaim) *claimRenewal {
	renewal := &claimRenewal{claim: claim, owned: claim.IsGranted() || p.dedup == nil}
	if p.dedup == nil || !claim.IsGranted() || p.options.ClaimRenewal <= 0 {
		return renewal
	}
	renewCtx, cancel := context.WithCancel(ctx)
	renewal.cancel = cancel
	renewal.done = make(chan struct{})
	go func() {
		defer close(renewal.done)
		ticker := time.NewTicker(p.options.ClaimRenewal)
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-ticker.C:
				renewed, ok, err := p.dedup.Renew(renewCtx, token, renewal.claim)
				if err != nil {
					p.log.Warn("Could not renew the claim of a SET", "jti", token.JTI(), "error", err)
					continue
				}
				if !ok {
					p.log.Warn("The claim of a SET was taken over by another instance while its handlers ran", "jti", token.JTI())
					renewal.owned = false
					return
				}
				renewal.claim = renewed
			}
		}
	}()
	return renewal
}

// stop ends the renewal and returns the claim as last renewed and whether it is still owned.
func (r *claimRenewal) stop() (JTIClaim, bool) {
	if r.cancel != nil {
		r.cancel()
		<-r.done
	}
	return r.claim, r.owned
}
