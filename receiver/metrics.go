package receiver

import (
	"time"

	"github.com/easyssf/easyssf-go/ssf"
)

// SetOutcome is what happened to a received SET, the tag of the easyssf.receiver.sets metric.
type SetOutcome string

const (
	OutcomeHandled         SetOutcome = "handled"
	OutcomeDuplicate       SetOutcome = "duplicate"
	OutcomeInProgress      SetOutcome = "in-progress"
	OutcomeInvalid         SetOutcome = "invalid"
	OutcomeUnavailable     SetOutcome = "unavailable"
	OutcomeFailed          SetOutcome = "failed"
	OutcomeUnauthenticated SetOutcome = "unauthenticated"
)

// Metrics records what the receiver does, under the Java names: easyssf.receiver.sets (a
// counter of received SETs by transmitter, delivery and outcome), easyssf.receiver.events (a
// counter of handled events by transmitter, event type and delivery), easyssf.receiver.poll (a
// histogram of the duration of poll requests by transmitter and outcome) and
// easyssf.receiver.poll.pending-acks (a gauge of the acknowledgements a poller owes).
// Implement it over OpenTelemetry or Prometheus, embedding NoopMetrics for the methods you do
// not record; NoopMetrics records nothing.
type Metrics interface {
	// SetReceived counts a received SET by transmitter ("" if unknown), delivery and outcome.
	SetReceived(transmitter string, delivery ssf.DeliveryMethod, outcome SetOutcome)
	// EventHandled counts a handled event by transmitter, event type URI and delivery.
	EventHandled(transmitter, eventType string, delivery ssf.DeliveryMethod)
	// PollCompleted records a poll request to the transmitter and whether it answered it.
	PollCompleted(transmitter string, duration time.Duration, success bool)
	// PendingAcksChanged records the number of acknowledgements and error reports a poller owes
	// its transmitter, for a gauge.
	PendingAcksChanged(transmitter string, pendingAcks int)
}

// NoopMetrics records nothing. Embed it in a Metrics implementation to record only some of the
// metrics.
type NoopMetrics struct{}

// SetReceived implements Metrics.
func (NoopMetrics) SetReceived(string, ssf.DeliveryMethod, SetOutcome) {}

// EventHandled implements Metrics.
func (NoopMetrics) EventHandled(string, string, ssf.DeliveryMethod) {}

// PollCompleted implements Metrics.
func (NoopMetrics) PollCompleted(string, time.Duration, bool) {}

// PendingAcksChanged implements Metrics.
func (NoopMetrics) PendingAcksChanged(string, int) {}
