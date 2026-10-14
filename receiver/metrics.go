package receiver

import "github.com/easyssf/easyssf-go/ssf"

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

// Metrics records what the receiver does, under the Java names: easyssf.receiver.sets,
// easyssf.receiver.events, easyssf.receiver.poll and easyssf.receiver.poll.pending-acks.
// Implement it over OpenTelemetry or Prometheus; NoopMetrics records nothing.
type Metrics interface {
	// SetReceived counts a received SET by transmitter ("" if unknown), delivery and outcome.
	SetReceived(transmitter string, delivery ssf.DeliveryMethod, outcome SetOutcome)
	// EventHandled counts a handled event by transmitter, event type URI and delivery.
	EventHandled(transmitter, eventType string, delivery ssf.DeliveryMethod)
}

// NoopMetrics records nothing.
type NoopMetrics struct{}

// SetReceived implements Metrics.
func (NoopMetrics) SetReceived(string, ssf.DeliveryMethod, SetOutcome) {}

// EventHandled implements Metrics.
func (NoopMetrics) EventHandled(string, string, ssf.DeliveryMethod) {}
