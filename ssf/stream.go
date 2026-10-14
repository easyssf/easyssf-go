package ssf

import (
	"net/url"

	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// StreamConfiguration is the configuration of an event stream (SSF 1.0, section 8.1.1), as sent
// to and returned by the transmitter.
type StreamConfiguration struct {
	claims Claims
}

// NewStreamConfiguration is a stream configuration with the given members.
func NewStreamConfiguration(claims Claims) *StreamConfiguration {
	if claims == nil {
		claims = Claims{}
	}
	return &StreamConfiguration{claims: claims}
}

// PushStream is a stream the transmitter pushes events to. endpointURL is the push endpoint of
// the receiver as the transmitter reaches it, authorizationHeader the Authorization header the
// transmitter has to send ("" for none), eventsRequested the requested event types (alias or
// URI), description optional.
func PushStream(endpointURL *url.URL, authorizationHeader string, eventsRequested []string, description string) *StreamConfiguration {
	delivery := Claims{"method": PushURI, "endpoint_url": endpointURL.String()}
	if authorizationHeader != "" {
		delivery["authorization_header"] = authorizationHeader
	}
	return newStream(delivery, eventsRequested, description)
}

// PollStream is a stream the receiver polls events from.
func PollStream(eventsRequested []string, description string) *StreamConfiguration {
	return newStream(Claims{"method": PollURI}, eventsRequested, description)
}

func newStream(delivery Claims, eventsRequested []string, description string) *StreamConfiguration {
	requested := make([]any, 0, len(eventsRequested))
	for _, event := range eventsRequested {
		requested = append(requested, eventtypes.Resolve(event))
	}
	claims := Claims{"delivery": delivery, "events_requested": requested}
	if description != "" {
		claims["description"] = description
	}
	return &StreamConfiguration{claims: claims}
}

// Claims are the members of the stream configuration.
func (s *StreamConfiguration) Claims() Claims { return s.claims }

// StreamID is the stream_id, "" if the transmitter has not assigned one.
func (s *StreamConfiguration) StreamID() string { return StringMember(s.claims, "stream_id") }

// Issuer is the iss, the issuer of the SETs of this stream.
func (s *StreamConfiguration) Issuer() string { return StringMember(s.claims, "iss") }

// Audience is the audiences of the SETs of this stream, empty if unknown.
func (s *StreamConfiguration) Audience() []string { return Audiences(s.claims["aud"]) }

// EventsSupported are the events_supported of the transmitter.
func (s *StreamConfiguration) EventsSupported() []string {
	return Strings(s.claims["events_supported"])
}

// EventsRequested are the events_requested by the receiver.
func (s *StreamConfiguration) EventsRequested() []string {
	return Strings(s.claims["events_requested"])
}

// EventsDelivered are the events_delivered on this stream.
func (s *StreamConfiguration) EventsDelivered() []string {
	return Strings(s.claims["events_delivered"])
}

// Description is the description.
func (s *StreamConfiguration) Description() string { return StringMember(s.claims, "description") }

// DeliveryMethodURI is the identifier of the delivery method, see DeliveryMethod.URI.
func (s *StreamConfiguration) DeliveryMethodURI() string {
	return StringMember(ObjectMember(s.claims, "delivery"), "method")
}

// DeliveryEndpointURL is the push endpoint of the receiver or the poll endpoint of the
// transmitter, nil if absent or malformed.
func (s *StreamConfiguration) DeliveryEndpointURL() *url.URL {
	value := StringMember(ObjectMember(s.claims, "delivery"), "endpoint_url")
	if value == "" {
		return nil
	}
	u, err := url.Parse(value)
	if err != nil {
		return nil
	}
	return u
}

// Stream statuses (SSF 1.0, section 8.1.2).
const (
	// StreamEnabled: the stream delivers events.
	StreamEnabled = "enabled"
	// StreamPaused: the stream holds events back and delivers them when enabled again.
	StreamPaused = "paused"
	// StreamDisabled: the stream delivers no events and drops them.
	StreamDisabled = "disabled"
)

// StreamStatus is the status of an event stream (SSF 1.0, section 8.1.2).
type StreamStatus struct {
	// StreamID is the identifier of the stream.
	StreamID string
	// Status is enabled, paused or disabled.
	Status string
	// Reason is why the stream has that status, "" if the transmitter gave none.
	Reason string
}
