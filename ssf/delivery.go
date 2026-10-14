package ssf

// DeliveryMethod is how SETs get from the transmitter to the receiver.
type DeliveryMethod int

const (
	// Push: the transmitter sends SETs to an endpoint of the receiver (RFC 8935).
	Push DeliveryMethod = iota + 1
	// Poll: the receiver fetches SETs from an endpoint of the transmitter (RFC 8936).
	Poll
)

const (
	// PushURI identifies push delivery in a stream configuration.
	PushURI = "urn:ietf:rfc:8935"
	// PollURI identifies poll delivery in a stream configuration.
	PollURI = "urn:ietf:rfc:8936"
)

// URI is the identifier of the delivery method in a stream configuration.
func (m DeliveryMethod) URI() string {
	switch m {
	case Push:
		return PushURI
	case Poll:
		return PollURI
	}
	return ""
}

// String is the lowercase name, for logs and metric tags: "push" or "poll".
func (m DeliveryMethod) String() string {
	switch m {
	case Push:
		return "push"
	case Poll:
		return "poll"
	}
	return "unknown"
}

// DeliveryMethodFromURI returns the delivery method with the given identifier; ok is false for
// any other string.
func DeliveryMethodFromURI(uri string) (m DeliveryMethod, ok bool) {
	switch uri {
	case PushURI:
		return Push, true
	case PollURI:
		return Poll, true
	}
	return 0, false
}
