// Package scim holds SCIM Events (RFC 9967): the operations, the scim subject (a SCIM resource
// named by its uri, id and externalId) and typed access to the attributes and data members of
// the payload. A port of scim.rs of the Rust port and of org.easyssf.core.scim.
package scim

import (
	"sort"
	"strings"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

// Operation is what a SCIM Event (RFC 9967) reports, independent of whether its payload carries
// the resource (full) or only names the attributes that changed (notice). The specification may
// add operations; do not switch over them exhaustively.
type Operation int

const (
	// Unknown is not a SCIM Event.
	Unknown Operation = iota
	// FeedAdd: the resource joined the event feed (section 2.3.1), it is not necessarily new.
	FeedAdd
	// FeedRemove: the resource left the event feed (section 2.3.2), it was not necessarily
	// deleted.
	FeedRemove
	// Create: the resource was created (section 2.4.1).
	Create
	// Patch: the resource was modified with SCIM PATCH (section 2.4.2).
	Patch
	// Put: the resource was replaced with SCIM PUT (section 2.4.3).
	Put
	// Delete: the resource was deleted, and thereby removed from the feed (section 2.4.4).
	Delete
	// Activate: the resource was activated, for example its account may be logged in to
	// (section 2.4.5).
	Activate
	// Deactivate: the resource was deactivated, typically its user may no longer have an active
	// session (section 2.4.6).
	Deactivate
	// AsyncResponse: an asynchronous SCIM request completed (section 2.5.1.3).
	AsyncResponse
)

// Known are the operations and the event type URIs that report them.
var Known = []struct {
	Operation Operation
	EventType string
}{
	{FeedAdd, eventtypes.ScimFeedAdd},
	{FeedRemove, eventtypes.ScimFeedRemove},
	{Create, eventtypes.ScimProvCreateNotice},
	{Create, eventtypes.ScimProvCreateFull},
	{Patch, eventtypes.ScimProvPatchNotice},
	{Patch, eventtypes.ScimProvPatchFull},
	{Put, eventtypes.ScimProvPutNotice},
	{Put, eventtypes.ScimProvPutFull},
	{Delete, eventtypes.ScimProvDelete},
	{Activate, eventtypes.ScimProvActivate},
	{Deactivate, eventtypes.ScimProvDeactivate},
	{AsyncResponse, eventtypes.ScimMiscAsyncResponse},
}

var names = map[Operation]string{
	FeedAdd: "FeedAdd", FeedRemove: "FeedRemove", Create: "Create", Patch: "Patch", Put: "Put", Delete: "Delete",
	Activate: "Activate", Deactivate: "Deactivate", AsyncResponse: "AsyncResponse",
}

// String is the name of the operation: FeedAdd, Create, ..., Unknown.
func (o Operation) String() string {
	if name, ok := names[o]; ok {
		return name
	}
	return "Unknown"
}

// EventTypes are the event type URIs that report this operation, one or, for the provisioning
// operations with a notice and a full variant, two.
func (o Operation) EventTypes() []string {
	var uris []string
	for _, known := range Known {
		if known.Operation == o {
			uris = append(uris, known.EventType)
		}
	}
	return uris
}

// IsProvisioning reports whether this is one of the provisioning operations of section 2.4,
// which report a change of the resource at the SCIM service provider.
func (o Operation) IsProvisioning() bool {
	return o != Unknown && o != FeedAdd && o != FeedRemove && o != AsyncResponse
}

// OperationOf is the operation an event type URI or alias reports, Unknown if it is not a SCIM
// Event.
func OperationOf(eventType string) Operation {
	uri := eventtypes.Resolve(eventType)
	for _, known := range Known {
		if known.EventType == uri {
			return known.Operation
		}
	}
	return Unknown
}

// IsScimEvent reports whether the event type is one of SCIM Events.
func IsScimEvent(eventType string) bool { return OperationOf(eventType) != Unknown }

// Subject is the subject of a SCIM Event (RFC 9967, section 2.1): a SCIM resource named by a
// scim subject identifier. The identifier carries the relative uri of the resource (its resource
// type endpoint plus its id, for example /Users/2b2f880af6674ac284bae9381673d462), the
// externalId and id of the resource if known, and possibly further attributes of the resource
// that are unique at the SCIM service provider, such as userName.
type Subject struct {
	identifier *ssf.SubjectIdentifier
}

// SubjectFromIdentifier is the SCIM subject of an identifier, nil if the identifier is nil or not
// of format scim.
func SubjectFromIdentifier(identifier *ssf.SubjectIdentifier) *Subject {
	if identifier == nil || !identifier.IsSCIM() {
		return nil
	}
	return &Subject{identifier: identifier}
}

// SubjectOf is the SCIM subject of a SET's subject, nil if the subject is not a scim identifier
// (nor a complex subject whose user is one).
func SubjectOf(subject *ssf.Subject) *Subject {
	if subject == nil {
		return nil
	}
	return SubjectFromIdentifier(subject.UserIdentifier())
}

// Identifier is the scim subject identifier as received.
func (s *Subject) Identifier() *ssf.SubjectIdentifier { return s.identifier }

// URI is the relative path of the resource at the SCIM service provider, which RFC 9967
// requires; "" if the transmitter left it out nevertheless.
func (s *Subject) URI() string { return s.identifier.Claim("uri") }

// ResourceType is the resource type endpoint of the URI, for example Users or Groups; "" if the
// uri has no such segment.
func (s *Subject) ResourceType() string {
	segments := s.segments()
	if len(segments) < 2 {
		return ""
	}
	return segments[len(segments)-2]
}

// ID is the id of the resource: the id attribute of the identifier or, if absent, the last
// segment of the URI; "" if there is neither.
func (s *Subject) ID() string {
	if id := s.identifier.Claim("id"); id != "" {
		return id
	}
	segments := s.segments()
	if len(segments) == 0 {
		return ""
	}
	return segments[len(segments)-1]
}

// ExternalID is the externalId of the resource, the identifier the receiver's domain knows it
// by; "" if absent.
func (s *Subject) ExternalID() string { return s.identifier.Claim("externalId") }

// Attribute is a further attribute of the identifier, such as userName; "" if absent or not a
// non-empty string.
func (s *Subject) Attribute(name string) string { return s.identifier.Claim(name) }

// Claims are all members of the identifier as received, including format.
func (s *Subject) Claims() ssf.Claims { return s.identifier.Claims() }

func (s *Subject) segments() []string {
	uri := s.URI()
	if uri == "" {
		return nil
	}
	path, _, _ := strings.Cut(uri, "?")
	var segments []string
	for _, segment := range strings.Split(path, "/") {
		if segment != "" {
			segments = append(segments, segment)
		}
	}
	return segments
}

// Event is a SCIM Event (RFC 9967) of a SET, with typed access to the common payload attributes
// of section 2.2: the resource as data in full mode, the modified attributes in notice mode, and
// the ETag version of the resource after the event. The txn that groups the SETs of one
// transaction is a claim of the ssf.EventToken.
//
// A SET may carry several SCIM Events; RFC 9967 then has them arise from the same change of the
// same resource, so they share the Subject.
type Event struct {
	eventType string
	operation Operation
	subject   *Subject
	payload   ssf.Claims
}

// Of is the event with the given type (URI or alias), the SCIM subject of the SET (nil if it has
// none) and the payload; nil if the type is not one of SCIM Events.
func Of(eventType string, subject *Subject, payload ssf.Claims) *Event {
	operation := OperationOf(eventType)
	if operation == Unknown {
		return nil
	}
	if payload == nil {
		payload = ssf.Claims{}
	}
	return &Event{eventType: eventtypes.Resolve(eventType), operation: operation, subject: subject, payload: payload}
}

// InToken are the SCIM Events of a SET, in the order of their event type URIs.
func InToken(token *ssf.EventToken) []*Event {
	subject := SubjectOf(ssf.SubjectFrom(token.SubjectID()))
	keys := make([]string, 0, len(token.Events()))
	for key := range token.Events() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var events []*Event
	for _, eventType := range keys {
		if event := Of(eventType, subject, ssf.Object(token.Events()[eventType])); event != nil {
			events = append(events, event)
		}
	}
	return events
}

// EventType is the event type URI.
func (e *Event) EventType() string { return e.eventType }

// Operation is what the event reports.
func (e *Event) Operation() Operation { return e.operation }

// Subject is the SCIM resource the event is about, nil if the sub_id of the SET is not a scim
// subject identifier (which RFC 9967 requires, but a handler should expect).
func (e *Event) Subject() *Subject { return e.subject }

// Payload is the event payload as received.
func (e *Event) Payload() ssf.Claims { return e.payload }

// IsFull reports whether the payload carries the resource as Data: the event type ends in
// :full.
func (e *Event) IsFull() bool { return strings.HasSuffix(e.eventType, ":full") }

// IsNotice reports whether the payload only names the modified Attributes: the event type ends
// in :notice. A receiver may fetch the resource from the SCIM service provider with a GET of the
// subject's uri.
func (e *Event) IsNotice() bool { return strings.HasSuffix(e.eventType, ":notice") }

// Data is the data of a full event: the representation of the created or replaced resource, or
// the PatchOp applied; nil if absent.
func (e *Event) Data() ssf.Claims { return ssf.ObjectMember(e.payload, "data") }

// Attributes are the attributes of a notice event: the paths of the attributes created,
// modified or removed; empty if absent.
func (e *Event) Attributes() []string { return ssf.Strings(e.payload["attributes"]) }

// Version is the ETag version of the resource after the event.
func (e *Event) Version() string { return ssf.StringMember(e.payload, "version") }

// Method is the HTTP method of the request an AsyncResponse reports on, "" for other events.
func (e *Event) Method() string { return ssf.StringMember(e.payload, "method") }

// Status is the HTTP status of the request an AsyncResponse reports on, as a string like the
// SCIM bulk response has it; "" for other events.
func (e *Event) Status() string { return ssf.StringMember(e.payload, "status") }

// Response is the SCIM error response of a failed request an AsyncResponse reports on, with
// scimType and detail; nil if the request succeeded or for other events.
func (e *Event) Response() ssf.Claims { return ssf.ObjectMember(e.payload, "response") }
