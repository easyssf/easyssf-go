package ssf

import "net/url"

// SpecVersion1_0 is the spec_version of the final SSF 1.0 specification.
const SpecVersion1_0 = "1_0"

// TransmitterMetadata is the transmitter configuration metadata published at
// .well-known/ssf-configuration (SSF 1.0, section 7.1).
type TransmitterMetadata struct {
	issuer  string
	jwksURI *url.URL
	claims  Claims
}

// NewTransmitterMetadata is the metadata of a transmitter: its issuer, the location of its JWK
// Set if any, and all members of the metadata document.
func NewTransmitterMetadata(issuer string, jwksURI *url.URL, claims Claims) *TransmitterMetadata {
	if claims == nil {
		claims = Claims{}
	}
	return &TransmitterMetadata{issuer: issuer, jwksURI: jwksURI, claims: claims}
}

// Issuer is the transmitter issuer.
func (m *TransmitterMetadata) Issuer() string { return m.issuer }

// JWKSURI is the location of the transmitter's JWK Set, nil if the metadata has none.
func (m *TransmitterMetadata) JWKSURI() *url.URL { return m.jwksURI }

// Claims are all members of the metadata document.
func (m *TransmitterMetadata) Claims() Claims { return m.claims }

// SpecVersion is the version of the specification the transmitter implements (spec_version), ""
// if the transmitter does not say.
func (m *TransmitterMetadata) SpecVersion() string { return StringMember(m.claims, "spec_version") }

// DeliveryMethodsSupported are the delivery method URIs the transmitter supports
// (delivery_methods_supported), empty if the transmitter does not say.
func (m *TransmitterMetadata) DeliveryMethodsSupported() []string {
	return Strings(m.claims["delivery_methods_supported"])
}

// SupportsDeliveryMethod reports whether the transmitter supports the delivery method; true as
// well if it does not say which methods it supports.
func (m *TransmitterMetadata) SupportsDeliveryMethod(method DeliveryMethod) bool {
	supported := m.DeliveryMethodsSupported()
	if len(supported) == 0 {
		return true
	}
	for _, uri := range supported {
		if uri == method.URI() {
			return true
		}
	}
	return false
}

// CriticalSubjectMembers are the members of a complex subject the transmitter requires to be
// understood (critical_subject_members), empty if none.
func (m *TransmitterMetadata) CriticalSubjectMembers() []string {
	return Strings(m.claims["critical_subject_members"])
}

// AuthorizationSchemes are the authorization schemes of the management endpoints
// (authorization_schemes), each with a spec_urn, empty if the transmitter does not say.
func (m *TransmitterMetadata) AuthorizationSchemes() []Claims {
	array, _ := m.claims["authorization_schemes"].([]any)
	var schemes []Claims
	for _, element := range array {
		if scheme := Object(element); scheme != nil {
			schemes = append(schemes, scheme)
		}
	}
	return schemes
}

// DefaultSubjects is which subjects a stream receives events for by default (default_subjects):
// ALL or NONE, "" if the transmitter does not say.
func (m *TransmitterMetadata) DefaultSubjects() string {
	return StringMember(m.claims, "default_subjects")
}

// ConfigurationEndpoint is the endpoint to create, read, update and delete streams.
func (m *TransmitterMetadata) ConfigurationEndpoint() *url.URL {
	return m.url("configuration_endpoint")
}

// StatusEndpoint is the endpoint to read and update the status of a stream.
func (m *TransmitterMetadata) StatusEndpoint() *url.URL { return m.url("status_endpoint") }

// AddSubjectEndpoint is the endpoint to add subjects to a stream.
func (m *TransmitterMetadata) AddSubjectEndpoint() *url.URL { return m.url("add_subject_endpoint") }

// RemoveSubjectEndpoint is the endpoint to remove subjects from a stream.
func (m *TransmitterMetadata) RemoveSubjectEndpoint() *url.URL {
	return m.url("remove_subject_endpoint")
}

// VerificationEndpoint is the endpoint to request a verification event.
func (m *TransmitterMetadata) VerificationEndpoint() *url.URL { return m.url("verification_endpoint") }

func (m *TransmitterMetadata) url(name string) *url.URL {
	value := StringMember(m.claims, name)
	if value == "" {
		return nil
	}
	u, err := url.Parse(value)
	if err != nil {
		return nil
	}
	return u
}
