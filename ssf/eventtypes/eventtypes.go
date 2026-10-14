// Package eventtypes holds the event type URIs defined by OpenID SSF, CAEP and RISC, and by
// SCIM Events (RFC 9967), together with short aliases (for example CaepSessionRevoked) that can
// be used wherever an event type is expected.
//
// Event types are identified by their URIs; the aliases are a convenience of easyssf, the family
// and the event name in PascalCase. Both forms are accepted wherever an event type is named;
// Resolve goes from one to the other. Vendor specific event types get aliases of their own with
// RegisterAlias.
package eventtypes

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

const (
	ssfNamespace  = "https://schemas.openid.net/secevent/ssf/event-type/"
	caepNamespace = "https://schemas.openid.net/secevent/caep/event-type/"
	riscNamespace = "https://schemas.openid.net/secevent/risc/event-type/"
	scimNamespace = "urn:ietf:params:scim:event:"
)

// The event types of SSF 1.0 (section 8.1.4), CAEP 1.0 (section 3), RISC 1.0 (section 2) and
// SCIM Events (RFC 9967).
const (
	// SSFStreamVerification: SSF 1.0, section 8.1.4.1, the stream verification event.
	SSFStreamVerification = ssfNamespace + "verification"
	// SSFStreamUpdated: SSF 1.0, section 8.1.4.2, the stream was updated.
	SSFStreamUpdated = ssfNamespace + "stream-updated"

	CaepSessionRevoked         = caepNamespace + "session-revoked"          // CAEP 1.0, 3.1
	CaepTokenClaimsChange      = caepNamespace + "token-claims-change"      // CAEP 1.0, 3.2
	CaepCredentialChange       = caepNamespace + "credential-change"        // CAEP 1.0, 3.3
	CaepAssuranceLevelChange   = caepNamespace + "assurance-level-change"   // CAEP 1.0, 3.4
	CaepDeviceComplianceChange = caepNamespace + "device-compliance-change" // CAEP 1.0, 3.5
	CaepSessionEstablished     = caepNamespace + "session-established"      // CAEP 1.0, 3.6
	CaepSessionPresented       = caepNamespace + "session-presented"        // CAEP 1.0, 3.7
	CaepRiskLevelChange        = caepNamespace + "risk-level-change"        // CAEP 1.0, 3.8

	RiscAccountCredentialChangeRequired = riscNamespace + "account-credential-change-required" // RISC 1.0, 2.1
	RiscAccountPurged                   = riscNamespace + "account-purged"                     // RISC 1.0, 2.2
	RiscAccountDisabled                 = riscNamespace + "account-disabled"                   // RISC 1.0, 2.3
	RiscAccountEnabled                  = riscNamespace + "account-enabled"                    // RISC 1.0, 2.4
	RiscIdentifierChanged               = riscNamespace + "identifier-changed"                 // RISC 1.0, 2.5
	RiscIdentifierRecycled              = riscNamespace + "identifier-recycled"                // RISC 1.0, 2.6
	RiscCredentialCompromise            = riscNamespace + "credential-compromise"              // RISC 1.0, 2.7
	RiscOptIn                           = riscNamespace + "opt-in"                             // RISC 1.0, 2.8.1
	RiscOptOutInitiated                 = riscNamespace + "opt-out-initiated"                  // RISC 1.0, 2.8.2
	RiscOptOutCancelled                 = riscNamespace + "opt-out-cancelled"                  // RISC 1.0, 2.8.3
	RiscOptOutEffective                 = riscNamespace + "opt-out-effective"                  // RISC 1.0, 2.8.4
	RiscRecoveryActivated               = riscNamespace + "recovery-activated"                 // RISC 1.0, 2.9
	RiscRecoveryInformationChanged      = riscNamespace + "recovery-information-changed"       // RISC 1.0, 2.10
	// RiscSessionsRevoked: all sessions of the account were revoked (RISC 1.0, section 2.11).
	// Deprecated by RISC in favour of CaepSessionRevoked, but still emitted by some transmitters.
	RiscSessionsRevoked = riscNamespace + "sessions-revoked"

	ScimFeedAdd           = scimNamespace + "feed:add"           // RFC 9967, 2.3.1
	ScimFeedRemove        = scimNamespace + "feed:remove"        // RFC 9967, 2.3.2
	ScimProvCreateNotice  = scimNamespace + "prov:create:notice" // RFC 9967, 2.4.1
	ScimProvCreateFull    = scimNamespace + "prov:create:full"   // RFC 9967, 2.4.1
	ScimProvPatchNotice   = scimNamespace + "prov:patch:notice"  // RFC 9967, 2.4.2
	ScimProvPatchFull     = scimNamespace + "prov:patch:full"    // RFC 9967, 2.4.2
	ScimProvPutNotice     = scimNamespace + "prov:put:notice"    // RFC 9967, 2.4.3
	ScimProvPutFull       = scimNamespace + "prov:put:full"      // RFC 9967, 2.4.3
	ScimProvDelete        = scimNamespace + "prov:delete"        // RFC 9967, 2.4.4
	ScimProvActivate      = scimNamespace + "prov:activate"      // RFC 9967, 2.4.5
	ScimProvDeactivate    = scimNamespace + "prov:deactivate"    // RFC 9967, 2.4.6
	ScimMiscAsyncResponse = scimNamespace + "misc:asyncresp"     // RFC 9967, 2.5.1.3
)

var builtIn = [][2]string{
	{"SsfStreamVerification", SSFStreamVerification},
	{"SsfStreamUpdated", SSFStreamUpdated},
	{"CaepSessionRevoked", CaepSessionRevoked},
	{"CaepTokenClaimsChange", CaepTokenClaimsChange},
	{"CaepCredentialChange", CaepCredentialChange},
	{"CaepAssuranceLevelChange", CaepAssuranceLevelChange},
	{"CaepDeviceComplianceChange", CaepDeviceComplianceChange},
	{"CaepSessionEstablished", CaepSessionEstablished},
	{"CaepSessionPresented", CaepSessionPresented},
	{"CaepRiskLevelChange", CaepRiskLevelChange},
	{"RiscAccountCredentialChangeRequired", RiscAccountCredentialChangeRequired},
	{"RiscAccountPurged", RiscAccountPurged},
	{"RiscAccountDisabled", RiscAccountDisabled},
	{"RiscAccountEnabled", RiscAccountEnabled},
	{"RiscIdentifierChanged", RiscIdentifierChanged},
	{"RiscIdentifierRecycled", RiscIdentifierRecycled},
	{"RiscCredentialCompromise", RiscCredentialCompromise},
	{"RiscOptIn", RiscOptIn},
	{"RiscOptOutInitiated", RiscOptOutInitiated},
	{"RiscOptOutCancelled", RiscOptOutCancelled},
	{"RiscOptOutEffective", RiscOptOutEffective},
	{"RiscRecoveryActivated", RiscRecoveryActivated},
	{"RiscRecoveryInformationChanged", RiscRecoveryInformationChanged},
	{"RiscSessionsRevoked", RiscSessionsRevoked},
	{"ScimFeedAdd", ScimFeedAdd},
	{"ScimFeedRemove", ScimFeedRemove},
	{"ScimProvCreateNotice", ScimProvCreateNotice},
	{"ScimProvCreateFull", ScimProvCreateFull},
	{"ScimProvPatchNotice", ScimProvPatchNotice},
	{"ScimProvPatchFull", ScimProvPatchFull},
	{"ScimProvPutNotice", ScimProvPutNotice},
	{"ScimProvPutFull", ScimProvPutFull},
	{"ScimProvDelete", ScimProvDelete},
	{"ScimProvActivate", ScimProvActivate},
	{"ScimProvDeactivate", ScimProvDeactivate},
	{"ScimMiscAsyncResponse", ScimMiscAsyncResponse},
}

var registry = struct {
	sync.RWMutex
	uriByAlias map[string]string
	aliasByURI map[string]string
}{
	uriByAlias: map[string]string{},
	aliasByURI: map[string]string{},
}

func init() {
	for _, pair := range builtIn {
		registry.uriByAlias[pair[0]] = pair[1]
		registry.aliasByURI[pair[1]] = pair[0]
	}
}

// RegisterAlias registers an alias for an event type URI, for example of a vendor specific event
// type, so that it can be used wherever an event type is named: in handlers, in the events
// requested of a stream, in configuration. Aliases are a convenience of easyssf, the URIs stay
// the canonical names.
//
// Aliases do not conflict: an alias cannot be redefined to another URI, neither a built-in one
// nor one registered before. A URI may have several aliases; the first one registered is the one
// AliasOf returns. Registering a mapping that exists already does nothing.
//
// It fails if the alias is not a name without ':' or '/', the URI is not an absolute URI, or the
// alias is already mapped to another URI.
func RegisterAlias(alias, uri string) error {
	if strings.TrimSpace(alias) == "" || strings.ContainsAny(alias, ":/") || alias != strings.TrimSpace(alias) {
		return fmt.Errorf("an event type alias must be a name without ':' or '/' and surrounding whitespace: %q", alias)
	}
	if strings.TrimSpace(uri) == "" || !strings.Contains(uri, ":") || uri != strings.TrimSpace(uri) {
		return fmt.Errorf("an event type must be an absolute URI: %q", uri)
	}
	registry.Lock()
	defer registry.Unlock()
	if existing, ok := registry.uriByAlias[alias]; ok && existing != uri {
		return fmt.Errorf("the event type alias %q is already mapped to %s, not to %s", alias, existing, uri)
	}
	registry.uriByAlias[alias] = uri
	if _, ok := registry.aliasByURI[uri]; !ok {
		registry.aliasByURI[uri] = alias
	}
	return nil
}

// Aliases are the known aliases and their event type URIs, built-in and registered, sorted by
// alias.
func Aliases() [][2]string {
	registry.RLock()
	defer registry.RUnlock()
	aliases := make([][2]string, 0, len(registry.uriByAlias))
	for alias, uri := range registry.uriByAlias {
		aliases = append(aliases, [2]string{alias, uri})
	}
	sort.Slice(aliases, func(i, j int) bool { return aliases[i][0] < aliases[j][0] })
	return aliases
}

// IsAlias reports whether the name is a known alias.
func IsAlias(name string) bool {
	registry.RLock()
	defer registry.RUnlock()
	_, ok := registry.uriByAlias[name]
	return ok
}

// IsCaepEvent reports whether the event type is in the CAEP namespace, one of the events of CAEP
// 1.0 or a later one.
func IsCaepEvent(aliasOrURI string) bool {
	return strings.HasPrefix(Resolve(aliasOrURI), caepNamespace)
}

// IsRiscEvent reports whether the event type is in the RISC namespace, one of the events of RISC
// 1.0 or a later one.
func IsRiscEvent(aliasOrURI string) bool {
	return strings.HasPrefix(Resolve(aliasOrURI), riscNamespace)
}

// IsSSFEvent reports whether the event type is in the SSF namespace, a stream management event.
func IsSSFEvent(aliasOrURI string) bool { return strings.HasPrefix(Resolve(aliasOrURI), ssfNamespace) }

// IsScimEvent reports whether the event type is one of SCIM Events (RFC 9967).
func IsScimEvent(aliasOrURI string) bool {
	return strings.HasPrefix(Resolve(aliasOrURI), scimNamespace)
}

// Resolve resolves an alias to its event type URI. Anything that is not a known alias is returned
// unchanged, so full URIs (including vendor specific ones) pass through.
func Resolve(aliasOrURI string) string {
	registry.RLock()
	defer registry.RUnlock()
	if uri, ok := registry.uriByAlias[aliasOrURI]; ok {
		return uri
	}
	return aliasOrURI
}

// AliasOf returns the alias of the given event type URI, or the URI itself if it has none.
func AliasOf(eventTypeURI string) string {
	registry.RLock()
	defer registry.RUnlock()
	if alias, ok := registry.aliasByURI[eventTypeURI]; ok {
		return alias
	}
	return eventTypeURI
}
