package ssf

import "sort"

// Subject identifier formats of RFC 9493 and the scim format of SCIM Events (RFC 9967).
const (
	// FormatAccount: an acct: URI (RFC 7565).
	FormatAccount = "account"
	// FormatEmail: an email address.
	FormatEmail = "email"
	// FormatIssSub: an issuer and the subject at that issuer.
	FormatIssSub = "iss_sub"
	// FormatOpaque: an identifier that does not tell what it names.
	FormatOpaque = "opaque"
	// FormatPhoneNumber: E.164.
	FormatPhoneNumber = "phone_number"
	// FormatDID: a decentralized identifier.
	FormatDID = "did"
	// FormatURI: a URI.
	FormatURI = "uri"
	// FormatAliases: several identifiers that name the same subject.
	FormatAliases = "aliases"
	// FormatSCIM is the format of SCIM Events (RFC 9967, section 2.1): a SCIM resource named by
	// its relative uri, with its externalId and id if known.
	FormatSCIM = "scim"
	// FormatComplex marks a complex subject (SSF 1.0, section 5).
	FormatComplex = "complex"
)

// The members of a complex subject (SSF 1.0, section 5).
const (
	MemberUser        = "user"
	MemberSession     = "session"
	MemberDevice      = "device"
	MemberApplication = "application"
	MemberTenant      = "tenant"
	MemberOrgUnit     = "org_unit"
	MemberGroup       = "group"
)

// Members lists the members of a complex subject Subject gives access to, in the order of the
// SSF specification.
var Members = []string{
	MemberUser, MemberSession, MemberDevice, MemberApplication, MemberTenant, MemberOrgUnit, MemberGroup,
}

// AllSessions is the session identifier Keycloak uses to refer to all sessions of a user.
const AllSessions = "ALL"

// SubjectIdentifier is a subject identifier (RFC 9493): a format and the members that format
// defines. Any format is represented, the ones of RFC 9493 and the scim format are known by name.
type SubjectIdentifier struct {
	format string
	claims Claims
}

// SubjectIdentifierFrom reads an identifier. Lenient: nil if it has no non-empty string format.
func SubjectIdentifierFrom(identifier Claims) *SubjectIdentifier {
	format := StringMember(identifier, "format")
	if format == "" {
		return nil
	}
	return &SubjectIdentifier{format: format, claims: identifier}
}

// Format is the format, never empty.
func (i *SubjectIdentifier) Format() string { return i.format }

// Claims are the members of the identifier as received, including format.
func (i *SubjectIdentifier) Claims() Claims { return i.claims }

// Is reports whether the identifier has the given format.
func (i *SubjectIdentifier) Is(format string) bool { return i.format == format }

// IsIssSub reports whether the format is iss_sub.
func (i *SubjectIdentifier) IsIssSub() bool { return i.Is(FormatIssSub) }

// IsEmail reports whether the format is email.
func (i *SubjectIdentifier) IsEmail() bool { return i.Is(FormatEmail) }

// IsOpaque reports whether the format is opaque.
func (i *SubjectIdentifier) IsOpaque() bool { return i.Is(FormatOpaque) }

// IsSCIM reports whether the format is scim.
func (i *SubjectIdentifier) IsSCIM() bool { return i.Is(FormatSCIM) }

// Claim is a member of the identifier, "" if absent or not a non-empty string.
func (i *SubjectIdentifier) Claim(name string) string { return StringMember(i.claims, name) }

// Issuer is the issuer of an iss_sub identifier, "" for other formats.
func (i *SubjectIdentifier) Issuer() string {
	if i.IsIssSub() {
		return i.Claim("iss")
	}
	return ""
}

// Value is the member that identifies the subject within its format: sub of iss_sub, email, id
// of opaque, uri of account, uri and scim, phone_number, url of did. "" for aliases and unknown
// formats.
func (i *SubjectIdentifier) Value() string {
	switch i.format {
	case FormatIssSub:
		return i.Claim("sub")
	case FormatEmail:
		return i.Claim("email")
	case FormatOpaque:
		return i.Claim("id")
	case FormatAccount, FormatURI, FormatSCIM:
		return i.Claim("uri")
	case FormatPhoneNumber:
		return i.Claim("phone_number")
	case FormatDID:
		return i.Claim("url")
	}
	return ""
}

// Aliases are the identifiers of an aliases identifier, nil for other formats.
func (i *SubjectIdentifier) Aliases() []*SubjectIdentifier {
	if !i.Is(FormatAliases) {
		return nil
	}
	identifiers, _ := i.claims["identifiers"].([]any)
	var aliases []*SubjectIdentifier
	for _, element := range identifiers {
		if alias := SubjectIdentifierFrom(Object(element)); alias != nil {
			aliases = append(aliases, alias)
		}
	}
	return aliases
}

// member is a named member of a complex subject.
type member struct {
	name       string
	identifier *SubjectIdentifier
}

// Subject is the subject of a SET (its sub_id claim): a simple subject identifier (RFC 9493), or
// a complex subject whose members (user, session, device, tenant, ...) are identifiers.
//
// UserIdentifier and Session are the two members the receiver acts on, and Issuer, Sub,
// SessionID, Email and OpaqueID are shortcuts to their most common values. Everything else is
// available through Member and Raw.
//
// Keycloak reports the revocation of all sessions of a user with a session member whose
// identifier is AllSessions. Such a subject is resolved like one that names only the user: it
// has no session.
//
// The zero value is the subject of a SET that carried none.
type Subject struct {
	raw        Claims
	identifier *SubjectIdentifier
	members    []member
}

// EmptySubject is the subject of a SET that carried none.
func EmptySubject() *Subject { return &Subject{} }

// SubjectFrom resolves the given sub_id claim; lenient, empty for nil or an empty object.
func SubjectFrom(subjectID Claims) *Subject {
	if len(subjectID) == 0 {
		return EmptySubject()
	}
	format, hasFormat := subjectID["format"].(string)
	// Early SSF drafts used complex subjects without a format member
	complex := format == FormatComplex || (!hasFormat && hasObjectMembers(subjectID))
	if !complex {
		return &Subject{raw: subjectID, identifier: SubjectIdentifierFrom(subjectID)}
	}
	var members []member
	for _, name := range sortedKeys(subjectID) {
		if identifier := SubjectIdentifierFrom(Object(subjectID[name])); identifier != nil {
			members = append(members, member{name, identifier})
		}
	}
	subject := &Subject{raw: subjectID, members: members}
	if session := subject.Session(); session != nil && subject.User() != nil &&
		session.IsOpaque() && session.Value() == AllSessions {
		subject.members = subject.membersWithout(MemberSession)
	}
	return subject
}

// Raw is the subject identifier as received, nil if the SET carried none.
func (s *Subject) Raw() Claims { return s.raw }

// Identifier is the identifier of a simple subject, nil for a complex subject or none.
func (s *Subject) Identifier() *SubjectIdentifier { return s.identifier }

// Members calls fn for every member of a complex subject, by name in alphabetical order; a
// simple subject has none. fn returns false to stop.
func (s *Subject) Members(fn func(name string, identifier *SubjectIdentifier) bool) {
	for _, m := range s.members {
		if !fn(m.name, m.identifier) {
			return
		}
	}
}

// MemberNames are the names of the members of a complex subject, whether or not Member can read
// them; nil for a simple subject.
func (s *Subject) MemberNames() []string {
	if s.identifier != nil {
		return nil
	}
	var names []string
	for _, name := range sortedKeys(s.raw) {
		if name != "format" && Object(s.raw[name]) != nil {
			names = append(names, name)
		}
	}
	return names
}

// IsComplex reports whether this is a complex subject.
func (s *Subject) IsComplex() bool { return len(s.members) > 0 }

// Member is the member of a complex subject with the given name, nil if absent.
func (s *Subject) Member(name string) *SubjectIdentifier {
	for _, m := range s.members {
		if m.name == name {
			return m.identifier
		}
	}
	return nil
}

// User is the user member of a complex subject.
func (s *Subject) User() *SubjectIdentifier { return s.Member(MemberUser) }

// Session is the session member of a complex subject.
func (s *Subject) Session() *SubjectIdentifier { return s.Member(MemberSession) }

// Device is the device member of a complex subject.
func (s *Subject) Device() *SubjectIdentifier { return s.Member(MemberDevice) }

// Application is the application member of a complex subject.
func (s *Subject) Application() *SubjectIdentifier { return s.Member(MemberApplication) }

// Tenant is the tenant member of a complex subject.
func (s *Subject) Tenant() *SubjectIdentifier { return s.Member(MemberTenant) }

// OrgUnit is the org_unit member of a complex subject.
func (s *Subject) OrgUnit() *SubjectIdentifier { return s.Member(MemberOrgUnit) }

// Group is the group member of a complex subject.
func (s *Subject) Group() *SubjectIdentifier { return s.Member(MemberGroup) }

// UserIdentifier is the identifier that names the user: the user member of a complex subject, or
// the identifier of a simple subject unless it is opaque, which may as well name a session (see
// OpaqueID). nil if the subject does not name a user.
func (s *Subject) UserIdentifier() *SubjectIdentifier {
	if s.identifier != nil {
		if s.identifier.IsOpaque() {
			return nil
		}
		return s.identifier
	}
	return s.User()
}

// Issuer is the issuer of the user, from an iss_sub identifier.
func (s *Subject) Issuer() string {
	if user := s.UserIdentifier(); user != nil {
		return user.Issuer()
	}
	return ""
}

// Sub is the identifier of the user at the issuer: sub of an iss_sub identifier, or the id of an
// opaque user of a complex subject.
func (s *Subject) Sub() string {
	user := s.UserIdentifier()
	if user == nil || !(user.IsIssSub() || user.IsOpaque()) {
		return ""
	}
	return user.Value()
}

// SessionID is the identifier of the session.
func (s *Subject) SessionID() string {
	if session := s.Session(); session != nil {
		return session.Value()
	}
	return ""
}

// Email is the email address of the user, from an email identifier.
func (s *Subject) Email() string {
	if user := s.UserIdentifier(); user != nil && user.IsEmail() {
		return user.Value()
	}
	return ""
}

// OpaqueID is the identifier of a simple opaque subject, which does not tell whether it names a
// user or a session.
func (s *Subject) OpaqueID() string {
	if s.identifier != nil && s.identifier.IsOpaque() {
		return s.identifier.Value()
	}
	return ""
}

// IsEmpty reports whether the SET carried no subject identifier that could be resolved.
func (s *Subject) IsEmpty() bool { return s.identifier == nil && len(s.members) == 0 }

// HasUser reports whether this subject identifies a user (as opposed to only a session).
func (s *Subject) HasUser() bool { return s.UserIdentifier() != nil }

// WithoutSession is this subject without its session, i.e. widened to the user.
func (s *Subject) WithoutSession() *Subject {
	if s.Session() == nil {
		return s
	}
	return &Subject{raw: s.raw, identifier: s.identifier, members: s.membersWithout(MemberSession)}
}

func (s *Subject) membersWithout(name string) []member {
	kept := make([]member, 0, len(s.members))
	for _, m := range s.members {
		if m.name != name {
			kept = append(kept, m)
		}
	}
	return kept
}

func hasObjectMembers(object Claims) bool {
	for _, value := range object {
		if Object(value) != nil {
			return true
		}
	}
	return false
}

func sortedKeys(object Claims) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
