package ssf

// Constructors for subject identifiers (RFC 9493) as they appear in the sub_id claim of a SET
// and in requests to add or remove subjects of a stream; the SsfSubjectIdentifiers of the Java
// library. They return the JSON object, so they can be nested, marshalled and resolved.

// IssSub is a subject identified by its issuer and its identifier at that issuer.
func IssSub(issuer, sub string) Claims {
	return Claims{"format": FormatIssSub, "iss": issuer, "sub": sub}
}

// Email is a subject identified by an email address.
func Email(email string) Claims {
	return Claims{"format": FormatEmail, "email": email}
}

// Opaque is a subject identified by an opaque identifier.
func Opaque(id string) Claims {
	return Claims{"format": FormatOpaque, "id": id}
}

// Account is a subject identified by an acct: URI (RFC 7565).
func Account(uri string) Claims {
	return Claims{"format": FormatAccount, "uri": uri}
}

// PhoneNumber is a subject identified by a telephone number in E.164 format.
func PhoneNumber(phoneNumber string) Claims {
	return Claims{"format": FormatPhoneNumber, "phone_number": phoneNumber}
}

// DID is a subject identified by a decentralized identifier.
func DID(url string) Claims {
	return Claims{"format": FormatDID, "url": url}
}

// URI is a subject identified by a URI.
func URI(uri string) Claims {
	return Claims{"format": FormatURI, "uri": uri}
}

// SCIM is a SCIM resource (RFC 9967), the subject of SCIM Events. uri is the relative path of
// the resource, for example /Users/2b2f880a; externalID is added as externalId when not empty.
func SCIM(uri, externalID string) Claims {
	identifier := Claims{"format": FormatSCIM, "uri": uri}
	if externalID != "" {
		identifier["externalId"] = externalID
	}
	return identifier
}

// Aliases is a subject with several identifiers that all name it.
func Aliases(identifiers ...Claims) Claims {
	list := make([]any, 0, len(identifiers))
	for _, identifier := range identifiers {
		list = append(list, identifier)
	}
	return Claims{"format": FormatAliases, "identifiers": list}
}

// ComplexMembers is a complex subject with the given members (user, session, device, tenant,
// ...), each a subject identifier.
func ComplexMembers(members map[string]Claims) Claims {
	identifier := Claims{"format": FormatComplex}
	for name, member := range members {
		identifier[name] = member
	}
	return identifier
}

// Complex is a subject made up of a user and a session, either may be nil.
func Complex(user, session Claims) Claims {
	members := map[string]Claims{}
	if user != nil {
		members[MemberUser] = user
	}
	if session != nil {
		members[MemberSession] = session
	}
	return ComplexMembers(members)
}
