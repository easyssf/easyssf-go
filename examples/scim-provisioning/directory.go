package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/easyssf/easyssf-go/ssf"
)

// User is a user of the local directory, the mirror of a SCIM User resource (RFC 7643, section
// 4.1): the attributes this application cares about, and the ETag version the service provider
// reported with the last event about the resource.
type User struct {
	// ID is the id of the resource, the last segment of the subject's uri.
	ID string `json:"id"`
	// ExternalID is the externalId of the subject.
	ExternalID string `json:"externalId,omitempty"`
	// UserName is userName.
	UserName string `json:"userName,omitempty"`
	// DisplayName is displayName, or the name assembled from name.
	DisplayName string `json:"displayName,omitempty"`
	// Emails are the addresses of emails.
	Emails []string `json:"emails"`
	// Active is active.
	Active bool `json:"active"`
	// Version is the version of the last event.
	Version string `json:"version,omitempty"`
}

// UserFromSCIM builds the user from the data of a prov:create:full or prov:put:full event, the
// representation of the resource.
func UserFromSCIM(id, externalID string, data ssf.Claims, version string) User {
	active := true
	if value, ok := data["active"].(bool); ok {
		active = value
	}
	return User{ID: id, ExternalID: externalID, UserName: ssf.StringMember(data, "userName"), DisplayName: displayName(data),
		Emails: emails(data["emails"]), Active: active, Version: version}
}

// With applies one attribute of a SCIM PATCH (replace or add) to the user. Attributes this
// application does not mirror are ignored.
func (u User) With(attribute string, value any) User {
	switch attribute {
	case "userName":
		u.UserName, _ = value.(string)
	case "displayName":
		u.DisplayName, _ = value.(string)
	case "emails":
		u.Emails = emails(value)
	case "active":
		u.Active = value != false && value != "false"
	}
	return u
}

// WithActive is the user with active.
func (u User) WithActive(active bool) User {
	u.Active = active
	return u
}

// WithVersion is the user with version, if the event carried one.
func (u User) WithVersion(version string) User {
	if version != "" {
		u.Version = version
	}
	return u
}

func (u User) String() string {
	return fmt.Sprintf("User[id=%s, externalId=%s, userName=%s, displayName=%s, emails=%v, active=%v, version=%s]",
		u.ID, u.ExternalID, u.UserName, u.DisplayName, u.Emails, u.Active, u.Version)
}

func displayName(data ssf.Claims) string {
	if name := ssf.StringMember(data, "displayName"); name != "" {
		return name
	}
	name := ssf.ObjectMember(data, "name")
	if formatted := ssf.StringMember(name, "formatted"); formatted != "" {
		return formatted
	}
	return strings.TrimSpace(ssf.StringMember(name, "givenName") + " " + ssf.StringMember(name, "familyName"))
}

// emails are the values of the multi-valued emails attribute: complex values with a value
// member, or plain strings.
func emails(value any) []string {
	values, _ := value.([]any)
	addresses := []string{}
	for _, email := range values {
		switch e := email.(type) {
		case map[string]any:
			if address := ssf.StringMember(e, "value"); address != "" {
				addresses = append(addresses, address)
			}
		case string:
			addresses = append(addresses, e)
		}
	}
	return addresses
}

// UserDirectory is the local directory the SCIM Events are mirrored into, in memory. An
// application would keep its own user table here.
type UserDirectory struct {
	mu    sync.Mutex
	users map[string]User
}

// NewUserDirectory is an empty directory.
func NewUserDirectory() *UserDirectory { return &UserDirectory{users: map[string]User{}} }

// Save stores the user, replacing the user with the same id.
func (d *UserDirectory) Save(user User) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[user.ID] = user
}

// Find is the user with the id, if the directory has one.
func (d *UserDirectory) Find(id string) (User, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	user, ok := d.users[id]
	return user, ok
}

// Update changes the user, if it is in the directory; ok is false if the directory has no such
// user.
func (d *UserDirectory) Update(id string, change func(User) User) (User, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	user, ok := d.users[id]
	if !ok {
		return User{}, false
	}
	changed := change(user)
	d.users[id] = changed
	return changed, true
}

// Remove removes the user, returning it if the directory had one.
func (d *UserDirectory) Remove(id string) (User, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	user, ok := d.users[id]
	delete(d.users, id)
	return user, ok
}

// All are all users, by id.
func (d *UserDirectory) All() []User {
	d.mu.Lock()
	defer d.mu.Unlock()
	all := make([]User, 0, len(d.users))
	for _, user := range d.users {
		all = append(all, user)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all
}
