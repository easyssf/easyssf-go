package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
	"github.com/easyssf/easyssf-go/ssftest"
)

// Alice and Bob in the scripted demo.
const (
	Alice = "/Users/2b2f880af6674ac284bae9381673d462"
	Bob   = "/Users/c3a6e1f0b2d94f0e9a7c5d8b6e4f2a10"
)

const pause = 4 * time.Second

// ErrNotReady says that the receiver has not registered its stream yet.
var ErrNotReady = fmt.Errorf("the receiver has not registered its stream yet, try again in a moment")

// DemoScimProvider plays the SCIM service provider: every operation on a user becomes a SCIM
// Event (RFC 9967) that the demo transmitter delivers to the receiver of this very application.
// The operations are driven by Handler (/demo/scim) and, with autoplay, by Play, which tells
// the life of two users once the receiver has registered its stream, one SET every few seconds.
//
// The SETs transmitted are kept, decoded, for GET /demo/scim/events: that is what a SCIM Event
// looks like on the wire.
type DemoScimProvider struct {
	transmitter *ssftest.TestTransmitter
	log         *slog.Logger
	mu          sync.Mutex
	versions    map[string]int
	externalIDs map[string]string
	transmitted []ssf.Claims
}

// NewDemoScimProvider is a service provider that transmits through transmitter.
func NewDemoScimProvider(transmitter *ssftest.TestTransmitter, log *slog.Logger) *DemoScimProvider {
	return &DemoScimProvider{transmitter: transmitter, log: log, versions: map[string]int{}, externalIDs: map[string]string{}}
}

// Play is the life of two users: created, modified, replaced, deactivated, deleted. The
// resources and the patch are written as JSON here so that the SCIM payloads are easy to read;
// an application would build them from its own objects.
func (p *DemoScimProvider) Play() {
	for len(p.transmitter.Streams()) == 0 {
		time.Sleep(200 * time.Millisecond)
	}
	p.log.Info("The receiver registered its stream, the demo SCIM service provider starts")
	p.narrate("Alice is created at the service provider and joins the feed: feed:add and prov:create:full in one SET, with her representation as data")
	_, _ = p.Create(Alice, "alice", object(`{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "alice", "displayName": "Alice Adams",
		"emails": [{"type": "work", "value": "alice@example.com", "primary": true}], "active": true}`))
	time.Sleep(pause)
	p.narrate("Bob is created as well")
	_, _ = p.Create(Bob, "bob", object(`{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "bob", "displayName": "Bob Brown",
		"emails": [{"type": "work", "value": "bob@example.com", "primary": true}], "active": true}`))
	time.Sleep(pause)
	p.narrate("Alice marries: a SCIM PATCH changes her display name and adds an email, prov:patch:full carries the PatchOp as data")
	_, _ = p.Patch(Alice, object(`{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
		{"op": "replace", "path": "displayName", "value": "Alice Baker"},
		{"op": "add", "path": "emails", "value": [{"type": "work", "value": "alice@example.com"}, {"type": "home", "value": "alice.baker@home.example"}]}]}`))
	time.Sleep(pause)
	p.narrate("Bob is replaced wholesale with a SCIM PUT: prov:put:full carries the new representation")
	_, _ = p.Replace(Bob, object(`{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "robert", "displayName": "Robert Brown",
		"emails": [{"type": "work", "value": "robert@example.com", "primary": true}], "active": true}`))
	time.Sleep(pause)
	p.narrate("Alice's phone number changes, reported as a notice: prov:patch:notice names the attribute but carries no data, the receiver would have to GET the resource")
	_, _ = p.PatchNotice(Alice, []string{"phoneNumbers"})
	time.Sleep(pause)
	p.narrate("Alice leaves the company and is deactivated: prov:deactivate, an event without payload")
	_, _ = p.Deactivate(Alice)
	time.Sleep(pause)
	p.narrate("Bob is deleted: prov:delete, which also removes him from the feed")
	_, _ = p.Delete(Bob)
	p.log.Info("The demo SCIM service provider is done, GET /users shows the result once the receiver has polled, GET /demo/scim/events the SETs")
}

// Create creates the user: feed:add and prov:create:full in one SET, as RFC 9967 allows for
// events about the same resource. Returns the SET transmitted, decoded.
func (p *DemoScimProvider) Create(uri, externalID string, user ssf.Claims) (ssf.Claims, error) {
	if externalID != "" {
		p.mu.Lock()
		p.externalIDs[uri] = externalID
		p.mu.Unlock()
	}
	return p.transmit(uri, ssf.Claims{
		eventtypes.ScimFeedAdd:        ssf.Claims{},
		eventtypes.ScimProvCreateFull: ssf.Claims{"version": p.nextVersion(uri), "data": map[string]any(user)},
	})
}

// Replace replaces the user with SCIM PUT: prov:put:full with the new representation.
func (p *DemoScimProvider) Replace(uri string, user ssf.Claims) (ssf.Claims, error) {
	return p.transmit(uri, ssf.Claims{eventtypes.ScimProvPutFull: ssf.Claims{"version": p.nextVersion(uri), "data": map[string]any(user)}})
}

// Patch modifies the user with SCIM PATCH: prov:patch:full with the PatchOp.
func (p *DemoScimProvider) Patch(uri string, patchOp ssf.Claims) (ssf.Claims, error) {
	return p.transmit(uri, ssf.Claims{eventtypes.ScimProvPatchFull: ssf.Claims{"version": p.nextVersion(uri), "data": map[string]any(patchOp)}})
}

// PatchNotice reports a modification without its data: prov:patch:notice naming the attributes
// that changed.
func (p *DemoScimProvider) PatchNotice(uri string, attributes []string) (ssf.Claims, error) {
	list := make([]any, 0, len(attributes))
	for _, attribute := range attributes {
		list = append(list, attribute)
	}
	return p.transmit(uri, ssf.Claims{eventtypes.ScimProvPatchNotice: ssf.Claims{"version": p.nextVersion(uri), "attributes": list}})
}

// Activate activates the user: prov:activate.
func (p *DemoScimProvider) Activate(uri string) (ssf.Claims, error) {
	return p.transmit(uri, ssf.Claims{eventtypes.ScimProvActivate: ssf.Claims{}})
}

// Deactivate deactivates the user: prov:deactivate.
func (p *DemoScimProvider) Deactivate(uri string) (ssf.Claims, error) {
	return p.transmit(uri, ssf.Claims{eventtypes.ScimProvDeactivate: ssf.Claims{}})
}

// Delete deletes the user: prov:delete, which has no payload attributes and removes the resource
// from the feed as well.
func (p *DemoScimProvider) Delete(uri string) (ssf.Claims, error) {
	set, err := p.transmit(uri, ssf.Claims{eventtypes.ScimProvDelete: ssf.Claims{}})
	p.mu.Lock()
	delete(p.versions, uri)
	delete(p.externalIDs, uri)
	p.mu.Unlock()
	return set, err
}

// Transmitted are the SETs transmitted so far, oldest first: the compact JWT as set and its
// decoded claims.
func (p *DemoScimProvider) Transmitted() []ssf.Claims {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]ssf.Claims{}, p.transmitted...)
}

func (p *DemoScimProvider) transmit(uri string, events ssf.Claims) (ssf.Claims, error) {
	streams := p.transmitter.Streams()
	if len(streams) == 0 {
		return nil, ErrNotReady
	}
	// the receiver expects the audience the transmitter assigned to the stream
	eventType := ""
	for key := range events {
		if eventType == "" || key < eventType {
			eventType = key
		}
	}
	p.mu.Lock()
	externalID := p.externalIDs[uri]
	p.mu.Unlock()
	claims := p.transmitter.SetClaimsWithPayload(eventType, ssf.SCIM(uri, externalID), nil)
	claims["aud"] = streams[0]["aud"]
	claims["txn"] = randomHex(16)
	claims["events"] = events
	set := p.transmitter.SignSET(claims)
	p.transmitter.QueueSet(set)
	transmitted := ssf.Claims{"set": set, "claims": claims}
	p.mu.Lock()
	p.transmitted = append(p.transmitted, transmitted)
	p.mu.Unlock()
	// the decoded SET in the log: this is what a SCIM Event looks like
	var aliases []string
	for key := range events {
		aliases = append(aliases, eventtypes.AliasOf(key))
	}
	pretty, _ := json.MarshalIndent(claims, "", "  ")
	p.log.Info(fmt.Sprintf("Transmitted SET %s with %v for %s:\n%s", claims["jti"], aliases, uri, pretty))
	return transmitted, nil
}

func (p *DemoScimProvider) nextVersion(uri string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.versions[uri]++
	return fmt.Sprint(p.versions[uri])
}

// narrate is a headline in the log for the step that follows, to scroll along in a demo.
func (p *DemoScimProvider) narrate(whatHappens string) { p.log.Info("\n### " + whatHappens) }

// NewUserURI is the URI of a new user.
func NewUserURI() string { return "/Users/" + randomHex(16) }

// Handler is the API of the demo SCIM service provider under /demo/scim, a tiny stand-in for the
// /Users endpoint of a SCIM server: each request changes a user and transmits the SCIM Event
// about it, which the receiver of this application mirrors into /users on its next poll. Every
// response is the SET transmitted, so that the event is visible next to its cause. See
// example-scim-provisioning.http.
func (p *DemoScimProvider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /demo/scim/Users", func(w http.ResponseWriter, r *http.Request) {
		user, ok := readJSON(w, r)
		if !ok {
			return
		}
		uri := NewUserURI()
		name := ssf.StringMember(user, "userName")
		if name == "" {
			name = uri
		}
		p.narrate("POST /demo/scim/Users: " + name + " is created and joins the feed")
		set, err := p.Create(uri, ssf.StringMember(user, "externalId"), user)
		if err == nil {
			w.Header().Set("Location", "/demo/scim"+uri)
		}
		respond(w, http.StatusCreated, set, err)
	})
	mux.HandleFunc("PUT /demo/scim/Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		user, ok := readJSON(w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		p.narrate("PUT /demo/scim/Users/" + id + ": the user is replaced")
		set, err := p.Replace("/Users/"+id, user)
		respond(w, http.StatusOK, set, err)
	})
	mux.HandleFunc("PATCH /demo/scim/Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		patchOp, ok := readJSON(w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		if r.URL.Query().Get("mode") == "notice" {
			p.narrate("PATCH /demo/scim/Users/" + id + "?mode=notice: the user is modified, reported without data")
			set, err := p.PatchNotice("/Users/"+id, paths(patchOp))
			respond(w, http.StatusOK, set, err)
			return
		}
		p.narrate("PATCH /demo/scim/Users/" + id + ": the user is modified")
		set, err := p.Patch("/Users/"+id, patchOp)
		respond(w, http.StatusOK, set, err)
	})
	mux.HandleFunc("POST /demo/scim/Users/{id}/activate", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		p.narrate("POST /demo/scim/Users/" + id + "/activate: the user is activated")
		set, err := p.Activate("/Users/" + id)
		respond(w, http.StatusOK, set, err)
	})
	mux.HandleFunc("POST /demo/scim/Users/{id}/deactivate", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		p.narrate("POST /demo/scim/Users/" + id + "/deactivate: the user is deactivated")
		set, err := p.Deactivate("/Users/" + id)
		respond(w, http.StatusOK, set, err)
	})
	mux.HandleFunc("DELETE /demo/scim/Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		p.narrate("DELETE /demo/scim/Users/" + id + ": the user is deleted")
		set, err := p.Delete("/Users/" + id)
		respond(w, http.StatusOK, set, err)
	})
	mux.HandleFunc("GET /demo/scim/events", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, p.Transmitted())
	})
	return mux
}

func readJSON(w http.ResponseWriter, r *http.Request) (ssf.Claims, bool) {
	var body ssf.Claims
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the body is not a JSON object: " + err.Error()})
		return nil, false
	}
	return body, true
}

func respond(w http.ResponseWriter, status int, set ssf.Claims, err error) {
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, status, set)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func paths(patchOp ssf.Claims) []string {
	var paths []string
	operations, _ := patchOp["Operations"].([]any)
	for _, element := range operations {
		operation := ssf.Object(element)
		if path := ssf.StringMember(operation, "path"); path != "" {
			paths = append(paths, path)
		} else if attributes := ssf.ObjectMember(operation, "value"); attributes != nil {
			for attribute := range attributes {
				paths = append(paths, attribute)
			}
		}
	}
	return paths
}

func object(text string) ssf.Claims {
	claims, err := ssf.ParseClaims([]byte(strings.TrimSpace(text)))
	if err != nil {
		panic(err)
	}
	return claims
}

func randomHex(bytes int) string {
	b := make([]byte, bytes)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
