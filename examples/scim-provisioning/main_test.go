package main

// Runs the application against the in-process transmitter, without the demo, and plays the
// life of a user; and the demo service provider against the application.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
	"github.com/easyssf/easyssf-go/ssftest"
)

const timeout = 10 * time.Second

func start(t *testing.T, transmitter *ssftest.TestTransmitter, demo bool) (*Application, *httptest.Server) {
	t.Helper()
	config := receiverConfig(transmitter)
	config.Poll.Interval = receiver.D(100 * time.Millisecond)
	config.Poll.InitialDelay = 0
	application, err := build(transmitter, config, demo, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(application.Handler)
	t.Cleanup(server.Close)
	application.Receiver.Start(context.Background())
	t.Cleanup(func() { application.Receiver.Stop(context.Background()) })
	ssftest.Eventually(t, timeout, "the receiver registers its stream", func() bool { return len(transmitter.Streams()) > 0 })
	return application, server
}

func transmit(transmitter *ssftest.TestTransmitter, eventType, uri, externalID string, payload ssf.Claims) {
	claims := transmitter.SetClaimsWithPayload(eventType, ssf.SCIM(uri, externalID), payload)
	claims["aud"] = transmitter.Streams()[0]["aud"]
	transmitter.QueueSet(transmitter.SignSET(claims))
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

func TestMirrorsTheLifeOfAUser(t *testing.T) {
	transmitter := ssftest.New()
	application, server := start(t, transmitter, false)
	directory := application.Directory
	id := strings.TrimPrefix(Alice, "/Users/")
	transmit(transmitter, eventtypes.ScimProvCreateFull, Alice, "alice", ssf.Claims{"version": "1", "data": map[string]any{
		"userName": "alice", "name": map[string]any{"givenName": "Alice", "familyName": "Adams"}, "emails": []any{map[string]any{"value": "alice@example.com"}}}})
	ssftest.Eventually(t, timeout, "alice is created", func() bool { _, ok := directory.Find(id); return ok })
	alice, _ := directory.Find(id)
	if alice.UserName != "alice" || alice.DisplayName != "Alice Adams" || len(alice.Emails) != 1 || alice.ExternalID != "alice" || !alice.Active || alice.Version != "1" {
		t.Fatalf("%s", alice)
	}
	status, body := get(t, server.URL+"/users")
	if status != 200 || !strings.Contains(body, `"userName":"alice"`) || !strings.Contains(body, `"displayName":"Alice Adams"`) {
		t.Fatalf("%d %s", status, body)
	}
	transmit(transmitter, eventtypes.ScimProvPatchFull, Alice, "alice", ssf.Claims{"version": "2", "data": map[string]any{"Operations": []any{
		map[string]any{"op": "replace", "path": "displayName", "value": "Alice Baker"},
		map[string]any{"op": "replace", "value": map[string]any{"active": false}}}}})
	ssftest.Eventually(t, timeout, "alice is patched", func() bool { u, ok := directory.Find(id); return ok && u.Version == "2" })
	alice, _ = directory.Find(id)
	if alice.DisplayName != "Alice Baker" || alice.Active {
		t.Fatalf("%s", alice)
	}
	transmit(transmitter, eventtypes.ScimProvActivate, Alice, "alice", nil)
	ssftest.Eventually(t, timeout, "alice is activated", func() bool { u, ok := directory.Find(id); return ok && u.Active })
	// a notice carries no data and changes nothing
	transmit(transmitter, eventtypes.ScimProvPutNotice, Alice, "alice", ssf.Claims{"attributes": []any{"userName"}})
	transmit(transmitter, eventtypes.ScimProvDelete, Alice, "alice", nil)
	ssftest.Eventually(t, timeout, "alice is deleted", func() bool { _, ok := directory.Find(id); return !ok })
	if status, _ := get(t, server.URL+"/users/"+id); status != 404 {
		t.Fatal(status)
	}
}

func TestIgnoresGroups(t *testing.T) {
	transmitter := ssftest.New()
	application, _ := start(t, transmitter, false)
	transmit(transmitter, eventtypes.ScimProvCreateFull, "/Groups/176f397ec4c44b94b2cfcb759780b8c2", "crmUsers", ssf.Claims{"data": map[string]any{"displayName": "crmUsers"}})
	transmit(transmitter, eventtypes.ScimProvCreateFull, "/Users/44f6142df96bd6ab61e7521d9", "", ssf.Claims{"data": map[string]any{"userName": "jdoe"}})
	ssftest.Eventually(t, timeout, "jdoe is created", func() bool { _, ok := application.Directory.Find("44f6142df96bd6ab61e7521d9"); return ok })
	if _, ok := application.Directory.Find("176f397ec4c44b94b2cfcb759780b8c2"); ok {
		t.Fatal("groups are not mirrored")
	}
}

func TestDemoServiceProviderTransmitsWhatItIsAskedFor(t *testing.T) {
	transmitter := ssftest.New()
	application, server := start(t, transmitter, true)
	post := func(path, body string) (int, string) {
		response, err := http.Post(server.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(data)
	}
	status, body := post("/demo/scim/Users", `{"userName": "carol", "externalId": "carol", "emails": ["carol@example.com"]}`)
	if status != 201 || !strings.Contains(body, `"set"`) {
		t.Fatalf("%d %s", status, body)
	}
	ssftest.Eventually(t, timeout, "carol is mirrored", func() bool {
		for _, user := range application.Directory.All() {
			if user.UserName == "carol" && user.ExternalID == "carol" {
				return true
			}
		}
		return false
	})
	if status, body := get(t, server.URL+"/demo/scim/events"); status != 200 || !strings.Contains(body, eventtypes.ScimProvCreateFull) {
		t.Fatalf("%d %s", status, body)
	}
	if _, err := application.Demo.Deactivate("/Users/nobody"); err != nil {
		t.Fatal(err)
	}
}

func TestBuildsTheUserFromTheScimRepresentationAndAppliesPatches(t *testing.T) {
	data := ssf.Claims{"userName": "carol", "name": map[string]any{"givenName": "Carol", "familyName": "Clark"},
		"emails": []any{map[string]any{"type": "work", "value": "carol@example.com"}, "carol@home.example"}}
	user := UserFromSCIM("1", "carol", data, "1")
	if user.UserName != "carol" || user.DisplayName != "Carol Clark" || len(user.Emails) != 2 || !user.Active || user.Version != "1" {
		t.Fatalf("%s", user)
	}
	patched := user.With("displayName", "Carol Davis").With("active", "false").With("phoneNumbers", []any{"+1"})
	if patched.DisplayName != "Carol Davis" || patched.Active {
		t.Fatalf("%s", patched)
	}
}
