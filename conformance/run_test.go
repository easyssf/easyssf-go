package conformance_test

// ConformanceRunLocalTransmitterTests of the Java library: runs the scenarios against the test
// transmitter of the receiver library, with POLL delivery so that the transmitter does not have
// to reach this application.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/conformance"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssftest"
)

type localReceiver struct {
	transmitter *ssftest.TestTransmitter
	server      *httptest.Server
	runner      *conformance.Runner
}

func startLocalReceiver(t *testing.T) *localReceiver {
	t.Helper()
	transmitter := ssftest.New()
	settings := conformance.DefaultReceiverSettings()
	settings.Issuer = transmitter.Issuer()
	settings.Delivery = ssf.Poll
	settings.PollInterval = 200 * time.Millisecond
	settings.IdleTimeout = 2 * time.Second
	settings.VerificationTimeout = 5 * time.Second
	settings.Auth.ClientID, settings.Auth.ClientSecret = ssftest.ClientID, ssftest.ClientSecret
	runner := conformance.NewRunner(settings, transmitter.Client, nil)
	modules := conformance.NewSuiteModules(settings, transmitter.Client)
	server := httptest.NewServer(conformance.Handler(runner, modules))
	t.Cleanup(func() {
		if run := runner.Current(); run != nil {
			run.Stop()
		}
		server.Close()
	})
	return &localReceiver{transmitter: transmitter, server: server, runner: runner}
}

func (r *localReceiver) request(t *testing.T, method, path string) (int, map[string]any) {
	t.Helper()
	request, _ := http.NewRequest(method, r.server.URL+path, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	var parsed map[string]any
	_ = json.Unmarshal(body, &parsed)
	return response.StatusCode, parsed
}

func (r *localReceiver) start(t *testing.T, scenario string) map[string]any {
	t.Helper()
	status, run := r.request(t, http.MethodPost, "/cts/runs?scenario="+scenario)
	if status != 202 {
		t.Fatalf("%d %v", status, run)
	}
	return run
}

func (r *localReceiver) current(t *testing.T) map[string]any {
	t.Helper()
	_, run := r.request(t, http.MethodGet, "/cts/runs/current")
	return run
}

func (r *localReceiver) awaitStatus(t *testing.T, status string) map[string]any {
	t.Helper()
	ssftest.Eventually(t, 20*time.Second, "run status "+status, func() bool { return r.current(t)["status"] == status })
	return r.current(t)
}

func (r *localReceiver) awaitStreamAndVerificationRequest(t *testing.T) string {
	t.Helper()
	ssftest.Eventually(t, 10*time.Second, "the verification request", func() bool { return len(r.transmitter.VerificationRequests()) > 0 })
	if len(r.transmitter.Streams()) != 1 {
		t.Fatal("one stream")
	}
	return ssf.StringMember(r.transmitter.Streams()[0], "stream_id")
}

func (r *localReceiver) audience() any { return r.transmitter.Streams()[0]["aud"] }

func (r *localReceiver) queueVerificationEvent(streamID, state string) string {
	claims := r.transmitter.SetClaimsWithPayload("SsfStreamVerification", ssf.Opaque(streamID), ssf.Claims{"state": state})
	claims["aud"] = r.audience()
	r.transmitter.QueueSet(r.transmitter.SignSET(claims))
	return claims["jti"].(string)
}

func (r *localReceiver) queueSessionRevoked() string {
	claims := r.transmitter.SetClaims("CaepSessionRevoked", ssf.IssSub(r.transmitter.Issuer(), "alice"))
	claims["aud"] = r.audience()
	r.transmitter.QueueSet(r.transmitter.SignSET(claims))
	return claims["jti"].(string)
}

func acknowledged(transmitter *ssftest.TestTransmitter, jti string) func() bool {
	return func() bool {
		for _, acked := range transmitter.AcknowledgedSets() {
			if acked == jti {
				return true
			}
		}
		return false
	}
}

func reported(transmitter *ssftest.TestTransmitter, jti string) func() bool {
	return func() bool {
		for _, report := range transmitter.ReportedErrors() {
			if report.JTI == jti {
				return true
			}
		}
		return false
	}
}

func logMessages(run map[string]any) []string {
	entries, _ := run["log"].([]any)
	var messages []string
	for _, entry := range entries {
		messages = append(messages, ssf.StringMember(ssf.Object(entry), "message"))
	}
	return messages
}

func containsEntry(messages []string, parts ...string) bool {
	for _, message := range messages {
		all := true
		for _, part := range parts {
			all = all && strings.Contains(message, part)
		}
		if all {
			return true
		}
	}
	return false
}

func TestPlaysTheCaepInteropScenario(t *testing.T) {
	r := startLocalReceiver(t)
	run := r.start(t, "caep-interop")
	if status := run["status"]; status != "STARTING" && status != "RUNNING" {
		t.Fatalf("%v", status)
	}
	streamID := r.awaitStreamAndVerificationRequest(t)
	verification := r.queueVerificationEvent(streamID, r.transmitter.VerificationRequests()[0])
	ssftest.Eventually(t, 5*time.Second, "the verification acknowledged", acknowledged(r.transmitter, verification))
	sessionRevoked := r.queueSessionRevoked()
	ssftest.Eventually(t, 5*time.Second, "the event acknowledged", acknowledged(r.transmitter, sessionRevoked))
	finished := r.awaitStatus(t, "FINISHED")
	if len(r.transmitter.Streams()) != 0 || len(r.transmitter.ReportedErrors()) != 0 {
		t.Fatal("stream deleted, nothing reported")
	}
	messages := logMessages(finished)
	if !containsEntry(messages, "Read stream status") || !containsEntry(messages, "Verification event", "accepted") || !containsEntry(messages, "Deleted stream "+streamID) {
		t.Fatalf("%v", messages)
	}
}

func TestRejectsVerificationEventWithWrongStateAndRequestsVerificationAgain(t *testing.T) {
	r := startLocalReceiver(t)
	r.start(t, "caep-interop")
	streamID := r.awaitStreamAndVerificationRequest(t)
	wrong := r.queueVerificationEvent(streamID, "made-up")
	ssftest.Eventually(t, 5*time.Second, "the wrong state reported", reported(r.transmitter, wrong))
	for _, report := range r.transmitter.ReportedErrors() {
		if report.JTI == wrong && report.Code != "invalid_state" {
			t.Fatalf("%+v", report)
		}
	}
	ssftest.Eventually(t, 5*time.Second, "a second verification request", func() bool { return len(r.transmitter.VerificationRequests()) == 2 })
	right := r.queueVerificationEvent(streamID, r.transmitter.VerificationRequests()[1])
	ssftest.Eventually(t, 5*time.Second, "the right one acknowledged", acknowledged(r.transmitter, right))
	r.awaitStatus(t, "FINISHED")
	if len(r.transmitter.Streams()) != 0 {
		t.Fatal("stream deleted")
	}
}

func TestRejectsVerificationEventAboutAnotherStream(t *testing.T) {
	r := startLocalReceiver(t)
	r.start(t, "caep-interop")
	streamID := r.awaitStreamAndVerificationRequest(t)
	wrong := r.queueVerificationEvent("another-stream", r.transmitter.VerificationRequests()[0])
	ssftest.Eventually(t, 5*time.Second, "the wrong stream reported", reported(r.transmitter, wrong))
	ssftest.Eventually(t, 5*time.Second, "a second verification request", func() bool { return len(r.transmitter.VerificationRequests()) == 2 })
	right := r.queueVerificationEvent(streamID, r.transmitter.VerificationRequests()[1])
	ssftest.Eventually(t, 5*time.Second, "the right one acknowledged", acknowledged(r.transmitter, right))
	r.awaitStatus(t, "FINISHED")
}

func TestRefusesStreamWithAnotherIssuer(t *testing.T) {
	r := startLocalReceiver(t)
	r.transmitter.SetStreamIssuer("https://other.example")
	r.start(t, "caep-interop")
	run := r.awaitStatus(t, "REFUSED_STREAM")
	if len(r.transmitter.Streams()) != 0 || len(r.transmitter.VerificationRequests()) != 0 || !containsEntry(logMessages(run), "Refusing the stream") {
		t.Fatalf("%v", logMessages(run))
	}
}

func TestCreatesAndDeletesTheStream(t *testing.T) {
	r := startLocalReceiver(t)
	r.start(t, "create-delete")
	r.awaitStatus(t, "FINISHED")
	if len(r.transmitter.Streams()) != 0 || len(r.transmitter.VerificationRequests()) != 0 {
		t.Fatal("created and deleted only")
	}
}

func TestManagesStreamAndStatusAndSubjects(t *testing.T) {
	r := startLocalReceiver(t)
	for _, scenario := range []string{"stream-management", "status-update", "remove-subject"} {
		r.transmitter.Reset()
		r.start(t, scenario)
		streamID := r.awaitStreamAndVerificationRequest(t)
		r.queueVerificationEvent(streamID, r.transmitter.VerificationRequests()[0])
		run := r.awaitStatus(t, "FINISHED")
		if len(r.transmitter.Streams()) != 0 {
			t.Fatal(scenario)
		}
		messages := logMessages(run)
		if !containsEntry(messages, "Replaced stream") && !containsEntry(messages, "Enabling the stream") && !containsEntry(messages, "Removed subject") {
			t.Fatalf("%s: %v", scenario, messages)
		}
	}
}

func TestPushEndpointAnswersWithoutRun(t *testing.T) {
	r := startLocalReceiver(t)
	response, err := http.Post(r.server.URL+"/ssf/push", "application/secevent+jwt", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 503 {
		t.Fatalf("%d", response.StatusCode)
	}
	if status, _ := r.request(t, http.MethodGet, "/"); status != 200 {
		t.Fatal("usage")
	}
	if status, _ := r.request(t, http.MethodPost, "/cts/runs?scenario=nope"); status != 400 {
		t.Fatal("unknown scenario")
	}
	if status, _ := r.request(t, http.MethodPost, "/cts/runs/auto"); status != 400 {
		t.Fatal("the test transmitter is not a test instance of the suite")
	}
}
