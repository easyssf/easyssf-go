package conformance_test

// The four conformance plans against the receiver under test, Handler served over https on the
// receiver port; the Ssf10Push/Poll and CaepInterop10Push/Poll ReceiverConformanceTests of the
// Java library. Skipped unless EASYSSF_CONFORMANCE_TESTS=true: a plan takes minutes and needs
// Docker.

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/conformance"
	"github.com/easyssf/easyssf-go/ssf"
)

const conformanceTests = "EASYSSF_CONFORMANCE_TESTS"

func TestMain(m *testing.M) {
	code := m.Run()
	conformance.CloseSharedSuite()
	os.Exit(code)
}

// receiverUnderTest starts the suite (once per process) and the receiver under test for the
// plan on the receiver port, reachable by the suite at its push URL.
func receiverUnderTest(t *testing.T, plan conformance.PlanDefinition) (*conformance.Suite, *conformance.Runner) {
	t.Helper()
	if os.Getenv(conformanceTests) != "true" {
		t.Skipf("Set %s=true to run the conformance suite in Docker (minutes per plan)", conformanceTests)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	suite, err := conformance.SharedSuite(context.Background(), log)
	if err != nil {
		t.Fatal(err)
	}
	settings := conformance.DefaultReceiverSettings()
	settings.PushURL = suite.ReceiverPushURL()
	if plan.DeliveryMode == "poll" {
		settings.Delivery = ssf.Poll
	}
	client := suite.HTTPClient()
	runner := conformance.NewRunner(settings, client, log)
	tlsConfig, err := conformance.ReceiverTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", suite.Settings().ReceiverPort))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: conformance.Handler(runner, conformance.NewSuiteModules(settings, client)), TLSConfig: tlsConfig, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		if run := runner.Current(); run != nil {
			run.Stop()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return suite, runner
}

func TestSSF10PushPlan(t *testing.T) {
	suite, runner := receiverUnderTest(t, conformance.SSF10Push)
	conformance.RunPlan(t, suite, conformance.SSF10Push, runner)
}

func TestSSF10PollPlan(t *testing.T) {
	suite, runner := receiverUnderTest(t, conformance.SSF10Poll)
	conformance.RunPlan(t, suite, conformance.SSF10Poll, runner)
}

func TestCaepInterop10PushPlan(t *testing.T) {
	suite, runner := receiverUnderTest(t, conformance.CaepInterop10Push)
	conformance.RunPlan(t, suite, conformance.CaepInterop10Push, runner)
}

func TestCaepInterop10PollPlan(t *testing.T) {
	suite, runner := receiverUnderTest(t, conformance.CaepInterop10Poll)
	conformance.RunPlan(t, suite, conformance.CaepInterop10Poll, runner)
}
