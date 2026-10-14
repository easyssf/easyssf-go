package conformance_test

// ConformanceSuiteModulesTests of the Java library.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easyssf/easyssf-go/conformance"
	"github.com/easyssf/easyssf-go/ssf"
)

var ctx = context.Background()

func info(testName, alias, status, deliveryMode string) string {
	return fmt.Sprintf(`{"testName":"%s","alias":"%s","status":"%s","variant":{"ssf_delivery_mode":"%s"}}`, testName, alias, status, deliveryMode)
}

// suite is a suite API that answers the given paths (relative to the suite) with the given
// bodies and everything else with 404.
func suite(t *testing.T, responses map[string]string) (string, *conformance.SuiteModules, string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := responses[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	base := server.URL + "/"
	issuer := base + "test/a/easyssf-receiver-ssf1_0-caepiop1_0-push"
	settings := conformance.DefaultReceiverSettings()
	settings.Issuer = issuer
	return base, conformance.NewSuiteModules(settings, server.Client()), issuer
}

func TestParsesTheTestInstanceOfTheIssuer(t *testing.T) {
	instance, err := conformance.ParseTestInstance("https://localhost.emobix.co.uk:8443/test/a/easyssf-receiver-ssf1_0-caepiop1_0-push/")
	if err != nil || instance.Suite != "https://localhost.emobix.co.uk:8443/" || instance.Alias != "easyssf-receiver-ssf1_0-caepiop1_0-push" ||
		instance.Issuer("other") != "https://localhost.emobix.co.uk:8443/test/a/other" {
		t.Fatalf("%+v %v", instance, err)
	}
	if instance, _ := conformance.ParseTestInstance("https://suite.example.com/suite/test/a/alias"); instance.Suite != "https://suite.example.com/suite/" {
		t.Fatal(instance.Suite)
	}
	if _, err := conformance.ParseTestInstance("https://suite.example.com/"); err == nil {
		t.Fatal("not a test instance")
	}
}

func TestUsesTheConfiguredIssuerByDefault(t *testing.T) {
	base, modules, _ := suite(t, nil)
	if instance, err := modules.TestInstance(""); err != nil || instance.Alias != "easyssf-receiver-ssf1_0-caepiop1_0-push" {
		t.Fatal(err)
	}
	if instance, _ := modules.TestInstance(base + "test/a/other"); instance.Alias != "other" {
		t.Fatal(instance.Alias)
	}
	unconfigured := conformance.NewSuiteModules(conformance.DefaultReceiverSettings(), http.DefaultClient)
	if _, err := unconfigured.TestInstance(""); err == nil {
		t.Fatal("no issuer")
	}
}

func TestListsTheRunningModulesWithTheirScenario(t *testing.T) {
	base, modules, issuer := suite(t, map[string]string{
		"api/runner/running": `["abc","def"]`,
		"api/info/abc":       info("openid-ssf-receiver-stream-create-delete", "easyssf-receiver-ssf1_0-caepiop1_0-push", "WAITING", "push"),
		"api/info/def":       info("openid-ssf-receiver-happypath", "other", "RUNNING", "poll"),
	})
	instance, _ := conformance.ParseTestInstance(issuer)
	running, err := modules.Running(ctx, instance)
	if err != nil || len(running) != 2 {
		t.Fatalf("%v %v", running, err)
	}
	first := running[0]
	delivery, _ := first.DeliveryMethod()
	if first.ID != "abc" || first.Name != "openid-ssf-receiver-stream-create-delete" || first.Alias != "easyssf-receiver-ssf1_0-caepiop1_0-push" ||
		first.Status != "WAITING" || delivery != ssf.Push || first.Issuer != issuer || first.Scenario != "create-delete" || first.LogURL != base+"log-detail.html?log=abc" {
		t.Fatalf("%+v", first)
	}
	second := running[1]
	delivery, _ = second.DeliveryMethod()
	if delivery != ssf.Poll || second.Issuer != base+"test/a/other" || second.Scenario != "stream-management" {
		t.Fatalf("%+v", second)
	}
}

func TestPrefersTheWaitingModulesOfTheConfiguredAlias(t *testing.T) {
	base, modules, issuer := suite(t, map[string]string{
		"api/runner/running": `["abc","def","ghi"]`,
		"api/info/abc":       info("openid-ssf-receiver-happypath", "other", "WAITING", "push"),
		"api/info/def":       info("openid-ssf-receiver-stream-create-delete", "easyssf-receiver-ssf1_0-caepiop1_0-push", "WAITING", "push"),
		"api/info/ghi":       info("openid-ssf-receiver-removed-subject-event", "easyssf-receiver-ssf1_0-caepiop1_0-push", "RUNNING", "push"),
	})
	instance, _ := conformance.ParseTestInstance(issuer)
	waiting, err := modules.Waiting(ctx, instance)
	if err != nil || len(waiting) != 1 || waiting[0].ID != "def" {
		t.Fatalf("%v %v", waiting, err)
	}
	// without a module under the configured alias, any waiting module will do
	waiting, _ = modules.Waiting(ctx, conformance.TestInstance{Suite: base, Alias: "unused"})
	if len(waiting) != 2 || waiting[0].ID != "abc" || waiting[1].ID != "def" {
		t.Fatalf("%v", waiting)
	}
}

func TestReportsAnUnreachableSuite(t *testing.T) {
	_, modules, issuer := suite(t, nil)
	instance, _ := conformance.ParseTestInstance(issuer)
	if _, err := modules.Running(ctx, instance); err == nil || !strings.Contains(err.Error(), "returned HTTP 404") {
		t.Fatalf("%v", err)
	}
}

func TestScenariosAndExpectations(t *testing.T) {
	if scenario, err := conformance.ScenarioFromAlias("CAEP-INTEROP"); err != nil || scenario != conformance.CaepInterop {
		t.Fatal(err)
	}
	if scenario, err := conformance.ScenarioFromAlias("StreamManagement"); err != nil || scenario != conformance.StreamManagement {
		t.Fatal(err)
	}
	if _, err := conformance.ScenarioFromAlias("nope"); err == nil {
		t.Fatal("unknown")
	}
	if conformance.ScenarioForModule("openid-ssf-receiver-stream-status-update") != conformance.StatusUpdate || conformance.ScenarioForModule("anything") != conformance.CaepInterop {
		t.Fatal("for module")
	}
	mismatch := conformance.ExpectationForModule("openid-ssf-receiver-stream-issuer-mismatch")
	if mismatch.RunStatus != conformance.RunRefusedStream || mismatch.Scenario != conformance.CaepInterop || mismatch.IdleTimeout != conformance.DefaultIdleTimeout {
		t.Fatalf("%+v", mismatch)
	}
	expiry := conformance.ExpectationForModule("openid-ssf-receiver-access-token-expiry")
	if expiry.RunStatus != conformance.RunFinished || expiry.IdleTimeout != conformance.PausingIdleTimeout {
		t.Fatalf("%+v", expiry)
	}
	for _, plan := range conformance.Plans {
		config, alias, err := plan.Config()
		if err != nil || len(config) == 0 || alias == "" || plan.Variant()["ssf_delivery_mode"] != plan.DeliveryMode {
			t.Fatalf("%v %v", plan, err)
		}
	}
	if _, err := conformance.ReceiverTLSConfig(); err != nil {
		t.Fatal(err)
	}
}
