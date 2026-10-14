package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/ssf"
)

// ModuleTimeout is how long a module of a plan may take.
const ModuleTimeout = 8 * time.Minute

// RunPlan runs a plan of the OpenID conformance suite against a receiver under test: creates the
// plan in the suite and runs every module of it as a subtest, playing the scenario the module
// expects with the runner of the receiver under test, which has to be reachable by the suite at
// Suite.ReceiverPushURL. A module fails with the failures and warnings the suite logged, the
// receiver's log and the link to the suite's log page; the AbstractReceiverConformanceTest of
// the Java library.
func RunPlan(t *testing.T, suite *Suite, plan PlanDefinition, runner *Runner) {
	t.Helper()
	ctx := context.Background()
	config, alias, err := plan.Config()
	if err != nil {
		t.Fatal(err)
	}
	created, err := suite.Client().CreatePlan(ctx, plan.Name, plan.Variant(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Created plan %s %v with %d modules: %s", plan.Name, plan.Variant(), len(created.Modules), created.URL)
	issuer := suite.BaseURL().String() + "/test/a/" + alias
	delivery := ssf.Push
	if plan.DeliveryMode == "poll" {
		delivery = ssf.Poll
	}
	for _, module := range created.Modules {
		t.Run(module.Name, func(t *testing.T) {
			expectation := ExpectationForModule(module.Name)
			moduleID, err := suite.Client().StartModule(ctx, created, module)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("Module %s %s is waiting for the receiver: %s/log-detail.html?log=%s", module, moduleID, suite.BaseURL(), moduleID)
			run, err := runner.Start(ctx, expectation.Scenario, issuer, delivery, expectation.IdleTimeout)
			if err != nil {
				t.Fatal(err)
			}
			waitFor(ModuleTimeout, func() bool { return !run.IsActive() })
			t.Logf("Receiver run %s ended with %s:\n%s", run.ID(), run.Status(), receiverLog(run))
			result, err := suite.Client().AwaitResult(ctx, created, module, moduleID, ModuleTimeout)
			if err != nil {
				t.Fatal(err)
			}
			if !result.FinishedWith("PASSED") {
				logs, _ := json.MarshalIndent(result.Logs, "", "  ")
				t.Logf("Full log of the failed module %s:\n%s", module, logs)
				t.Fatalf("%s\nReceiver run %s ended with %s:\n%s", result.Summary(), run.ID(), run.Status(), receiverLog(run))
			}
			if run.Status() != expectation.RunStatus {
				t.Fatalf("status of the receiver run for %s: %s, expected %s", module, run.Status(), expectation.RunStatus)
			}
		})
	}
}

func waitFor(timeout time.Duration, condition func() bool) {
	deadline := time.Now().Add(timeout)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
	}
}

func receiverLog(run *Run) string {
	var log strings.Builder
	for _, entry := range run.Log() {
		fmt.Fprintf(&log, "  %s %s\n", entry.Time.Format(time.RFC3339), entry.Message)
	}
	return log.String()
}
