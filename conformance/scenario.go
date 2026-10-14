package conformance

import (
	"fmt"
	"strings"
	"time"
)

// Scenario is what the receiver does with its stream in a test run. All scenarios create the
// stream, check its issuer, and delete it at the end; the ones that keep the stream read its
// configuration and status, verify it and accept the events the transmitter delivers until none
// arrives for a while.
type Scenario int

const (
	// CaepInterop fits the CAEP interop plan and most tests of the default plan.
	CaepInterop Scenario = iota
	// CreateDelete creates and deletes the stream, nothing else.
	CreateDelete
	// StreamManagement additionally updates and replaces the stream configuration (receiver
	// happy path test of the default plan).
	StreamManagement
	// StatusUpdate additionally pauses and enables the stream (stream status test of the
	// default plan).
	StatusUpdate
	// RemoveSubject additionally removes a subject from the stream (removed subject test of the
	// default plan).
	RemoveSubject
)

// Scenarios are all scenarios.
var Scenarios = []Scenario{CaepInterop, CreateDelete, StreamManagement, StatusUpdate, RemoveSubject}

var scenarioAliases = map[Scenario]string{CaepInterop: "caep-interop", CreateDelete: "create-delete",
	StreamManagement: "stream-management", StatusUpdate: "status-update", RemoveSubject: "remove-subject"}

// moduleScenarios are the test modules of the suite's receiver plans that need another scenario
// than CaepInterop, which fits all tests that just expect a stream to be created, verified, fed
// and deleted.
var moduleScenarios = map[string]Scenario{
	"openid-ssf-receiver-happypath":             StreamManagement,
	"openid-ssf-receiver-stream-create-delete":  CreateDelete,
	"openid-ssf-receiver-stream-status-update":  StatusUpdate,
	"openid-ssf-receiver-removed-subject-event": RemoveSubject,
}

// Alias is the name used in the API, e.g. caep-interop.
func (s Scenario) Alias() string { return scenarioAliases[s] }

// String is the alias.
func (s Scenario) String() string { return s.Alias() }

// ScenarioFromAlias is the scenario with the given alias (caep-interop) or name (CaepInterop),
// case-insensitive.
func ScenarioFromAlias(alias string) (Scenario, error) {
	for scenario, name := range scenarioAliases {
		if strings.EqualFold(name, alias) || strings.EqualFold(strings.ReplaceAll(name, "-", ""), alias) {
			return scenario, nil
		}
	}
	return 0, fmt.Errorf("unknown scenario %q", alias)
}

// ScenarioForModule is the scenario the receiver plays for a test module of the suite, e.g.
// openid-ssf-receiver-stream-create-delete.
func ScenarioForModule(moduleName string) Scenario {
	if scenario, ok := moduleScenarios[moduleName]; ok {
		return scenario
	}
	return CaepInterop
}

// Idle timeouts of the runs the plan tests start.
const (
	// DefaultIdleTimeout is how long the receiver waits for further events before it deletes
	// the stream. The suite delivers the events of most modules back to back (gaps of at most
	// about 2 seconds), so this is far below the configured idle timeout of a manual run.
	DefaultIdleTimeout = 5 * time.Second
	// PausingIdleTimeout is the idle timeout for the modules that pause between events on
	// purpose: 20 seconds token lifetime in the access token expiry test, 15 seconds in the
	// transmitter-initiated status change test.
	PausingIdleTimeout = 30 * time.Second
)

// ModuleExpectation is what the receiver does for a test module of the suite's receiver plans
// and how its run is expected to end.
type ModuleExpectation struct {
	// Scenario is the scenario the receiver plays.
	Scenario Scenario
	// RunStatus is the status the run has to end with.
	RunStatus RunStatus
	// IdleTimeout is how long the run waits for further events before it deletes the stream.
	IdleTimeout time.Duration
}

var moduleOutcomes = map[string]ModuleExpectation{
	// the transmitter's issuer differs from the one the stream is created at
	"openid-ssf-receiver-stream-issuer-mismatch":              {RunStatus: RunRefusedStream, IdleTimeout: DefaultIdleTimeout},
	"openid-ssf-receiver-access-token-expiry":                 {RunStatus: RunFinished, IdleTimeout: PausingIdleTimeout},
	"openid-ssf-receiver-transmitter-initiated-status-change": {RunStatus: RunFinished, IdleTimeout: PausingIdleTimeout},
}

// ExpectationForModule is the expectation for a module, by its name.
func ExpectationForModule(moduleName string) ModuleExpectation {
	expectation := ModuleExpectation{RunStatus: RunFinished, IdleTimeout: DefaultIdleTimeout}
	if outcome, ok := moduleOutcomes[moduleName]; ok {
		expectation = outcome
	}
	expectation.Scenario = ScenarioForModule(moduleName)
	return expectation
}
