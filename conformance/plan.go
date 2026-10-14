package conformance

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed suite-config/*.json
var suiteConfigs embed.FS

// PlanDefinition is a receiver test plan of the OpenID conformance suite, with the variant and
// the configuration (in suite-config/) the tests create it with. All of them use
// ssf_auth_mode=dynamic and client_auth_type=client_secret_basic.
type PlanDefinition struct {
	// Name is the name of the test plan in the suite.
	Name string
	// DeliveryMode is push or poll.
	DeliveryMode string
	// ConfigFile is the name of the suite configuration file in suite-config/.
	ConfigFile string
}

// The four plans.
var (
	SSF10Push         = PlanDefinition{"openid-ssf-receiver-test-plan", "push", "receiver-ssf1.0-push.json"}
	SSF10Poll         = PlanDefinition{"openid-ssf-receiver-test-plan", "poll", "receiver-ssf1.0-poll.json"}
	CaepInterop10Push = PlanDefinition{"openid-ssf-receiver-caep-test-plan", "push", "receiver-ssf1.0-caepiop1.0-push.json"}
	CaepInterop10Poll = PlanDefinition{"openid-ssf-receiver-caep-test-plan", "poll", "receiver-ssf1.0-caepiop1.0-poll.json"}
)

// Plans are the four plans.
var Plans = []PlanDefinition{SSF10Push, SSF10Poll, CaepInterop10Push, CaepInterop10Poll}

// Variant is the variant the plan is created with.
func (p PlanDefinition) Variant() map[string]string {
	return map[string]string{"ssf_delivery_mode": p.DeliveryMode, "ssf_auth_mode": "dynamic", "client_auth_type": "client_secret_basic"}
}

// Config is the suite configuration of the plan, and its alias.
func (p PlanDefinition) Config() (config json.RawMessage, alias string, err error) {
	data, err := suiteConfigs.ReadFile("suite-config/" + p.ConfigFile)
	if err != nil {
		return nil, "", err
	}
	var parsed struct {
		Alias string `json:"alias"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, "", fmt.Errorf("%s: %w", p.ConfigFile, err)
	}
	if parsed.Alias == "" {
		return nil, "", fmt.Errorf("%s has no alias", p.ConfigFile)
	}
	return data, parsed.Alias, nil
}

// SuiteConfig is the suite configuration with the given file name, for example
// easyssf-receiver.json, the one of the manual runs.
func SuiteConfig(name string) ([]byte, error) { return suiteConfigs.ReadFile("suite-config/" + name) }
