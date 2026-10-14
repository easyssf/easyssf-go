package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/easyssf/easyssf-go/ssf"
)

// SuiteModules looks up the test modules running in the conformance suite, so that a run can be
// started for the module that waits for the receiver without knowing its name. The suite is the
// one the transmitter issuer belongs to: a test instance is <suite>/test/a/<alias>. Its API
// (/api/runner/running, /api/info/<id>) needs no login with the suite's dev profile, as the
// local suite runs it.
type SuiteModules struct {
	settings ReceiverSettings
	client   *http.Client
}

// NewSuiteModules looks up modules with client, which has to trust the suite's certificate.
func NewSuiteModules(settings ReceiverSettings, client *http.Client) *SuiteModules {
	return &SuiteModules{settings: settings, client: client}
}

// Waiting is the status of a module that waits for the receiver to act.
const Waiting = "WAITING"

// Module is a test module running in the suite.
type Module struct {
	// ID is the id of the module in the suite.
	ID string `json:"id"`
	// Name is the name of the test module, e.g. openid-ssf-receiver-stream-create-delete.
	Name string `json:"name"`
	// Alias is the alias of the test instance the module runs under.
	Alias string `json:"alias"`
	// Status is the status reported by the suite; WAITING means it waits for the receiver.
	Status string `json:"status"`
	// Delivery is the delivery mode of the module's variant, "" if it has none.
	Delivery string `json:"delivery,omitempty"`
	// Issuer is the transmitter issuer the receiver has to use for this module.
	Issuer string `json:"issuer"`
	// Scenario is the scenario the receiver plays for the module.
	Scenario string `json:"scenario"`
	// LogURL is the suite's log page of the module.
	LogURL string `json:"logUrl"`
}

// IsWaiting reports whether the module waits for the receiver.
func (m Module) IsWaiting() bool { return m.Status == Waiting }

// DeliveryMethod is the delivery method of the module's variant; ok is false if it has none.
func (m Module) DeliveryMethod() (ssf.DeliveryMethod, bool) {
	switch strings.ToLower(m.Delivery) {
	case "push":
		return ssf.Push, true
	case "poll":
		return ssf.Poll, true
	}
	return 0, false
}

// TestInstance is the suite and the alias a transmitter issuer refers to.
type TestInstance struct {
	// Suite is the URL of the suite, with a trailing slash.
	Suite string
	Alias string
}

var testInstancePattern = regexp.MustCompile(`^(https?://.+?)/test/a/([^/?#]+)/?$`)

// ParseTestInstance parses a transmitter issuer of the form <suite>/test/a/<alias>.
func ParseTestInstance(issuer string) (TestInstance, error) {
	match := testInstancePattern.FindStringSubmatch(strings.TrimSpace(issuer))
	if match == nil {
		return TestInstance{}, fmt.Errorf("the transmitter issuer %q is not a test instance of the conformance suite (<suite>/test/a/<alias>)", issuer)
	}
	return TestInstance{Suite: match[1] + "/", Alias: match[2]}, nil
}

// Issuer is the issuer of the test instance with the given alias in the same suite.
func (i TestInstance) Issuer(alias string) string { return i.Suite + "test/a/" + alias }

// TestInstance is the test instance of the given issuer, or of the configured one if it is "".
func (m *SuiteModules) TestInstance(issuer string) (TestInstance, error) {
	if strings.TrimSpace(issuer) == "" {
		issuer = m.settings.Issuer
		if issuer == "" {
			return TestInstance{}, fmt.Errorf("the transmitter issuer must be set when no issuer is given")
		}
	}
	return ParseTestInstance(issuer)
}

// Running are all modules currently running in the suite, in the order the suite lists them.
func (m *SuiteModules) Running(ctx context.Context, instance TestInstance) ([]Module, error) {
	var ids []string
	if err := m.get(ctx, instance.Suite+"api/runner/running", &ids); err != nil {
		return nil, err
	}
	modules := make([]Module, 0, len(ids))
	for _, id := range ids {
		var info map[string]any
		if err := m.get(ctx, instance.Suite+"api/info/"+url.PathEscape(id), &info); err != nil {
			return nil, err
		}
		modules = append(modules, moduleOf(instance, id, info))
	}
	return modules, nil
}

// Waiting are the modules waiting for the receiver that a run should be started for: the ones
// running under the alias of the test instance, or, if there is none, all waiting modules of
// the suite (another alias than configured may have been used to create the plan).
func (m *SuiteModules) Waiting(ctx context.Context, instance TestInstance) ([]Module, error) {
	running, err := m.Running(ctx, instance)
	if err != nil {
		return nil, err
	}
	var waiting, ofInstance []Module
	for _, module := range running {
		if !module.IsWaiting() {
			continue
		}
		waiting = append(waiting, module)
		if module.Alias == instance.Alias {
			ofInstance = append(ofInstance, module)
		}
	}
	if len(ofInstance) > 0 {
		return ofInstance, nil
	}
	return waiting, nil
}

func moduleOf(instance TestInstance, id string, info map[string]any) Module {
	name, _ := info["testName"].(string)
	alias, _ := info["alias"].(string)
	if alias == "" {
		alias = instance.Alias
	}
	status, _ := info["status"].(string)
	variant, _ := info["variant"].(map[string]any)
	delivery, _ := variant["ssf_delivery_mode"].(string)
	return Module{ID: id, Name: name, Alias: alias, Status: status, Delivery: delivery, Issuer: instance.Issuer(alias),
		Scenario: ScenarioForModule(name).Alias(), LogURL: instance.Suite + "log-detail.html?log=" + id}
}

func (m *SuiteModules) get(ctx context.Context, target string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		return fmt.Errorf("the conformance suite could not be reached at %s: %w", target, err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("the conformance suite API %s returned HTTP %d: %s", target, response.StatusCode, body)
	}
	return json.Unmarshal(body, into)
}
