package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
)

// RunView is a Run as the API shows it.
type RunView struct {
	ID           string        `json:"id"`
	Scenario     string        `json:"scenario"`
	Issuer       string        `json:"issuer"`
	Delivery     string        `json:"delivery"`
	Status       RunStatus     `json:"status"`
	StreamID     string        `json:"streamId,omitempty"`
	StartedAt    time.Time     `json:"startedAt"`
	Log          []LogEntry    `json:"log"`
	ReceivedSets []ReceivedSet `json:"receivedSets"`
}

// ViewOf is the view of a run.
func ViewOf(run *Run) RunView {
	return RunView{ID: run.ID(), Scenario: run.Scenario().Alias(), Issuer: run.Issuer(), Delivery: run.Delivery().String(), Status: run.Status(),
		StreamID: run.StreamID(), StartedAt: run.StartedAt(), Log: run.Log(), ReceivedSets: run.ReceivedSets()}
}

// ModuleRunView is a run started for the module waiting in the suite.
type ModuleRunView struct {
	Module Module  `json:"module"`
	Run    RunView `json:"run"`
}

const usage = `easyssf receiver under test for the OpenID conformance suite
POST /cts/runs/auto                  start the run the test module waiting in the suite expects
     ?issuer=<issuer>                optional: a test instance of the suite, default the configured issuer
GET  /cts/suite/modules              the test modules running in the suite and the scenario each gets
POST /cts/runs?scenario=<scenario>   start a run (stops the current one), scenarios: %v
     &issuer=<issuer>                optional: the test instance of the suite, default the configured issuer
     &delivery=push|poll             optional: default the configured delivery
GET  /cts/runs/current               what the current run did so far
POST /cts/runs/current/stop          stop the current run and delete its stream
POST /ssf/push                       push endpoint for the suite
`

// Handler is the HTTP API of the receiver under test: starts test runs and receives the SETs
// the suite pushes. The CtsController of the Java receiver.
func Handler(runner *Runner, modules *SuiteModules) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		names := make([]string, 0, len(Scenarios))
		for _, scenario := range Scenarios {
			names = append(names, scenario.Alias())
		}
		fmt.Fprintf(w, usage, names)
	})
	mux.HandleFunc("POST /cts/runs", func(w http.ResponseWriter, r *http.Request) {
		scenarioName := r.URL.Query().Get("scenario")
		if scenarioName == "" {
			scenarioName = CaepInterop.Alias()
		}
		scenario, err := ScenarioFromAlias(scenarioName)
		if err != nil {
			problem(w, http.StatusBadRequest, err.Error())
			return
		}
		var delivery ssf.DeliveryMethod
		if name := r.URL.Query().Get("delivery"); name != "" {
			switch strings.ToLower(name) {
			case "push":
				delivery = ssf.Push
			case "poll":
				delivery = ssf.Poll
			default:
				problem(w, http.StatusBadRequest, "delivery must be push or poll")
				return
			}
		}
		// detached from the request: the run outlives the response
		run, err := runner.Start(context.WithoutCancel(r.Context()), scenario, r.URL.Query().Get("issuer"), delivery, 0)
		if err != nil {
			problem(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, ViewOf(run))
	})
	mux.HandleFunc("POST /cts/runs/auto", func(w http.ResponseWriter, r *http.Request) {
		instance, err := modules.TestInstance(r.URL.Query().Get("issuer"))
		if err != nil {
			problem(w, http.StatusBadRequest, err.Error())
			return
		}
		waiting, err := modules.Waiting(r.Context(), instance)
		if err != nil {
			problem(w, http.StatusBadGateway, err.Error())
			return
		}
		if len(waiting) == 0 {
			problem(w, http.StatusNotFound, "No test module is waiting for the receiver in the conformance suite at "+instance.Suite+"; start one there first")
			return
		}
		if len(waiting) > 1 {
			var names []string
			for _, module := range waiting {
				names = append(names, module.Name+" ("+module.Issuer+")")
			}
			problem(w, http.StatusConflict, "Several test modules are waiting for the receiver: "+strings.Join(names, ", ")+"; pick one with ?issuer=<issuer>")
			return
		}
		module := waiting[0]
		delivery, _ := module.DeliveryMethod()
		scenario, _ := ScenarioFromAlias(module.Scenario)
		run, err := runner.Start(context.WithoutCancel(r.Context()), scenario, module.Issuer, delivery, 0)
		if err != nil {
			problem(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, ModuleRunView{Module: module, Run: ViewOf(run)})
	})
	mux.HandleFunc("GET /cts/suite/modules", func(w http.ResponseWriter, r *http.Request) {
		instance, err := modules.TestInstance(r.URL.Query().Get("issuer"))
		if err != nil {
			problem(w, http.StatusBadRequest, err.Error())
			return
		}
		running, err := modules.Running(r.Context(), instance)
		if err != nil {
			problem(w, http.StatusBadGateway, err.Error())
			return
		}
		if running == nil {
			running = []Module{}
		}
		writeJSON(w, http.StatusOK, running)
	})
	mux.HandleFunc("GET /cts/runs/current", func(w http.ResponseWriter, r *http.Request) {
		run := runner.Current()
		if run == nil {
			problem(w, http.StatusNotFound, "No run was started yet")
			return
		}
		writeJSON(w, http.StatusOK, ViewOf(run))
	})
	mux.HandleFunc("POST /cts/runs/current/stop", func(w http.ResponseWriter, r *http.Request) {
		run := runner.Current()
		if run == nil {
			problem(w, http.StatusNotFound, "No run was started yet")
			return
		}
		run.Stop()
		writeJSON(w, http.StatusOK, ViewOf(run))
	})
	mux.HandleFunc("POST /ssf/push", func(w http.ResponseWriter, r *http.Request) {
		run := runner.Current()
		if run == nil || !run.IsActive() {
			w.Header().Set("Content-Type", receiver.PushContentType)
			w.Header().Set("Content-Language", receiver.PushContentLanguage)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"err":"invalid_request","description":"No conformance run is active"}`))
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, receiver.MaxSETSize+1))
		if err != nil && !errors.Is(err, io.EOF) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response := run.Push(r.Context(), r.Header.Get("Authorization"), body)
		if response.Body != nil {
			w.Header().Set("Content-Type", receiver.PushContentType)
			w.Header().Set("Content-Language", receiver.PushContentLanguage)
		}
		w.WriteHeader(response.Status)
		if response.Body != nil {
			_, _ = w.Write(response.Body)
		}
	})
	return mux
}

func problem(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"status": status, "message": message})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
