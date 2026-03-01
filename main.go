package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/kelseyhightower/envconfig"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// PolicyEngine holds the compiled policy and data
type PolicyEngine struct {
	mu    sync.RWMutex
	query rego.PreparedEvalQuery

	PolicyFilePath string `envconfig:"POLICY_FILE_PATH" default:"policy.rego"`
	DataFilePath   string `envconfig:"DATA_FILE_PATH" default:"data.json"`
	QueryString    string `envconfig:"QUERY_STRING" default:"data.caddy.allow"`

	AgentHeader    string `envconfig:"AGENT_HEADER" default:"X-Auth-Request-Email"`
	ResourceHeader string `envconfig:"RESOURCE_HEADER" default:"X-App-ID"`

	Port string `envconfig:"PORT" default:":8080"`
}

func (pe *PolicyEngine) load() error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	fmt.Println("loading policy and data...")

	policyCode, err := os.ReadFile(pe.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("reading policy file: %w", err)
	}

	dataFile, err := os.ReadFile(pe.DataFilePath)
	if err != nil {
		return fmt.Errorf("reading data file: %w", err)
	}

	var values map[string]interface{}
	if err := json.Unmarshal(dataFile, &values); err != nil {
		return fmt.Errorf("parsing data json: %w", err)
	}
	store := inmem.NewFromObject(values)

	ctx := context.Background()
	q, err := rego.New(
		rego.Query(pe.QueryString),
		rego.Module(pe.PolicyFilePath, string(policyCode)),
		rego.Store(store),
	).PrepareForEval(ctx)

	if err != nil {
		return fmt.Errorf("compiling policy: %w", err)
	}

	pe.query = q
	fmt.Println("policy loaded successfully.")
	return nil
}

func (pe *PolicyEngine) checkAuth(w http.ResponseWriter, r *http.Request) {
	agent := r.Header.Get(pe.AgentHeader)
	resource := r.Header.Get(pe.ResourceHeader)

	if agent == "" || resource == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	input := map[string]interface{}{
		"agent":    agent,
		"resource": resource,
	}

	pe.mu.RLock()
	results, err := pe.query.Eval(r.Context(), rego.EvalInput(input))
	pe.mu.RUnlock()

	if err != nil {
		fmt.Printf("Error evaluating policy: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if len(results) > 0 {
		allowed, ok := results[0].Expressions[0].Value.(bool)
		if ok && allowed {
			fmt.Printf("access granted, agent: %s, resource: %s", agent, resource)
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	fmt.Printf("access denied, agent: %s, resource: %s", agent, resource)
	http.Error(w, "Forbidden", http.StatusForbidden)
}

func main() {
	engine := PolicyEngine{}
	err := envconfig.Process("", &engine)
	if err != nil {
		log.Fatal(err.Error())
	}
	err = engine.load()
	if err != nil {
		log.Fatal(err.Error())
	}

	http.HandleFunc("/", engine.checkAuth)
	fmt.Printf("bridge service listening on: %s", engine.Port)
	log.Fatal(http.ListenAndServe(engine.Port, nil))
}
