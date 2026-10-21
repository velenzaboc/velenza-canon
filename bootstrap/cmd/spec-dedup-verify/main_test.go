package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

func TestRunPersistsRuntimeResultsWithoutVertex(t *testing.T) {
	dir := t.TempDir()
	cfg := validCredentialConfig()
	cfg.Pipeline = &PipelineConfig{Flash: validFlashConfig()}
	cfgPath, bucketsPath := filepath.Join(dir, "config.json"), filepath.Join(dir, "buckets.json")
	writeJSONFixture(t, cfgPath, cfg)
	writeJSONFixture(t, bucketsPath, &ClusterBuckets{ConceptDomain: "test"})
	old := verifyRuntime
	t.Cleanup(func() { verifyRuntime = old })
	verifyRuntime = func(_ context.Context, _ *Config, got *ClusterBuckets) (*DedupDecisions, *FlashLedger, error) {
		if got.ConceptDomain != "test" {
			t.Fatalf("buckets %#v", got)
		}
		return &DedupDecisions{ConceptDomain: "test"}, &FlashLedger{ConceptDomain: "test"}, nil
	}
	decisions, ledger := filepath.Join(dir, "decisions.json"), filepath.Join(dir, "ledger.json")
	code, err := run([]string{"--config", cfgPath, "--buckets", bucketsPath, "--output-decisions", decisions, "--output-ledger", ledger}, &bytes.Buffer{})
	if err != nil || code != 0 {
		t.Fatalf("run = %d, %v", code, err)
	}
	for _, path := range []string{decisions, ledger} {
		if data, err := os.ReadFile(path); err != nil || len(data) == 0 {
			t.Fatalf("%s: %q %v", path, data, err)
		}
	}
}

func TestRunPersistsPartialResultsAndClosesInvalidInputs(t *testing.T) {
	if code, err := run(nil, &bytes.Buffer{}); err == nil || code != 2 {
		t.Fatalf("missing = %d, %v", code, err)
	}
	dir := t.TempDir()
	cfg := validCredentialConfig()
	cfg.Pipeline = &PipelineConfig{Flash: validFlashConfig()}
	cfgPath, bucketsPath := filepath.Join(dir, "config.json"), filepath.Join(dir, "buckets.json")
	writeJSONFixture(t, cfgPath, cfg)
	writeJSONFixture(t, bucketsPath, &ClusterBuckets{})
	old := verifyRuntime
	t.Cleanup(func() { verifyRuntime = old })
	verifyRuntime = func(context.Context, *Config, *ClusterBuckets) (*DedupDecisions, *FlashLedger, error) {
		return &DedupDecisions{}, &FlashLedger{}, errors.New("provider unavailable")
	}
	code, err := run([]string{"--config", cfgPath, "--buckets", bucketsPath, "--output-decisions", filepath.Join(dir, "d.json"), "--output-ledger", filepath.Join(dir, "l.json")}, &bytes.Buffer{})
	if err == nil || code != 1 {
		t.Fatalf("partial = %d, %v", code, err)
	}
}

func TestVerifyWithVertexClosesUnavailableCredentialCarrier(t *testing.T) {
	cfg := validCredentialConfig()
	cfg.Pipeline = &PipelineConfig{Flash: validFlashConfig()}
	decisions, ledger, err := verifyWithVertex(context.Background(), cfg, &ClusterBuckets{ConceptDomain: "empty"})
	if err == nil || decisions != nil || ledger != nil {
		t.Fatalf("credential carrier must fail closed: %#v %#v %v", decisions, ledger, err)
	}
}

func TestVerifyWithVertexUsesInjectedFactoriesWithoutCalls(t *testing.T) {
	oldAuth, oldFlash := newVertexAuth, newFlashClient
	t.Cleanup(func() { newVertexAuth, newFlashClient = oldAuth, oldFlash })
	newVertexAuth = func(context.Context, vertexai.TokenSourceFactory) (*vertexai.Auth, error) {
		return &vertexai.Auth{}, nil
	}
	newFlashClient = func(auth *vertexai.Auth, cfg vertexai.FlashConfig) (*vertexai.FlashClient, error) {
		return vertexai.NewFlashClient(auth, cfg)
	}
	cfg := validCredentialConfig()
	cfg.Pipeline = &PipelineConfig{Flash: validFlashConfig()}
	decisions, ledger, err := verifyWithVertex(context.Background(), cfg, &ClusterBuckets{ConceptDomain: "empty"})
	if err != nil || decisions.ConceptDomain != "empty" || ledger.ConceptDomain != "empty" {
		t.Fatalf("empty setup %#v %#v %v", decisions, ledger, err)
	}
	newVertexAuth = func(context.Context, vertexai.TokenSourceFactory) (*vertexai.Auth, error) {
		return nil, errors.New("auth")
	}
	if _, _, err := verifyWithVertex(context.Background(), cfg, &ClusterBuckets{}); err == nil {
		t.Fatal("accepted auth failure")
	}
	newVertexAuth = func(context.Context, vertexai.TokenSourceFactory) (*vertexai.Auth, error) {
		return &vertexai.Auth{}, nil
	}
	newFlashClient = func(*vertexai.Auth, vertexai.FlashConfig) (*vertexai.FlashClient, error) {
		return nil, errors.New("endpoint")
	}
	if _, _, err := verifyWithVertex(context.Background(), cfg, &ClusterBuckets{}); err == nil {
		t.Fatal("accepted endpoint failure")
	}
}

func TestMainUsesReturnedExitCode(t *testing.T) {
	oldArgs, oldExit := os.Args, exit
	t.Cleanup(func() { os.Args, exit = oldArgs, oldExit })
	os.Args = []string{"spec-dedup-verify"}
	code := -1
	exit = func(got int) { code = got; panic("exit") }
	defer func() {
		if recover() == nil || code != 2 {
			t.Fatalf("exit %d", code)
		}
	}()
	main()
}

func TestLoadConfigAndFlashValidationCloseMalformedShapes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if _, err := LoadConfig(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("accepted missing config")
	}
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("accepted malformed config")
	}
	cfg := validCredentialConfig()
	cfg.Pipeline = &PipelineConfig{Flash: validFlashConfig()}
	writeJSONFixture(t, path, cfg)
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	for _, mutate := range []func(*FlashConfig){func(f *FlashConfig) { f.Provider = "other" }, func(f *FlashConfig) { f.Project = "" }, func(f *FlashConfig) { f.Prompts.SameConceptQueryPath = "" }} {
		f := *validFlashConfig()
		mutate(&f)
		if err := f.Validate(); err == nil {
			t.Fatal("accepted invalid flash config")
		}
	}
}

func TestRunClosesDecisionWriteFailure(t *testing.T) {
	dir := t.TempDir()
	cfg := validCredentialConfig()
	cfg.Pipeline = &PipelineConfig{Flash: validFlashConfig()}
	cfgPath, bucketsPath := filepath.Join(dir, "config.json"), filepath.Join(dir, "buckets.json")
	writeJSONFixture(t, cfgPath, cfg)
	writeJSONFixture(t, bucketsPath, &ClusterBuckets{})
	old := verifyRuntime
	t.Cleanup(func() { verifyRuntime = old })
	verifyRuntime = func(context.Context, *Config, *ClusterBuckets) (*DedupDecisions, *FlashLedger, error) {
		return &DedupDecisions{}, &FlashLedger{}, nil
	}
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, err := run([]string{"--config", cfgPath, "--buckets", bucketsPath, "--output-decisions", filepath.Join(blocker, "d.json"), "--output-ledger", filepath.Join(dir, "l.json")}, &bytes.Buffer{})
	if err == nil || code != 1 {
		t.Fatalf("write failure = %d, %v", code, err)
	}
}

func TestRunClosesLedgerWriteFailure(t *testing.T) {
	dir := t.TempDir()
	cfg := validCredentialConfig()
	cfg.Pipeline = &PipelineConfig{Flash: validFlashConfig()}
	cfgPath, bucketsPath := filepath.Join(dir, "config.json"), filepath.Join(dir, "buckets.json")
	writeJSONFixture(t, cfgPath, cfg)
	writeJSONFixture(t, bucketsPath, &ClusterBuckets{})
	old := verifyRuntime
	t.Cleanup(func() { verifyRuntime = old })
	verifyRuntime = func(context.Context, *Config, *ClusterBuckets) (*DedupDecisions, *FlashLedger, error) {
		return &DedupDecisions{}, &FlashLedger{}, nil
	}
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, err := run([]string{"--config", cfgPath, "--buckets", bucketsPath, "--output-decisions", filepath.Join(dir, "d.json"), "--output-ledger", filepath.Join(blocker, "l.json")}, &bytes.Buffer{})
	if err == nil || code != 1 {
		t.Fatalf("write failure = %d, %v", code, err)
	}
}

func writeJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
