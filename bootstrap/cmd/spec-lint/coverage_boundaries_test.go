package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
)

func TestRunRefusesInvalidInvocationBeforeAnyCloudClient(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.json")
	if err := os.WriteFile(input, []byte(`{"node_kind":"axiom","stable_id":"fixture"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeConfig := func(name string, value interface{}) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	validCredentials := map[string]interface{}{
		"credentials_source":   gcpauth.CredentialsSourceApplicationDefault,
		"credentials_profile":  gcpauth.CredentialsProfileImpersonatedServiceAccount,
		"credentials_identity": "spec-lint-fixture@fixture-project.iam.gserviceaccount.com",
	}
	validFlash := map[string]interface{}{
		"provider": "vertex_ai", "project": "fixture-project", "location": "us-central1", "model": "gemini-2.0-flash",
		"max_output_tokens": 128, "temperature": 0.1, "prompts": map[string]interface{}{"r6_prose_check_path": "fixture-r6.txt"},
	}
	withoutFlash := writeConfig("without-flash.json", map[string]interface{}{"mode": "experimental_bootstrap", "google_credentials": validCredentials})
	badCredentials := writeConfig("bad-credentials.json", map[string]interface{}{"mode": "experimental_bootstrap", "pipeline": map[string]interface{}{"flash": validFlash}})
	badFlash := writeConfig("bad-flash.json", map[string]interface{}{"mode": "experimental_bootstrap", "google_credentials": validCredentials, "pipeline": map[string]interface{}{"flash": map[string]interface{}{"provider": "other"}}})

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"missing required flags", nil, "--config and --input are required"},
		{"unknown flag", []string{"--unknown"}, "flag provided but not defined"},
		{"missing config", []string{"--config", filepath.Join(dir, "missing.json"), "--input", input}, "read config"},
		{"missing input", []string{"--config", withoutFlash, "--input", filepath.Join(dir, "missing-input.json")}, "load submissions"},
		{"flash required", []string{"--config", withoutFlash, "--input", input}, "pipeline.flash required"},
		{"credential topology", []string{"--config", badCredentials, "--input", input}, "google credentials invalid"},
		{"flash contract", []string{"--config", badFlash, "--input", input}, "pipeline.flash invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("run(%v) code=%d stdout=%q stderr=%q, want invocation refusal %q", tc.args, code, stdout.String(), stderr.String(), tc.want)
			}
		})
	}
}

func TestRunWithFlashGeneratorPublishesPassFailAndFactoryRefusals(t *testing.T) {
	dir := t.TempDir()
	prompt := filepath.Join(dir, "r6.txt")
	if err := os.WriteFile(prompt, []byte("VERDICT: {{value}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	config := map[string]interface{}{
		"mode": "experimental_bootstrap",
		"google_credentials": map[string]interface{}{
			"credentials_source":   gcpauth.CredentialsSourceApplicationDefault,
			"credentials_profile":  gcpauth.CredentialsProfileImpersonatedServiceAccount,
			"credentials_identity": "spec-lint-fixture@fixture-project.iam.gserviceaccount.com",
		},
		"node_kinds": []map[string]interface{}{{"name": "axiom"}},
		"pipeline": map[string]interface{}{"flash": map[string]interface{}{
			"provider": "vertex_ai", "project": "fixture-project", "location": "us-central1", "model": "gemini-2.0-flash",
			"max_output_tokens": 128, "temperature": 0.1, "prompts": map[string]interface{}{"r6_prose_check_path": prompt},
		}},
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	passInput := filepath.Join(dir, "pass.json")
	failInput := filepath.Join(dir, "fail.json")
	if err := os.WriteFile(passInput, []byte(`{"node_kind":"axiom","stable_id":"fixture"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(failInput, []byte(`{"node_kind":"unknown","stable_id":"fixture"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	factory := func(context.Context, *Config) (Generator, error) { return alwaysCleanGenerator{}, nil }
	var stdout, stderr bytes.Buffer
	if code := runWithFlashGenerator([]string{"--config", configPath, "--input", passInput, "--concept-domain", "fixture_domain"}, &stdout, &stderr, factory); code != 0 {
		t.Fatalf("pass run code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"verdict": "pass"`) || !strings.Contains(stdout.String(), `"concept_domain": "fixture_domain"`) {
		t.Fatalf("pass report=%q", stdout.String())
	}

	output := filepath.Join(dir, "findings.json")
	stdout.Reset()
	stderr.Reset()
	if code := runWithFlashGenerator([]string{"--config", configPath, "--input", failInput, "--output", output}, &stdout, &stderr, factory); code != 1 {
		t.Fatalf("fail run code=%d stderr=%q", code, stderr.String())
	}
	report, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || !strings.Contains(string(report), `"verdict": "fail"`) || !strings.Contains(string(report), "R3_kind_in_registry") {
		t.Fatalf("fail report stdout=%q report=%q", stdout.String(), report)
	}

	stderr.Reset()
	brokenFactory := func(context.Context, *Config) (Generator, error) { return nil, os.ErrPermission }
	if code := runWithFlashGenerator([]string{"--config", configPath, "--input", passInput}, &stdout, &stderr, brokenFactory); code != 2 || !strings.Contains(stderr.String(), "vertex client") {
		t.Fatalf("factory refusal code=%d stderr=%q", code, stderr.String())
	}
}

func TestLoadSubmissionsDirectoryOrdersJSONAndRejectsBrokenInputs(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("z.json", `{"node_kind":"axiom","stable_id":"z"}`)
	write("a.json", `{"node_kind":"section","stable_id":"a"}`)
	write("_findings.json", `{"node_kind":"audit_record","stable_id":"ignored"}`)
	write("notes.txt", `not a submission`)
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}

	subs, err := LoadSubmissions(dir)
	if err != nil {
		t.Fatalf("LoadSubmissions(directory): %v", err)
	}
	if len(subs) != 2 || subs[0].CanonicalName() != "a" || subs[1].CanonicalName() != "z" {
		t.Fatalf("directory loader must select and sort only submission JSON: %+v", subs)
	}
	if !strings.HasSuffix(subs[0].SourceFile, "a.json") || !strings.HasSuffix(subs[1].SourceFile, "z.json") {
		t.Fatalf("directory loader lost source attribution: %+v", subs)
	}

	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{"node_kind":`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOneFile(broken); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("broken submission error=%v, want attributed parse failure", err)
	}
	if _, err := LoadSubmissions(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing input was accepted")
	}
}

func TestLoadConceptTableAndFileShapeRejectMalformedDocuments(t *testing.T) {
	if _, err := loadConceptTable([]byte(`{"concepts":`), "broken-table.json"); err == nil || !strings.Contains(err.Error(), "parse ConceptTable broken-table.json") {
		t.Fatalf("malformed ConceptTable error=%v", err)
	}
	dir := t.TempDir()
	arrayPath := filepath.Join(dir, "array.json")
	if err := os.WriteFile(arrayPath, []byte(`[]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFromFileDetectShape(arrayPath); err == nil || !strings.Contains(err.Error(), "parse "+arrayPath) {
		t.Fatalf("non-object legacy input error=%v, want attributed submission parse failure", err)
	}
}

func validFlashConfig() *FlashConfig {
	return &FlashConfig{
		Provider: "vertex_ai", Project: "fixture-project", Location: "us-central1", Model: "gemini-2.0-flash",
		MaxOutputTokens: 256, Temperature: 0.2, Prompts: &FlashPromptsConfig{R6ProseCheckPath: "fixture-r6.txt"},
	}
}

func TestFlashConfigValidationRejectsEveryRequiredBoundary(t *testing.T) {
	if err := validFlashConfig().Validate(); err != nil {
		t.Fatalf("valid Flash config rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*FlashConfig)
		want   string
	}{
		{"provider", func(c *FlashConfig) { c.Provider = "" }, "provider required"},
		{"project", func(c *FlashConfig) { c.Project = "" }, "project required"},
		{"location", func(c *FlashConfig) { c.Location = "" }, "location required"},
		{"model", func(c *FlashConfig) { c.Model = "" }, "model required"},
		{"unsupported provider", func(c *FlashConfig) { c.Provider = "other" }, "must be vertex_ai"},
		{"output tokens", func(c *FlashConfig) { c.MaxOutputTokens = 0 }, "max_output_tokens"},
		{"negative temperature", func(c *FlashConfig) { c.Temperature = -0.1 }, "temperature"},
		{"high temperature", func(c *FlashConfig) { c.Temperature = 2.1 }, "temperature"},
		{"prompts", func(c *FlashConfig) { c.Prompts = nil }, "prompts required"},
		{"r6 prompt", func(c *FlashConfig) { c.Prompts.R6ProseCheckPath = "" }, "r6_prose_check_path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := *validFlashConfig()
			cfg.Prompts = &FlashPromptsConfig{R6ProseCheckPath: cfg.Prompts.R6ProseCheckPath}
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error=%v, want %q", err, tc.want)
			}
		})
	}
	if err := (*FlashConfig)(nil).Validate(); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil Flash config error=%v", err)
	}
}

func TestConfigAndIdentityHelpersPreserveClosedInputs(t *testing.T) {
	if err := (*Config)(nil).ValidateGoogleCredentialTopology(); err == nil {
		t.Fatal("nil config accepted")
	}
	for _, mode := range []string{"", "unrecognized"} {
		cfg := &Config{Mode: mode}
		if err := cfg.ValidateGoogleCredentialTopology(); err == nil {
			t.Fatalf("mode %q accepted", mode)
		}
	}
	cfg := &Config{Mode: "experimental_bootstrap", GoogleCredentials: gcpauth.Selector{
		CredentialsSource:   gcpauth.CredentialsSourceApplicationDefault,
		CredentialsProfile:  gcpauth.CredentialsProfileImpersonatedServiceAccount,
		CredentialsIdentity: "spec-lint-fixture@fixture-project.iam.gserviceaccount.com",
	}}
	if err := cfg.ValidateGoogleCredentialTopology(); err != nil {
		t.Fatalf("valid credential topology rejected: %v", err)
	}
	if got := (Submission{Contract: map[string]interface{}{"canonical_name": "from_contract"}}).CanonicalName(); got != "from_contract" {
		t.Fatalf("contract canonical name=%q", got)
	}
	if got := (Submission{Contract: map[string]interface{}{"canonical_err_name": "ErrFixture"}}).CanonicalName(); got != "ErrFixture" {
		t.Fatalf("sentinel canonical name=%q", got)
	}
	if got := (Submission{}).CanonicalName(); got != "" {
		t.Fatalf("empty canonical name=%q", got)
	}
	for _, rule := range AllRules() {
		if rule.Name() == "" {
			t.Fatalf("rule %T has no stable name", rule)
		}
	}
}

func TestLoadConfigRoundTripsAllowedShapeAndRejectsMalformedJSON(t *testing.T) {
	data, err := json.Marshal(map[string]interface{}{
		"mode": "experimental_bootstrap",
		"google_credentials": map[string]interface{}{
			"credentials_source":   gcpauth.CredentialsSourceApplicationDefault,
			"credentials_profile":  gcpauth.CredentialsProfileImpersonatedServiceAccount,
			"credentials_identity": "spec-lint-fixture@fixture-project.iam.gserviceaccount.com",
		},
		"node_kinds":  []map[string]interface{}{{"name": "axiom"}},
		"edge_labels": []map[string]interface{}{{"name": "depends_on"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(data)
	if err != nil {
		t.Fatalf("LoadConfig(valid): %v", err)
	}
	if cfg.KindByName("axiom") == nil || cfg.EdgeLabelByName("depends_on") == nil || cfg.KindByName("missing") != nil || cfg.EdgeLabelByName("missing") != nil {
		t.Fatalf("registry lookup mismatch: %+v", cfg)
	}
	if _, err := LoadConfig([]byte(`{"mode":`)); err == nil {
		t.Fatal("malformed config accepted")
	}
}
