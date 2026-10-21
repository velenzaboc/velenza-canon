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

func TestResolveConfigPathHonorsVelenzaCanonConfigAndFallback(t *testing.T) {
	env := map[string]string{
		"VELENZA_CANON_CONFIG": "/etc/velenza/canon.json",
		"SPEC_GRAPH_CONFIG":    "/etc/velenza/legacy-spec-graph.json",
	}
	got := resolveConfigPath(func(k string) string { return env[k] })
	if got != "/etc/velenza/canon.json" {
		t.Fatalf("resolveConfigPath with VELENZA_CANON_CONFIG = %q, want /etc/velenza/canon.json", got)
	}

	delete(env, "VELENZA_CANON_CONFIG")
	got = resolveConfigPath(func(k string) string { return env[k] })
	if got != "/etc/velenza/legacy-spec-graph.json" {
		t.Fatalf("resolveConfigPath fallback to SPEC_GRAPH_CONFIG = %q, want /etc/velenza/legacy-spec-graph.json", got)
	}

	delete(env, "SPEC_GRAPH_CONFIG")
	got = resolveConfigPath(func(k string) string { return env[k] })
	if got != "spec-graph.config.json" {
		t.Fatalf("resolveConfigPath default = %q, want spec-graph.config.json", got)
	}
}

func TestOpenSourceExampleConfigsHaveZeroInternalLiteralsAndValidate(t *testing.T) {
	exampleFiles := []string{
		"velenza-canon.config.example.json",
		"spec-graph.config.bootstrap.example.json",
		"spec-graph.config.production.example.json",
	}
	forbidden := []string{
		"je" + "eves-" + "486" + "102",
		"je" + "eves-rg-spanner-prod-" + "4d" + "0e4c43",
		"no" + "13productions",
		"no" + "13core",
		"no" + "13-infra",
		"meri" + "dian-staging",
		"/Users/bra" + "ndon",
	}

	for _, path := range exampleFiles {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			raw := string(data)
			for _, lit := range forbidden {
				if strings.Contains(raw, lit) {
					t.Errorf("%s contains internal literal %q", path, lit)
				}
			}
			if err := gcpauth.ValidateConfigCredentialShape(data); err != nil {
				t.Fatalf("%s credential shape error: %v", path, err)
			}
			var cfg SpecGraphConfig
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatalf("%s unmarshal error: %v", path, err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("%s Validate() error: %v", path, err)
			}
		})
	}
}

func TestScanSpecCodeTraceabilityDetectsCoveredUncoveredAndDanglingAnnotations(t *testing.T) {
	tmp := t.TempDir()
	specDir := filepath.Join(tmp, "specs")
	codeDir := filepath.Join(tmp, "code")
	if err := os.MkdirAll(specDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(codeDir, "pkg", "engine"), 0o755); err != nil {
		t.Fatal(err)
	}

	spec1 := `{
  "doc_id": "DOC-ARBOR-001",
  "title": "Arbor Graft Integrity Specification",
  "sections": {
    "s1_graft_seal": {
      "rule": "Every graft seal must verify BLAKE3 content hashes before admission."
    },
    "s2_vascular_flow": {
      "rule": "Cambium edges must link to valid symbol hashes."
    },
    "s3_unimplemented_clause": {
      "rule": "Future distributed federation clause."
    }
  }
}`
	if err := os.WriteFile(filepath.Join(specDir, "ARBOR_GRAFT_v1.ood.json"), []byte(spec1), 0o600); err != nil {
		t.Fatal(err)
	}

	code1 := `package engine

// VerifySeal implements the graft seal verification requirement.
// //spec:DOC-ARBOR-001#s1_graft_seal
// //volt:arbor.graft.verify_seal
func VerifySeal() bool {
	return true
}

// FlowCheck links via spec prefix stem.
// //spec:arbor_graft#s2_vascular_flow.rule
func FlowCheck() {}

// BrokenRef references a non-existent spec section.
// //spec:DOC-ARBOR-001#s99_nonexistent
func BrokenRef() {}
`
	if err := os.WriteFile(filepath.Join(codeDir, "pkg", "engine", "engine.go"), []byte(code1), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := ScanSpecCodeTraceability(specDir, codeDir)
	if err != nil {
		t.Fatalf("ScanSpecCodeTraceability failed: %v", err)
	}
	if report.SpecsScanned != 1 {
		t.Fatalf("SpecsScanned = %d, want 1", report.SpecsScanned)
	}
	if report.TotalSections != 3 {
		t.Fatalf("TotalSections = %d, want 3", report.TotalSections)
	}
	if report.CoveredSections != 2 {
		t.Fatalf("CoveredSections = %d, want 2", report.CoveredSections)
	}
	if len(report.UncoveredSections) != 1 || report.UncoveredSections[0].SectionID != "s3_unimplemented_clause" {
		t.Fatalf("UncoveredSections = %+v, want [s3_unimplemented_clause]", report.UncoveredSections)
	}
	if len(report.DanglingAnnotations) != 1 || report.DanglingAnnotations[0].Target != "DOC-ARBOR-001#s99_nonexistent" {
		t.Fatalf("DanglingAnnotations = %+v, want [DOC-ARBOR-001#s99_nonexistent]", report.DanglingAnnotations)
	}
	if len(report.VoltAnnotations) != 1 || report.VoltAnnotations[0].Target != "arbor.graft.verify_seal" {
		t.Fatalf("VoltAnnotations = %+v, want [arbor.graft.verify_seal]", report.VoltAnnotations)
	}
}

func TestCmdTraceCodeCLIOutputsJSONAndEnforcesFailOnDanglingFlag(t *testing.T) {
	tmp := t.TempDir()
	specDir := filepath.Join(tmp, "specs")
	codeDir := filepath.Join(tmp, "code")
	if err := os.MkdirAll(specDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(codeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	specJSON := `{
  "doc_id": "DOC-CLI-001",
  "sections": {
    "s1_core": { "rule": "Core requirement." }
  }
}`
	if err := os.WriteFile(filepath.Join(specDir, "CLI_SPEC_v1.ood.json"), []byte(specJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	codeSrc := `package main
// //spec:DOC-CLI-001#s1_core
func core() {}
`
	if err := os.WriteFile(filepath.Join(codeDir, "main.go"), []byte(codeSrc), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := runTraceCodeCLI(context.Background(), []string{"--spec-dir", specDir, "--code-dir", codeDir, "--fail-on-dangling"}, &out)
	if err != nil {
		t.Fatalf("runTraceCodeCLI unexpected error: %v", err)
	}
	var report SpecCodeTraceabilityReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal CLI output: %v (raw: %s)", err, out.String())
	}
	if report.CoveredSections != 1 || len(report.DanglingAnnotations) != 0 {
		t.Fatalf("unexpected CLI report: %+v", report)
	}

	// Add a dangling annotation and verify --fail-on-dangling returns a non-nil error.
	danglingCode := codeSrc + "\n// //spec:DOC-CLI-001#s2_missing\nfunc broken() {}\n"
	if err := os.WriteFile(filepath.Join(codeDir, "main.go"), []byte(danglingCode), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err = runTraceCodeCLI(context.Background(), []string{"--spec-dir", specDir, "--code-dir", codeDir, "--fail-on-dangling"}, &out)
	if err == nil || !strings.Contains(err.Error(), "dangling") {
		t.Fatalf("runTraceCodeCLI with --fail-on-dangling err = %v, want dangling error", err)
	}
}

// REQ-CANON-ARBOR-INFO: BuildCanonArborDescriptor and runArborInfoCLI emit the Layer 2 Velenza Arbor descriptor.
func TestCanonArborInfoCLI(t *testing.T) {
	desc := BuildCanonArborDescriptor()
	if desc.Layer != 2 {
		t.Fatalf("Layer = %d, want 2", desc.Layer)
	}
	if desc.CanonicalName != "velenza-canon" {
		t.Fatalf("CanonicalName = %q, want velenza-canon", desc.CanonicalName)
	}
	if desc.CompatAlias != "spec-graph" {
		t.Fatalf("CompatAlias = %q, want spec-graph", desc.CompatAlias)
	}

	wantEnv := []string{
		"VELENZA_CANON_CONFIG",
		"SPEC_GRAPH_CONFIG",
		"ARBOR_GCP_PROJECT",
		"ARBOR_SPANNER_INSTANCE",
	}
	for _, k := range wantEnv {
		found := false
		for _, v := range desc.ConfigEnvVars {
			if v == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ConfigEnvVars %v missing %q", desc.ConfigEnvVars, k)
		}
	}

	var buf bytes.Buffer
	if err := runArborInfoCLI(nil, &buf); err != nil {
		t.Fatalf("runArborInfoCLI error: %v", err)
	}
	var parsed CanonArborDescriptor
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("json.Unmarshal arbor-info output: %v", err)
	}
	if parsed.CanonicalName != "velenza-canon" || parsed.Layer != 2 {
		t.Fatalf("parsed = %+v, want velenza-canon layer 2", parsed)
	}
}

// REQ-CANON-OPEN-SOURCE-HYGIENE: LICENSE and README.md are open-source ready with zero hardcoded developer paths.
func TestCanonOpenSourceLicenseAndReadmeHygiene(t *testing.T) {
	licBytes, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatalf("LICENSE file must exist at repository root: %v", err)
	}
	lic := string(licBytes)
	if !strings.Contains(lic, "Apache License") || !strings.Contains(lic, "Version 2.0") {
		t.Fatalf("LICENSE must be Apache-2.0")
	}

	readmeBytes, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readme := string(readmeBytes)
	for _, forbidden := range []string{"/Users/bra" + "ndon", "je" + "eves-" + "486" + "102", "je" + "eves-rg-spanner-prod-" + "4d" + "0e4c43"} {
		if strings.Contains(readme, forbidden) {
			t.Errorf("README.md contains forbidden internal path/ID %q", forbidden)
		}
	}
	for _, required := range []string{"velenza-canon", "arbor-info", "trace-code", "Velenza Arbor Stack"} {
		if !strings.Contains(readme, required) {
			t.Errorf("README.md missing documentation for %q", required)
		}
	}
}

// REQ-CANON-OPEN-SOURCE-REPO-HYGIENE: Every tracked/source file across the repository
// (including tests, docs, SQL schemas, CI workflows, and scripts) is free of internal
// infrastructure identifiers, workstation paths, and legacy repo coordinates.
func TestOpenSourceHygiene(t *testing.T) {
	for _, requiredDoc := range []string{"LICENSE", "NOTICE", "CONTRIBUTING.md"} {
		info, err := os.Stat(requiredDoc)
		if err != nil {
			t.Fatalf("required open-source file %s missing: %v", requiredDoc, err)
		}
		if info.Size() == 0 {
			t.Fatalf("required open-source file %s is empty", requiredDoc)
		}
	}

	forbiddenCaseInsensitive := []string{
		"je" + "eves",
		"486" + "102",
		"4d0" + "e4c43",
		"no" + "13",
		"ini" + "tech",
		"ba" + "os",
		"meri" + "dian",
		"rag" + "gedy",
		"ko" + "pia",
		"velenza-" + "core",
		"kernel-" + "staging",
		"fleet-" + "plan",
		"arc-" + "runner",
		"ar" + "cserver",
		"ar" + "crunner",
		"ma" + "cmini",
		"ma" + "cbook",
		"bra" + "ndon",
		"open" + "scion",
		"296" + "5825",
		"rg_workflow_" + "app_key",
		"100." + "86.",
		"100." + "104.",
		"100." + "110.",
		"100." + "101.",
		"100." + "66.",
		"velenzaboc/" + "code-graph",
		"velenzaboc/" + "spec-graph",
		"velenzaboc/" + "task-graph",
	}

	skipNames := map[string]bool{
		".git":                   true,
		"bin":                    true,
		"_canonical":             true,
		".DS_Store":              true,
		"spec-graph.config.json": true,
	}

	err := filepath.WalkDir(".", func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := d.Name()
		if skipNames[name] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lower := strings.ToLower(string(data))
		for _, token := range forbiddenCaseInsensitive {
			if strings.Contains(lower, token) {
				t.Errorf("%s contains forbidden internal identifier %q", path, token)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}
}


