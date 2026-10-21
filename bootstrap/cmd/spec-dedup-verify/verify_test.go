package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
)

// ---------------- Parse ----------------

func TestParseSameConcept_Yes(t *testing.T) {
	verdict, rationale, err := ParseSameConceptResponse("VERDICT: yes\nRATIONALE: same claim")
	if err != nil {
		t.Fatal(err)
	}
	if verdict != "yes" || rationale != "same claim" {
		t.Errorf("got verdict=%q rationale=%q", verdict, rationale)
	}
}

func TestParseSameConcept_No(t *testing.T) {
	verdict, _, err := ParseSameConceptResponse("VERDICT: no\nRATIONALE: different domains")
	if err != nil {
		t.Fatal(err)
	}
	if verdict != "no" {
		t.Errorf("got verdict=%q", verdict)
	}
}

func TestParseSameConcept_Uncertain(t *testing.T) {
	verdict, _, err := ParseSameConceptResponse("VERDICT: uncertain\nRATIONALE: ambiguous")
	if err != nil {
		t.Fatal(err)
	}
	if verdict != "uncertain" {
		t.Errorf("got verdict=%q", verdict)
	}
}

func TestParseSameConcept_BadVerdictRejected(t *testing.T) {
	if _, _, err := ParseSameConceptResponse("VERDICT: maybe\nRATIONALE: x"); err == nil {
		t.Error("expected error on non-yes/no/uncertain verdict")
	}
}

func TestParseSameConcept_MissingVerdictRejected(t *testing.T) {
	if _, _, err := ParseSameConceptResponse("RATIONALE: just rationale"); err == nil {
		t.Error("expected error on missing verdict")
	}
}

func TestParseSameConcept_CaseInsensitive(t *testing.T) {
	verdict, _, err := ParseSameConceptResponse("verdict: YES\nrationale: x")
	if err != nil {
		t.Fatal(err)
	}
	if verdict != "yes" {
		t.Errorf("got %q", verdict)
	}
}

func TestParseCanonicalName_Selected(t *testing.T) {
	name, _, proposed, err := ParseCanonicalNameResponse("NAME: gate_evaluation\nRATIONALE: concise")
	if err != nil {
		t.Fatal(err)
	}
	if name != "gate_evaluation" || proposed {
		t.Errorf("got name=%q proposed=%v", name, proposed)
	}
}

func TestParseCanonicalName_Proposed(t *testing.T) {
	name, _, proposed, err := ParseCanonicalNameResponse("NAME: PROPOSE: better_name\nRATIONALE: shorter")
	if err != nil {
		t.Fatal(err)
	}
	if name != "better_name" || !proposed {
		t.Errorf("got name=%q proposed=%v", name, proposed)
	}
}

func TestParseCanonicalName_MissingName(t *testing.T) {
	if _, _, _, err := ParseCanonicalNameResponse("RATIONALE: just rationale"); err == nil {
		t.Error("expected error on missing NAME line")
	}
}

// ---------------- Config ----------------

func validFlashConfig() *FlashConfig {
	return &FlashConfig{
		Provider:        "vertex_ai",
		Project:         "test-project",
		Location:        "us-central1",
		Model:           "gemini-2.0-flash",
		MaxOutputTokens: 200,
		Temperature:     0,
		Prompts: &FlashPromptsConfig{
			SameConceptQueryPath:       "/tmp/same.txt",
			CanonicalNameSelectionPath: "/tmp/canon.txt",
		},
	}
}

func TestConfig_RequiresPipelineFlashAndPrompts(t *testing.T) {
	missingPipeline := validCredentialConfig()
	missingFlash := validCredentialConfig()
	missingFlash.Pipeline = &PipelineConfig{}
	emptyFlash := validCredentialConfig()
	emptyFlash.Pipeline = &PipelineConfig{Flash: &FlashConfig{}}
	missingPrompts := validCredentialConfig()
	missingPrompts.Pipeline = &PipelineConfig{Flash: &FlashConfig{Provider: "vertex_ai", Project: "proj-x", Location: "us-central1", Model: "model-x", MaxOutputTokens: 100, Temperature: 0}}
	cases := []*Config{
		missingPipeline,
		missingFlash,
		emptyFlash,
		missingPrompts,
	}
	for i, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestConfig_ValidPasses(t *testing.T) {
	c := validCredentialConfig()
	c.Pipeline = &PipelineConfig{Flash: validFlashConfig()}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid config to pass, got %v", err)
	}
}

func validCredentialConfig() *Config {
	return &Config{
		Mode: "experimental_bootstrap",
		GoogleCredentials: gcpauth.Selector{
			CredentialsSource:   gcpauth.CredentialsSourceApplicationDefault,
			CredentialsProfile:  gcpauth.CredentialsProfileImpersonatedServiceAccount,
			CredentialsIdentity: "spec-graph-local@example-gcp-project.iam.gserviceaccount.com",
		},
	}
}

func TestFlashConfig_TemperatureBounds(t *testing.T) {
	cfg := *validFlashConfig()
	cfg.Temperature = -0.1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error on negative temperature")
	}
	cfg.Temperature = 2.5
	if err := cfg.Validate(); err == nil {
		t.Error("expected error on temperature > 2")
	}
}

func TestFlashConfig_MaxOutputTokensRequired(t *testing.T) {
	cfg := *validFlashConfig()
	cfg.MaxOutputTokens = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error on zero max_output_tokens")
	}
}

// ---------------- Prompt loading (read-every-call discipline) ----------------

// TestLoadAndRender_ReadsFreshEveryCall verifies that editing the
// template file between calls produces different rendered output. This
// is the load-bearing test for the directive's "read every call, no
// cache" rule.
func TestLoadAndRender_ReadsFreshEveryCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tmpl.txt")
	if err := os.WriteFile(path, []byte("v1: {{.X}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	out1, err := LoadAndRender(path, map[string]string{"X": "a"})
	if err != nil {
		t.Fatal(err)
	}
	if out1 != "v1: a" {
		t.Errorf("first render: got %q, want %q", out1, "v1: a")
	}
	// Mutate the file. Next call MUST observe the new contents.
	if err := os.WriteFile(path, []byte("v2: {{.X}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	out2, err := LoadAndRender(path, map[string]string{"X": "a"})
	if err != nil {
		t.Fatal(err)
	}
	if out2 != "v2: a" {
		t.Errorf("second render: got %q, want %q (cache leak?)", out2, "v2: a")
	}
}

func TestLoadAndRender_MissingFileErrors(t *testing.T) {
	if _, err := LoadAndRender("/nonexistent/path.txt", nil); err == nil {
		t.Error("expected error on missing template file")
	}
}

func TestLoadAndRender_SameConceptTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "same.txt")
	tmpl := "A: {{.StatementA}} B: {{.StatementB}} from {{.SourceA}}"
	if err := os.WriteFile(path, []byte(tmpl), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := LoadAndRender(path, SameConceptQueryData{
		StatementA: "a", StatementB: "b", SourceA: "src_a", SourceB: "src_b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out != "A: a B: b from src_a" {
		t.Errorf("got %q", out)
	}
}

// ---------------- VerifyAll orchestration (with mock Flash) ----------------

type mockGen struct {
	responses []string
	calls     int
	prompts   []string
}

func (m *mockGen) Generate(ctx context.Context, prompt string) (string, error) {
	m.prompts = append(m.prompts, prompt)
	if m.calls >= len(m.responses) {
		return "", nil
	}
	r := m.responses[m.calls]
	m.calls++
	return r, nil
}

func newTestPrompts(t *testing.T) *FlashPromptsConfig {
	t.Helper()
	dir := t.TempDir()
	sameP := filepath.Join(dir, "same.txt")
	canonP := filepath.Join(dir, "canon.txt")
	if err := os.WriteFile(sameP, []byte("A:{{.StatementA}} B:{{.StatementB}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canonP, []byte("S:{{.Statement}} C:{{range .Candidates}}{{.}},{{end}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &FlashPromptsConfig{SameConceptQueryPath: sameP, CanonicalNameSelectionPath: canonP}
}

func cr(path, val string) ConceptRecord {
	return ConceptRecord{SourceFile: "t.json", SourcePath: path, LeafName: "statement", RawValue: val}
}

// crWithLeaf is the constructor that exercises records sharing a
// source_path with different leaf_names — the shape that surfaced the
// identity-key bug fixed in fix/spec-dedup-verify-record-identity.
func crWithLeaf(path, leaf, val string) ConceptRecord {
	return ConceptRecord{SourceFile: "t.json", SourcePath: path, LeafName: leaf, RawValue: val}
}

// TestVerifyAll_DoesNotSkipSiblingConcept_SamePath_DifferentLeaf is
// the load-bearing regression test for the record-identity bug
// surfaced by the VOLT_SECRET_DETECTION Tier C pipeline run. Two
// distinct concepts can legitimately share a source_path (a section
// with multiple concept-bearing subkeys); the verify pass MUST use
// (source_file, source_path, leaf_name) as the identity key — NOT
// source_path alone — when skipping the representative. Pre-fix,
// the second record was wrongly skipped from Flash comparison and
// became invisible to the dedup decision.
func TestVerifyAll_DoesNotSkipSiblingConcept_SamePath_DifferentLeaf(t *testing.T) {
	cfg := validFlashConfig()
	cfg.Prompts = newTestPrompts(t)
	rep := crWithLeaf("sections.s1_section", "leaf_a", "value a")
	sibling := crWithLeaf("sections.s1_section", "leaf_b", "value b") // same source_path, DIFFERENT leaf_name
	other := crWithLeaf("sections.s2_other", "leaf_a", "value c")
	buckets := &ClusterBuckets{
		ConceptDomain: "test",
		VerifyRequired: []Cluster{{
			Representative: rep,
			Members: []ClusterMember{
				{Record: rep, DistanceFromAnchor: 0},
				{Record: sibling, DistanceFromAnchor: 0.2},
				{Record: other, DistanceFromAnchor: 0.25},
			},
		}},
	}
	gen := &mockGen{responses: []string{
		"VERDICT: no\nRATIONALE: split",
		"VERDICT: no\nRATIONALE: split",
	}}
	decisions, _, _ := VerifyAll(context.Background(), buckets, gen, cfg)
	if len(decisions.Verified) != 2 {
		t.Fatalf("expected 2 verifications (sibling + other vs rep), got %d — sibling concept with same source_path was wrongly skipped",
			len(decisions.Verified))
	}
	// Both non-representative records must appear as B in the verifications.
	seen := map[string]bool{}
	for _, v := range decisions.Verified {
		seen[v.B.LeafName] = true
	}
	if !seen["leaf_b"] {
		t.Error("sibling record (leaf_b, same source_path as rep) was skipped from verification — identity key bug regressed")
	}
	if !seen["leaf_a"] {
		t.Error("other record (leaf_a, different source_path) missing from verification")
	}
}

// TestRecordIdentityKey verifies the helper builds the triple key as
// (source_file # source_path # leaf_name) so two records with the
// same source_path but different leaf_names have distinct keys.
func TestRecordIdentityKey(t *testing.T) {
	a := crWithLeaf("s.x", "leaf_a", "")
	b := crWithLeaf("s.x", "leaf_b", "")
	if recordIdentityKey(a) == recordIdentityKey(b) {
		t.Error("records with same source_path but different leaf_names must have distinct identity keys")
	}
	c := crWithLeaf("s.x", "leaf_a", "different value")
	if recordIdentityKey(a) != recordIdentityKey(c) {
		t.Error("identity key must not depend on raw_value")
	}
}

func TestVerifyAll_AutoMergePicksCanonicalName(t *testing.T) {
	cfg := validFlashConfig()
	cfg.Prompts = newTestPrompts(t)
	buckets := &ClusterBuckets{
		ConceptDomain: "test",
		AutoMerge: []Cluster{{
			Representative: cr("rep_path", "the gate fires on deny"),
			Members: []ClusterMember{
				{Record: cr("rep_path", "the gate fires on deny"), DistanceFromAnchor: 0},
				{Record: cr("alt_path", "gate halts on rejected"), DistanceFromAnchor: 0.05},
			},
		}},
	}
	gen := &mockGen{responses: []string{"NAME: rep_path\nRATIONALE: shorter"}}
	decisions, ledger, err := VerifyAll(context.Background(), buckets, gen, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions.AutoMerge) != 1 {
		t.Fatalf("expected 1 auto_merge decision, got %d", len(decisions.AutoMerge))
	}
	if decisions.AutoMerge[0].ChosenName != "rep_path" {
		t.Errorf("got chosen_name=%q", decisions.AutoMerge[0].ChosenName)
	}
	if len(ledger.Entries) != 1 {
		t.Errorf("expected 1 ledger entry, got %d", len(ledger.Entries))
	}
}

func TestVerifyAll_VerifyRequiredYesProducesMerge(t *testing.T) {
	cfg := validFlashConfig()
	cfg.Prompts = newTestPrompts(t)
	buckets := &ClusterBuckets{
		ConceptDomain: "test",
		VerifyRequired: []Cluster{{
			Representative: cr("rep", "a"),
			Members: []ClusterMember{
				{Record: cr("rep", "a"), DistanceFromAnchor: 0},
				{Record: cr("m1", "b"), DistanceFromAnchor: 0.2},
			},
		}},
	}
	gen := &mockGen{responses: []string{"VERDICT: yes\nRATIONALE: same"}}
	decisions, _, err := VerifyAll(context.Background(), buckets, gen, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions.Verified) != 1 {
		t.Fatalf("expected 1 verified decision, got %d", len(decisions.Verified))
	}
	if decisions.Verified[0].Verdict != "merge" {
		t.Errorf("got verdict=%q", decisions.Verified[0].Verdict)
	}
}

func TestVerifyAll_UncertainProducesEscalation(t *testing.T) {
	cfg := validFlashConfig()
	cfg.Prompts = newTestPrompts(t)
	buckets := &ClusterBuckets{
		ConceptDomain: "test",
		VerifyRequired: []Cluster{{
			Representative: cr("rep", "a"),
			Members: []ClusterMember{
				{Record: cr("rep", "a"), DistanceFromAnchor: 0},
				{Record: cr("m1", "b"), DistanceFromAnchor: 0.25},
			},
		}},
	}
	gen := &mockGen{responses: []string{"VERDICT: uncertain\nRATIONALE: unclear"}}
	decisions, _, err := VerifyAll(context.Background(), buckets, gen, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions.Escalations) != 1 {
		t.Fatalf("expected 1 escalation, got %d", len(decisions.Escalations))
	}
	if decisions.Escalations[0].Reason != "flash_uncertain" {
		t.Errorf("got reason=%q", decisions.Escalations[0].Reason)
	}
}

func TestVerifyAll_UnparseableProducesEscalation(t *testing.T) {
	cfg := validFlashConfig()
	cfg.Prompts = newTestPrompts(t)
	buckets := &ClusterBuckets{
		ConceptDomain: "test",
		VerifyRequired: []Cluster{{
			Representative: cr("rep", "a"),
			Members: []ClusterMember{
				{Record: cr("rep", "a"), DistanceFromAnchor: 0},
				{Record: cr("m1", "b"), DistanceFromAnchor: 0.2},
			},
		}},
	}
	gen := &mockGen{responses: []string{"this response has no VERDICT line"}}
	decisions, _, _ := VerifyAll(context.Background(), buckets, gen, cfg)
	if len(decisions.Escalations) != 1 {
		t.Fatalf("expected 1 escalation on unparseable, got %d", len(decisions.Escalations))
	}
	if !strings.Contains(decisions.Escalations[0].Reason, "unparseable") {
		t.Errorf("expected unparseable reason, got %q", decisions.Escalations[0].Reason)
	}
}

func TestVerifyAll_LedgerCapturesEveryCall(t *testing.T) {
	cfg := validFlashConfig()
	cfg.Prompts = newTestPrompts(t)
	buckets := &ClusterBuckets{
		ConceptDomain: "test",
		AutoMerge: []Cluster{{
			Representative: cr("a_rep", "a"),
			Members: []ClusterMember{
				{Record: cr("a_rep", "a"), DistanceFromAnchor: 0},
				{Record: cr("a_alt", "a2"), DistanceFromAnchor: 0.05},
			},
		}},
		VerifyRequired: []Cluster{{
			Representative: cr("v_rep", "x"),
			Members: []ClusterMember{
				{Record: cr("v_rep", "x"), DistanceFromAnchor: 0},
				{Record: cr("v_alt", "y"), DistanceFromAnchor: 0.2},
			},
		}},
	}
	gen := &mockGen{responses: []string{
		"NAME: a_rep\nRATIONALE: ok",
		"VERDICT: yes\nRATIONALE: same",
	}}
	_, ledger, _ := VerifyAll(context.Background(), buckets, gen, cfg)
	if len(ledger.Entries) != 2 {
		t.Fatalf("expected 2 ledger entries (1 canon + 1 verify), got %d", len(ledger.Entries))
	}
	// Both entries must carry the prompt template path so future audits
	// can correlate decisions back to the template version.
	for _, e := range ledger.Entries {
		if e.PromptTemplate == "" {
			t.Errorf("ledger entry missing prompt_template_path: %+v", e)
		}
	}
}

func TestVerifyAll_NoMatchPassThrough(t *testing.T) {
	cfg := validFlashConfig()
	cfg.Prompts = newTestPrompts(t)
	buckets := &ClusterBuckets{
		ConceptDomain: "test",
		NoMatch:       []ConceptRecord{cr("alone", "x")},
	}
	gen := &mockGen{}
	decisions, _, _ := VerifyAll(context.Background(), buckets, gen, cfg)
	if len(decisions.NoMatch) != 1 {
		t.Errorf("expected no_match pass-through, got %d", len(decisions.NoMatch))
	}
}
