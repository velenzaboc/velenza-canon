package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestToSubmissions_Concepts(t *testing.T) {
	ct := &ConceptTable{
		ConceptDomain: "test_domain",
		Concepts: []Concept{
			{CanonicalName: "node_b", NodeKind: "axiom",
				Contract: map[string]interface{}{"asserts": "x"},
				Payload:  map[string]interface{}{"title": "B"}},
			{CanonicalName: "node_a", NodeKind: "section",
				Payload: map[string]interface{}{"statement": "A statement"}},
		},
	}
	subs, err := ToSubmissions(ct, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 {
		t.Fatalf("expected 2 submissions, got %d", len(subs))
	}
	// Stable-sort by canonical_name: node_a first.
	if subs[0].StableID != "node_a" {
		t.Errorf("expected node_a first, got %q", subs[0].StableID)
	}
	if subs[0].ArtifactType != "section" || subs[1].ArtifactType != "axiom" {
		t.Errorf("artifact_type mapping wrong: %q / %q", subs[0].ArtifactType, subs[1].ArtifactType)
	}
	if subs[0].OrganizationID != "tenant-1" {
		t.Errorf("organization_id not propagated")
	}
}

func TestToSubmissions_NodesBeforeEdges(t *testing.T) {
	ct := &ConceptTable{
		Concepts: []Concept{
			{CanonicalName: "n1", NodeKind: "axiom"},
		},
		Edges: []Edge{
			{EdgeLabel: "references", SourceName: "n1", TargetName: "n2"},
		},
	}
	subs, _ := ToSubmissions(ct, "t")
	if len(subs) != 2 {
		t.Fatalf("expected 2 submissions, got %d", len(subs))
	}
	if subs[0].ArtifactType != "axiom" || subs[1].ArtifactType != "edge" {
		t.Errorf("expected node before edge: %+v", subs)
	}
}

func TestToSubmissions_UnknownKindRejected(t *testing.T) {
	ct := &ConceptTable{Concepts: []Concept{{CanonicalName: "x", NodeKind: "made_up_kind"}}}
	_, err := ToSubmissions(ct, "t")
	if err == nil {
		t.Error("expected error on unknown kind")
	}
}

func TestToSubmissions_EdgeFieldsPropagated(t *testing.T) {
	ct := &ConceptTable{
		Edges: []Edge{
			{EdgeLabel: "depends_on", SourceName: "a", TargetName: "b"},
		},
	}
	subs, _ := ToSubmissions(ct, "t")
	if len(subs) != 1 {
		t.Fatalf("expected 1 edge submission, got %d", len(subs))
	}
	if subs[0].EdgeLabel != "depends_on" || subs[0].SourceID != "a" || subs[0].TargetID != "b" {
		t.Errorf("edge fields wrong: %+v", subs[0])
	}
}

func TestWriteSubmissionDir_FilesNumberedAndNamed(t *testing.T) {
	subs := []Submission{
		{ArtifactType: "axiom", StableID: "alpha"},
		{ArtifactType: "section", StableID: "beta"},
		{ArtifactType: "edge", EdgeLabel: "ref", SourceID: "alpha", TargetID: "beta"},
	}
	dir := t.TempDir()
	if err := WriteSubmissionDir(subs, dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) != 3 {
		t.Fatalf("expected 3 files, got %d (%v)", len(names), names)
	}
	if !strings.HasPrefix(names[0], "001_") {
		t.Errorf("expected 001_ prefix on first file, got %q", names[0])
	}
	if !strings.HasPrefix(names[1], "002_") {
		t.Errorf("expected 002_ prefix on second file, got %q", names[1])
	}
	if !strings.HasPrefix(names[2], "003_") {
		t.Errorf("expected 003_ prefix on third file, got %q", names[2])
	}
	// Verify edge filename embeds label + endpoints.
	if !strings.Contains(names[2], "ref__alpha__beta") {
		t.Errorf("edge filename should embed label+endpoints, got %q", names[2])
	}
}

func TestWriteSubmissionDir_FileContentsParseAsSubmission(t *testing.T) {
	subs := []Submission{
		{ArtifactType: "axiom", OrganizationID: "t", NodeKind: "axiom",
			StableID: "node_a", Contract: map[string]interface{}{"asserts": "y"}},
	}
	dir := t.TempDir()
	if err := WriteSubmissionDir(subs, dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var parsed Submission
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("written file should round-trip parse: %v", err)
	}
	if parsed.StableID != "node_a" || parsed.NodeKind != "axiom" {
		t.Errorf("parsed back wrong: %+v", parsed)
	}
}

func TestSanitizeFilenameComponent(t *testing.T) {
	cases := map[string]string{
		"clean_name":              "clean_name",
		"with.dots":               "with.dots",
		"with-dashes":             "with-dashes",
		"weird/slash":             "weird_slash",
		"with spaces":             "with_spaces",
	}
	for in, want := range cases {
		if got := sanitizeFilenameComponent(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
