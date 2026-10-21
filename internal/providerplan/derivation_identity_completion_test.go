package providerplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStageCompileFileManifestRefusesUnreadableDeclaredMembers(t *testing.T) {
	for _, test := range []struct {
		name     string
		manifest string
	}{
		{
			name:     "absent predecessor receipt",
			manifest: `{"request_path":"request.json","predecessor_receipt_paths":["absent.json"],"materials":[],"evidence_bodies":[]}`,
		},
		{
			name:     "absent material",
			manifest: `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[{"role":"material","id":"m","version":"1","path":"absent.json"}],"evidence_bodies":[]}`,
		},
		{
			name:     "absent evidence body",
			manifest: `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[{"manifest_role":"r","manifest_id":"m","manifest_version":"1","component_ordinal":0,"path":"absent.json"}]}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "request.json"), []byte(`{"value":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
			manifestPath := writeStageInputManifestFixture(t, dir, test.manifest)
			// The request resolves, so the refusal must come from the missing
			// declared member rather than from the manifest as a whole.
			if _, _, err := LoadStageCompileFileManifest(manifestPath); err == nil {
				t.Fatalf("a manifest declaring an absent member was accepted")
			}
		})
	}
}

func TestCandidateAPISymbolDerivationBindingForRefusesAmbiguousOccurrences(t *testing.T) {
	symbol := apiSymbol{ID: "capisym_one"}
	roster := sha256Hex([]byte("evidence selection roster"))

	if _, err := candidateAPISymbolDerivationBindingFor(symbol, roster, nil); err == nil ||
		!strings.Contains(err.Error(), "has no classification occurrences") {
		t.Fatalf("empty occurrence error = %v, want an empty-roster refusal", err)
	}

	first := sourceClassificationOccurrenceFixture("list_invoices", "evloc_one")
	divergent := sourceClassificationOccurrenceFixture("a_different_symbol", "evloc_two")
	if _, err := candidateAPISymbolDerivationBindingFor(symbol, roster, []sourceClassificationOccurrence{first, divergent}); err == nil ||
		!strings.Contains(err.Error(), "semantically ambiguous") {
		t.Fatalf("ambiguous roster error = %v, want an ambiguity refusal", err)
	}

	repeated := sourceClassificationOccurrenceFixture("list_invoices", "evloc_one")
	if _, err := candidateAPISymbolDerivationBindingFor(symbol, roster, []sourceClassificationOccurrence{first, repeated}); err == nil ||
		!strings.Contains(err.Error(), "duplicates locator") {
		t.Fatalf("duplicate locator error = %v, want a duplicate-locator refusal", err)
	}
}

func TestGraphGapDerivationTargetIdentityRefusesUncanonicalizableProofBinding(t *testing.T) {
	gap := graphGap{GapProofBinding: json.RawMessage(`{"unterminated":`)}
	if _, err := graphGapDerivationTargetIdentity(gap); err == nil ||
		!strings.Contains(err.Error(), "gap_proof_binding") {
		t.Fatalf("error = %v, want a gap_proof_binding refusal", err)
	}
}

func TestTypedGraphPredecessorDerivationBindingForOrdersItsFactRoster(t *testing.T) {
	first := typedGraphCompletionFact()
	second := typedGraphCompletionFact()
	second.RowIdentityValue = "another_operation"

	// Declared in one order, the binding must serialize them in canonical
	// identity order so the derived binding id cannot depend on caller order.
	forward, err := typedGraphPredecessorDerivationBindingFor("api_relationship", "capi_rel_fixture", []typedGraphPredecessorFact{first, second})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := typedGraphPredecessorDerivationBindingFor("api_relationship", "capi_rel_fixture", []typedGraphPredecessorFact{second, first})
	if err != nil {
		t.Fatal(err)
	}
	if string(forward) != string(reverse) {
		t.Fatalf("declaration order changed the derivation binding:\nforward=%s\nreverse=%s", forward, reverse)
	}
}

func TestValidateAndResolveTypedGraphPredecessorBindingRefusesNoncanonicalRowCoordinates(t *testing.T) {
	const candidateKind = "api_relationship"
	const candidateIdentity = "capi_rel_fixture"
	artifactRaw := []byte("artifact")

	fact := typedGraphCompletionFact()
	fact.ArtifactSHA256 = sha256Hex(artifactRaw)
	fact.RowKind = "Not A Canonical Row Kind"
	raw, err := typedGraphPredecessorDerivationBindingFor(candidateKind, candidateIdentity, []typedGraphPredecessorFact{fact})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := typedGraphPredecessorArtifacts{
		typedGraphArtifactRoleSourceContract: {
			input: artifactInput{Raw: artifactRaw, Manifest: map[string]interface{}{"artifact": "source_contract_index", "artifact_version": "1"}},
			rows:  dependencySemanticRows{byKind: map[string][]dependencySemanticRow{}},
		},
	}
	if _, err := validateAndResolveTypedGraphPredecessorBinding(candidateKind, candidateIdentity, raw, artifacts); err == nil ||
		!strings.Contains(err.Error(), "invalid typed row coordinate") {
		t.Fatalf("error = %v, want a noncanonical row coordinate refusal", err)
	}
}

func TestExecuteExactDocumentationDerivationWithManifestRequiresAnExactGeneration(t *testing.T) {
	reference := dependencyProfileReference{id: "profile", version: "1", digest: sha256Hex([]byte("program"))}
	// A zero semantic generation binds no claim schema, so manifest execution
	// must refuse before any page is derived.
	_, err := executeExactDocumentationDerivationWithManifest(
		reference, exactDocumentationDerivationProgram{}, documentationSemanticGenerationBinding{},
		sourceClassificationSelectionProof{}, map[string]exactEvidenceBody{},
	)
	if err == nil || !strings.Contains(err.Error(), "requires an exact semantic generation") {
		t.Fatalf("error = %v, want an exact-generation refusal", err)
	}
}
