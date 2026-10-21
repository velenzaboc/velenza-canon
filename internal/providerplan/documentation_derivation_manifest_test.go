package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExactDocumentationDerivationManifestCommitsEveryOccurrence(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n| memo | String | Optional |\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 2, 2)
	program, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		t.Fatal(err)
	}
	generation := exactDocumentationFieldClaimSchemaFixture(t, reference)
	first, err := executeExactDocumentationDerivationWithManifest(reference, program, generation, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	second, err := executeExactDocumentationDerivationWithManifest(reference, program, generation, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if first.ResultRootSHA256 != second.ResultRootSHA256 || first.OutcomeSetRootSHA256 != second.OutcomeSetRootSHA256 || first.FactSetRootSHA256 != second.FactSetRootSHA256 || first.PageCount != second.PageCount || first.PageCount <= 0 || first.PageSetRootSHA256 != second.PageSetRootSHA256 || !isLowerSHA256(first.PageSetRootSHA256) || first.SemanticGenerationSHA256 != generation.identitySHA256 {
		t.Fatal("repeated manifest execution changed its content identity")
	}
	if len(first.Outcomes) != 1 || first.Outcomes[0].MatchCount != 2 || len(first.Outcomes[0].DerivedFactIDs) != 2 || len(first.Facts) != 2 {
		t.Fatalf("execution closure = outcomes %#v facts %d", first.Outcomes, len(first.Facts))
	}
	if first.MatcherEvaluationCount <= 0 || first.MatcherInputByteCount <= 0 || first.MatcherInputByteLimitPerInputUnit != program.MaxMatcherInputBytesPerInputUnit || first.MatcherInputByteLimitPerRun != program.MaxMatcherInputBytesPerRun || first.CanonicalFactBytes <= 0 || first.CanonicalOutcomeBytes <= 0 || first.RetainedCanonicalBytes != first.CanonicalFactBytes+first.CanonicalOutcomeBytes {
		t.Fatalf("streaming retained-resource seal = %#v", first)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"Pages"`) || strings.Contains(string(encoded), `"pages"`) {
		t.Fatal("production manifest result retained page bodies")
	}
}

func TestExactDocumentationSortedOccurrencesIsStableAndDoesNotMutateInput(t *testing.T) {
	input := []sourceClassificationOccurrence{
		{Binding: classificationArtifactBinding{ArtifactID: "z", ArtifactVersion: "1", ArtifactSHA256: strings.Repeat("a", 64)}, SurfaceKind: "table", Locator: evidenceLocator{ID: "z"}},
		{Binding: classificationArtifactBinding{ArtifactID: "a", ArtifactVersion: "1", ArtifactSHA256: strings.Repeat("b", 64)}, SurfaceKind: "table", Locator: evidenceLocator{ID: "a"}},
	}
	sorted := exactDocumentationSortedOccurrences(input)
	if sorted[0].Locator.ID != "a" || input[0].Locator.ID != "z" {
		t.Fatalf("sorted=%q input=%q; ordering must be canonical and non-mutating", sorted[0].Locator.ID, input[0].Locator.ID)
	}
}

func TestExactDocumentationDerivationManifestRejectsOutputOutsideBoundClaimSchema(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	program, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		t.Fatal(err)
	}
	id := "urn:test:documentation:reject-output"
	schemaBytes := mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012, "$id": id,
		"type": "object", "additionalProperties": false,
		"required":   []string{"different_field"},
		"properties": map[string]interface{}{"different_field": map[string]interface{}{"type": "string"}},
	})
	authority, err := resolveDocumentationClaimSchema(
		dependencyProfileReference{id: id, version: "1", digest: sha256Hex(schemaBytes)},
		"field_contract", string(schemaBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := newDocumentationSemanticGenerationBinding("field_contract", reference, authority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeExactDocumentationDerivationWithManifest(reference, program, generation, proof, bodies); err == nil || !strings.Contains(err.Error(), "fails exact validation schema") {
		t.Fatalf("out-of-schema manifest error = %v", err)
	}
}

func TestExactDocumentationDerivationManifestDistinguishesZeroFactRuns(t *testing.T) {
	body := []byte("no field rows\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 0, 1)
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	program, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		t.Fatal(err)
	}
	generation := exactDocumentationFieldClaimSchemaFixture(t, reference)
	result, err := executeExactDocumentationDerivationWithManifest(reference, program, generation, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != 0 || len(result.Outcomes) != 1 || result.Outcomes[0].Disposition != exactDocumentationDerivationZeroMatchAllowed || result.ResultRootSHA256 == "" || !isLowerSHA256(result.PageSetRootSHA256) {
		t.Fatalf("zero-fact execution is not explicitly content-addressed: %#v", result)
	}

	object["input_source_symbols"] = []interface{}{"fixture_fields"}
	object["ordered_rules"].([]interface{})[0].(map[string]interface{})["target_row_kind"] = "different_target"
	mutated, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(mutated)
	if err != nil {
		t.Fatal(err)
	}
	mutatedReference := reference
	mutatedReference.digest = sha256Hex(canonical)
	mutatedProgram, err := parseExactDocumentationDerivationProgram(canonical, mutatedReference)
	if err != nil {
		t.Fatal(err)
	}
	mutatedGeneration := exactDocumentationFieldClaimSchemaFixture(t, mutatedReference)
	mutatedResult, err := executeExactDocumentationDerivationWithManifest(mutatedReference, mutatedProgram, mutatedGeneration, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if result.FactSetRootSHA256 != mutatedResult.FactSetRootSHA256 || result.ResultRootSHA256 == mutatedResult.ResultRootSHA256 {
		t.Fatalf("zero-fact executions did not preserve universal empty fact root plus distinct profile/proof result roots")
	}
}
