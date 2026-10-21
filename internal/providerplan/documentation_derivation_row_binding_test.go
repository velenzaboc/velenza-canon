package providerplan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExactDocumentationDerivedSemanticRowAcceptsExactClosedBinding(t *testing.T) {
	fact, row := exactDocumentationDerivedSemanticRowFixture(t)
	if err := validateExactDocumentationDerivedSemanticRow(fact.TargetArtifactRole, row, fact); err != nil {
		t.Fatal(err)
	}
	if err := validateExactDocumentationDerivedSemanticRowSet(fact.TargetArtifactRole, []dependencySemanticRow{row}, []exactDocumentationDerivedFact{fact}); err != nil {
		t.Fatal(err)
	}
}

func TestExactDocumentationDerivedSemanticRowRejectsEveryBindingMutation(t *testing.T) {
	fact, original := exactDocumentationDerivedSemanticRowFixture(t)
	wrongDigest := strings.Repeat("f", 64)
	tests := []struct {
		name       string
		role       string
		mutate     func(map[string]interface{})
		mutateKind string
	}{
		{name: "wrong artifact role", role: "surface_family_disposition"},
		{name: "wrong row kind", role: fact.TargetArtifactRole, mutateKind: "different_row_kind", mutate: func(row map[string]interface{}) { row["row_kind"] = "different_row_kind" }},
		{name: "wrong fact ID", role: fact.TargetArtifactRole, mutate: func(row map[string]interface{}) {
			row[exactDocumentationDerivedFactIDField] = stableID("docfact", "wrong")
		}},
		{name: "wrong source ref", role: fact.TargetArtifactRole, mutate: func(row map[string]interface{}) { row["source_ref"] = "different.source" }},
		{name: "wrong source URL", role: fact.TargetArtifactRole, mutate: func(row map[string]interface{}) { row["source_url"] = "https://example.com/different" }},
		{name: "wrong source digest", role: fact.TargetArtifactRole, mutate: func(row map[string]interface{}) { row["source_content_sha256"] = wrongDigest }},
		{name: "digest alias", role: fact.TargetArtifactRole, mutate: func(row map[string]interface{}) { row["content_sha256"] = fact.EvidenceLocator.SourceContentSHA256 }},
		{name: "wrong locator start", role: fact.TargetArtifactRole, mutate: func(row map[string]interface{}) {
			row["evidence_hydration_coordinate"].(map[string]interface{})["byte_start_offset"] = json.Number("1")
		}},
		{name: "locator alias", role: fact.TargetArtifactRole, mutate: func(row map[string]interface{}) {
			row["evidence_hydration_coordinate"].(map[string]interface{})["start_byte_offset_inclusive"] = json.Number("0")
		}},
		{name: "missing output field", role: fact.TargetArtifactRole, mutate: func(row map[string]interface{}) { delete(row, "provider_type") }},
		{name: "extra output field", role: fact.TargetArtifactRole, mutate: func(row map[string]interface{}) { row["inferred_default"] = "forbidden" }},
		{name: "changed output value", role: fact.TargetArtifactRole, mutate: func(row map[string]interface{}) { row["provider_requirement"] = "Optional" }},
		{name: "missing envelope field", role: fact.TargetArtifactRole, mutate: func(row map[string]interface{}) { delete(row, "source_url") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := cloneExactDocumentationDependencyRow(t, original)
			if test.mutate != nil {
				test.mutate(row.data)
				row = exactDocumentationDependencyRowFromObject(t, row.data)
			}
			if test.mutateKind != "" {
				row.kind = test.mutateKind
			}
			if err := validateExactDocumentationDerivedSemanticRow(test.role, row, fact); err == nil {
				t.Fatal("mutation was accepted")
			}
		})
	}
}

func TestExactDocumentationDerivedSemanticRowRejectsNoncanonicalAuthoritativeValue(t *testing.T) {
	fact, row := exactDocumentationDerivedSemanticRowFixture(t)
	mutatedRaw := bytes.Replace(row.raw, []byte(`"Required"`), []byte(`"\u0052equired"`), 1)
	if bytes.Equal(mutatedRaw, row.raw) {
		t.Fatal("fixture did not contain the expected authoritative value")
	}
	mutated := exactDocumentationDependencyRowFromRaw(t, mutatedRaw)
	if err := validateExactDocumentationDerivedSemanticRow(fact.TargetArtifactRole, mutated, fact); err == nil || !strings.Contains(err.Error(), "canonical JSON value") {
		t.Fatalf("error = %v, want noncanonical-value refusal", err)
	}
}

func TestExactDocumentationDerivedSemanticRowRejectsInvalidFactIntegrity(t *testing.T) {
	fact, row := exactDocumentationDerivedSemanticRowFixture(t)
	tests := []struct {
		name   string
		mutate func(*exactDocumentationDerivedFact)
	}{
		{name: "fact output changed", mutate: func(candidate *exactDocumentationDerivedFact) {
			output, err := decodeExactDocumentationFactOutputFields(*candidate)
			if err != nil {
				t.Fatal(err)
			}
			output["provider_type"] = "Changed"
			raw, err := json.Marshal(output)
			if err != nil {
				t.Fatal(err)
			}
			candidate.CanonicalOutputFields, err = canonicalizeCandidateJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "fact locator changed", mutate: func(candidate *exactDocumentationDerivedFact) { candidate.EvidenceLocator.ByteEndOffsetExclusive++ }},
		{name: "fact locator row kind changed", mutate: func(candidate *exactDocumentationDerivedFact) {
			candidate.EvidenceLocator.RowKind = "different_locator_kind"
		}},
		{name: "fact ID changed", mutate: func(candidate *exactDocumentationDerivedFact) { candidate.FactID = stableID("docfact", "changed") }},
		{name: "unsorted output roster", mutate: func(candidate *exactDocumentationDerivedFact) {
			candidate.ExactOutputFieldNames[0], candidate.ExactOutputFieldNames[1] = candidate.ExactOutputFieldNames[1], candidate.ExactOutputFieldNames[0]
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneExactDocumentationDerivedFact(t, fact)
			test.mutate(&candidate)
			if err := validateExactDocumentationDerivedSemanticRow(candidate.TargetArtifactRole, row, candidate); err == nil {
				t.Fatal("invalid fact was accepted")
			}
		})
	}
}

func TestExactDocumentationDerivedSemanticRowSetRejectsNonBijectiveUse(t *testing.T) {
	fact, row := exactDocumentationDerivedSemanticRowFixture(t)
	t.Run("duplicate fact use", func(t *testing.T) {
		if err := validateExactDocumentationDerivedSemanticRowSet(fact.TargetArtifactRole, []dependencySemanticRow{row, row}, []exactDocumentationDerivedFact{fact}); err == nil || !strings.Contains(err.Error(), "more than once") {
			t.Fatalf("error = %v, want duplicate-use refusal", err)
		}
	})
	t.Run("omitted fact", func(t *testing.T) {
		if err := validateExactDocumentationDerivedSemanticRowSet(fact.TargetArtifactRole, nil, []exactDocumentationDerivedFact{fact}); err == nil {
			t.Fatal("omitted fact was accepted")
		}
	})
	t.Run("unknown fact", func(t *testing.T) {
		unknown := cloneExactDocumentationDependencyRow(t, row)
		unknown.data[exactDocumentationDerivedFactIDField] = stableID("docfact", "unknown")
		unknown = exactDocumentationDependencyRowFromObject(t, unknown.data)
		if err := validateExactDocumentationDerivedSemanticRowSet(fact.TargetArtifactRole, []dependencySemanticRow{unknown}, []exactDocumentationDerivedFact{fact}); err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("error = %v, want unknown-fact refusal", err)
		}
	})
	t.Run("duplicate fact roster", func(t *testing.T) {
		if err := validateExactDocumentationDerivedSemanticRowSet(fact.TargetArtifactRole, []dependencySemanticRow{row}, []exactDocumentationDerivedFact{fact, fact}); err == nil || !strings.Contains(err.Error(), "duplicates") {
			t.Fatalf("error = %v, want duplicate-roster refusal", err)
		}
	})
}

func exactDocumentationDerivedSemanticRowFixture(t *testing.T) (exactDocumentationDerivedFact, dependencySemanticRow) {
	t.Helper()
	body := []byte("| amount | Decimal | Required |\r\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	program, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := executeExactDocumentationDerivationProgram(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Fatalf("derived fact count = %d, want 1", len(facts))
	}
	fact := facts[0]
	locator := fact.EvidenceLocator
	row := map[string]interface{}{
		"row_kind":                           fact.TargetRowKind,
		exactDocumentationDerivedFactIDField: fact.FactID,
		"source_ref":                         locator.SourceRefs[0],
		"source_url":                         locator.SourceURLs[0],
		"source_content_sha256":              locator.SourceContentSHA256,
		"evidence_hydration_coordinate": map[string]interface{}{
			"source_content_sha256":     locator.SourceContentSHA256,
			"byte_start_offset":         locator.ByteStartOffset,
			"byte_end_offset_exclusive": locator.ByteEndOffsetExclusive,
			"selected_range_byte_count": locator.SelectedRangeByteCount,
			"selected_range_sha256":     locator.SelectedRangeSHA256,
		},
	}
	output, err := decodeExactDocumentationFactOutputFields(fact)
	if err != nil {
		t.Fatal(err)
	}
	for field, value := range output {
		row[field] = value
	}
	return fact, exactDocumentationDependencyRowFromObject(t, row)
}

func exactDocumentationDependencyRowFromObject(t *testing.T, object map[string]interface{}) dependencySemanticRow {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return exactDocumentationDependencyRowFromRaw(t, canonical)
}

func exactDocumentationDependencyRowFromRaw(t *testing.T, raw []byte) dependencySemanticRow {
	t.Helper()
	var object map[string]interface{}
	if err := decodeOneValidationProfileJSON(raw, &object); err != nil {
		t.Fatal(err)
	}
	kind, ok := semanticString(object, "row_kind")
	if !ok {
		t.Fatal("test row has no row_kind")
	}
	return dependencySemanticRow{line: 1, raw: bytes.Clone(raw), kind: kind, data: object}
}

func cloneExactDocumentationDependencyRow(t *testing.T, row dependencySemanticRow) dependencySemanticRow {
	t.Helper()
	return exactDocumentationDependencyRowFromObject(t, row.data)
}

func cloneExactDocumentationDerivedFact(t *testing.T, fact exactDocumentationDerivedFact) exactDocumentationDerivedFact {
	t.Helper()
	clone := fact
	clone.ExactOutputFieldNames = append([]string(nil), fact.ExactOutputFieldNames...)
	clone.CanonicalOutputFields = bytes.Clone(fact.CanonicalOutputFields)
	clone.TargetRowSelector = append([]exactDocumentationResolvedTargetRowSelector(nil), fact.TargetRowSelector...)
	clone.TargetMemberIdentity = append([]exactDocumentationResolvedMemberIdentity(nil), fact.TargetMemberIdentity...)
	clone.EvidenceLocator.SourceRefs = append([]string(nil), fact.EvidenceLocator.SourceRefs...)
	clone.EvidenceLocator.SourceURLs = append([]string(nil), fact.EvidenceLocator.SourceURLs...)
	return clone
}
