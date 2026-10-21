package providerplan

import (
	"strings"
	"testing"
)

func TestDependencyApplicabilityBoundsClassifierExecutionAndPredicates(t *testing.T) {
	contract := operationClassifierFactContract{matchField: "semantic", matchFields: map[string]struct{}{"semantic": {}}}
	program := operationClassifierProgram{
		factContracts:     map[string]operationClassifierFactContract{"fact": contract},
		subjectTraits:     map[string]struct{}{"read": {}, "write": {}},
		subjectTraitOrder: []string{"read", "write"},
		accessRuleByPredicate: map[string]operationClassifierAccessOutput{
			lengthPrefixedIdentityKey("fact", "semantic", "read"):  {relationshipLabel: "reads", accessSemantics: "read", subjectTraitContributions: map[string]bool{"read": true}},
			lengthPrefixedIdentityKey("fact", "semantic", "write"): {relationshipLabel: "writes", accessSemantics: "write", subjectTraitContributions: map[string]bool{"write": true}},
		},
		aggregateRuleByTraits: map[string]string{"11": "read_write"},
	}
	output, accesses, err := executeOperationClassifierProgram(program, []operationClassifierFact{{kind: "fact", values: map[string]string{"semantic": "read"}}, {kind: "fact", values: map[string]string{"semantic": "write"}}})
	if err != nil || output.operationKind != "read_write" || len(accesses) != 2 || output.subjectTraits["read"] != true || output.subjectTraits["write"] != true {
		t.Fatalf("classifier output=%#v accesses=%#v err=%v", output, accesses, err)
	}
	if _, _, err := executeOperationClassifierProgram(program, nil); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty fact roster error=%v", err)
	}
	if _, _, err := executeOperationClassifierProgram(program, []operationClassifierFact{{kind: "unknown", values: map[string]string{"semantic": "read"}}}); err == nil || !strings.Contains(err.Error(), "closed input") {
		t.Fatalf("unknown fact error=%v", err)
	}
	entry := operationApplicabilityEntry{classifierReference: dependencyProfileReference{id: "classifier"}, subjectTraits: output.subjectTraits, resourceAccesses: []operationResourceAccess{{relationshipLabel: "reads", accessSemantics: "read"}, {relationshipLabel: "writes", accessSemantics: "write"}}}
	if matched, err := operationApplicabilityPredicateMatches(applicabilityPredicate{kind: "subject_trait_equals", trait: "read", value: true}, entry); err != nil || !matched {
		t.Fatalf("subject trait predicate matched=%v err=%v", matched, err)
	}
	if matched, err := operationApplicabilityPredicateMatches(applicabilityPredicate{kind: "classifier_output_in", classifierProfileID: "classifier", values: map[string]struct{}{"read": {}}}, entry, "writes"); err != nil || matched {
		t.Fatalf("scoped classifier predicate matched=%v err=%v", matched, err)
	}
	if _, err := operationApplicabilityPredicateMatches(applicabilityPredicate{kind: "invented"}, entry); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown predicate error=%v", err)
	}
}

func TestDependencyApplicabilityBoundsVocabularyTraitsAndDispositionFailClosed(t *testing.T) {
	if !canonicalOperationClassifierVocabulary([]string{"api_operation", "data_entity"}, 2) || canonicalOperationClassifierVocabulary([]string{"data_entity", "api_operation"}, 2) || canonicalOperationClassifierVocabulary([]string{"api_operation", "api_operation"}, 2) {
		t.Fatal("classifier vocabulary canonical ordering/uniqueness changed")
	}
	if key, err := operationClassifierTraitVectorKey(map[string]interface{}{"read": true, "write": false}, []string{"read", "write"}); err != nil || key != "10" {
		t.Fatalf("trait vector key=%q err=%v", key, err)
	}
	if _, err := operationClassifierTraitVectorKey(map[string]interface{}{"read": "true"}, []string{"read"}); err == nil || !strings.Contains(err.Error(), "non-boolean") {
		t.Fatalf("nonboolean trait vector error=%v", err)
	}
	operations := operationApplicabilityState{byOperationID: map[string]operationApplicabilityEntry{"op": {subjectTraits: map[string]interface{}{"read": true}}}}
	disposition, err := evaluateGraphSubjectDisposition("optional", []applicabilityConditionalRule{{disposition: "required", predicate: applicabilityPredicate{kind: "subject_trait_equals", trait: "read", value: true}}}, graphApplicabilitySubject{kind: "api_symbol_object", id: "op"}, operations)
	if err != nil || disposition != "required" {
		t.Fatalf("subject disposition=%q err=%v", disposition, err)
	}
	if _, err := evaluateGraphSubjectDisposition("optional", []applicabilityConditionalRule{{disposition: "required", predicate: applicabilityPredicate{kind: "subject_trait_equals", trait: "read", value: true}}}, graphApplicabilitySubject{kind: "data_entity", id: "entity"}, operations); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("non-operation predicate error=%v", err)
	}
	if err := validateRelationshipCoverageCardinality("required", applicabilityCardinality{minimum: 1}, 0, 0); err == nil || !strings.Contains(err.Error(), "below") {
		t.Fatalf("required cardinality error=%v", err)
	}
	maximum := int64(1)
	if err := validateRelationshipCoverageCardinality("optional", applicabilityCardinality{maximum: &maximum}, 2, 0); err == nil || !strings.Contains(err.Error(), "above") {
		t.Fatalf("maximum cardinality error=%v", err)
	}
}

func TestDependencyApplicabilityBoundsResourceBudgetRejectsOverages(t *testing.T) {
	limits := canonicalOperationClassifierResourceLimits
	if err := validateOperationClassifierResourceLimits(limits); err != nil {
		t.Fatalf("canonical classifier limits: %v", err)
	}
	actual := int64(0)
	if err := reserveOperationClassifierResource(&actual, 1, 1, "fixture"); err != nil || actual != 1 {
		t.Fatalf("reserve resource actual=%d err=%v", actual, err)
	}
	if err := reserveOperationClassifierResource(&actual, 1, 1, "fixture"); err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("resource overage error=%v", err)
	}
	if err := reserveOperationClassifierResource(&actual, -1, 1, "fixture"); err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("negative resource error=%v", err)
	}
	bad := limits
	bad.programs++
	if err := validateOperationClassifierResourceLimits(bad); err == nil || !strings.Contains(err.Error(), "program count") {
		t.Fatalf("limit overage error=%v", err)
	}
}
