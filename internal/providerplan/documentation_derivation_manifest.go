package providerplan

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

const (
	exactDocumentationDerivationExecutionKind    = "exact_documentation_derivation_execution_v2"
	exactDocumentationDerivationOutcomeKind      = "exact_documentation_derivation_occurrence_outcome_v1"
	exactDocumentationDerivationComplete         = "complete"
	exactDocumentationDerivationMatched          = "matched"
	exactDocumentationDerivationZeroMatchAllowed = "zero_match_permitted"
)

// exactDocumentationDerivationOccurrenceOutcome makes every executed
// (rule, classified occurrence) visible even when its admitted rule permits
// zero matches. Facts alone are not completeness evidence.
type exactDocumentationDerivationOccurrenceOutcome struct {
	OutcomeKind              string   `json:"outcome_kind"`
	OutcomeID                string   `json:"outcome_id"`
	RuleID                   string   `json:"rule_id"`
	InputSourceSymbol        string   `json:"input_source_symbol"`
	ClassificationArtifactID string   `json:"classification_artifact_id"`
	ClassificationVersion    string   `json:"classification_artifact_version"`
	ClassificationSHA256     string   `json:"classification_artifact_sha256"`
	ClassificationRole       string   `json:"classification_role"`
	PredecessorLocatorID     string   `json:"predecessor_locator_id"`
	MatchCount               int64    `json:"match_count"`
	Disposition              string   `json:"disposition"`
	DerivedFactIDs           []string `json:"derived_fact_ids"`
	DerivedFactSetRootSHA256 string   `json:"derived_fact_set_root_sha256"`
}

func newExactDocumentationDerivationOccurrenceOutcome(reference dependencyProfileReference, proof sourceClassificationSelectionProof, rule exactDocumentationDerivationRule, occurrence exactDocumentationSelectedOccurrence, derivedFactIDs []string) (exactDocumentationDerivationOccurrenceOutcome, []byte, error) {
	factIDs := append([]string(nil), derivedFactIDs...)
	sort.Strings(factIDs)
	for index, factID := range factIDs {
		if factID == "" || (index > 0 && factIDs[index-1] == factID) {
			return exactDocumentationDerivationOccurrenceOutcome{}, nil, fmt.Errorf("documentation derivation occurrence outcome has an empty or duplicate derived fact identity")
		}
	}
	disposition := exactDocumentationDerivationMatched
	if len(factIDs) == 0 {
		disposition = exactDocumentationDerivationZeroMatchAllowed
	}
	factRows := make([][]byte, len(factIDs))
	for index, factID := range factIDs {
		factRows[index] = []byte(factID)
	}
	key := exactDocumentationDerivationOutcomeKey(rule.RuleID, rule.InputSourceSymbol, occurrence.binding, occurrence.surfaceKind, occurrence.locator.ID)
	outcome := exactDocumentationDerivationOccurrenceOutcome{
		OutcomeKind: exactDocumentationDerivationOutcomeKind,
		RuleID:      rule.RuleID, InputSourceSymbol: rule.InputSourceSymbol,
		ClassificationArtifactID: occurrence.binding.ArtifactID,
		ClassificationVersion:    occurrence.binding.ArtifactVersion,
		ClassificationSHA256:     occurrence.binding.ArtifactSHA256,
		ClassificationRole:       occurrence.surfaceKind,
		PredecessorLocatorID:     occurrence.locator.ID,
		MatchCount:               int64(len(factIDs)), Disposition: disposition,
		DerivedFactIDs: factIDs, DerivedFactSetRootSHA256: stageCanonicalSetRoot(factRows),
	}
	outcome.OutcomeID = stableID("docout", lengthPrefixedIdentityKey(
		reference.id, reference.version, reference.digest,
		proof.contentSHA256, key, disposition,
		fmt.Sprint(outcome.MatchCount), outcome.DerivedFactSetRootSHA256,
	))
	canonical, err := canonicalDocumentationBytes(outcome)
	if err != nil {
		return exactDocumentationDerivationOccurrenceOutcome{}, nil, fmt.Errorf("canonicalize documentation derivation occurrence outcome: %w", err)
	}
	return outcome, canonical, nil
}

func conservativeExactDocumentationOutcomeBytes(rule exactDocumentationDerivationRule, occurrence exactDocumentationSelectedOccurrence, derivedFactIDs []string) (int64, error) {
	// Every JSON string byte can expand to at most one six-byte \u00XX escape.
	// The fixed allowance covers property names, punctuation, int64 text, both
	// SHA-256 fields, the stable outcome ID, and disposition/kind literals.
	total := int64(2048)
	strings := []string{rule.RuleID, rule.InputSourceSymbol, occurrence.binding.ArtifactID, occurrence.binding.ArtifactVersion, occurrence.binding.ArtifactSHA256, occurrence.surfaceKind, occurrence.locator.ID}
	strings = append(strings, derivedFactIDs...)
	for _, value := range strings {
		length := int64(len(value))
		if length > (math.MaxInt64-3)/6 || total > math.MaxInt64-(length*6+3) {
			return 0, fmt.Errorf("documentation derivation occurrence outcome byte bound overflows INT64")
		}
		total += length*6 + 3
	}
	return total, nil
}

func validateExactDocumentationDerivationOccurrenceOutcome(reference dependencyProfileReference, proof sourceClassificationSelectionProof, outcome exactDocumentationDerivationOccurrenceOutcome) ([]byte, error) {
	if outcome.OutcomeKind != exactDocumentationDerivationOutcomeKind || outcome.RuleID == "" || outcome.InputSourceSymbol == "" || outcome.ClassificationArtifactID == "" || outcome.ClassificationVersion == "" || !isLowerSHA256(outcome.ClassificationSHA256) || outcome.ClassificationRole == "" || outcome.PredecessorLocatorID == "" || outcome.MatchCount < 0 || outcome.MatchCount != int64(len(outcome.DerivedFactIDs)) {
		return nil, fmt.Errorf("documentation derivation occurrence outcome is structurally invalid")
	}
	factRows := make([][]byte, len(outcome.DerivedFactIDs))
	for index, factID := range outcome.DerivedFactIDs {
		if factID == "" || (index > 0 && outcome.DerivedFactIDs[index-1] >= factID) {
			return nil, fmt.Errorf("documentation derivation occurrence outcome fact identities are not strictly sorted and unique")
		}
		factRows[index] = []byte(factID)
	}
	expectedDisposition := exactDocumentationDerivationMatched
	if len(outcome.DerivedFactIDs) == 0 {
		expectedDisposition = exactDocumentationDerivationZeroMatchAllowed
	}
	if outcome.Disposition != expectedDisposition || outcome.DerivedFactSetRootSHA256 != stageCanonicalSetRoot(factRows) {
		return nil, fmt.Errorf("documentation derivation occurrence outcome disposition or fact-set root disagrees")
	}
	binding := classificationArtifactBinding{ArtifactID: outcome.ClassificationArtifactID, ArtifactVersion: outcome.ClassificationVersion, ArtifactSHA256: outcome.ClassificationSHA256}
	key := exactDocumentationDerivationOutcomeKey(outcome.RuleID, outcome.InputSourceSymbol, binding, outcome.ClassificationRole, outcome.PredecessorLocatorID)
	expectedID := stableID("docout", lengthPrefixedIdentityKey(reference.id, reference.version, reference.digest, proof.contentSHA256, key, outcome.Disposition, fmt.Sprint(outcome.MatchCount), outcome.DerivedFactSetRootSHA256))
	if outcome.OutcomeID != expectedID {
		return nil, fmt.Errorf("documentation derivation occurrence outcome identity disagrees with its full canonical state")
	}
	return canonicalDocumentationBytes(outcome)
}

type exactDocumentationDerivationExecutionResult struct {
	seal                              *exactDocumentationDerivationExecutionResultSeal
	ExecutionKind                     string
	Profile                           dependencyProfileReference
	SemanticGenerationSHA256          string
	Provider                          string
	EvidenceRosterSHA256              string
	ClassificationProofSHA256         string
	Outcomes                          []exactDocumentationDerivationOccurrenceOutcome
	Facts                             []exactDocumentationDerivedFact
	OutcomeSetRootSHA256              string
	FactSetRootSHA256                 string
	CanonicalFactBytes                int64
	CanonicalOutcomeBytes             int64
	RetainedCanonicalBytes            int64
	MatcherEvaluationCount            int64
	MatcherInputByteCount             int64
	MatcherInputByteLimitPerInputUnit int64
	MatcherInputByteLimitPerRun       int64
	PageCount                         int64
	PageSetRootSHA256                 string
	ResultRootSHA256                  string
	Status                            string
}

type exactDocumentationDerivationExecutionResultSeal struct{}

var exactDocumentationDerivationExecutionResultAuthority = &exactDocumentationDerivationExecutionResultSeal{}

type exactDocumentationDerivationResultIdentity struct {
	ExecutionKind                     string `json:"execution_kind"`
	ProfileID                         string `json:"profile_id"`
	ProfileVersion                    string `json:"profile_version"`
	ProfileSHA256                     string `json:"profile_sha256"`
	SemanticGenerationSHA256          string `json:"semantic_generation_sha256"`
	Provider                          string `json:"provider"`
	EvidenceRosterSHA256              string `json:"evidence_selection_roster_sha256"`
	ClassificationProofSHA256         string `json:"classification_selection_proof_sha256"`
	OutcomeCount                      int64  `json:"outcome_count"`
	OutcomeSetRootSHA256              string `json:"outcome_set_root_sha256"`
	FactCount                         int64  `json:"fact_count"`
	FactSetRootSHA256                 string `json:"fact_set_root_sha256"`
	CanonicalFactBytes                int64  `json:"canonical_fact_bytes"`
	CanonicalOutcomeBytes             int64  `json:"canonical_outcome_bytes"`
	RetainedCanonicalBytes            int64  `json:"retained_canonical_bytes"`
	MatcherEvaluationCount            int64  `json:"matcher_evaluation_count"`
	MatcherInputByteCount             int64  `json:"matcher_input_byte_count"`
	MatcherInputByteLimitPerInputUnit int64  `json:"matcher_input_byte_limit_per_input_unit"`
	MatcherInputByteLimitPerRun       int64  `json:"matcher_input_byte_limit_per_run"`
	PageCount                         int64  `json:"page_count"`
	PageSetRootSHA256                 string `json:"page_set_root_sha256"`
	Status                            string `json:"status"`
}

func executeExactDocumentationDerivationWithManifest(reference dependencyProfileReference, program exactDocumentationDerivationProgram, generation documentationSemanticGenerationBinding, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody) (exactDocumentationDerivationExecutionResult, error) {
	var result exactDocumentationDerivationExecutionResult
	if err := validateDocumentationSemanticGenerationBinding(generation); err != nil {
		return result, fmt.Errorf("documentation derivation manifest requires an exact semantic generation: %w", err)
	}
	if dependencyProfileReferenceKey(generation.program) != dependencyProfileReferenceKey(reference) {
		return result, fmt.Errorf("documentation derivation manifest program coordinate differs from its semantic generation")
	}
	if err := validateSourceClassificationSelectionProof(proof); err != nil {
		return result, fmt.Errorf("documentation derivation manifest requires a sealed exact classification-selection proof: %w", err)
	}
	encodedProgram, err := json.Marshal(program)
	if err != nil {
		return result, fmt.Errorf("marshal documentation derivation program for manifest execution: %w", err)
	}
	program, err = parseExactDocumentationDerivationProgram(encodedProgram, reference)
	if err != nil {
		return result, fmt.Errorf("revalidate documentation derivation program for manifest execution: %w", err)
	}
	accumulator, err := newExactDocumentationPageSetAccumulator(reference, program, proof, bodies)
	if err != nil {
		return result, err
	}
	facts := make([]exactDocumentationDerivedFact, 0)
	outcomes := make([]exactDocumentationDerivationOccurrenceOutcome, 0)
	err = streamExactDocumentationDerivationPages(reference, program, proof, bodies, func(page exactDocumentationDerivationPage) error {
		if err := accumulator.add(page); err != nil {
			return err
		}
		for _, fact := range page.Facts {
			if err := validateDocumentationClaimOutput(generation.claimSchema, fact.CanonicalOutputFields); err != nil {
				return fmt.Errorf("documentation-derived fact %q: %w", fact.FactID, err)
			}
		}
		// Production retains one bounded fact/outcome copy required by target
		// placement and proof. Page bodies are released after this callback.
		facts = append(facts, page.Facts...)
		outcomes = append(outcomes, page.Outcomes...)
		return nil
	})
	if err != nil {
		return exactDocumentationDerivationExecutionResult{}, err
	}
	seal, err := accumulator.finish()
	if err != nil {
		return exactDocumentationDerivationExecutionResult{}, err
	}
	if seal.Status != exactDocumentationDerivationPagingComplete || !isLowerSHA256(seal.PageSetRootSHA256) {
		return result, fmt.Errorf("documentation derivation page set is not sealed complete")
	}
	if int64(len(facts)) != seal.FactCount || int64(len(outcomes)) != seal.OutcomeCount {
		return result, fmt.Errorf("documentation derivation streaming retention count disagrees with sealed page set")
	}
	if seal.CanonicalFactBytes > math.MaxInt64-seal.CanonicalOutcomeBytes {
		return result, fmt.Errorf("documentation derivation retained canonical byte count overflows INT64")
	}
	retainedCanonicalBytes := seal.CanonicalFactBytes + seal.CanonicalOutcomeBytes
	sort.Slice(facts, func(i, j int) bool { return facts[i].FactID < facts[j].FactID })
	sort.Slice(outcomes, func(i, j int) bool { return outcomes[i].OutcomeID < outcomes[j].OutcomeID })
	result = exactDocumentationDerivationExecutionResult{
		seal:          exactDocumentationDerivationExecutionResultAuthority,
		ExecutionKind: exactDocumentationDerivationExecutionKind,
		Profile:       reference, SemanticGenerationSHA256: generation.identitySHA256,
		Provider: proof.provider, EvidenceRosterSHA256: proof.evidenceSelectionRosterSHA256,
		ClassificationProofSHA256: proof.contentSHA256,
		Outcomes:                  outcomes, Facts: facts,
		OutcomeSetRootSHA256: seal.OutcomeSetRootSHA256,
		FactSetRootSHA256:    exactDocumentationFactRoot(facts),
		CanonicalFactBytes:   seal.CanonicalFactBytes, CanonicalOutcomeBytes: seal.CanonicalOutcomeBytes,
		RetainedCanonicalBytes: retainedCanonicalBytes, MatcherEvaluationCount: seal.MatcherEvaluationCount,
		MatcherInputByteCount:             seal.MatcherInputByteCount,
		MatcherInputByteLimitPerInputUnit: seal.MatcherInputByteLimitPerInputUnit,
		MatcherInputByteLimitPerRun:       seal.MatcherInputByteLimitPerRun,
		PageCount:                         seal.PageCount, PageSetRootSHA256: seal.PageSetRootSHA256,
		Status: exactDocumentationDerivationComplete,
	}
	identity := exactDocumentationDerivationResultIdentity{
		ExecutionKind: result.ExecutionKind,
		ProfileID:     reference.id, ProfileVersion: reference.version, ProfileSHA256: reference.digest,
		SemanticGenerationSHA256: result.SemanticGenerationSHA256,
		Provider:                 result.Provider, EvidenceRosterSHA256: result.EvidenceRosterSHA256,
		ClassificationProofSHA256: result.ClassificationProofSHA256,
		OutcomeCount:              int64(len(result.Outcomes)), OutcomeSetRootSHA256: result.OutcomeSetRootSHA256,
		FactCount: int64(len(result.Facts)), FactSetRootSHA256: result.FactSetRootSHA256,
		CanonicalFactBytes: result.CanonicalFactBytes, CanonicalOutcomeBytes: result.CanonicalOutcomeBytes,
		RetainedCanonicalBytes: result.RetainedCanonicalBytes, MatcherEvaluationCount: result.MatcherEvaluationCount,
		MatcherInputByteCount:             result.MatcherInputByteCount,
		MatcherInputByteLimitPerInputUnit: result.MatcherInputByteLimitPerInputUnit,
		MatcherInputByteLimitPerRun:       result.MatcherInputByteLimitPerRun,
		PageCount:                         result.PageCount,
		PageSetRootSHA256:                 result.PageSetRootSHA256,
		Status:                            result.Status,
	}
	rawIdentity, err := json.Marshal(identity)
	if err != nil {
		return exactDocumentationDerivationExecutionResult{}, fmt.Errorf("marshal documentation derivation result identity: %w", err)
	}
	canonicalIdentity, err := canonicalizeCandidateJSON(rawIdentity)
	if err != nil {
		return exactDocumentationDerivationExecutionResult{}, fmt.Errorf("canonicalize documentation derivation result identity: %w", err)
	}
	result.ResultRootSHA256 = sha256Hex(canonicalIdentity)
	return result, nil
}

func exactDocumentationDerivationOutcomeKey(ruleID, sourceSymbol string, binding classificationArtifactBinding, role, predecessorLocatorID string) string {
	return lengthPrefixedIdentityKey(ruleID, sourceSymbol, binding.ArtifactID, binding.ArtifactVersion, binding.ArtifactSHA256, role, predecessorLocatorID)
}

func exactDocumentationSortedOccurrences(input []sourceClassificationOccurrence) []sourceClassificationOccurrence {
	occurrences := append([]sourceClassificationOccurrence(nil), input...)
	sort.Slice(occurrences, func(i, j int) bool {
		left := occurrences[i]
		right := occurrences[j]
		return lengthPrefixedIdentityKey(left.Binding.ArtifactID, left.Binding.ArtifactVersion, left.Binding.ArtifactSHA256, left.SurfaceKind, left.Locator.ID) <
			lengthPrefixedIdentityKey(right.Binding.ArtifactID, right.Binding.ArtifactVersion, right.Binding.ArtifactSHA256, right.SurfaceKind, right.Locator.ID)
	})
	return occurrences
}
