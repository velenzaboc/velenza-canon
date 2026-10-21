package providerplan

import (
	"encoding/json"
	"fmt"
	"sort"
)

const (
	apiSymbolDerivationBindingKind         = "source_classification_api_symbol_v1"
	typedGraphPredecessorDerivationKind    = "typed_graph_predecessor_derivation_v1"
	typedGraphFactSourceOperationAccess    = "source_operation_resource_access"
	typedGraphFactGraphApplicabilityRule   = "graph_applicability_rule"
	typedGraphArtifactRoleSourceContract   = "source_contract_index"
	typedGraphArtifactRoleAPIApplicability = "api_graph_applicability_profile"
)

type sourceClassificationSelectionSeal struct{}

var sourceClassificationSelectionAuthority = &sourceClassificationSelectionSeal{}

// sourceClassificationSelectionProof exists only after the v4 selection roster,
// every referenced v2 classification row, and every selected occurrence have
// passed exact-byte and exact-set validation. It is deliberately in-process:
// candidate graph rows cannot manufacture this authority in their JSON.
type sourceClassificationSelectionProof struct {
	seal                          *sourceClassificationSelectionSeal
	provider                      string
	evidenceSelectionRosterSHA256 string
	classificationsBySourceSymbol map[string][]sourceClassificationOccurrence
	contentSHA256                 string
}

func newSourceClassificationSelectionProof(provider, rosterSHA256 string, classifications map[string][]sourceClassificationOccurrence) sourceClassificationSelectionProof {
	cloned := make(map[string][]sourceClassificationOccurrence, len(classifications))
	for sourceSymbol, occurrences := range classifications {
		cloned[sourceSymbol] = make([]sourceClassificationOccurrence, len(occurrences))
		for index, occurrence := range occurrences {
			occurrence.Locator.SourceRefs = append([]string(nil), occurrence.Locator.SourceRefs...)
			occurrence.Locator.SourceURLs = append([]string(nil), occurrence.Locator.SourceURLs...)
			cloned[sourceSymbol][index] = occurrence
		}
	}
	proof := sourceClassificationSelectionProof{
		seal:                          sourceClassificationSelectionAuthority,
		provider:                      provider,
		evidenceSelectionRosterSHA256: rosterSHA256,
		classificationsBySourceSymbol: cloned,
	}
	proof.contentSHA256, _ = sourceClassificationSelectionProofContentSHA256(proof)
	return proof
}

func validateSourceClassificationSelectionProof(proof sourceClassificationSelectionProof) error {
	if proof.seal != sourceClassificationSelectionAuthority {
		return fmt.Errorf("source classification selection proof has no in-process authority seal")
	}
	contentSHA256, err := sourceClassificationSelectionProofContentSHA256(proof)
	if err != nil {
		return err
	}
	if !isLowerSHA256(proof.contentSHA256) || proof.contentSHA256 != contentSHA256 {
		return fmt.Errorf("source classification selection proof content differs from its sealed exact identity")
	}
	return nil
}

func sourceClassificationSelectionProofContentSHA256(proof sourceClassificationSelectionProof) (string, error) {
	if !canonicalEvidenceMetadataString(proof.provider, 512) || !isLowerSHA256(proof.evidenceSelectionRosterSHA256) {
		return "", fmt.Errorf("source classification selection proof has an invalid provider or evidence-selection roster coordinate")
	}
	if len(proof.classificationsBySourceSymbol) == 0 {
		return "", fmt.Errorf("source classification selection proof has no classified source symbols")
	}
	sourceSymbols := sortedSetKeys(stringMapKeysAsSet(proof.classificationsBySourceSymbol))
	rows := make([]string, 0)
	for _, sourceSymbol := range sourceSymbols {
		occurrences := proof.classificationsBySourceSymbol[sourceSymbol]
		if !canonicalEvidenceMetadataString(sourceSymbol, 512) || len(occurrences) == 0 {
			return "", fmt.Errorf("source classification selection proof source_symbol %q has an invalid or empty occurrence roster", sourceSymbol)
		}
		occurrenceRows := make([]string, 0, len(occurrences))
		seen := make(map[string]struct{}, len(occurrences))
		for _, occurrence := range occurrences {
			if occurrence.SourceSymbol != sourceSymbol || !canonicalSurfaceKindPattern.MatchString(occurrence.SurfaceKind) || !canonicalSurfaceKindPattern.MatchString(occurrence.Binding.ArtifactID) || !canonicalEvidenceMetadataString(occurrence.Binding.ArtifactVersion, 64) || !isLowerSHA256(occurrence.Binding.ArtifactSHA256) {
				return "", fmt.Errorf("source classification selection proof source_symbol %q has an invalid occurrence coordinate", sourceSymbol)
			}
			locator := occurrence.Locator
			locatorRaw, err := json.Marshal(locator)
			if err != nil {
				return "", fmt.Errorf("source classification selection proof source_symbol %q locator: %w", sourceSymbol, err)
			}
			canonicalLocator, err := canonicalizeCandidateJSON(locatorRaw)
			if err != nil {
				return "", fmt.Errorf("source classification selection proof source_symbol %q locator: %w", sourceSymbol, err)
			}
			row := lengthPrefixedIdentityKey(
				occurrence.Binding.ArtifactID, occurrence.Binding.ArtifactVersion, occurrence.Binding.ArtifactSHA256,
				occurrence.SourceSymbol, occurrence.SurfaceKind, locator.ID, sha256Hex(canonicalLocator),
			)
			if _, duplicate := seen[row]; duplicate {
				return "", fmt.Errorf("source classification selection proof source_symbol %q duplicates locator %q in its exact occurrence roster", sourceSymbol, locator.ID)
			}
			seen[row] = struct{}{}
			occurrenceRows = append(occurrenceRows, row)
		}
		sort.Strings(occurrenceRows)
		rows = append(rows, lengthPrefixedIdentityKey(sourceSymbol, lengthPrefixedIdentityKey(occurrenceRows...)))
	}
	return sha256Hex([]byte(lengthPrefixedIdentityKey(
		"source_classification_selection_proof_v1",
		proof.provider,
		proof.evidenceSelectionRosterSHA256,
		lengthPrefixedIdentityKey(rows...),
	))), nil
}

type candidateAPISymbolDerivationBinding struct {
	Kind                               string   `json:"derivation_binding_kind"`
	ID                                 string   `json:"derivation_binding_id"`
	EvidenceSelectionRosterSHA256      string   `json:"evidence_selection_roster_sha256"`
	ClassificationArtifactID           string   `json:"classification_artifact_id"`
	ClassificationArtifactVersion      string   `json:"classification_artifact_version"`
	ClassificationArtifactSHA256       string   `json:"classification_artifact_sha256"`
	SourceSymbol                       string   `json:"source_symbol"`
	SurfaceKind                        string   `json:"surface_kind"`
	ClassificationOccurrenceLocatorIDs []string `json:"classification_occurrence_locator_ids"`
}

func candidateAPISymbolDerivationBindingID(symbolID string, binding candidateAPISymbolDerivationBinding) string {
	return stableID("capisymder", lengthPrefixedIdentityKey(
		symbolID,
		binding.EvidenceSelectionRosterSHA256,
		binding.ClassificationArtifactID,
		binding.ClassificationArtifactVersion,
		binding.ClassificationArtifactSHA256,
		binding.SourceSymbol,
		binding.SurfaceKind,
		lengthPrefixedIdentityKey(binding.ClassificationOccurrenceLocatorIDs...),
	))
}

// candidateAPISymbolDerivationBindingFor is the sole constructor used by the
// generic producer/tests. The verifier still independently recomputes every
// member from its sealed classification-selection proof.
func candidateAPISymbolDerivationBindingFor(symbol apiSymbol, rosterSHA256 string, occurrences []sourceClassificationOccurrence) (json.RawMessage, error) {
	if len(occurrences) == 0 {
		return nil, fmt.Errorf("candidate API symbol %s has no classification occurrences", symbol.ID)
	}
	binding := candidateAPISymbolDerivationBinding{
		Kind:                          apiSymbolDerivationBindingKind,
		EvidenceSelectionRosterSHA256: rosterSHA256,
		ClassificationArtifactID:      occurrences[0].Binding.ArtifactID,
		ClassificationArtifactVersion: occurrences[0].Binding.ArtifactVersion,
		ClassificationArtifactSHA256:  occurrences[0].Binding.ArtifactSHA256,
		SourceSymbol:                  occurrences[0].SourceSymbol,
		SurfaceKind:                   occurrences[0].SurfaceKind,
	}
	locatorSet := make(map[string]struct{}, len(occurrences))
	for _, occurrence := range occurrences {
		if occurrence.Binding != occurrences[0].Binding || occurrence.SourceSymbol != binding.SourceSymbol || occurrence.SurfaceKind != binding.SurfaceKind {
			return nil, fmt.Errorf("candidate API symbol %s classification occurrence roster is semantically ambiguous", symbol.ID)
		}
		if _, duplicate := locatorSet[occurrence.Locator.ID]; duplicate {
			return nil, fmt.Errorf("candidate API symbol %s classification occurrence roster duplicates locator %s", symbol.ID, occurrence.Locator.ID)
		}
		locatorSet[occurrence.Locator.ID] = struct{}{}
	}
	binding.ClassificationOccurrenceLocatorIDs = sortedSetKeys(locatorSet)
	binding.ID = candidateAPISymbolDerivationBindingID(symbol.ID, binding)
	raw, err := json.Marshal(binding)
	if err != nil {
		return nil, fmt.Errorf("marshal candidate API symbol %s derivation binding: %w", symbol.ID, err)
	}
	return raw, nil
}

func validateCandidateAPISymbolDerivationBindings(plan *parsedPlan, loaded loadedEvidence, rosterSHA256 string) error {
	proof, exists := loaded.ClassificationSelectionProofs[rosterSHA256]
	if !exists || proof.evidenceSelectionRosterSHA256 != rosterSHA256 || proof.provider != plan.Manifest.Provider {
		return fmt.Errorf("candidate API symbol derivation requires the sealed exact evidence-selection/classification proof %s", rosterSHA256)
	}
	if err := validateSourceClassificationSelectionProof(proof); err != nil {
		return fmt.Errorf("candidate API symbol derivation requires the sealed exact evidence-selection/classification proof %s: %w", rosterSHA256, err)
	}
	if !isLowerSHA256(rosterSHA256) {
		return fmt.Errorf("candidate API symbol derivation has malformed evidence-selection roster digest %q", rosterSHA256)
	}
	resolved := make(map[string]string, len(plan.Symbols))
	for _, symbol := range plan.Symbols {
		var binding candidateAPISymbolDerivationBinding
		if err := strictUnmarshal(symbol.DerivationBinding, &binding); err != nil {
			return fmt.Errorf("candidate API symbol %s derivation binding is not the closed %s contract: %w", symbol.ID, apiSymbolDerivationBindingKind, err)
		}
		if binding.Kind != apiSymbolDerivationBindingKind || binding.EvidenceSelectionRosterSHA256 != rosterSHA256 {
			return fmt.Errorf("candidate API symbol %s derivation binding does not select the exact sealed classification roster", symbol.ID)
		}
		if !canonicalEvidenceMetadataString(binding.SourceSymbol, 512) || !canonicalSurfaceKindPattern.MatchString(binding.SurfaceKind) || !canonicalSurfaceKindPattern.MatchString(binding.ClassificationArtifactID) || !canonicalEvidenceMetadataString(binding.ClassificationArtifactVersion, 64) || !isLowerSHA256(binding.ClassificationArtifactSHA256) {
			return fmt.Errorf("candidate API symbol %s derivation binding has an invalid classification coordinate", symbol.ID)
		}
		if symbol.Role != binding.SurfaceKind {
			return fmt.Errorf("candidate API symbol %s role %q does not exactly equal authoritative classification surface_kind %q", symbol.ID, symbol.Role, binding.SurfaceKind)
		}
		occurrences, classified := proof.classificationsBySourceSymbol[binding.SourceSymbol]
		if !classified || len(occurrences) == 0 {
			return fmt.Errorf("candidate API symbol %s names unknown classified source_symbol %q", symbol.ID, binding.SourceSymbol)
		}
		expected, err := candidateAPISymbolDerivationBindingFor(symbol, rosterSHA256, occurrences)
		if err != nil {
			return err
		}
		var exact candidateAPISymbolDerivationBinding
		if err := strictUnmarshal(expected, &exact); err != nil {
			return fmt.Errorf("candidate API symbol %s internal exact binding: %w", symbol.ID, err)
		}
		if binding.ID != exact.ID || binding.ClassificationArtifactID != exact.ClassificationArtifactID || binding.ClassificationArtifactVersion != exact.ClassificationArtifactVersion || binding.ClassificationArtifactSHA256 != exact.ClassificationArtifactSHA256 || binding.SourceSymbol != exact.SourceSymbol || binding.SurfaceKind != exact.SurfaceKind || !equalOrderedStrings(binding.ClassificationOccurrenceLocatorIDs, exact.ClassificationOccurrenceLocatorIDs) {
			return fmt.Errorf("candidate API symbol %s derivation binding is not content-derived and set-equal to its selected v4 classification occurrences", symbol.ID)
		}
		if !equalOrderedStrings(symbol.EvidenceLocatorIDs, exact.ClassificationOccurrenceLocatorIDs) {
			return fmt.Errorf("candidate API symbol %s evidence locator roster is not the exact sorted classification-occurrence locator roster", symbol.ID)
		}
		if priorID, alias := resolved[binding.SourceSymbol]; alias {
			return fmt.Errorf("candidate API symbols %s and %s semantically alias authoritative source_symbol %q", priorID, symbol.ID, binding.SourceSymbol)
		}
		resolved[binding.SourceSymbol] = symbol.ID
	}
	if loaded.CandidateSymbolsBySourceSymbol == nil {
		return fmt.Errorf("candidate API symbol derivation requires an initialized typed symbol index")
	}
	for sourceSymbol := range loaded.CandidateSymbolsBySourceSymbol {
		delete(loaded.CandidateSymbolsBySourceSymbol, sourceSymbol)
	}
	for sourceSymbol, symbolID := range resolved {
		loaded.CandidateSymbolsBySourceSymbol[sourceSymbol] = symbolID
	}
	return nil
}

type typedGraphPredecessorDerivationBinding struct {
	Kind             string                      `json:"derivation_binding_kind"`
	ID               string                      `json:"derivation_binding_id"`
	PredecessorFacts []typedGraphPredecessorFact `json:"predecessor_facts"`
}

type typedGraphPredecessorFact struct {
	ArtifactRole     string `json:"artifact_role"`
	ArtifactID       string `json:"artifact_id"`
	ArtifactVersion  string `json:"artifact_version"`
	ArtifactSHA256   string `json:"artifact_sha256"`
	RowKind          string `json:"row_kind"`
	RowIdentityField string `json:"row_identity_field"`
	RowIdentityValue string `json:"row_identity_value"`
	RowRawSHA256     string `json:"row_raw_sha256"`
	FactKind         string `json:"fact_kind"`
	FactOrdinal      int64  `json:"fact_ordinal"`
}

type resolvedTypedGraphPredecessor struct {
	fact typedGraphPredecessorFact
	row  dependencySemanticRow
}

func typedGraphPredecessorFactIdentity(fact typedGraphPredecessorFact) string {
	return lengthPrefixedIdentityKey(
		fact.ArtifactRole,
		fact.ArtifactID,
		fact.ArtifactVersion,
		fact.ArtifactSHA256,
		fact.RowKind,
		fact.RowIdentityField,
		fact.RowIdentityValue,
		fact.RowRawSHA256,
		fact.FactKind,
		fmt.Sprint(fact.FactOrdinal),
	)
}

func typedGraphPredecessorDerivationBindingID(candidateKind, candidateSemanticIdentity string, facts []typedGraphPredecessorFact) string {
	identities := make([]string, len(facts))
	for index, fact := range facts {
		identities[index] = typedGraphPredecessorFactIdentity(fact)
	}
	return stableID("capider", lengthPrefixedIdentityKey(candidateKind, candidateSemanticIdentity, lengthPrefixedIdentityKey(identities...)))
}

func typedGraphPredecessorFactForRow(artifactRole string, input artifactInput, row dependencySemanticRow, identityField, identityValue, factKind string, factOrdinal int64) (typedGraphPredecessorFact, error) {
	artifactID, idOK := manifestString(input.Manifest, "artifact")
	artifactVersion, versionOK := manifestString(input.Manifest, "artifact_version")
	if !idOK || !versionOK || artifactID == "" || artifactVersion == "" || len(row.raw) == 0 {
		return typedGraphPredecessorFact{}, fmt.Errorf("typed graph predecessor row has no exact artifact and row identity")
	}
	return typedGraphPredecessorFact{
		ArtifactRole: artifactRole, ArtifactID: artifactID, ArtifactVersion: artifactVersion, ArtifactSHA256: sha256Hex(input.Raw),
		RowKind: row.kind, RowIdentityField: identityField, RowIdentityValue: identityValue, RowRawSHA256: sha256Hex(row.raw),
		FactKind: factKind, FactOrdinal: factOrdinal,
	}, nil
}

func typedGraphPredecessorDerivationBindingFor(candidateKind, candidateSemanticIdentity string, facts []typedGraphPredecessorFact) (json.RawMessage, error) {
	cloned := append([]typedGraphPredecessorFact(nil), facts...)
	sort.Slice(cloned, func(i, j int) bool {
		return typedGraphPredecessorFactIdentity(cloned[i]) < typedGraphPredecessorFactIdentity(cloned[j])
	})
	binding := typedGraphPredecessorDerivationBinding{Kind: typedGraphPredecessorDerivationKind, PredecessorFacts: cloned}
	binding.ID = typedGraphPredecessorDerivationBindingID(candidateKind, candidateSemanticIdentity, cloned)
	raw, err := json.Marshal(binding)
	if err != nil {
		return nil, fmt.Errorf("marshal typed graph predecessor derivation binding: %w", err)
	}
	return raw, nil
}

func graphGapDerivationTargetIdentity(gap graphGap) (string, error) {
	proof, err := canonicalizeCandidateJSON(gap.GapProofBinding)
	if err != nil {
		return "", fmt.Errorf("gap_proof_binding: %w", err)
	}
	locators := append([]string(nil), gap.EvidenceLocatorIDs...)
	sort.Strings(locators)
	return lengthPrefixedIdentityKey(
		gap.GapClass,
		gap.BlockedSubjectKind,
		gap.BlockedSubjectID,
		gap.BlockedClaimKind,
		gap.BlockedClaimID,
		gap.Disposition,
		gap.ApplicabilityProfileID,
		gap.ApplicabilityProfileVersion,
		gap.ApplicabilityProfileSHA256,
		gap.ApplicabilityRuleID,
		sha256Hex(proof),
		lengthPrefixedIdentityKey(locators...),
	), nil
}

func validateTypedGraphCandidateDerivationBindings(plan *parsedPlan, loaded loadedEvidence, sourceInput artifactInput, sourceRows dependencySemanticRows, applicabilityInput artifactInput, applicabilityRows dependencySemanticRows) error {
	artifacts := map[string]struct {
		input artifactInput
		rows  dependencySemanticRows
	}{
		typedGraphArtifactRoleSourceContract:   {input: sourceInput, rows: sourceRows},
		typedGraphArtifactRoleAPIApplicability: {input: applicabilityInput, rows: applicabilityRows},
	}

	for _, relationship := range plan.Relationships {
		resolved, err := validateAndResolveTypedGraphPredecessorBinding(relationship.RowKind, relationship.ID, relationship.DerivationBinding, artifacts)
		if err != nil {
			return fmt.Errorf("candidate API relationship %s label %q requires the admitted %s predecessor family; unsupported or self-asserted positive semantics must be emitted as candidate_graph_gap: %w", relationship.ID, relationship.Label, typedGraphFactSourceOperationAccess, err)
		}
		if err := validateSourceOperationAccessRelationshipDerivation(plan, loaded, relationship, resolved); err != nil {
			return fmt.Errorf("candidate API relationship %s label %q requires the admitted %s predecessor family; unsupported or self-asserted positive semantics must be emitted as candidate_graph_gap: %w", relationship.ID, relationship.Label, typedGraphFactSourceOperationAccess, err)
		}
	}

	for _, property := range plan.Properties {
		if _, err := validateAndResolveTypedGraphPredecessorBinding(property.RowKind, property.ID, property.DerivationBinding, artifacts); err != nil {
			return fmt.Errorf("candidate API property claim %s family %q has no admitted typed positive-property predecessor family; emit candidate_graph_gap backed by %s: %w", property.ID, property.Family, typedGraphFactGraphApplicabilityRule, err)
		}
		return fmt.Errorf("candidate API property claim %s family %q has no admitted typed positive-property predecessor family; emit candidate_graph_gap backed by %s", property.ID, property.Family, typedGraphFactGraphApplicabilityRule)
	}

	for _, gap := range plan.Gaps {
		targetIdentity, err := graphGapDerivationTargetIdentity(gap)
		if err != nil {
			return fmt.Errorf("candidate graph gap %s derivation target: %w", gap.ID, err)
		}
		resolved, err := validateAndResolveTypedGraphPredecessorBinding(gap.RowKind, targetIdentity, gap.DerivationBinding, artifacts)
		if err != nil {
			return fmt.Errorf("candidate graph gap %s requires the admitted %s predecessor family: %w", gap.ID, typedGraphFactGraphApplicabilityRule, err)
		}
		if err := validateGraphApplicabilityGapDerivation(gap, resolved); err != nil {
			return fmt.Errorf("candidate graph gap %s requires the admitted %s predecessor family: %w", gap.ID, typedGraphFactGraphApplicabilityRule, err)
		}
	}
	return nil
}

func validateAndResolveTypedGraphPredecessorBinding(candidateKind, candidateSemanticIdentity string, raw json.RawMessage, artifacts map[string]struct {
	input artifactInput
	rows  dependencySemanticRows
}) ([]resolvedTypedGraphPredecessor, error) {
	var binding typedGraphPredecessorDerivationBinding
	if err := strictUnmarshal(raw, &binding); err != nil {
		return nil, fmt.Errorf("derivation binding is not the closed %s contract: %w", typedGraphPredecessorDerivationKind, err)
	}
	if binding.Kind != typedGraphPredecessorDerivationKind || len(binding.PredecessorFacts) == 0 {
		return nil, fmt.Errorf("derivation binding has wrong kind or an empty predecessor fact roster")
	}
	priorIdentity := ""
	for index, fact := range binding.PredecessorFacts {
		identity := typedGraphPredecessorFactIdentity(fact)
		if index > 0 && identity <= priorIdentity {
			return nil, fmt.Errorf("predecessor fact roster is not in strict canonical order")
		}
		priorIdentity = identity
	}
	if binding.ID != typedGraphPredecessorDerivationBindingID(candidateKind, candidateSemanticIdentity, binding.PredecessorFacts) {
		return nil, fmt.Errorf("derivation_binding_id is not content-derived from the outer candidate and exact predecessor roster")
	}

	resolved := make([]resolvedTypedGraphPredecessor, 0, len(binding.PredecessorFacts))
	for index, fact := range binding.PredecessorFacts {
		artifact, exists := artifacts[fact.ArtifactRole]
		if !exists {
			return nil, fmt.Errorf("predecessor_facts[%d] artifact_role %q is outside the closed source/protocol-independent predecessor roster", index, fact.ArtifactRole)
		}
		artifactID, idOK := manifestString(artifact.input.Manifest, "artifact")
		artifactVersion, versionOK := manifestString(artifact.input.Manifest, "artifact_version")
		if !idOK || !versionOK || fact.ArtifactID != artifactID || fact.ArtifactVersion != artifactVersion || fact.ArtifactSHA256 != sha256Hex(artifact.input.Raw) || !isLowerSHA256(fact.ArtifactSHA256) {
			return nil, fmt.Errorf("predecessor_facts[%d] does not bind the exact selected artifact identity/version/raw SHA", index)
		}
		if !canonicalSurfaceKindPattern.MatchString(fact.RowKind) || !canonicalSurfaceKindPattern.MatchString(fact.RowIdentityField) || !canonicalEvidenceMetadataString(fact.RowIdentityValue, 2048) || !isLowerSHA256(fact.RowRawSHA256) {
			return nil, fmt.Errorf("predecessor_facts[%d] has an invalid typed row coordinate", index)
		}
		identityMatches := make([]dependencySemanticRow, 0, 1)
		for _, row := range artifact.rows.byKind[fact.RowKind] {
			identity, ok := semanticString(row.data, fact.RowIdentityField)
			if ok && identity == fact.RowIdentityValue {
				identityMatches = append(identityMatches, row)
			}
		}
		if len(identityMatches) != 1 {
			return nil, fmt.Errorf("predecessor_facts[%d] row coordinate %s/%s=%q resolves %d rows, want exactly 1", index, fact.RowKind, fact.RowIdentityField, fact.RowIdentityValue, len(identityMatches))
		}
		if sha256Hex(identityMatches[0].raw) != fact.RowRawSHA256 {
			return nil, fmt.Errorf("predecessor_facts[%d] row_raw_sha256 does not equal exact selected row bytes", index)
		}
		resolved = append(resolved, resolvedTypedGraphPredecessor{fact: fact, row: identityMatches[0]})
	}
	return resolved, nil
}

func validateSourceOperationAccessRelationshipDerivation(plan *parsedPlan, loaded loadedEvidence, relationship apiRelationship, predecessors []resolvedTypedGraphPredecessor) error {
	if len(predecessors) != 1 {
		return fmt.Errorf("positive relationship has %d predecessors, want exactly one typed source operation access", len(predecessors))
	}
	predecessor := predecessors[0]
	fact := predecessor.fact
	if fact.ArtifactRole != typedGraphArtifactRoleSourceContract || fact.RowKind != "api_operation" || fact.RowIdentityField != "source_symbol" || fact.FactKind != typedGraphFactSourceOperationAccess || fact.FactOrdinal < 0 {
		return fmt.Errorf("predecessor is not a typed source_contract_index api_operation.resource_accesses member")
	}
	operationSourceSymbol, sourceOK := semanticString(predecessor.row.data, "source_symbol")
	operationSurfaceKind, surfaceOK := semanticString(predecessor.row.data, "surface_kind")
	accesses, accessesOK := semanticObjectSlice(predecessor.row.data, "resource_accesses")
	if !sourceOK || !surfaceOK || !accessesOK || fact.FactOrdinal >= int64(len(accesses)) {
		return fmt.Errorf("source operation predecessor row or fact ordinal is incomplete")
	}
	access := accesses[fact.FactOrdinal]
	resourceSourceSymbol, resourceOK := semanticString(access, "source_symbol")
	label, labelOK := semanticString(access, "relationship_label")
	if !resourceOK || !labelOK {
		return fmt.Errorf("source operation resource_accesses[%d] is incomplete", fact.FactOrdinal)
	}
	operationID, operationBound := loaded.CandidateSymbolsBySourceSymbol[operationSourceSymbol]
	resourceID, resourceBound := loaded.CandidateSymbolsBySourceSymbol[resourceSourceSymbol]
	operation, operationExists := plan.Symbols[operationID]
	resource, resourceExists := plan.Symbols[resourceID]
	if !operationBound || !resourceBound || !operationExists || !resourceExists {
		return fmt.Errorf("source operation/resource symbols %q/%q do not resolve through the sealed typed symbol index", operationSourceSymbol, resourceSourceSymbol)
	}
	if operation.Role != "operation" || operationSurfaceKind != operation.Role || resource.Role != "resource" {
		return fmt.Errorf("source operation/resource predecessor roles do not equal operation/resource")
	}
	if relationship.SourceID != operation.ID || relationship.TargetID != resource.ID || relationship.Label != label {
		return fmt.Errorf("relationship endpoints/label do not equal exact source operation resource access")
	}
	expectedID := stableID("capi_rel", lengthPrefixedIdentityKey(label, operation.ID, resource.ID))
	if relationship.ID != expectedID {
		return fmt.Errorf("relationship ID does not equal the content-derived source operation resource access identity")
	}
	return nil
}

func validateGraphApplicabilityGapDerivation(gap graphGap, predecessors []resolvedTypedGraphPredecessor) error {
	if len(predecessors) != 1 {
		return fmt.Errorf("gap has %d predecessors, want exactly one graph applicability rule", len(predecessors))
	}
	predecessor := predecessors[0]
	fact := predecessor.fact
	if fact.ArtifactRole != typedGraphArtifactRoleAPIApplicability || fact.RowIdentityField != "applicability_rule_id" || fact.RowIdentityValue != gap.ApplicabilityRuleID || fact.FactKind != typedGraphFactGraphApplicabilityRule || fact.FactOrdinal != -1 {
		return fmt.Errorf("predecessor is not the gap's exact whole-row API graph applicability rule")
	}
	switch fact.RowKind {
	case "relationship_applicability_rule":
		label, ok := semanticString(predecessor.row.data, "relationship_label")
		if !ok || gap.BlockedClaimKind != "api_relationship" {
			return fmt.Errorf("relationship applicability predecessor does not govern an API relationship gap")
		}
		_ = label // Endpoint/label/cardinality evaluation is independently closed by the applicability proof.
	case "property_family_applicability_rule":
		if _, ok := semanticString(predecessor.row.data, "property_family"); !ok || gap.BlockedClaimKind != "api_property_claim" {
			return fmt.Errorf("property applicability predecessor does not govern an API property gap")
		}
	case "claim_applicability_rule":
		blockedClaimKind, claimOK := semanticString(predecessor.row.data, "blocked_claim_kind")
		blockedSubjectKind, subjectOK := semanticString(predecessor.row.data, "blocked_subject_kind")
		if !claimOK || !subjectOK || gap.BlockedClaimKind != blockedClaimKind || gap.BlockedSubjectKind != blockedSubjectKind {
			return fmt.Errorf("claim applicability predecessor does not exactly govern the gap's blocked claim/subject kinds")
		}
	default:
		return fmt.Errorf("applicability predecessor row_kind %q is unsupported", fact.RowKind)
	}
	return nil
}
