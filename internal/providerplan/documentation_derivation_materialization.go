package providerplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	documentationDerivationClosureComplete = "complete"

	// These are emergency verifier ceilings for the target-placement phase.
	// Parent rows are indexed once per distinct selector-pointer roster; the
	// sealed closure binds both the ceilings and the actual work so a profile
	// set cannot hide an unbounded shape-by-row expansion behind valid facts.
	maxDocumentationTargetParentRegistrations  = int64(1 << 20)
	maxDocumentationTargetSelectorHydrations   = int64(1 << 22)
	maxDocumentationTargetParentCanonicalBytes = int64(256 << 20)
	// Target materializations repeat schema and target coordinates that are not
	// part of the canonical fact-byte total. This independent ceiling therefore
	// leaves the existing 1 GiB fact-envelope acceptance unchanged while making
	// the previously unbounded retained materialization roster explicit.
	maxDocumentationTargetMaterializationCanonicalBytes = int64(8 << 30)
)

var documentationDerivationMemberEnvelopeFields = map[string]struct{}{
	"documentation_derived_fact_ids": {},
	"evidence_locator_ids":           {},
}

type documentationDerivationClosureSeal struct{}

var documentationDerivationClosureAuthority = &documentationDerivationClosureSeal{}

// documentationDerivationClosureProof is minted only after every executable
// profile has run over the sealed exact evidence selection, every output page
// is complete, and every emitted fact is consumed exactly once by a
// schema-authorized semantic row or row member.
type documentationDerivationClosureProof struct {
	seal                                         *documentationDerivationClosureSeal
	provider                                     string
	evidenceSelectionRosterSHA256                string
	derivationProfileArtifactSHA256              string
	classificationProofSHA256                    string
	profilePageSetRootSHA256                     string
	profileResultSetRootSHA256                   string
	profileExecutionSetRootSHA256                string
	profileBudgetRootSHA256                      string
	factEnvelopeRootSHA256                       string
	profileCountLimit                            int64
	ruleCount                                    int64
	ruleCountLimit                               int64
	canonicalProgramBytes                        int64
	canonicalProgramByteLimit                    int64
	canonicalClaimSchemaBytes                    int64
	canonicalClaimSchemaByteLimit                int64
	factCountLimit                               int64
	canonicalFactBytes                           int64
	canonicalFactByteLimit                       int64
	outcomeCountLimit                            int64
	canonicalOutcomeBytes                        int64
	canonicalOutcomeByteLimit                    int64
	retainedCanonicalBytes                       int64
	retainedCanonicalByteLimit                   int64
	pageCountLimit                               int64
	matcherEvaluationCount                       int64
	matcherEvaluationCountLimit                  int64
	matcherInputByteCount                        int64
	matcherInputByteLimit                        int64
	targetMaterializationRootSHA256              string
	targetMaterializationBindingRosterRootSHA256 string
	canonicalTargetMaterializationBytes          int64
	canonicalTargetMaterializationByteLimit      int64
	targetParentRegistrationRootSHA256           string
	profileCount                                 int64
	outcomeCount                                 int64
	factCount                                    int64
	pageCount                                    int64
	wholeRowBindingCount                         int64
	rowMemberBindingCount                        int64
	targetParentRegistrationCount                int64
	targetParentRegistrationLimit                int64
	targetParentRegistrationCanonicalByteCount   int64
	targetParentRegistrationCanonicalByteLimit   int64
	targetSelectorHydrationCount                 int64
	targetSelectorHydrationLimit                 int64
	proofSHA256                                  string
	materializationBindingSHA256ByFact           map[string]string
	materializationCanonicalBytesByFact          map[string]int64
	factsByID                                    map[string]exactDocumentationDerivedFact
	executionSetReceipt                          documentationDerivationExecutionSetReceipt
	parentRegistrationReceipt                    documentationTargetParentRegistrationClosure
}

type documentationDerivationClosureIdentity struct {
	Provider                                     string `json:"provider"`
	EvidenceSelectionRosterSHA256                string `json:"evidence_selection_roster_sha256"`
	DerivationProfileArtifactSHA256              string `json:"derivation_profile_artifact_sha256"`
	ClassificationProofSHA256                    string `json:"classification_proof_sha256"`
	ProfilePageSetRootSHA256                     string `json:"profile_page_set_root_sha256"`
	ProfileResultSetRootSHA256                   string `json:"profile_result_set_root_sha256"`
	ProfileExecutionSetRootSHA256                string `json:"profile_execution_set_root_sha256"`
	ProfileBudgetRootSHA256                      string `json:"profile_budget_root_sha256"`
	FactEnvelopeRootSHA256                       string `json:"fact_envelope_root_sha256"`
	TargetMaterializationRootSHA256              string `json:"target_materialization_root_sha256"`
	TargetMaterializationBindingRosterRootSHA256 string `json:"target_materialization_binding_roster_root_sha256"`
	CanonicalTargetMaterializationBytes          int64  `json:"canonical_target_materialization_bytes"`
	CanonicalTargetMaterializationByteLimit      int64  `json:"canonical_target_materialization_byte_limit"`
	TargetParentRegistrationRootSHA256           string `json:"target_parent_registration_root_sha256"`
	ProfileCount                                 int64  `json:"profile_count"`
	ProfileCountLimit                            int64  `json:"profile_count_limit"`
	RuleCount                                    int64  `json:"rule_count"`
	RuleCountLimit                               int64  `json:"rule_count_limit"`
	CanonicalProgramBytes                        int64  `json:"canonical_program_bytes"`
	CanonicalProgramByteLimit                    int64  `json:"canonical_program_byte_limit"`
	CanonicalClaimSchemaBytes                    int64  `json:"canonical_claim_schema_bytes"`
	CanonicalClaimSchemaByteLimit                int64  `json:"canonical_claim_schema_byte_limit"`
	OutcomeCount                                 int64  `json:"outcome_count"`
	OutcomeCountLimit                            int64  `json:"outcome_count_limit"`
	FactCount                                    int64  `json:"fact_count"`
	FactCountLimit                               int64  `json:"fact_count_limit"`
	CanonicalFactBytes                           int64  `json:"canonical_fact_bytes"`
	CanonicalFactByteLimit                       int64  `json:"canonical_fact_byte_limit"`
	CanonicalOutcomeBytes                        int64  `json:"canonical_outcome_bytes"`
	CanonicalOutcomeByteLimit                    int64  `json:"canonical_outcome_byte_limit"`
	RetainedCanonicalBytes                       int64  `json:"retained_canonical_bytes"`
	RetainedCanonicalByteLimit                   int64  `json:"retained_canonical_byte_limit"`
	PageCount                                    int64  `json:"page_count"`
	PageCountLimit                               int64  `json:"page_count_limit"`
	MatcherEvaluationCount                       int64  `json:"matcher_evaluation_count"`
	MatcherEvaluationCountLimit                  int64  `json:"matcher_evaluation_count_limit"`
	MatcherInputByteCount                        int64  `json:"matcher_input_byte_count"`
	MatcherInputByteLimit                        int64  `json:"matcher_input_byte_limit"`
	WholeRowBindingCount                         int64  `json:"whole_row_binding_count"`
	RowMemberBindingCount                        int64  `json:"row_member_binding_count"`
	TargetParentRegistrationCount                int64  `json:"target_parent_registration_count"`
	TargetParentRegistrationLimit                int64  `json:"target_parent_registration_limit"`
	TargetParentRegistrationCanonicalByteCount   int64  `json:"target_parent_registration_canonical_byte_count"`
	TargetParentRegistrationCanonicalByteLimit   int64  `json:"target_parent_registration_canonical_byte_limit"`
	TargetSelectorHydrationCount                 int64  `json:"target_selector_hydration_count"`
	TargetSelectorHydrationLimit                 int64  `json:"target_selector_hydration_limit"`
	Status                                       string `json:"status"`
}

type documentationTargetGroupKey struct {
	artifactRole      string
	rowKind           string
	bindingKind       string
	memberJSONPointer string
	rowSelectorSHA256 string
}

type documentationTargetShapeKey struct {
	artifactRole      string
	rowKind           string
	bindingKind       string
	memberJSONPointer string
}

type documentationTargetRuleKey struct {
	profileKey string
	ruleID     string
}

type documentationTargetShape struct {
	key                        documentationTargetShapeKey
	rowSelectorJSONPointers    []string
	memberIdentityJSONPointers []string
	resolution                 dependencySemanticDerivationTargetResolution
	memberSchema               documentationMemberSchemaDescriptor
}

type documentationTargetGroup struct {
	shape       documentationTargetShape
	rowSelector []exactDocumentationResolvedTargetRowSelector
	facts       []exactDocumentationDerivedFact
}

type documentationTargetParentIndexKey struct {
	artifactRole         string
	rowKind              string
	selectorRosterSHA256 string
}

type documentationTargetParentRow struct {
	row                dependencySemanticRow
	selectors          []exactDocumentationResolvedTargetRowSelector
	selectorSHA256     string
	canonicalRowSHA256 string
}

type documentationTargetParentIndex struct {
	selectorPointers []string
	selectorDigests  []string
	bySelectorSHA256 map[string]documentationTargetParentRow
}

type documentationTargetParentRegistrationIdentity struct {
	TargetArtifactRole            string `json:"target_artifact_role"`
	TargetArtifactSHA256          string `json:"target_artifact_sha256"`
	TargetSchemaRole              string `json:"target_schema_role"`
	TargetSchemaID                string `json:"target_schema_id"`
	TargetSchemaVersion           string `json:"target_schema_version"`
	TargetSchemaSHA256            string `json:"target_schema_sha256"`
	TargetRowKind                 string `json:"target_row_kind"`
	TargetBindingKind             string `json:"target_binding_kind"`
	TargetMemberJSONPointer       string `json:"target_member_json_pointer"`
	TargetRowSelectorRosterSHA256 string `json:"target_row_selector_roster_sha256"`
	TargetRowSelectorSHA256       string `json:"target_row_selector_sha256"`
	TargetRowCanonicalSHA256      string `json:"target_row_canonical_sha256"`
}

type documentationTargetParentRegistrationClosure struct {
	seal               *documentationTargetParentRegistrationSeal
	registrations      []documentationTargetParentRegistrationReceipt
	rootSHA256         string
	registrationCount  int64
	selectorHydrations int64
	canonicalByteCount int64
}

type documentationTargetParentRegistrationSeal struct{}

var documentationTargetParentRegistrationAuthority = &documentationTargetParentRegistrationSeal{}

type documentationTargetParentRegistrationReceipt struct {
	SHA256         string `json:"sha256"`
	CanonicalBytes int64  `json:"canonical_bytes"`
}

type documentationDerivationExecutionSetReceipt struct {
	seal       *exactDocumentationDerivationProfileExecutionSetSeal
	identity   exactDocumentationDerivationProfileExecutionSetIdentity
	rootSHA256 string
}

type documentationTargetMaterializationIdentity struct {
	EvidenceLocatorID             string `json:"evidence_locator_id"`
	EvidenceLocatorIdentitySHA256 string `json:"evidence_locator_identity_sha256"`
	FactID                        string `json:"fact_id"`
	FactOutputSHA256              string `json:"fact_output_sha256"`
	TargetArtifactRole            string `json:"target_artifact_role"`
	TargetArtifactSHA256          string `json:"target_artifact_sha256"`
	TargetBindingKind             string `json:"target_binding_kind"`
	TargetMemberCanonicalSHA256   string `json:"target_member_canonical_sha256"`
	TargetMemberIdentitySHA256    string `json:"target_member_identity_sha256"`
	TargetMemberInstancePointer   string `json:"target_member_instance_pointer"`
	TargetMemberJSONPointer       string `json:"target_member_json_pointer"`
	TargetRowCanonicalSHA256      string `json:"target_row_canonical_sha256"`
	TargetRowKind                 string `json:"target_row_kind"`
	TargetRowSelectorSHA256       string `json:"target_row_selector_sha256"`
	TargetSchemaID                string `json:"target_schema_id"`
	TargetSchemaRole              string `json:"target_schema_role"`
	TargetSchemaSHA256            string `json:"target_schema_sha256"`
	TargetSchemaVersion           string `json:"target_schema_version"`
}

type documentationTargetMaterialization struct {
	identity       documentationTargetMaterializationIdentity
	canonical      []byte
	bindingSHA256  string
	canonicalBytes int64
}

type documentationMemberSchemaDescriptor struct {
	pointer       string
	tokens        []string
	propertyNames map[string]struct{}
	root          map[string]interface{}
	itemSchema    map[string]interface{}
}

func executeAndValidateDocumentationDerivationClosure(
	derivationRows dependencySemanticRows,
	derivationState documentationClaimDerivationState,
	targetAuthority dependencySemanticDerivationTargetSchemaAuthority,
	roleArtifacts map[string]artifactInput,
	roleRows map[string]dependencySemanticRows,
	classificationProof sourceClassificationSelectionProof,
	bodies map[string]exactEvidenceBody,
) (documentationDerivationClosureProof, error) {
	var empty documentationDerivationClosureProof
	if targetAuthority.seal != dependencySemanticDerivationTargetSchemaAuthorityIdentity || len(targetAuthority.byRole) == 0 {
		return empty, fmt.Errorf("documentation derivation closure requires sealed target-schema authority")
	}
	if err := requireExactSet("documentation derivation target artifact roles", stringMapKeysAsSet(roleArtifacts), stringMapKeysAsSet(targetAuthority.byRole)); err != nil {
		return empty, err
	}
	if err := requireExactSet("documentation derivation target row roles", stringMapKeysAsSet(roleRows), stringMapKeysAsSet(targetAuthority.byRole)); err != nil {
		return empty, err
	}
	for _, role := range sortedProviderStringMapKeys(targetAuthority.byRole) {
		target := targetAuthority.byRole[role]
		artifact := roleArtifacts[role]
		rows := roleRows[role]
		if target.artifactRole != role || !isLowerSHA256(target.artifactSHA256) || target.artifactSHA256 != sha256Hex(artifact.Raw) || !bytes.Equal(artifact.Raw, rows.raw) || (artifact.SHA256 != "" && artifact.SHA256 != target.artifactSHA256) {
			return empty, fmt.Errorf("documentation derivation target role %q does not bind the exact schema-validated artifact and parsed-row bytes", role)
		}
	}
	if err := validateSourceClassificationSelectionProof(classificationProof); err != nil {
		return empty, fmt.Errorf("documentation derivation classification proof: %w", err)
	}
	if derivationState.artifactSHA256 != sha256Hex(derivationRows.raw) {
		return empty, fmt.Errorf("documentation derivation state does not bind the exact profile artifact bytes")
	}
	executableProfiles, err := parseExecutableDocumentationDerivationProfiles(derivationRows)
	if err != nil {
		return empty, err
	}
	if err := requireExactSet("documentation derivation executable profile coordinates", stringMapKeysAsSet(executableProfiles), stringMapKeysAsSet(derivationState.derivations)); err != nil {
		return empty, err
	}
	for _, key := range sortedProviderStringMapKeys(executableProfiles) {
		executable := executableProfiles[key]
		declared := derivationState.derivations[key]
		if executable.ClaimKind != declared.claimKind {
			return empty, fmt.Errorf("documentation derivation executable profile %q claim kind differs from its validated declaration", key)
		}
	}
	execution, err := executeDocumentationDerivationProfileSet(executableProfiles, classificationProof, bodies)
	if err != nil {
		return empty, err
	}
	if err := validateExactDocumentationDerivationProfileExecutionSet(execution, classificationProof); err != nil {
		return empty, err
	}
	facts := make([]exactDocumentationDerivedFact, 0)
	for _, result := range execution.Results {
		facts = append(facts, result.Facts...)
	}
	var parentRegistrationClosure documentationTargetParentRegistrationClosure
	materializations, wholeCount, memberCount, _, _, err := validateExactDocumentationTargetMaterializationsWithResourceCounts(executableProfiles, facts, targetAuthority, roleArtifacts, roleRows, &parentRegistrationClosure)
	if err != nil {
		return empty, err
	}
	// The target validator has finished with its flattened view. The execution
	// set remains the sole owner until sealing transfers each fact into proof.
	facts = nil
	return sealDocumentationDerivationClosure(
		derivationState.artifactSHA256,
		&execution,
		classificationProof,
		materializations,
		parentRegistrationClosure,
		wholeCount,
		memberCount,
	)
}

func validateExactDocumentationTargetMaterializations(
	profiles map[string]executableDocumentationDerivationProfile,
	facts []exactDocumentationDerivedFact,
	targetAuthority dependencySemanticDerivationTargetSchemaAuthority,
	roleArtifacts map[string]artifactInput,
	roleRows map[string]dependencySemanticRows,
) ([]documentationTargetMaterialization, int64, int64, error) {
	materializations, wholeCount, memberCount, _, _, err := validateExactDocumentationTargetMaterializationsWithResourceCounts(profiles, facts, targetAuthority, roleArtifacts, roleRows, nil)
	return materializations, wholeCount, memberCount, err
}

func validateExactDocumentationTargetMaterializationsWithResourceCounts(
	profiles map[string]executableDocumentationDerivationProfile,
	facts []exactDocumentationDerivedFact,
	targetAuthority dependencySemanticDerivationTargetSchemaAuthority,
	roleArtifacts map[string]artifactInput,
	roleRows map[string]dependencySemanticRows,
	parentRegistrationOutput *documentationTargetParentRegistrationClosure,
) ([]documentationTargetMaterialization, int64, int64, int64, int64, error) {
	if parentRegistrationOutput != nil {
		*parentRegistrationOutput = documentationTargetParentRegistrationClosure{}
	}
	groups, shapes, rules, err := registerDocumentationTargetDeclarations(profiles, targetAuthority, roleArtifacts, roleRows)
	if err != nil {
		return nil, 0, 0, 0, 0, err
	}
	allFacts := make(map[string]exactDocumentationDerivedFact, len(facts))
	for _, fact := range facts {
		if err := validateExactDocumentationDerivedFactIntegrity(fact); err != nil {
			return nil, 0, 0, 0, 0, fmt.Errorf("documentation-derived fact %q: %w", fact.FactID, err)
		}
		if _, duplicate := allFacts[fact.FactID]; duplicate {
			return nil, 0, 0, 0, 0, fmt.Errorf("documentation-derived fact roster duplicates fact %q", fact.FactID)
		}
		allFacts[fact.FactID] = fact
		ruleKey := documentationTargetRuleKey{profileKey: dependencyProfileReferenceKey(fact.Profile), ruleID: fact.RuleID}
		shapeKey, declared := rules[ruleKey]
		if !declared {
			return nil, 0, 0, 0, 0, fmt.Errorf("documentation-derived fact %q does not bind one declared executable rule target", fact.FactID)
		}
		shape := shapes[shapeKey]
		if fact.TargetArtifactRole != shape.key.artifactRole || fact.TargetRowKind != shape.key.rowKind || fact.TargetBindingKind != shape.key.bindingKind || fact.TargetMemberJSONPointer != shape.key.memberJSONPointer {
			return nil, 0, 0, 0, 0, fmt.Errorf("documentation-derived fact %q target coordinate differs from its executable rule declaration", fact.FactID)
		}
		if !equalOrderedStrings(resolvedDocumentationSelectorPointers(fact.TargetRowSelector), shape.rowSelectorJSONPointers) || !equalOrderedStrings(resolvedDocumentationMemberIdentityPointers(fact.TargetMemberIdentity), shape.memberIdentityJSONPointers) {
			return nil, 0, 0, 0, 0, fmt.Errorf("documentation-derived fact %q row selector or member identity roster differs from its executable rule declaration", fact.FactID)
		}
		artifact, artifactOK := roleArtifacts[fact.TargetArtifactRole]
		rows, rowsOK := roleRows[fact.TargetArtifactRole]
		if !artifactOK || !rowsOK || sha256Hex(artifact.Raw) != sha256Hex(rows.raw) {
			return nil, 0, 0, 0, 0, fmt.Errorf("documentation-derived fact %q target role %q has no exact semantic artifact/row binding", fact.FactID, fact.TargetArtifactRole)
		}
		key := documentationTargetGroupKey{artifactRole: fact.TargetArtifactRole, rowKind: fact.TargetRowKind, bindingKind: fact.TargetBindingKind, memberJSONPointer: fact.TargetMemberJSONPointer, rowSelectorSHA256: fact.TargetRowSelectorSHA256}
		group, exists := groups[key]
		if exists && !equalResolvedDocumentationTargetRowSelectors(group.rowSelector, fact.TargetRowSelector) {
			return nil, 0, 0, 0, 0, fmt.Errorf("documentation-derived fact %q aliases a target selector digest with different selector values", fact.FactID)
		}
		if !exists {
			group = documentationTargetGroup{shape: shape, rowSelector: cloneResolvedDocumentationTargetRowSelectors(fact.TargetRowSelector)}
		}
		group.facts = append(group.facts, fact)
		groups[key] = group
	}
	parentIndexes, parentRegistrationCount, selectorHydrationCount, err := registerDocumentationTargetParentRowsWithRoot(groups, shapes, roleRows, maxDocumentationTargetParentRegistrations, maxDocumentationTargetSelectorHydrations, maxDocumentationTargetParentCanonicalBytes, parentRegistrationOutput)
	if err != nil {
		return nil, 0, 0, 0, 0, err
	}

	keys := make([]documentationTargetGroupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left := lengthPrefixedIdentityKey(keys[i].artifactRole, keys[i].rowKind, keys[i].bindingKind, keys[i].memberJSONPointer, keys[i].rowSelectorSHA256)
		right := lengthPrefixedIdentityKey(keys[j].artifactRole, keys[j].rowKind, keys[j].bindingKind, keys[j].memberJSONPointer, keys[j].rowSelectorSHA256)
		return left < right
	})
	usedFacts := map[string]struct{}{}
	materializations := make([]documentationTargetMaterialization, 0, len(facts))
	var wholeCount, memberCount, canonicalMaterializationBytes int64
	for _, key := range keys {
		group := groups[key]
		groupFacts := group.facts
		artifact := roleArtifacts[key.artifactRole]
		rows := roleRows[key.artifactRole]
		resolution := group.shape.resolution
		switch key.bindingKind {
		case exactDocumentationTargetWholeRow:
			selectedRows := rows.byKind[key.rowKind]
			if len(selectedRows) != len(groupFacts) {
				return nil, 0, 0, 0, 0, fmt.Errorf("documentation whole-row target role %q row kind %q has %d rows, want exactly %d executor facts", key.artifactRole, key.rowKind, len(selectedRows), len(groupFacts))
			}
			if err := validateExactDocumentationDerivedSemanticRowSet(key.artifactRole, selectedRows, groupFacts); err != nil {
				return nil, 0, 0, 0, 0, err
			}
			factsByID := make(map[string]exactDocumentationDerivedFact, len(groupFacts))
			for _, fact := range groupFacts {
				factsByID[fact.FactID] = fact
			}
			for _, row := range selectedRows {
				factID, _ := semanticString(row.data, exactDocumentationDerivedFactIDField)
				fact := factsByID[factID]
				if _, duplicate := usedFacts[factID]; duplicate {
					return nil, 0, 0, 0, 0, fmt.Errorf("documentation-derived fact %q is materialized more than once", factID)
				}
				canonicalRowSHA256, err := canonicalDocumentationTargetRowSHA256(row)
				if err != nil {
					return nil, 0, 0, 0, 0, err
				}
				materialization, err := newDocumentationTargetMaterialization(fact, artifact, resolution, canonicalRowSHA256, "", nil, maxDocumentationTargetMaterializationCanonicalBytes-canonicalMaterializationBytes)
				if err != nil {
					return nil, 0, 0, 0, 0, err
				}
				canonicalMaterializationBytes += materialization.canonicalBytes
				usedFacts[factID] = struct{}{}
				materializations = append(materializations, materialization)
				wholeCount++
			}
		case exactDocumentationTargetRowMember:
			descriptor := group.shape.memberSchema
			if descriptor.pointer != key.memberJSONPointer || descriptor.root == nil || descriptor.itemSchema == nil {
				return nil, 0, 0, 0, 0, fmt.Errorf("documentation target role %q row kind %q has no cached exact member schema", key.artifactRole, key.rowKind)
			}
			indexKey, err := documentationTargetParentIndexKeyForShape(group.shape)
			if err != nil {
				return nil, 0, 0, 0, 0, err
			}
			parentIndex, exists := parentIndexes[indexKey]
			if !exists {
				return nil, 0, 0, 0, 0, fmt.Errorf("documentation target role %q row kind %q has no sealed parent index", key.artifactRole, key.rowKind)
			}
			parent, exists := parentIndex.bySelectorSHA256[key.rowSelectorSHA256]
			if !exists || !equalResolvedDocumentationTargetRowSelectors(parent.selectors, group.rowSelector) {
				return nil, 0, 0, 0, 0, fmt.Errorf("documentation target role %q row kind %q parent-row selector resolves 0 rows, want exactly one", key.artifactRole, key.rowKind)
			}
			row := parent.row
			value, err := documentationJSONPointerValue(row.data, descriptor.tokens)
			if err != nil {
				return nil, 0, 0, 0, 0, fmt.Errorf("documentation target member pointer %q: %w", descriptor.pointer, err)
			}
			members, ok := value.([]interface{})
			if !ok {
				return nil, 0, 0, 0, 0, fmt.Errorf("documentation target member pointer %q does not select an array", descriptor.pointer)
			}
			groupByID := make(map[string]exactDocumentationDerivedFact, len(groupFacts))
			for _, fact := range groupFacts {
				groupByID[fact.FactID] = fact
			}
			seenMemberIdentities := map[string]int{}
			for index, rawMember := range members {
				member, ok := rawMember.(map[string]interface{})
				if !ok {
					return nil, 0, 0, 0, 0, fmt.Errorf("documentation target member %q[%d] is not an object", descriptor.pointer, index)
				}
				if err := requireExactSet("documentation target member schema fields", stringMapKeysAsSet(member), descriptor.propertyNames); err != nil {
					return nil, 0, 0, 0, 0, err
				}
				factIDs, factOK := semanticStringSlice(member, "documentation_derived_fact_ids")
				locatorIDs, locatorOK := semanticStringSlice(member, "evidence_locator_ids")
				if !factOK || len(factIDs) == 0 || hasEmptyOrDuplicateSemanticStrings(factIDs) || !strictlyIncreasingStrings(factIDs) || !locatorOK || len(locatorIDs) == 0 || hasEmptyOrDuplicateSemanticStrings(locatorIDs) || !strictlyIncreasingStrings(locatorIDs) {
					return nil, 0, 0, 0, 0, fmt.Errorf("documentation target member %q[%d] has no canonical nonempty fact/locator rosters", descriptor.pointer, index)
				}
				payload := make(map[string]interface{}, len(member)-len(documentationDerivationMemberEnvelopeFields))
				for field, memberValue := range member {
					if _, envelope := documentationDerivationMemberEnvelopeFields[field]; !envelope {
						payload[field] = memberValue
					}
				}
				canonicalPayload, err := canonicalDocumentationJSON(payload)
				if err != nil {
					return nil, 0, 0, 0, 0, err
				}
				memberIdentity, memberIdentitySHA256, err := resolveDocumentationMemberIdentity(payload, group.shape.memberIdentityJSONPointers)
				if err != nil {
					return nil, 0, 0, 0, 0, fmt.Errorf("documentation target member %q[%d] semantic identity: %w", descriptor.pointer, index, err)
				}
				if priorIndex, duplicate := seenMemberIdentities[memberIdentitySHA256]; duplicate {
					return nil, 0, 0, 0, 0, fmt.Errorf("documentation target pointer %q splits semantic member identity %s across members %d and %d", descriptor.pointer, memberIdentitySHA256, priorIndex, index)
				}
				seenMemberIdentities[memberIdentitySHA256] = index
				canonicalMember, err := canonicalDocumentationJSON(member)
				if err != nil {
					return nil, 0, 0, 0, 0, err
				}
				expectedLocators := map[string]struct{}{}
				for _, factID := range factIDs {
					fact, exists := groupByID[factID]
					if !exists {
						return nil, 0, 0, 0, 0, fmt.Errorf("documentation target member %q[%d] references unknown or cross-target fact %q", descriptor.pointer, index, factID)
					}
					if _, duplicate := usedFacts[factID]; duplicate {
						return nil, 0, 0, 0, 0, fmt.Errorf("documentation-derived fact %q is materialized by more than one target member", factID)
					}
					if !bytes.Equal(canonicalPayload, fact.CanonicalOutputFields) || !equalOrderedStrings(sortedSetKeys(stringMapKeysAsSet(payload)), fact.ExactOutputFieldNames) {
						return nil, 0, 0, 0, 0, fmt.Errorf("documentation target member %q[%d] semantic payload differs from fact %q", descriptor.pointer, index, factID)
					}
					if fact.TargetMemberIdentitySHA256 != memberIdentitySHA256 || !equalResolvedDocumentationMemberIdentities(fact.TargetMemberIdentity, memberIdentity) {
						return nil, 0, 0, 0, 0, fmt.Errorf("documentation target member %q[%d] semantic identity differs from fact %q", descriptor.pointer, index, factID)
					}
					expectedLocators[fact.EvidenceLocatorID] = struct{}{}
					instancePointer := descriptor.pointer + "/" + strconv.Itoa(index)
					materialization, err := newDocumentationTargetMaterialization(fact, artifact, resolution, parent.canonicalRowSHA256, instancePointer, canonicalMember, maxDocumentationTargetMaterializationCanonicalBytes-canonicalMaterializationBytes)
					if err != nil {
						return nil, 0, 0, 0, 0, err
					}
					canonicalMaterializationBytes += materialization.canonicalBytes
					usedFacts[factID] = struct{}{}
					materializations = append(materializations, materialization)
					memberCount++
				}
				if err := requireExactSet("documentation target member locator roster", stringSliceSet(locatorIDs), expectedLocators); err != nil {
					return nil, 0, 0, 0, 0, err
				}
			}
		default:
			return nil, 0, 0, 0, 0, fmt.Errorf("documentation target binding kind %q is unsupported", key.bindingKind)
		}
	}
	if err := requireExactSet("documentation-derived fact materialization", usedFacts, stringMapKeysAsSet(allFacts)); err != nil {
		return nil, 0, 0, 0, 0, err
	}
	if len(materializations) != len(facts) {
		return nil, 0, 0, 0, 0, fmt.Errorf("documentation target materialization count %d does not equal emitted fact count %d", len(materializations), len(facts))
	}
	return materializations, wholeCount, memberCount, parentRegistrationCount, selectorHydrationCount, nil
}

// registerDocumentationTargetParentRows makes row-member validation target-
// total. Capture-derived selectors cannot be pre-registered from rule literals,
// so every schema-authorized parent row is resolved through the declaration's
// exact selector pointers and registered before any member is inspected. This
// prevents an extra parent row (and its documentation evidence envelope) from
// remaining invisible merely because no emitted fact selected it.
func registerDocumentationTargetParentRows(
	groups map[documentationTargetGroupKey]documentationTargetGroup,
	shapes map[documentationTargetShapeKey]documentationTargetShape,
	roleRows map[string]dependencySemanticRows,
	maxParentRegistrations int64,
	maxSelectorHydrations int64,
) (map[documentationTargetParentIndexKey]documentationTargetParentIndex, int64, int64, error) {
	return registerDocumentationTargetParentRowsWithRoot(groups, shapes, roleRows, maxParentRegistrations, maxSelectorHydrations, maxDocumentationTargetParentCanonicalBytes, nil)
}

func registerDocumentationTargetParentRowsWithRoot(
	groups map[documentationTargetGroupKey]documentationTargetGroup,
	shapes map[documentationTargetShapeKey]documentationTargetShape,
	roleRows map[string]dependencySemanticRows,
	maxParentRegistrations int64,
	maxSelectorHydrations int64,
	maxParentCanonicalBytes int64,
	parentRegistrationOutput *documentationTargetParentRegistrationClosure,
) (map[documentationTargetParentIndexKey]documentationTargetParentIndex, int64, int64, error) {
	if parentRegistrationOutput != nil {
		*parentRegistrationOutput = documentationTargetParentRegistrationClosure{}
	}
	if maxParentRegistrations <= 0 || maxParentRegistrations > maxDocumentationTargetParentRegistrations || maxSelectorHydrations <= 0 || maxSelectorHydrations > maxDocumentationTargetSelectorHydrations || maxParentCanonicalBytes <= 0 || maxParentCanonicalBytes > maxDocumentationTargetParentCanonicalBytes {
		return nil, 0, 0, fmt.Errorf("documentation target parent indexing has invalid resource limits")
	}
	indexes := map[documentationTargetParentIndexKey]documentationTargetParentIndex{}
	canonicalRowSHA256ByCoordinate := map[string]string{}
	parentRegistrationRows := make([][]byte, 0)
	parentRegistrationReceipts := make([]documentationTargetParentRegistrationReceipt, 0)
	var parentRegistrationCount, selectorHydrationCount, parentRegistrationCanonicalByteCount int64
	allShapeKeys := make([]documentationTargetShapeKey, 0, len(shapes))
	for key := range shapes {
		allShapeKeys = append(allShapeKeys, key)
	}
	sort.Slice(allShapeKeys, func(i, j int) bool {
		left := lengthPrefixedIdentityKey(allShapeKeys[i].artifactRole, allShapeKeys[i].rowKind, allShapeKeys[i].memberJSONPointer)
		right := lengthPrefixedIdentityKey(allShapeKeys[j].artifactRole, allShapeKeys[j].rowKind, allShapeKeys[j].memberJSONPointer)
		return left < right
	})
	shapeKeys := make([]documentationTargetShapeKey, 0, len(allShapeKeys))
	for _, key := range allShapeKeys {
		shape := shapes[key]
		if key.bindingKind == exactDocumentationTargetRowMember {
			if len(shape.rowSelectorJSONPointers) == 0 {
				return nil, 0, 0, fmt.Errorf("documentation row-member target role %q row kind %q has no selector roster", key.artifactRole, key.rowKind)
			}
			shapeKeys = append(shapeKeys, key)
		}
	}
	sort.Slice(shapeKeys, func(i, j int) bool {
		left := lengthPrefixedIdentityKey(shapeKeys[i].artifactRole, shapeKeys[i].rowKind, shapeKeys[i].memberJSONPointer)
		right := lengthPrefixedIdentityKey(shapeKeys[j].artifactRole, shapeKeys[j].rowKind, shapeKeys[j].memberJSONPointer)
		return left < right
	})
	for _, shapeKey := range shapeKeys {
		shape := shapes[shapeKey]
		rows, exists := roleRows[shapeKey.artifactRole]
		if !exists {
			return nil, 0, 0, fmt.Errorf("documentation row-member target role %q has no parsed target rows", shapeKey.artifactRole)
		}
		indexKey, err := documentationTargetParentIndexKeyForShape(shape)
		if err != nil {
			return nil, 0, 0, err
		}
		index, indexed := indexes[indexKey]
		if !indexed {
			rowCount := int64(len(rows.byKind[shapeKey.rowKind]))
			selectorCount := int64(len(shape.rowSelectorJSONPointers))
			// Refuse the complete index shape before allocating or hydrating it.
			// The parent-registration ceiling is deliberately smaller than the
			// selector-work ceiling and therefore remains the allocation bound
			// even for a one-selector row shape.
			if rowCount > maxParentRegistrations-parentRegistrationCount {
				return nil, 0, 0, fmt.Errorf("documentation target parent registrations exceed limit %d", maxParentRegistrations)
			}
			if selectorCount <= 0 || rowCount > (maxSelectorHydrations-selectorHydrationCount)/selectorCount {
				return nil, 0, 0, fmt.Errorf("documentation target selector hydrations exceed limit %d", maxSelectorHydrations)
			}
			index = documentationTargetParentIndex{
				selectorPointers: append([]string(nil), shape.rowSelectorJSONPointers...),
				bySelectorSHA256: make(map[string]documentationTargetParentRow, int(rowCount)),
			}
			selectorTokens := make([][]string, len(shape.rowSelectorJSONPointers))
			for selectorIndex, pointer := range shape.rowSelectorJSONPointers {
				tokens, err := exactDocumentationJSONPointerTokens(pointer)
				if err != nil {
					return nil, 0, 0, fmt.Errorf("documentation target role %q row kind %q selector %q: %w", shapeKey.artifactRole, shapeKey.rowKind, pointer, err)
				}
				selectorTokens[selectorIndex] = tokens
			}
			for rowIndex, row := range rows.byKind[shapeKey.rowKind] {
				if int64(len(shape.rowSelectorJSONPointers)) > maxSelectorHydrations-selectorHydrationCount {
					return nil, 0, 0, fmt.Errorf("documentation target selector hydrations exceed limit %d", maxSelectorHydrations)
				}
				selectors := make([]exactDocumentationResolvedTargetRowSelector, len(shape.rowSelectorJSONPointers))
				for selectorIndex, pointer := range shape.rowSelectorJSONPointers {
					value, err := documentationJSONPointerValue(row.data, selectorTokens[selectorIndex])
					if err != nil {
						return nil, 0, 0, fmt.Errorf("documentation target role %q row kind %q row %d selector %q: %w", shapeKey.artifactRole, shapeKey.rowKind, rowIndex, pointer, err)
					}
					text, ok := value.(string)
					if !ok || text == "" {
						return nil, 0, 0, fmt.Errorf("documentation target role %q row kind %q row %d selector %q is not a nonempty string", shapeKey.artifactRole, shapeKey.rowKind, rowIndex, pointer)
					}
					selectors[selectorIndex] = exactDocumentationResolvedTargetRowSelector{TargetRowJSONPointer: pointer, ExpectedString: text}
				}
				selectorHydrationCount += int64(len(selectors))
				selectorSHA256, err := canonicalDocumentationDigest(selectors)
				if err != nil {
					return nil, 0, 0, err
				}
				rowCoordinate := lengthPrefixedIdentityKey(shapeKey.artifactRole, shapeKey.rowKind, strconv.Itoa(rowIndex))
				canonicalRowSHA256, canonicalized := canonicalRowSHA256ByCoordinate[rowCoordinate]
				if !canonicalized {
					canonicalRowSHA256, err = canonicalDocumentationTargetRowSHA256(row)
					if err != nil {
						return nil, 0, 0, fmt.Errorf("documentation target role %q row kind %q row %d: %w", shapeKey.artifactRole, shapeKey.rowKind, rowIndex, err)
					}
					canonicalRowSHA256ByCoordinate[rowCoordinate] = canonicalRowSHA256
				}
				if prior, duplicate := index.bySelectorSHA256[selectorSHA256]; duplicate {
					if !equalResolvedDocumentationTargetRowSelectors(prior.selectors, selectors) {
						return nil, 0, 0, fmt.Errorf("documentation target role %q row kind %q aliases one selector digest across different parent rows", shapeKey.artifactRole, shapeKey.rowKind)
					}
					return nil, 0, 0, fmt.Errorf("documentation target role %q row kind %q duplicates parent-row selector identity %s", shapeKey.artifactRole, shapeKey.rowKind, selectorSHA256)
				}
				index.bySelectorSHA256[selectorSHA256] = documentationTargetParentRow{
					row: row, selectors: selectors, selectorSHA256: selectorSHA256, canonicalRowSHA256: canonicalRowSHA256,
				}
			}
			index.selectorDigests = sortedSetKeys(stringMapKeysAsSet(index.bySelectorSHA256))
			indexes[indexKey] = index
		} else if !equalOrderedStrings(index.selectorPointers, shape.rowSelectorJSONPointers) {
			return nil, 0, 0, fmt.Errorf("documentation target parent index aliases one selector-roster digest across different pointers")
		}
		if int64(len(index.selectorDigests)) > maxParentRegistrations-parentRegistrationCount {
			return nil, 0, 0, fmt.Errorf("documentation target parent registrations exceed limit %d", maxParentRegistrations)
		}
		parentRegistrationCount += int64(len(index.selectorDigests))
		for _, selectorSHA256 := range index.selectorDigests {
			parent := index.bySelectorSHA256[selectorSHA256]
			registration, err := canonicalDocumentationTargetParentRegistration(documentationTargetParentRegistrationIdentity{
				TargetArtifactRole:            shapeKey.artifactRole,
				TargetArtifactSHA256:          shape.resolution.artifactSHA256,
				TargetSchemaRole:              shape.resolution.schemaRole,
				TargetSchemaID:                shape.resolution.schemaID,
				TargetSchemaVersion:           shape.resolution.schemaVersion,
				TargetSchemaSHA256:            shape.resolution.schemaSHA256,
				TargetRowKind:                 shapeKey.rowKind,
				TargetBindingKind:             shapeKey.bindingKind,
				TargetMemberJSONPointer:       shapeKey.memberJSONPointer,
				TargetRowSelectorRosterSHA256: indexKey.selectorRosterSHA256,
				TargetRowSelectorSHA256:       selectorSHA256,
				TargetRowCanonicalSHA256:      parent.canonicalRowSHA256,
			})
			if err != nil {
				return nil, 0, 0, err
			}
			if int64(len(registration)) > maxParentCanonicalBytes-parentRegistrationCanonicalByteCount {
				return nil, 0, 0, fmt.Errorf("documentation target parent canonical registration bytes exceed limit %d", maxParentCanonicalBytes)
			}
			parentRegistrationCanonicalByteCount += int64(len(registration))
			registrationSHA256 := sha256Hex(registration)
			receipt := documentationTargetParentRegistrationReceipt{SHA256: registrationSHA256, CanonicalBytes: int64(len(registration))}
			receiptRow, err := canonicalDocumentationBytes(receipt)
			if err != nil {
				return nil, 0, 0, err
			}
			parentRegistrationRows = append(parentRegistrationRows, receiptRow)
			parentRegistrationReceipts = append(parentRegistrationReceipts, receipt)
			groupKey := documentationTargetGroupKey{
				artifactRole: shapeKey.artifactRole, rowKind: shapeKey.rowKind,
				bindingKind: shapeKey.bindingKind, memberJSONPointer: shapeKey.memberJSONPointer,
				rowSelectorSHA256: parent.selectorSHA256,
			}
			if prior, exists := groups[groupKey]; exists {
				if !equalResolvedDocumentationTargetRowSelectors(prior.rowSelector, parent.selectors) {
					return nil, 0, 0, fmt.Errorf("documentation target role %q row kind %q aliases one selector digest across different parent rows", shapeKey.artifactRole, shapeKey.rowKind)
				}
				continue
			}
			groups[groupKey] = documentationTargetGroup{shape: shape, rowSelector: cloneResolvedDocumentationTargetRowSelectors(parent.selectors)}
		}
	}
	if parentRegistrationOutput != nil {
		*parentRegistrationOutput = documentationTargetParentRegistrationClosure{
			seal:          documentationTargetParentRegistrationAuthority,
			registrations: append([]documentationTargetParentRegistrationReceipt(nil), parentRegistrationReceipts...),
			rootSHA256:    stageCanonicalSetRoot(parentRegistrationRows), registrationCount: parentRegistrationCount,
			selectorHydrations: selectorHydrationCount, canonicalByteCount: parentRegistrationCanonicalByteCount,
		}
	}
	return indexes, parentRegistrationCount, selectorHydrationCount, nil
}

func validateDocumentationTargetParentRegistrationClosure(closure documentationTargetParentRegistrationClosure) error {
	if closure.seal != documentationTargetParentRegistrationAuthority || closure.registrationCount < 0 || closure.registrationCount > maxDocumentationTargetParentRegistrations || closure.registrationCount != int64(len(closure.registrations)) || closure.selectorHydrations < 0 || closure.selectorHydrations > maxDocumentationTargetSelectorHydrations || closure.canonicalByteCount < 0 || closure.canonicalByteCount > maxDocumentationTargetParentCanonicalBytes {
		return fmt.Errorf("documentation target parent-registration closure is absent or has invalid resource actuals")
	}
	rows := make([][]byte, len(closure.registrations))
	var canonicalBytes int64
	for index, receipt := range closure.registrations {
		if !isLowerSHA256(receipt.SHA256) || receipt.CanonicalBytes <= 0 || receipt.CanonicalBytes > maxDocumentationTargetParentCanonicalBytes-canonicalBytes {
			return fmt.Errorf("documentation target parent-registration receipt %d is malformed or exceeds the byte limit", index)
		}
		canonicalBytes += receipt.CanonicalBytes
		canonical, err := canonicalDocumentationBytes(receipt)
		if err != nil {
			return fmt.Errorf("documentation target parent-registration receipt %d: %w", index, err)
		}
		rows[index] = canonical
	}
	if canonicalBytes != closure.canonicalByteCount || stageCanonicalSetRoot(rows) != closure.rootSHA256 {
		return fmt.Errorf("documentation target parent-registration root or byte actual differs from its exact receipt roster")
	}
	return nil
}

func documentationTargetParentIndexKeyForShape(shape documentationTargetShape) (documentationTargetParentIndexKey, error) {
	if shape.key.bindingKind != exactDocumentationTargetRowMember || len(shape.rowSelectorJSONPointers) == 0 {
		return documentationTargetParentIndexKey{}, fmt.Errorf("documentation target parent index requires a row-member shape with selectors")
	}
	rosterSHA256, err := canonicalDocumentationDigest(shape.rowSelectorJSONPointers)
	if err != nil {
		return documentationTargetParentIndexKey{}, err
	}
	return documentationTargetParentIndexKey{
		artifactRole: shape.key.artifactRole, rowKind: shape.key.rowKind, selectorRosterSHA256: rosterSHA256,
	}, nil
}

func canonicalDocumentationTargetRowSHA256(row dependencySemanticRow) (string, error) {
	if len(row.raw) == 0 {
		if !isLowerSHA256(row.canonicalSHA256) {
			return "", fmt.Errorf("documentation target row is not encoded as canonical JSON")
		}
		return row.canonicalSHA256, nil
	}
	canonicalRow, err := canonicalizeCandidateJSON(row.raw)
	if err != nil || !bytes.Equal(bytes.TrimSpace(row.raw), canonicalRow) {
		return "", fmt.Errorf("documentation target row is not encoded as canonical JSON")
	}
	return sha256Hex(canonicalRow), nil
}

func canonicalDocumentationTargetParentRegistration(identity documentationTargetParentRegistrationIdentity) ([]byte, error) {
	for _, check := range []struct{ label, value string }{
		{"target artifact role", identity.TargetArtifactRole},
		{"target schema role", identity.TargetSchemaRole},
		{"target schema id", identity.TargetSchemaID},
		{"target schema version", identity.TargetSchemaVersion},
		{"target row kind", identity.TargetRowKind},
		{"target binding kind", identity.TargetBindingKind},
	} {
		if !canonicalEvidenceMetadataString(check.value, 2048) {
			return nil, fmt.Errorf("documentation target parent registration %s is invalid", check.label)
		}
	}
	if identity.TargetBindingKind != exactDocumentationTargetRowMember || identity.TargetMemberJSONPointer == "" {
		return nil, fmt.Errorf("documentation target parent registration is not a row-member binding")
	}
	if _, err := documentationJSONPointerTokens(identity.TargetMemberJSONPointer); err != nil {
		return nil, fmt.Errorf("documentation target parent registration member pointer: %w", err)
	}
	for _, check := range []struct{ label, digest string }{
		{"target artifact", identity.TargetArtifactSHA256},
		{"target schema", identity.TargetSchemaSHA256},
		{"target selector roster", identity.TargetRowSelectorRosterSHA256},
		{"target selector", identity.TargetRowSelectorSHA256},
		{"target row", identity.TargetRowCanonicalSHA256},
	} {
		if !isLowerSHA256(check.digest) {
			return nil, fmt.Errorf("documentation target parent registration %s digest is malformed", check.label)
		}
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		return nil, err
	}
	return canonicalizeCandidateJSON(raw)
}

func registerDocumentationTargetDeclarations(
	profiles map[string]executableDocumentationDerivationProfile,
	targetAuthority dependencySemanticDerivationTargetSchemaAuthority,
	roleArtifacts map[string]artifactInput,
	roleRows map[string]dependencySemanticRows,
) (map[documentationTargetGroupKey]documentationTargetGroup, map[documentationTargetShapeKey]documentationTargetShape, map[documentationTargetRuleKey]documentationTargetShapeKey, error) {
	groups := map[documentationTargetGroupKey]documentationTargetGroup{}
	shapes := map[documentationTargetShapeKey]documentationTargetShape{}
	rules := map[documentationTargetRuleKey]documentationTargetShapeKey{}
	targetModes := map[string]string{}
	profileKeys := sortedSetKeys(stringMapKeysAsSet(profiles))
	if len(profileKeys) == 0 {
		return nil, nil, nil, fmt.Errorf("documentation target declaration roster has no executable profiles")
	}
	for _, profileKey := range profileKeys {
		profile := profiles[profileKey]
		if dependencyProfileReferenceKey(profile.Reference) != profileKey {
			return nil, nil, nil, fmt.Errorf("documentation target declaration profile key %q differs from its executable coordinate", profileKey)
		}
		for _, rule := range profile.Program.OrderedRules {
			resolution, err := targetAuthority.validateDocumentationDerivationTarget(rule.TargetArtifactRole, rule.TargetRowKind)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("documentation derivation rule %q target: %w", rule.RuleID, err)
			}
			artifact, artifactOK := roleArtifacts[rule.TargetArtifactRole]
			rows, rowsOK := roleRows[rule.TargetArtifactRole]
			if !artifactOK || !rowsOK || resolution.artifactSHA256 != sha256Hex(artifact.Raw) || (artifact.SHA256 != "" && artifact.SHA256 != resolution.artifactSHA256) || !bytes.Equal(artifact.Raw, rows.raw) {
				return nil, nil, nil, fmt.Errorf("documentation derivation rule %q target role %q has no exact schema-authorized artifact/row binding", rule.RuleID, rule.TargetArtifactRole)
			}
			modeKey := lengthPrefixedIdentityKey(rule.TargetArtifactRole, rule.TargetRowKind)
			if prior, exists := targetModes[modeKey]; exists && prior != rule.TargetBindingKind {
				return nil, nil, nil, fmt.Errorf("documentation derivation declarations mix whole-row and row-member modes for target role %q row kind %q", rule.TargetArtifactRole, rule.TargetRowKind)
			}
			targetModes[modeKey] = rule.TargetBindingKind

			shapeKey := documentationTargetShapeKey{
				artifactRole: rule.TargetArtifactRole, rowKind: rule.TargetRowKind,
				bindingKind: rule.TargetBindingKind, memberJSONPointer: rule.TargetMemberJSONPointer,
			}
			shape := documentationTargetShape{key: shapeKey, resolution: resolution}
			for _, selector := range rule.TargetRowSelector {
				shape.rowSelectorJSONPointers = append(shape.rowSelectorJSONPointers, selector.TargetRowJSONPointer)
			}
			shape.memberIdentityJSONPointers = append(shape.memberIdentityJSONPointers, rule.TargetMemberIdentityJSONPointers...)
			if prior, exists := shapes[shapeKey]; exists {
				if !equalOrderedStrings(prior.rowSelectorJSONPointers, shape.rowSelectorJSONPointers) || !equalOrderedStrings(prior.memberIdentityJSONPointers, shape.memberIdentityJSONPointers) {
					return nil, nil, nil, fmt.Errorf("documentation derivation target role %q row kind %q member %q has inconsistent selector or semantic-identity rosters", rule.TargetArtifactRole, rule.TargetRowKind, rule.TargetMemberJSONPointer)
				}
				shape = prior
			} else {
				switch rule.TargetBindingKind {
				case exactDocumentationTargetWholeRow:
					if len(shape.rowSelectorJSONPointers) != 0 || len(shape.memberIdentityJSONPointers) != 0 || rule.TargetMemberJSONPointer != "" {
						return nil, nil, nil, fmt.Errorf("documentation derivation rule %q whole-row declaration carries row-member coordinates", rule.RuleID)
					}
				case exactDocumentationTargetRowMember:
					descriptor, err := resolveDocumentationMemberSchema(resolution, rule.TargetMemberJSONPointer)
					if err != nil {
						return nil, nil, nil, fmt.Errorf("documentation derivation rule %q member schema: %w", rule.RuleID, err)
					}
					if err := validateDocumentationTargetRowSelectorSchema(resolution, rule.TargetRowSelector); err != nil {
						return nil, nil, nil, fmt.Errorf("documentation derivation rule %q row selector schema: %w", rule.RuleID, err)
					}
					if err := validateDocumentationMemberIdentitySchema(descriptor, rule.TargetMemberIdentityJSONPointers); err != nil {
						return nil, nil, nil, fmt.Errorf("documentation derivation rule %q member identity schema: %w", rule.RuleID, err)
					}
					shape.memberSchema = descriptor
				default:
					return nil, nil, nil, fmt.Errorf("documentation derivation rule %q target binding kind %q is unsupported", rule.RuleID, rule.TargetBindingKind)
				}
				shapes[shapeKey] = shape
			}
			ruleKey := documentationTargetRuleKey{profileKey: profileKey, ruleID: rule.RuleID}
			if _, duplicate := rules[ruleKey]; duplicate {
				return nil, nil, nil, fmt.Errorf("documentation target declarations duplicate executable rule %q in profile %q", rule.RuleID, profileKey)
			}
			rules[ruleKey] = shapeKey

			selector, selectorSHA256, literal, err := literalDocumentationTargetRowSelector(rule)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("documentation derivation rule %q literal target selector: %w", rule.RuleID, err)
			}
			if rule.MinimumMatches == 0 && !literal {
				return nil, nil, nil, fmt.Errorf("documentation derivation rule %q permits zero matches but has no independently resolvable literal parent-row selector", rule.RuleID)
			}
			if rule.TargetBindingKind == exactDocumentationTargetWholeRow || literal {
				groupKey := documentationTargetGroupKey{
					artifactRole: rule.TargetArtifactRole, rowKind: rule.TargetRowKind,
					bindingKind: rule.TargetBindingKind, memberJSONPointer: rule.TargetMemberJSONPointer,
					rowSelectorSHA256: selectorSHA256,
				}
				if prior, exists := groups[groupKey]; exists && !equalResolvedDocumentationTargetRowSelectors(prior.rowSelector, selector) {
					return nil, nil, nil, fmt.Errorf("documentation target declarations alias one selector digest with different values")
				}
				groups[groupKey] = documentationTargetGroup{shape: shape, rowSelector: selector}
			}
		}
	}
	return groups, shapes, rules, nil
}

func literalDocumentationTargetRowSelector(rule exactDocumentationDerivationRule) ([]exactDocumentationResolvedTargetRowSelector, string, bool, error) {
	if rule.TargetBindingKind == exactDocumentationTargetWholeRow {
		return nil, sha256Hex(nil), true, nil
	}
	selectors := make([]exactDocumentationResolvedTargetRowSelector, len(rule.TargetRowSelector))
	for index, selector := range rule.TargetRowSelector {
		if documentationTemplateCapturePattern.MatchString(selector.ExpectedStringTemplate) {
			return nil, "", false, nil
		}
		if selector.ExpectedStringTemplate == "" {
			return nil, "", false, fmt.Errorf("selector %q resolves to an empty string", selector.TargetRowJSONPointer)
		}
		selectors[index] = exactDocumentationResolvedTargetRowSelector{
			TargetRowJSONPointer: selector.TargetRowJSONPointer,
			ExpectedString:       selector.ExpectedStringTemplate,
		}
	}
	root, err := canonicalDocumentationDigest(selectors)
	return selectors, root, true, err
}

func validateDocumentationTargetRowSelectorSchema(resolution dependencySemanticDerivationTargetResolution, selectors []exactDocumentationTargetRowSelectorTemplate) error {
	if len(selectors) == 0 {
		return fmt.Errorf("row-member target has no parent-row selector")
	}
	var root map[string]interface{}
	if err := decodeOneValidationProfileJSON(resolution.schemaBytes, &root); err != nil {
		return fmt.Errorf("decode documentation target schema: %w", err)
	}
	branches, err := documentationRowKindSchemaBranches(root, root, resolution.discriminatorProperty, resolution.targetRowKind, "$", map[string]bool{})
	if err != nil {
		return err
	}
	if len(branches) == 0 {
		return fmt.Errorf("target schema has no branch for row_kind %q", resolution.targetRowKind)
	}
	for _, selector := range selectors {
		tokens, err := exactDocumentationJSONPointerTokens(selector.TargetRowJSONPointer)
		if err != nil {
			return err
		}
		for branchIndex, branch := range branches {
			if err := documentationSchemaProvesRequiredStringAtPointer(root, branch, tokens); err != nil {
				return fmt.Errorf("row_kind %q branch %d selector %q: %w", resolution.targetRowKind, branchIndex, selector.TargetRowJSONPointer, err)
			}
		}
	}
	return nil
}

func validateDocumentationMemberIdentitySchema(descriptor documentationMemberSchemaDescriptor, pointers []string) error {
	if len(pointers) == 0 || descriptor.root == nil || descriptor.itemSchema == nil {
		return fmt.Errorf("row-member target has no exact semantic member identity schema")
	}
	for _, pointer := range pointers {
		tokens, err := exactDocumentationJSONPointerTokens(pointer)
		if err != nil {
			return err
		}
		if err := documentationSchemaProvesRequiredStringAtPointer(descriptor.root, descriptor.itemSchema, tokens); err != nil {
			return fmt.Errorf("member identity pointer %q: %w", pointer, err)
		}
	}
	return nil
}

func documentationSchemaProvesRequiredStringAtPointer(root map[string]interface{}, start map[string]interface{}, tokens []string) error {
	var current interface{} = start
	for _, token := range tokens {
		resolved, err := documentationResolveSchemaNode(root, current)
		if err != nil {
			return err
		}
		object, ok := resolved.(map[string]interface{})
		if !ok {
			return fmt.Errorf("path traverses a non-object schema node")
		}
		required, err := documentationSchemaRequiredSet(object)
		if err != nil {
			return err
		}
		if _, exists := required[token]; !exists {
			return fmt.Errorf("property %q is not required", token)
		}
		properties, ok := object["properties"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("schema node has no finite properties")
		}
		next, exists := properties[token]
		if !exists {
			return fmt.Errorf("property %q is absent", token)
		}
		current = next
	}
	resolved, err := documentationResolveSchemaNode(root, current)
	if err != nil {
		return err
	}
	schema, ok := resolved.(map[string]interface{})
	if !ok || !documentationSchemaProvesString(schema) {
		return fmt.Errorf("path does not resolve to an exact string schema")
	}
	return nil
}

func documentationSchemaProvesString(schema map[string]interface{}) bool {
	if documentationSchemaTypeEquals(schema, "string") {
		return true
	}
	if value, present := schema["const"]; present {
		_, ok := value.(string)
		return ok
	}
	values, present := schema["enum"].([]interface{})
	if !present || len(values) == 0 {
		return false
	}
	for _, value := range values {
		if _, ok := value.(string); !ok {
			return false
		}
	}
	return true
}

func resolveDocumentationMemberIdentity(payload map[string]interface{}, pointers []string) ([]exactDocumentationResolvedMemberIdentity, string, error) {
	identities := make([]exactDocumentationResolvedMemberIdentity, len(pointers))
	for index, pointer := range pointers {
		value, err := exactDocumentationStringAtJSONPointer(payload, pointer)
		if err != nil {
			return nil, "", err
		}
		identities[index] = exactDocumentationResolvedMemberIdentity{OutputJSONPointer: pointer, ExpectedString: value}
	}
	root, err := canonicalDocumentationDigest(identities)
	return identities, root, err
}

func canonicalDocumentationJSON(value interface{}) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalizeCandidateJSON(raw)
}

func resolvedDocumentationSelectorPointers(values []exactDocumentationResolvedTargetRowSelector) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = values[index].TargetRowJSONPointer
	}
	return result
}

func resolvedDocumentationMemberIdentityPointers(values []exactDocumentationResolvedMemberIdentity) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = values[index].OutputJSONPointer
	}
	return result
}

func cloneResolvedDocumentationTargetRowSelectors(values []exactDocumentationResolvedTargetRowSelector) []exactDocumentationResolvedTargetRowSelector {
	return append([]exactDocumentationResolvedTargetRowSelector(nil), values...)
}

func cloneExactDocumentationDerivedFactValue(fact exactDocumentationDerivedFact) exactDocumentationDerivedFact {
	clone := fact
	clone.TargetRowSelector = append([]exactDocumentationResolvedTargetRowSelector(nil), fact.TargetRowSelector...)
	clone.TargetMemberIdentity = append([]exactDocumentationResolvedMemberIdentity(nil), fact.TargetMemberIdentity...)
	clone.ExactOutputFieldNames = append([]string(nil), fact.ExactOutputFieldNames...)
	clone.CanonicalOutputFields = bytes.Clone(fact.CanonicalOutputFields)
	clone.EvidenceLocator.SourceRefs = append([]string(nil), fact.EvidenceLocator.SourceRefs...)
	clone.EvidenceLocator.SourceURLs = append([]string(nil), fact.EvidenceLocator.SourceURLs...)
	return clone
}

func equalResolvedDocumentationTargetRowSelectors(left, right []exactDocumentationResolvedTargetRowSelector) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalResolvedDocumentationMemberIdentities(left, right []exactDocumentationResolvedMemberIdentity) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func newDocumentationTargetMaterialization(
	fact exactDocumentationDerivedFact,
	artifact artifactInput,
	resolution dependencySemanticDerivationTargetResolution,
	canonicalRowSHA256 string,
	memberInstancePointer string,
	canonicalMember []byte,
	remainingCanonicalBytes int64,
) (documentationTargetMaterialization, error) {
	var result documentationTargetMaterialization
	if resolution.artifactRole != fact.TargetArtifactRole || resolution.artifactSHA256 != sha256Hex(artifact.Raw) || resolution.targetRowKind != fact.TargetRowKind || sha256Hex(resolution.schemaBytes) != resolution.schemaSHA256 {
		return result, fmt.Errorf("documentation target materialization does not equal its exact artifact, row-kind, and schema authority")
	}
	if err := validateExactDocumentationResolvedTargetCoordinates(fact); err != nil {
		return result, fmt.Errorf("documentation target materialization coordinates: %w", err)
	}
	switch fact.TargetBindingKind {
	case exactDocumentationTargetWholeRow:
		if fact.TargetMemberJSONPointer != "" || memberInstancePointer != "" || len(canonicalMember) != 0 {
			return result, fmt.Errorf("whole-row documentation target carries row-member materialization state")
		}
	case exactDocumentationTargetRowMember:
		if fact.TargetMemberJSONPointer == "" || !strings.HasPrefix(memberInstancePointer, fact.TargetMemberJSONPointer+"/") || len(canonicalMember) == 0 {
			return result, fmt.Errorf("row-member documentation target has no exact member instance")
		}
	default:
		return result, fmt.Errorf("documentation target binding kind %q is unsupported", fact.TargetBindingKind)
	}
	if !isLowerSHA256(canonicalRowSHA256) {
		return result, fmt.Errorf("documentation target materialization has no prevalidated canonical parent-row digest")
	}
	identity := documentationTargetMaterializationIdentity{
		FactID: fact.FactID, FactOutputSHA256: sha256Hex(fact.CanonicalOutputFields),
		EvidenceLocatorID: fact.EvidenceLocatorID, EvidenceLocatorIdentitySHA256: sha256Hex([]byte(candidateEvidenceLocatorIdentityKey(fact.EvidenceLocator))),
		TargetArtifactRole: fact.TargetArtifactRole, TargetArtifactSHA256: sha256Hex(artifact.Raw),
		TargetSchemaRole: resolution.schemaRole, TargetSchemaID: resolution.schemaID,
		TargetSchemaVersion: resolution.schemaVersion, TargetSchemaSHA256: resolution.schemaSHA256,
		TargetRowKind: fact.TargetRowKind, TargetBindingKind: fact.TargetBindingKind,
		TargetRowSelectorSHA256:  fact.TargetRowSelectorSHA256,
		TargetRowCanonicalSHA256: canonicalRowSHA256, TargetMemberJSONPointer: fact.TargetMemberJSONPointer,
		TargetMemberIdentitySHA256:  fact.TargetMemberIdentitySHA256,
		TargetMemberInstancePointer: memberInstancePointer,
	}
	if len(canonicalMember) != 0 {
		identity.TargetMemberCanonicalSHA256 = sha256Hex(canonicalMember)
	}
	canonicalBytes, err := exactDocumentationTargetMaterializationCanonicalByteCount(identity)
	if err != nil {
		return result, err
	}
	if remainingCanonicalBytes < 0 || canonicalBytes > remainingCanonicalBytes {
		return result, fmt.Errorf("documentation target canonical materialization bytes exceed the remaining limit %d before allocation", remainingCanonicalBytes)
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		return result, err
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		return result, err
	}
	if int64(len(canonical)) != canonicalBytes {
		return result, fmt.Errorf("documentation target canonical materialization byte preflight disagrees with canonical encoding")
	}
	return documentationTargetMaterialization{identity: identity, canonical: canonical, bindingSHA256: sha256Hex(canonical), canonicalBytes: canonicalBytes}, nil
}

func exactDocumentationTargetMaterializationCanonicalByteCount(identity documentationTargetMaterializationIdentity) (int64, error) {
	fields := []struct {
		name  string
		value string
	}{
		{"evidence_locator_id", identity.EvidenceLocatorID},
		{"evidence_locator_identity_sha256", identity.EvidenceLocatorIdentitySHA256},
		{"fact_id", identity.FactID},
		{"fact_output_sha256", identity.FactOutputSHA256},
		{"target_artifact_role", identity.TargetArtifactRole},
		{"target_artifact_sha256", identity.TargetArtifactSHA256},
		{"target_binding_kind", identity.TargetBindingKind},
		{"target_member_canonical_sha256", identity.TargetMemberCanonicalSHA256},
		{"target_member_identity_sha256", identity.TargetMemberIdentitySHA256},
		{"target_member_instance_pointer", identity.TargetMemberInstancePointer},
		{"target_member_json_pointer", identity.TargetMemberJSONPointer},
		{"target_row_canonical_sha256", identity.TargetRowCanonicalSHA256},
		{"target_row_kind", identity.TargetRowKind},
		{"target_row_selector_sha256", identity.TargetRowSelectorSHA256},
		{"target_schema_id", identity.TargetSchemaID},
		{"target_schema_role", identity.TargetSchemaRole},
		{"target_schema_sha256", identity.TargetSchemaSHA256},
		{"target_schema_version", identity.TargetSchemaVersion},
	}
	total := int64(2) // braces
	for index, field := range fields {
		nameBytes, err := exactDocumentationJSONStringByteCount(field.name)
		if err != nil {
			return 0, err
		}
		valueBytes, err := exactDocumentationJSONStringByteCount(field.value)
		if err != nil {
			return 0, err
		}
		addition := nameBytes + 1 + valueBytes
		if index > 0 {
			addition++
		}
		if addition < 0 || total > math.MaxInt64-addition {
			return 0, fmt.Errorf("documentation target canonical materialization byte count overflows INT64")
		}
		total += addition
	}
	return total, nil
}

// exactDocumentationJSONStringByteCount matches canonicalizeCandidateJSON's
// non-HTML string escaping, including U+2028/U+2029, without allocating the
// full enclosing materialization. It lets the aggregate gate refuse before
// json.Marshal/canonicalization allocates the next row.
func exactDocumentationJSONStringByteCount(value string) (int64, error) {
	if !utf8.ValidString(value) {
		return 0, fmt.Errorf("documentation target materialization contains invalid UTF-8")
	}
	total := int64(2) // quotes
	for index := 0; index < len(value); {
		char := value[index]
		if char < utf8.RuneSelf {
			width := int64(1)
			switch char {
			case '\\', '"', '\b', '\f', '\n', '\r', '\t':
				width = 2
			default:
				if char < 0x20 {
					width = 6
				}
			}
			if total > math.MaxInt64-width {
				return 0, fmt.Errorf("documentation target materialization JSON string byte count overflows INT64")
			}
			total += width
			index++
			continue
		}
		runeValue, size := utf8.DecodeRuneInString(value[index:])
		width := int64(size)
		if runeValue == '\u2028' || runeValue == '\u2029' {
			width = 6
		}
		if total > math.MaxInt64-width {
			return 0, fmt.Errorf("documentation target materialization JSON string byte count overflows INT64")
		}
		total += width
		index += size
	}
	return total, nil
}

type documentationTargetMaterializationRootStats struct {
	canonicalBytes               int64
	sortIndexBytes               int64
	peakAdditionalCanonicalBytes int64
}

func documentationTargetMaterializationRoot(materializations []documentationTargetMaterialization) string {
	root, _, err := documentationTargetMaterializationRootWithStats(materializations)
	if err != nil {
		return ""
	}
	return root
}

func documentationTargetMaterializationRootWithStats(materializations []documentationTargetMaterialization) (string, documentationTargetMaterializationRootStats, error) {
	stats := documentationTargetMaterializationRootStats{sortIndexBytes: int64(len(materializations)) * int64(strconv.IntSize/8)}
	if len(materializations) == 0 {
		return sha256Hex(nil), stats, nil
	}
	indexes := make([]int, len(materializations))
	for index := range materializations {
		materialization := materializations[index]
		if materialization.canonicalBytes <= 0 || materialization.canonicalBytes != int64(len(materialization.canonical)) {
			return "", stats, fmt.Errorf("documentation target materialization %d has invalid canonical-byte ownership", index)
		}
		if materialization.canonicalBytes > maxDocumentationTargetMaterializationCanonicalBytes-stats.canonicalBytes {
			return "", stats, fmt.Errorf("documentation target canonical materialization bytes exceed limit %d", maxDocumentationTargetMaterializationCanonicalBytes)
		}
		stats.canonicalBytes += materialization.canonicalBytes
		indexes[index] = index
	}
	sort.Slice(indexes, func(i, j int) bool {
		return bytes.Compare(materializations[indexes[i]].canonical, materializations[indexes[j]].canonical) < 0
	})
	hasher := sha256.New()
	var prefixBuffer [32]byte
	for _, index := range indexes {
		canonical := materializations[index].canonical
		prefix := strconv.AppendInt(prefixBuffer[:0], int64(len(canonical)), 10)
		prefix = append(prefix, ':')
		_, _ = hasher.Write(prefix)
		_, _ = hasher.Write(canonical)
	}
	return hex.EncodeToString(hasher.Sum(nil)), stats, nil
}

func documentationTargetMaterializationBindingRosterRoot(materializations []documentationTargetMaterialization) string {
	if len(materializations) == 0 {
		return sha256Hex(nil)
	}
	indexes := make([]int, len(materializations))
	for index := range materializations {
		indexes[index] = index
	}
	sort.Slice(indexes, func(i, j int) bool {
		return compareDocumentationMaterializationBinding(
			materializations[indexes[i]].identity.FactID,
			materializations[indexes[i]].bindingSHA256,
			materializations[indexes[i]].canonicalBytes,
			materializations[indexes[j]].identity.FactID,
			materializations[indexes[j]].bindingSHA256,
			materializations[indexes[j]].canonicalBytes,
		) < 0
	})
	hasher := sha256.New()
	for _, index := range indexes {
		materialization := materializations[index]
		writeDocumentationMaterializationBinding(hasher, materialization.identity.FactID, materialization.bindingSHA256, materialization.canonicalBytes)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func documentationTargetMaterializationBindingMapRoot(bindings map[string]string, canonicalBytesByFact map[string]int64) string {
	if len(bindings) == 0 {
		return sha256Hex(nil)
	}
	factIDs := make([]string, 0, len(bindings))
	for factID := range bindings {
		factIDs = append(factIDs, factID)
	}
	sort.Slice(factIDs, func(i, j int) bool {
		return compareDocumentationMaterializationBinding(factIDs[i], bindings[factIDs[i]], canonicalBytesByFact[factIDs[i]], factIDs[j], bindings[factIDs[j]], canonicalBytesByFact[factIDs[j]]) < 0
	})
	hasher := sha256.New()
	for _, factID := range factIDs {
		writeDocumentationMaterializationBinding(hasher, factID, bindings[factID], canonicalBytesByFact[factID])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func compareDocumentationMaterializationBinding(leftFactID, leftBinding string, leftBytes int64, rightFactID, rightBinding string, rightBytes int64) int {
	if result := compareDocumentationLengthPrefixedString(leftFactID, rightFactID); result != 0 {
		return result
	}
	if result := compareDocumentationLengthPrefixedString(leftBinding, rightBinding); result != 0 {
		return result
	}
	var leftBuffer, rightBuffer [32]byte
	leftText := strconv.AppendInt(leftBuffer[:0], leftBytes, 10)
	rightText := strconv.AppendInt(rightBuffer[:0], rightBytes, 10)
	return compareDocumentationLengthPrefixedBytes(leftText, rightText)
}

func compareDocumentationLengthPrefixedString(left, right string) int {
	var leftBuffer, rightBuffer [32]byte
	leftPrefix := strconv.AppendInt(leftBuffer[:0], int64(len([]byte(left))), 10)
	rightPrefix := strconv.AppendInt(rightBuffer[:0], int64(len([]byte(right))), 10)
	leftPrefix = append(leftPrefix, ':')
	rightPrefix = append(rightPrefix, ':')
	if result := bytes.Compare(leftPrefix, rightPrefix); result != 0 {
		return result
	}
	return strings.Compare(left, right)
}

func compareDocumentationLengthPrefixedBytes(left, right []byte) int {
	var leftBuffer, rightBuffer [32]byte
	leftPrefix := strconv.AppendInt(leftBuffer[:0], int64(len(left)), 10)
	rightPrefix := strconv.AppendInt(rightBuffer[:0], int64(len(right)), 10)
	leftPrefix = append(leftPrefix, ':')
	rightPrefix = append(rightPrefix, ':')
	if result := bytes.Compare(leftPrefix, rightPrefix); result != 0 {
		return result
	}
	return bytes.Compare(left, right)
}

func writeDocumentationMaterializationBinding(hasher interface{ Write([]byte) (int, error) }, factID, bindingSHA256 string, canonicalBytes int64) {
	var byteBuffer [32]byte
	byteText := strconv.AppendInt(byteBuffer[:0], canonicalBytes, 10)
	rowBytes := documentationLengthPrefixedStringByteCount(factID) + documentationLengthPrefixedStringByteCount(bindingSHA256) + documentationLengthPrefixedByteCount(int64(len(byteText)))
	writeDocumentationLengthPrefix(hasher, rowBytes)
	writeDocumentationLengthPrefixedString(hasher, factID)
	writeDocumentationLengthPrefixedString(hasher, bindingSHA256)
	writeDocumentationLengthPrefixedBytes(hasher, byteText)
}

func writeDocumentationLengthPrefixedBytes(hasher interface{ Write([]byte) (int, error) }, value []byte) {
	writeDocumentationLengthPrefix(hasher, int64(len(value)))
	_, _ = hasher.Write(value)
}

func writeDocumentationLengthPrefixedString(hasher interface{ Write([]byte) (int, error) }, value string) {
	writeDocumentationLengthPrefix(hasher, int64(len([]byte(value))))
	_, _ = hasher.Write([]byte(value))
}

func writeDocumentationLengthPrefix(hasher interface{ Write([]byte) (int, error) }, byteCount int64) {
	var buffer [32]byte
	prefix := strconv.AppendInt(buffer[:0], byteCount, 10)
	prefix = append(prefix, ':')
	_, _ = hasher.Write(prefix)
}

func documentationLengthPrefixedStringByteCount(value string) int64 {
	byteCount := int64(len([]byte(value)))
	return documentationLengthPrefixedByteCount(byteCount)
}

func documentationLengthPrefixedByteCount(byteCount int64) int64 {
	return documentationDecimalByteCount(byteCount) + 1 + byteCount
}

func documentationDecimalByteCount(value int64) int64 {
	if value == 0 {
		return 1
	}
	var count int64
	for value > 0 {
		count++
		value /= 10
	}
	return count
}

func documentationDerivationProfileExecutionSetRoot(identity documentationDerivationClosureIdentity) string {
	setIdentity := exactDocumentationDerivationProfileExecutionSetIdentity{
		ExecutionSetKind:           documentationDerivationProfileExecutionSetKind,
		ClassificationProofSHA256:  identity.ClassificationProofSHA256,
		ProfileBudgetRootSHA256:    identity.ProfileBudgetRootSHA256,
		ProfilePageSetRootSHA256:   identity.ProfilePageSetRootSHA256,
		ProfileResultSetRootSHA256: identity.ProfileResultSetRootSHA256,
		ProfileCount:               identity.ProfileCount, ProfileCountLimit: identity.ProfileCountLimit,
		RuleCount: identity.RuleCount, RuleCountLimit: identity.RuleCountLimit,
		CanonicalProgramBytes: identity.CanonicalProgramBytes, CanonicalProgramByteLimit: identity.CanonicalProgramByteLimit,
		CanonicalClaimSchemaBytes: identity.CanonicalClaimSchemaBytes, CanonicalClaimSchemaLimit: identity.CanonicalClaimSchemaByteLimit,
		FactCount: identity.FactCount, FactCountLimit: identity.FactCountLimit,
		CanonicalFactBytes: identity.CanonicalFactBytes, CanonicalFactByteLimit: identity.CanonicalFactByteLimit,
		OutcomeCount: identity.OutcomeCount, OutcomeCountLimit: identity.OutcomeCountLimit,
		CanonicalOutcomeBytes: identity.CanonicalOutcomeBytes, CanonicalOutcomeByteLimit: identity.CanonicalOutcomeByteLimit,
		RetainedCanonicalBytes: identity.RetainedCanonicalBytes, RetainedCanonicalByteLimit: identity.RetainedCanonicalByteLimit,
		PageCount: identity.PageCount, PageCountLimit: identity.PageCountLimit,
		MatcherEvaluationCount: identity.MatcherEvaluationCount, MatcherEvaluationCountLimit: identity.MatcherEvaluationCountLimit,
		MatcherInputByteCount: identity.MatcherInputByteCount, MatcherInputByteLimit: identity.MatcherInputByteLimit,
		Status: documentationDerivationProfileExecutionSetComplete,
	}
	raw, err := json.Marshal(setIdentity)
	if err != nil {
		return ""
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		return ""
	}
	return sha256Hex(canonical)
}

func exactDocumentationCanonicalFactByteCount(facts []exactDocumentationDerivedFact, limit int64) (int64, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("documentation canonical fact-byte limit is invalid")
	}
	var total int64
	for _, fact := range facts {
		canonical, err := canonicalExactDocumentationFactEnvelopeBytes(fact)
		if err != nil {
			return 0, err
		}
		if int64(len(canonical)) > limit-total {
			return 0, fmt.Errorf("documentation canonical fact bytes exceed limit %d", limit)
		}
		total += int64(len(canonical))
	}
	return total, nil
}

func sealDocumentationDerivationClosure(
	derivationProfileArtifactSHA256 string,
	execution *exactDocumentationDerivationProfileExecutionSet,
	classificationProof sourceClassificationSelectionProof,
	materializations []documentationTargetMaterialization,
	parentRegistrations documentationTargetParentRegistrationClosure,
	wholeRowBindingCount int64,
	rowMemberBindingCount int64,
) (documentationDerivationClosureProof, error) {
	var proof documentationDerivationClosureProof
	if execution == nil {
		return proof, fmt.Errorf("documentation derivation closure has no execution-set ownership to consume")
	}
	if !isLowerSHA256(derivationProfileArtifactSHA256) {
		return proof, fmt.Errorf("documentation derivation closure profile-artifact digest is malformed")
	}
	if err := validateSourceClassificationSelectionProof(classificationProof); err != nil {
		return proof, fmt.Errorf("documentation derivation closure classification proof: %w", err)
	}
	if err := validateExactDocumentationDerivationProfileExecutionSet(*execution, classificationProof); err != nil {
		return proof, err
	}
	if err := validateDocumentationTargetParentRegistrationClosure(parentRegistrations); err != nil {
		return proof, err
	}
	facts := make([]exactDocumentationDerivedFact, 0, execution.FactCount)
	for _, result := range execution.Results {
		facts = append(facts, result.Facts...)
	}
	if int64(len(facts)) != execution.FactCount || int64(len(materializations)) != execution.FactCount || wholeRowBindingCount < 0 || rowMemberBindingCount < 0 || wholeRowBindingCount+rowMemberBindingCount != execution.FactCount {
		return proof, fmt.Errorf("documentation derivation closure materialization counts do not equal the executor-minted fact roster")
	}
	bindings := make(map[string]string, len(materializations))
	canonicalBytesByFact := make(map[string]int64, len(materializations))
	var canonicalMaterializationBytes int64
	for _, materialization := range materializations {
		factID := materialization.identity.FactID
		if _, duplicate := bindings[factID]; duplicate || !isLowerSHA256(materialization.bindingSHA256) || materialization.bindingSHA256 != sha256Hex(materialization.canonical) || materialization.canonicalBytes <= 0 || materialization.canonicalBytes != int64(len(materialization.canonical)) || materialization.canonicalBytes > maxDocumentationTargetMaterializationCanonicalBytes-canonicalMaterializationBytes {
			return proof, fmt.Errorf("documentation derivation closure has a duplicate or invalid materialization for fact %q", factID)
		}
		bindings[factID] = materialization.bindingSHA256
		canonicalBytesByFact[factID] = materialization.canonicalBytes
		canonicalMaterializationBytes += materialization.canonicalBytes
	}
	materializationRoot, materializationRootStats, err := documentationTargetMaterializationRootWithStats(materializations)
	if err != nil || materializationRootStats.canonicalBytes != canonicalMaterializationBytes {
		return proof, fmt.Errorf("documentation derivation closure canonical materialization roster is invalid")
	}
	canonicalFactBytes, err := exactDocumentationCanonicalFactByteCount(facts, execution.Limits.canonicalFactBytes)
	if err != nil || canonicalFactBytes != execution.CanonicalFactBytes {
		return proof, fmt.Errorf("documentation derivation closure canonical fact bytes do not equal the executed fact envelopes")
	}
	factEnvelopeRootSHA256 := exactDocumentationFactRoot(facts)
	if !isLowerSHA256(factEnvelopeRootSHA256) {
		return proof, fmt.Errorf("documentation derivation closure fact-envelope root is invalid")
	}
	factsByID := make(map[string]exactDocumentationDerivedFact, len(facts))
	for index := range facts {
		fact := facts[index]
		if err := validateExactDocumentationDerivedFactIntegrity(fact); err != nil {
			return proof, fmt.Errorf("documentation derivation closure fact %q: %w", fact.FactID, err)
		}
		if _, duplicate := factsByID[fact.FactID]; duplicate {
			return proof, fmt.Errorf("documentation derivation closure duplicates fact %q", fact.FactID)
		}
		// Transfer the already executor-owned immutable value. No canonical
		// output bytes are cloned; source ownership is released after proof
		// validation succeeds.
		factsByID[fact.FactID] = fact
		facts[index] = exactDocumentationDerivedFact{}
	}
	if err := requireExactSet("documentation derivation closure fact/materialization roster", stringMapKeysAsSet(factsByID), stringMapKeysAsSet(bindings)); err != nil {
		return proof, err
	}
	for _, materialization := range materializations {
		fact := factsByID[materialization.identity.FactID]
		if err := validateDocumentationTargetMaterializationFactBinding(materialization, fact); err != nil {
			return proof, err
		}
	}
	identity := documentationDerivationClosureIdentity{
		Provider: classificationProof.provider, EvidenceSelectionRosterSHA256: classificationProof.evidenceSelectionRosterSHA256,
		DerivationProfileArtifactSHA256:              derivationProfileArtifactSHA256,
		ClassificationProofSHA256:                    execution.ClassificationProofSHA256,
		ProfileBudgetRootSHA256:                      execution.ProfileBudgetRootSHA256,
		ProfilePageSetRootSHA256:                     execution.ProfilePageSetRootSHA256,
		ProfileResultSetRootSHA256:                   execution.ProfileResultSetRootSHA256,
		ProfileExecutionSetRootSHA256:                execution.ExecutionSetRootSHA256,
		FactEnvelopeRootSHA256:                       factEnvelopeRootSHA256,
		TargetMaterializationRootSHA256:              materializationRoot,
		TargetMaterializationBindingRosterRootSHA256: documentationTargetMaterializationBindingRosterRoot(materializations),
		CanonicalTargetMaterializationBytes:          canonicalMaterializationBytes,
		CanonicalTargetMaterializationByteLimit:      maxDocumentationTargetMaterializationCanonicalBytes,
		TargetParentRegistrationRootSHA256:           parentRegistrations.rootSHA256,
		ProfileCount:                                 int64(len(execution.Profiles)), ProfileCountLimit: execution.Limits.profileCount,
		RuleCount: execution.RuleCount, RuleCountLimit: execution.Limits.ruleCount,
		CanonicalProgramBytes: execution.CanonicalProgramBytes, CanonicalProgramByteLimit: execution.Limits.canonicalProgramBytes,
		CanonicalClaimSchemaBytes: execution.CanonicalClaimSchemaBytes, CanonicalClaimSchemaByteLimit: execution.Limits.canonicalSchemaBytes,
		OutcomeCount: execution.OutcomeCount, OutcomeCountLimit: execution.Limits.outcomeCount,
		FactCount: execution.FactCount, FactCountLimit: execution.Limits.factCount,
		CanonicalFactBytes: execution.CanonicalFactBytes, CanonicalFactByteLimit: execution.Limits.canonicalFactBytes,
		CanonicalOutcomeBytes: execution.CanonicalOutcomeBytes, CanonicalOutcomeByteLimit: execution.Limits.canonicalOutcomeBytes,
		RetainedCanonicalBytes: execution.RetainedCanonicalBytes, RetainedCanonicalByteLimit: execution.Limits.retainedCanonicalBytes,
		PageCount: execution.PageCount, PageCountLimit: execution.Limits.pageCount,
		MatcherEvaluationCount: execution.MatcherEvaluationCount, MatcherEvaluationCountLimit: execution.Limits.matcherEvaluations,
		MatcherInputByteCount: execution.MatcherInputByteCount, MatcherInputByteLimit: execution.Limits.matcherInputBytes,
		WholeRowBindingCount: wholeRowBindingCount, RowMemberBindingCount: rowMemberBindingCount,
		TargetParentRegistrationCount: parentRegistrations.registrationCount, TargetParentRegistrationLimit: maxDocumentationTargetParentRegistrations,
		TargetParentRegistrationCanonicalByteCount: parentRegistrations.canonicalByteCount, TargetParentRegistrationCanonicalByteLimit: maxDocumentationTargetParentCanonicalBytes,
		TargetSelectorHydrationCount: parentRegistrations.selectorHydrations, TargetSelectorHydrationLimit: maxDocumentationTargetSelectorHydrations,
		Status: documentationDerivationClosureComplete,
	}
	if documentationDerivationProfileExecutionSetRoot(identity) != execution.ExecutionSetRootSHA256 {
		return proof, fmt.Errorf("documentation derivation closure execution receipt differs from the executor-minted set")
	}
	canonical, err := canonicalDocumentationBytes(identity)
	if err != nil {
		return proof, err
	}
	executionIdentity := exactDocumentationDerivationProfileExecutionSetIdentityFor(*execution)
	proof = documentationDerivationClosureProof{
		seal:     documentationDerivationClosureAuthority,
		provider: identity.Provider, evidenceSelectionRosterSHA256: identity.EvidenceSelectionRosterSHA256,
		derivationProfileArtifactSHA256:              identity.DerivationProfileArtifactSHA256,
		classificationProofSHA256:                    identity.ClassificationProofSHA256,
		profilePageSetRootSHA256:                     identity.ProfilePageSetRootSHA256,
		profileResultSetRootSHA256:                   identity.ProfileResultSetRootSHA256,
		profileExecutionSetRootSHA256:                identity.ProfileExecutionSetRootSHA256,
		profileBudgetRootSHA256:                      identity.ProfileBudgetRootSHA256,
		factEnvelopeRootSHA256:                       identity.FactEnvelopeRootSHA256,
		profileCountLimit:                            identity.ProfileCountLimit,
		ruleCount:                                    identity.RuleCount,
		ruleCountLimit:                               identity.RuleCountLimit,
		canonicalProgramBytes:                        identity.CanonicalProgramBytes,
		canonicalProgramByteLimit:                    identity.CanonicalProgramByteLimit,
		canonicalClaimSchemaBytes:                    identity.CanonicalClaimSchemaBytes,
		canonicalClaimSchemaByteLimit:                identity.CanonicalClaimSchemaByteLimit,
		factCountLimit:                               identity.FactCountLimit,
		canonicalFactBytes:                           identity.CanonicalFactBytes,
		canonicalFactByteLimit:                       identity.CanonicalFactByteLimit,
		outcomeCountLimit:                            identity.OutcomeCountLimit,
		canonicalOutcomeBytes:                        identity.CanonicalOutcomeBytes,
		canonicalOutcomeByteLimit:                    identity.CanonicalOutcomeByteLimit,
		retainedCanonicalBytes:                       identity.RetainedCanonicalBytes,
		retainedCanonicalByteLimit:                   identity.RetainedCanonicalByteLimit,
		pageCountLimit:                               identity.PageCountLimit,
		matcherEvaluationCount:                       identity.MatcherEvaluationCount,
		matcherEvaluationCountLimit:                  identity.MatcherEvaluationCountLimit,
		matcherInputByteCount:                        identity.MatcherInputByteCount,
		matcherInputByteLimit:                        identity.MatcherInputByteLimit,
		targetMaterializationRootSHA256:              identity.TargetMaterializationRootSHA256,
		targetMaterializationBindingRosterRootSHA256: identity.TargetMaterializationBindingRosterRootSHA256,
		canonicalTargetMaterializationBytes:          identity.CanonicalTargetMaterializationBytes,
		canonicalTargetMaterializationByteLimit:      identity.CanonicalTargetMaterializationByteLimit,
		targetParentRegistrationRootSHA256:           identity.TargetParentRegistrationRootSHA256,
		profileCount:                                 identity.ProfileCount, outcomeCount: identity.OutcomeCount,
		factCount: identity.FactCount, pageCount: identity.PageCount,
		wholeRowBindingCount: identity.WholeRowBindingCount, rowMemberBindingCount: identity.RowMemberBindingCount,
		targetParentRegistrationCount: identity.TargetParentRegistrationCount, targetParentRegistrationLimit: identity.TargetParentRegistrationLimit,
		targetParentRegistrationCanonicalByteCount: identity.TargetParentRegistrationCanonicalByteCount, targetParentRegistrationCanonicalByteLimit: identity.TargetParentRegistrationCanonicalByteLimit,
		targetSelectorHydrationCount: identity.TargetSelectorHydrationCount, targetSelectorHydrationLimit: identity.TargetSelectorHydrationLimit,
		proofSHA256: sha256Hex(canonical), materializationBindingSHA256ByFact: bindings, materializationCanonicalBytesByFact: canonicalBytesByFact, factsByID: factsByID,
		executionSetReceipt:       documentationDerivationExecutionSetReceipt{seal: execution.seal, identity: executionIdentity, rootSHA256: execution.ExecutionSetRootSHA256},
		parentRegistrationReceipt: cloneDocumentationTargetParentRegistrationClosure(parentRegistrations),
	}
	if err := validateDocumentationDerivationClosureProof(proof); err != nil {
		return documentationDerivationClosureProof{}, err
	}
	for resultIndex := range execution.Results {
		for factIndex := range execution.Results[resultIndex].Facts {
			execution.Results[resultIndex].Facts[factIndex] = exactDocumentationDerivedFact{}
		}
		execution.Results[resultIndex].Facts = nil
	}
	return proof, nil
}

func cloneDocumentationTargetParentRegistrationClosure(input documentationTargetParentRegistrationClosure) documentationTargetParentRegistrationClosure {
	input.registrations = append([]documentationTargetParentRegistrationReceipt(nil), input.registrations...)
	return input
}

func validateDocumentationTargetMaterializationFactBinding(materialization documentationTargetMaterialization, fact exactDocumentationDerivedFact) error {
	identity := materialization.identity
	if identity.FactID != fact.FactID || identity.FactOutputSHA256 != sha256Hex(fact.CanonicalOutputFields) ||
		identity.EvidenceLocatorID != fact.EvidenceLocatorID || identity.EvidenceLocatorIdentitySHA256 != sha256Hex([]byte(candidateEvidenceLocatorIdentityKey(fact.EvidenceLocator))) ||
		identity.TargetArtifactRole != fact.TargetArtifactRole || identity.TargetRowKind != fact.TargetRowKind || identity.TargetBindingKind != fact.TargetBindingKind ||
		identity.TargetMemberJSONPointer != fact.TargetMemberJSONPointer || identity.TargetRowSelectorSHA256 != fact.TargetRowSelectorSHA256 || identity.TargetMemberIdentitySHA256 != fact.TargetMemberIdentitySHA256 {
		return fmt.Errorf("documentation target materialization for fact %q differs from its exact executed fact envelope", fact.FactID)
	}
	return nil
}

func validateDocumentationDerivationClosureProof(proof documentationDerivationClosureProof) error {
	if proof.seal != documentationDerivationClosureAuthority || !isLowerSHA256(proof.proofSHA256) || proof.factsByID == nil || int64(len(proof.materializationBindingSHA256ByFact)) != proof.factCount || int64(len(proof.materializationCanonicalBytesByFact)) != proof.factCount {
		return fmt.Errorf("documentation derivation closure proof is absent, malformed, or incomplete")
	}
	hard := canonicalDocumentationDerivationProfileSetHardLimits()
	if !canonicalEvidenceMetadataString(proof.provider, 512) || proof.profileCount <= 0 || proof.outcomeCount <= 0 || proof.pageCount <= 0 || proof.pageCount < proof.profileCount || proof.factCount < 0 || proof.wholeRowBindingCount < 0 || proof.rowMemberBindingCount < 0 || proof.wholeRowBindingCount+proof.rowMemberBindingCount != proof.factCount ||
		proof.profileCountLimit != hard.profileCount || proof.profileCount > proof.profileCountLimit ||
		proof.ruleCount <= 0 || proof.ruleCountLimit != hard.ruleCount || proof.ruleCount > proof.ruleCountLimit ||
		proof.canonicalProgramBytes <= 0 || proof.canonicalProgramByteLimit != hard.canonicalProgramBytes || proof.canonicalProgramBytes > proof.canonicalProgramByteLimit ||
		proof.canonicalClaimSchemaBytes <= 0 || proof.canonicalClaimSchemaByteLimit != hard.canonicalSchemaBytes || proof.canonicalClaimSchemaBytes > proof.canonicalClaimSchemaByteLimit ||
		proof.factCountLimit <= 0 || proof.factCountLimit > hard.factCount || proof.factCount > proof.factCountLimit || proof.canonicalFactByteLimit <= 0 || proof.canonicalFactByteLimit > hard.canonicalFactBytes || proof.canonicalFactBytes < 0 || proof.canonicalFactBytes > proof.canonicalFactByteLimit ||
		proof.outcomeCountLimit <= 0 || proof.outcomeCountLimit > hard.outcomeCount || proof.outcomeCount > proof.outcomeCountLimit || proof.canonicalOutcomeByteLimit <= 0 || proof.canonicalOutcomeByteLimit > hard.canonicalOutcomeBytes || proof.canonicalOutcomeBytes < 0 || proof.canonicalOutcomeBytes > proof.canonicalOutcomeByteLimit ||
		proof.retainedCanonicalByteLimit <= 0 || proof.retainedCanonicalByteLimit > hard.retainedCanonicalBytes || proof.retainedCanonicalBytes < 0 || proof.retainedCanonicalBytes > proof.retainedCanonicalByteLimit || proof.canonicalFactBytes > proof.retainedCanonicalBytes || proof.canonicalOutcomeBytes != proof.retainedCanonicalBytes-proof.canonicalFactBytes ||
		proof.canonicalTargetMaterializationByteLimit != maxDocumentationTargetMaterializationCanonicalBytes || proof.canonicalTargetMaterializationBytes < 0 || proof.canonicalTargetMaterializationBytes > proof.canonicalTargetMaterializationByteLimit ||
		proof.pageCountLimit <= 0 || proof.pageCountLimit > hard.pageCount || proof.pageCount > proof.pageCountLimit || proof.matcherEvaluationCountLimit <= 0 || proof.matcherEvaluationCountLimit > hard.matcherEvaluations || proof.matcherEvaluationCount < 0 || proof.matcherEvaluationCount > proof.matcherEvaluationCountLimit || proof.matcherInputByteLimit <= 0 || proof.matcherInputByteLimit > hard.matcherInputBytes || proof.matcherInputByteCount < 0 || proof.matcherInputByteCount > proof.matcherInputByteLimit ||
		proof.targetParentRegistrationLimit != maxDocumentationTargetParentRegistrations || proof.targetParentRegistrationCount < 0 || proof.targetParentRegistrationCount > proof.targetParentRegistrationLimit ||
		proof.targetParentRegistrationCanonicalByteLimit != maxDocumentationTargetParentCanonicalBytes || proof.targetParentRegistrationCanonicalByteCount < 0 || proof.targetParentRegistrationCanonicalByteCount > proof.targetParentRegistrationCanonicalByteLimit ||
		proof.targetSelectorHydrationLimit != maxDocumentationTargetSelectorHydrations || proof.targetSelectorHydrationCount < 0 || proof.targetSelectorHydrationCount > proof.targetSelectorHydrationLimit {
		return fmt.Errorf("documentation derivation closure proof has invalid identity or counts")
	}
	for _, check := range []struct{ label, digest string }{
		{"evidence selection roster", proof.evidenceSelectionRosterSHA256},
		{"derivation profile artifact", proof.derivationProfileArtifactSHA256},
		{"classification proof", proof.classificationProofSHA256},
		{"profile page set", proof.profilePageSetRootSHA256},
		{"profile result set", proof.profileResultSetRootSHA256},
		{"profile execution set", proof.profileExecutionSetRootSHA256},
		{"profile budget", proof.profileBudgetRootSHA256},
		{"fact envelope", proof.factEnvelopeRootSHA256},
		{"target materialization", proof.targetMaterializationRootSHA256},
		{"target materialization binding roster", proof.targetMaterializationBindingRosterRootSHA256},
		{"target parent registration", proof.targetParentRegistrationRootSHA256},
	} {
		if !isLowerSHA256(check.digest) {
			return fmt.Errorf("documentation derivation closure proof %s digest is malformed", check.label)
		}
	}
	identity := documentationDerivationClosureIdentity{
		Provider: proof.provider, EvidenceSelectionRosterSHA256: proof.evidenceSelectionRosterSHA256,
		DerivationProfileArtifactSHA256:              proof.derivationProfileArtifactSHA256,
		ClassificationProofSHA256:                    proof.classificationProofSHA256,
		ProfileBudgetRootSHA256:                      proof.profileBudgetRootSHA256,
		ProfilePageSetRootSHA256:                     proof.profilePageSetRootSHA256,
		ProfileResultSetRootSHA256:                   proof.profileResultSetRootSHA256,
		ProfileExecutionSetRootSHA256:                proof.profileExecutionSetRootSHA256,
		FactEnvelopeRootSHA256:                       proof.factEnvelopeRootSHA256,
		TargetMaterializationRootSHA256:              proof.targetMaterializationRootSHA256,
		TargetMaterializationBindingRosterRootSHA256: proof.targetMaterializationBindingRosterRootSHA256,
		CanonicalTargetMaterializationBytes:          proof.canonicalTargetMaterializationBytes,
		CanonicalTargetMaterializationByteLimit:      proof.canonicalTargetMaterializationByteLimit,
		TargetParentRegistrationRootSHA256:           proof.targetParentRegistrationRootSHA256,
		ProfileCount:                                 proof.profileCount, ProfileCountLimit: proof.profileCountLimit,
		RuleCount: proof.ruleCount, RuleCountLimit: proof.ruleCountLimit,
		CanonicalProgramBytes: proof.canonicalProgramBytes, CanonicalProgramByteLimit: proof.canonicalProgramByteLimit,
		CanonicalClaimSchemaBytes: proof.canonicalClaimSchemaBytes, CanonicalClaimSchemaByteLimit: proof.canonicalClaimSchemaByteLimit,
		OutcomeCount: proof.outcomeCount, OutcomeCountLimit: proof.outcomeCountLimit,
		FactCount: proof.factCount, FactCountLimit: proof.factCountLimit,
		CanonicalFactBytes: proof.canonicalFactBytes, CanonicalFactByteLimit: proof.canonicalFactByteLimit,
		CanonicalOutcomeBytes: proof.canonicalOutcomeBytes, CanonicalOutcomeByteLimit: proof.canonicalOutcomeByteLimit,
		RetainedCanonicalBytes: proof.retainedCanonicalBytes, RetainedCanonicalByteLimit: proof.retainedCanonicalByteLimit,
		PageCount: proof.pageCount, PageCountLimit: proof.pageCountLimit,
		MatcherEvaluationCount: proof.matcherEvaluationCount, MatcherEvaluationCountLimit: proof.matcherEvaluationCountLimit,
		MatcherInputByteCount: proof.matcherInputByteCount, MatcherInputByteLimit: proof.matcherInputByteLimit,
		WholeRowBindingCount: proof.wholeRowBindingCount, RowMemberBindingCount: proof.rowMemberBindingCount,
		TargetParentRegistrationCount: proof.targetParentRegistrationCount, TargetParentRegistrationLimit: proof.targetParentRegistrationLimit,
		TargetParentRegistrationCanonicalByteCount: proof.targetParentRegistrationCanonicalByteCount, TargetParentRegistrationCanonicalByteLimit: proof.targetParentRegistrationCanonicalByteLimit,
		TargetSelectorHydrationCount: proof.targetSelectorHydrationCount, TargetSelectorHydrationLimit: proof.targetSelectorHydrationLimit,
		Status: documentationDerivationClosureComplete,
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		return err
	}
	setIdentity := exactDocumentationDerivationProfileExecutionSetIdentity{
		ExecutionSetKind: documentationDerivationProfileExecutionSetKind, ClassificationProofSHA256: proof.classificationProofSHA256,
		ProfileBudgetRootSHA256: proof.profileBudgetRootSHA256, ProfilePageSetRootSHA256: proof.profilePageSetRootSHA256, ProfileResultSetRootSHA256: proof.profileResultSetRootSHA256,
		ProfileCount: proof.profileCount, ProfileCountLimit: proof.profileCountLimit, RuleCount: proof.ruleCount, RuleCountLimit: proof.ruleCountLimit,
		CanonicalProgramBytes: proof.canonicalProgramBytes, CanonicalProgramByteLimit: proof.canonicalProgramByteLimit,
		CanonicalClaimSchemaBytes: proof.canonicalClaimSchemaBytes, CanonicalClaimSchemaLimit: proof.canonicalClaimSchemaByteLimit,
		FactCount: proof.factCount, FactCountLimit: proof.factCountLimit, CanonicalFactBytes: proof.canonicalFactBytes, CanonicalFactByteLimit: proof.canonicalFactByteLimit,
		OutcomeCount: proof.outcomeCount, OutcomeCountLimit: proof.outcomeCountLimit, CanonicalOutcomeBytes: proof.canonicalOutcomeBytes, CanonicalOutcomeByteLimit: proof.canonicalOutcomeByteLimit,
		RetainedCanonicalBytes: proof.retainedCanonicalBytes, RetainedCanonicalByteLimit: proof.retainedCanonicalByteLimit,
		PageCount: proof.pageCount, PageCountLimit: proof.pageCountLimit, MatcherEvaluationCount: proof.matcherEvaluationCount, MatcherEvaluationCountLimit: proof.matcherEvaluationCountLimit,
		MatcherInputByteCount: proof.matcherInputByteCount, MatcherInputByteLimit: proof.matcherInputByteLimit, Status: documentationDerivationProfileExecutionSetComplete,
	}
	setCanonical, setErr := canonicalDocumentationBytes(setIdentity)
	if setErr != nil || proof.executionSetReceipt.seal != exactDocumentationDerivationProfileExecutionSetAuthority || proof.executionSetReceipt.identity != setIdentity || proof.executionSetReceipt.rootSHA256 != proof.profileExecutionSetRootSHA256 || sha256Hex(setCanonical) != proof.executionSetReceipt.rootSHA256 {
		return fmt.Errorf("documentation derivation closure execution-set receipt is absent or differs from its exact evidence")
	}
	if err := validateDocumentationTargetParentRegistrationClosure(proof.parentRegistrationReceipt); err != nil || proof.parentRegistrationReceipt.rootSHA256 != proof.targetParentRegistrationRootSHA256 || proof.parentRegistrationReceipt.registrationCount != proof.targetParentRegistrationCount || proof.parentRegistrationReceipt.selectorHydrations != proof.targetSelectorHydrationCount || proof.parentRegistrationReceipt.canonicalByteCount != proof.targetParentRegistrationCanonicalByteCount {
		return fmt.Errorf("documentation derivation closure parent-registration receipt differs from its exact evidence")
	}
	if sha256Hex(canonical) != proof.proofSHA256 || documentationTargetMaterializationBindingMapRoot(proof.materializationBindingSHA256ByFact, proof.materializationCanonicalBytesByFact) != proof.targetMaterializationBindingRosterRootSHA256 || documentationDerivationProfileExecutionSetRoot(identity) != proof.profileExecutionSetRootSHA256 {
		return fmt.Errorf("documentation derivation closure proof differs from its sealed identity")
	}
	var canonicalMaterializationBytes int64
	for _, factID := range sortedProviderStringMapKeys(proof.materializationBindingSHA256ByFact) {
		bindingSHA := proof.materializationBindingSHA256ByFact[factID]
		canonicalBytes, exists := proof.materializationCanonicalBytesByFact[factID]
		if !canonicalEvidenceMetadataString(factID, 512) || !isLowerSHA256(bindingSHA) || !exists || canonicalBytes <= 0 || canonicalBytes > proof.canonicalTargetMaterializationByteLimit-canonicalMaterializationBytes {
			return fmt.Errorf("documentation derivation closure proof has an invalid fact/materialization binding")
		}
		canonicalMaterializationBytes += canonicalBytes
	}
	if canonicalMaterializationBytes != proof.canonicalTargetMaterializationBytes {
		return fmt.Errorf("documentation derivation closure proof canonical materialization bytes differ from the exact per-fact roster")
	}
	if int64(len(proof.factsByID)) != proof.factCount {
		return fmt.Errorf("documentation derivation closure proof fact roster is incomplete")
	}
	facts := make([]exactDocumentationDerivedFact, 0, len(proof.factsByID))
	for _, factID := range sortedProviderStringMapKeys(proof.factsByID) {
		fact := proof.factsByID[factID]
		if factID != fact.FactID {
			return fmt.Errorf("documentation derivation closure proof fact map key differs from its fact identity")
		}
		if _, materialized := proof.materializationBindingSHA256ByFact[factID]; !materialized {
			return fmt.Errorf("documentation derivation closure proof fact %q has no exact materialization binding", factID)
		}
		if err := validateExactDocumentationDerivedFactIntegrity(fact); err != nil {
			return fmt.Errorf("documentation derivation closure proof fact %q: %w", factID, err)
		}
		facts = append(facts, fact)
	}
	if exactDocumentationFactRoot(facts) != proof.factEnvelopeRootSHA256 {
		return fmt.Errorf("documentation derivation closure proof fact roster differs from its sealed root")
	}
	canonicalFactBytes, err := exactDocumentationCanonicalFactByteCount(facts, proof.canonicalFactByteLimit)
	if err != nil || canonicalFactBytes != proof.canonicalFactBytes {
		return fmt.Errorf("documentation derivation closure proof canonical fact bytes differ from its executed envelopes")
	}
	return nil
}

func resolveDocumentationMemberSchema(resolution dependencySemanticDerivationTargetResolution, pointer string) (documentationMemberSchemaDescriptor, error) {
	var descriptor documentationMemberSchemaDescriptor
	if resolution.discriminatorProperty != "row_kind" || resolution.targetRowKind == "" || sha256Hex(resolution.schemaBytes) != resolution.schemaSHA256 {
		return descriptor, fmt.Errorf("documentation target member schema resolution is not exact")
	}
	tokens, err := documentationJSONPointerTokens(pointer)
	if err != nil {
		return descriptor, err
	}
	var root map[string]interface{}
	if err := decodeOneValidationProfileJSON(resolution.schemaBytes, &root); err != nil {
		return descriptor, fmt.Errorf("decode documentation target schema: %w", err)
	}
	branches, err := documentationRowKindSchemaBranches(root, root, resolution.discriminatorProperty, resolution.targetRowKind, "$", map[string]bool{})
	if err != nil {
		return descriptor, err
	}
	if len(branches) == 0 {
		return descriptor, fmt.Errorf("documentation target schema has no branch for row_kind %q", resolution.targetRowKind)
	}
	var exactDescriptor []byte
	var propertyNames map[string]struct{}
	for index, branch := range branches {
		memberSchema, names, err := documentationMemberSchemaAtPointer(root, branch, tokens)
		if err != nil {
			return descriptor, fmt.Errorf("documentation target schema row_kind %q branch %d pointer %q: %w", resolution.targetRowKind, index, pointer, err)
		}
		canonical, err := canonicalizeCandidateJSON(memberSchema)
		if err != nil {
			return descriptor, err
		}
		if exactDescriptor == nil {
			exactDescriptor = canonical
			propertyNames = names
		} else if !bytes.Equal(exactDescriptor, canonical) || !stringSetsEqual(propertyNames, names) {
			return descriptor, fmt.Errorf("documentation target schema row_kind %q branches disagree on member pointer %q", resolution.targetRowKind, pointer)
		}
	}
	for _, field := range sortedProviderStringMapKeys(documentationDerivationMemberEnvelopeFields) {
		if _, exists := propertyNames[field]; !exists {
			return descriptor, fmt.Errorf("documentation target member schema pointer %q omits required generic envelope field %q", pointer, field)
		}
	}
	var itemSchema map[string]interface{}
	if err := decodeOneValidationProfileJSON(exactDescriptor, &itemSchema); err != nil {
		return descriptor, fmt.Errorf("decode exact documentation target member schema: %w", err)
	}
	return documentationMemberSchemaDescriptor{pointer: pointer, tokens: tokens, propertyNames: propertyNames, root: root, itemSchema: itemSchema}, nil
}

func documentationJSONPointerTokens(pointer string) ([]string, error) {
	if err := validateExactDocumentationTargetBinding(exactDocumentationTargetRowMember, pointer); err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	tokens := make([]string, len(parts))
	for index, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("documentation target member JSON Pointer has an empty property token")
		}
		token, err := unescapeValidationProfileJSONPointerToken(part)
		if err != nil {
			return nil, err
		}
		if escapeValidationProfileJSONPointerToken(token) != part {
			return nil, fmt.Errorf("documentation target member JSON Pointer is not canonically escaped")
		}
		tokens[index] = token
	}
	return tokens, nil
}

func documentationRowKindSchemaBranches(node interface{}, root map[string]interface{}, discriminator, rowKind, path string, stack map[string]bool) ([]map[string]interface{}, error) {
	object, ok := node.(map[string]interface{})
	if !ok {
		return nil, nil
	}
	for _, keyword := range []string{"$ref", "$dynamicRef"} {
		if rawRef, present := object[keyword]; present {
			ref, ok := rawRef.(string)
			if !ok {
				return nil, fmt.Errorf("documentation target schema %s at %s is not a string", keyword, path)
			}
			target, targetPath, err := resolveValidationProfileLocalJSONPointer(root, ref)
			if err != nil {
				return nil, err
			}
			if stack[targetPath] {
				return nil, fmt.Errorf("documentation target schema reference cycle at %s", targetPath)
			}
			stack[targetPath] = true
			result, err := documentationRowKindSchemaBranches(target, root, discriminator, rowKind, targetPath, stack)
			delete(stack, targetPath)
			return result, err
		}
	}
	for _, keyword := range []string{"oneOf", "anyOf"} {
		if rawBranches, present := object[keyword]; present {
			branches, ok := rawBranches.([]interface{})
			if !ok || len(branches) == 0 {
				return nil, fmt.Errorf("documentation target schema %s at %s is empty or malformed", keyword, path)
			}
			result := make([]map[string]interface{}, 0)
			for index, branch := range branches {
				selected, err := documentationRowKindSchemaBranches(branch, root, discriminator, rowKind, fmt.Sprintf("%s/%s/%d", path, keyword, index), stack)
				if err != nil {
					return nil, err
				}
				result = append(result, selected...)
			}
			return result, nil
		}
	}
	if _, present := object["allOf"]; present {
		return nil, fmt.Errorf("documentation target row/member resolution does not accept ambiguous allOf composition at %s", path)
	}
	properties, ok := object["properties"].(map[string]interface{})
	if !ok {
		return nil, nil
	}
	discriminatorSchema, ok := properties[discriminator].(map[string]interface{})
	if !ok {
		return nil, nil
	}
	values, finite := finiteValidationProfileStringValues(discriminatorSchema)
	if !finite {
		return nil, fmt.Errorf("documentation target schema discriminator %q at %s is not finite", discriminator, path)
	}
	if _, selected := values[rowKind]; !selected {
		return nil, nil
	}
	return []map[string]interface{}{object}, nil
}

func documentationMemberSchemaAtPointer(root map[string]interface{}, branch map[string]interface{}, tokens []string) ([]byte, map[string]struct{}, error) {
	current := interface{}(branch)
	for _, token := range tokens {
		resolved, err := documentationResolveSchemaNode(root, current)
		if err != nil {
			return nil, nil, err
		}
		object, ok := resolved.(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("schema path traverses a non-object schema node")
		}
		required, err := documentationSchemaRequiredSet(object)
		if err != nil {
			return nil, nil, err
		}
		if _, requiredProperty := required[token]; !requiredProperty {
			return nil, nil, fmt.Errorf("property %q is not required", token)
		}
		properties, ok := object["properties"].(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("schema node has no closed properties")
		}
		next, exists := properties[token]
		if !exists {
			return nil, nil, fmt.Errorf("property %q is absent", token)
		}
		current = next
	}
	resolved, err := documentationResolveSchemaNode(root, current)
	if err != nil {
		return nil, nil, err
	}
	arraySchema, ok := resolved.(map[string]interface{})
	if !ok || !documentationSchemaTypeEquals(arraySchema, "array") {
		return nil, nil, fmt.Errorf("selected member roster schema is not an array")
	}
	items, exists := arraySchema["items"]
	if !exists {
		return nil, nil, fmt.Errorf("selected member roster schema has no items schema")
	}
	resolvedItems, err := documentationResolveSchemaNode(root, items)
	if err != nil {
		return nil, nil, err
	}
	itemObject, ok := resolvedItems.(map[string]interface{})
	if !ok || !documentationSchemaTypeEquals(itemObject, "object") || !validationProfileSchemaHasLocalObjectClosure(itemObject) {
		return nil, nil, fmt.Errorf("selected member roster items are not one closed object shape")
	}
	properties, ok := itemObject["properties"].(map[string]interface{})
	if !ok || len(properties) == 0 {
		return nil, nil, fmt.Errorf("selected member roster item has no finite property roster")
	}
	required, err := documentationSchemaRequiredSet(itemObject)
	if err != nil {
		return nil, nil, err
	}
	propertyNames := stringMapKeysAsSet(properties)
	if !stringSetsEqual(required, propertyNames) {
		return nil, nil, fmt.Errorf("selected member roster item properties are not all required")
	}
	for _, field := range sortedProviderStringMapKeys(documentationDerivationMemberEnvelopeFields) {
		fieldSchema, exists := properties[field]
		if !exists {
			return nil, nil, fmt.Errorf("selected member roster item omits %q", field)
		}
		resolvedField, err := documentationResolveSchemaNode(root, fieldSchema)
		if err != nil {
			return nil, nil, err
		}
		array, ok := resolvedField.(map[string]interface{})
		if !ok || !documentationSchemaTypeEquals(array, "array") {
			return nil, nil, fmt.Errorf("selected member roster field %q is not an array", field)
		}
		item, err := documentationResolveSchemaNode(root, array["items"])
		if err != nil {
			return nil, nil, err
		}
		itemSchema, ok := item.(map[string]interface{})
		if !ok || !documentationSchemaTypeEquals(itemSchema, "string") {
			return nil, nil, fmt.Errorf("selected member roster field %q items are not strings", field)
		}
	}
	raw, err := json.Marshal(itemObject)
	return raw, propertyNames, err
}

func documentationResolveSchemaNode(root map[string]interface{}, node interface{}) (interface{}, error) {
	object, ok := node.(map[string]interface{})
	if !ok {
		return node, nil
	}
	for _, keyword := range []string{"$ref", "$dynamicRef"} {
		if rawRef, present := object[keyword]; present {
			ref, ok := rawRef.(string)
			if !ok {
				return nil, fmt.Errorf("schema %s is not a string", keyword)
			}
			resolved, _, err := resolveValidationProfileLocalJSONPointer(root, ref)
			return resolved, err
		}
	}
	return object, nil
}

func documentationSchemaRequiredSet(object map[string]interface{}) (map[string]struct{}, error) {
	raw, ok := object["required"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("schema object has no required property roster")
	}
	result := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		property, ok := value.(string)
		if !ok || property == "" {
			return nil, fmt.Errorf("schema required property roster is malformed")
		}
		if _, duplicate := result[property]; duplicate {
			return nil, fmt.Errorf("schema required property roster duplicates %q", property)
		}
		result[property] = struct{}{}
	}
	return result, nil
}

func documentationSchemaTypeEquals(schema map[string]interface{}, expected string) bool {
	value, ok := schema["type"].(string)
	return ok && value == expected
}

func documentationJSONPointerValue(root interface{}, tokens []string) (interface{}, error) {
	current := root
	for _, token := range tokens {
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("pointer traverses a non-object value")
		}
		next, exists := object[token]
		if !exists {
			return nil, fmt.Errorf("pointer property %q is absent", token)
		}
		current = next
	}
	return current, nil
}
