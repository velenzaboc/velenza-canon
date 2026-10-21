package providerplan

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

const (
	applicabilityDispositionRequired     = "required"
	applicabilityDispositionOptional     = "optional"
	applicabilityDispositionInapplicable = "inapplicable"
)

type applicabilityProfileBinding struct {
	id      string
	version string
	digest  string
}

type applicabilityPredicate struct {
	kind                string
	trait               string
	value               interface{}
	classifierProfileID string
	values              map[string]struct{}
}

type applicabilityConditionalRule struct {
	disposition string
	predicate   applicabilityPredicate
}

type applicabilityCardinality struct {
	minimum int64
	maximum *int64
}

type relationshipApplicabilityRule struct {
	id                           string
	label                        string
	sourceRole                   string
	targetRole                   string
	subjectEndpoint              string
	subjectRole                  string
	defaultDisposition           string
	conditionalRules             []applicabilityConditionalRule
	cardinality                  applicabilityCardinality
	unmatchedEndpointDisposition string
}

type claimApplicabilityRule struct {
	id                 string
	blockedClaimKind   string
	blockedSubjectKind string
	defaultDisposition string
	conditionalRules   []applicabilityConditionalRule
	cardinality        applicabilityCardinality
}

type propertyApplicabilityRule struct {
	id                           string
	family                       string
	eligibleSubjectKinds         map[string]struct{}
	allowedRoles                 map[string]struct{}
	relationshipLabelScope       map[string]struct{}
	defaultDisposition           string
	conditionalRules             []applicabilityConditionalRule
	disallowedSubjectDisposition string
	maximumClaimsPerSubject      int64
}

type apiGraphApplicabilityState struct {
	binding             applicabilityProfileBinding
	relationshipByLabel map[string]relationshipApplicabilityRule
	propertyByID        map[string]propertyApplicabilityRule
	claimByID           map[string]claimApplicabilityRule
	allRuleKindsByID    map[string]string
}

type operationApplicabilityEntry struct {
	row                     dependencySemanticRow
	applicabilityID         string
	operationID             string
	semanticIdentity        string
	operationKind           string
	sourceSymbol            string
	sourceIdentity          map[string]interface{}
	sourceIdentityCanonical string
	resourceAccesses        []operationResourceAccess
	classifierReference     dependencyProfileReference
	subjectTraits           map[string]interface{}
	sourcePropertyIDs       map[string]struct{}
	actualRelationshipIDs   map[string]struct{}
	actualPropertyIDs       map[string]struct{}
	evidenceLocatorIDs      map[string]struct{}
	evidenceFactIDs         map[string]struct{}
}

type operationResourceAccess struct {
	id                       string
	resourceID               string
	resourceSemanticIdentity string
	resourceSourceSymbol     string
	relationshipLabel        string
	accessSemantics          string
	classifierInputBinding   operationClassifierInputBinding
	evidenceLocatorIDs       map[string]struct{}
	evidenceFactIDs          map[string]struct{}
}

type operationApplicabilityState struct {
	byOperationID              map[string]operationApplicabilityEntry
	bySemanticIdentity         map[string]operationApplicabilityEntry
	resourceBindingsByID       map[string]string
	resourceSourceSymbolsByID  map[string]string
	sourceContractOperationIDs map[string]struct{}
	operationKindCounts        map[string]int
	classifierResourceActuals  operationClassifierResourceBudget
	classifierResourceLimits   operationClassifierResourceBudget
	coverageProof              applicabilityCoverageProof
}

const applicabilityCoverageProofSeal = "exact_independently_evaluated_required_disposition_v1"

type applicabilityCoverageProof struct {
	seal           string
	requiredGapIDs map[string]struct{}
}

const (
	operationClassifierProgramKind           = "source_neutral_operation_applicability_v1"
	operationClassifierSourceFactKind        = "source_resource_access"
	operationClassifierProtocolFactKind      = "protocol_semantic_class"
	operationClassifierSourceArtifactRole    = "source_contract_index"
	operationClassifierProtocolArtifactRole  = "protocol_contract_index"
	maxOperationClassifierPrograms           = int64(1024)
	maxOperationClassifierProgramBytes       = int64(16 << 20)
	maxOperationClassifierProgramSetBytes    = int64(64 << 20)
	maxOperationClassifierVocabularyMembers  = int64(4096)
	maxOperationClassifierSubjectTraits      = int64(256)
	maxOperationClassifierAccessRules        = int64(4096)
	maxOperationClassifierAggregateRules     = int64(4096)
	maxOperationClassifierSourceRows         = int64(1 << 20)
	maxOperationClassifierSourceAccesses     = int64(1 << 22)
	maxOperationClassifierSourceEvidenceRefs = int64(1 << 23)
	maxOperationClassifierProtocolRows       = int64(1 << 20)
	maxOperationClassifierProtocolAssertions = int64(1 << 22)
	maxOperationClassifierProtocolBindings   = int64(1 << 23)
	maxOperationClassifierPlanRelationships  = int64(1 << 22)
	maxOperationClassifierPlanProperties     = int64(1 << 22)
	maxOperationClassifierEntries            = int64(1 << 20)
	maxOperationClassifierEntryAccesses      = int64(1 << 22)
	maxOperationClassifierEntryEvidenceRefs  = int64(1 << 23)
)

type operationClassifierResourceBudget struct {
	programs           int64
	programBytes       int64
	sourceRows         int64
	sourceAccesses     int64
	sourceEvidenceRefs int64
	protocolRows       int64
	protocolAssertions int64
	protocolBindings   int64
	planRelationships  int64
	planProperties     int64
	entries            int64
	entryAccesses      int64
	entryEvidenceRefs  int64
}

var canonicalOperationClassifierResourceLimits = operationClassifierResourceBudget{
	programs:           maxOperationClassifierPrograms,
	programBytes:       maxOperationClassifierProgramSetBytes,
	sourceRows:         maxOperationClassifierSourceRows,
	sourceAccesses:     maxOperationClassifierSourceAccesses,
	sourceEvidenceRefs: maxOperationClassifierSourceEvidenceRefs,
	protocolRows:       maxOperationClassifierProtocolRows,
	protocolAssertions: maxOperationClassifierProtocolAssertions,
	protocolBindings:   maxOperationClassifierProtocolBindings,
	planRelationships:  maxOperationClassifierPlanRelationships,
	planProperties:     maxOperationClassifierPlanProperties,
	entries:            maxOperationClassifierEntries,
	entryAccesses:      maxOperationClassifierEntryAccesses,
	entryEvidenceRefs:  maxOperationClassifierEntryEvidenceRefs,
}

type operationClassifierInputBinding struct {
	artifactRole    string
	artifactSHA256  string
	rowKind         string
	rowIdentity     string
	rowSHA256       string
	factLocatorKind string
	factOrdinal     int64
}

type operationClassifierFact struct {
	kind   string
	values map[string]string
}

type protocolOperationClassifierPredecessor struct {
	id                               string
	sourceSymbol                     string
	resourceSourceSymbol             string
	sourceOperationIdentity          map[string]interface{}
	sourceOperationIdentityCanonical string
	semanticClass                    string
	assertionIDs                     []string
	locatorIDs                       []string
}

type operationClassifierOutput struct {
	operationKind string
	subjectTraits map[string]interface{}
}

type operationClassifierAccessOutput struct {
	relationshipLabel         string
	accessSemantics           string
	subjectTraitContributions map[string]bool
}

type operationClassifierFactContract struct {
	artifactRole string
	rowKind      string
	matchFields  map[string]struct{}
	matchField   string
}

type operationClassifierProgram struct {
	factContracts         map[string]operationClassifierFactContract
	relationshipLabels    map[string]struct{}
	subjectTraits         map[string]struct{}
	accessRuleByPredicate map[string]operationClassifierAccessOutput
	aggregateRuleByTraits map[string]string
	subjectTraitOrder     []string
	canonicalByteCount    int64
	traitAggregationKind  string
}

type indexedSourceOperationAccess struct {
	resourceSourceSymbol string
	relationshipLabel    string
	evidenceLocatorIDs   map[string]struct{}
	evidenceFactIDs      map[string]struct{}
}

type indexedSourceOperationPredecessor struct {
	rowSHA256               string
	semanticIdentity        string
	sourceSymbol            string
	sourceIdentityCanonical string
	accesses                []indexedSourceOperationAccess
}

type indexedProtocolOperationPredecessor struct {
	rowSHA256 string
	value     protocolOperationClassifierPredecessor
}

type operationClassifierValidationContext struct {
	programsByReference                 map[string]operationClassifierProgram
	sourceArtifactSHA256                string
	protocolArtifactSHA256              string
	sourceBySemanticIdentity            map[string][]*indexedSourceOperationPredecessor
	sourceBySemanticIdentityAndRowSHA   map[string][]*indexedSourceOperationPredecessor
	protocolByID                        map[string][]*indexedProtocolOperationPredecessor
	protocolByOperationSemanticIdentity map[string][]*indexedProtocolOperationPredecessor
	protocolAssertionCounts             map[string]int
	incidentRelationshipIDsBySymbol     map[string]map[string]struct{}
	propertyIDsByOperation              map[string]map[string]struct{}
	actuals                             operationClassifierResourceBudget
	limits                              operationClassifierResourceBudget
}

func validateOperationClassifierResourceLimits(limits operationClassifierResourceBudget) error {
	checks := []struct {
		label   string
		value   int64
		ceiling int64
	}{
		{"program count", limits.programs, canonicalOperationClassifierResourceLimits.programs},
		{"canonical program bytes", limits.programBytes, canonicalOperationClassifierResourceLimits.programBytes},
		{"source rows", limits.sourceRows, canonicalOperationClassifierResourceLimits.sourceRows},
		{"source accesses", limits.sourceAccesses, canonicalOperationClassifierResourceLimits.sourceAccesses},
		{"source evidence references", limits.sourceEvidenceRefs, canonicalOperationClassifierResourceLimits.sourceEvidenceRefs},
		{"protocol rows", limits.protocolRows, canonicalOperationClassifierResourceLimits.protocolRows},
		{"protocol assertions", limits.protocolAssertions, canonicalOperationClassifierResourceLimits.protocolAssertions},
		{"protocol bindings", limits.protocolBindings, canonicalOperationClassifierResourceLimits.protocolBindings},
		{"plan relationships", limits.planRelationships, canonicalOperationClassifierResourceLimits.planRelationships},
		{"plan properties", limits.planProperties, canonicalOperationClassifierResourceLimits.planProperties},
		{"operation entries", limits.entries, canonicalOperationClassifierResourceLimits.entries},
		{"entry accesses", limits.entryAccesses, canonicalOperationClassifierResourceLimits.entryAccesses},
		{"entry evidence references", limits.entryEvidenceRefs, canonicalOperationClassifierResourceLimits.entryEvidenceRefs},
	}
	for _, check := range checks {
		if check.value <= 0 || check.value > check.ceiling {
			return fmt.Errorf("operation classifier %s limit %d is outside its closed canonical ceiling %d", check.label, check.value, check.ceiling)
		}
	}
	return nil
}

func reserveOperationClassifierResource(actual *int64, add, limit int64, label string) error {
	if add < 0 || *actual < 0 || add > limit || *actual > limit-add {
		return fmt.Errorf("operation classifier %s actual would exceed limit %d", label, limit)
	}
	*actual += add
	return nil
}

func newOperationClassifierValidationContext(rows dependencySemanticRows, derivationState documentationClaimDerivationState, apiState apiGraphApplicabilityState, sourceRows, protocolRows dependencySemanticRows, plan *parsedPlan, limits operationClassifierResourceBudget) (*operationClassifierValidationContext, error) {
	if err := validateOperationClassifierResourceLimits(limits); err != nil {
		return nil, err
	}
	context, err := newOperationClassifierPredecessorContext(sourceRows, protocolRows, limits)
	if err != nil {
		return nil, err
	}
	context.programsByReference = map[string]operationClassifierProgram{}
	context.limits = limits
	operationRows := rows.byKind["operation_applicability"]
	if err := reserveOperationClassifierResource(&context.actuals.entries, int64(len(operationRows)), limits.entries, "operation-entry count"); err != nil {
		return nil, err
	}
	references := map[string]dependencyProfileReference{}
	for _, row := range operationRows {
		derivation, derivationOK := semanticObject(row.data, "derivation_binding")
		reference, referenceOK := dependencyProfileReferenceFromFields(derivation, "classifier_profile")
		if !derivationOK || !referenceOK {
			return nil, semanticRowError(rows, row, "derivation binding has no exact operation-classifier coordinate")
		}
		key := dependencyProfileReferenceKey(reference)
		if _, exists := references[key]; exists {
			continue
		}
		if err := reserveOperationClassifierResource(&context.actuals.programs, 1, limits.programs, "program count"); err != nil {
			return nil, err
		}
		references[key] = reference
	}
	for _, key := range sortedSetKeys(stringMapKeysAsSet(references)) {
		reference := references[key]
		profile, exists := derivationState.classifiers[key]
		if !exists {
			return nil, fmt.Errorf("operation applicability classifier coordinate %s/%s/%s is absent from the exact documentation-derivation profile", reference.id, reference.version, reference.digest)
		}
		program, err := parseOperationClassifierProgram(profile, reference)
		if err != nil {
			return nil, fmt.Errorf("operation applicability classifier coordinate %s/%s/%s: %w", reference.id, reference.version, reference.digest, err)
		}
		if err := reserveOperationClassifierResource(&context.actuals.programBytes, program.canonicalByteCount, limits.programBytes, "canonical program bytes"); err != nil {
			return nil, err
		}
		if err := validateOperationClassifierProgramRelationshipLabelClosure(program, apiState); err != nil {
			return nil, err
		}
		context.programsByReference[key] = program
	}
	if plan != nil {
		if err := indexOperationClassifierPlan(context, plan); err != nil {
			return nil, err
		}
	}
	return context, nil
}

func newOperationClassifierPredecessorContext(sourceRows, protocolRows dependencySemanticRows, limits operationClassifierResourceBudget) (*operationClassifierValidationContext, error) {
	if err := validateOperationClassifierResourceLimits(limits); err != nil {
		return nil, err
	}
	context := &operationClassifierValidationContext{
		sourceArtifactSHA256:                sha256Hex(sourceRows.raw),
		protocolArtifactSHA256:              sha256Hex(protocolRows.raw),
		sourceBySemanticIdentity:            map[string][]*indexedSourceOperationPredecessor{},
		sourceBySemanticIdentityAndRowSHA:   map[string][]*indexedSourceOperationPredecessor{},
		protocolByID:                        map[string][]*indexedProtocolOperationPredecessor{},
		protocolByOperationSemanticIdentity: map[string][]*indexedProtocolOperationPredecessor{},
		protocolAssertionCounts:             map[string]int{},
		incidentRelationshipIDsBySymbol:     map[string]map[string]struct{}{},
		propertyIDsByOperation:              map[string]map[string]struct{}{},
		limits:                              limits,
	}
	sourceOperationRows := sourceRows.byKind["api_operation"]
	if err := reserveOperationClassifierResource(&context.actuals.sourceRows, int64(len(sourceOperationRows)), limits.sourceRows, "source-row count"); err != nil {
		return nil, err
	}
	for _, row := range sourceOperationRows {
		if _, err := coordinateFromRow(row.data); err != nil {
			return nil, semanticRowError(sourceRows, row, "operation classifier predecessor coordinate: %v", err)
		}
		sourceSymbol, sourceOK := semanticString(row.data, "source_symbol")
		identity, identityErr := parseSourceOperationIdentity(row.data)
		if !sourceOK || identityErr != nil {
			return nil, semanticRowError(sourceRows, row, "operation classifier predecessor identity is incomplete")
		}
		identityCanonical, err := canonicalSourceOperationIdentity(identity)
		if err != nil {
			return nil, semanticRowError(sourceRows, row, "operation classifier predecessor identity: %v", err)
		}
		semanticIdentity, err := sourceOperationSemanticKey(sourceSymbol, identity)
		if err != nil {
			return nil, semanticRowError(sourceRows, row, "operation classifier predecessor identity: %v", err)
		}
		accessObjects, accessesOK := semanticObjectSlice(row.data, "resource_accesses")
		if !accessesOK || len(accessObjects) == 0 {
			return nil, semanticRowError(sourceRows, row, "source operation predecessor has no typed resource_accesses")
		}
		if err := reserveOperationClassifierResource(&context.actuals.sourceAccesses, int64(len(accessObjects)), limits.sourceAccesses, "source-access count"); err != nil {
			return nil, err
		}
		predecessor := &indexedSourceOperationPredecessor{
			rowSHA256: sha256Hex(row.raw), semanticIdentity: semanticIdentity,
			sourceSymbol: sourceSymbol, sourceIdentityCanonical: string(identityCanonical),
			accesses: make([]indexedSourceOperationAccess, 0, len(accessObjects)),
		}
		for index, object := range accessObjects {
			resourceSourceSymbol, resourceOK := semanticString(object, "source_symbol")
			relationshipLabel, labelOK := semanticString(object, "relationship_label")
			locators, facts, evidenceErr := parseSourceOperationAccessEvidence(object)
			if !resourceOK || !labelOK || evidenceErr != nil {
				return nil, semanticRowError(sourceRows, row, "resource_accesses[%d] is incomplete: %v", index, evidenceErr)
			}
			if err := reserveOperationClassifierResource(&context.actuals.sourceEvidenceRefs, int64(len(locators)), limits.sourceEvidenceRefs, "source-evidence reference count"); err != nil {
				return nil, err
			}
			if err := reserveOperationClassifierResource(&context.actuals.sourceEvidenceRefs, int64(len(facts)), limits.sourceEvidenceRefs, "source-evidence reference count"); err != nil {
				return nil, err
			}
			predecessor.accesses = append(predecessor.accesses, indexedSourceOperationAccess{
				resourceSourceSymbol: resourceSourceSymbol, relationshipLabel: relationshipLabel,
				evidenceLocatorIDs: locators, evidenceFactIDs: facts,
			})
		}
		context.sourceBySemanticIdentity[semanticIdentity] = append(context.sourceBySemanticIdentity[semanticIdentity], predecessor)
		exactKey := lengthPrefixedIdentityKey(semanticIdentity, predecessor.rowSHA256)
		context.sourceBySemanticIdentityAndRowSHA[exactKey] = append(context.sourceBySemanticIdentityAndRowSHA[exactKey], predecessor)
	}

	protocolPredecessorRows := protocolRows.byKind["operation_classifier_fact"]
	if err := reserveOperationClassifierResource(&context.actuals.protocolRows, int64(len(protocolPredecessorRows)), limits.protocolRows, "protocol-row count"); err != nil {
		return nil, err
	}
	assertionRows := protocolRows.byKind["protocol_assertion_projection"]
	if err := reserveOperationClassifierResource(&context.actuals.protocolAssertions, int64(len(assertionRows)), limits.protocolAssertions, "protocol-assertion count"); err != nil {
		return nil, err
	}
	for _, assertion := range assertionRows {
		if assertionID, ok := semanticString(assertion.data, "assertion_id"); ok {
			context.protocolAssertionCounts[assertionID]++
		}
	}
	for _, row := range protocolPredecessorRows {
		predecessor, err := parseProtocolOperationClassifierPredecessor(protocolRows, row)
		if err != nil {
			return nil, err
		}
		if err := reserveOperationClassifierResource(&context.actuals.protocolBindings, int64(len(predecessor.assertionIDs)), limits.protocolBindings, "protocol-binding count"); err != nil {
			return nil, err
		}
		if err := reserveOperationClassifierResource(&context.actuals.protocolBindings, int64(len(predecessor.locatorIDs)), limits.protocolBindings, "protocol-binding count"); err != nil {
			return nil, err
		}
		canonicalIdentity, err := canonicalSourceOperationIdentity(predecessor.sourceOperationIdentity)
		if err != nil {
			return nil, err
		}
		predecessor.sourceOperationIdentityCanonical = string(canonicalIdentity)
		semanticIdentity, err := sourceOperationSemanticKey(predecessor.sourceSymbol, predecessor.sourceOperationIdentity)
		if err != nil {
			return nil, err
		}
		predecessor.sourceOperationIdentity = nil
		indexed := &indexedProtocolOperationPredecessor{rowSHA256: sha256Hex(row.raw), value: predecessor}
		context.protocolByID[predecessor.id] = append(context.protocolByID[predecessor.id], indexed)
		context.protocolByOperationSemanticIdentity[semanticIdentity] = append(context.protocolByOperationSemanticIdentity[semanticIdentity], indexed)
	}
	return context, nil
}

func indexOperationClassifierPlan(context *operationClassifierValidationContext, plan *parsedPlan) error {
	if err := reserveOperationClassifierResource(&context.actuals.planRelationships, int64(len(plan.Relationships)), context.limits.planRelationships, "plan-relationship count"); err != nil {
		return err
	}
	addIncident := func(symbolID, relationshipID string) {
		symbol, exists := plan.Symbols[symbolID]
		if !exists || symbol.Role != "operation" {
			return
		}
		if context.incidentRelationshipIDsBySymbol[symbolID] == nil {
			context.incidentRelationshipIDsBySymbol[symbolID] = map[string]struct{}{}
		}
		context.incidentRelationshipIDsBySymbol[symbolID][relationshipID] = struct{}{}
	}
	for _, id := range sortedProviderStringMapKeys(plan.Relationships) {
		relationship := plan.Relationships[id]
		addIncident(relationship.SourceID, id)
		if relationship.TargetID != relationship.SourceID {
			addIncident(relationship.TargetID, id)
		}
	}
	if err := reserveOperationClassifierResource(&context.actuals.planProperties, int64(len(plan.Properties)), context.limits.planProperties, "plan-property count"); err != nil {
		return err
	}
	for _, id := range sortedProviderStringMapKeys(plan.Properties) {
		property := plan.Properties[id]
		if property.SubjectKind != "api_symbol_object" {
			continue
		}
		symbol, exists := plan.Symbols[property.SubjectID]
		if !exists || symbol.Role != "operation" {
			continue
		}
		if context.propertyIDsByOperation[property.SubjectID] == nil {
			context.propertyIDsByOperation[property.SubjectID] = map[string]struct{}{}
		}
		context.propertyIDsByOperation[property.SubjectID][id] = struct{}{}
	}
	return nil
}

func validateOperationApplicabilityRows(rows, apiRows, sourceRows, protocolRows, derivationRows dependencySemanticRows, plan *parsedPlan, apiState apiGraphApplicabilityState, derivationState documentationClaimDerivationState) (operationApplicabilityState, error) {
	state := operationApplicabilityState{
		byOperationID:              map[string]operationApplicabilityEntry{},
		bySemanticIdentity:         map[string]operationApplicabilityEntry{},
		resourceBindingsByID:       map[string]string{},
		resourceSourceSymbolsByID:  map[string]string{},
		sourceContractOperationIDs: map[string]struct{}{},
		operationKindCounts:        map[string]int{},
	}
	applicabilityIDs := map[string]struct{}{}
	manifestRows := rows.byKind["artifact_manifest"]
	if len(manifestRows) != 1 {
		return state, fmt.Errorf("operation applicability dependency %q has %d artifact_manifest rows, want 1", rows.path, len(manifestRows))
	}
	if count := len(rows.byKind["protocol_assertion_disposition"]); count != 0 {
		return state, fmt.Errorf("operation applicability dependency %q has %d duplicate protocol_assertion_disposition rows; exact protocol semantic rows are the sole disposition authority", rows.path, count)
	}
	manifest := manifestRows[0]
	bindings := []struct {
		field string
		want  string
	}{
		{"canonical_ood_graph_sha256", plan.Manifest.CanonicalOODGraphSHA256},
		{"source_contract_index_sha256", sha256Hex(sourceRows.raw)},
		{"protocol_contract_index_sha256", sha256Hex(protocolRows.raw)},
		{"documentation_claim_derivation_profile_sha256", sha256Hex(derivationRows.raw)},
		{"api_graph_applicability_profile_sha256", sha256Hex(apiRows.raw)},
	}
	for _, binding := range bindings {
		got, ok := semanticString(manifest.data, binding.field)
		if !ok || got != binding.want {
			return state, semanticRowError(rows, manifest, "%s does not equal its exact authority bytes", binding.field)
		}
	}
	evaluationBinding, err := parseApplicabilityProfileBinding(manifest.data, "applicability_profile_binding")
	if err != nil || evaluationBinding != apiState.binding {
		return state, semanticRowError(rows, manifest, "applicability_profile_binding does not equal the API applicability evaluation profile: %v", err)
	}
	manifestEvidence, evidenceOK := semanticStringSlice(manifest.data, "evidence_manifest_sha256s")
	wantEvidence := make(map[string]struct{}, len(plan.Manifest.EvidenceManifestBindings))
	for _, binding := range plan.Manifest.EvidenceManifestBindings {
		wantEvidence[binding.EvidenceManifestSHA256] = struct{}{}
	}
	if !evidenceOK || hasEmptyOrDuplicateSemanticStrings(manifestEvidence) || !stringSetsEqual(stringSliceSet(manifestEvidence), wantEvidence) {
		return state, semanticRowError(rows, manifest, "evidence_manifest_sha256s is not set-equal to the plan evidence authority roster")
	}
	classifierContext, err := newOperationClassifierValidationContext(rows, derivationState, apiState, sourceRows, protocolRows, plan, canonicalOperationClassifierResourceLimits)
	if err != nil {
		return state, err
	}

	for _, row := range rows.byKind["operation_applicability"] {
		entry, err := parseOperationApplicabilityEntry(rows, row, plan, apiState, classifierContext)
		if err != nil {
			return state, err
		}
		if _, duplicate := state.byOperationID[entry.operationID]; duplicate {
			return state, semanticRowError(rows, row, "duplicates operation candidate id %q", entry.operationID)
		}
		if _, duplicate := applicabilityIDs[entry.applicabilityID]; duplicate {
			return state, semanticRowError(rows, row, "duplicates operation applicability identity %q", entry.applicabilityID)
		}
		if _, duplicate := state.bySemanticIdentity[entry.semanticIdentity]; duplicate {
			return state, semanticRowError(rows, row, "duplicates operation semantic identity %q", entry.semanticIdentity)
		}
		for _, access := range entry.resourceAccesses {
			if prior, exists := state.resourceBindingsByID[access.resourceID]; exists && prior != access.resourceSemanticIdentity {
				return state, semanticRowError(rows, row, "resource candidate id %q aliases semantic identities %q and %q", access.resourceID, prior, access.resourceSemanticIdentity)
			}
			if prior, exists := state.resourceSourceSymbolsByID[access.resourceID]; exists && prior != access.resourceSourceSymbol {
				return state, semanticRowError(rows, row, "resource candidate id %q aliases source symbols %q and %q", access.resourceID, prior, access.resourceSourceSymbol)
			}
			state.resourceBindingsByID[access.resourceID] = access.resourceSemanticIdentity
			state.resourceSourceSymbolsByID[access.resourceID] = access.resourceSourceSymbol
		}
		state.byOperationID[entry.operationID] = entry
		applicabilityIDs[entry.applicabilityID] = struct{}{}
		state.bySemanticIdentity[entry.semanticIdentity] = entry
		state.operationKindCounts[entry.operationKind]++
	}
	state.classifierResourceActuals = classifierContext.actuals
	state.classifierResourceLimits = classifierContext.limits

	planOperationIDs := map[string]struct{}{}
	for _, id := range sortedProviderStringMapKeys(plan.Symbols) {
		symbol := plan.Symbols[id]
		if symbol.Role == "operation" {
			planOperationIDs[id] = struct{}{}
		}
	}
	if err := requireExactSet("operation applicability to plan operation symbols", stringMapKeysAsSet(state.byOperationID), planOperationIDs); err != nil {
		return state, err
	}
	coverageProof, err := compileGraphApplicabilityCoverage(plan, apiState, state)
	if err != nil {
		return state, err
	}
	state.coverageProof = coverageProof
	if err := validateOperationApplicabilitySummary(rows, state, plan); err != nil {
		return state, err
	}
	return state, nil
}

func parseOperationApplicabilityEntry(rows dependencySemanticRows, row dependencySemanticRow, plan *parsedPlan, apiState apiGraphApplicabilityState, classifierContext *operationClassifierValidationContext) (operationApplicabilityEntry, error) {
	entry := operationApplicabilityEntry{row: row}
	var ok bool
	var err error
	entry.applicabilityID, ok = semanticString(row.data, "operation_applicability_id")
	if !ok || !canonicalEvidenceMetadataString(entry.applicabilityID, 512) {
		return entry, semanticRowError(rows, row, "operation applicability identity is missing or noncanonical")
	}
	entry.operationID, ok = semanticString(row.data, "operation_candidate_api_symbol_id")
	if !ok {
		return entry, semanticRowError(rows, row, "operation candidate identity is missing")
	}
	entry.semanticIdentity, ok = semanticString(row.data, "operation_semantic_identity")
	if !ok {
		return entry, semanticRowError(rows, row, "operation semantic identity is missing")
	}
	entry.operationKind, ok = semanticString(row.data, "operation_kind")
	if !ok || !canonicalSurfaceKindPattern.MatchString(entry.operationKind) {
		return entry, semanticRowError(rows, row, "operation_kind is not a canonical source-neutral kind")
	}
	entry.sourceSymbol, ok = semanticString(row.data, "source_symbol")
	if !ok || !canonicalEvidenceMetadataString(entry.sourceSymbol, 2048) {
		return entry, semanticRowError(rows, row, "source_symbol is missing or noncanonical")
	}
	entry.sourceIdentity, err = parseSourceOperationIdentity(row.data)
	if err != nil {
		return entry, semanticRowError(rows, row, "source operation identity is incomplete: %v", err)
	}
	canonicalSourceIdentity, err := canonicalSourceOperationIdentity(entry.sourceIdentity)
	if err != nil {
		return entry, semanticRowError(rows, row, "source operation identity is noncanonical: %v", err)
	}
	entry.sourceIdentityCanonical = string(canonicalSourceIdentity)
	entry.subjectTraits, ok = semanticObject(row.data, "subject_traits")
	if !ok || len(entry.subjectTraits) == 0 {
		return entry, semanticRowError(rows, row, "subject_traits is empty")
	}

	readRoster := func(field string) (map[string]struct{}, error) {
		values, present := semanticStringSlice(row.data, field)
		if !present || hasEmptyOrDuplicateSemanticStrings(values) || !strictlyIncreasingStrings(values) {
			return nil, semanticRowError(rows, row, "%s is not a canonical ordered unique identity roster", field)
		}
		return stringSliceSet(values), nil
	}
	if entry.sourcePropertyIDs, err = readRoster("source_operation_property_claim_ids"); err != nil {
		return entry, err
	}
	if entry.actualRelationshipIDs, err = readRoster("actual_relationship_ids"); err != nil {
		return entry, err
	}
	if entry.actualPropertyIDs, err = readRoster("actual_property_claim_ids"); err != nil {
		return entry, err
	}
	if entry.evidenceLocatorIDs, err = readRoster("evidence_locator_ids"); err != nil {
		return entry, err
	}
	if len(entry.evidenceLocatorIDs) == 0 {
		return entry, semanticRowError(rows, row, "evidence_locator_ids is empty")
	}
	if entry.evidenceFactIDs, err = readRoster("evidence_fact_ids"); err != nil {
		return entry, err
	}
	if len(entry.evidenceFactIDs) == 0 {
		return entry, semanticRowError(rows, row, "evidence_fact_ids is empty")
	}
	binding, err := parseApplicabilityProfileBinding(row.data, "applicability_profile_binding")
	if err != nil || binding != apiState.binding {
		return entry, semanticRowError(rows, row, "applicability_profile_binding does not equal the API applicability evaluation profile: %v", err)
	}
	derivation, derivationOK := semanticObject(row.data, "derivation_binding")
	entry.classifierReference, ok = dependencyProfileReferenceFromFields(derivation, "classifier_profile")
	exactInputLocators, locatorOK := semanticStringSlice(derivation, "exact_input_locator_ids")
	exactInputFacts, factOK := semanticStringSlice(derivation, "exact_input_fact_ids")
	sourceBytes, sourceBytesOK := semanticBool(row.data, "source_bytes_present")
	if !derivationOK || !ok || !locatorOK || hasEmptyOrDuplicateSemanticStrings(exactInputLocators) || !strictlyIncreasingStrings(exactInputLocators) || !stringSetsEqual(stringSliceSet(exactInputLocators), entry.evidenceLocatorIDs) || !factOK || hasEmptyOrDuplicateSemanticStrings(exactInputFacts) || !strictlyIncreasingStrings(exactInputFacts) || !stringSetsEqual(stringSliceSet(exactInputFacts), entry.evidenceFactIDs) || !sourceBytesOK || sourceBytes {
		return entry, semanticRowError(rows, row, "derivation binding, exact locator roster, or body-free posture is invalid")
	}
	accessRows, accessesOK := semanticObjectSlice(row.data, "resource_accesses")
	if !accessesOK || len(accessRows) == 0 {
		return entry, semanticRowError(rows, row, "resource_accesses is not a nonempty typed roster")
	}
	if err := reserveOperationClassifierResource(&classifierContext.actuals.entryAccesses, int64(len(accessRows)), classifierContext.limits.entryAccesses, "entry-access count"); err != nil {
		return entry, semanticRowError(rows, row, "%v", err)
	}
	seenAccessIDs := map[string]struct{}{}
	seenAccessFacts := map[string]struct{}{}
	previousAccessID := ""
	accessLocatorUnion := map[string]struct{}{}
	accessFactUnion := map[string]struct{}{}
	for index, accessRow := range accessRows {
		access, accessErr := parseOperationResourceAccess(accessRow, entry.operationID)
		if accessErr != nil {
			return entry, semanticRowError(rows, row, "resource_accesses[%d]: %v", index, accessErr)
		}
		if err := reserveOperationClassifierResource(&classifierContext.actuals.entryEvidenceRefs, int64(len(access.evidenceLocatorIDs)), classifierContext.limits.entryEvidenceRefs, "entry-evidence reference count"); err != nil {
			return entry, semanticRowError(rows, row, "%v", err)
		}
		if err := reserveOperationClassifierResource(&classifierContext.actuals.entryEvidenceRefs, int64(len(access.evidenceFactIDs)), classifierContext.limits.entryEvidenceRefs, "entry-evidence reference count"); err != nil {
			return entry, semanticRowError(rows, row, "%v", err)
		}
		if previousAccessID != "" && access.id <= previousAccessID {
			return entry, semanticRowError(rows, row, "resource_accesses is not sorted by its content-derived resource_access_id")
		}
		previousAccessID = access.id
		if _, duplicate := seenAccessIDs[access.id]; duplicate {
			return entry, semanticRowError(rows, row, "resource_accesses duplicates resource_access_id %q", access.id)
		}
		factIdentity := semanticIdentity(access.resourceSourceSymbol, access.relationshipLabel)
		if _, duplicate := seenAccessFacts[factIdentity]; duplicate {
			return entry, semanticRowError(rows, row, "resource_accesses duplicates source resource %q relationship %q", access.resourceSourceSymbol, access.relationshipLabel)
		}
		seenAccessIDs[access.id] = struct{}{}
		seenAccessFacts[factIdentity] = struct{}{}
		for locatorID := range access.evidenceLocatorIDs {
			accessLocatorUnion[locatorID] = struct{}{}
		}
		for factID := range access.evidenceFactIDs {
			accessFactUnion[factID] = struct{}{}
		}
		entry.resourceAccesses = append(entry.resourceAccesses, access)
	}
	if !stringSetsEqual(accessLocatorUnion, entry.evidenceLocatorIDs) {
		return entry, semanticRowError(rows, row, "resource access locator union does not equal the exact operation locator roster")
	}
	if !stringSetsEqual(accessFactUnion, entry.evidenceFactIDs) {
		return entry, semanticRowError(rows, row, "resource access fact union does not equal the exact operation fact roster")
	}
	applicabilityIdentityParts := []string{entry.operationID, entry.semanticIdentity, entry.classifierReference.id, entry.classifierReference.version, entry.classifierReference.digest}
	for _, access := range entry.resourceAccesses {
		applicabilityIdentityParts = append(applicabilityIdentityParts, access.id)
	}
	if entry.applicabilityID != stableID("opapp", lengthPrefixedIdentityKey(applicabilityIdentityParts...)) {
		return entry, semanticRowError(rows, row, "operation_applicability_id is not content-derived from the operation, classifier coordinate, and exact ordered resource-access roster")
	}
	operation, exists := plan.Symbols[entry.operationID]
	if !exists || operation.Role != "operation" || operation.SemanticKey != entry.semanticIdentity {
		return entry, semanticRowError(rows, row, "operation identity does not equal its plan operation symbol")
	}
	for _, access := range entry.resourceAccesses {
		resource, exists := plan.Symbols[access.resourceID]
		if !exists || resource.Role != "resource" || resource.SemanticKey != access.resourceSemanticIdentity {
			return entry, semanticRowError(rows, row, "source resource binding %q does not equal its plan resource symbol", access.id)
		}
		rule, exists := apiState.relationshipByLabel[access.relationshipLabel]
		if !exists || rule.sourceRole != "operation" || rule.targetRole != "resource" || rule.subjectEndpoint != "source" {
			return entry, semanticRowError(rows, row, "resource access %q relationship label %q has no exact operation-to-resource applicability rule", access.id, access.relationshipLabel)
		}
	}
	incidentRelationships := classifierContext.incidentRelationshipIDsBySymbol[entry.operationID]
	if incidentRelationships == nil {
		incidentRelationships = map[string]struct{}{}
	}
	if err := requireExactSet("operation "+entry.operationID+" incident relationship roster", entry.actualRelationshipIDs, incidentRelationships); err != nil {
		return entry, semanticRowError(rows, row, "%v", err)
	}
	operationProperties := classifierContext.propertyIDsByOperation[entry.operationID]
	if operationProperties == nil {
		operationProperties = map[string]struct{}{}
	}
	if err := requireExactSet("operation "+entry.operationID+" property roster", entry.actualPropertyIDs, operationProperties); err != nil {
		return entry, semanticRowError(rows, row, "%v", err)
	}
	if !setContainsAll(entry.actualPropertyIDs, entry.sourcePropertyIDs) {
		return entry, semanticRowError(rows, row, "source operation property roster is not a subset of actual operation properties")
	}
	if err := requireExactSet("operation "+entry.operationID+" locator roster", entry.evidenceLocatorIDs, stringSliceSet(operation.EvidenceLocatorIDs)); err != nil {
		return entry, semanticRowError(rows, row, "%v", err)
	}
	if err := validateOperationClassifierOutputWithContext(entry, classifierContext); err != nil {
		return entry, semanticRowError(rows, row, "%v", err)
	}
	return entry, nil
}

func validateOperationClassifierProgramRelationshipLabelClosure(program operationClassifierProgram, apiState apiGraphApplicabilityState) error {
	for _, label := range sortedProviderStringMapKeys(program.relationshipLabels) {
		rule, exists := apiState.relationshipByLabel[label]
		if !exists || rule.sourceRole != "operation" || rule.targetRole != "resource" || rule.subjectEndpoint != "source" {
			return fmt.Errorf("operation classifier relationship-label output %q has no exact operation-to-resource API applicability rule", label)
		}
	}
	return nil
}

func parseOperationResourceAccess(object map[string]interface{}, operationID string) (operationResourceAccess, error) {
	result := operationResourceAccess{}
	var ok bool
	result.id, ok = semanticString(object, "resource_access_id")
	if !ok || !canonicalEvidenceMetadataString(result.id, 512) {
		return result, fmt.Errorf("resource_access_id is missing or noncanonical")
	}
	result.resourceSourceSymbol, ok = semanticString(object, "source_symbol")
	if !ok || !canonicalEvidenceMetadataString(result.resourceSourceSymbol, 2048) {
		return result, fmt.Errorf("source_symbol is missing or noncanonical")
	}
	result.resourceID, ok = semanticString(object, "resource_candidate_api_symbol_id")
	if !ok {
		return result, fmt.Errorf("resource_candidate_api_symbol_id is missing")
	}
	result.resourceSemanticIdentity, ok = semanticString(object, "resource_semantic_identity")
	if !ok {
		return result, fmt.Errorf("resource_semantic_identity is missing")
	}
	result.relationshipLabel, ok = semanticString(object, "relationship_label")
	if !ok || !canonicalSurfaceKindPattern.MatchString(result.relationshipLabel) {
		return result, fmt.Errorf("relationship_label is missing or noncanonical")
	}
	result.accessSemantics, ok = semanticString(object, "access_semantics")
	if !ok || !canonicalSurfaceKindPattern.MatchString(result.accessSemantics) {
		return result, fmt.Errorf("access_semantics is missing or noncanonical")
	}
	locators, locatorsOK := semanticStringSlice(object, "evidence_locator_ids")
	if !locatorsOK || len(locators) == 0 || hasEmptyOrDuplicateSemanticStrings(locators) || !strictlyIncreasingStrings(locators) {
		return result, fmt.Errorf("evidence_locator_ids is not a nonempty canonical roster")
	}
	result.evidenceLocatorIDs = stringSliceSet(locators)
	facts, factsOK := semanticStringSlice(object, "evidence_fact_ids")
	if !factsOK || len(facts) == 0 || hasEmptyOrDuplicateSemanticStrings(facts) || !strictlyIncreasingStrings(facts) {
		return result, fmt.Errorf("evidence_fact_ids is not a nonempty canonical roster")
	}
	result.evidenceFactIDs = stringSliceSet(facts)
	var err error
	result.classifierInputBinding, err = parseOperationClassifierInputBinding(object)
	if err != nil {
		return result, err
	}
	identityParts := []string{
		operationID,
		result.resourceSourceSymbol,
		result.resourceID,
		result.resourceSemanticIdentity,
		result.relationshipLabel,
		result.accessSemantics,
		result.classifierInputBinding.artifactRole,
		result.classifierInputBinding.artifactSHA256,
		result.classifierInputBinding.rowKind,
		result.classifierInputBinding.rowIdentity,
		result.classifierInputBinding.rowSHA256,
		result.classifierInputBinding.factLocatorKind,
		fmt.Sprintf("%d", result.classifierInputBinding.factOrdinal),
	}
	identityParts = append(identityParts, locators...)
	identityParts = append(identityParts, facts...)
	if result.id != stableID("opaccess", lengthPrefixedIdentityKey(identityParts...)) {
		return result, fmt.Errorf("resource_access_id is not content-derived from the exact access and predecessor binding")
	}
	return result, nil
}

type graphApplicabilitySubject struct {
	kind              string
	id                string
	relationshipLabel string
}

func parseOperationClassifierInputBinding(derivation map[string]interface{}) (operationClassifierInputBinding, error) {
	result := operationClassifierInputBinding{factOrdinal: -1}
	binding, ok := semanticObject(derivation, "predecessor_fact_binding")
	if !ok {
		return result, fmt.Errorf("predecessor_fact_binding is missing")
	}
	result.artifactRole, ok = semanticString(binding, "artifact_role")
	if !ok {
		return result, fmt.Errorf("predecessor artifact role is missing")
	}
	result.artifactSHA256, ok = semanticString(binding, "artifact_sha256")
	if !ok || !isLowerSHA256(result.artifactSHA256) {
		return result, fmt.Errorf("predecessor artifact digest is missing or noncanonical")
	}
	result.rowKind, ok = semanticString(binding, "row_kind")
	if !ok {
		return result, fmt.Errorf("predecessor row kind is missing")
	}
	result.rowIdentity, ok = semanticString(binding, "row_identity")
	if !ok || !canonicalEvidenceMetadataString(result.rowIdentity, 2048) {
		return result, fmt.Errorf("predecessor row identity is missing or noncanonical")
	}
	result.rowSHA256, ok = semanticString(binding, "row_sha256")
	if !ok || !isLowerSHA256(result.rowSHA256) {
		return result, fmt.Errorf("predecessor row digest is missing or noncanonical")
	}
	locator, locatorOK := semanticObject(binding, "fact_locator")
	result.factLocatorKind, ok = semanticString(locator, "locator_kind")
	if !locatorOK || !ok {
		return result, fmt.Errorf("predecessor fact locator is missing")
	}
	if (result.artifactRole != operationClassifierSourceArtifactRole || result.rowKind != "api_operation") && (result.artifactRole != operationClassifierProtocolArtifactRole || result.rowKind != "operation_classifier_fact") {
		return result, fmt.Errorf("predecessor artifact role/row kind %q/%q is outside the closed acyclic operation-classifier inputs", result.artifactRole, result.rowKind)
	}
	switch result.artifactRole {
	case operationClassifierSourceArtifactRole:
		result.factOrdinal, ok = semanticInt64(locator, "ordinal")
		if result.factLocatorKind != "resource_access_ordinal" || !ok || result.factOrdinal < 0 {
			return result, fmt.Errorf("source predecessor fact locator must be a nonnegative resource_access_ordinal")
		}
	case operationClassifierProtocolArtifactRole:
		if result.factLocatorKind != "whole_row" || len(locator) != 1 {
			return result, fmt.Errorf("protocol predecessor fact locator must select the exact whole row")
		}
	}
	return result, nil
}

func validateOperationClassifierOutput(entry operationApplicabilityEntry, derivationState documentationClaimDerivationState, sourceRows, protocolRows dependencySemanticRows) error {
	profile, exists := derivationState.classifiers[dependencyProfileReferenceKey(entry.classifierReference)]
	if !exists {
		return fmt.Errorf("operation applicability classifier coordinate %s/%s/%s is absent from the exact documentation-derivation profile", entry.classifierReference.id, entry.classifierReference.version, entry.classifierReference.digest)
	}
	program, err := parseOperationClassifierProgram(profile, entry.classifierReference)
	if err != nil {
		return fmt.Errorf("operation applicability classifier coordinate %s/%s/%s: %w", entry.classifierReference.id, entry.classifierReference.version, entry.classifierReference.digest, err)
	}
	context, err := newOperationClassifierPredecessorContext(sourceRows, protocolRows, canonicalOperationClassifierResourceLimits)
	if err != nil {
		return err
	}
	context.programsByReference = map[string]operationClassifierProgram{dependencyProfileReferenceKey(entry.classifierReference): program}
	if entry.sourceIdentityCanonical == "" && entry.sourceIdentity != nil {
		canonical, canonicalErr := canonicalSourceOperationIdentity(entry.sourceIdentity)
		if canonicalErr != nil {
			return canonicalErr
		}
		entry.sourceIdentityCanonical = string(canonical)
	}
	return validateOperationClassifierOutputWithContext(entry, context)
}

func validateOperationClassifierOutputWithContext(entry operationApplicabilityEntry, context *operationClassifierValidationContext) error {
	program, exists := context.programsByReference[dependencyProfileReferenceKey(entry.classifierReference)]
	if !exists {
		return fmt.Errorf("operation applicability classifier coordinate %s/%s/%s is absent from the compiled classifier cache", entry.classifierReference.id, entry.classifierReference.version, entry.classifierReference.digest)
	}
	facts, err := resolveOperationClassifierFacts(entry, context)
	if err != nil {
		return err
	}
	for index, fact := range facts {
		contract, exists := program.factContracts[fact.kind]
		binding := entry.resourceAccesses[index].classifierInputBinding
		if !exists || contract.artifactRole != binding.artifactRole || contract.rowKind != binding.rowKind {
			return fmt.Errorf("operation classifier predecessor fact %q is absent from or disagrees with the exact program input contract", fact.kind)
		}
	}
	output, accessOutputs, err := executeOperationClassifierProgram(program, facts)
	if err != nil {
		return err
	}
	if len(accessOutputs) != len(entry.resourceAccesses) {
		return fmt.Errorf("operation classifier reexecution produced %d access outputs for %d exact resource accesses", len(accessOutputs), len(entry.resourceAccesses))
	}
	for index, accessOutput := range accessOutputs {
		access := entry.resourceAccesses[index]
		if access.relationshipLabel != accessOutput.relationshipLabel || access.accessSemantics != accessOutput.accessSemantics {
			return fmt.Errorf("operation applicability resource access %q asserted relationship/access output %q/%q but generic classifier reexecution produced %q/%q", access.id, access.relationshipLabel, access.accessSemantics, accessOutput.relationshipLabel, accessOutput.accessSemantics)
		}
	}
	if entry.operationKind != output.operationKind || !reflect.DeepEqual(entry.subjectTraits, output.subjectTraits) {
		return fmt.Errorf("operation applicability asserted output does not equal generic classifier reexecution: operation_kind=%q/%q subject_traits_equal=%t", entry.operationKind, output.operationKind, reflect.DeepEqual(entry.subjectTraits, output.subjectTraits))
	}
	return nil
}

func parseOperationClassifierProgram(profile documentationClassifierProfile, reference dependencyProfileReference) (operationClassifierProgram, error) {
	result := operationClassifierProgram{
		factContracts:         map[string]operationClassifierFactContract{},
		relationshipLabels:    map[string]struct{}{},
		subjectTraits:         map[string]struct{}{},
		accessRuleByPredicate: map[string]operationClassifierAccessOutput{},
		aggregateRuleByTraits: map[string]string{},
	}
	canonicalProgram, err := canonicalOperationClassifierProgram(profile.program)
	if err != nil {
		return result, err
	}
	if len(canonicalProgram) == 0 || int64(len(canonicalProgram)) > maxOperationClassifierProgramBytes || sha256Hex(canonicalProgram) != reference.digest {
		return result, fmt.Errorf("classifier_profile_sha256 does not equal bounded RFC-canonical program bytes")
	}
	result.canonicalByteCount = int64(len(canonicalProgram))
	if err := requireExactSet("operation classifier program fields", stringMapKeysAsSet(profile.program), map[string]struct{}{
		"program_kind": {}, "input_claim_kind": {}, "match_semantics": {}, "operation_match_semantics": {},
		"closed_predicate_kinds": {}, "closed_input_fact_contracts": {}, "closed_operation_kind_outputs": {},
		"closed_access_semantics_outputs": {}, "closed_relationship_label_outputs": {}, "closed_subject_trait_names": {},
		"subject_trait_aggregation": {}, "ordered_access_rules": {}, "ordered_operation_rules": {},
	}); err != nil {
		return result, err
	}
	programKind, kindOK := semanticString(profile.program, "program_kind")
	inputClaimKind, claimKindOK := semanticString(profile.program, "input_claim_kind")
	matchSemantics, matchOK := semanticString(profile.program, "match_semantics")
	operationMatchSemantics, operationMatchOK := semanticString(profile.program, "operation_match_semantics")
	predicateKinds, predicatesOK := semanticStringSlice(profile.program, "closed_predicate_kinds")
	if !kindOK || programKind != operationClassifierProgramKind || !claimKindOK || inputClaimKind != profile.claimKind || !isCanonicalValidationProfileIdentity(inputClaimKind) || !matchOK || matchSemantics != "exactly_one_rule_required" || !operationMatchOK || operationMatchSemantics != "exactly_one_rule_required" || !predicatesOK || !strictlyIncreasingStrings(predicateKinds) || !equalStringSet(predicateKinds, []string{"exact_string_equals", "exact_subject_traits_equals"}) {
		return result, fmt.Errorf("program_kind, hashed input_claim_kind, deterministic match semantics, or closed predicate vocabulary is invalid")
	}
	operationKinds, operationKindsOK := semanticStringSlice(profile.program, "closed_operation_kind_outputs")
	accessSemantics, accessOK := semanticStringSlice(profile.program, "closed_access_semantics_outputs")
	relationshipLabels, labelsOK := semanticStringSlice(profile.program, "closed_relationship_label_outputs")
	subjectTraits, traitsOK := semanticStringSlice(profile.program, "closed_subject_trait_names")
	if !operationKindsOK || !canonicalOperationClassifierVocabulary(operationKinds, maxOperationClassifierVocabularyMembers) || !accessOK || !canonicalOperationClassifierVocabulary(accessSemantics, maxOperationClassifierVocabularyMembers) || !labelsOK || !canonicalOperationClassifierVocabulary(relationshipLabels, maxOperationClassifierVocabularyMembers) || !traitsOK || !canonicalOperationClassifierVocabulary(subjectTraits, maxOperationClassifierSubjectTraits) {
		return result, fmt.Errorf("closed operation/access/relationship/trait output vocabularies are incomplete or noncanonical")
	}
	operationKindSet := stringSliceSet(operationKinds)
	accessSemanticsSet := stringSliceSet(accessSemantics)
	result.relationshipLabels = stringSliceSet(relationshipLabels)
	result.subjectTraits = stringSliceSet(subjectTraits)
	result.subjectTraitOrder = append([]string(nil), subjectTraits...)
	if !stringSetsEqual(accessSemanticsSet, profile.semanticClasses) || !stringSetsEqual(map[string]struct{}{programKind: {}}, profile.computationPaths) {
		return result, fmt.Errorf("program access outputs or computation path do not equal the classifier profile closed unions")
	}

	contracts, contractsOK := semanticObjectSlice(profile.program, "closed_input_fact_contracts")
	if !contractsOK || len(contracts) == 0 || len(contracts) > 2 {
		return result, fmt.Errorf("closed_input_fact_contracts is outside the nonempty two-kind acyclic input bound")
	}
	artifactRoles := map[string]struct{}{}
	for index, object := range contracts {
		if err := requireExactSet("operation classifier input fact contract fields", stringMapKeysAsSet(object), map[string]struct{}{
			"ordinal": {}, "fact_kind": {}, "artifact_role": {}, "row_kind": {}, "match_fields": {},
		}); err != nil {
			return result, fmt.Errorf("closed_input_fact_contracts[%d]: %w", index, err)
		}
		ordinal, ordinalOK := semanticInt64(object, "ordinal")
		factKind, factOK := semanticString(object, "fact_kind")
		artifactRole, roleOK := semanticString(object, "artifact_role")
		rowKind, rowOK := semanticString(object, "row_kind")
		matchFields, fieldsOK := semanticStringSlice(object, "match_fields")
		if !ordinalOK || ordinal != int64(index) || !factOK || !roleOK || !rowOK || !fieldsOK || len(matchFields) == 0 || hasEmptyOrDuplicateSemanticStrings(matchFields) || !strictlyIncreasingStrings(matchFields) {
			return result, fmt.Errorf("closed_input_fact_contracts[%d] is incomplete or noncanonical", index)
		}
		if _, duplicate := result.factContracts[factKind]; duplicate {
			return result, fmt.Errorf("closed_input_fact_contracts duplicates fact_kind %q", factKind)
		}
		var expectedRole, expectedRow string
		var expectedFields []string
		switch factKind {
		case operationClassifierSourceFactKind:
			expectedRole, expectedRow, expectedFields = operationClassifierSourceArtifactRole, "api_operation", []string{"relationship_label"}
		case operationClassifierProtocolFactKind:
			expectedRole, expectedRow, expectedFields = operationClassifierProtocolArtifactRole, "operation_classifier_fact", []string{"semantic_class"}
		default:
			return result, fmt.Errorf("closed_input_fact_contracts names unsupported acyclic fact_kind %q", factKind)
		}
		if artifactRole != expectedRole || rowKind != expectedRow || !equalStringSet(matchFields, expectedFields) {
			return result, fmt.Errorf("fact contract %q does not equal its closed predecessor role/row/field shape", factKind)
		}
		result.factContracts[factKind] = operationClassifierFactContract{artifactRole: artifactRole, rowKind: rowKind, matchFields: stringSliceSet(matchFields), matchField: matchFields[0]}
		artifactRoles[artifactRole] = struct{}{}
	}
	if !stringSetsEqual(artifactRoles, profile.carriers) {
		return result, fmt.Errorf("predecessor artifact roles do not equal authoritative_carrier_union")
	}

	aggregation, aggregationOK := semanticObject(profile.program, "subject_trait_aggregation")
	if aggregationOK {
		if err := requireExactSet("operation classifier subject_trait_aggregation fields", stringMapKeysAsSet(aggregation), map[string]struct{}{"aggregation_kind": {}, "empty_access_roster_allowed": {}}); err != nil {
			return result, err
		}
	}
	var aggregationKindOK bool
	result.traitAggregationKind, aggregationKindOK = semanticString(aggregation, "aggregation_kind")
	emptyAllowed, emptyAllowedOK := semanticBool(aggregation, "empty_access_roster_allowed")
	if !aggregationOK || !aggregationKindOK || result.traitAggregationKind != "boolean_or_across_accesses" || !emptyAllowedOK || emptyAllowed || len(aggregation) != 2 {
		return result, fmt.Errorf("subject_trait_aggregation must be closed boolean_or_across_accesses with an empty-roster refusal")
	}

	rules, rulesOK := semanticObjectSlice(profile.program, "ordered_access_rules")
	if !rulesOK || len(rules) == 0 || int64(len(rules)) > maxOperationClassifierAccessRules {
		return result, fmt.Errorf("ordered_access_rules is outside the nonempty bounded rule roster")
	}
	seenAccessPredicates := map[string]struct{}{}
	usedFactKinds := map[string]struct{}{}
	actualAccessSemantics := map[string]struct{}{}
	actualRelationshipLabels := map[string]struct{}{}
	for index, object := range rules {
		if err := requireExactSet("operation classifier access rule fields", stringMapKeysAsSet(object), map[string]struct{}{"ordinal": {}, "input_fact_kind": {}, "predicate": {}, "output": {}}); err != nil {
			return result, fmt.Errorf("ordered_access_rules[%d]: %w", index, err)
		}
		ordinal, ordinalOK := semanticInt64(object, "ordinal")
		factKind, factOK := semanticString(object, "input_fact_kind")
		predicate, predicateOK := semanticObject(object, "predicate")
		predicateKind, predicateKindOK := semanticString(predicate, "predicate_kind")
		matchField, fieldOK := semanticString(predicate, "input_field")
		matchValue, valueOK := semanticString(predicate, "value")
		outputObject, outputOK := semanticObject(object, "output")
		if predicateOK {
			if err := requireExactSet("operation classifier access predicate fields", stringMapKeysAsSet(predicate), map[string]struct{}{"predicate_kind": {}, "input_field": {}, "value": {}}); err != nil {
				return result, fmt.Errorf("ordered_access_rules[%d]: %w", index, err)
			}
		}
		if outputOK {
			if err := requireExactSet("operation classifier access output fields", stringMapKeysAsSet(outputObject), map[string]struct{}{"relationship_label": {}, "access_semantics": {}, "subject_trait_contributions": {}}); err != nil {
				return result, fmt.Errorf("ordered_access_rules[%d]: %w", index, err)
			}
		}
		relationshipLabel, labelOK := semanticString(outputObject, "relationship_label")
		access, accessValueOK := semanticString(outputObject, "access_semantics")
		traits, traitsValueOK := semanticObject(outputObject, "subject_trait_contributions")
		contract, contractOK := result.factContracts[factKind]
		if !ordinalOK || ordinal != int64(index) || !factOK || !predicateOK || !predicateKindOK || predicateKind != "exact_string_equals" || !fieldOK || !valueOK || !canonicalSurfaceKindPattern.MatchString(matchValue) || !outputOK || !labelOK || !accessValueOK || !traitsValueOK || !contractOK {
			return result, fmt.Errorf("ordered_access_rules[%d] is incomplete or outside the closed classifier vocabulary", index)
		}
		if _, allowed := contract.matchFields[matchField]; !allowed {
			return result, fmt.Errorf("ordered_access_rules[%d] input_field %q is absent from fact contract %q", index, matchField, factKind)
		}
		if _, allowed := result.relationshipLabels[relationshipLabel]; !allowed {
			return result, fmt.Errorf("ordered_access_rules[%d] relationship_label %q is outside the closed output union", index, relationshipLabel)
		}
		if _, allowed := accessSemanticsSet[access]; !allowed {
			return result, fmt.Errorf("ordered_access_rules[%d] access_semantics %q is outside the closed output union", index, access)
		}
		if err := requireExactSet("operation classifier subject_trait_contributions", stringMapKeysAsSet(traits), result.subjectTraits); err != nil {
			return result, fmt.Errorf("ordered_access_rules[%d]: %w", index, err)
		}
		traitContributions := make(map[string]bool, len(traits))
		for _, trait := range sortedProviderStringMapKeys(traits) {
			value := traits[trait]
			boolean, ok := value.(bool)
			if !ok {
				return result, fmt.Errorf("ordered_access_rules[%d] subject trait contribution %q is not boolean", index, trait)
			}
			traitContributions[trait] = boolean
		}
		predicateIdentity := lengthPrefixedIdentityKey(factKind, matchField, matchValue)
		if _, duplicate := seenAccessPredicates[predicateIdentity]; duplicate {
			return result, fmt.Errorf("ordered_access_rules duplicates exact predecessor predicate %s/%s/%s", factKind, matchField, matchValue)
		}
		seenAccessPredicates[predicateIdentity] = struct{}{}
		usedFactKinds[factKind] = struct{}{}
		actualAccessSemantics[access] = struct{}{}
		actualRelationshipLabels[relationshipLabel] = struct{}{}
		if factKind == operationClassifierSourceFactKind && relationshipLabel != matchValue {
			return result, fmt.Errorf("ordered_access_rules[%d] source relationship output %q does not preserve exact predecessor relationship_label %q", index, relationshipLabel, matchValue)
		}
		output := operationClassifierAccessOutput{relationshipLabel: relationshipLabel, accessSemantics: access, subjectTraitContributions: traitContributions}
		result.accessRuleByPredicate[predicateIdentity] = output
	}
	if err := requireExactSet("operation classifier executable input fact kinds", usedFactKinds, stringMapKeysAsSet(result.factContracts)); err != nil {
		return result, err
	}
	if err := requireExactSet("operation classifier executable access outputs", actualAccessSemantics, accessSemanticsSet); err != nil {
		return result, err
	}
	if err := requireExactSet("operation classifier executable relationship outputs", actualRelationshipLabels, result.relationshipLabels); err != nil {
		return result, err
	}

	aggregateRules, aggregateRulesOK := semanticObjectSlice(profile.program, "ordered_operation_rules")
	if !aggregateRulesOK || len(aggregateRules) == 0 || int64(len(aggregateRules)) > maxOperationClassifierAggregateRules {
		return result, fmt.Errorf("ordered_operation_rules is outside the nonempty bounded rule roster")
	}
	seenTraitPredicates := map[string]struct{}{}
	actualOperationKinds := map[string]struct{}{}
	for index, object := range aggregateRules {
		if err := requireExactSet("operation classifier aggregate rule fields", stringMapKeysAsSet(object), map[string]struct{}{"ordinal": {}, "predicate": {}, "output": {}}); err != nil {
			return result, fmt.Errorf("ordered_operation_rules[%d]: %w", index, err)
		}
		ordinal, ordinalOK := semanticInt64(object, "ordinal")
		predicate, predicateOK := semanticObject(object, "predicate")
		predicateKind, predicateKindOK := semanticString(predicate, "predicate_kind")
		traits, traitsOK := semanticObject(predicate, "subject_traits")
		output, outputOK := semanticObject(object, "output")
		if predicateOK {
			if err := requireExactSet("operation classifier aggregate predicate fields", stringMapKeysAsSet(predicate), map[string]struct{}{"predicate_kind": {}, "subject_traits": {}}); err != nil {
				return result, fmt.Errorf("ordered_operation_rules[%d]: %w", index, err)
			}
		}
		if outputOK {
			if err := requireExactSet("operation classifier aggregate output fields", stringMapKeysAsSet(output), map[string]struct{}{"operation_kind": {}}); err != nil {
				return result, fmt.Errorf("ordered_operation_rules[%d]: %w", index, err)
			}
		}
		operationKind, operationKindOK := semanticString(output, "operation_kind")
		if !ordinalOK || ordinal != int64(index) || !predicateOK || !predicateKindOK || predicateKind != "exact_subject_traits_equals" || !traitsOK || !outputOK || !operationKindOK {
			return result, fmt.Errorf("ordered_operation_rules[%d] is incomplete or outside the closed classifier vocabulary", index)
		}
		if err := requireExactSet("operation classifier aggregate subject_traits", stringMapKeysAsSet(traits), result.subjectTraits); err != nil {
			return result, fmt.Errorf("ordered_operation_rules[%d]: %w", index, err)
		}
		for _, trait := range sortedProviderStringMapKeys(traits) {
			value := traits[trait]
			if _, ok := value.(bool); !ok {
				return result, fmt.Errorf("ordered_operation_rules[%d] subject trait %q is not boolean", index, trait)
			}
		}
		if _, allowed := operationKindSet[operationKind]; !allowed {
			return result, fmt.Errorf("ordered_operation_rules[%d] operation_kind %q is outside the closed output union", index, operationKind)
		}
		canonicalTraits, err := canonicalOperationClassifierProgram(traits)
		if err != nil {
			return result, fmt.Errorf("ordered_operation_rules[%d] subject traits: %w", index, err)
		}
		if _, duplicate := seenTraitPredicates[string(canonicalTraits)]; duplicate {
			return result, fmt.Errorf("ordered_operation_rules duplicates an exact subject-trait predicate")
		}
		seenTraitPredicates[string(canonicalTraits)] = struct{}{}
		traitKey, err := operationClassifierTraitVectorKey(traits, result.subjectTraitOrder)
		if err != nil {
			return result, fmt.Errorf("ordered_operation_rules[%d]: %w", index, err)
		}
		result.aggregateRuleByTraits[traitKey] = operationKind
		actualOperationKinds[operationKind] = struct{}{}
	}
	if err := requireExactSet("operation classifier executable operation-kind outputs", actualOperationKinds, operationKindSet); err != nil {
		return result, err
	}
	return result, nil
}

func canonicalOperationClassifierVocabulary(values []string, maximum int64) bool {
	if len(values) == 0 || int64(len(values)) > maximum || hasEmptyOrDuplicateSemanticStrings(values) || !strictlyIncreasingStrings(values) {
		return false
	}
	for _, value := range values {
		if !canonicalSurfaceKindPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func canonicalOperationClassifierProgram(program map[string]interface{}) ([]byte, error) {
	raw, err := json.Marshal(program)
	if err != nil {
		return nil, fmt.Errorf("marshal classifier program: %w", err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize classifier program: %w", err)
	}
	return canonical, nil
}

func operationClassifierTraitVectorKey(traits map[string]interface{}, orderedNames []string) (string, error) {
	if len(traits) != len(orderedNames) {
		return "", fmt.Errorf("operation classifier trait vector has %d fields, want %d", len(traits), len(orderedNames))
	}
	key := make([]byte, len(orderedNames))
	for index, name := range orderedNames {
		value, exists := traits[name]
		boolean, booleanOK := value.(bool)
		if !exists || !booleanOK {
			return "", fmt.Errorf("operation classifier trait vector field %q is missing or non-boolean", name)
		}
		if boolean {
			key[index] = '1'
		} else {
			key[index] = '0'
		}
	}
	return string(key), nil
}

func resolveOperationClassifierFacts(entry operationApplicabilityEntry, context *operationClassifierValidationContext) ([]operationClassifierFact, error) {
	if len(entry.resourceAccesses) == 0 {
		return nil, fmt.Errorf("operation classifier has an empty resource-access predecessor roster")
	}
	if entry.sourceIdentityCanonical == "" {
		canonical, err := canonicalSourceOperationIdentity(entry.sourceIdentity)
		if err != nil {
			return nil, err
		}
		entry.sourceIdentityCanonical = string(canonical)
	}
	facts := make([]operationClassifierFact, 0, len(entry.resourceAccesses))
	for _, access := range entry.resourceAccesses {
		binding := access.classifierInputBinding
		var fact operationClassifierFact
		var err error
		switch binding.artifactRole {
		case operationClassifierSourceArtifactRole:
			if binding.artifactSHA256 != context.sourceArtifactSHA256 || binding.rowKind != "api_operation" {
				return nil, fmt.Errorf("source operation predecessor binding does not equal exact source-contract artifact bytes")
			}
			fact, err = resolveSourceOperationClassifierFact(entry, access, context)
		case operationClassifierProtocolArtifactRole:
			if binding.artifactSHA256 != context.protocolArtifactSHA256 || binding.rowKind != "operation_classifier_fact" {
				return nil, fmt.Errorf("protocol operation predecessor binding does not equal exact protocol-contract artifact bytes")
			}
			fact, err = resolveProtocolOperationClassifierFact(entry, access, context)
		default:
			return nil, fmt.Errorf("operation classifier predecessor artifact role %q is unsupported", binding.artifactRole)
		}
		if err != nil {
			return nil, err
		}
		facts = append(facts, fact)
	}
	if err := validateOperationClassifierPredecessorCompleteness(entry, facts, context); err != nil {
		return nil, err
	}
	return facts, nil
}

func resolveSourceOperationClassifierFact(entry operationApplicabilityEntry, access operationResourceAccess, context *operationClassifierValidationContext) (operationClassifierFact, error) {
	binding := access.classifierInputBinding
	matches := context.sourceBySemanticIdentityAndRowSHA[lengthPrefixedIdentityKey(binding.rowIdentity, binding.rowSHA256)]
	if len(matches) != 1 {
		return operationClassifierFact{}, fmt.Errorf("source operation predecessor identity %q resolves %d rows, want 1", binding.rowIdentity, len(matches))
	}
	predecessor := matches[0]
	if predecessor.rowSHA256 != binding.rowSHA256 {
		return operationClassifierFact{}, fmt.Errorf("source operation predecessor row digest does not equal exact bound bytes")
	}
	if entry.sourceIdentityCanonical != predecessor.sourceIdentityCanonical || predecessor.sourceSymbol != entry.sourceSymbol || binding.rowIdentity != entry.semanticIdentity || predecessor.semanticIdentity != binding.rowIdentity {
		return operationClassifierFact{}, fmt.Errorf("source operation predecessor identity does not equal the operation applicability source identity")
	}
	if binding.factLocatorKind != "resource_access_ordinal" || binding.factOrdinal < 0 || binding.factOrdinal >= int64(len(predecessor.accesses)) {
		return operationClassifierFact{}, fmt.Errorf("source operation predecessor fact locator ordinal %d is outside its exact resource_accesses roster", binding.factOrdinal)
	}
	selected := predecessor.accesses[binding.factOrdinal]
	if selected.resourceSourceSymbol != access.resourceSourceSymbol || selected.relationshipLabel != access.relationshipLabel {
		return operationClassifierFact{}, fmt.Errorf("source operation predecessor selected access does not equal resource source symbol %q", access.resourceSourceSymbol)
	}
	if !stringSetsEqual(access.evidenceLocatorIDs, selected.evidenceLocatorIDs) || !stringSetsEqual(access.evidenceFactIDs, selected.evidenceFactIDs) {
		return operationClassifierFact{}, fmt.Errorf("source resource access %q exact locator/fact roster differs from its selected predecessor access", access.id)
	}
	return operationClassifierFact{kind: operationClassifierSourceFactKind, values: map[string]string{"relationship_label": selected.relationshipLabel}}, nil
}

func resolveProtocolOperationClassifierFact(entry operationApplicabilityEntry, access operationResourceAccess, context *operationClassifierValidationContext) (operationClassifierFact, error) {
	binding := access.classifierInputBinding
	matches := context.protocolByID[binding.rowIdentity]
	if len(matches) != 1 {
		return operationClassifierFact{}, fmt.Errorf("protocol operation predecessor identity %q resolves %d rows, want 1", binding.rowIdentity, len(matches))
	}
	indexed := matches[0]
	if indexed.rowSHA256 != binding.rowSHA256 {
		return operationClassifierFact{}, fmt.Errorf("protocol operation predecessor row digest does not equal exact bound bytes")
	}
	predecessor := indexed.value
	if binding.factLocatorKind != "whole_row" || !stringSetsEqual(stringSliceSet(predecessor.locatorIDs), access.evidenceLocatorIDs) || !stringSetsEqual(stringSliceSet(predecessor.assertionIDs), access.evidenceFactIDs) {
		return operationClassifierFact{}, fmt.Errorf("protocol operation predecessor exact row/locator/fact binding differs from resource access %q", access.id)
	}
	if entry.sourceIdentityCanonical != predecessor.sourceOperationIdentityCanonical || entry.sourceSymbol != predecessor.sourceSymbol || access.resourceSourceSymbol != predecessor.resourceSourceSymbol {
		return operationClassifierFact{}, fmt.Errorf("protocol operation predecessor does not equal the operation applicability source/resource identity")
	}
	for _, assertionID := range predecessor.assertionIDs {
		if context.protocolAssertionCounts[assertionID] != 1 {
			return operationClassifierFact{}, fmt.Errorf("protocol operation predecessor assertion %q resolves %d exact protocol assertion rows, want 1", assertionID, context.protocolAssertionCounts[assertionID])
		}
	}
	return operationClassifierFact{kind: operationClassifierProtocolFactKind, values: map[string]string{"semantic_class": predecessor.semanticClass}}, nil
}

func validateOperationClassifierPredecessorCompleteness(entry operationApplicabilityEntry, facts []operationClassifierFact, context *operationClassifierValidationContext) error {
	if len(facts) != len(entry.resourceAccesses) || len(facts) == 0 {
		return fmt.Errorf("operation classifier predecessor fact roster is incomplete")
	}
	expectedSource := map[string]struct{}{}
	for _, predecessor := range context.sourceBySemanticIdentity[entry.semanticIdentity] {
		for ordinal := range predecessor.accesses {
			expectedSource[lengthPrefixedIdentityKey(predecessor.rowSHA256, fmt.Sprintf("%d", ordinal))] = struct{}{}
		}
	}

	expectedProtocol := map[string]struct{}{}
	operationSemanticIdentity, err := sourceOperationSemanticKey(entry.sourceSymbol, entry.sourceIdentity)
	if err != nil {
		return err
	}
	for _, indexed := range context.protocolByOperationSemanticIdentity[operationSemanticIdentity] {
		expectedProtocol[indexed.value.id] = struct{}{}
	}

	actualSource := map[string]struct{}{}
	actualProtocol := map[string]struct{}{}
	for _, access := range entry.resourceAccesses {
		binding := access.classifierInputBinding
		switch binding.artifactRole {
		case operationClassifierSourceArtifactRole:
			if binding.rowIdentity != entry.semanticIdentity || binding.factLocatorKind != "resource_access_ordinal" || binding.factOrdinal < 0 {
				return fmt.Errorf("source resource access %q has an invalid semantic-row or ordinal binding", access.id)
			}
			identity := lengthPrefixedIdentityKey(binding.rowSHA256, fmt.Sprintf("%d", binding.factOrdinal))
			if _, duplicate := actualSource[identity]; duplicate {
				return fmt.Errorf("source resource accesses duplicate exact predecessor row/ordinal %q", identity)
			}
			actualSource[identity] = struct{}{}
		case operationClassifierProtocolArtifactRole:
			identity := binding.rowIdentity
			if _, duplicate := actualProtocol[identity]; duplicate {
				return fmt.Errorf("protocol resource accesses duplicate predecessor row %q", identity)
			}
			actualProtocol[identity] = struct{}{}
		default:
			return fmt.Errorf("unsupported operation classifier predecessor artifact role %q", binding.artifactRole)
		}
	}
	if err := requireExactSet("operation source-contract predecessor fact partition", actualSource, expectedSource); err != nil {
		return err
	}
	if err := requireExactSet("operation protocol-contract predecessor fact partition", actualProtocol, expectedProtocol); err != nil {
		return err
	}
	return nil
}

func parseSourceOperationAccessEvidence(object map[string]interface{}) (map[string]struct{}, map[string]struct{}, error) {
	locators, locatorsOK := semanticStringSlice(object, "evidence_locator_ids")
	if !locatorsOK || len(locators) == 0 || hasEmptyOrDuplicateSemanticStrings(locators) || !strictlyIncreasingStrings(locators) {
		return nil, nil, fmt.Errorf("evidence_locator_ids is not a nonempty canonical roster")
	}
	facts, factsOK := semanticStringSlice(object, "documentation_derived_fact_ids")
	if !factsOK || len(facts) == 0 || hasEmptyOrDuplicateSemanticStrings(facts) || !strictlyIncreasingStrings(facts) {
		return nil, nil, fmt.Errorf("documentation_derived_fact_ids is not a nonempty canonical roster")
	}
	return stringSliceSet(locators), stringSliceSet(facts), nil
}

func parseProtocolOperationClassifierPredecessor(rows dependencySemanticRows, row dependencySemanticRow) (protocolOperationClassifierPredecessor, error) {
	result := protocolOperationClassifierPredecessor{}
	var ok bool
	var err error
	result.id, ok = semanticString(row.data, "operation_classifier_fact_id")
	if !ok {
		return result, semanticRowError(rows, row, "operation_classifier_fact_id is missing")
	}
	result.sourceSymbol, ok = semanticString(row.data, "source_symbol")
	if !ok {
		return result, semanticRowError(rows, row, "source_symbol is missing")
	}
	result.resourceSourceSymbol, ok = semanticString(row.data, "resource_source_symbol")
	if !ok {
		return result, semanticRowError(rows, row, "resource_source_symbol is missing")
	}
	result.semanticClass, ok = semanticString(row.data, "semantic_class")
	if !ok || !canonicalSurfaceKindPattern.MatchString(result.semanticClass) {
		return result, semanticRowError(rows, row, "semantic_class is missing or noncanonical")
	}
	result.assertionIDs, ok = semanticStringSlice(row.data, "protocol_assertion_ids")
	if !ok || len(result.assertionIDs) == 0 || hasEmptyOrDuplicateSemanticStrings(result.assertionIDs) || !strictlyIncreasingStrings(result.assertionIDs) {
		return result, semanticRowError(rows, row, "protocol_assertion_ids is not a nonempty canonical roster")
	}
	result.locatorIDs, ok = semanticStringSlice(row.data, "evidence_locator_ids")
	if !ok || len(result.locatorIDs) == 0 || hasEmptyOrDuplicateSemanticStrings(result.locatorIDs) || !strictlyIncreasingStrings(result.locatorIDs) {
		return result, semanticRowError(rows, row, "evidence_locator_ids is not a nonempty canonical roster")
	}
	sourceBytesPresent, sourceBytesOK := semanticBool(row.data, "source_bytes_present")
	if !sourceBytesOK || sourceBytesPresent {
		return result, semanticRowError(rows, row, "operation classifier predecessor must be body-free")
	}
	result.sourceOperationIdentity, err = parseSourceOperationIdentity(row.data)
	if err != nil {
		return result, semanticRowError(rows, row, "source_operation_identity: %v", err)
	}
	canonicalIdentity, err := canonicalSourceOperationIdentity(result.sourceOperationIdentity)
	if err != nil {
		return result, semanticRowError(rows, row, "source_operation_identity: %v", err)
	}
	identityParts := []string{result.sourceSymbol, result.resourceSourceSymbol, result.semanticClass, string(canonicalIdentity)}
	identityParts = append(identityParts, result.assertionIDs...)
	if result.id != stableID("opfact", lengthPrefixedIdentityKey(identityParts...)) {
		return result, semanticRowError(rows, row, "operation_classifier_fact_id is not content-derived from the exact predecessor facts")
	}
	return result, nil
}

func parseSourceOperationIdentity(object map[string]interface{}) (map[string]interface{}, error) {
	identity, ok := semanticObject(object, "source_operation_identity")
	if !ok {
		return nil, fmt.Errorf("source_operation_identity is missing")
	}
	identityKind, kindOK := semanticString(identity, "identity_kind")
	components, componentsOK := semanticObject(identity, "identity_components")
	if !kindOK || !canonicalSurfaceKindPattern.MatchString(identityKind) || !componentsOK || len(components) == 0 {
		return nil, fmt.Errorf("source_operation_identity requires a canonical identity_kind and nonempty typed identity_components")
	}
	if _, err := canonicalSourceOperationIdentity(identity); err != nil {
		return nil, err
	}
	return identity, nil
}

func canonicalSourceOperationIdentity(identity map[string]interface{}) ([]byte, error) {
	raw, err := json.Marshal(identity)
	if err != nil {
		return nil, fmt.Errorf("marshal source operation identity: %w", err)
	}
	if err := rejectNonIntegerNumbers(raw); err != nil {
		return nil, fmt.Errorf("source operation identity: %w", err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize source operation identity: %w", err)
	}
	return canonical, nil
}

func sourceOperationSemanticKey(sourceSymbol string, identity map[string]interface{}) (string, error) {
	if sourceSymbol == "" {
		return "", fmt.Errorf("source operation identity has an incomplete source symbol")
	}
	canonical, err := canonicalSourceOperationIdentity(identity)
	if err != nil {
		return "", err
	}
	// Exact evidence occurrences are deliberately outside semantic operation
	// identity so wording, byte offsets, and retrieval coordinates cannot fork
	// one source-neutral operation.
	return stableID("srcop", lengthPrefixedIdentityKey(sourceSymbol, string(canonical))), nil
}

func equalCanonicalSourceOperationIdentities(left, right map[string]interface{}) (bool, error) {
	leftCanonical, err := canonicalSourceOperationIdentity(left)
	if err != nil {
		return false, err
	}
	rightCanonical, err := canonicalSourceOperationIdentity(right)
	if err != nil {
		return false, err
	}
	return string(leftCanonical) == string(rightCanonical), nil
}

func executeOperationClassifierProgram(program operationClassifierProgram, facts []operationClassifierFact) (operationClassifierOutput, []operationClassifierAccessOutput, error) {
	if len(facts) == 0 {
		return operationClassifierOutput{}, nil, fmt.Errorf("operation classifier fact roster is empty")
	}
	aggregatedTraits := make(map[string]interface{}, len(program.subjectTraits))
	for trait := range program.subjectTraits {
		aggregatedTraits[trait] = false
	}
	accessOutputs := make([]operationClassifierAccessOutput, 0, len(facts))
	for _, fact := range facts {
		contract, exists := program.factContracts[fact.kind]
		if !exists {
			return operationClassifierOutput{}, nil, fmt.Errorf("operation classifier fact %q is outside the closed input contract", fact.kind)
		}
		value, exists := fact.values[contract.matchField]
		if !exists {
			return operationClassifierOutput{}, nil, fmt.Errorf("operation classifier fact %q omits declared match field %q", fact.kind, contract.matchField)
		}
		output, matched := program.accessRuleByPredicate[lengthPrefixedIdentityKey(fact.kind, contract.matchField, value)]
		if !matched {
			return operationClassifierOutput{}, nil, fmt.Errorf("operation classifier fact %q matches 0 access rules, want exactly 1", fact.kind)
		}
		for _, trait := range sortedProviderStringMapKeys(output.subjectTraitContributions) {
			contribution := output.subjectTraitContributions[trait]
			prior, ok := aggregatedTraits[trait].(bool)
			if !ok {
				return operationClassifierOutput{}, nil, fmt.Errorf("operation classifier aggregate trait %q is not boolean", trait)
			}
			aggregatedTraits[trait] = prior || contribution
		}
		accessOutputs = append(accessOutputs, output)
	}
	traitKey, err := operationClassifierTraitVectorKey(aggregatedTraits, program.subjectTraitOrder)
	if err != nil {
		return operationClassifierOutput{}, nil, err
	}
	operationKind, matched := program.aggregateRuleByTraits[traitKey]
	if !matched {
		return operationClassifierOutput{}, nil, fmt.Errorf("aggregated operation classifier traits match 0 operation rules, want exactly 1")
	}
	return operationClassifierOutput{operationKind: operationKind, subjectTraits: aggregatedTraits}, accessOutputs, nil
}

func validateGraphApplicabilityCoverage(plan *parsedPlan, apiState apiGraphApplicabilityState, operations operationApplicabilityState) error {
	_, err := compileGraphApplicabilityCoverage(plan, apiState, operations)
	return err
}

func compileGraphApplicabilityCoverage(plan *parsedPlan, apiState apiGraphApplicabilityState, operations operationApplicabilityState) (applicabilityCoverageProof, error) {
	proof := applicabilityCoverageProof{seal: applicabilityCoverageProofSeal, requiredGapIDs: map[string]struct{}{}}
	if err := validateRelationshipApplicabilityCoverage(plan, apiState, operations, &proof); err != nil {
		return applicabilityCoverageProof{}, err
	}
	if err := validatePropertyApplicabilityCoverage(plan, apiState, operations, &proof); err != nil {
		return applicabilityCoverageProof{}, err
	}
	if err := validateClaimApplicabilityCoverage(plan, apiState, operations, &proof); err != nil {
		return applicabilityCoverageProof{}, err
	}
	return proof, nil
}

func validateRelationshipApplicabilityCoverage(plan *parsedPlan, apiState apiGraphApplicabilityState, operations operationApplicabilityState, proof *applicabilityCoverageProof) error {
	labels := make([]string, 0, len(apiState.relationshipByLabel))
	for label := range apiState.relationshipByLabel {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		rule := apiState.relationshipByLabel[label]
		subjectIDs := make([]string, 0)
		for _, id := range sortedProviderStringMapKeys(plan.Symbols) {
			symbol := plan.Symbols[id]
			if symbol.Role == rule.subjectRole {
				subjectIDs = append(subjectIDs, id)
			}
		}
		sort.Strings(subjectIDs)
		for _, subjectID := range subjectIDs {
			disposition, err := evaluateGraphSubjectDisposition(rule.defaultDisposition, rule.conditionalRules, graphApplicabilitySubject{kind: "api_symbol_object", id: subjectID, relationshipLabel: rule.label}, operations)
			if err != nil {
				return fmt.Errorf("relationship rule %q subject %q: %w", rule.label, subjectID, err)
			}
			actual := make([]apiRelationship, 0)
			for _, relationshipID := range sortedProviderStringMapKeys(plan.Relationships) {
				relationship := plan.Relationships[relationshipID]
				if relationship.Label == rule.label && ((rule.subjectEndpoint == "source" && relationship.SourceID == subjectID) || (rule.subjectEndpoint == "target" && relationship.TargetID == subjectID)) {
					actual = append(actual, relationship)
				}
			}
			gaps := make([]graphGap, 0)
			for _, gapID := range sortedProviderStringMapKeys(plan.Gaps) {
				gap := plan.Gaps[gapID]
				if gap.ApplicabilityRuleID == rule.id && gap.BlockedSubjectKind == "api_symbol_object" && gap.BlockedSubjectID == subjectID && gap.BlockedClaimKind == "api_relationship" {
					gaps = append(gaps, gap)
				}
			}
			if rule.subjectEndpoint == "source" && rule.sourceRole == "operation" && rule.targetRole == "resource" {
				entry, exists := operations.byOperationID[subjectID]
				if !exists {
					return fmt.Errorf("relationship rule %q subject %q has no exact operation applicability entry", rule.label, subjectID)
				}
				if err := validateExactOperationResourceRelationshipCoverage(rule, disposition, entry, actual, gaps); err != nil {
					return fmt.Errorf("relationship rule %q subject %q: %w", rule.label, subjectID, err)
				}
			}
			if err := validateRelationshipCoverageCardinality(disposition, rule.cardinality, len(actual), len(gaps)); err != nil {
				return fmt.Errorf("relationship rule %q subject %q: %w", rule.label, subjectID, err)
			}
			if disposition == applicabilityDispositionRequired {
				for _, gap := range gaps {
					proof.requiredGapIDs[gap.ID] = struct{}{}
				}
			}
		}
	}
	return nil
}

func validateExactOperationResourceRelationshipCoverage(rule relationshipApplicabilityRule, disposition string, entry operationApplicabilityEntry, actual []apiRelationship, gaps []graphGap) error {
	expected := map[string]operationResourceAccess{}
	for _, access := range entry.resourceAccesses {
		if access.relationshipLabel != rule.label {
			continue
		}
		relationshipID := stableID("capi_rel", lengthPrefixedIdentityKey(rule.label, entry.operationID, access.resourceID))
		if _, duplicate := expected[relationshipID]; duplicate {
			return fmt.Errorf("independent predecessor roster duplicates exact relationship %q", relationshipID)
		}
		expected[relationshipID] = access
	}
	if len(expected) > 0 && disposition != applicabilityDispositionRequired {
		return fmt.Errorf("%d independently established resource access(es) resolve disposition %q rather than required", len(expected), disposition)
	}
	coverage := map[string]int{}
	for _, relationship := range actual {
		access, exists := expected[relationship.ID]
		if !exists || relationship.SourceID != entry.operationID || relationship.TargetID != access.resourceID || relationship.Label != access.relationshipLabel {
			return fmt.Errorf("materialized operation-to-resource relationship %q is absent from the exact independently classified access roster", relationship.ID)
		}
		coverage[relationship.ID]++
	}
	for _, gap := range gaps {
		if _, exists := expected[gap.BlockedClaimID]; !exists {
			return fmt.Errorf("operation-to-resource gap blocks %q, absent from the exact independently classified access roster", gap.BlockedClaimID)
		}
		coverage[gap.BlockedClaimID]++
	}
	for _, relationshipID := range sortedProviderStringMapKeys(expected) {
		if coverage[relationshipID] != 1 {
			return fmt.Errorf("exact independently classified operation-to-resource relationship %q has fact-or-gap coverage %d, want 1", relationshipID, coverage[relationshipID])
		}
	}
	if len(coverage) != len(expected) {
		return fmt.Errorf("operation-to-resource fact-or-gap roster has %d identities, want exact predecessor roster size %d", len(coverage), len(expected))
	}
	return nil
}

func validateRelationshipCoverageCardinality(disposition string, cardinality applicabilityCardinality, factCount, gapCount int) error {
	coverage := int64(factCount + gapCount)
	switch disposition {
	case applicabilityDispositionRequired:
		if cardinality.minimum < 1 {
			return fmt.Errorf("required disposition declares a minimum below one")
		}
		if coverage < cardinality.minimum {
			return fmt.Errorf("required disposition has materialized-plus-fail-closed coverage %d below minimum %d", coverage, cardinality.minimum)
		}
		if cardinality.maximum != nil && coverage > *cardinality.maximum {
			return fmt.Errorf("required disposition has materialized-plus-fail-closed coverage %d above maximum %d", coverage, *cardinality.maximum)
		}
	case applicabilityDispositionOptional:
		if gapCount != 0 {
			return fmt.Errorf("optional disposition persists %d absence gap(s)", gapCount)
		}
		if cardinality.maximum != nil && int64(factCount) > *cardinality.maximum {
			return fmt.Errorf("optional disposition has %d facts above maximum %d", factCount, *cardinality.maximum)
		}
	case applicabilityDispositionInapplicable:
		if coverage != 0 {
			return fmt.Errorf("inapplicable disposition has %d materialized or gap facts", coverage)
		}
	default:
		return fmt.Errorf("unknown applicability disposition %q", disposition)
	}
	return nil
}

func validatePropertyApplicabilityCoverage(plan *parsedPlan, apiState apiGraphApplicabilityState, operations operationApplicabilityState, proof *applicabilityCoverageProof) error {
	subjects := make([]graphApplicabilitySubject, 0, len(plan.Symbols)+len(plan.Relationships))
	for id := range plan.Symbols {
		subjects = append(subjects, graphApplicabilitySubject{kind: "api_symbol_object", id: id})
	}
	for id := range plan.Relationships {
		subjects = append(subjects, graphApplicabilitySubject{kind: "api_relationship_edge", id: id})
	}
	sort.Slice(subjects, func(i, j int) bool {
		if subjects[i].kind != subjects[j].kind {
			return subjects[i].kind < subjects[j].kind
		}
		return subjects[i].id < subjects[j].id
	})
	ruleIDs := make([]string, 0, len(apiState.propertyByID))
	for id := range apiState.propertyByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	for _, ruleID := range ruleIDs {
		rule := apiState.propertyByID[ruleID]
		for _, subject := range subjects {
			allowed := propertySubjectAllowed(plan, rule, subject)
			disposition := rule.disallowedSubjectDisposition
			var err error
			if allowed {
				disposition, err = evaluateGraphSubjectDisposition(rule.defaultDisposition, rule.conditionalRules, subject, operations)
				if err != nil {
					return fmt.Errorf("property-family rule %q subject %s/%s: %w", rule.family, subject.kind, subject.id, err)
				}
			}
			factCount := 0
			for _, propertyID := range sortedProviderStringMapKeys(plan.Properties) {
				property := plan.Properties[propertyID]
				if property.Family == rule.family && property.SubjectKind == subject.kind && property.SubjectID == subject.id {
					factCount++
				}
			}
			gapCount := 0
			for _, gapID := range sortedProviderStringMapKeys(plan.Gaps) {
				gap := plan.Gaps[gapID]
				if gap.ApplicabilityRuleID == rule.id && gap.BlockedSubjectKind == subject.kind && gap.BlockedSubjectID == subject.id && gap.BlockedClaimKind == "api_property_claim" {
					gapCount++
				}
			}
			if int64(factCount) > rule.maximumClaimsPerSubject {
				return fmt.Errorf("property-family rule %q subject %s/%s has %d property facts above maximum_claims_per_subject %d", rule.family, subject.kind, subject.id, factCount, rule.maximumClaimsPerSubject)
			}
			coverage := int64(factCount + gapCount)
			switch disposition {
			case applicabilityDispositionRequired:
				if rule.maximumClaimsPerSubject < 1 {
					return fmt.Errorf("property-family rule %q subject %s/%s is required but maximum_claims_per_subject is below one", rule.family, subject.kind, subject.id)
				}
				if coverage < 1 {
					return fmt.Errorf("property-family rule %q subject %s/%s required disposition has no materialized fact or exact fail-closed gap", rule.family, subject.kind, subject.id)
				}
				if coverage > rule.maximumClaimsPerSubject {
					return fmt.Errorf("property-family rule %q subject %s/%s coverage %d exceeds maximum_claims_per_subject %d", rule.family, subject.kind, subject.id, coverage, rule.maximumClaimsPerSubject)
				}
			case applicabilityDispositionOptional:
				if gapCount != 0 {
					return fmt.Errorf("property-family rule %q subject %s/%s optional disposition persists %d absence gap(s)", rule.family, subject.kind, subject.id, gapCount)
				}
			case applicabilityDispositionInapplicable:
				if coverage != 0 {
					return fmt.Errorf("property-family rule %q subject %s/%s inapplicable disposition has %d materialized or gap facts", rule.family, subject.kind, subject.id, coverage)
				}
			default:
				return fmt.Errorf("property-family rule %q subject %s/%s has unknown disposition %q", rule.family, subject.kind, subject.id, disposition)
			}
			if disposition == applicabilityDispositionRequired {
				for _, gapID := range sortedProviderStringMapKeys(plan.Gaps) {
					gap := plan.Gaps[gapID]
					if gap.ApplicabilityRuleID == rule.id && gap.BlockedSubjectKind == subject.kind && gap.BlockedSubjectID == subject.id && gap.BlockedClaimKind == "api_property_claim" {
						proof.requiredGapIDs[gap.ID] = struct{}{}
					}
				}
			}
		}
	}
	return nil
}

func propertySubjectAllowed(plan *parsedPlan, rule propertyApplicabilityRule, subject graphApplicabilitySubject) bool {
	if _, eligible := rule.eligibleSubjectKinds[subject.kind]; !eligible {
		return false
	}
	switch subject.kind {
	case "api_symbol_object":
		symbol, exists := plan.Symbols[subject.id]
		if !exists {
			return false
		}
		_, allowed := rule.allowedRoles[symbol.Role]
		return allowed
	case "api_relationship_edge":
		relationship, exists := plan.Relationships[subject.id]
		if !exists {
			return false
		}
		_, allowed := rule.relationshipLabelScope[relationship.Label]
		return allowed
	default:
		return false
	}
}

func validateClaimApplicabilityCoverage(plan *parsedPlan, apiState apiGraphApplicabilityState, operations operationApplicabilityState, proof *applicabilityCoverageProof) error {
	ruleIDs := make([]string, 0, len(apiState.claimByID))
	for ruleID := range apiState.claimByID {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	for _, ruleID := range ruleIDs {
		rule := apiState.claimByID[ruleID]
		subjects, err := graphApplicabilitySubjectsForKind(plan, rule.blockedSubjectKind)
		if err != nil {
			return fmt.Errorf("claim applicability rule %q: %w", rule.id, err)
		}
		for _, subject := range subjects {
			disposition, err := evaluateGraphSubjectDisposition(rule.defaultDisposition, rule.conditionalRules, subject, operations)
			if err != nil {
				return fmt.Errorf("claim applicability rule %q subject %s/%s: %w", rule.id, subject.kind, subject.id, err)
			}
			gaps := make([]graphGap, 0)
			for _, gapID := range sortedProviderStringMapKeys(plan.Gaps) {
				gap := plan.Gaps[gapID]
				if gap.ApplicabilityRuleID == rule.id && gap.BlockedSubjectKind == subject.kind && gap.BlockedSubjectID == subject.id && gap.BlockedClaimKind == rule.blockedClaimKind {
					gaps = append(gaps, gap)
				}
			}
			if err := validateClaimGapCardinality(rule, disposition, len(gaps)); err != nil {
				return fmt.Errorf("claim applicability rule %q subject %s/%s: %w", rule.id, subject.kind, subject.id, err)
			}
			if disposition == applicabilityDispositionRequired {
				for _, gap := range gaps {
					proof.requiredGapIDs[gap.ID] = struct{}{}
				}
			}
		}
	}
	return nil
}

func graphApplicabilitySubjectsForKind(plan *parsedPlan, subjectKind string) ([]graphApplicabilitySubject, error) {
	result := make([]graphApplicabilitySubject, 0)
	switch subjectKind {
	case "api_symbol_object":
		for id := range plan.Symbols {
			result = append(result, graphApplicabilitySubject{kind: subjectKind, id: id})
		}
	case "api_relationship_edge":
		for id := range plan.Relationships {
			result = append(result, graphApplicabilitySubject{kind: subjectKind, id: id})
		}
	default:
		return nil, fmt.Errorf("blocked_subject_kind %q has no independently enumerable plan subject roster", subjectKind)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].id < result[j].id })
	return result, nil
}

func validateClaimGapCardinality(rule claimApplicabilityRule, disposition string, gapCount int) error {
	count := int64(gapCount)
	switch disposition {
	case applicabilityDispositionRequired:
		if rule.cardinality.minimum < 1 {
			return fmt.Errorf("required disposition declares a minimum below one")
		}
		if count < rule.cardinality.minimum {
			return fmt.Errorf("required disposition has exact fail-closed gap coverage %d below minimum %d; no profile-bound materialized claim carrier exists", count, rule.cardinality.minimum)
		}
		if rule.cardinality.maximum != nil && count > *rule.cardinality.maximum {
			return fmt.Errorf("required disposition has exact fail-closed gap coverage %d above maximum %d", count, *rule.cardinality.maximum)
		}
	case applicabilityDispositionOptional:
		if gapCount != 0 {
			return fmt.Errorf("optional disposition persists %d absence gap(s)", gapCount)
		}
	case applicabilityDispositionInapplicable:
		if gapCount != 0 {
			return fmt.Errorf("inapplicable disposition persists %d gap(s)", gapCount)
		}
	default:
		return fmt.Errorf("unknown applicability disposition %q", disposition)
	}
	return nil
}

func evaluateGraphSubjectDisposition(defaultDisposition string, rules []applicabilityConditionalRule, subject graphApplicabilitySubject, operations operationApplicabilityState) (string, error) {
	for _, rule := range rules {
		matched := false
		var err error
		if rule.predicate.kind == "always" {
			matched = true
		} else if subject.kind == "api_symbol_object" {
			entry, exists := operations.byOperationID[subject.id]
			if !exists {
				return "", fmt.Errorf("predicate %q requires exact operation classifier inputs unavailable for this subject", rule.predicate.kind)
			}
			matched, err = operationApplicabilityPredicateMatches(rule.predicate, entry, subject.relationshipLabel)
		} else {
			return "", fmt.Errorf("predicate %q requires exact operation classifier inputs unavailable for subject kind %q", rule.predicate.kind, subject.kind)
		}
		if err != nil {
			return "", err
		}
		if matched {
			return rule.disposition, nil
		}
	}
	return defaultDisposition, nil
}

func operationApplicabilityPredicateMatches(predicate applicabilityPredicate, entry operationApplicabilityEntry, relationshipLabelScope ...string) (bool, error) {
	switch predicate.kind {
	case "always":
		return true, nil
	case "subject_trait_equals":
		actual, exists := entry.subjectTraits[predicate.trait]
		if !exists {
			return false, fmt.Errorf("operation applicability omits required subject trait %q", predicate.trait)
		}
		return reflect.DeepEqual(actual, predicate.value), nil
	case "classifier_output_in":
		if entry.classifierReference.id != predicate.classifierProfileID {
			return false, fmt.Errorf("classifier profile %q does not equal rule profile %q", entry.classifierReference.id, predicate.classifierProfileID)
		}
		for _, access := range entry.resourceAccesses {
			if len(relationshipLabelScope) > 0 && relationshipLabelScope[0] != "" && access.relationshipLabel != relationshipLabelScope[0] {
				continue
			}
			if _, matched := predicate.values[access.accessSemantics]; matched {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("unknown predicate kind %q", predicate.kind)
	}
}

func validateOperationApplicabilitySummary(rows dependencySemanticRows, state operationApplicabilityState, plan *parsedPlan) error {
	summaries := rows.byKind["validation_summary"]
	if len(summaries) != 1 {
		return fmt.Errorf("operation applicability dependency %q has %d validation_summary rows, want 1", rows.path, len(summaries))
	}
	summary := summaries[0]
	checks := []struct {
		field string
		want  int64
	}{
		{"operation_applicability_count", int64(len(state.byOperationID))},
		{"persisted_optional_absence_row_count", 0},
		{"persisted_inapplicable_absence_row_count", 0},
		{"candidate_subject_count", int64(len(plan.Symbols) + len(plan.Relationships))},
		{"actual_relationship_fact_count", int64(len(plan.Relationships))},
		{"actual_property_fact_count", int64(len(plan.Properties))},
		{"sparse_required_gap_count", int64(len(plan.Gaps))},
	}
	for _, check := range checks {
		got, ok := semanticInt64(summary.data, check.field)
		if !ok || got != check.want {
			return semanticRowError(rows, summary, "%s %d does not equal recomputed value %d", check.field, got, check.want)
		}
	}
	declaredKinds, kindsOK := manifestNamedCountArray(summary.data, "captured_operation_kind_counts", "operation_kind")
	planKinds := make(map[string]int, len(plan.Summary.CapturedOperationKindCounts))
	for _, count := range plan.Summary.CapturedOperationKindCounts {
		planKinds[count.OperationKind] = count.Count
	}
	if !kindsOK || !equalIntegerMaps(declaredKinds, state.operationKindCounts) || !equalIntegerMaps(declaredKinds, planKinds) {
		return semanticRowError(rows, summary, "captured_operation_kind_counts is not exact across sidecar, plan, and recomputed operations")
	}
	for _, root := range []struct {
		field string
		want  string
	}{
		{"subject_set_root_sha256", plan.Summary.SubjectSetRootSHA256},
		{"fact_set_root_sha256", plan.Summary.FactSetRootSHA256},
		{"gap_set_root_sha256", plan.Summary.GapSetRootSHA256},
	} {
		got, ok := semanticString(summary.data, root.field)
		if !ok || got != root.want {
			return semanticRowError(rows, summary, "%s does not equal the exact graph-plan commitment root", root.field)
		}
	}
	sourceBytes, sourceBytesOK := semanticBool(summary.data, "source_bytes_present")
	if !sourceBytesOK || sourceBytes {
		return semanticRowError(rows, summary, "validation summary is not body-free")
	}
	return nil
}

func strictlyIncreasingStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] <= values[index-1] {
			return false
		}
	}
	return true
}

func stringSetsEqual(left, right map[string]struct{}) bool {
	return len(left) == len(right) && setContainsAll(left, right)
}

func validateAPIGraphApplicabilityRows(rows dependencySemanticRows, plan *parsedPlan, ood oodContract) (apiGraphApplicabilityState, error) {
	state := apiGraphApplicabilityState{
		relationshipByLabel: map[string]relationshipApplicabilityRule{},
		propertyByID:        map[string]propertyApplicabilityRule{},
		claimByID:           map[string]claimApplicabilityRule{},
		allRuleKindsByID:    map[string]string{},
	}
	manifest := rows.byKind["artifact_manifest"]
	if len(manifest) != 1 {
		return state, fmt.Errorf("API graph applicability dependency %q has %d artifact_manifest rows, want 1", rows.path, len(manifest))
	}
	manifestRow := manifest[0]
	canonicalOOD, canonicalOK := semanticString(manifestRow.data, "canonical_ood_graph_sha256")
	sourceNeutral, sourceNeutralOK := semanticBool(manifestRow.data, "source_neutral")
	transient, transientOK := semanticBool(manifestRow.data, "transient_expansion_required")
	candidateAuthority, candidateAuthorityOK := semanticBool(manifestRow.data, "candidate_rows_are_authority")
	binding, err := parseEvaluationProfileBinding(manifestRow.data, "evaluation_profile_binding")
	if !canonicalOK || canonicalOOD != plan.Manifest.CanonicalOODGraphSHA256 || !sourceNeutralOK || !sourceNeutral || !transientOK || !transient || !candidateAuthorityOK || candidateAuthority || err != nil {
		return state, semanticRowError(rows, manifestRow, "manifest does not bind the source-neutral transient evaluation profile and exact OOD authority: %v", err)
	}
	closed, closedOK := semanticStringSlice(manifestRow.data, "closed_dispositions")
	if !closedOK || !sameStringSet(closed, []string{applicabilityDispositionRequired, applicabilityDispositionOptional, applicabilityDispositionInapplicable}) {
		return state, semanticRowError(rows, manifestRow, "closed_dispositions is not the exact required/optional/inapplicable set")
	}
	state.binding = binding

	roles, constraints, families, eligiblePropertySubjects, err := normalizeOODContract(ood)
	if err != nil {
		return state, err
	}
	for _, row := range rows.byKind["relationship_applicability_rule"] {
		rule, err := parseRelationshipApplicabilityRule(rows, row)
		if err != nil {
			return state, err
		}
		constraint, exists := constraints[rule.label]
		if !exists || constraint.SourceRole != rule.sourceRole || constraint.TargetRole != rule.targetRole {
			return state, semanticRowError(rows, row, "relationship rule %q does not exactly equal the OOD endpoint-role contract", rule.label)
		}
		if (rule.subjectEndpoint == "source" && rule.subjectRole != rule.sourceRole) || (rule.subjectEndpoint == "target" && rule.subjectRole != rule.targetRole) {
			return state, semanticRowError(rows, row, "relationship rule %q applicability subject does not equal its selected endpoint role", rule.label)
		}
		if _, duplicate := state.relationshipByLabel[rule.label]; duplicate {
			return state, semanticRowError(rows, row, "duplicates relationship applicability label %q", rule.label)
		}
		if err := addApplicabilityRuleIdentity(state.allRuleKindsByID, rule.id, "relationship"); err != nil {
			return state, semanticRowError(rows, row, "%v", err)
		}
		state.relationshipByLabel[rule.label] = rule
	}
	if err := requireExactSet("API graph relationship applicability labels", stringMapKeysAsSet(state.relationshipByLabel), stringMapKeysAsSet(constraints)); err != nil {
		return state, err
	}

	propertyFamilies := map[string]struct{}{}
	for _, row := range rows.byKind["property_family_applicability_rule"] {
		id, idOK := semanticString(row.data, "applicability_rule_id")
		family, familyOK := semanticString(row.data, "property_family")
		eligibleSubjects, eligibleOK := semanticStringSlice(row.data, "eligible_subject_kinds")
		allowedRoles, rolesOK := semanticStringSlice(row.data, "allowed_api_symbol_roles")
		labelScope, labelScopeOK := semanticStringSlice(row.data, "api_relationship_label_scope")
		disallowedDisposition, disallowedOK := semanticString(row.data, "disallowed_subject_disposition")
		maximumClaims, maximumOK := semanticInt64(row.data, "maximum_claims_per_subject")
		defaultDisposition, conditionalRules, mechanicsErr := parseApplicabilityDispositionRules(rows, row)
		if !idOK || !familyOK || !eligibleOK || hasEmptyOrDuplicateSemanticStrings(eligibleSubjects) || !rolesOK || hasEmptyOrDuplicateSemanticStrings(allowedRoles) || !labelScopeOK || hasEmptyOrDuplicateSemanticStrings(labelScope) || !disallowedOK || !validApplicabilityDisposition(disallowedDisposition) || !maximumOK || maximumClaims < 0 || mechanicsErr != nil {
			return state, semanticRowError(rows, row, "property-family applicability identity or role roster is incomplete")
		}
		if _, exists := families[family]; !exists {
			return state, semanticRowError(rows, row, "property-family rule %q is absent from the OOD property-family registry", family)
		}
		for _, role := range allowedRoles {
			if _, exists := roles[role]; !exists {
				return state, semanticRowError(rows, row, "property-family rule %q names unknown API role %q", family, role)
			}
		}
		for _, subjectKind := range eligibleSubjects {
			if _, exists := eligiblePropertySubjects[subjectKind]; !exists {
				return state, semanticRowError(rows, row, "property-family rule %q names unknown eligible subject kind %q", family, subjectKind)
			}
		}
		for _, label := range labelScope {
			if _, exists := constraints[label]; !exists {
				return state, semanticRowError(rows, row, "property-family rule %q names unknown relationship label %q", family, label)
			}
		}
		if _, duplicate := propertyFamilies[family]; duplicate {
			return state, semanticRowError(rows, row, "duplicates property-family applicability %q", family)
		}
		if err := addApplicabilityRuleIdentity(state.allRuleKindsByID, id, "property_family"); err != nil {
			return state, semanticRowError(rows, row, "%v", err)
		}
		state.propertyByID[id] = propertyApplicabilityRule{
			id: id, family: family, eligibleSubjectKinds: stringSliceSet(eligibleSubjects),
			allowedRoles: stringSliceSet(allowedRoles), relationshipLabelScope: stringSliceSet(labelScope),
			defaultDisposition: defaultDisposition, conditionalRules: conditionalRules,
			disallowedSubjectDisposition: disallowedDisposition, maximumClaimsPerSubject: maximumClaims,
		}
		propertyFamilies[family] = struct{}{}
	}
	if err := requireExactSet("API graph property-family applicability", propertyFamilies, families); err != nil {
		return state, err
	}

	for _, row := range rows.byKind["claim_applicability_rule"] {
		rule, err := parseClaimApplicabilityRule(rows, row)
		if err != nil {
			return state, err
		}
		if _, duplicate := state.claimByID[rule.id]; duplicate {
			return state, semanticRowError(rows, row, "duplicates claim applicability rule %q", rule.id)
		}
		if err := addApplicabilityRuleIdentity(state.allRuleKindsByID, rule.id, "claim"); err != nil {
			return state, semanticRowError(rows, row, "%v", err)
		}
		state.claimByID[rule.id] = rule
	}
	if len(state.claimByID) == 0 {
		return state, fmt.Errorf("API graph applicability dependency %q has no claim applicability rules", rows.path)
	}
	if err := validateAPIGraphApplicabilitySummary(rows, state, len(propertyFamilies)); err != nil {
		return state, err
	}
	if err := validateGraphGapApplicabilityBindings(plan, state); err != nil {
		return state, err
	}
	return state, nil
}

func parseRelationshipApplicabilityRule(rows dependencySemanticRows, row dependencySemanticRow) (relationshipApplicabilityRule, error) {
	mechanics, err := parseApplicabilityRuleMechanics(rows, row)
	if err != nil {
		return relationshipApplicabilityRule{}, err
	}
	id, idOK := semanticString(row.data, "applicability_rule_id")
	label, labelOK := semanticString(row.data, "relationship_label")
	sourceRole, sourceOK := semanticString(row.data, "source_api_element_role")
	targetRole, targetOK := semanticString(row.data, "target_api_element_role")
	endpoint, endpointOK := semanticString(row.data, "applicability_subject_endpoint")
	subjectRole, subjectOK := semanticString(row.data, "applicability_subject_role")
	unmatched, unmatchedOK := semanticString(row.data, "unmatched_endpoint_disposition")
	if !idOK || !labelOK || !sourceOK || !targetOK || !endpointOK || (endpoint != "source" && endpoint != "target") || !subjectOK || !unmatchedOK || !validApplicabilityDisposition(unmatched) {
		return relationshipApplicabilityRule{}, semanticRowError(rows, row, "relationship applicability rule has incomplete identity, endpoint, or disposition")
	}
	return relationshipApplicabilityRule{id: id, label: label, sourceRole: sourceRole, targetRole: targetRole, subjectEndpoint: endpoint, subjectRole: subjectRole, defaultDisposition: mechanics.defaultDisposition, conditionalRules: mechanics.conditionalRules, cardinality: mechanics.cardinality, unmatchedEndpointDisposition: unmatched}, nil
}

func parseClaimApplicabilityRule(rows dependencySemanticRows, row dependencySemanticRow) (claimApplicabilityRule, error) {
	mechanics, err := parseApplicabilityRuleMechanics(rows, row)
	if err != nil {
		return claimApplicabilityRule{}, err
	}
	id, idOK := semanticString(row.data, "applicability_rule_id")
	claimKind, claimOK := semanticString(row.data, "blocked_claim_kind")
	subjectKind, subjectOK := semanticString(row.data, "blocked_subject_kind")
	if !idOK || !claimOK || !subjectOK {
		return claimApplicabilityRule{}, semanticRowError(rows, row, "claim applicability rule has incomplete identity")
	}
	return claimApplicabilityRule{id: id, blockedClaimKind: claimKind, blockedSubjectKind: subjectKind, defaultDisposition: mechanics.defaultDisposition, conditionalRules: mechanics.conditionalRules, cardinality: mechanics.cardinality}, nil
}

type applicabilityRuleMechanics struct {
	defaultDisposition string
	conditionalRules   []applicabilityConditionalRule
	cardinality        applicabilityCardinality
}

func parseApplicabilityRuleMechanics(rows dependencySemanticRows, row dependencySemanticRow) (applicabilityRuleMechanics, error) {
	result := applicabilityRuleMechanics{}
	defaultDisposition, conditionalRules, err := parseApplicabilityDispositionRules(rows, row)
	if err != nil {
		return result, err
	}
	cardinalityObject, cardinalityOK := semanticObject(row.data, "required_cardinality")
	if !cardinalityOK {
		return result, semanticRowError(rows, row, "applicability mechanics are incomplete")
	}
	result.defaultDisposition = defaultDisposition
	result.conditionalRules = conditionalRules
	minimum, minimumOK := semanticInt64(cardinalityObject, "minimum")
	maximumValue, maximumPresent := cardinalityObject["maximum"]
	if !minimumOK || minimum < 0 || !maximumPresent {
		return result, semanticRowError(rows, row, "required_cardinality is incomplete")
	}
	result.cardinality.minimum = minimum
	if maximumValue != nil {
		maximum, maximumOK := semanticJSONInt64(maximumValue)
		if !maximumOK || maximum < minimum {
			return result, semanticRowError(rows, row, "required_cardinality maximum is invalid")
		}
		result.cardinality.maximum = &maximum
	}
	return result, nil
}

func parseApplicabilityDispositionRules(rows dependencySemanticRows, row dependencySemanticRow) (string, []applicabilityConditionalRule, error) {
	defaultDisposition, defaultOK := semanticString(row.data, "default_disposition")
	conditionalRows, conditionalOK := semanticObjectSlice(row.data, "ordered_conditional_rules")
	if !defaultOK || !validApplicabilityDisposition(defaultDisposition) || !conditionalOK {
		return "", nil, semanticRowError(rows, row, "applicability disposition mechanics are incomplete")
	}
	result := make([]applicabilityConditionalRule, 0, len(conditionalRows))
	for index, conditional := range conditionalRows {
		ordinal, ordinalOK := semanticInt64(conditional, "ordinal")
		disposition, dispositionOK := semanticString(conditional, "disposition")
		predicateObject, predicateOK := semanticObject(conditional, "predicate")
		if !ordinalOK || ordinal != int64(index) || !dispositionOK || !validApplicabilityDisposition(disposition) || !predicateOK {
			return "", nil, semanticRowError(rows, row, "ordered_conditional_rules[%d] is not contiguous or complete", index)
		}
		predicate, err := parseApplicabilityPredicate(predicateObject)
		if err != nil {
			return "", nil, semanticRowError(rows, row, "ordered_conditional_rules[%d]: %v", index, err)
		}
		result = append(result, applicabilityConditionalRule{disposition: disposition, predicate: predicate})
	}
	return defaultDisposition, result, nil
}

func parseApplicabilityPredicate(object map[string]interface{}) (applicabilityPredicate, error) {
	result := applicabilityPredicate{}
	kind, ok := semanticString(object, "predicate_kind")
	if !ok {
		return result, fmt.Errorf("predicate_kind is missing")
	}
	result.kind = kind
	switch kind {
	case "always":
		return result, nil
	case "subject_trait_equals":
		trait, traitOK := semanticString(object, "trait")
		value, valueOK := object["value"]
		if !traitOK || !valueOK || value == nil {
			return result, fmt.Errorf("subject_trait_equals is incomplete")
		}
		result.trait, result.value = trait, value
		return result, nil
	case "classifier_output_in":
		profileID, profileOK := semanticString(object, "classifier_profile_id")
		values, valuesOK := semanticStringSlice(object, "values")
		if !profileOK || !valuesOK || len(values) == 0 || hasEmptyOrDuplicateSemanticStrings(values) {
			return result, fmt.Errorf("classifier_output_in is incomplete")
		}
		result.classifierProfileID = profileID
		result.values = stringSliceSet(values)
		return result, nil
	default:
		return result, fmt.Errorf("unknown source-neutral predicate_kind %q", kind)
	}
}

func parseApplicabilityProfileBinding(object map[string]interface{}, key string) (applicabilityProfileBinding, error) {
	return parseNamedApplicabilityProfileBinding(object, key, "applicability_profile")
}

func parseEvaluationProfileBinding(object map[string]interface{}, key string) (applicabilityProfileBinding, error) {
	return parseNamedApplicabilityProfileBinding(object, key, "evaluation_profile")
}

func parseNamedApplicabilityProfileBinding(object map[string]interface{}, key, fieldPrefix string) (applicabilityProfileBinding, error) {
	bindingObject, ok := semanticObject(object, key)
	if !ok {
		return applicabilityProfileBinding{}, fmt.Errorf("%s is not an object", key)
	}
	id, idOK := semanticString(bindingObject, fieldPrefix+"_id")
	version, versionOK := semanticString(bindingObject, fieldPrefix+"_version")
	digest, digestOK := semanticString(bindingObject, fieldPrefix+"_sha256")
	if !idOK || !versionOK || !digestOK || !isLowerSHA256(digest) {
		return applicabilityProfileBinding{}, fmt.Errorf("%s has incomplete identity/version/digest", key)
	}
	return applicabilityProfileBinding{id: id, version: version, digest: digest}, nil
}

func validApplicabilityDisposition(value string) bool {
	return value == applicabilityDispositionRequired || value == applicabilityDispositionOptional || value == applicabilityDispositionInapplicable
}

func addApplicabilityRuleIdentity(roster map[string]string, id, kind string) error {
	if id == "" {
		return fmt.Errorf("applicability rule has empty identity")
	}
	if prior, duplicate := roster[id]; duplicate {
		return fmt.Errorf("applicability rule %q aliases %s and %s", id, prior, kind)
	}
	roster[id] = kind
	return nil
}

func sameStringSet(left, right []string) bool {
	if hasEmptyOrDuplicateSemanticStrings(left) || hasEmptyOrDuplicateSemanticStrings(right) || len(left) != len(right) {
		return false
	}
	leftSet := stringSliceSet(left)
	for _, value := range right {
		if _, ok := leftSet[value]; !ok {
			return false
		}
	}
	return true
}

func validateAPIGraphApplicabilitySummary(rows dependencySemanticRows, state apiGraphApplicabilityState, propertyRuleCount int) error {
	summaries := rows.byKind["validation_summary"]
	if len(summaries) != 1 {
		return fmt.Errorf("API graph applicability dependency %q has %d validation_summary rows, want 1", rows.path, len(summaries))
	}
	summary := summaries[0]
	checks := []struct {
		field string
		want  int64
	}{{"relationship_applicability_rule_count", int64(len(state.relationshipByLabel))}, {"property_family_applicability_rule_count", int64(propertyRuleCount)}, {"claim_applicability_rule_count", int64(len(state.claimByID))}}
	for _, check := range checks {
		value, ok := semanticInt64(summary.data, check.field)
		if !ok || value != check.want {
			return semanticRowError(rows, summary, "%s %d does not equal exact rule count %d", check.field, value, check.want)
		}
	}
	subjectExpansion, subjectOK := semanticBool(summary.data, "subject_expansion_persisted")
	optionalAbsence, optionalOK := semanticBool(summary.data, "optional_absence_rows_persisted")
	admission, admissionOK := semanticBool(summary.data, "canonical_admission_authorized")
	if !subjectOK || subjectExpansion || !optionalOK || optionalAbsence || !admissionOK || admission {
		return semanticRowError(rows, summary, "summary permits persisted expansion, optional absence, or candidate admission")
	}
	return nil
}

func validateGraphGapApplicabilityBindings(plan *parsedPlan, state apiGraphApplicabilityState) error {
	for _, gapID := range sortedProviderStringMapKeys(plan.Gaps) {
		gap := plan.Gaps[gapID]
		if gap.ApplicabilityProfileID != state.binding.id || gap.ApplicabilityProfileVersion != state.binding.version || gap.ApplicabilityProfileSHA256 != state.binding.digest {
			return fmt.Errorf("graph gap %s does not bind the exact API applicability evaluation profile", gap.ID)
		}
		if gap.Disposition != "fail_closed" || gap.MaterializationEligible {
			return fmt.Errorf("graph gap %s does not preserve a non-materializable fail-closed disposition", gap.ID)
		}
		ruleKind, exists := state.allRuleKindsByID[gap.ApplicabilityRuleID]
		if !exists {
			return fmt.Errorf("graph gap %s binds unknown applicability rule %q", gap.ID, gap.ApplicabilityRuleID)
		}
		if ruleKind == "claim" {
			rule := state.claimByID[gap.ApplicabilityRuleID]
			if gap.BlockedClaimKind != rule.blockedClaimKind || gap.BlockedSubjectKind != rule.blockedSubjectKind {
				return fmt.Errorf("graph gap %s does not equal its claim applicability rule", gap.ID)
			}
			if err := validateApplicabilityGapSubject(plan, gap.BlockedSubjectKind, gap.BlockedSubjectID, ""); err != nil {
				return fmt.Errorf("graph gap %s: %w", gap.ID, err)
			}
		} else if ruleKind == "relationship" {
			rule := relationshipApplicabilityRule{}
			for _, label := range sortedProviderStringMapKeys(state.relationshipByLabel) {
				candidate := state.relationshipByLabel[label]
				if candidate.id == gap.ApplicabilityRuleID {
					rule = candidate
					break
				}
			}
			if gap.BlockedClaimKind != "api_relationship" || gap.BlockedSubjectKind != "api_symbol_object" {
				return fmt.Errorf("graph gap %s binds a relationship rule but blocked_claim_kind is %q", gap.ID, gap.BlockedClaimKind)
			}
			if err := validateApplicabilityGapSubject(plan, gap.BlockedSubjectKind, gap.BlockedSubjectID, rule.subjectRole); err != nil {
				return fmt.Errorf("graph gap %s: %w", gap.ID, err)
			}
		} else if ruleKind == "property_family" {
			rule := state.propertyByID[gap.ApplicabilityRuleID]
			if gap.BlockedClaimKind != "api_property_claim" {
				return fmt.Errorf("graph gap %s does not equal its property-family applicability rule", gap.ID)
			}
			if _, eligible := rule.eligibleSubjectKinds[gap.BlockedSubjectKind]; !eligible {
				return fmt.Errorf("graph gap %s subject kind %q is not eligible for property-family rule %q", gap.ID, gap.BlockedSubjectKind, rule.family)
			}
			if err := validateApplicabilityGapSubject(plan, gap.BlockedSubjectKind, gap.BlockedSubjectID, ""); err != nil {
				return fmt.Errorf("graph gap %s: %w", gap.ID, err)
			}
		} else {
			return fmt.Errorf("graph gap %s binds unsupported applicability rule kind %q", gap.ID, ruleKind)
		}
	}
	return nil
}

func validateApplicabilityGapSubject(plan *parsedPlan, subjectKind, subjectID, requiredRole string) error {
	switch subjectKind {
	case "api_symbol_object":
		symbol, exists := plan.Symbols[subjectID]
		if !exists {
			return fmt.Errorf("blocked subject %q resolves no plan API symbol", subjectID)
		}
		if requiredRole != "" && symbol.Role != requiredRole {
			return fmt.Errorf("blocked subject %q role %q does not equal applicability role %q", subjectID, symbol.Role, requiredRole)
		}
	case "api_relationship_edge":
		if _, exists := plan.Relationships[subjectID]; !exists {
			return fmt.Errorf("blocked subject %q resolves no plan API relationship", subjectID)
		}
	default:
		if requiredRole != "" {
			return fmt.Errorf("blocked subject kind %q cannot satisfy API role %q", subjectKind, requiredRole)
		}
		// Claim rules may target a typed semantic subject outside the API graph
		// (for example, an assertion owned by another exact dependency). The
		// later no-orphan closure must resolve every such gap through that
		// dependency; this evaluator must not invent its identity vocabulary.
		return nil
	}
	return nil
}
