package providerplan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	targetCandidatePathPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	singlePathSegmentPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

type dependencySemanticRow struct {
	line            int
	raw             []byte
	canonicalSHA256 string
	kind            string
	data            map[string]interface{}
}

type dependencySemanticRows struct {
	path   string
	raw    []byte
	byKind map[string][]dependencySemanticRow
}

type dependencyHydrationCoordinate struct {
	digest   string
	start    int64
	end      int64
	count    int64
	rangeSHA string
}

// dependencySemanticValidationProof is an in-process capability proving that
// every semantic dependency was validated against its exact, digest-bound
// JSON Schema 2020-12 profile before semantic closure was evaluated. It is
// deliberately package-private and has no serialization form: schema
// authority belongs to the data-driven profile validator, never to Go row-key
// or version literals in this semantic checker.
type dependencySemanticValidationProof struct {
	seal   *dependencySemanticValidationSeal
	byRole map[string]dependencySemanticValidatedArtifact
}

type dependencySemanticValidationSeal struct{}

type dependencySemanticValidatedArtifact struct {
	artifactSHA256 string
	schemaRole     string
	schemaID       string
	schemaVersion  string
	schemaSHA256   string
}

var dependencySemanticValidationAuthority = &dependencySemanticValidationSeal{}

const (
	dependencySemanticRoleProfile            = "provider_neutral_compilation_profile"
	dependencySemanticRoleSourceContract     = "source_contract_index"
	dependencySemanticRoleSampleShape        = "sample_shape_index"
	dependencySemanticRoleProtocolContract   = "protocol_contract_index"
	dependencySemanticRoleFieldMapping       = "field_mapping_candidate"
	dependencySemanticRoleSurfaceDisposition = "surface_family_disposition"
)

type dependencySemanticAuxiliaries struct {
	operationApplicability              artifactInput
	apiGraphApplicability               artifactInput
	fieldSecurityPolicy                 artifactInput
	mappingTransitiveDependencyRoster   artifactInput
	documentationClaimDerivationProfile artifactInput
}

// validateDependencySemanticClosure proves that the structured dependencies
// carry the exact source-derived rows that the graph plan claims. It is a
// source-neutral compiler gate: provider identities, vocabularies, and counts
// come from the supplied artifacts and OOD contract, never from Go constants.
func validateDependencySemanticClosure(proof dependencySemanticValidationProof, derivationTargets dependencySemanticDerivationTargetSchemaAuthority, derivationTargetArtifacts map[string]artifactInput, plan *parsedPlan, ood oodContract, loaded loadedEvidence, profile, sourceContract, sampleShape, protocolContract, fieldMapping, surfaceDisposition artifactInput, auxiliaries dependencySemanticAuxiliaries, closureOutput *documentationDerivationClosureProof) error {
	if closureOutput == nil {
		return fmt.Errorf("dependency semantic closure requires a documentation-derivation closure output")
	}
	*closureOutput = documentationDerivationClosureProof{}
	roleArtifacts := map[string]artifactInput{
		dependencySemanticRoleProfile:                      profile,
		dependencySemanticRoleSourceContract:               sourceContract,
		dependencySemanticRoleSampleShape:                  sampleShape,
		dependencySemanticRoleProtocolContract:             protocolContract,
		dependencySemanticRoleFieldMapping:                 fieldMapping,
		dependencySemanticRoleOperationApplicability:       auxiliaries.operationApplicability,
		dependencySemanticRoleAPIGraphApplicability:        auxiliaries.apiGraphApplicability,
		dependencySemanticRoleSurfaceDisposition:           surfaceDisposition,
		dependencySemanticRoleFieldSecurityPolicy:          auxiliaries.fieldSecurityPolicy,
		dependencySemanticRoleMappingTransitiveRoster:      auxiliaries.mappingTransitiveDependencyRoster,
		dependencySemanticRoleDocumentationClaimDerivation: auxiliaries.documentationClaimDerivationProfile,
	}
	if err := validateDependencySemanticProof(proof, roleArtifacts); err != nil {
		return err
	}

	profileRows, err := parseDependencySemanticRows(profile)
	if err != nil {
		return err
	}
	sourceRows, err := parseDependencySemanticRows(sourceContract)
	if err != nil {
		return err
	}
	sampleRows, err := parseDependencySemanticRows(sampleShape)
	if err != nil {
		return err
	}
	protocolRows, err := parseDependencySemanticRows(protocolContract)
	if err != nil {
		return err
	}
	fieldRows, err := parseDependencySemanticRows(fieldMapping)
	if err != nil {
		return err
	}
	surfaceRows, err := parseDependencySemanticRows(surfaceDisposition)
	if err != nil {
		return err
	}
	securityRows, err := parseDependencySemanticRows(auxiliaries.fieldSecurityPolicy)
	if err != nil {
		return err
	}
	transitiveRows, err := parseDependencySemanticRows(auxiliaries.mappingTransitiveDependencyRoster)
	if err != nil {
		return err
	}
	derivationRows, err := parseDependencySemanticRows(auxiliaries.documentationClaimDerivationProfile)
	if err != nil {
		return err
	}
	operationApplicabilityRows, err := parseDependencySemanticRows(auxiliaries.operationApplicability)
	if err != nil {
		return err
	}
	apiGraphApplicabilityRows, err := parseDependencySemanticRows(auxiliaries.apiGraphApplicability)
	if err != nil {
		return err
	}
	derivationState, err := parseDocumentationClaimDerivationRows(derivationRows)
	if err != nil {
		return err
	}
	classificationProof, exists := loaded.ClassificationSelectionProofs[plan.Manifest.EvidenceSelectionRosterSHA256]
	if !exists {
		return fmt.Errorf("documentation derivation requires the sealed classification proof for evidence selection roster %s", plan.Manifest.EvidenceSelectionRosterSHA256)
	}
	if classificationProof.provider != plan.Manifest.Provider || classificationProof.evidenceSelectionRosterSHA256 != plan.Manifest.EvidenceSelectionRosterSHA256 {
		return fmt.Errorf("documentation derivation classification proof does not equal the plan provider and evidence-selection roster")
	}
	if err := validateSourceClassificationSelectionProof(classificationProof); err != nil {
		return fmt.Errorf("documentation derivation classification proof: %w", err)
	}
	targetRows := make(map[string]dependencySemanticRows, len(derivationTargetArtifacts))
	for _, role := range sortedProviderStringMapKeys(derivationTargetArtifacts) {
		rows, err := parseDependencySemanticRows(derivationTargetArtifacts[role])
		if err != nil {
			return fmt.Errorf("documentation target role %q: %w", role, err)
		}
		targetRows[role] = rows
	}
	derivationClosure, err := executeAndValidateDocumentationDerivationClosure(
		derivationRows,
		derivationState,
		derivationTargets,
		derivationTargetArtifacts,
		targetRows,
		classificationProof,
		loaded.Bodies,
	)
	if err != nil {
		return fmt.Errorf("validate executable documentation derivation and exact target materialization closure: %w", err)
	}
	if err := validateProfileSemanticRows(profileRows, ood); err != nil {
		return err
	}
	apiApplicabilityState, err := validateAPIGraphApplicabilityRows(apiGraphApplicabilityRows, plan, ood)
	if err != nil {
		return err
	}
	operationApplicabilityState, err := validateOperationApplicabilityRows(operationApplicabilityRows, apiGraphApplicabilityRows, sourceRows, protocolRows, derivationRows, plan, apiApplicabilityState, derivationState)
	if err != nil {
		return err
	}
	sourceState, err := validateSourceContractSemanticRows(sourceRows, plan, ood, loaded, &operationApplicabilityState, apiApplicabilityState)
	if err != nil {
		return err
	}
	if err := validateSampleShapeSemanticRows(sampleRows, sourceState, loaded); err != nil {
		return err
	}
	if err := validateProtocolSemanticRows(protocolRows, profileRows, plan, loaded); err != nil {
		return err
	}
	surfaceState, err := validateSurfaceDispositionSemanticRows(surfaceRows, sourceState, loaded, derivationState)
	if err != nil {
		return err
	}
	if err := validateFieldMappingSemanticRows(fieldRows, securityRows, transitiveRows, derivationRows, derivationState, derivationClosure, sourceState, surfaceState, loaded); err != nil {
		return err
	}
	if err := validateNoOrphanGraphGaps(plan, operationApplicabilityState); err != nil {
		return err
	}
	if err := validateTypedGraphCandidateDerivationBindings(plan, loaded, sourceContract, sourceRows, auxiliaries.apiGraphApplicability, apiGraphApplicabilityRows); err != nil {
		return err
	}
	if err := validateEvidenceConsumerIdentityClosure(plan, loaded, map[string]artifactInput{
		"source_contract_index":      sourceContract,
		"sample_shape_index":         sampleShape,
		"protocol_contract_index":    protocolContract,
		"field_mapping_candidate":    fieldMapping,
		"surface_family_disposition": surfaceDisposition,
	}); err != nil {
		return err
	}
	if err := validateDocumentationDerivationClosureProof(derivationClosure); err != nil {
		return err
	}
	*closureOutput = derivationClosure
	return nil
}

func validateDependencySemanticProof(proof dependencySemanticValidationProof, roleArtifacts map[string]artifactInput) error {
	if proof.seal != dependencySemanticValidationAuthority {
		return fmt.Errorf("dependency semantic closure requires an exact schema-validation proof")
	}
	if err := requireExactSet("dependency semantic closure role roster", stringMapKeysAsSet(roleArtifacts), stringSliceSet(dependencySemanticRequiredRoles)); err != nil {
		return err
	}
	if len(proof.byRole) != len(roleArtifacts) {
		return fmt.Errorf("dependency semantic validation proof role roster is not set-equal to the required semantic artifact roles")
	}
	seenArtifactDigests := make(map[string]string, len(roleArtifacts))
	for _, role := range sortedProviderStringMapKeys(roleArtifacts) {
		input := roleArtifacts[role]
		binding, ok := proof.byRole[role]
		if !ok {
			return fmt.Errorf("dependency semantic validation proof is missing role %q", role)
		}
		if !isLowerSHA256(binding.artifactSHA256) || binding.artifactSHA256 != sha256Hex(input.Raw) {
			return fmt.Errorf("dependency semantic validation proof role %q does not bind the supplied exact artifact bytes", role)
		}
		if input.SHA256 != "" && input.SHA256 != binding.artifactSHA256 {
			return fmt.Errorf("dependency semantic validation proof role %q disagrees with the artifact input digest", role)
		}
		if priorRole, duplicate := seenArtifactDigests[binding.artifactSHA256]; duplicate {
			return fmt.Errorf("dependency semantic validation proof aliases artifact bytes across roles %q and %q", priorRole, role)
		}
		seenArtifactDigests[binding.artifactSHA256] = role
		coordinate, err := newValidationProfileCoordinate("schema", binding.schemaID, binding.schemaVersion)
		if err != nil || !isLowerSHA256(binding.schemaSHA256) {
			return fmt.Errorf("dependency semantic validation proof role %q has no exact schema identity, version, and digest", role)
		}
		_ = coordinate // Exact schema reuse across roles is intentionally legal.
	}
	for _, role := range sortedProviderStringMapKeys(proof.byRole) {
		if _, ok := roleArtifacts[role]; !ok {
			return fmt.Errorf("dependency semantic validation proof has extra role %q", role)
		}
	}
	return nil
}

func validateEvidenceConsumerIdentityClosure(plan *parsedPlan, loaded loadedEvidence, roleArtifacts map[string]artifactInput) error {
	expectedByRole := map[string]map[string]struct{}{}
	for identity, metadata := range loaded.MetadataByIdentity {
		identityKey := evidenceBodyIdentityKey(identity)
		for role := range metadata.ConsumerRoles {
			if expectedByRole[role] == nil {
				expectedByRole[role] = map[string]struct{}{}
			}
			expectedByRole[role][identityKey] = struct{}{}
		}
	}
	graphActual := map[string]struct{}{}
	for _, locatorID := range sortedProviderStringMapKeys(plan.Locators) {
		locator := plan.Locators[locatorID]
		identity := evidenceBodyIdentity{ManifestSHA256: locator.EvidenceManifestSHA256, SourceRef: locator.SourceRefs[0], ContentSHA256: locator.SourceContentSHA256}
		if _, exists := loaded.MetadataByIdentity[identity]; !exists {
			return fmt.Errorf("api_graph_projection locator %s resolves no exact manifest/ref/content evidence identity", locator.ID)
		}
		graphActual[evidenceBodyIdentityKey(identity)] = struct{}{}
	}
	if err := requireExactSet("api_graph_projection exact evidence identities", graphActual, expectedByRole["api_graph_projection"]); err != nil {
		return err
	}
	for _, role := range sortedProviderStringMapKeys(roleArtifacts) {
		input := roleArtifacts[role]
		actual, err := artifactHydratedEvidenceIdentities(input, loaded)
		if err != nil {
			return fmt.Errorf("%s dependency %q exact evidence consumption: %w", role, input.Path, err)
		}
		if err := requireExactSet(role+" exact evidence identities", actual, expectedByRole[role]); err != nil {
			return err
		}
	}
	return nil
}

func artifactHydratedEvidenceIdentities(input artifactInput, loaded loadedEvidence) (map[string]struct{}, error) {
	result := map[string]struct{}{}
	state := artifactHydrationWalkState{}
	for _, rowKind := range sortedProviderStringMapKeys(input.RowsByKind) {
		if rowKind == "artifact_manifest" || rowKind == "validation_summary" {
			continue
		}
		rows := input.RowsByKind[rowKind]
		for rowIndex, row := range rows {
			if err := collectArtifactHydrationIdentities(row, "", "", loaded, result, 1, &state); err != nil {
				return nil, fmt.Errorf("%s row %d: %w", rowKind, rowIndex, err)
			}
		}
	}
	return result, nil
}

type artifactHydrationWalkState struct {
	nodes int
}

func collectArtifactHydrationIdentities(value interface{}, inheritedRef, inheritedURL string, loaded loadedEvidence, result map[string]struct{}, depth int, state *artifactHydrationWalkState) error {
	if depth > maxProviderJSONNestingDepth {
		return fmt.Errorf("evidence hydration traversal exceeds fixed nesting depth")
	}
	state.nodes++
	if state.nodes > int(maxProviderJSONNodesPerArtifact) {
		return fmt.Errorf("evidence hydration traversal exceeds fixed artifact node bound")
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		ref := inheritedRef
		if candidate, ok := semanticString(typed, "source_ref"); ok {
			ref = candidate
		} else if candidate, ok := semanticString(typed, "source_symbol"); ok {
			ref = candidate
		}
		sourceURL := inheritedURL
		if candidate, ok := semanticString(typed, "source_url"); ok {
			sourceURL = candidate
		}
		if rawCoordinate, present := typed["evidence_hydration_coordinate"]; present {
			coordinateObject, ok := rawCoordinate.(map[string]interface{})
			if !ok {
				return fmt.Errorf("evidence_hydration_coordinate is not an object")
			}
			if err := addHydratedEvidenceIdentity(coordinateObject, ref, sourceURL, loaded, result); err != nil {
				return err
			}
		}
		if rawCoordinates, present := typed["evidence_hydration_coordinates"]; present {
			coordinates, ok := rawCoordinates.([]interface{})
			if !ok {
				return fmt.Errorf("evidence_hydration_coordinates is not an array")
			}
			for index, rawBinding := range coordinates {
				binding, ok := rawBinding.(map[string]interface{})
				if !ok {
					return fmt.Errorf("evidence_hydration_coordinates[%d] is not an object", index)
				}
				bindingRef := ref
				if candidate, ok := semanticString(binding, "source_ref"); ok {
					bindingRef = candidate
				}
				bindingURL := sourceURL
				if candidate, ok := semanticString(binding, "source_url"); ok {
					bindingURL = candidate
				}
				coordinateObject, ok := semanticObject(binding, "coordinate")
				if !ok {
					return fmt.Errorf("evidence_hydration_coordinates[%d].coordinate is not an object", index)
				}
				if err := addHydratedEvidenceIdentity(coordinateObject, bindingRef, bindingURL, loaded, result); err != nil {
					return err
				}
			}
		}
		for _, key := range sortedProviderStringMapKeys(typed) {
			if key == "evidence_hydration_coordinate" || key == "evidence_hydration_coordinates" || key == "diagnostic_navigation_coordinate" {
				continue
			}
			if err := collectArtifactHydrationIdentities(typed[key], ref, sourceURL, loaded, result, depth+1, state); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, child := range typed {
			if err := collectArtifactHydrationIdentities(child, inheritedRef, inheritedURL, loaded, result, depth+1, state); err != nil {
				return err
			}
		}
	}
	return nil
}

func addHydratedEvidenceIdentity(object map[string]interface{}, ref, sourceURL string, loaded loadedEvidence, result map[string]struct{}) error {
	coordinate, err := parseDependencyHydrationCoordinate(object)
	if err != nil {
		return err
	}
	if !isLowerSHA256(coordinate.digest) || !isLowerSHA256(coordinate.rangeSHA) || coordinate.start < 0 || coordinate.end <= coordinate.start || coordinate.count != coordinate.end-coordinate.start {
		return fmt.Errorf("evidence hydration coordinate is malformed")
	}
	body, ok := loaded.Bodies[coordinate.digest]
	if !ok || coordinate.end > int64(len(body.Bytes)) {
		return fmt.Errorf("evidence hydration coordinate resolves no complete exact body range")
	}
	selected := body.Bytes[coordinate.start:coordinate.end]
	if int64(len(selected)) != coordinate.count || sha256Hex(selected) != coordinate.rangeSHA {
		return fmt.Errorf("evidence hydration coordinate does not hydrate its exact selected bytes")
	}
	matches := make([]evidenceBodyIdentity, 0, 1)
	for identity, metadata := range loaded.MetadataByIdentity {
		if identity.ContentSHA256 != coordinate.digest || (ref != "" && identity.SourceRef != ref) || (sourceURL != "" && metadata.SourceURL != sourceURL) {
			continue
		}
		matches = append(matches, identity)
	}
	if len(matches) != 1 {
		return fmt.Errorf("hydrated evidence ref=%q url=%q digest=%s resolves %d exact manifest/ref/content identities, want 1", ref, sourceURL, coordinate.digest, len(matches))
	}
	result[evidenceBodyIdentityKey(matches[0])] = struct{}{}
	return nil
}

func evidenceBodyIdentityKey(identity evidenceBodyIdentity) string {
	return lengthPrefixedIdentityKey(identity.ManifestSHA256, identity.SourceRef, identity.ContentSHA256)
}

func validateNoOrphanGraphGaps(plan *parsedPlan, operations operationApplicabilityState) error {
	if operations.coverageProof.seal != applicabilityCoverageProofSeal || operations.coverageProof.requiredGapIDs == nil {
		return fmt.Errorf("typed graph gap closure has no independently evaluated applicability proof")
	}
	return requireExactSet("typed graph gaps consumed by independently evaluated required dispositions", operations.coverageProof.requiredGapIDs, stringMapKeysAsSet(plan.Gaps))
}

func parseDependencySemanticRows(input artifactInput) (dependencySemanticRows, error) {
	result := dependencySemanticRows{path: input.Path, raw: input.Raw, byKind: map[string][]dependencySemanticRow{}}
	if len(bytes.TrimSpace(input.Raw)) == 0 {
		return result, fmt.Errorf("dependency artifact %q is empty", input.Path)
	}
	if err := requireValidUTF8(fmt.Sprintf("dependency artifact %q", input.Path), input.Raw); err != nil {
		return result, err
	}
	if input.ParsedRows != nil {
		for _, parsed := range input.ParsedRows {
			if parsed.Discriminator != "row_kind" || !isCanonicalValidationProfileIdentity(parsed.Kind) {
				return result, fmt.Errorf("dependency artifact %q line %d has no canonical row_kind", input.Path, parsed.Line)
			}
			if parsed.RawStart < 0 || parsed.RawEnd <= parsed.RawStart || parsed.RawEnd > len(input.Raw) {
				return result, fmt.Errorf("dependency artifact %q line %d has no exact retained JSON byte range", input.Path, parsed.Line)
			}
			result.byKind[parsed.Kind] = append(result.byKind[parsed.Kind], dependencySemanticRow{line: parsed.Line, raw: input.Raw[parsed.RawStart:parsed.RawEnd], canonicalSHA256: parsed.CanonicalSHA256, kind: parsed.Kind, data: parsed.Data})
		}
		if len(result.byKind["artifact_manifest"]) != 1 || len(result.byKind["validation_summary"]) != 1 {
			return result, fmt.Errorf("dependency artifact %q requires exactly one artifact_manifest and one validation_summary", input.Path)
		}
		return result, nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(input.Raw))
	scanner.Buffer(make([]byte, 64*1024), 32*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := bytes.Clone(bytes.TrimSpace(scanner.Bytes()))
		if len(raw) == 0 {
			continue
		}
		if err := rejectDuplicateJSONKeys(raw); err != nil {
			return result, fmt.Errorf("dependency artifact %q line %d: %w", input.Path, lineNo, err)
		}
		var object map[string]interface{}
		if err := decodeOneValidationProfileJSON(raw, &object); err != nil {
			return result, fmt.Errorf("dependency artifact %q line %d: %w", input.Path, lineNo, err)
		}
		kind, ok := semanticString(object, "row_kind")
		if !ok || !isCanonicalValidationProfileIdentity(kind) {
			return result, fmt.Errorf("dependency artifact %q line %d has no canonical row_kind", input.Path, lineNo)
		}
		result.byKind[kind] = append(result.byKind[kind], dependencySemanticRow{line: lineNo, raw: raw, kind: kind, data: object})
	}
	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("scan dependency artifact %q: %w", input.Path, err)
	}
	if len(result.byKind["artifact_manifest"]) != 1 || len(result.byKind["validation_summary"]) != 1 {
		return result, fmt.Errorf("dependency artifact %q requires exactly one artifact_manifest and one validation_summary", input.Path)
	}
	return result, nil
}

func stringSliceSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func validateProfileSemanticRows(rows dependencySemanticRows, ood oodContract) error {
	roles, constraints, families, eligibleSubjects, err := normalizeOODContract(ood)
	if err != nil {
		return err
	}
	actualRoles := map[string]struct{}{}
	const roleSourcePath = "sections.s2_graph_object_model.api_symbol_role_registry.roles"
	for _, row := range rows.byKind["api_element_role"] {
		role, roleOK := semanticString(row.data, "api_element_role")
		objectClass, classOK := semanticString(row.data, "object_class")
		binding, bindingOK := semanticString(row.data, "role_binding_authority")
		path, pathOK := semanticString(row.data, "source_field_path")
		symbolKindAuthority, authorityOK := semanticBool(row.data, "symbol_kind_authority")
		if !roleOK || !classOK || objectClass != "api_symbol" || !bindingOK || binding != ood.Sections.ObjectModel.Roles.AuthorityRule || !pathOK || path != roleSourcePath || !authorityOK || symbolKindAuthority {
			return semanticRowError(rows, row, "api_element_role row is incomplete or does not bind one authoritative api_symbol role")
		}
		if _, duplicate := actualRoles[role]; duplicate {
			return semanticRowError(rows, row, "duplicate api_element_role %q", role)
		}
		actualRoles[role] = struct{}{}
	}
	if err := requireExactSet("provider-neutral profile api_element_role registry", actualRoles, roles); err != nil {
		return err
	}

	actualRelationships := map[string]struct{}{}
	const relationshipSourcePath = "sections.s4_edge_model.api_relationship_contract.labels_and_role_constraints"
	for _, row := range rows.byKind["api_relationship"] {
		label, labelOK := semanticString(row.data, "edge_label")
		sourceRole, sourceOK := semanticString(row.data, "source_api_element_role")
		targetRole, targetOK := semanticString(row.data, "target_api_element_role")
		sourceClass, sourceClassOK := semanticString(row.data, "source_object_class")
		targetClass, targetClassOK := semanticString(row.data, "target_object_class")
		providerSpecific, providerOK := semanticBool(row.data, "provider_specific_label_allowed")
		genericSubstitution, substitutionOK := semanticBool(row.data, "generic_references_or_depends_on_substitution_allowed")
		path, pathOK := semanticString(row.data, "source_field_path")
		constraint, exists := constraints[label]
		if !labelOK || !sourceOK || !targetOK || !sourceClassOK || !targetClassOK || sourceClass != "api_symbol" || targetClass != "api_symbol" ||
			!providerOK || providerSpecific != ood.Sections.EdgeModel.Relationships.ProviderSpecificLabelsAllowed || !substitutionOK || genericSubstitution != ood.Sections.EdgeModel.Relationships.ReferencesOrDependsOnSubstitutionAllowed || !pathOK || path != relationshipSourcePath ||
			ood.Sections.EdgeModel.Relationships.Family != "api_relationship" || ood.Sections.EdgeModel.Relationships.SourceClass != sourceClass || ood.Sections.EdgeModel.Relationships.TargetClass != targetClass || ood.Sections.EdgeModel.Relationships.FreeFormSubtypeAllowed || !exists || constraint.SourceRole != sourceRole || constraint.TargetRole != targetRole {
			return semanticRowError(rows, row, "api_relationship %q does not exactly match its OOD endpoint-role constraint", label)
		}
		if _, duplicate := actualRelationships[label]; duplicate {
			return semanticRowError(rows, row, "duplicate api_relationship %q", label)
		}
		actualRelationships[label] = struct{}{}
	}
	if err := requireExactSet("provider-neutral profile api_relationship registry", actualRelationships, constraintsToSet(constraints)); err != nil {
		return err
	}

	actualFamilies := map[string]struct{}{}
	const propertyFamilySourcePath = "sections.s2_graph_object_model.api_property_claim_model.property_families"
	for _, row := range rows.byKind["api_property_family"] {
		family, familyOK := semanticString(row.data, "property_family")
		eligible, eligibleOK := semanticStringSlice(row.data, "eligible_subjects")
		exclusions, exclusionsOK := semanticStringSlice(row.data, "authority_exclusions")
		schemaBinding, schemaOK := semanticBool(row.data, "property_schema_binding_required")
		locatorBinding, locatorOK := semanticBool(row.data, "exact_evidence_locator_manifest_required")
		path, pathOK := semanticString(row.data, "source_field_path")
		if !familyOK || !eligibleOK || len(eligible) == 0 || hasDuplicateStrings(eligible) || !exclusionsOK || hasDuplicateStrings(exclusions) || !equalOrderedStrings(exclusions, ood.Sections.ObjectModel.Properties.AuthorityExclusions) || !schemaOK || !schemaBinding || !locatorOK || !locatorBinding || !pathOK || path != propertyFamilySourcePath {
			return semanticRowError(rows, row, "api_property_family %q is incomplete or weakens schema/evidence binding", family)
		}
		eligibleSet := make(map[string]struct{}, len(eligible))
		for _, subject := range eligible {
			eligibleSet[subject] = struct{}{}
		}
		if err := requireExactSet("provider-neutral profile api_property_family "+family+" eligible_subjects", eligibleSet, eligibleSubjects); err != nil {
			return semanticRowError(rows, row, "%v", err)
		}
		if _, duplicate := actualFamilies[family]; duplicate {
			return semanticRowError(rows, row, "duplicate api_property_family %q", family)
		}
		actualFamilies[family] = struct{}{}
	}
	if err := requireExactSet("provider-neutral profile api_property_family registry", actualFamilies, families); err != nil {
		return err
	}
	return validateProfileSupportingRows(rows, ood)
}

func validateProfileSupportingRows(rows dependencySemanticRows, ood oodContract) error {
	ordinals := map[int64]struct{}{}
	capabilitiesByOrdinal := map[int64]string{}
	const capabilitySourcePath = "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.canonical_ingestion_execution_model.capability_sequence"
	for _, row := range rows.byKind["capability_stage"] {
		ordinal, ordinalOK := semanticInt64(row.data, "ordinal")
		capability, capabilityOK := semanticString(row.data, "capability")
		path, pathOK := semanticString(row.data, "source_field_path")
		mustResolve, resolveOK := semanticBool(row.data, "must_resolve_to_admitted_executable_node")
		providerSpecific, providerOK := semanticBool(row.data, "provider_specific_implementation_allowed")
		if !ordinalOK || ordinal <= 0 || !capabilityOK || !pathOK || path != capabilitySourcePath || !resolveOK || !mustResolve || !providerOK || providerSpecific {
			return semanticRowError(rows, row, "capability_stage is a marker or weakens admitted generic execution")
		}
		if _, duplicate := ordinals[ordinal]; duplicate {
			return semanticRowError(rows, row, "duplicate capability_stage ordinal %d", ordinal)
		}
		ordinals[ordinal] = struct{}{}
		capabilitiesByOrdinal[ordinal] = capability
	}
	if len(ordinals) != len(ood.Sections.GraphMaterialization.ExternalReferenceIngestion.CanonicalIngestionExecutionModel.CapabilitySequence) {
		return fmt.Errorf("provider-neutral profile capability_stage count %d does not equal OOD sequence count %d", len(ordinals), len(ood.Sections.GraphMaterialization.ExternalReferenceIngestion.CanonicalIngestionExecutionModel.CapabilitySequence))
	}
	for ordinal := int64(1); ordinal <= int64(len(ordinals)); ordinal++ {
		if _, ok := ordinals[ordinal]; !ok {
			return fmt.Errorf("provider-neutral profile capability_stage ordinals are not contiguous from 1")
		}
		if got, want := capabilitiesByOrdinal[ordinal], ood.Sections.GraphMaterialization.ExternalReferenceIngestion.CanonicalIngestionExecutionModel.CapabilitySequence[ordinal-1]; got != want {
			return fmt.Errorf("provider-neutral profile capability_stage ordinal %d is %q, want OOD capability %q", ordinal, got, want)
		}
	}
	tables := map[string]struct{}{}
	for _, row := range rows.byKind["canonical_table_surface"] {
		logicalName, logicalOK := semanticString(row.data, "logical_name")
		physicalName, physicalOK := semanticString(row.data, "physical_table_name")
		purpose, purposeOK := semanticString(row.data, "purpose")
		primaryKey, primaryOK := semanticStringSlice(row.data, "primary_key")
		organizationScoped, scopeOK := semanticBool(row.data, "organization_scoped")
		columnCount, countOK := semanticInt64(row.data, "column_count")
		sourcePath, pathOK := semanticString(row.data, "source_field_path")
		loadedFromSpec, loadedOK := semanticBool(row.data, "columns_are_loaded_from_canonical_spec_at_execution")
		if !logicalOK || !physicalOK || !purposeOK || !primaryOK || len(primaryKey) == 0 || hasEmptyOrDuplicateSemanticStrings(primaryKey) || !scopeOK || !organizationScoped || !countOK || columnCount <= 0 || !pathOK || !loadedOK || !loadedFromSpec {
			return semanticRowError(rows, row, "canonical_table_surface is a marker or weakens organization/spec ownership")
		}
		if _, duplicate := tables[logicalName]; duplicate {
			return semanticRowError(rows, row, "duplicate canonical_table_surface logical_name %q", logicalName)
		}
		governing, exists := ood.Sections.StorageModel.TableSurfaces[logicalName]
		expectedPath := "sections.s6_spanner_storage_model.table_surfaces." + logicalName
		if !exists || governing.PhysicalTableName != physicalName || governing.Purpose != purpose || !equalOrderedStrings(governing.PrimaryKey, primaryKey) || int64(len(governing.Columns)) != columnCount || sourcePath != expectedPath {
			return semanticRowError(rows, row, "canonical_table_surface %q does not exactly match the selected OOD descriptor", logicalName)
		}
		if primaryKey[0] != "organization_id" {
			return semanticRowError(rows, row, "canonical_table_surface %q primary key is not organization_id-first", logicalName)
		}
		tables[logicalName] = struct{}{}
	}
	if err := requireExactSet("provider-neutral profile canonical_table_surface registry", tables, stringMapKeysAsSet(ood.Sections.StorageModel.TableSurfaces)); err != nil {
		return err
	}
	for _, item := range []struct {
		kind       string
		field      string
		sourcePath string
		expected   []string
	}{
		{"external_document_object_class", "object_class", "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.object_classes_created", ood.Sections.GraphMaterialization.ExternalReferenceIngestion.ObjectClassesCreated},
		{"external_document_edge_label", "edge_label", "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.edge_labels_created", ood.Sections.GraphMaterialization.ExternalReferenceIngestion.EdgeLabelsCreated},
	} {
		seen := map[string]struct{}{}
		for _, row := range rows.byKind[item.kind] {
			value, valueOK := semanticString(row.data, item.field)
			path, pathOK := semanticString(row.data, "source_field_path")
			if !valueOK || !pathOK || path != item.sourcePath {
				return semanticRowError(rows, row, "%s is a marker", item.kind)
			}
			if _, duplicate := seen[value]; duplicate {
				return semanticRowError(rows, row, "duplicate %s %q", item.field, value)
			}
			seen[value] = struct{}{}
		}
		expected := make(map[string]struct{}, len(item.expected))
		for _, value := range item.expected {
			expected[value] = struct{}{}
		}
		if err := requireExactSet("provider-neutral profile "+item.kind+" registry", seen, expected); err != nil {
			return err
		}
	}
	allowedClasses := stringSliceSet(ood.Sections.GraphMaterialization.ExternalReferenceIngestion.SourceAuthorityPolicy.AllowedSourceClasses)
	forbiddenClasses := stringSliceSet(ood.Sections.GraphMaterialization.ExternalReferenceIngestion.SourceAuthorityPolicy.ForbiddenSourceClasses)
	seenSourceClasses := map[string]struct{}{}
	for _, row := range rows.byKind["source_authority_class"] {
		value, valueOK := semanticString(row.data, "source_class")
		disposition, dispositionOK := semanticString(row.data, "disposition")
		path, pathOK := semanticString(row.data, "source_field_path")
		policyRule, ruleOK := semanticString(row.data, "policy_rule")
		_, allowed := allowedClasses[value]
		_, forbidden := forbiddenClasses[value]
		expectedPath := "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.source_authority_policy.allowed_source_classes"
		expectedDisposition := "requires_exact_binding"
		if forbidden {
			expectedPath = "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.source_authority_policy.forbidden_source_classes"
			expectedDisposition = "forbidden"
		}
		if !valueOK || !dispositionOK || !pathOK || !ruleOK || policyRule != ood.Sections.GraphMaterialization.ExternalReferenceIngestion.SourceAuthorityPolicy.Rule || allowed == forbidden || path != expectedPath || disposition != expectedDisposition {
			return semanticRowError(rows, row, "source_authority_class %q does not exactly project the selected OOD authority class", value)
		}
		if _, duplicate := seenSourceClasses[value]; duplicate {
			return semanticRowError(rows, row, "duplicate source_class %q", value)
		}
		seenSourceClasses[value] = struct{}{}
	}
	expectedSourceClasses := make(map[string]struct{}, len(allowedClasses)+len(forbiddenClasses))
	for value := range allowedClasses {
		expectedSourceClasses[value] = struct{}{}
	}
	for value := range forbiddenClasses {
		expectedSourceClasses[value] = struct{}{}
	}
	if err := requireExactSet("provider-neutral profile source_authority_class registry", seenSourceClasses, expectedSourceClasses); err != nil {
		return err
	}
	for _, kind := range []string{"exact_evidence_locator_profile", "execution_boundary", "external_evidence_lifecycle", "provider_fixture_input_contract", "publication_acceptance_contract", "tenant_scope_contract"} {
		if len(rows.byKind[kind]) != 1 {
			return fmt.Errorf("provider-neutral profile %q requires exactly one %s row", rows.path, kind)
		}
	}
	execution := rows.byKind["execution_boundary"][0]
	entryCapability, entryOK := semanticString(execution.data, "entry_capability")
	executionPath, executionPathOK := semanticString(execution.data, "source_field_path")
	if !entryOK || entryCapability != ood.Sections.GraphMaterialization.ExternalReferenceIngestion.CanonicalIngestionExecutionModel.EntryCapability || !executionPathOK || executionPath != "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.canonical_ingestion_execution_model" {
		return semanticRowError(rows, execution, "execution boundary does not exactly bind the selected OOD entry capability")
	}
	fixture := rows.byKind["provider_fixture_input_contract"][0]
	sourceNeutral, sourceNeutralOK := semanticBool(fixture.data, "source_neutral")
	if !sourceNeutralOK || !sourceNeutral {
		return semanticRowError(rows, fixture, "provider fixture input contract must be source-neutral")
	}
	for _, field := range []string{"authority_bindings", "required_inputs", "provider_adapter_may_supply", "provider_adapter_must_not_own"} {
		values, ok := semanticStringSlice(fixture.data, field)
		if !ok || len(values) == 0 || hasEmptyOrDuplicateSemanticStrings(values) {
			return semanticRowError(rows, fixture, "%s must be a nonempty unique roster", field)
		}
	}
	publication := rows.byKind["publication_acceptance_contract"][0]
	for _, field := range []string{"authority_bindings", "required_proofs"} {
		values, ok := semanticStringSlice(publication.data, field)
		if !ok || len(values) == 0 || hasEmptyOrDuplicateSemanticStrings(values) {
			return semanticRowError(rows, publication, "%s must be a nonempty unique roster", field)
		}
	}
	tenantMinimum, tenantOK := semanticInt64(publication.data, "acceptance_tenant_count_minimum")
	substitution, substitutionOK := semanticBool(publication.data, "source_substitution_required")
	zeroFindings, findingsOK := semanticBool(publication.data, "zero_findings_required")
	if !tenantOK || tenantMinimum < 2 || !substitutionOK || !substitution || !findingsOK || !zeroFindings {
		return semanticRowError(rows, publication, "publication acceptance must require two tenants, source substitution, and zero findings")
	}
	if err := validateProfileSafetyContracts(rows); err != nil {
		return err
	}
	return validateProfileSummaryFromRows(rows)
}

func validateProfileSafetyContracts(rows dependencySemanticRows) error {
	locator := rows.byKind["exact_evidence_locator_profile"][0]
	requiredBeforeFetch, requiredOK := semanticBool(locator.data, "required_before_fetch")
	bodyInGraph, graphBodyOK := semanticBool(locator.data, "body_persistence_in_ood_graph_allowed")
	archiveRequired, archiveOK := semanticBool(locator.data, "durable_exact_byte_archive_required")
	diagnosticAuthority, diagnosticOK := semanticBool(locator.data, "line_heading_dom_accessibility_navigation_or_ai_summary_authority")
	manifestRequired, manifestOK := semanticBool(locator.data, "graph_fact_locator_manifest_required")
	coordinate, coordinateOK := semanticObject(locator.data, "coordinate")
	hashAlgorithm, algorithmOK := semanticString(coordinate, "source_content_hash_algorithm")
	hashProfile, profileOK := semanticString(coordinate, "source_content_hash_profile")
	if !requiredOK || !requiredBeforeFetch || !graphBodyOK || bodyInGraph || !archiveOK || !archiveRequired || !diagnosticOK || diagnosticAuthority || !manifestOK || !manifestRequired || !coordinateOK || !algorithmOK || hashAlgorithm != "sha256" || !profileOK || hashProfile != sourceContentHashProfile {
		return semanticRowError(rows, locator, "exact evidence locator profile weakens pre-fetch, exact-byte, graph-body, coordinate, or diagnostic-authority closure")
	}
	for _, field := range []string{"source_content_sha256", "byte_start_offset", "byte_end_offset_exclusive", "selected_range_byte_count", "selected_range_sha256"} {
		value, ok := semanticString(coordinate, field)
		if !ok || canonicalSemanticToken(value) != "required" {
			return semanticRowError(rows, locator, "coordinate.%s must be the exact required locator field", field)
		}
	}
	for _, check := range []struct{ field, expected string }{
		{"representation_identity_owner", "selected_evidence_metadata"},
		{"provider_evidence_body", "exact source-declared machine-export bytes selected by an admitted representation declaration"},
		{"machine_export_authority_rule", "selected_exact_bytes_only"},
		{"source_origin_authority_rule", "typed_binding_required"},
		{"source_ui_export_rule", "declared_representation_only"},
		{"navigation_aid_rule", "non_authoritative"},
		{"contradiction_behavior", "preserve_and_fail_closed"},
	} {
		value, ok := semanticString(locator.data, check.field)
		if !ok || value != check.expected {
			return semanticRowError(rows, locator, "%s %q does not equal the closed locator posture %q", check.field, value, check.expected)
		}
	}

	lifecycle := rows.byKind["external_evidence_lifecycle"][0]
	identity, identityOK := semanticStringSlice(lifecycle.data, "immutable_evidence_identity")
	requiredMetadata, metadataOK := semanticStringSlice(lifecycle.data, "required_metadata")
	retrievalInIdentity, retrievalOK := semanticBool(lifecycle.data, "retrieved_at_or_observed_at_in_evidence_identity")
	bodyPersistence, persistenceOK := semanticBool(lifecycle.data, "body_persistence_in_ood_graph_allowed")
	byteFaithful, byteFaithfulOK := semanticBool(lifecycle.data, "byte_faithful_archive_required")
	archiveIsIdentity, archiveIdentityOK := semanticBool(lifecycle.data, "archive_record_is_evidence_identity")
	if !identityOK || len(identity) < 2 || hasEmptyOrDuplicateSemanticStrings(identity) || !metadataOK || len(requiredMetadata) < 2 || hasEmptyOrDuplicateSemanticStrings(requiredMetadata) || !retrievalOK || retrievalInIdentity || !persistenceOK || bodyPersistence || !byteFaithfulOK || !byteFaithful || !archiveIdentityOK || archiveIsIdentity {
		return semanticRowError(rows, lifecycle, "external evidence lifecycle weakens immutable identity, receipt freshness, graph-body exclusion, or byte-faithful archive separation")
	}
	if !equalStringSet(identity, []string{"source_coordinate", "content_digest"}) || !equalStringSet(requiredMetadata, []string{"source_coordinate", "content_digest", "record_deletion_domain", "archive_crypto_shred_domain"}) {
		return semanticRowError(rows, lifecycle, "external evidence lifecycle does not bind occurrence receipts, sealed pre-parse completeness, exact successor closure, and separate deletion/crypto-shred domains")
	}
	for _, check := range []struct{ field, expected string }{
		{"fetch_occurrence", "typed_receipt"},
		{"same_bytes_new_fetch", "new_receipt"},
		{"same_occurrence_retry", "same_receipt"},
		{"freshness_source", "receipt"},
		{"pre_parse_completeness", "sealed_selection_roster"},
		{"successor_receipt_closure", "exact_deletion_domain_closure"},
	} {
		value, ok := semanticString(lifecycle.data, check.field)
		if !ok || value != check.expected {
			return semanticRowError(rows, lifecycle, "%s %q does not equal closed lifecycle posture %q", check.field, value, check.expected)
		}
	}

	tenant := rows.byKind["tenant_scope_contract"][0]
	scopeSource, sourceOK := semanticString(tenant.data, "organization_id_source")
	callerScope, callerOK := semanticString(tenant.data, "caller_supplied_organization_id")
	failClosed, failClosedOK := semanticStringSlice(tenant.data, "fail_closed_when_missing")
	predicate, predicateOK := semanticString(tenant.data, "predicate_rule")
	sourceRecordAuthority, sourceRecordOK := semanticObject(tenant.data, "source_record_authority")
	requiredEverywhere, everywhereOK := semanticObject(tenant.data, "organization_id_required_everywhere")
	joinRequired, joinOK := semanticBool(tenant.data, "organization_id_join_key_required")
	siblingCrossTenant, siblingOK := semanticBool(tenant.data, "cross_tenant_sibling_reference_allowed")
	graphCrossTenant, graphOK := semanticBool(tenant.data, "cross_tenant_graph_closure_allowed")
	sourceDocID, sourceDocOK := semanticString(sourceRecordAuthority, "doc_id")
	sourceVersion, sourceVersionOK := semanticString(sourceRecordAuthority, "version")
	sourceDigest, sourceDigestOK := semanticString(sourceRecordAuthority, "raw_sha256")
	profileManifest := rows.byKind["artifact_manifest"][0]
	manifestSourceRecord, manifestSourceOK := semanticObject(profileManifest.data, "source_record_contract")
	manifestDocID, manifestDocOK := semanticString(manifestSourceRecord, "doc_id")
	manifestVersion, manifestVersionOK := semanticString(manifestSourceRecord, "version")
	manifestDigest, manifestDigestOK := semanticString(manifestSourceRecord, "raw_sha256")
	if !sourceOK || scopeSource != "kernel_injected_request_context" || !callerOK || callerScope != "forbidden" || !failClosedOK || !equalStringSet(failClosed, []string{"organization_id"}) || !predicateOK || predicate != "exact_organization_id_equality" || !sourceRecordOK || !sourceDocOK || !sourceVersionOK || !sourceDigestOK || !isLowerSHA256(sourceDigest) || !manifestSourceOK || !manifestDocOK || sourceDocID != manifestDocID || !manifestVersionOK || sourceVersion != manifestVersion || !manifestDigestOK || sourceDigest != manifestDigest || !everywhereOK || !joinOK || !joinRequired || !siblingOK || siblingCrossTenant || !graphOK || graphCrossTenant {
		return semanticRowError(rows, tenant, "tenant scope must be kernel-injected, caller-scope-forbidden, fail closed on organization_id, exact-join-scoped, and cross-tenant closed")
	}
	if err := validateTenantRequiredEverywhereSurfaces(requiredEverywhere); err != nil {
		return semanticRowError(rows, tenant, "%v", err)
	}
	for _, field := range sortedProviderStringMapKeys(requiredEverywhere) {
		value := requiredEverywhere[field]
		required, ok := value.(bool)
		if !ok || !required {
			return semanticRowError(rows, tenant, "organization_id_required_everywhere.%s must be true", field)
		}
	}
	execution := rows.byKind["execution_boundary"][0]
	entryCapability, entryOK := semanticString(execution.data, "entry_capability")
	firstCapability := ""
	for _, row := range rows.byKind["capability_stage"] {
		ordinal, _ := semanticInt64(row.data, "ordinal")
		if ordinal == 1 {
			firstCapability, _ = semanticString(row.data, "capability")
		}
	}
	if !entryOK || entryCapability != firstCapability {
		return semanticRowError(rows, execution, "execution entry_capability does not equal capability_stage ordinal 1")
	}
	for _, check := range []struct{ field, expected string }{
		{"rule", "admitted_capabilities_only"},
		{"external_ingress_executability_rule", "typed_ingress_only"},
		{"http_service_boundary", "adapter_only"},
		{"ring_contract", "preserve_specified_ring_chokepoints"},
		{"graph_source_of_truth_boundary", "derived_graph_only"},
		{"semantic_projection_separation", "post_publication_only"},
	} {
		value, ok := semanticString(execution.data, check.field)
		if !ok || value != check.expected {
			return semanticRowError(rows, execution, "%s %q does not equal closed execution posture %q", check.field, value, check.expected)
		}
	}
	return nil
}

func validateTenantRequiredEverywhereSurfaces(requiredEverywhere map[string]interface{}) error {
	wantTenantSurfaces := stringSliceSet([]string{
		"forge_output_envelopes",
		"forge_request_envelopes",
		"graph_queries",
		"ood_graph_rows",
		"policy_decision_refs",
		"projection_artifacts",
		"property_graph_edge_views",
		"property_graph_node_views",
		"retrieval_outputs",
		"validation_evidence_refs",
		"violations",
	})
	return requireExactSet("tenant organization_id_required_everywhere surfaces", stringMapKeysAsSet(requiredEverywhere), wantTenantSurfaces)
}

func validateProfileSummaryFromRows(rows dependencySemanticRows) error {
	summary := rows.byKind["validation_summary"][0]
	for _, check := range []struct {
		field string
		want  int64
	}{
		{"api_element_role_count", int64(len(rows.byKind["api_element_role"]))},
		{"api_relationship_count", int64(len(rows.byKind["api_relationship"]))},
		{"api_property_family_count", int64(len(rows.byKind["api_property_family"]))},
		{"canonical_capability_stage_count", int64(len(rows.byKind["capability_stage"]))},
		{"canonical_table_surface_count", int64(len(rows.byKind["canonical_table_surface"]))},
		{"external_document_object_class_count", int64(len(rows.byKind["external_document_object_class"]))},
		{"external_document_edge_label_count", int64(len(rows.byKind["external_document_edge_label"]))},
	} {
		got, ok := semanticInt64(summary.data, check.field)
		if !ok || got != check.want {
			return semanticRowError(rows, summary, "%s %d does not equal recomputed row count %d", check.field, got, check.want)
		}
	}
	allowedAuthorities := int64(0)
	forbiddenAuthorities := int64(0)
	for _, row := range rows.byKind["source_authority_class"] {
		disposition, ok := semanticString(row.data, "disposition")
		_, policyOK := semanticString(row.data, "policy_rule")
		if !ok || !policyOK {
			return semanticRowError(rows, row, "source authority row must carry operative disposition and policy")
		}
		switch disposition {
		case "forbidden":
			forbiddenAuthorities++
		case "requires_exact_binding":
			allowedAuthorities++
		default:
			return semanticRowError(rows, row, "source authority disposition %q is outside the closed registry", disposition)
		}
	}
	for _, check := range []struct {
		field string
		want  int64
	}{{"source_authority_allowed_class_count", allowedAuthorities}, {"source_authority_forbidden_class_count", forbiddenAuthorities}} {
		got, ok := semanticInt64(summary.data, check.field)
		if !ok || got != check.want {
			return semanticRowError(rows, summary, "%s %d does not equal recomputed source-authority count %d", check.field, got, check.want)
		}
	}
	organizationInjected, organizationOK := semanticBool(summary.data, "organization_id_kernel_injected")
	providerGo, providerGoOK := semanticBool(summary.data, "provider_specific_go_required")
	kernelGo, kernelGoOK := semanticBool(summary.data, "kernel_go_required")
	admittedExecution, executionOK := semanticBool(summary.data, "canonical_execution_is_admitted_nodes")
	ready, readyOK := semanticBool(summary.data, "ready_to_execute")
	blockers, blockersOK := semanticStringSlice(summary.data, "execution_blockers")
	if !organizationOK || !organizationInjected || !providerGoOK || providerGo || !kernelGoOK || kernelGo || !executionOK || !admittedExecution || !readyOK || ready || !blockersOK || len(blockers) == 0 || hasEmptyOrDuplicateSemanticStrings(blockers) {
		return semanticRowError(rows, summary, "profile validation summary does not equal recomputed source-neutral, kernel-scoped, blocked candidate posture")
	}
	return nil
}

type sourceContractSemanticState struct {
	documentsByIdentity     map[evidenceBodyIdentity]dependencySemanticRow
	classificationsBySymbol map[string][]sourceClassificationOccurrence
	resourceSymbols         map[string]struct{}
	fieldsByIdentity        map[string]dependencySemanticRow
	operationAccesses       map[string][]sourceOperationResourceAccess
}

type sourceOperationResourceAccess struct {
	resourceSourceSymbol        string
	relationshipLabel           string
	evidenceLocatorIDs          []string
	documentationDerivedFactIDs []string
}

func sortedStringSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sourceOperationAccessOccurrenceIdentity(operationKey string, access sourceOperationResourceAccess, plan *parsedPlan) string {
	parts := []string{operationKey, access.resourceSourceSymbol, access.relationshipLabel}
	for _, locatorID := range access.evidenceLocatorIDs {
		locator, exists := plan.Locators[locatorID]
		if !exists {
			parts = append(parts, "missing_locator", locatorID)
			continue
		}
		parts = append(parts, locatorID, candidateEvidenceLocatorIdentityKey(locator))
	}
	parts = append(parts, access.documentationDerivedFactIDs...)
	return semanticIdentity(parts...)
}

func parseSourceOperationEvidenceOccurrences(row map[string]interface{}, plan *parsedPlan, classifications []sourceClassificationOccurrence, surfaceKind string) (map[string]struct{}, map[string]string, error) {
	objects, ok := semanticObjectSlice(row, "operation_evidence_occurrences")
	if !ok || len(objects) == 0 {
		return nil, nil, fmt.Errorf("operation_evidence_occurrences is not a nonempty typed roster")
	}
	locatorIDs := map[string]struct{}{}
	factToLocator := map[string]string{}
	seenOccurrenceIDs := map[string]struct{}{}
	previousID := ""
	for index, object := range objects {
		occurrenceID, occurrenceOK := semanticString(object, "occurrence_id")
		locatorID, locatorOK := semanticString(object, "evidence_locator_id")
		factID, factOK := semanticString(object, "documentation_derived_fact_id")
		locator, exists := plan.Locators[locatorID]
		if !occurrenceOK || !locatorOK || !factOK || !exists || !canonicalEvidenceMetadataString(factID, 512) {
			return nil, nil, fmt.Errorf("operation_evidence_occurrences[%d] has an incomplete occurrence/fact/locator coordinate", index)
		}
		if len(locator.SourceRefs) != 1 || len(locator.SourceURLs) != 1 || !isLowerSHA256(locator.EvidenceManifestSHA256) || !isLowerSHA256(locator.SourceContentSHA256) || !isLowerSHA256(locator.SelectedRangeSHA256) || locator.ByteStartOffset < 0 || locator.ByteEndOffsetExclusive <= locator.ByteStartOffset || locator.SelectedRangeByteCount != locator.ByteEndOffsetExclusive-locator.ByteStartOffset {
			return nil, nil, fmt.Errorf("operation_evidence_occurrences[%d] locator %q is not one exact full manifest/ref/url/body/range coordinate", index, locatorID)
		}
		expectedID := stableID("opocc", lengthPrefixedIdentityKey(factID, locatorID, candidateEvidenceLocatorIdentityKey(locator)))
		if occurrenceID != expectedID {
			return nil, nil, fmt.Errorf("operation_evidence_occurrences[%d] occurrence_id is not content-derived from its exact fact and full locator coordinate", index)
		}
		if previousID != "" && occurrenceID <= previousID {
			return nil, nil, fmt.Errorf("operation_evidence_occurrences is not sorted by occurrence_id")
		}
		previousID = occurrenceID
		if _, duplicate := seenOccurrenceIDs[occurrenceID]; duplicate {
			return nil, nil, fmt.Errorf("operation_evidence_occurrences duplicates occurrence_id %q", occurrenceID)
		}
		if _, duplicate := factToLocator[factID]; duplicate {
			return nil, nil, fmt.Errorf("operation_evidence_occurrences aliases documentation-derived fact %q", factID)
		}
		coverage := 0
		for _, classification := range classifications {
			classified := classification.Locator
			if classification.SurfaceKind == surfaceKind && classified.SourceContentSHA256 == locator.SourceContentSHA256 && len(classified.SourceRefs) == 1 && len(locator.SourceRefs) == 1 && classified.SourceRefs[0] == locator.SourceRefs[0] && len(classified.SourceURLs) == 1 && len(locator.SourceURLs) == 1 && classified.SourceURLs[0] == locator.SourceURLs[0] && locator.ByteStartOffset >= classified.ByteStartOffset && locator.ByteEndOffsetExclusive <= classified.ByteEndOffsetExclusive {
				coverage++
			}
		}
		if coverage != 1 {
			return nil, nil, fmt.Errorf("operation_evidence_occurrences[%d] locator %q resolves %d covering classification occurrences, want 1", index, locatorID, coverage)
		}
		seenOccurrenceIDs[occurrenceID] = struct{}{}
		locatorIDs[locatorID] = struct{}{}
		factToLocator[factID] = locatorID
	}
	return locatorIDs, factToLocator, nil
}

func validateSourceContractSemanticRows(rows dependencySemanticRows, plan *parsedPlan, ood oodContract, loaded loadedEvidence, operationApplicability *operationApplicabilityState, apiApplicability apiGraphApplicabilityState) (sourceContractSemanticState, error) {
	state := sourceContractSemanticState{documentsByIdentity: map[evidenceBodyIdentity]dependencySemanticRow{}, classificationsBySymbol: map[string][]sourceClassificationOccurrence{}, resourceSymbols: map[string]struct{}{}, fieldsByIdentity: map[string]dependencySemanticRow{}, operationAccesses: map[string][]sourceOperationResourceAccess{}}
	_, relationshipConstraints, _, _, err := normalizeOODContract(ood)
	if err != nil {
		return state, err
	}
	sourceContractMetadata := map[evidenceBodyIdentity]evidenceBodyMetadata{}
	for _, coordinate := range sortedEvidenceSourceCoordinates(loaded.MetadataByCoordinate) {
		metadata := loaded.MetadataByCoordinate[coordinate]
		if _, selected := metadata.ConsumerRoles["source_contract_index"]; !selected {
			continue
		}
		if coordinate.Ref != metadata.SourceRef || coordinate.URL != metadata.SourceURL || metadata.SourceRef == "" || metadata.SourceURL == "" || metadata.Representation == "" || metadata.RepresentationCoordinate == "" || metadata.SourceRepresentationKind == "" || metadata.ComponentByteDomainProfile != componentByteDomainProfile || metadata.SourceContentHashProfile != sourceContentHashProfile || !isLowerSHA256(metadata.ManifestSHA256) || !isLowerSHA256(metadata.ContentSHA256) || metadata.ContentBytes <= 0 {
			return state, fmt.Errorf("source-contract evidence coordinate ref=%q url=%q has incomplete or inconsistent document metadata", coordinate.Ref, coordinate.URL)
		}
		identity := evidenceBodyIdentity{ManifestSHA256: metadata.ManifestSHA256, SourceRef: metadata.SourceRef, ContentSHA256: metadata.ContentSHA256}
		if _, duplicate := sourceContractMetadata[identity]; duplicate {
			return state, fmt.Errorf("source-contract evidence metadata duplicates document identity %+v", identity)
		}
		sourceContractMetadata[identity] = metadata
	}
	classifiedDocumentIdentities := map[string]struct{}{}
	for _, symbol := range sortedProviderStringMapKeys(loaded.ClassificationsBySourceSymbol) {
		occurrences := loaded.ClassificationsBySourceSymbol[symbol]
		for _, occurrence := range occurrences {
			if occurrence.SourceSymbol != symbol || occurrence.SurfaceKind == "" || len(occurrence.Locator.SourceRefs) != 1 || len(occurrence.Locator.SourceURLs) != 1 {
				return state, fmt.Errorf("source classification occurrence for %q is incomplete", symbol)
			}
			metadata, exists := loaded.MetadataByCoordinate[evidenceSourceCoordinate{Ref: occurrence.Locator.SourceRefs[0], URL: occurrence.Locator.SourceURLs[0]}]
			if !exists {
				return state, fmt.Errorf("source classification occurrence for %q resolves no selected document", symbol)
			}
			if _, selected := metadata.ConsumerRoles["source_contract_index"]; !selected {
				continue
			}
			if occurrence.Locator.SourceContentSHA256 != metadata.ContentSHA256 || occurrence.Locator.EvidenceManifestSHA256 != metadata.ManifestSHA256 {
				return state, fmt.Errorf("source classification occurrence for %q does not bind its exact selected document", symbol)
			}
			classifiedDocumentIdentities[lengthPrefixedIdentityKey(metadata.ManifestSHA256, metadata.SourceRef, metadata.ContentSHA256)] = struct{}{}
			state.classificationsBySymbol[symbol] = append(state.classificationsBySymbol[symbol], occurrence)
		}
	}
	if len(state.classificationsBySymbol) == 0 {
		return state, fmt.Errorf("source-contract selection has no occurrence-backed semantic source symbols")
	}
	expectedClassifiedDocuments := make(map[string]struct{}, len(sourceContractMetadata))
	for _, identity := range sortedEvidenceBodyIdentityKeys(sourceContractMetadata) {
		expectedClassifiedDocuments[lengthPrefixedIdentityKey(identity.ManifestSHA256, identity.SourceRef, identity.ContentSHA256)] = struct{}{}
	}
	if err := requireExactSet("source-contract selected documents reached by classification occurrences", classifiedDocumentIdentities, expectedClassifiedDocuments); err != nil {
		return state, err
	}
	for _, row := range rows.byKind["source_document"] {
		manifestSHA, manifestOK := semanticString(row.data, "evidence_manifest_sha256")
		sourceRef, refOK := semanticString(row.data, "source_ref")
		sourceURL, urlOK := semanticString(row.data, "source_url")
		contentDigest, digestOK := semanticString(row.data, "content_sha256")
		contentBytes, bytesOK := semanticInt64(row.data, "content_bytes")
		representation, representationOK := semanticString(row.data, "representation")
		representationCoordinate, representationCoordinateOK := semanticString(row.data, "representation_coordinate")
		sourceRepresentationKind, sourceRepresentationKindOK := semanticString(row.data, "source_representation_kind")
		componentByteDomainProfile, componentProfileOK := semanticString(row.data, "component_byte_domain_profile")
		contentHashProfile, hashProfileOK := semanticString(row.data, "source_content_hash_profile")
		_, lineProfileOK := semanticString(row.data, "observed_line_delimiter_profile")
		if !manifestOK || !refOK || !urlOK || !digestOK || !bytesOK || contentBytes <= 0 || !representationOK || !representationCoordinateOK || !sourceRepresentationKindOK || !componentProfileOK || !hashProfileOK || !lineProfileOK {
			return state, semanticRowError(rows, row, "source_document is a marker or has incomplete identity/evidence fields")
		}
		identity := evidenceBodyIdentity{ManifestSHA256: manifestSHA, SourceRef: sourceRef, ContentSHA256: contentDigest}
		if _, duplicate := state.documentsByIdentity[identity]; duplicate {
			return state, semanticRowError(rows, row, "duplicate source_document identity %+v", identity)
		}
		metadata, metadataOK := sourceContractMetadata[identity]
		if !metadataOK {
			return state, semanticRowError(rows, row, "source_document has no exact source-contract-role document identity")
		}
		if metadata.SourceURL != sourceURL || metadata.ContentBytes != contentBytes || metadata.Representation != representation || metadata.RepresentationCoordinate != representationCoordinate || metadata.SourceRepresentationKind != sourceRepresentationKind || metadata.ComponentByteDomainProfile != componentByteDomainProfile || metadata.SourceContentHashProfile != contentHashProfile || contentHashProfile != sourceContentHashProfile {
			return state, semanticRowError(rows, row, "source_document fields do not exactly equal their roster-bound source-contract evidence metadata")
		}
		coordinate, err := validateRowHydration(rows, row, loaded)
		if err != nil {
			return state, err
		}
		if coordinate.start != 0 || coordinate.end != contentBytes || coordinate.count != contentBytes || coordinate.rangeSHA != contentDigest {
			return state, semanticRowError(rows, row, "source_document hydration coordinate is not the exact complete selected evidence body")
		}
		state.documentsByIdentity[identity] = row
	}
	if len(state.documentsByIdentity) != len(sourceContractMetadata) {
		return state, fmt.Errorf("source_document identity count %d does not equal exact source-contract-role selected-document count %d", len(state.documentsByIdentity), len(sourceContractMetadata))
	}
	for _, identity := range sortedEvidenceBodyIdentityKeys(sourceContractMetadata) {
		if _, ok := state.documentsByIdentity[identity]; !ok {
			return state, fmt.Errorf("source_document roster is missing exact selected document %+v", identity)
		}
	}

	if operationApplicability == nil {
		return state, fmt.Errorf("source-contract semantic validation requires the exact operation applicability state")
	}
	actualResources := map[string]apiSymbol{}
	matchedResourceIDs := map[string]struct{}{}
	for _, sourceSymbol := range sortedProviderStringMapKeys(state.classificationsBySymbol) {
		symbolID, bound := loaded.CandidateSymbolsBySourceSymbol[sourceSymbol]
		if !bound {
			continue
		}
		symbol, exists := plan.Symbols[symbolID]
		if !exists {
			return state, fmt.Errorf("typed source symbol %q resolves absent candidate API symbol %q", sourceSymbol, symbolID)
		}
		if symbol.Role != "resource" {
			continue
		}
		actualResources[sourceSymbol] = symbol
		state.resourceSymbols[sourceSymbol] = struct{}{}
		matchedResourceIDs[symbol.ID] = struct{}{}
	}
	for _, resourceID := range sortedProviderStringMapKeys(operationApplicability.resourceSourceSymbolsByID) {
		sourceSymbol := operationApplicability.resourceSourceSymbolsByID[resourceID]
		typedSymbolID, typed := loaded.CandidateSymbolsBySourceSymbol[sourceSymbol]
		if !typed {
			return state, fmt.Errorf("operation-profile resource binding %q names source symbol %q without a sealed typed API-symbol derivation", resourceID, sourceSymbol)
		}
		resource, classified := actualResources[sourceSymbol]
		if !classified || resource.ID != resourceID || typedSymbolID != resourceID {
			return state, fmt.Errorf("operation-profile resource binding %q retargets typed source symbol %q away from exact plan resource %q", resourceID, sourceSymbol, typedSymbolID)
		}
	}
	for _, id := range sortedProviderStringMapKeys(plan.Symbols) {
		symbol := plan.Symbols[id]
		if symbol.Role != "resource" {
			continue
		}
		if _, matched := matchedResourceIDs[id]; matched {
			continue
		}
		semanticIdentity, bound := operationApplicability.resourceBindingsByID[id]
		sourceSymbol, sourceBound := operationApplicability.resourceSourceSymbolsByID[id]
		if !bound || !sourceBound || semanticIdentity != symbol.SemanticKey || sourceSymbol == "" {
			return state, fmt.Errorf("plan resource %s is neither an exact source_document materialization nor an operation-profile resource binding", id)
		}
	}

	expectedOperations := map[string][]dependencySemanticRow{}
	actualOperations := map[string]apiSymbol{}
	accessesByOperation := map[string]map[string]sourceOperationResourceAccess{}
	factOccurrenceOwners := map[string]string{}
	accessSemanticsPresent := false
	accessSemanticsAbsent := false
	for _, row := range rows.byKind["api_operation"] {
		if _, err := validateRowHydration(rows, row, loaded); err != nil {
			return state, err
		}
		sourceSymbol, symbolOK := semanticString(row.data, "source_symbol")
		surfaceKind, surfaceOK := semanticString(row.data, "surface_kind")
		_, refOK := semanticString(row.data, "source_ref")
		_, urlOK := semanticString(row.data, "source_url")
		sourceOperationIdentity, identityErr := parseSourceOperationIdentity(row.data)
		if !symbolOK || !surfaceOK || !refOK || !urlOK || identityErr != nil {
			return state, semanticRowError(rows, row, "api_operation is a marker or has incomplete semantic identity")
		}
		if _, exists := state.classificationsBySymbol[sourceSymbol]; !exists {
			return state, semanticRowError(rows, row, "api_operation source_symbol %q has no selected classification occurrence", sourceSymbol)
		}
		if count := sourceClassificationOccurrenceCoverageCount(state.classificationsBySymbol[sourceSymbol], row.data); count != 1 {
			return state, semanticRowError(rows, row, "api_operation source_symbol %q resolves %d covering classification occurrences, want 1", sourceSymbol, count)
		}
		key, err := sourceOperationSemanticKey(sourceSymbol, sourceOperationIdentity)
		if err != nil {
			return state, semanticRowError(rows, row, "api_operation semantic identity: %v", err)
		}
		if len(expectedOperations[key]) != 0 {
			return state, semanticRowError(rows, row, "duplicates semantic api_operation %q instead of consolidating exact evidence into operation_evidence_occurrences", key)
		}
		occurrenceLocatorIDs, occurrenceFactToLocator, occurrenceErr := parseSourceOperationEvidenceOccurrences(row.data, plan, state.classificationsBySymbol[sourceSymbol], surfaceKind)
		if occurrenceErr != nil {
			return state, semanticRowError(rows, row, "%v", occurrenceErr)
		}
		entry, exists := operationApplicability.bySemanticIdentity[key]
		if !exists {
			return state, semanticRowError(rows, row, "api_operation semantic identity %q has no exact operation applicability entry", key)
		}
		typedOperationID, typed := loaded.CandidateSymbolsBySourceSymbol[sourceSymbol]
		if !typed || typedOperationID != entry.operationID {
			return state, semanticRowError(rows, row, "api_operation source_symbol %q does not resolve to applicability operation %q through the sealed typed API-symbol index", sourceSymbol, entry.operationID)
		}
		identityEqual, identityEqualErr := equalCanonicalSourceOperationIdentities(entry.sourceIdentity, sourceOperationIdentity)
		if identityEqualErr != nil || !identityEqual || entry.sourceSymbol != sourceSymbol {
			return state, semanticRowError(rows, row, "operation applicability source identity does not equal the source-contract api_operation: %v", identityEqualErr)
		}
		operationSymbol, exists := plan.Symbols[entry.operationID]
		if !exists || operationSymbol.Role != "operation" || operationSymbol.SemanticKey != key {
			return state, semanticRowError(rows, row, "operation applicability entry does not resolve the exact plan operation")
		}
		if prior, present := actualOperations[key]; present && prior.ID != operationSymbol.ID {
			return state, semanticRowError(rows, row, "semantic operation %q aliases candidate operation symbols %q and %q", key, prior.ID, operationSymbol.ID)
		}
		actualOperations[key] = operationSymbol
		operationApplicability.sourceContractOperationIDs[entry.operationID] = struct{}{}
		accessRows, accessesOK := semanticObjectSlice(row.data, "resource_accesses")
		if _, present := row.data["resource_accesses"]; present {
			accessSemanticsPresent = true
			if !accessesOK || len(accessRows) == 0 {
				return state, semanticRowError(rows, row, "api_operation resource_accesses must be a nonempty typed roster when selected by its schema")
			}
		} else {
			accessSemanticsAbsent = true
		}
		seenAccesses := map[string]struct{}{}
		rowLocatorUnion := map[string]struct{}{}
		rowFactUnion := map[string]struct{}{}
		for index, accessRow := range accessRows {
			resourceSymbol, resourceOK := semanticString(accessRow, "source_symbol")
			label, labelOK := semanticString(accessRow, "relationship_label")
			constraint, constraintOK := relationshipConstraints[label]
			if !resourceOK || !labelOK || !constraintOK || constraint.SourceRole != "operation" || constraint.TargetRole != "resource" {
				return state, semanticRowError(rows, row, "resource_accesses[%d] does not name an OOD operation-to-resource relationship", index)
			}
			if _, exists := state.classificationsBySymbol[resourceSymbol]; !exists {
				return state, semanticRowError(rows, row, "resource_accesses[%d] names unknown source resource %q", index, resourceSymbol)
			}
			locatorSet, factSet, evidenceErr := parseSourceOperationAccessEvidence(accessRow)
			if evidenceErr != nil {
				return state, semanticRowError(rows, row, "resource_accesses[%d] evidence: %v", index, evidenceErr)
			}
			locatorIDs := sortedStringSet(locatorSet)
			factIDs := sortedStringSet(factSet)
			for _, locatorID := range locatorIDs {
				if _, exists := occurrenceLocatorIDs[locatorID]; !exists {
					return state, semanticRowError(rows, row, "resource_accesses[%d] locator %q is absent from operation_evidence_occurrences", index, locatorID)
				}
				rowLocatorUnion[locatorID] = struct{}{}
			}
			accessLocatorHasFact := map[string]struct{}{}
			for _, factID := range factIDs {
				locatorID, exists := occurrenceFactToLocator[factID]
				if !exists {
					return state, semanticRowError(rows, row, "resource_accesses[%d] fact %q is absent from operation_evidence_occurrences", index, factID)
				}
				if _, selected := locatorSet[locatorID]; !selected {
					return state, semanticRowError(rows, row, "resource_accesses[%d] fact %q pairs with unselected locator %q", index, factID, locatorID)
				}
				accessLocatorHasFact[locatorID] = struct{}{}
				rowFactUnion[factID] = struct{}{}
			}
			if !stringSetsEqual(accessLocatorHasFact, locatorSet) {
				return state, semanticRowError(rows, row, "resource_accesses[%d] locator/fact roster is not pair-complete", index)
			}
			accessIdentity := semanticIdentity(resourceSymbol, label)
			if _, duplicate := seenAccesses[accessIdentity]; duplicate {
				return state, semanticRowError(rows, row, "resource_accesses duplicates resource %q label %q", resourceSymbol, label)
			}
			seenAccesses[accessIdentity] = struct{}{}
			access := sourceOperationResourceAccess{resourceSourceSymbol: resourceSymbol, relationshipLabel: label, evidenceLocatorIDs: locatorIDs, documentationDerivedFactIDs: factIDs}
			owner := sourceOperationAccessOccurrenceIdentity(key, access, plan)
			for _, factID := range factIDs {
				if prior, duplicate := factOccurrenceOwners[factID]; duplicate && prior != owner {
					return state, semanticRowError(rows, row, "documentation-derived fact %q aliases distinct operation access occurrences", factID)
				}
				factOccurrenceOwners[factID] = owner
			}
			if accessesByOperation[key] == nil {
				accessesByOperation[key] = map[string]sourceOperationResourceAccess{}
			}
			accessesByOperation[key][accessIdentity] = access
		}
		if !stringSetsEqual(rowLocatorUnion, occurrenceLocatorIDs) || !stringSetsEqual(rowFactUnion, stringMapKeysAsSet(occurrenceFactToLocator)) {
			return state, semanticRowError(rows, row, "resource access locator/fact union does not equal operation_evidence_occurrences")
		}
		expectedOperations[key] = append(expectedOperations[key], row)
	}
	if accessSemanticsPresent && accessSemanticsAbsent {
		return state, fmt.Errorf("source-contract api_operation rows mix schemas with and without typed resource-access semantics")
	}
	if err := requireSemanticKeySet("api_operation to operation-profile plan materialization", actualOperations, expectedOperations); err != nil {
		return state, err
	}
	for _, key := range sortedProviderStringMapKeys(expectedOperations) {
		entry := operationApplicability.bySemanticIdentity[key]
		expectedAccesses := accessesByOperation[key]
		actualSourceAccesses := map[string]operationResourceAccess{}
		for _, access := range entry.resourceAccesses {
			if access.classifierInputBinding.artifactRole != operationClassifierSourceArtifactRole {
				continue
			}
			accessIdentity := semanticIdentity(access.resourceSourceSymbol, access.relationshipLabel)
			if _, duplicate := actualSourceAccesses[accessIdentity]; duplicate {
				return state, fmt.Errorf("operation %q duplicates source-contract access %q", key, accessIdentity)
			}
			actualSourceAccesses[accessIdentity] = access
		}
		if err := requireExactSet("operation "+key+" source access partition", stringMapKeysAsSet(actualSourceAccesses), stringMapKeysAsSet(expectedAccesses)); err != nil {
			return state, err
		}
		accessIdentities := make([]string, 0, len(expectedAccesses))
		for accessIdentity := range expectedAccesses {
			accessIdentities = append(accessIdentities, accessIdentity)
		}
		sort.Strings(accessIdentities)
		for _, accessIdentity := range accessIdentities {
			expected := expectedAccesses[accessIdentity]
			actual := actualSourceAccesses[accessIdentity]
			if !stringSetsEqual(stringSliceSet(expected.evidenceLocatorIDs), actual.evidenceLocatorIDs) || !stringSetsEqual(stringSliceSet(expected.documentationDerivedFactIDs), actual.evidenceFactIDs) {
				return state, fmt.Errorf("operation %q source access %q does not equal its consolidated exact locator/fact occurrence manifest", key, accessIdentity)
			}
			state.operationAccesses[key] = append(state.operationAccesses[key], expected)
		}
	}
	if accessSemanticsPresent {
		expectedAccessEdges := map[string]sourceOperationResourceAccess{}
		expectedAccessRelationshipIDs := map[string]string{}
		expectedAccessOperationIDs := map[string]string{}
		expectedAccessLabels := map[string]string{}
		for _, operationKey := range sortedProviderStringMapKeys(state.operationAccesses) {
			accesses := state.operationAccesses[operationKey]
			operationSymbol := actualOperations[operationKey]
			operationRows := expectedOperations[operationKey]
			if len(operationRows) == 0 {
				return state, fmt.Errorf("operation %q has no exact occurrence row", operationKey)
			}
			for _, access := range accesses {
				resourceSymbol, resourceExists := actualResources[access.resourceSourceSymbol]
				if !resourceExists {
					return state, semanticRowError(rows, operationRows[0], "resource access names source resource %q without an exact plan materialization", access.resourceSourceSymbol)
				}
				edgeIdentity := semanticIdentity(access.relationshipLabel, operationSymbol.ID, resourceSymbol.ID)
				expectedAccessEdges[edgeIdentity] = access
				expectedAccessRelationshipIDs[edgeIdentity] = stableID("capi_rel", lengthPrefixedIdentityKey(access.relationshipLabel, operationSymbol.ID, resourceSymbol.ID))
				expectedAccessOperationIDs[edgeIdentity] = operationSymbol.ID
				expectedAccessLabels[edgeIdentity] = access.relationshipLabel
			}
		}
		actualAccessEdges := map[string]apiRelationship{}
		for _, relationshipID := range sortedProviderStringMapKeys(plan.Relationships) {
			relationship := plan.Relationships[relationshipID]
			sourceSymbol, sourceExists := plan.Symbols[relationship.SourceID]
			targetSymbol, targetExists := plan.Symbols[relationship.TargetID]
			constraint, constraintExists := relationshipConstraints[relationship.Label]
			if !sourceExists || !targetExists || !constraintExists || constraint.SourceRole != "operation" || constraint.TargetRole != "resource" || sourceSymbol.Role != "operation" || targetSymbol.Role != "resource" {
				continue
			}
			if _, sourceContractOperation := operationApplicability.sourceContractOperationIDs[sourceSymbol.ID]; !sourceContractOperation {
				continue
			}
			identity := semanticIdentity(relationship.Label, relationship.SourceID, relationship.TargetID)
			if _, duplicate := actualAccessEdges[identity]; duplicate {
				return state, fmt.Errorf("plan duplicates typed operation-to-resource access %q", identity)
			}
			actualAccessEdges[identity] = relationship
		}
		coveredAccessEdges := make(map[string]apiRelationship, len(actualAccessEdges))
		for _, identity := range sortedProviderStringMapKeys(actualAccessEdges) {
			relationship := actualAccessEdges[identity]
			coveredAccessEdges[identity] = relationship
		}
		for _, identity := range sortedProviderStringMapKeys(expectedAccessRelationshipIDs) {
			expectedRelationshipID := expectedAccessRelationshipIDs[identity]
			if _, materialized := actualAccessEdges[identity]; materialized {
				continue
			}
			for _, gapID := range sortedProviderStringMapKeys(plan.Gaps) {
				gap := plan.Gaps[gapID]
				if gap.BlockedSubjectKind == "api_symbol_object" && gap.BlockedSubjectID == expectedAccessOperationIDs[identity] && gap.BlockedClaimKind == "api_relationship" && gap.BlockedClaimID == expectedRelationshipID {
					rule, exists := apiApplicability.relationshipByLabel[expectedAccessLabels[identity]]
					if !exists || gap.ApplicabilityRuleID != rule.id {
						continue
					}
					coveredAccessEdges[identity] = apiRelationship{}
					break
				}
			}
		}
		if err := requireSemanticKeySet("evidence-derived operation-to-resource access or matching typed gap", coveredAccessEdges, expectedAccessEdges); err != nil {
			return state, err
		}
		for _, identity := range sortedProviderStringMapKeys(expectedAccessEdges) {
			access := expectedAccessEdges[identity]
			if _, materialized := actualAccessEdges[identity]; !materialized {
				continue
			}
			actualLocatorIDs := actualAccessEdges[identity].LocatorIDs
			if hasEmptyOrDuplicateSemanticStrings(actualLocatorIDs) || !strictlyIncreasingStrings(actualLocatorIDs) || !stringSetsEqual(stringSliceSet(actualLocatorIDs), stringSliceSet(access.evidenceLocatorIDs)) {
				return state, fmt.Errorf("plan operation-to-resource access %q locator roster does not equal its exact access claim roster", identity)
			}
		}
	}

	for _, kind := range []string{"section_index", "field_contract", "documentation_table_row"} {
		for _, row := range rows.byKind[kind] {
			if _, err := validateRowHydration(rows, row, loaded); err != nil {
				return state, err
			}
			symbol, ok := semanticString(row.data, "source_symbol")
			if !ok {
				return state, semanticRowError(rows, row, "%s is missing source_symbol", kind)
			}
			occurrences, exists := state.classificationsBySymbol[symbol]
			if !exists {
				return state, semanticRowError(rows, row, "%s source_symbol %q has no selected classification occurrence", kind, symbol)
			}
			if count := sourceClassificationOccurrenceCoverageCount(occurrences, row.data); count != 1 {
				return state, semanticRowError(rows, row, "%s source_symbol %q resolves %d covering classification occurrences, want 1", kind, symbol, count)
			}
			if kind == "field_contract" {
				numeric, ok := semanticObject(row.data, "numeric_disposition")
				if !ok {
					return state, semanticRowError(rows, row, "field_contract numeric_disposition is missing")
				}
				numericSemantics, numericOK := semanticString(numeric, "numeric_semantics")
				carrier, carrierOK := semanticString(numeric, "authoritative_carrier")
				computationPath, computationOK := semanticString(numeric, "computation_path")
				floatAuthority, floatOK := semanticBool(numeric, "binary_float_authoritative")
				if !numericOK || !carrierOK || !computationOK || !floatOK || floatAuthority {
					return state, semanticRowError(rows, row, "field_contract numeric_disposition is incomplete or asserts binary-float authority")
				}
				if err := validateExactNumericDisposition(numericSemantics, carrier, computationPath); err != nil {
					return state, semanticRowError(rows, row, "field_contract numeric_disposition: %v", err)
				}
				identity, err := sourceFieldOccurrenceIdentity(row.data)
				if err != nil {
					return state, semanticRowError(rows, row, "%v", err)
				}
				if _, duplicate := state.fieldsByIdentity[identity]; duplicate {
					return state, semanticRowError(rows, row, "duplicate field_contract occurrence identity")
				}
				state.fieldsByIdentity[identity] = row
			}
		}
	}
	summary := rows.byKind["validation_summary"][0]
	for _, check := range []struct {
		field string
		want  int64
	}{
		{"expected_source_documents", int64(len(sourceContractMetadata))},
		{"parsed_source_documents", int64(len(state.documentsByIdentity))},
		{"section_count", int64(len(rows.byKind["section_index"]))},
		{"field_contract_count", int64(len(rows.byKind["field_contract"]))},
		{"documentation_table_row_count", int64(len(rows.byKind["documentation_table_row"]))},
		{"api_operation_count", int64(len(rows.byKind["api_operation"]))},
		{"parse_issue_count", int64(len(rows.byKind["parse_issue"]))},
	} {
		got, ok := semanticInt64(summary.data, check.field)
		if !ok || got != check.want {
			return state, semanticRowError(rows, summary, "%s %d does not equal recomputed value %d", check.field, got, check.want)
		}
	}
	exactCoordinates, exactOK := semanticBool(summary.data, "exact_evidence_hydration_coordinates_present")
	diagnosticAuthority, diagnosticOK := semanticBool(summary.data, "diagnostic_line_and_section_coordinates_are_authority")
	targetsAdmitted, admittedOK := semanticBool(summary.data, "source_neutral_targets_admitted")
	if !exactOK || !exactCoordinates || !diagnosticOK || diagnosticAuthority || !admittedOK || targetsAdmitted {
		return state, semanticRowError(rows, summary, "source summary weakens exact hydration, diagnostic non-authority, or candidate-only target posture")
	}
	return state, nil
}

const (
	sampleParseOutcomeParsed        = "parsed"
	sampleParseOutcomeFailed        = "failed"
	sampleParseOutcomeUnsupported   = "unsupported"
	sampleParseOutcomeNotApplicable = "not_applicable"

	sampleDecoderKindUTF8Strict = "utf8_strict"
	sampleDecoderKindNone       = "none"

	sampleParserKindJSONRFC8259   = "json_rfc8259_use_number"
	sampleParserKindUnsupported   = "unsupported"
	sampleParserKindNotApplicable = "not_applicable"
)

var (
	sampleMediaTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+\-]*/[a-z0-9][a-z0-9!#$&^_.+\-]*$`)
	sampleCharsetPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._\-]*$`)
)

type sampleParseProfile struct {
	reference        dependencyProfileReference
	mediaType        string
	transportCharset string
	decoderReference dependencyProfileReference
	decoderKind      string
	parserReference  dependencyProfileReference
	parserKind       string
}

type sampleParseFailure struct {
	class   string
	stage   string
	profile dependencyProfileReference
}

func validateSampleShapeSemanticRows(rows dependencySemanticRows, source sourceContractSemanticState, loaded loadedEvidence) error {
	profiles, err := parseSampleParseProfiles(rows)
	if err != nil {
		return err
	}
	blocks := map[string]dependencySemanticRow{}
	blockOutcomes := map[string]string{}
	usedProfiles := map[string]struct{}{}
	expectedShapes := map[string]map[string]computedSampleShape{}
	outcomeCounts := map[string]int64{
		sampleParseOutcomeParsed: 0, sampleParseOutcomeFailed: 0,
		sampleParseOutcomeUnsupported: 0, sampleParseOutcomeNotApplicable: 0,
	}
	for _, row := range rows.byKind["sample_json_block"] {
		coordinate, err := validateRowHydration(rows, row, loaded)
		if err != nil {
			return err
		}
		symbol, symbolOK := semanticString(row.data, "source_symbol")
		_, surfaceOK := semanticString(row.data, "surface_kind")
		_, urlOK := semanticString(row.data, "source_url")
		documentDigest, digestOK := semanticString(row.data, "document_content_sha256")
		blockDigest, blockOK := semanticString(row.data, "block_content_sha256")
		blockBytes, bytesOK := semanticInt64(row.data, "block_content_bytes")
		outcome, outcomeOK := semanticString(row.data, "parse_outcome")
		_, sectionOK := semanticStringSlice(row.data, "section_path")
		if !symbolOK || !surfaceOK || !urlOK || !digestOK || !blockOK || !bytesOK || blockBytes <= 0 || !outcomeOK || !sectionOK {
			return semanticRowError(rows, row, "sample_json_block is incomplete or has no closed parse outcome")
		}
		if _, legacy := row.data["parsed"]; legacy {
			return semanticRowError(rows, row, "sample_json_block carries retired parsed boolean instead of parse_outcome")
		}
		if _, legacy := row.data["parse_error_class"]; legacy {
			return semanticRowError(rows, row, "sample_json_block carries retired parse_error_class instead of typed parse_failure")
		}
		if _, resource := source.resourceSymbols[symbol]; !resource {
			return semanticRowError(rows, row, "sample_json_block source_symbol %q is not a sealed typed resource", symbol)
		}
		occurrences := source.classificationsBySymbol[symbol]
		if sourceClassificationOccurrenceCoverageCount(occurrences, row.data) != 1 {
			return semanticRowError(rows, row, "sample_json_block source_symbol %q does not bind exactly one selected classification occurrence", symbol)
		}
		if documentDigest != coordinate.digest || blockDigest != coordinate.rangeSHA || blockBytes != coordinate.count {
			return semanticRowError(rows, row, "sample_json_block does not bind its exact selected document range")
		}
		profile, err := resolveSampleParseProfile(rows, row, profiles)
		if err != nil {
			return err
		}
		usedProfiles[dependencyProfileReferenceKey(profile.reference)] = struct{}{}
		body := loaded.Bodies[coordinate.digest]
		selected := body.Bytes[coordinate.start:coordinate.end]
		recomputedOutcome, recomputedFailure, sample := executeSampleParseProfile(profile, selected)
		if outcome != recomputedOutcome {
			return semanticRowError(rows, row, "parse_outcome %q does not equal deterministic profile result %q", outcome, recomputedOutcome)
		}
		if err := validateSampleParseFailure(rows, row, recomputedFailure, profile.reference); err != nil {
			return err
		}
		identity := sampleBlockIdentity(symbol, blockDigest, coordinate)
		if _, duplicate := blocks[identity]; duplicate {
			return semanticRowError(rows, row, "duplicate sample_json_block identity")
		}
		blocks[identity] = row
		blockOutcomes[identity] = outcome
		outcomeCounts[outcome]++
		if outcome == sampleParseOutcomeParsed {
			computed := map[string]computedSampleShape{}
			accumulateComputedSampleShapes(computed, "", sample)
			expectedShapes[identity] = computed
		}
	}
	if err := requireExactSet("sample parse profiles referenced by exact attempts", usedProfiles, stringMapKeysAsSet(profiles)); err != nil {
		return err
	}
	shapes := map[string]struct{}{}
	seenByBlock := map[string]map[string]struct{}{}
	for _, row := range rows.byKind["sample_json_shape"] {
		coordinate, err := validateRowHydration(rows, row, loaded)
		if err != nil {
			return err
		}
		symbol, symbolOK := semanticString(row.data, "source_symbol")
		_, surfaceOK := semanticString(row.data, "surface_kind")
		blockDigest, digestOK := semanticString(row.data, "block_content_sha256")
		pointer, pointerOK := semanticStringAllowEmpty(row.data, "normalized_json_pointer")
		observedKinds, kindsOK := semanticStringSlice(row.data, "observed_kinds")
		occurrences, occurrencesOK := semanticInt64(row.data, "occurrences")
		authority, authorityOK := semanticString(row.data, "schema_authority")
		floatAuthority, floatOK := semanticBool(row.data, "binary_float_authoritative")
		if !symbolOK || !surfaceOK || !digestOK || !pointerOK || !kindsOK || len(observedKinds) == 0 || hasDuplicateStrings(observedKinds) || !occurrencesOK || occurrences <= 0 || !authorityOK || authority != "sample_only_not_schema" || !floatOK || floatAuthority {
			return semanticRowError(rows, row, "sample_json_shape is incomplete, has non-sample schema authority, or asserts binary-float authority")
		}
		blockIdentity := sampleBlockIdentity(symbol, blockDigest, coordinate)
		block, exists := blocks[blockIdentity]
		if !exists {
			return semanticRowError(rows, row, "sample_json_shape resolves no exact sample_json_block")
		}
		if blockOutcomes[blockIdentity] != sampleParseOutcomeParsed {
			return semanticRowError(rows, row, "sample_json_shape targets %s parse outcome; only parsed JSON may emit shapes", blockOutcomes[blockIdentity])
		}
		if err := requireEqualStringFields(row.data, block.data, "surface_kind"); err != nil {
			return semanticRowError(rows, row, "%v", err)
		}
		identity := semanticIdentity(blockIdentity, pointer)
		if _, duplicate := shapes[identity]; duplicate {
			return semanticRowError(rows, row, "duplicate sample_json_shape identity")
		}
		shapes[identity] = struct{}{}
		expected, exists := expectedShapes[blockIdentity][pointer]
		if !exists {
			return semanticRowError(rows, row, "sample_json_shape pointer %q is absent from the exact parsed sample block", pointer)
		}
		if err := requireExactSet("sample_json_shape observed_kinds", stringSet(observedKinds), expected.kinds); err != nil {
			return semanticRowError(rows, row, "%v", err)
		}
		if occurrences != expected.occurrences {
			return semanticRowError(rows, row, "sample_json_shape occurrences %d does not equal exact parsed occurrence count %d", occurrences, expected.occurrences)
		}
		observedLexemes, lexemesOK := semanticNullableStringSlice(row.data, "observed_raw_number_lexemes")
		if !lexemesOK || hasEmptyOrDuplicateSemanticStrings(observedLexemes) {
			return semanticRowError(rows, row, "observed_raw_number_lexemes must be null or a unique string roster")
		}
		if err := requireExactSet("sample_json_shape observed_raw_number_lexemes", stringSet(observedLexemes), expected.numberLexemes); err != nil {
			return semanticRowError(rows, row, "%v", err)
		}
		stringClasses, classesOK := semanticNullableStringSlice(row.data, "observed_string_classes")
		if !classesOK || hasEmptyOrDuplicateSemanticStrings(stringClasses) {
			return semanticRowError(rows, row, "observed_string_classes must be null or a unique string roster")
		}
		if err := requireExactSet("sample_json_shape observed_string_classes", stringSet(stringClasses), expected.stringClasses); err != nil {
			return semanticRowError(rows, row, "%v", err)
		}
		if seenByBlock[blockIdentity] == nil {
			seenByBlock[blockIdentity] = map[string]struct{}{}
		}
		seenByBlock[blockIdentity][pointer] = struct{}{}
	}
	for _, blockIdentity := range sortedProviderStringMapKeys(expectedShapes) {
		expected := expectedShapes[blockIdentity]
		if err := requireExactSet("sample_json_shape pointer roster", seenByBlock[blockIdentity], expectedShapePointerSet(expected)); err != nil {
			return semanticRowError(rows, blocks[blockIdentity], "%v", err)
		}
	}
	summary := rows.byKind["validation_summary"][0]
	for _, check := range []struct {
		field string
		want  int64
	}{
		{"expected_source_documents", int64(len(source.documentsByIdentity))},
		{"sample_json_block_count", int64(len(blocks))},
		{"sample_parse_profile_count", int64(len(profiles))},
		{"parsed_sample_json_block_count", outcomeCounts[sampleParseOutcomeParsed]},
		{"unparsed_sample_json_block_count", int64(len(blocks)) - outcomeCounts[sampleParseOutcomeParsed]},
		{"failed_sample_json_block_count", outcomeCounts[sampleParseOutcomeFailed]},
		{"unsupported_sample_json_block_count", outcomeCounts[sampleParseOutcomeUnsupported]},
		{"not_applicable_sample_json_block_count", outcomeCounts[sampleParseOutcomeNotApplicable]},
		{"sample_json_shape_row_count", int64(len(shapes))},
		{"exact_evidence_locator_binding_count", int64(len(blocks) + len(shapes))},
	} {
		got, ok := semanticInt64(summary.data, check.field)
		if !ok || got != check.want {
			return semanticRowError(rows, summary, "%s %d does not equal recomputed value %d", check.field, got, check.want)
		}
	}
	rawLexemes, rawOK := semanticBool(summary.data, "raw_numeric_lexemes_preserved")
	sampleAsSchema, schemaOK := semanticBool(summary.data, "source_examples_treated_as_schema")
	if !rawOK || !rawLexemes || !schemaOK || sampleAsSchema {
		return semanticRowError(rows, summary, "sample summary must preserve raw numeric lexemes and forbid treating examples as schema authority")
	}
	return nil
}

func sampleParseOutcomeCountsFromArtifact(input artifactInput) (map[string]int, error) {
	counts := map[string]int{
		sampleParseOutcomeParsed: 0, sampleParseOutcomeFailed: 0,
		sampleParseOutcomeUnsupported: 0, sampleParseOutcomeNotApplicable: 0,
	}
	for index, row := range input.RowsByKind["sample_json_block"] {
		outcome, ok := manifestString(row, "parse_outcome")
		if !ok {
			return nil, fmt.Errorf("sample-shape dependency %q sample_json_block[%d] has no parse_outcome", input.Path, index)
		}
		if _, closed := counts[outcome]; !closed {
			return nil, fmt.Errorf("sample-shape dependency %q sample_json_block[%d] has unsupported parse_outcome %q", input.Path, index, outcome)
		}
		counts[outcome]++
	}
	return counts, nil
}

func parseSampleParseProfiles(rows dependencySemanticRows) (map[string]sampleParseProfile, error) {
	profiles := map[string]sampleParseProfile{}
	coordinates := map[string]string{}
	for _, row := range rows.byKind["sample_parse_profile"] {
		reference, referenceOK := dependencyProfileReferenceFromFields(row.data, "parse_profile")
		canonicalProfile, canonicalOK := semanticString(row.data, "canonical_profile_json")
		if !referenceOK || !canonicalOK || sha256Hex([]byte(canonicalProfile)) != reference.digest {
			return nil, semanticRowError(rows, row, "sample_parse_profile is incomplete or its exact canonical bytes do not match its digest")
		}
		canonicalBytes, err := canonicalizeCandidateJSON([]byte(canonicalProfile))
		if err != nil || string(canonicalBytes) != canonicalProfile {
			return nil, semanticRowError(rows, row, "sample_parse_profile canonical_profile_json is not duplicate-safe canonical JSON: %v", err)
		}
		definition, err := decodeJSONObject(canonicalBytes)
		if err != nil {
			return nil, semanticRowError(rows, row, "sample_parse_profile canonical_profile_json is not an object: %v", err)
		}
		if err := requireExactSemanticObjectKeys(definition, "parse profile definition", "parse_profile_id", "parse_profile_version", "source_representation_media_type", "transport_charset", "decoder_profile", "parser_profile"); err != nil {
			return nil, semanticRowError(rows, row, "%v", err)
		}
		definitionID, idOK := semanticString(definition, "parse_profile_id")
		definitionVersion, versionOK := semanticString(definition, "parse_profile_version")
		mediaType, mediaOK := semanticString(definition, "source_representation_media_type")
		charset, charsetOK := semanticString(definition, "transport_charset")
		decoderObject, decoderOK := semanticObject(definition, "decoder_profile")
		parserObject, parserOK := semanticObject(definition, "parser_profile")
		if !idOK || definitionID != reference.id || !versionOK || definitionVersion != reference.version || !mediaOK || !sampleMediaTypePattern.MatchString(mediaType) || strings.ToLower(mediaType) != mediaType || !charsetOK || !sampleCharsetPattern.MatchString(charset) || strings.ToLower(charset) != charset || !decoderOK || !parserOK {
			return nil, semanticRowError(rows, row, "sample_parse_profile definition has a noncanonical identity, media type, charset, decoder, or parser")
		}
		decoderReference, decoderProgram, err := parseSampleExecutableProfile(decoderObject, "decoder_profile")
		if err != nil {
			return nil, semanticRowError(rows, row, "decoder profile: %v", err)
		}
		parserReference, parserProgram, err := parseSampleExecutableProfile(parserObject, "parser_profile")
		if err != nil {
			return nil, semanticRowError(rows, row, "parser profile: %v", err)
		}
		decoderKind, decoderKindOK := semanticString(decoderProgram, "kind")
		parserKind, parserKindOK := semanticString(parserProgram, "kind")
		if !decoderKindOK || !parserKindOK {
			return nil, semanticRowError(rows, row, "sample_parse_profile has no closed decoder/parser kind")
		}
		if err := validateSampleParseProgram(decoderProgram, parserProgram, mediaType, charset); err != nil {
			return nil, semanticRowError(rows, row, "%v", err)
		}
		key := dependencyProfileReferenceKey(reference)
		coordinate := semanticIdentity(reference.id, reference.version)
		if priorDigest, duplicate := coordinates[coordinate]; duplicate && priorDigest != reference.digest {
			return nil, semanticRowError(rows, row, "sample_parse_profile coordinate %q version %q aliases different exact definitions", reference.id, reference.version)
		}
		if _, duplicate := profiles[key]; duplicate {
			return nil, semanticRowError(rows, row, "duplicate sample_parse_profile coordinate")
		}
		coordinates[coordinate] = reference.digest
		profiles[key] = sampleParseProfile{
			reference: reference, mediaType: mediaType, transportCharset: charset,
			decoderReference: decoderReference, decoderKind: decoderKind,
			parserReference: parserReference, parserKind: parserKind,
		}
	}
	if len(rows.byKind["sample_json_block"]) > 0 && len(profiles) == 0 {
		return nil, fmt.Errorf("sample-shape dependency %q has parse attempts but no exact sample_parse_profile", rows.path)
	}
	return profiles, nil
}

func parseSampleExecutableProfile(object map[string]interface{}, prefix string) (dependencyProfileReference, map[string]interface{}, error) {
	reference, referenceOK := dependencyProfileReferenceFromFields(object, prefix)
	program, programOK := semanticObject(object, "program")
	if !referenceOK || !programOK {
		return dependencyProfileReference{}, nil, fmt.Errorf("%s coordinate or program is incomplete", prefix)
	}
	if err := requireExactSemanticObjectKeys(object, prefix, prefix+"_id", prefix+"_version", prefix+"_sha256", "program"); err != nil {
		return dependencyProfileReference{}, nil, err
	}
	preimage := map[string]interface{}{prefix + "_id": reference.id, prefix + "_version": reference.version, "program": program}
	raw, err := json.Marshal(preimage)
	if err != nil {
		return dependencyProfileReference{}, nil, err
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil || sha256Hex(canonical) != reference.digest {
		return dependencyProfileReference{}, nil, fmt.Errorf("%s digest does not bind its exact canonical identity and program", prefix)
	}
	return reference, program, nil
}

func validateSampleParseProgram(decoder, parser map[string]interface{}, mediaType, charset string) error {
	decoderKind, _ := semanticString(decoder, "kind")
	parserKind, _ := semanticString(parser, "kind")
	switch decoderKind {
	case sampleDecoderKindUTF8Strict, sampleDecoderKindNone:
	default:
		return fmt.Errorf("unsupported decoder profile kind %q", decoderKind)
	}
	switch parserKind {
	case sampleParserKindJSONRFC8259:
		if err := requireExactSemanticObjectKeys(decoder, "decoder program", "kind"); err != nil {
			return err
		}
		if err := requireExactSemanticObjectKeys(parser, "JSON parser program", "kind", "duplicate_key_policy", "trailing_content_policy", "number_handling"); err != nil {
			return err
		}
		duplicatePolicy, duplicateOK := semanticString(parser, "duplicate_key_policy")
		trailingPolicy, trailingOK := semanticString(parser, "trailing_content_policy")
		numberHandling, numberOK := semanticString(parser, "number_handling")
		if !isJSONMediaType(mediaType) || charset != "utf-8" || decoderKind != sampleDecoderKindUTF8Strict || !duplicateOK || duplicatePolicy != "reject" || !trailingOK || trailingPolicy != "reject" || !numberOK || numberHandling != "preserve_raw_lexeme" {
			return fmt.Errorf("JSON parse profile does not bind exact JSON media, UTF-8 decoding, duplicate/trailing rejection, and raw-number lexemes")
		}
	case sampleParserKindUnsupported:
		if err := requireExactSemanticObjectKeys(decoder, "decoder program", "kind"); err != nil {
			return err
		}
		if err := requireExactSemanticObjectKeys(parser, "unsupported parser program", "kind"); err != nil {
			return err
		}
		if decoderKind != sampleDecoderKindNone || (isJSONMediaType(mediaType) && charset == "utf-8") {
			return fmt.Errorf("unsupported parse profile either selects a decoder or rejects the supported JSON/UTF-8 pair")
		}
	case sampleParserKindNotApplicable:
		if err := requireExactSemanticObjectKeys(decoder, "decoder program", "kind"); err != nil {
			return err
		}
		if err := requireExactSemanticObjectKeys(parser, "not-applicable parser program", "kind"); err != nil {
			return err
		}
		if decoderKind != sampleDecoderKindNone {
			return fmt.Errorf("not-applicable parse profile must not decode source bytes")
		}
	default:
		return fmt.Errorf("unsupported parser profile kind %q", parserKind)
	}
	return nil
}

func resolveSampleParseProfile(rows dependencySemanticRows, row dependencySemanticRow, profiles map[string]sampleParseProfile) (sampleParseProfile, error) {
	binding, bindingOK := semanticObject(row.data, "parse_profile_binding")
	if !bindingOK {
		return sampleParseProfile{}, semanticRowError(rows, row, "sample_json_block has no parse_profile_binding")
	}
	if err := requireExactSemanticObjectKeys(binding, "parse_profile_binding", "parse_profile_id", "parse_profile_version", "parse_profile_sha256"); err != nil {
		return sampleParseProfile{}, semanticRowError(rows, row, "%v", err)
	}
	reference, referenceOK := dependencyProfileReferenceFromFields(binding, "parse_profile")
	profile, exists := profiles[dependencyProfileReferenceKey(reference)]
	if !referenceOK || !exists {
		return sampleParseProfile{}, semanticRowError(rows, row, "sample_json_block parse_profile_binding resolves no exact profile")
	}
	return profile, nil
}

func executeSampleParseProfile(profile sampleParseProfile, selected []byte) (string, *sampleParseFailure, interface{}) {
	switch profile.parserKind {
	case sampleParserKindUnsupported:
		failureClass := "unsupported_media_type"
		failureStage := "media_type_selection"
		if isJSONMediaType(profile.mediaType) {
			failureClass = "unsupported_charset"
			failureStage = "decoder"
		}
		return sampleParseOutcomeUnsupported, &sampleParseFailure{class: failureClass, stage: failureStage, profile: profile.reference}, nil
	case sampleParserKindNotApplicable:
		return sampleParseOutcomeNotApplicable, nil, nil
	case sampleParserKindJSONRFC8259:
		if !utf8.Valid(selected) {
			return sampleParseOutcomeFailed, &sampleParseFailure{class: "invalid_charset_sequence", stage: "decoder", profile: profile.reference}, nil
		}
		if err := rejectDuplicateJSONKeys(selected); err != nil {
			failureClass := "malformed_json"
			if strings.Contains(err.Error(), "duplicate JSON key") {
				failureClass = "duplicate_json_key"
			} else if strings.Contains(err.Error(), "trailing JSON") {
				failureClass = "trailing_json_content"
			}
			return sampleParseOutcomeFailed, &sampleParseFailure{class: failureClass, stage: "parser", profile: profile.reference}, nil
		}
		var sample interface{}
		decoder := json.NewDecoder(bytes.NewReader(selected))
		decoder.UseNumber()
		if err := decoder.Decode(&sample); err != nil {
			return sampleParseOutcomeFailed, &sampleParseFailure{class: "malformed_json", stage: "parser", profile: profile.reference}, nil
		}
		var trailing interface{}
		if err := decoder.Decode(&trailing); err != io.EOF {
			return sampleParseOutcomeFailed, &sampleParseFailure{class: "trailing_json_content", stage: "parser", profile: profile.reference}, nil
		}
		return sampleParseOutcomeParsed, nil, sample
	default:
		return sampleParseOutcomeFailed, &sampleParseFailure{class: "invalid_parse_profile", stage: "profile_resolution", profile: profile.reference}, nil
	}
}

func validateSampleParseFailure(rows dependencySemanticRows, row dependencySemanticRow, expected *sampleParseFailure, profile dependencyProfileReference) error {
	value, present := row.data["parse_failure"]
	if !present {
		return semanticRowError(rows, row, "sample_json_block omits required parse_failure arm")
	}
	if expected == nil {
		if value != nil {
			return semanticRowError(rows, row, "successful or non-applicable parse outcome carries a parse_failure")
		}
		return nil
	}
	failure, ok := value.(map[string]interface{})
	if !ok {
		return semanticRowError(rows, row, "failed or unsupported parse outcome has no typed parse_failure")
	}
	if err := requireExactSemanticObjectKeys(failure, "parse_failure", "failure_class", "failure_stage", "parse_profile_id", "parse_profile_version", "parse_profile_sha256"); err != nil {
		return semanticRowError(rows, row, "%v", err)
	}
	failureClass, classOK := semanticString(failure, "failure_class")
	failureStage, stageOK := semanticString(failure, "failure_stage")
	failureProfile, profileOK := dependencyProfileReferenceFromFields(failure, "parse_profile")
	if !classOK || failureClass != expected.class || !stageOK || failureStage != expected.stage || !profileOK || dependencyProfileReferenceKey(failureProfile) != dependencyProfileReferenceKey(profile) || dependencyProfileReferenceKey(failureProfile) != dependencyProfileReferenceKey(expected.profile) {
		return semanticRowError(rows, row, "parse_failure does not equal the deterministic typed failure and exact profile coordinate")
	}
	return nil
}

func requireExactSemanticObjectKeys(object map[string]interface{}, label string, expected ...string) error {
	if len(object) != len(expected) {
		return fmt.Errorf("%s has %d fields, want exactly %d", label, len(object), len(expected))
	}
	for _, field := range expected {
		if _, present := object[field]; !present {
			return fmt.Errorf("%s is missing field %q", label, field)
		}
	}
	return nil
}

func isJSONMediaType(mediaType string) bool {
	parts := strings.SplitN(mediaType, "/", 2)
	return len(parts) == 2 && (parts[1] == "json" || strings.HasSuffix(parts[1], "+json"))
}

type computedSampleShape struct {
	kinds         map[string]struct{}
	numberLexemes map[string]struct{}
	stringClasses map[string]struct{}
	occurrences   int64
}

func accumulateComputedSampleShapes(shapes map[string]computedSampleShape, pointer string, value interface{}) {
	shape := shapes[pointer]
	if shape.kinds == nil {
		shape.kinds = map[string]struct{}{}
		shape.numberLexemes = map[string]struct{}{}
		shape.stringClasses = map[string]struct{}{}
	}
	shape.occurrences++
	switch typed := value.(type) {
	case map[string]interface{}:
		shape.kinds["object"] = struct{}{}
		shapes[pointer] = shape
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			accumulateComputedSampleShapes(shapes, pointer+"/"+escapeJSONPointerSegment(key), typed[key])
		}
	case []interface{}:
		shape.kinds["array"] = struct{}{}
		shapes[pointer] = shape
		for _, element := range typed {
			accumulateComputedSampleShapes(shapes, pointer+"/*", element)
		}
	case json.Number:
		shape.kinds["number"] = struct{}{}
		shape.numberLexemes[typed.String()] = struct{}{}
		shapes[pointer] = shape
	case string:
		shape.kinds["string"] = struct{}{}
		shape.stringClasses["text"] = struct{}{}
		shapes[pointer] = shape
	case bool:
		shape.kinds["boolean"] = struct{}{}
		shapes[pointer] = shape
	case nil:
		shape.kinds["null"] = struct{}{}
		shapes[pointer] = shape
	}
}

func escapeJSONPointerSegment(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func expectedShapePointerSet(values map[string]computedSampleShape) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for pointer := range values {
		result[pointer] = struct{}{}
	}
	return result
}

func profileSemanticBindingSet(rows dependencySemanticRows) map[string]struct{} {
	result := map[string]struct{}{}
	for _, item := range []struct {
		kind  string
		field string
	}{
		{"api_element_role", "api_element_role"},
		{"api_relationship", "edge_label"},
		{"api_property_family", "property_family"},
		{"capability_stage", "capability"},
		{"source_authority_class", "source_class"},
	} {
		for _, row := range rows.byKind[item.kind] {
			value, ok := semanticString(row.data, item.field)
			if ok {
				result[item.kind+":"+value] = struct{}{}
			}
		}
	}
	return result
}

func planGraphElementLocatorIDs(plan *parsedPlan, id string) ([]string, bool) {
	if symbol, ok := plan.Symbols[id]; ok {
		return symbol.EvidenceLocatorIDs, true
	}
	if relation, ok := plan.Relationships[id]; ok {
		return relation.LocatorIDs, true
	}
	if property, ok := plan.Properties[id]; ok {
		return property.LocatorIDs, true
	}
	return nil, false
}

func planLocatorRosterCoversCoordinate(plan *parsedPlan, locatorIDs []string, coordinate dependencyHydrationCoordinate, ref, sourceURL string) bool {
	for _, locatorID := range locatorIDs {
		locator, ok := plan.Locators[locatorID]
		if !ok || locator.SourceContentSHA256 != coordinate.digest || locator.ByteStartOffset != coordinate.start || locator.ByteEndOffsetExclusive != coordinate.end || locator.SelectedRangeByteCount != coordinate.count || locator.SelectedRangeSHA256 != coordinate.rangeSHA {
			continue
		}
		if len(locator.SourceRefs) == 1 && len(locator.SourceURLs) == 1 && locator.SourceRefs[0] == ref && locator.SourceURLs[0] == sourceURL {
			return true
		}
	}
	return false
}

func contradictionContainsAssertion(rows []dependencySemanticRow, contradictionID, assertionID string) bool {
	for _, row := range rows {
		rowID, _ := semanticString(row.data, "contradiction_id")
		if rowID != contradictionID {
			continue
		}
		assertions, _ := semanticStringSlice(row.data, "assertions")
		for _, candidate := range assertions {
			if candidate == assertionID {
				return true
			}
		}
	}
	return false
}

func validateProtocolSemanticRows(rows, profile dependencySemanticRows, plan *parsedPlan, loaded loadedEvidence) error {
	protocolBodyCount := int64(0)
	protocolBodyBytes := int64(0)
	for _, metadata := range loaded.MetadataByCoordinate {
		if _, selected := metadata.ConsumerRoles["protocol_contract_index"]; selected {
			protocolBodyCount++
			protocolBodyBytes += metadata.ContentBytes
		}
	}
	for _, row := range rows.byKind["protocol_section_projection"] {
		if _, err := validateRowHydration(rows, row, loaded); err != nil {
			return err
		}
		if _, ok := semanticString(row.data, "semantic_label"); !ok {
			return semanticRowError(rows, row, "protocol_section_projection is a marker")
		}
	}
	assertions := map[string]dependencySemanticRow{}
	dispositionSemanticsPresent := false
	dispositionSemanticsAbsent := false
	for _, row := range rows.byKind["protocol_assertion_projection"] {
		coordinate, err := validateRowHydration(rows, row, loaded)
		if err != nil {
			return err
		}
		assertionID, idOK := semanticString(row.data, "assertion_id")
		_, classOK := semanticString(row.data, "assertion_class")
		_, semanticsOK := semanticString(row.data, "candidate_semantics")
		_, consequenceOK := semanticString(row.data, "required_velenza_boc_consequence")
		_, literalOK := semanticString(row.data, "evidence_match_literal")
		if !idOK || !classOK || !semanticsOK || !consequenceOK || !literalOK {
			return semanticRowError(rows, row, "protocol_assertion_projection is a marker")
		}
		literal, _ := semanticString(row.data, "evidence_match_literal")
		body := loaded.Bodies[coordinate.digest]
		if !bytes.Contains(body.Bytes[coordinate.start:coordinate.end], []byte(literal)) {
			return semanticRowError(rows, row, "evidence_match_literal is absent from the exact selected evidence range")
		}
		if _, duplicate := assertions[assertionID]; duplicate {
			return semanticRowError(rows, row, "duplicate protocol assertion_id %q", assertionID)
		}
		if _, present := row.data["plan_semantic_disposition"]; present {
			dispositionSemanticsPresent = true
		} else {
			dispositionSemanticsAbsent = true
		}
		assertions[assertionID] = row
	}
	if dispositionSemanticsPresent && dispositionSemanticsAbsent {
		return fmt.Errorf("protocol assertion rows mix schemas with and without plan-semantic dispositions")
	}
	operationClassifierFacts := map[string]protocolOperationClassifierPredecessor{}
	operationClassifierAssertionBindingCount := 0
	for _, row := range rows.byKind["operation_classifier_fact"] {
		fact, err := parseProtocolOperationClassifierPredecessor(rows, row)
		if err != nil {
			return err
		}
		if _, duplicate := operationClassifierFacts[fact.id]; duplicate {
			return semanticRowError(rows, row, "duplicate operation_classifier_fact_id %q", fact.id)
		}
		for _, assertionID := range fact.assertionIDs {
			assertion, exists := assertions[assertionID]
			if !exists {
				return semanticRowError(rows, row, "operation classifier predecessor assertion %q is absent", assertionID)
			}
			coordinate, err := coordinateFromRow(assertion.data)
			if err != nil {
				return semanticRowError(rows, row, "operation classifier predecessor assertion %q: %v", assertionID, err)
			}
			ref, _ := semanticString(assertion.data, "source_ref")
			sourceURL, _ := semanticString(assertion.data, "source_url")
			if !planLocatorRosterCoversCoordinate(plan, fact.locatorIDs, coordinate, ref, sourceURL) {
				return semanticRowError(rows, row, "operation classifier predecessor locator roster does not cover assertion %q exact evidence coordinate", assertionID)
			}
			operationClassifierAssertionBindingCount++
		}
		operationClassifierFacts[fact.id] = fact
	}
	if protocolBodyCount > 0 && len(assertions) == 0 {
		return fmt.Errorf("protocol dependency %q selected %d exact protocol body/bodies but projected no assertions", rows.path, protocolBodyCount)
	}
	contradictionIDs := map[string]struct{}{}
	nestedBindingCount := 0
	for _, row := range rows.byKind["provider_contract_contradiction"] {
		contradictionID, idOK := semanticString(row.data, "contradiction_id")
		assertionIDs, assertionsOK := semanticStringSlice(row.data, "assertions")
		bindings, bindingsOK := semanticObjectSlice(row.data, "evidence_hydration_coordinates")
		_, dispositionOK := semanticString(row.data, "disposition")
		if !idOK || !assertionsOK || len(assertionIDs) < 2 || hasDuplicateStrings(assertionIDs) || !bindingsOK || len(bindings) != len(assertionIDs) || !dispositionOK {
			return semanticRowError(rows, row, "provider_contract_contradiction has incomplete or non-bijective assertion bindings")
		}
		if _, duplicate := contradictionIDs[contradictionID]; duplicate {
			return semanticRowError(rows, row, "duplicate contradiction_id %q", contradictionID)
		}
		contradictionIDs[contradictionID] = struct{}{}
		assertionSet := stringSet(assertionIDs)
		boundSet := map[string]struct{}{}
		for index, binding := range bindings {
			assertionID, assertionOK := semanticString(binding, "assertion_id")
			ref, refOK := semanticString(binding, "source_ref")
			coordinateObject, coordinateOK := semanticObject(binding, "coordinate")
			assertion, exists := assertions[assertionID]
			if !assertionOK || !refOK || !coordinateOK || !exists {
				return semanticRowError(rows, row, "contradiction binding %d resolves no exact assertion", index)
			}
			if _, expected := assertionSet[assertionID]; !expected {
				return semanticRowError(rows, row, "contradiction binding %d names assertion %q outside its assertion roster", index, assertionID)
			}
			if _, duplicate := boundSet[assertionID]; duplicate {
				return semanticRowError(rows, row, "contradiction binding duplicates assertion %q", assertionID)
			}
			boundSet[assertionID] = struct{}{}
			expectedRef, _ := semanticString(assertion.data, "source_ref")
			expectedCoordinate, err := coordinateFromRow(assertion.data)
			if err != nil {
				return semanticRowError(rows, row, "assertion %q: %v", assertionID, err)
			}
			coordinate, err := parseDependencyHydrationCoordinate(coordinateObject)
			if err != nil {
				return semanticRowError(rows, row, "contradiction binding %d: %v", index, err)
			}
			if ref != expectedRef || coordinate != expectedCoordinate {
				return semanticRowError(rows, row, "contradiction binding %d does not exactly equal assertion %q ref and coordinate", index, assertionID)
			}
			if err := validateExactHydrationCoordinate(rows, row, coordinate, ref, "", loaded); err != nil {
				return err
			}
			nestedBindingCount++
		}
		if err := requireExactSet("contradiction assertion binding roster", boundSet, assertionSet); err != nil {
			return semanticRowError(rows, row, "%v", err)
		}
	}
	if dispositionSemanticsPresent {
		profileBindings := profileSemanticBindingSet(profile)
		for _, assertionID := range sortedProviderStringMapKeys(assertions) {
			assertion := assertions[assertionID]
			disposition, _ := semanticObject(assertion.data, "plan_semantic_disposition")
			kind, kindOK := semanticString(disposition, "kind")
			bindings, bindingsOK := semanticStringSlice(disposition, "bindings")
			if !kindOK || !bindingsOK || len(bindings) == 0 || hasEmptyOrDuplicateSemanticStrings(bindings) {
				return semanticRowError(rows, assertion, "plan_semantic_disposition must carry one closed kind and a nonempty unique binding roster")
			}
			coordinate, _ := coordinateFromRow(assertion.data)
			ref, _ := semanticString(assertion.data, "source_ref")
			sourceURL, _ := semanticString(assertion.data, "source_url")
			switch kind {
			case "materialized_graph_elements":
				for _, binding := range bindings {
					locatorIDs, exists := planGraphElementLocatorIDs(plan, binding)
					if !exists || !planLocatorRosterCoversCoordinate(plan, locatorIDs, coordinate, ref, sourceURL) {
						return semanticRowError(rows, assertion, "materialized graph element binding %q is absent or does not carry the assertion's exact evidence coordinate", binding)
					}
				}
			case "reusable_profile_binding":
				for _, binding := range bindings {
					if _, exists := profileBindings[binding]; !exists {
						return semanticRowError(rows, assertion, "reusable profile binding %q resolves no exact provider-neutral profile row", binding)
					}
				}
			case "preserved_contradiction":
				for _, binding := range bindings {
					if _, exists := contradictionIDs[binding]; !exists || !contradictionContainsAssertion(rows.byKind["provider_contract_contradiction"], binding, assertionID) {
						return semanticRowError(rows, assertion, "preserved contradiction binding %q does not contain assertion %q", binding, assertionID)
					}
				}
			case "explicit_fail_closed_gap":
				for _, binding := range bindings {
					gap, exists := plan.Gaps[binding]
					if !exists || gap.Disposition != "fail_closed" || gap.MaterializationEligible || gap.BlockedSubjectID != assertionID || !planLocatorRosterCoversCoordinate(plan, gap.EvidenceLocatorIDs, coordinate, ref, sourceURL) {
						return semanticRowError(rows, assertion, "fail-closed gap binding %q is absent, not fail closed, or lacks the assertion's exact evidence coordinate", binding)
					}
				}
			default:
				return semanticRowError(rows, assertion, "unsupported plan_semantic_disposition kind %q", kind)
			}
		}
	}
	summary := rows.byKind["validation_summary"][0]
	declared, ok := semanticInt64(summary.data, "exact_evidence_locator_binding_count")
	exact := int64(len(rows.byKind["protocol_section_projection"]) + len(rows.byKind["protocol_assertion_projection"]) + nestedBindingCount + operationClassifierAssertionBindingCount)
	if !ok || declared != exact {
		return semanticRowError(rows, summary, "exact_evidence_locator_binding_count %d does not equal exact direct-plus-nested binding count %d", declared, exact)
	}
	for _, check := range []struct {
		field string
		want  int64
	}{
		{"evidence_body_count", protocolBodyCount},
		{"evidence_exact_source_bytes", protocolBodyBytes},
		{"protocol_section_projection_count", int64(len(rows.byKind["protocol_section_projection"]))},
		{"protocol_assertion_projection_count", int64(len(assertions))},
		{"operation_classifier_fact_count", int64(len(operationClassifierFacts))},
		{"preserved_provider_contradiction_count", int64(len(contradictionIDs))},
	} {
		got, valueOK := semanticInt64(summary.data, check.field)
		if !valueOK || got != check.want {
			return semanticRowError(rows, summary, "%s %d does not equal recomputed value %d", check.field, got, check.want)
		}
	}
	exportOnly, exportOK := semanticBool(summary.data, "selected_representation_is_only_evidence_body")
	hydrationPresent, hydrationOK := semanticBool(summary.data, "exact_hydration_coordinates_present")
	diagnosticAuthority, diagnosticOK := semanticBool(summary.data, "diagnostic_line_and_section_coordinates_are_authority")
	if !exportOK || !exportOnly || !hydrationOK || !hydrationPresent || !diagnosticOK || diagnosticAuthority {
		return semanticRowError(rows, summary, "protocol summary weakens selected-export evidence, exact hydration, or diagnostic non-authority")
	}
	return nil
}

type surfaceDispositionSemanticState struct {
	bySymbol map[string]dependencySemanticRow
}

func validateSurfaceDispositionSemanticRows(rows dependencySemanticRows, source sourceContractSemanticState, loaded loadedEvidence, derivation documentationClaimDerivationState) (surfaceDispositionSemanticState, error) {
	state := surfaceDispositionSemanticState{bySymbol: map[string]dependencySemanticRow{}}
	unlockedCount := int64(0)
	surfaceKindCounts := map[string]int64{}
	for _, row := range rows.byKind["surface_disposition"] {
		coordinate, err := validateRowHydration(rows, row, loaded)
		if err != nil {
			return state, err
		}
		symbol, symbolOK := semanticString(row.data, "source_symbol")
		family, familyOK := semanticString(row.data, "source_neutral_family")
		status, statusOK := semanticString(row.data, "target_contract_status")
		targetKind, targetKindOK := semanticString(row.data, "target_kind")
		businessProjection, businessOK := semanticBool(row.data, "business_record_projection")
		typedHome, typedOK := semanticString(row.data, "typed_home_rule")
		latticeRule, latticeOK := semanticString(row.data, "lattice_rule")
		unsupportedDisposition, unsupportedOK := semanticString(row.data, "unsupported_field_disposition")
		if !symbolOK || !familyOK || !singlePathSegmentPattern.MatchString(family) || !statusOK || !targetKindOK || !businessOK || !businessProjection || !typedOK || !latticeOK || !unsupportedOK {
			return state, semanticRowError(rows, row, "surface_disposition is a marker or has an invalid source-neutral family")
		}
		if semanticTextContainsAny(targetKind, "blob", "raw json", "provider json", "universal json") || semanticTextContainsAny(unsupportedDisposition, "silent", "drop", "ignore", "passthrough", "blob") || !semanticTextContainsAll(latticeRule, "source", "blind") {
			return state, semanticRowError(rows, row, "surface disposition permits a universal/raw target, silent unsupported-field loss, or source-aware lattice projection")
		}
		if semanticTextContainsAny(typedHome, "universal", "blob", "raw json") {
			return state, semanticRowError(rows, row, "surface disposition typed-home rule permits a raw or universal provider container")
		}
		if _, duplicate := state.bySymbol[symbol]; duplicate {
			return state, semanticRowError(rows, row, "duplicate surface_disposition source_symbol %q", symbol)
		}
		if _, resource := source.resourceSymbols[symbol]; !resource {
			return state, semanticRowError(rows, row, "surface_disposition source_symbol %q is not a sealed typed resource", symbol)
		}
		occurrences := source.classificationsBySymbol[symbol]
		if sourceClassificationOccurrenceCoverageCount(occurrences, row.data) != 1 {
			return state, semanticRowError(rows, row, "surface_disposition resource source_symbol %q does not bind exactly one selected classification occurrence", symbol)
		}
		if err := validateSurfaceDerivationBinding(rows, row, coordinate.digest, derivation); err != nil {
			return state, err
		}
		if snakeTokenPresent(status, "unlocked") {
			unlockedCount++
		}
		numericProfile, numericProfileOK := semanticObject(row.data, "exact_numeric_profile")
		if !numericProfileOK || len(numericProfile) == 0 {
			return state, semanticRowError(rows, row, "exact_numeric_profile must be a nonempty schema-governed count object")
		}
		semanticCounts := map[string]int64{}
		valueOfRecordCount := int64(0)
		for _, fieldIdentity := range sortedProviderStringMapKeys(source.fieldsByIdentity) {
			fieldRow := source.fieldsByIdentity[fieldIdentity]
			fieldSymbol, _ := semanticString(fieldRow.data, "source_symbol")
			if fieldSymbol != symbol {
				continue
			}
			numeric, _ := semanticObject(fieldRow.data, "numeric_disposition")
			semantics, _ := semanticString(numeric, "numeric_semantics")
			carrier, _ := semanticString(numeric, "authoritative_carrier")
			computation, _ := semanticString(numeric, "computation_path")
			semanticCounts[semantics]++
			if carrier != "not_applicable" || computation != "not_applicable" {
				valueOfRecordCount++
			}
		}
		declaredSemanticClasses := map[string]struct{}{}
		for _, field := range sortedProviderStringMapKeys(numericProfile) {
			rawCount := numericProfile[field]
			if !strings.HasSuffix(field, "_occurrences") {
				return state, semanticRowError(rows, row, "exact_numeric_profile member %q is not a schema-governed occurrence count", field)
			}
			semanticClass := strings.TrimSuffix(field, "_occurrences")
			count, countOK := semanticJSONInt64(rawCount)
			if semanticClass == "" || !countOK || count < 0 || count != semanticCounts[semanticClass] {
				return state, semanticRowError(rows, row, "exact_numeric_profile.%s does not equal recomputed source field count", field)
			}
			declaredSemanticClasses[semanticClass] = struct{}{}
		}
		for _, semanticClass := range sortedProviderStringMapKeys(semanticCounts) {
			if _, declared := declaredSemanticClasses[semanticClass]; !declared {
				return state, semanticRowError(rows, row, "exact_numeric_profile omits observed schema-owned semantic class %q", semanticClass)
			}
		}
		numericIngress, ingressOK := semanticString(row.data, "numeric_ingress")
		numericComputation, computationOK := semanticString(row.data, "numeric_computation")
		if !ingressOK || !computationOK || semanticNumericPolicyTextUnsafe(numericIngress) || semanticNumericPolicyTextUnsafe(numericComputation) || (valueOfRecordCount > 0 && (!semanticTextContainsAny(numericIngress, "lexeme", "typed exact") || !semanticTextContainsAny(numericComputation, "exact pipeline", "unresolved", "fail closed"))) {
			return state, semanticRowError(rows, row, "numeric ingress/computation does not preserve exact lexemes through an exact-computation faculty path")
		}
		surfaceKind, _ := semanticString(row.data, "surface_kind")
		surfaceKindCounts[surfaceKind]++
		state.bySymbol[symbol] = row
	}
	if len(state.bySymbol) != len(source.resourceSymbols) {
		return state, fmt.Errorf("surface-disposition source identity count %d does not equal sealed typed resource count %d", len(state.bySymbol), len(source.resourceSymbols))
	}
	for _, symbol := range sortedProviderStringMapKeys(source.resourceSymbols) {
		if _, ok := state.bySymbol[symbol]; !ok {
			return state, fmt.Errorf("surface-disposition roster is missing sealed typed resource source symbol %q", symbol)
		}
	}
	summary := rows.byKind["validation_summary"][0]
	declared, ok := semanticInt64(summary.data, "canonical_contracts_still_unlocked")
	if !ok || declared != unlockedCount {
		return state, semanticRowError(rows, summary, "canonical_contracts_still_unlocked %d does not equal recomputed unlocked status count %d", declared, unlockedCount)
	}
	for _, check := range []struct {
		field string
		want  int64
	}{
		{"selected_source_count", int64(len(source.resourceSymbols))},
		{"disposed_surface_count", int64(len(state.bySymbol))},
		{"exact_evidence_locator_binding_count", int64(len(state.bySymbol))},
		{"silent_unknown_count", 0},
		{"universal_blob_targets", 0},
	} {
		got, valueOK := semanticInt64(summary.data, check.field)
		if !valueOK || got != check.want {
			return state, semanticRowError(rows, summary, "%s %d does not equal recomputed value %d", check.field, got, check.want)
		}
	}
	declaredKindCounts, declaredKindsOK := manifestNamedCountArray(summary.data, "captured_surface_kind_counts", "surface_kind")
	if !declaredKindsOK || len(declaredKindCounts) != len(surfaceKindCounts) {
		return state, semanticRowError(rows, summary, "captured_surface_kind_counts has %d kinds, want exact selected-source kind count %d", len(declaredKindCounts), len(surfaceKindCounts))
	}
	for _, kind := range sortedProviderStringMapKeys(surfaceKindCounts) {
		want := surfaceKindCounts[kind]
		got, ok := declaredKindCounts[kind]
		if !ok || int64(got) != want {
			return state, semanticRowError(rows, summary, "captured_surface_kind_counts.%s %d does not equal recomputed count %d", kind, got, want)
		}
	}
	manifest := rows.byKind["artifact_manifest"][0]
	derivationDigest, derivationOK := semanticString(manifest.data, "documentation_claim_derivation_profile_sha256")
	if !derivationOK || derivationDigest != derivation.artifactSHA256 {
		return state, semanticRowError(rows, manifest, "surface manifest has no exact documentation derivation profile binding")
	}
	return state, nil
}

type fieldSecurityClassDefinition struct {
	class      string
	rawEmbed   bool
	visibility bool
	defaulted  bool
}

type fieldSecurityRule struct {
	id             string
	inputMember    string
	matchKind      string
	registryMember string
	outputClass    string
}

type fieldSecurityProfile struct {
	policyID      string
	policyVersion string
	digest        string
	rules         []fieldSecurityRule
	registries    map[string][]string
	definitions   map[string]fieldSecurityClassDefinition
}

type mappingTransitiveSemanticBinding struct {
	id      string
	ordinal int64
}

type mappingTransitiveSemanticState struct {
	byID       map[string]mappingTransitiveSemanticBinding
	orderedIDs []string
}

type dependencyProfileReference struct {
	id      string
	version string
	digest  string
}

type documentationDerivationDefinition struct {
	claimKind        string
	validationSchema dependencyProfileReference
}

type documentationValidationSchema struct {
	claimKind string
	authority documentationClaimSchemaAuthority
}

type documentationClassifierProfile struct {
	claimKind         string
	semanticClasses   map[string]struct{}
	carriers          map[string]struct{}
	computationPaths  map[string]struct{}
	program           map[string]interface{}
	exactValueProgram *exactValueClassifierProgram
}

type documentationResolutionProfile struct {
	failClosed bool
}

type documentationClaimDerivationState struct {
	artifactSHA256    string
	derivations       map[string]documentationDerivationDefinition
	validationSchemas map[string]documentationValidationSchema
	classifiers       map[string]documentationClassifierProfile
	resolutions       map[string]documentationResolutionProfile
}

func validateFieldMappingSemanticRows(rows, securityRows, transitiveRows, derivationRows dependencySemanticRows, derivation documentationClaimDerivationState, derivationClosure documentationDerivationClosureProof, source sourceContractSemanticState, surfaces surfaceDispositionSemanticState, loaded loadedEvidence) error {
	if err := validateDocumentationDerivationClosureProof(derivationClosure); err != nil {
		return fmt.Errorf("field mapping requires the exact executable documentation derivation closure: %w", err)
	}
	if derivationClosure.factsByID == nil {
		return fmt.Errorf("field mapping requires the executed documentation-fact roster, not an asserted closure identity")
	}
	security, err := parseFieldSecurityProfile(securityRows)
	if err != nil {
		return err
	}
	transitive, err := parseMappingTransitiveSemanticRows(transitiveRows)
	if err != nil {
		return err
	}
	manifest := rows.byKind["artifact_manifest"][0]
	securityArtifactDigest, securityArtifactOK := semanticString(manifest.data, "field_security_policy_artifact_sha256")
	securityID, securityIDOK := semanticString(manifest.data, "field_security_policy_id")
	securityVersion, securityVersionOK := semanticString(manifest.data, "field_security_policy_version")
	securityProfileDigest, securityProfileOK := semanticString(manifest.data, "field_security_policy_profile_sha256")
	transitiveDigest, transitiveOK := semanticString(manifest.data, "mapping_transitive_dependency_roster_sha256")
	derivationDigest, derivationOK := semanticString(manifest.data, "documentation_claim_derivation_profile_sha256")
	if !securityArtifactOK || securityArtifactDigest != sha256Hex(securityRows.raw) || !securityIDOK || securityID != security.policyID || !securityVersionOK || securityVersion != security.policyVersion || !securityProfileOK || securityProfileDigest != security.digest {
		return semanticRowError(rows, manifest, "field-security policy binding does not equal the exact external policy artifact")
	}
	if !transitiveOK || transitiveDigest != sha256Hex(transitiveRows.raw) {
		return semanticRowError(rows, manifest, "mapping transitive dependency binding does not equal the exact external roster artifact")
	}
	if !derivationOK || derivationDigest != sha256Hex(derivationRows.raw) {
		return semanticRowError(rows, manifest, "documentation derivation binding does not equal the exact external profile artifact")
	}

	seen := map[string]struct{}{}
	classCounts := map[string]int64{}
	reasonCounts := map[string]int64{}
	numericClassCounts := map[string]int64{}
	transitiveIDsUsed := map[string]struct{}{}
	rawEmbeddingCount := int64(0)
	floatAuthorityCount := int64(0)
	for _, row := range rows.byKind["field_occurrence_disposition"] {
		coordinate, err := validateRowHydration(rows, row, loaded)
		if err != nil {
			return err
		}
		identity, err := mappingFieldOccurrenceIdentity(row.data)
		if err != nil {
			return semanticRowError(rows, row, "%v", err)
		}
		if _, duplicate := seen[identity]; duplicate {
			return semanticRowError(rows, row, "duplicate field_occurrence_disposition identity")
		}
		seen[identity] = struct{}{}
		sourceRow, exists := source.fieldsByIdentity[identity]
		if !exists {
			return semanticRowError(rows, row, "field_occurrence_disposition resolves no exact field_contract occurrence")
		}
		sourceCoordinate, err := coordinateFromRow(sourceRow.data)
		if err != nil || coordinate != sourceCoordinate {
			return semanticRowError(rows, row, "field occurrence coordinate does not exactly equal its field_contract coordinate")
		}
		for _, pair := range []struct{ mappingKey, sourceKey string }{
			{"source_symbol", "source_symbol"}, {"surface_kind", "surface_kind"}, {"source_ref", "source_ref"}, {"source_url", "source_url"}, {"source_field", "field_name"}, {"source_provider_type", "provider_type"}, {"source_cardinality", "cardinality"}, {"source_requirement", "provider_requirement"},
		} {
			left, leftOK := semanticStringAllowEmpty(row.data, pair.mappingKey)
			right, rightOK := semanticStringAllowEmpty(sourceRow.data, pair.sourceKey)
			if !leftOK || !rightOK || left != right {
				return semanticRowError(rows, row, "mapping field %s does not equal source field %s", pair.mappingKey, pair.sourceKey)
			}
		}
		mappingSections, mappingSectionsOK := semanticStringSlice(row.data, "source_section_path")
		sourceSections, sourceSectionsOK := semanticStringSlice(sourceRow.data, "section_path")
		if !mappingSectionsOK || !sourceSectionsOK || !equalStringSlices(mappingSections, sourceSections) {
			return semanticRowError(rows, row, "source_section_path does not equal field_contract section_path")
		}
		numeric, numericOK := semanticObject(sourceRow.data, "numeric_disposition")
		if !numericOK {
			return semanticRowError(rows, row, "field_contract numeric_disposition is missing")
		}
		for _, pair := range []struct{ mappingKey, sourceKey string }{
			{"exact_numeric_semantics", "numeric_semantics"}, {"numeric_authoritative_carrier", "authoritative_carrier"}, {"financial_computation_path", "computation_path"},
		} {
			left, leftOK := semanticString(row.data, pair.mappingKey)
			right, rightOK := semanticString(numeric, pair.sourceKey)
			if !leftOK || !rightOK || left != right {
				return semanticRowError(rows, row, "mapping numeric field %s does not equal source numeric field %s", pair.mappingKey, pair.sourceKey)
			}
		}
		numericSemantics, _ := semanticString(row.data, "exact_numeric_semantics")
		numericCarrier, _ := semanticString(row.data, "numeric_authoritative_carrier")
		computationPath, _ := semanticString(row.data, "financial_computation_path")
		numericClassCounts[numericSemantics]++

		symbol, _ := semanticString(row.data, "source_symbol")
		surface, exists := surfaces.bySymbol[symbol]
		if !exists {
			return semanticRowError(rows, row, "source_symbol %q has no surface disposition", symbol)
		}
		family, familyOK := semanticString(row.data, "target_record_family")
		expectedFamily, expectedFamilyOK := semanticString(surface.data, "source_neutral_family")
		role, roleOK := semanticString(row.data, "target_role")
		path, pathOK := semanticString(row.data, "target_candidate_path")
		if !familyOK || !expectedFamilyOK || family != expectedFamily || !roleOK || !pathOK || !targetCandidatePathPattern.MatchString(path) || path != family+"."+role {
			return semanticRowError(rows, row, "target_candidate_path must be valid dotted lower_snake and equal target_record_family+'.'+target_role")
		}

		mappingFact, mappingFactOK := semanticBool(row.data, "mapping_is_provider_documentation_fact")
		providerEvidence, providerEvidenceOK := semanticBool(row.data, "provider_field_contract_is_evidence")
		floatAuthority, floatOK := semanticBool(row.data, "binary_float_authoritative")
		rawEmbed, rawOK := semanticBool(row.data, "raw_source_value_embedding_allowed")
		typedLocked, lockedOK := semanticBool(row.data, "typed_home_contract_locked")
		if !mappingFactOK || mappingFact || !providerEvidenceOK || !providerEvidence || !floatOK || floatAuthority || !rawOK || rawEmbed || !lockedOK || typedLocked {
			return semanticRowError(rows, row, "field mapping confuses provider evidence with semantic authority or weakens exact-value/source-blind boundaries")
		}
		if floatAuthority {
			floatAuthorityCount++
		}
		if rawEmbed {
			rawEmbeddingCount++
		}

		policyID, policyIDOK := semanticString(row.data, "security_policy_id")
		policyVersion, versionOK := semanticString(row.data, "security_policy_version")
		policyDigest, digestOK := semanticString(row.data, "security_policy_profile_sha256")
		class, classOK := semanticString(row.data, "security_class")
		reason, reasonOK := semanticString(row.data, "security_classification_reason")
		visibility, visibilityOK := semanticBool(row.data, "normal_consumer_visibility")
		definition, definitionOK := security.definitions[class]
		expectedClass, expectedReason, classificationOK := security.classify(row.data)
		if !policyIDOK || policyID != security.policyID || !versionOK || policyVersion != security.policyVersion || !digestOK || policyDigest != security.digest || !classOK || !reasonOK || !definitionOK || !classificationOK || class != expectedClass || reason != expectedReason || !visibilityOK || visibility != definition.visibility || rawEmbed != definition.rawEmbed {
			return semanticRowError(rows, row, "field security class, reason, booleans, or policy binding does not follow the exact profile")
		}
		classCounts[class]++
		reasonCounts[reason]++

		applicableBindingIDs, applicableOK := semanticStringSlice(row.data, "applicable_transitive_dependency_binding_ids")
		if !applicableOK || hasEmptyOrDuplicateSemanticStrings(applicableBindingIDs) {
			return semanticRowError(rows, row, "applicable_transitive_dependency_binding_ids must be a unique ordered roster")
		}
		priorOrdinal := int64(-1)
		for _, bindingID := range applicableBindingIDs {
			binding, exists := transitive.byID[bindingID]
			if !exists {
				return semanticRowError(rows, row, "applicable transitive dependency binding %q is absent from the exact roster", bindingID)
			}
			if binding.ordinal <= priorOrdinal {
				return semanticRowError(rows, row, "applicable transitive dependency bindings do not follow exact precedence order")
			}
			priorOrdinal = binding.ordinal
			transitiveIDsUsed[bindingID] = struct{}{}
		}

		if err := validateFieldDerivationAndExactComputation(rows, row, coordinate, numericSemantics, numericCarrier, computationPath, derivation, derivationClosure); err != nil {
			return err
		}
	}
	if len(seen) != len(source.fieldsByIdentity) {
		return fmt.Errorf("field mapping occurrence count %d does not equal exact source field occurrence count %d", len(seen), len(source.fieldsByIdentity))
	}
	for _, identity := range sortedProviderStringMapKeys(source.fieldsByIdentity) {
		if _, ok := seen[identity]; !ok {
			return fmt.Errorf("field mapping is missing exact source field occurrence %q", identity)
		}
	}
	if err := requireExactSet("field mapping transitive dependency references", transitiveIDsUsed, stringSet(transitive.orderedIDs)); err != nil {
		return err
	}

	summary := rows.byKind["validation_summary"][0]
	for _, class := range sortedProviderStringMapKeys(security.definitions) {
		want := classCounts[class]
		field := class + "_count"
		got, ok := semanticInt64(summary.data, field)
		if !ok || got != want {
			return semanticRowError(rows, summary, "%s %d does not equal recomputed security-class count %d", field, got, want)
		}
	}
	for _, semanticClass := range sortedProviderStringMapKeys(numericClassCounts) {
		want := numericClassCounts[semanticClass]
		field := semanticClass + "_count"
		got, ok := semanticInt64(summary.data, field)
		if !ok || got != want {
			return semanticRowError(rows, summary, "%s %d does not equal recomputed numeric-class count %d", field, got, want)
		}
	}
	for _, reason := range sortedProviderStringMapKeys(reasonCounts) {
		want := reasonCounts[reason]
		field := reason + "_count"
		if _, present := summary.data[field]; !present {
			continue
		}
		got, ok := semanticInt64(summary.data, field)
		if !ok || got != want {
			return semanticRowError(rows, summary, "%s %d does not equal recomputed classification-reason count %d", field, got, want)
		}
	}
	for _, check := range []struct {
		field string
		want  int64
	}{
		{"source_document_count", int64(len(source.documentsByIdentity))},
		{"surface_family_count", int64(len(surfaces.bySymbol))},
		{"documented_field_occurrence_count", int64(len(source.fieldsByIdentity))},
		{"disposed_field_occurrence_count", int64(len(seen))},
		{"exact_locator_binding_count", int64(len(seen))},
		{"raw_value_embedding_count", rawEmbeddingCount},
		{"binary_float_authoritative_count", floatAuthorityCount},
	} {
		got, ok := semanticInt64(summary.data, check.field)
		if !ok || got != check.want {
			return semanticRowError(rows, summary, "%s %d does not equal recomputed row count %d", check.field, got, check.want)
		}
	}
	summarySecurityArtifact, summarySecurityArtifactOK := semanticString(summary.data, "security_policy_artifact_sha256")
	summarySecurityProfile, summarySecurityProfileOK := semanticString(summary.data, "security_policy_profile_sha256")
	locked, lockedOK := semanticBool(summary.data, "canonical_target_contracts_locked")
	admittedDerivation, admittedDerivationOK := semanticBool(summary.data, "admitted_derivation_profile_proof_established")
	if !summarySecurityArtifactOK || summarySecurityArtifact != securityArtifactDigest || !summarySecurityProfileOK || summarySecurityProfile != security.digest || !lockedOK || locked || !admittedDerivationOK || admittedDerivation {
		return semanticRowError(rows, summary, "field mapping summary weakens external security, typed-home, or derivation-admission boundaries")
	}
	return nil
}

func parseFieldSecurityProfile(rows dependencySemanticRows) (fieldSecurityProfile, error) {
	result := fieldSecurityProfile{definitions: map[string]fieldSecurityClassDefinition{}, registries: map[string][]string{}}
	if len(rows.byKind["security_classification_profile"]) != 1 {
		return result, fmt.Errorf("field-security dependency %q requires exactly one security_classification_profile", rows.path)
	}
	profileRow := rows.byKind["security_classification_profile"][0]
	profile, ok := semanticObject(profileRow.data, "profile")
	if !ok {
		return result, semanticRowError(rows, profileRow, "profile must be an object")
	}
	profileRaw, err := semanticRawMember(profileRow.raw, "profile")
	if err != nil {
		return result, semanticRowError(rows, profileRow, "%v", err)
	}
	declaredDigest, digestOK := semanticString(profileRow.data, "profile_sha256")
	computedDigest := sha256Hex(profileRaw)
	if !digestOK || declaredDigest != computedDigest {
		return result, semanticRowError(rows, profileRow, "profile_sha256 %q does not equal exact profile object digest %q", declaredDigest, computedDigest)
	}
	result.digest = computedDigest
	result.policyID, ok = semanticString(profile, "policy_id")
	if !ok {
		return result, semanticRowError(rows, profileRow, "security profile has no policy_id")
	}
	result.policyVersion, ok = semanticString(profile, "policy_version")
	if !ok {
		return result, semanticRowError(rows, profileRow, "security profile has no policy_version")
	}
	sourceNeutral, sourceNeutralOK := semanticBool(profile, "source_neutral")
	unknownAllowed, unknownOK := semanticBool(profile, "unknown_security_class_allowed")
	rawAllowed, rawOK := semanticBool(profile, "raw_source_value_embedding_allowed")
	if !sourceNeutralOK || !sourceNeutral || !unknownOK || unknownAllowed || !rawOK || rawAllowed {
		return result, semanticRowError(rows, profileRow, "security profile must be source-neutral, closed-class, and forbid raw-source embedding")
	}
	closedClasses, closedOK := semanticStringSlice(profile, "closed_security_classes")
	if !closedOK || len(closedClasses) < 2 || hasDuplicateStrings(closedClasses) {
		return result, semanticRowError(rows, profileRow, "closed_security_classes must be a unique closed roster")
	}
	precedence, ok := semanticStringSlice(profile, "precedence")
	if !ok || len(precedence) == 0 || hasEmptyOrDuplicateSemanticStrings(precedence) {
		return result, semanticRowError(rows, profileRow, "precedence must be a nonempty unique roster")
	}
	orderedRules, rulesOK := semanticObjectSlice(profile, "ordered_rules")
	if !rulesOK || len(orderedRules) != len(precedence) {
		return result, semanticRowError(rows, profileRow, "ordered_rules must be set-equal and order-equal to precedence")
	}
	defaultRuleCount := 0
	for index, rawRule := range orderedRules {
		ordinal, ordinalOK := semanticInt64(rawRule, "ordinal")
		ruleID, ruleIDOK := semanticString(rawRule, "rule_id")
		inputMember, inputOK := semanticString(rawRule, "input_member")
		matchKind, matchOK := semanticString(rawRule, "match_kind")
		outputClass, outputOK := semanticString(rawRule, "output_security_class")
		registryMember, registryOK := semanticNullableString(rawRule, "registry_member")
		if !ordinalOK || ordinal != int64(index) || !ruleIDOK || ruleID != precedence[index] || !inputOK || !matchOK || !outputOK || !registryOK {
			return result, semanticRowError(rows, profileRow, "ordered security rule %d is incomplete or violates precedence", index)
		}
		if _, exists := stringSet(closedClasses)[outputClass]; !exists {
			return result, semanticRowError(rows, profileRow, "ordered security rule %q names undeclared class %q", ruleID, outputClass)
		}
		switch matchKind {
		case "exact_registry_membership", "prefix_registry_membership":
			if registryMember == "" {
				return result, semanticRowError(rows, profileRow, "ordered security rule %q has no registry binding", ruleID)
			}
			values, valuesOK := semanticStringSlice(profile, registryMember)
			if !valuesOK || hasDuplicateStrings(values) {
				return result, semanticRowError(rows, profileRow, "ordered security rule %q registry %q is absent or not unique", ruleID, registryMember)
			}
			result.registries[registryMember] = values
		case "default":
			defaultRuleCount++
			if registryMember != "" || inputMember != "*" || index != len(orderedRules)-1 {
				return result, semanticRowError(rows, profileRow, "default security rule must be the final unbound rule")
			}
		default:
			return result, semanticRowError(rows, profileRow, "ordered security rule %q has unsupported generic match kind %q", ruleID, matchKind)
		}
		result.rules = append(result.rules, fieldSecurityRule{id: ruleID, inputMember: inputMember, matchKind: matchKind, registryMember: registryMember, outputClass: outputClass})
	}
	if defaultRuleCount != 1 {
		return result, semanticRowError(rows, profileRow, "security policy requires exactly one final fail-closed default rule")
	}

	for _, row := range rows.byKind["security_class_definition"] {
		policyID, idOK := semanticString(row.data, "policy_id")
		policyVersion, versionOK := semanticString(row.data, "policy_version")
		policyDigest, digestOK := semanticString(row.data, "profile_sha256")
		class, classOK := semanticString(row.data, "security_class")
		rawEmbed, rawEmbedOK := semanticBool(row.data, "raw_source_value_embedding_allowed")
		visibility, visibilityOK := semanticBool(row.data, "normal_consumer_visibility")
		defaulted, defaultOK := semanticBool(row.data, "unclassified_default")
		if !idOK || policyID != result.policyID || !versionOK || policyVersion != result.policyVersion || !digestOK || policyDigest != result.digest || !classOK || !rawEmbedOK || rawEmbed || !visibilityOK || !defaultOK {
			return result, semanticRowError(rows, row, "security_class_definition is incomplete, unbound, or permits raw-source embedding")
		}
		if _, duplicate := result.definitions[class]; duplicate {
			return result, semanticRowError(rows, row, "duplicate security class definition %q", class)
		}
		result.definitions[class] = fieldSecurityClassDefinition{class: class, rawEmbed: rawEmbed, visibility: visibility, defaulted: defaulted}
	}
	if err := requireExactSet("security class definitions", mapKeysAsSet(result.definitions), stringSet(closedClasses)); err != nil {
		return result, err
	}
	defaultCount := 0
	for _, class := range sortedProviderStringMapKeys(result.definitions) {
		definition := result.definitions[class]
		if definition.defaulted {
			defaultCount++
			if definition.visibility {
				return result, fmt.Errorf("fail-closed default security class %q permits normal-consumer visibility", class)
			}
		}
	}
	if defaultCount != 1 {
		return result, fmt.Errorf("security profile requires exactly one fail-closed default class")
	}
	manifest := rows.byKind["artifact_manifest"][0]
	manifestID, idOK := semanticString(manifest.data, "policy_id")
	manifestVersion, versionOK := semanticString(manifest.data, "policy_version")
	manifestDigest, digestOK := semanticString(manifest.data, "profile_sha256")
	admissionAuthorized, admissionOK := semanticBool(manifest.data, "canonical_admission_authorized")
	if !idOK || manifestID != result.policyID || !versionOK || manifestVersion != result.policyVersion || !digestOK || manifestDigest != result.digest || !admissionOK || admissionAuthorized {
		return result, semanticRowError(rows, manifest, "manifest security policy binding does not equal the exact security profile")
	}
	summary := rows.byKind["validation_summary"][0]
	summaryClasses, summaryClassesOK := semanticInt64(summary.data, "security_class_definition_count")
	summaryProfiles, summaryProfilesOK := semanticInt64(summary.data, "profile_count")
	summaryRawEmbedding, summaryRawEmbeddingOK := semanticBool(summary.data, "raw_source_value_embedding_allowed")
	summaryAdmission, summaryAdmissionOK := semanticBool(summary.data, "canonical_admission_authorized")
	if !summaryClassesOK || summaryClasses != int64(len(result.definitions)) || !summaryProfilesOK || summaryProfiles != 1 || !summaryRawEmbeddingOK || summaryRawEmbedding || !summaryAdmissionOK || summaryAdmission {
		return result, semanticRowError(rows, summary, "field-security summary does not close its exact class roster or fail-closed authority posture")
	}
	return result, nil
}

func (profile fieldSecurityProfile) classify(row map[string]interface{}) (string, string, bool) {
	for _, rule := range profile.rules {
		if rule.matchKind == "default" {
			return rule.outputClass, rule.id, true
		}
		value, ok := semanticStringAllowEmpty(row, rule.inputMember)
		if !ok {
			continue
		}
		registry := profile.registries[rule.registryMember]
		switch rule.matchKind {
		case "exact_registry_membership":
			if _, present := stringSet(registry)[value]; present {
				return rule.outputClass, rule.id, true
			}
		case "prefix_registry_membership":
			if anyStringPrefix(value, registry) {
				return rule.outputClass, rule.id, true
			}
		}
	}
	return "", "", false
}

func parseMappingTransitiveSemanticRows(rows dependencySemanticRows) (mappingTransitiveSemanticState, error) {
	result := mappingTransitiveSemanticState{byID: map[string]mappingTransitiveSemanticBinding{}}
	manifest := rows.byKind["artifact_manifest"][0]
	declaredCount, countOK := semanticInt64(manifest.data, "dependency_count")
	admissionAuthorized, admissionOK := semanticBool(manifest.data, "canonical_admission_authorized")
	if !countOK || declaredCount < 0 || declaredCount != int64(len(rows.byKind["mapping_transitive_dependency"])) || !admissionOK || admissionAuthorized {
		return result, semanticRowError(rows, manifest, "transitive mapping manifest does not close its candidate dependency roster")
	}
	bindings := make([]mappingTransitiveSemanticBinding, 0, int(declaredCount))
	for _, row := range rows.byKind["mapping_transitive_dependency"] {
		bindingID, bindingIDOK := semanticString(row.data, "dependency_binding_id")
		ordinal, ordinalOK := semanticInt64(row.data, "precedence_ordinal")
		_, roleOK := semanticString(row.data, "dependency_role")
		artifactIdentity, artifactOK := semanticObject(row.data, "artifact_identity")
		applicability, applicabilityOK := semanticObject(row.data, "applicability")
		_, authorityOK := semanticString(row.data, "authority_posture")
		revalidation, revalidationOK := semanticBool(row.data, "exact_revalidation_required")
		validationBinding, validationOK := semanticObject(row.data, "validation_binding")
		selectorKind, selectorOK := semanticString(applicability, "selector_kind")
		selectorValues, selectorValuesOK := semanticStringSlice(applicability, "selector_values")
		artifactRef, artifactRefOK := dependencyArtifactIdentityReference(artifactIdentity)
		schemaRef, schemaRefOK := dependencyProfileReferenceFromFields(validationBinding, "validation_schema")
		profileRef, profileRefOK := dependencyProfileReferenceFromFields(validationBinding, "validation_profile")
		if !bindingIDOK || !ordinalOK || ordinal < 0 || !roleOK || !artifactOK || !artifactRefOK || !applicabilityOK || !selectorOK || !selectorValuesOK || hasEmptyOrDuplicateSemanticStrings(selectorValues) || !authorityOK || !revalidationOK || !revalidation || !validationOK || !schemaRefOK || !profileRefOK {
			return result, semanticRowError(rows, row, "transitive mapping dependency is incomplete, unpinned, or disables exact revalidation")
		}
		_ = selectorKind // Selector vocabulary and evaluation belong to the bound schema/profile.
		_ = artifactRef
		_ = schemaRef
		_ = profileRef
		if _, duplicate := result.byID[bindingID]; duplicate {
			return result, semanticRowError(rows, row, "duplicate transitive mapping dependency binding %q", bindingID)
		}
		binding := mappingTransitiveSemanticBinding{id: bindingID, ordinal: ordinal}
		result.byID[bindingID] = binding
		bindings = append(bindings, binding)
	}
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].ordinal != bindings[j].ordinal {
			return bindings[i].ordinal < bindings[j].ordinal
		}
		return bindings[i].id < bindings[j].id
	})
	for index, binding := range bindings {
		if binding.ordinal != int64(index) {
			return result, fmt.Errorf("transitive mapping dependency precedence ordinal %d does not close contiguous position %d", binding.ordinal, index)
		}
		if index > 0 && bindings[index-1].ordinal == binding.ordinal {
			return result, fmt.Errorf("transitive mapping dependency precedence ordinal %d is duplicated", binding.ordinal)
		}
		result.orderedIDs = append(result.orderedIDs, binding.id)
	}
	summary := rows.byKind["validation_summary"][0]
	summaryCount, summaryCountOK := semanticInt64(summary.data, "dependency_count")
	summaryAdmission, summaryAdmissionOK := semanticBool(summary.data, "canonical_admission_authorized")
	if !summaryCountOK || summaryCount != declaredCount || !summaryAdmissionOK || summaryAdmission {
		return result, semanticRowError(rows, summary, "transitive mapping summary does not close its exact candidate roster")
	}
	return result, nil
}

func dependencyArtifactIdentityReference(object map[string]interface{}) (dependencyProfileReference, bool) {
	if object == nil {
		return dependencyProfileReference{}, false
	}
	id, idOK := semanticString(object, "artifact")
	version, versionOK := semanticString(object, "artifact_version")
	digest, digestOK := semanticString(object, "artifact_sha256")
	if !idOK || !versionOK || !digestOK || !isLowerSHA256(digest) {
		return dependencyProfileReference{}, false
	}
	if _, err := newValidationProfileCoordinate("artifact", id, version); err != nil {
		return dependencyProfileReference{}, false
	}
	return dependencyProfileReference{id: id, version: version, digest: digest}, true
}

func dependencyProfileReferenceFromFields(object map[string]interface{}, prefix string) (dependencyProfileReference, bool) {
	if object == nil {
		return dependencyProfileReference{}, false
	}
	id, idOK := semanticString(object, prefix+"_id")
	version, versionOK := semanticString(object, prefix+"_version")
	digest, digestOK := semanticString(object, prefix+"_sha256")
	if !idOK || !versionOK || !digestOK || !isLowerSHA256(digest) {
		return dependencyProfileReference{}, false
	}
	if _, err := newValidationProfileCoordinate(prefix, id, version); err != nil {
		return dependencyProfileReference{}, false
	}
	return dependencyProfileReference{id: id, version: version, digest: digest}, true
}

func nullableDependencyProfileReference(object map[string]interface{}, prefix string) (dependencyProfileReference, bool, bool) {
	if object == nil {
		return dependencyProfileReference{}, false, false
	}
	values := []interface{}{object[prefix+"_id"], object[prefix+"_version"], object[prefix+"_sha256"]}
	nullCount := 0
	for _, value := range values {
		if value == nil {
			nullCount++
		}
	}
	if nullCount == len(values) {
		return dependencyProfileReference{}, true, false
	}
	if nullCount != 0 {
		return dependencyProfileReference{}, false, false
	}
	reference, ok := dependencyProfileReferenceFromFields(object, prefix)
	return reference, ok, ok
}

func dependencyProfileReferenceKey(reference dependencyProfileReference) string {
	return semanticIdentity(reference.id, reference.version, reference.digest)
}

func parseDocumentationClaimDerivationRows(rows dependencySemanticRows) (documentationClaimDerivationState, error) {
	result := documentationClaimDerivationState{
		artifactSHA256:    sha256Hex(rows.raw),
		derivations:       map[string]documentationDerivationDefinition{},
		validationSchemas: map[string]documentationValidationSchema{},
		classifiers:       map[string]documentationClassifierProfile{},
		resolutions:       map[string]documentationResolutionProfile{},
	}
	for _, row := range rows.byKind["validation_schema"] {
		reference, referenceOK := dependencyProfileReferenceFromFields(row.data, "validation_schema")
		claimKind, claimOK := semanticString(row.data, "claim_kind")
		dialect, dialectOK := semanticString(row.data, "schema_dialect")
		canonicalSchema, schemaOK := semanticString(row.data, "canonical_schema_json")
		if !referenceOK || !claimOK || !dialectOK || dialect != validationProfileDraft202012 || !schemaOK {
			return result, semanticRowError(rows, row, "documentation validation schema is incomplete or its exact canonical bytes do not match its digest")
		}
		authority, err := resolveDocumentationClaimSchema(reference, claimKind, canonicalSchema)
		if err != nil {
			return result, semanticRowError(rows, row, "documentation validation schema: %v", err)
		}
		key := dependencyProfileReferenceKey(reference)
		if _, duplicate := result.validationSchemas[key]; duplicate {
			return result, semanticRowError(rows, row, "duplicate documentation validation schema coordinate")
		}
		result.validationSchemas[key] = documentationValidationSchema{claimKind: claimKind, authority: authority}
	}
	for _, row := range rows.byKind["derivation_profile"] {
		reference, referenceOK := dependencyProfileReferenceFromFields(row.data, "derivation_profile")
		claimKind, claimOK := semanticString(row.data, "claim_kind")
		validationBinding, bindingOK := semanticObject(row.data, "validation_schema_binding")
		validationReference, validationOK := dependencyProfileReferenceFromFields(validationBinding, "validation_schema")
		if !referenceOK || !claimOK || !bindingOK || !validationOK {
			return result, semanticRowError(rows, row, "documentation derivation profile is incomplete or unbound")
		}
		key := dependencyProfileReferenceKey(reference)
		if _, duplicate := result.derivations[key]; duplicate {
			return result, semanticRowError(rows, row, "duplicate documentation derivation profile coordinate")
		}
		result.derivations[key] = documentationDerivationDefinition{claimKind: claimKind, validationSchema: validationReference}
	}
	for _, row := range rows.byKind["classifier_profile"] {
		reference, referenceOK := dependencyProfileReferenceFromFields(row.data, "classifier_profile")
		claimKind, claimOK := semanticString(row.data, "input_claim_kind")
		semanticClasses, semanticsOK := semanticStringSlice(row.data, "closed_output_union")
		carriers, carriersOK := semanticStringSlice(row.data, "authoritative_carrier_union")
		computationPaths, pathsOK := semanticStringSlice(row.data, "computation_path_union")
		program, programOK := semanticObject(row.data, "program")
		if !referenceOK || !claimOK || !semanticsOK || hasDuplicateStrings(semanticClasses) || !carriersOK || hasEmptyOrDuplicateSemanticStrings(carriers) || !pathsOK || hasEmptyOrDuplicateSemanticStrings(computationPaths) || !programOK {
			return result, semanticRowError(rows, row, "documentation classifier profile is incomplete or has a non-closed output union")
		}
		key := dependencyProfileReferenceKey(reference)
		if _, duplicate := result.classifiers[key]; duplicate {
			return result, semanticRowError(rows, row, "duplicate documentation classifier profile coordinate")
		}
		profile := documentationClassifierProfile{
			claimKind: claimKind, semanticClasses: stringSet(semanticClasses), carriers: stringSet(carriers), computationPaths: stringSet(computationPaths), program: program,
		}
		programKind, kindOK := semanticString(program, "program_kind")
		if !kindOK {
			return result, semanticRowError(rows, row, "documentation classifier profile has no closed executable program kind")
		}
		switch programKind {
		case exactValueClassifierProgramKind:
			compiled, err := parseExactValueClassifierProgram(profile, reference, result.validationSchemas)
			if err != nil {
				return result, semanticRowError(rows, row, "exact-value classifier profile: %v", err)
			}
			profile.exactValueProgram = &compiled
		case operationClassifierProgramKind:
			if _, err := parseOperationClassifierProgram(profile, reference); err != nil {
				return result, semanticRowError(rows, row, "operation classifier profile: %v", err)
			}
		default:
			return result, semanticRowError(rows, row, "documentation classifier program kind %q is outside the closed executable registry", programKind)
		}
		result.classifiers[key] = profile
	}
	for _, row := range rows.byKind["dependency_resolution_profile"] {
		reference, referenceOK := dependencyProfileReferenceFromFields(row.data, "resolution_profile")
		unresolvedDisposition, dispositionOK := semanticString(row.data, "unresolved_disposition")
		publicationAllowed, publicationOK := semanticBool(row.data, "publication_allowed_without_complete_coordinates")
		if !referenceOK || !dispositionOK || unresolvedDisposition != "fail_closed" || !publicationOK || publicationAllowed {
			return result, semanticRowError(rows, row, "documentation dependency-resolution profile does not fail closed")
		}
		key := dependencyProfileReferenceKey(reference)
		if _, duplicate := result.resolutions[key]; duplicate {
			return result, semanticRowError(rows, row, "duplicate documentation dependency-resolution profile coordinate")
		}
		result.resolutions[key] = documentationResolutionProfile{failClosed: true}
	}
	for _, key := range sortedProviderStringMapKeys(result.derivations) {
		derivation := result.derivations[key]
		validation, exists := result.validationSchemas[dependencyProfileReferenceKey(derivation.validationSchema)]
		if !exists || validation.claimKind != derivation.claimKind {
			return result, fmt.Errorf("documentation derivation profile %q does not resolve an exact same-claim validation schema", key)
		}
	}
	manifest := rows.byKind["artifact_manifest"][0]
	manifestAdmission, manifestAdmissionOK := semanticBool(manifest.data, "canonical_admission_authorized")
	manifestReexecution, manifestReexecutionOK := semanticBool(manifest.data, "independent_generic_reexecution_required")
	summary := rows.byKind["validation_summary"][0]
	summaryAdmission, summaryAdmissionOK := semanticBool(summary.data, "canonical_admission_authorized")
	summaryReexecution, summaryReexecutionOK := semanticBool(summary.data, "independent_generic_reexecution_required")
	for _, check := range []struct {
		field string
		want  int64
	}{
		{"validation_schema_count", int64(len(result.validationSchemas))},
		{"derivation_profile_count", int64(len(result.derivations))},
		{"classifier_profile_count", int64(len(result.classifiers))},
		{"dependency_resolution_profile_count", int64(len(result.resolutions))},
	} {
		got, ok := semanticInt64(summary.data, check.field)
		if !ok || got != check.want {
			return result, semanticRowError(rows, summary, "%s %d does not equal recomputed count %d", check.field, got, check.want)
		}
	}
	if !manifestAdmissionOK || manifestAdmission || !manifestReexecutionOK || !manifestReexecution || !summaryAdmissionOK || summaryAdmission || !summaryReexecutionOK || !summaryReexecution {
		return result, semanticRowError(rows, summary, "documentation derivation profile improperly asserts admission or bypasses independent reexecution")
	}
	return result, nil
}

func validateSurfaceDerivationBinding(rows dependencySemanticRows, row dependencySemanticRow, sourceContentSHA256 string, profiles documentationClaimDerivationState) error {
	binding, bindingOK := semanticObject(row.data, "derivation_binding")
	derivationReference, derivationOK := dependencyProfileReferenceFromFields(binding, "derivation_profile")
	validationReference, validationOK := dependencyProfileReferenceFromFields(binding, "validation_schema")
	classifierReference, classifierOK := dependencyProfileReferenceFromFields(binding, "classifier_profile")
	inputDigest, inputOK := semanticString(binding, "exact_input_source_content_sha256")
	if !bindingOK || !derivationOK || !validationOK || !classifierOK || !inputOK || inputDigest != sourceContentSHA256 {
		return semanticRowError(rows, row, "surface derivation binding is incomplete or does not bind the exact selected source body")
	}
	derivation, derivationExists := profiles.derivations[dependencyProfileReferenceKey(derivationReference)]
	validation, validationExists := profiles.validationSchemas[dependencyProfileReferenceKey(validationReference)]
	classifier, classifierExists := profiles.classifiers[dependencyProfileReferenceKey(classifierReference)]
	if !derivationExists || !validationExists || !classifierExists || dependencyProfileReferenceKey(derivation.validationSchema) != dependencyProfileReferenceKey(validationReference) || derivation.claimKind != validation.claimKind || derivation.claimKind != classifier.claimKind {
		return semanticRowError(rows, row, "surface derivation, validation-schema, and classifier references do not close on one exact claim kind")
	}
	return nil
}

func validateFieldDerivationAndExactComputation(rows dependencySemanticRows, row dependencySemanticRow, coordinate dependencyHydrationCoordinate, semantics, carrier, computationPath string, profiles documentationClaimDerivationState, closure documentationDerivationClosureProof) error {
	binding, bindingOK := semanticObject(row.data, "derivation_binding")
	if !bindingOK {
		return semanticRowError(rows, row, "derivation binding is absent")
	}
	if err := requireExactSet("field derivation binding fields", stringMapKeysAsSet(binding), map[string]struct{}{
		"derivation_profile_id": {}, "derivation_profile_version": {}, "derivation_profile_sha256": {},
		"validation_schema_id": {}, "validation_schema_version": {}, "validation_schema_sha256": {},
		"classifier_profile_id": {}, "classifier_profile_version": {}, "classifier_profile_sha256": {},
		"exact_input_documentation_fact_id": {}, "exact_input_evidence_locator_id": {},
		"exact_input_claim_sha256": {}, "exact_input_projection_sha256": {}, "exact_classifier_rule_id": {},
		"exact_input_coordinate": {}, "reexecution_status": {},
	}); err != nil {
		return semanticRowError(rows, row, "%v", err)
	}
	derivationReference, derivationOK := dependencyProfileReferenceFromFields(binding, "derivation_profile")
	validationReference, validationOK := dependencyProfileReferenceFromFields(binding, "validation_schema")
	classifierReference, classifierOK := dependencyProfileReferenceFromFields(binding, "classifier_profile")
	exactInput, inputOK := semanticObject(binding, "exact_input_coordinate")
	inputCoordinate, inputErr := parseDependencyHydrationCoordinate(exactInput)
	rowFactID, rowFactOK := semanticString(row.data, exactDocumentationDerivedFactIDField)
	inputFactID, inputFactOK := semanticString(binding, "exact_input_documentation_fact_id")
	inputLocatorID, inputLocatorOK := semanticString(binding, "exact_input_evidence_locator_id")
	inputClaimSHA256, inputClaimOK := semanticString(binding, "exact_input_claim_sha256")
	inputProjectionSHA256, inputProjectionOK := semanticString(binding, "exact_input_projection_sha256")
	classifierRuleID, classifierRuleOK := semanticString(binding, "exact_classifier_rule_id")
	reexecutionStatus, reexecutionOK := semanticString(binding, "reexecution_status")
	if !derivationOK || !validationOK || !classifierOK || !inputOK || inputErr != nil || !rowFactOK || !inputFactOK || inputFactID != rowFactID || !inputLocatorOK || !inputClaimOK || !isLowerSHA256(inputClaimSHA256) || !inputProjectionOK || !isLowerSHA256(inputProjectionSHA256) || !classifierRuleOK || !reexecutionOK || reexecutionStatus != "complete_exact_generic_reexecution" {
		return semanticRowError(rows, row, "derivation binding is incomplete or does not bind one exact reexecuted documentation claim")
	}
	derivation, derivationExists := profiles.derivations[dependencyProfileReferenceKey(derivationReference)]
	validation, validationExists := profiles.validationSchemas[dependencyProfileReferenceKey(validationReference)]
	classifier, classifierExists := profiles.classifiers[dependencyProfileReferenceKey(classifierReference)]
	if !derivationExists || !validationExists || !classifierExists || classifier.exactValueProgram == nil || dependencyProfileReferenceKey(derivation.validationSchema) != dependencyProfileReferenceKey(validationReference) || derivation.claimKind != validation.claimKind || derivation.claimKind != classifier.claimKind || dependencyProfileReferenceKey(classifier.exactValueProgram.inputValidationSchema) != dependencyProfileReferenceKey(validationReference) {
		return semanticRowError(rows, row, "derivation, validation-schema, and classifier references do not close on one exact claim kind")
	}
	fact, factExists := closure.factsByID[inputFactID]
	materializationBinding, materialized := closure.materializationBindingSHA256ByFact[inputFactID]
	if !factExists || !materialized || !isLowerSHA256(materializationBinding) || dependencyProfileReferenceKey(fact.Profile) != dependencyProfileReferenceKey(derivationReference) || fact.TargetArtifactRole != dependencySemanticRoleSourceContract || fact.TargetBindingKind != exactDocumentationTargetWholeRow {
		return semanticRowError(rows, row, "exact input fact is absent, unmaterialized, or outside the bound field derivation")
	}
	factOutput, err := decodeExactDocumentationFactOutputFields(fact)
	if err != nil {
		return semanticRowError(rows, row, "decode exact input field fact: %v", err)
	}
	factFieldName, factFieldNameOK := semanticString(factOutput, "field_name")
	factProviderType, factProviderTypeOK := semanticString(factOutput, "provider_type")
	mappedFieldName, mappedFieldNameOK := semanticString(row.data, "source_field")
	mappedProviderType, mappedProviderTypeOK := semanticString(row.data, "source_provider_type")
	if !factFieldNameOK || !factProviderTypeOK || !mappedFieldNameOK || !mappedProviderTypeOK || factFieldName != mappedFieldName || factProviderType != mappedProviderType {
		return semanticRowError(rows, row, "exact input fact does not equal the bound field name and provider type")
	}
	factCoordinate := dependencyHydrationCoordinate{
		digest: fact.EvidenceLocator.SourceContentSHA256, start: fact.EvidenceLocator.ByteStartOffset,
		end: fact.EvidenceLocator.ByteEndOffsetExclusive, count: fact.EvidenceLocator.SelectedRangeByteCount,
		rangeSHA: fact.EvidenceLocator.SelectedRangeSHA256,
	}
	if inputCoordinate != factCoordinate || inputLocatorID != fact.EvidenceLocatorID || inputClaimSHA256 != sha256Hex(fact.CanonicalOutputFields) || coordinate.digest != factCoordinate.digest || factCoordinate.start < coordinate.start || factCoordinate.end > coordinate.end {
		return semanticRowError(rows, row, "exact input fact, locator, claim bytes, or range does not equal the derivation binding and containing field coordinate")
	}
	classifierExecution, err := executeExactValueClassifier(*classifier.exactValueProgram, fact, validation)
	if err != nil {
		return semanticRowError(rows, row, "exact-value classifier reexecution: %v", err)
	}
	classifierOutput := classifierExecution.output
	if inputProjectionSHA256 != classifierExecution.inputProjectionSHA256 || classifierRuleID != classifierExecution.ruleID || semantics != classifierOutput.numericSemantics || carrier != classifierOutput.authoritativeCarrier || computationPath != classifierOutput.computationPath {
		return semanticRowError(rows, row, "asserted exact-value tuple or input projection does not equal exact generic classifier reexecution")
	}
	classifierStatus := classifierOutput.computationPath

	dependency, dependencyOK := semanticObject(row.data, "exact_computation_dependency")
	applicability, applicabilityOK := semanticString(dependency, "applicability")
	resolutionStatus, statusOK := semanticString(dependency, "resolution_status")
	resolutionReference, resolutionShapeOK, resolutionPresent := nullableDependencyProfileReference(dependency, "resolution_profile")
	if !dependencyOK || !applicabilityOK || !statusOK || !resolutionShapeOK {
		return semanticRowError(rows, row, "exact_computation_dependency is incomplete")
	}
	switch applicability {
	case "not_applicable":
		if resolutionStatus != "not_applicable" || resolutionPresent || carrier != "not_applicable" || computationPath != "not_applicable" {
			return semanticRowError(rows, row, "non-applicable exact computation dependency has a resolution or value-of-record computation carrier")
		}
	case "required":
		resolution, exists := profiles.resolutions[dependencyProfileReferenceKey(resolutionReference)]
		if resolutionStatus != "unresolved_fail_closed_gap" || classifierStatus != resolutionStatus || !resolutionPresent || !exists || !resolution.failClosed || carrier == "not_applicable" || computationPath == "not_applicable" {
			return semanticRowError(rows, row, "required exact computation dependency is not an exact unresolved fail-closed profile binding")
		}
	default:
		return semanticRowError(rows, row, "exact computation applicability %q is unsupported by the generic relationship checker", applicability)
	}
	return nil
}

func validateRowHydration(rows dependencySemanticRows, row dependencySemanticRow, loaded loadedEvidence) (dependencyHydrationCoordinate, error) {
	coordinate, err := coordinateFromRow(row.data)
	if err != nil {
		return coordinate, semanticRowError(rows, row, "%v", err)
	}
	for _, field := range []string{"content_sha256", "document_content_sha256", "evidence_body_sha256", "evidence_content_sha256"} {
		if value, present := row.data[field]; present {
			digest, ok := value.(string)
			if !ok || digest != coordinate.digest {
				return coordinate, semanticRowError(rows, row, "%s does not equal evidence_hydration_coordinate.source_content_sha256", field)
			}
		}
	}
	if value, present := row.data["block_content_sha256"]; present {
		digest, ok := value.(string)
		if !ok || digest != coordinate.rangeSHA {
			return coordinate, semanticRowError(rows, row, "block_content_sha256 does not equal evidence_hydration_coordinate.selected_range_sha256")
		}
	}
	ref, _ := semanticString(row.data, "source_ref")
	if ref == "" {
		ref, _ = semanticString(row.data, "source_symbol")
	}
	url, _ := semanticString(row.data, "source_url")
	if err := validateExactHydrationCoordinate(rows, row, coordinate, ref, url, loaded); err != nil {
		return coordinate, err
	}
	return coordinate, nil
}

func validateExactHydrationCoordinate(rows dependencySemanticRows, row dependencySemanticRow, coordinate dependencyHydrationCoordinate, ref, sourceURL string, loaded loadedEvidence) error {
	if !isLowerSHA256(coordinate.digest) || !isLowerSHA256(coordinate.rangeSHA) || coordinate.start < 0 || coordinate.end <= coordinate.start || coordinate.count <= 0 || coordinate.end-coordinate.start != coordinate.count {
		return semanticRowError(rows, row, "evidence hydration coordinate is malformed")
	}
	body, ok := loaded.Bodies[coordinate.digest]
	if !ok {
		return semanticRowError(rows, row, "evidence hydration digest %s resolves no exact selected evidence body", coordinate.digest)
	}
	if coordinate.end > int64(len(body.Bytes)) {
		return semanticRowError(rows, row, "evidence hydration range [%d,%d) exceeds exact body length %d", coordinate.start, coordinate.end, len(body.Bytes))
	}
	selected := body.Bytes[coordinate.start:coordinate.end]
	if int64(len(selected)) != coordinate.count || sha256Hex(selected) != coordinate.rangeSHA {
		return semanticRowError(rows, row, "evidence hydration selected range does not match byte count or range digest")
	}
	if ref == "" && sourceURL == "" {
		return nil
	}
	matches := 0
	for candidate := range body.Coordinates {
		if ref != "" && candidate.Ref != ref {
			continue
		}
		if sourceURL != "" && candidate.URL != sourceURL {
			continue
		}
		matches++
	}
	if matches != 1 {
		return semanticRowError(rows, row, "evidence hydration ref=%q url=%q resolves %d exact evidence coordinates, want exactly 1", ref, sourceURL, matches)
	}
	return nil
}

func coordinateFromRow(row map[string]interface{}) (dependencyHydrationCoordinate, error) {
	object, ok := semanticObject(row, "evidence_hydration_coordinate")
	if !ok {
		return dependencyHydrationCoordinate{}, fmt.Errorf("evidence_hydration_coordinate must be an object")
	}
	return parseDependencyHydrationCoordinate(object)
}

func parseDependencyHydrationCoordinate(object map[string]interface{}) (dependencyHydrationCoordinate, error) {
	digest, digestOK := semanticString(object, "source_content_sha256")
	start, startOK := semanticInt64(object, "byte_start_offset")
	end, endOK := semanticInt64(object, "byte_end_offset_exclusive")
	count, countOK := semanticInt64(object, "selected_range_byte_count")
	rangeSHA, rangeOK := semanticString(object, "selected_range_sha256")
	if !digestOK || !startOK || !endOK || !countOK || !rangeOK {
		return dependencyHydrationCoordinate{}, fmt.Errorf("evidence hydration coordinate has incomplete typed fields")
	}
	return dependencyHydrationCoordinate{digest: digest, start: start, end: end, count: count, rangeSHA: rangeSHA}, nil
}

func planSymbolHasExactLocator(plan *parsedPlan, symbol apiSymbol, coordinate dependencyHydrationCoordinate, ref, sourceURL string) bool {
	for _, locatorID := range symbol.EvidenceLocatorIDs {
		locator, ok := plan.Locators[locatorID]
		if !ok || locator.SourceContentSHA256 != coordinate.digest || locator.ByteStartOffset != coordinate.start || locator.ByteEndOffsetExclusive != coordinate.end || locator.SelectedRangeByteCount != coordinate.count || locator.SelectedRangeSHA256 != coordinate.rangeSHA {
			continue
		}
		if len(locator.SourceRefs) != 1 || len(locator.SourceURLs) != 1 || locator.SourceRefs[0] != ref || locator.SourceURLs[0] != sourceURL {
			continue
		}
		return true
	}
	return false
}

func sourceClassificationOccurrenceCoverageCount(occurrences []sourceClassificationOccurrence, row map[string]interface{}) int {
	coordinate, err := coordinateFromRow(row)
	if err != nil {
		return 0
	}
	ref, refOK := semanticString(row, "source_ref")
	url, urlOK := semanticString(row, "source_url")
	surfaceKind, surfaceKindOK := semanticString(row, "surface_kind")
	if !refOK || !urlOK || !surfaceKindOK {
		return 0
	}
	matches := 0
	for _, occurrence := range occurrences {
		locator := occurrence.Locator
		if occurrence.SurfaceKind != surfaceKind || locator.SourceContentSHA256 != coordinate.digest || len(locator.SourceRefs) != 1 || locator.SourceRefs[0] != ref || len(locator.SourceURLs) != 1 || locator.SourceURLs[0] != url {
			continue
		}
		if coordinate.start < locator.ByteStartOffset || coordinate.end > locator.ByteEndOffsetExclusive {
			continue
		}
		matches++
	}
	return matches
}

func sourceFieldOccurrenceIdentity(row map[string]interface{}) (string, error) {
	return fieldOccurrenceIdentity(row, map[string]string{
		"symbol":      "source_symbol",
		"surface":     "surface_kind",
		"field":       "field_name",
		"type":        "provider_type",
		"cardinality": "cardinality",
		"requirement": "provider_requirement",
		"sections":    "section_path",
	})
}

func mappingFieldOccurrenceIdentity(row map[string]interface{}) (string, error) {
	return fieldOccurrenceIdentity(row, map[string]string{
		"symbol":      "source_symbol",
		"surface":     "surface_kind",
		"field":       "source_field",
		"type":        "source_provider_type",
		"cardinality": "source_cardinality",
		"requirement": "source_requirement",
		"sections":    "source_section_path",
	})
}

func fieldOccurrenceIdentity(row map[string]interface{}, fields map[string]string) (string, error) {
	values := make([]string, 0, 9)
	for _, logical := range []string{"symbol", "surface", "field", "type", "cardinality", "requirement"} {
		value, ok := semanticStringAllowEmpty(row, fields[logical])
		if !ok || (logical != "type" && logical != "requirement" && value == "") {
			return "", fmt.Errorf("field occurrence has invalid %s field %q", logical, fields[logical])
		}
		values = append(values, value)
	}
	sections, ok := semanticStringSlice(row, fields["sections"])
	if !ok {
		return "", fmt.Errorf("field occurrence has invalid section path %q", fields["sections"])
	}
	sectionJSON, _ := json.Marshal(sections)
	values = append(values, string(sectionJSON))
	evidenceIdentity, err := fieldOccurrenceEvidenceIdentity(row)
	if err != nil {
		return "", err
	}
	values = append(values, evidenceIdentity)
	return semanticIdentity(values...), nil
}

func fieldOccurrenceEvidenceIdentity(row map[string]interface{}) (string, error) {
	if value, present := row[exactDocumentationDerivedFactIDField]; present {
		factID, ok := value.(string)
		if !ok || factID == "" || !canonicalEvidenceMetadataString(factID, 512) {
			return "", fmt.Errorf("field occurrence has invalid %s", exactDocumentationDerivedFactIDField)
		}
		return semanticIdentity(exactDocumentationDerivedFactIDField, factID), nil
	}
	manifestSHA, manifestOK := semanticString(row, "evidence_manifest_sha256")
	sourceRef, refOK := semanticString(row, "source_ref")
	sourceURL, urlOK := semanticString(row, "source_url")
	sourceContentSHA, contentOK := semanticString(row, "source_content_sha256")
	locatorID, locatorOK := semanticString(row, "evidence_locator_id")
	coordinate, coordinateErr := coordinateFromRow(row)
	if !manifestOK || !isLowerSHA256(manifestSHA) || !refOK || !urlOK || !contentOK || !isLowerSHA256(sourceContentSHA) || !locatorOK || !canonicalEvidenceMetadataString(locatorID, 512) || coordinateErr != nil {
		return "", fmt.Errorf("field occurrence without %s requires the full canonical manifest/ref/url/body/range/locator coordinate", exactDocumentationDerivedFactIDField)
	}
	if coordinate.digest != sourceContentSHA {
		return "", fmt.Errorf("field occurrence source_content_sha256 does not equal its exact hydration body digest")
	}
	return semanticIdentity("canonical_field_occurrence_locator", manifestSHA, sourceRef, sourceURL, sourceContentSHA, coordinateIdentity(coordinate), locatorID), nil
}

func sampleBlockIdentity(symbol, blockDigest string, coordinate dependencyHydrationCoordinate) string {
	return semanticIdentity(symbol, blockDigest, coordinateIdentity(coordinate))
}

func coordinateIdentity(coordinate dependencyHydrationCoordinate) string {
	return semanticIdentity(coordinate.digest, strconv.FormatInt(coordinate.start, 10), strconv.FormatInt(coordinate.end, 10), strconv.FormatInt(coordinate.count, 10), coordinate.rangeSHA)
}

func semanticIdentity(values ...string) string {
	var builder strings.Builder
	for _, value := range values {
		builder.WriteString(strconv.Itoa(len(value)))
		builder.WriteByte(':')
		builder.WriteString(value)
	}
	return builder.String()
}

func requireSemanticKeySet[A any, B any](name string, actual map[string]A, expected map[string]B) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("%s count %d does not equal exact expected count %d", name, len(actual), len(expected))
	}
	for _, key := range sortedProviderStringMapKeys(expected) {
		if _, ok := actual[key]; !ok {
			return fmt.Errorf("%s is missing semantic identity %q", name, key)
		}
	}
	return nil
}

func semanticRowError(rows dependencySemanticRows, row dependencySemanticRow, format string, values ...interface{}) error {
	return fmt.Errorf("dependency artifact %q line %d %s: %s", rows.path, row.line, row.kind, fmt.Sprintf(format, values...))
}

func semanticString(object map[string]interface{}, key string) (string, bool) {
	value, ok := object[key].(string)
	return value, ok && value != ""
}

func semanticStringAllowEmpty(object map[string]interface{}, key string) (string, bool) {
	value, ok := object[key].(string)
	return value, ok
}

func semanticNullableString(object map[string]interface{}, key string) (string, bool) {
	value, present := object[key]
	if !present {
		return "", false
	}
	if value == nil {
		return "", true
	}
	text, ok := value.(string)
	return text, ok
}

func semanticBool(object map[string]interface{}, key string) (bool, bool) {
	value, ok := object[key].(bool)
	return value, ok
}

func semanticInt64(object map[string]interface{}, key string) (int64, bool) {
	value, ok := object[key].(json.Number)
	if !ok {
		return 0, false
	}
	return semanticJSONInt64(value)
}

func semanticJSONInt64(value interface{}) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(number.String(), 10, 64)
	return parsed, err == nil
}

func semanticObject(object map[string]interface{}, key string) (map[string]interface{}, bool) {
	value, ok := object[key].(map[string]interface{})
	return value, ok
}

func semanticStringSlice(object map[string]interface{}, key string) ([]string, bool) {
	values, ok := object[key].([]interface{})
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, false
		}
		result = append(result, text)
	}
	return result, true
}

func semanticNullableStringSlice(object map[string]interface{}, key string) ([]string, bool) {
	value, present := object[key]
	if !present {
		return nil, false
	}
	if value == nil {
		return []string{}, true
	}
	return semanticStringSlice(object, key)
}

func semanticObjectSlice(object map[string]interface{}, key string) ([]map[string]interface{}, bool) {
	values, ok := object[key].([]interface{})
	if !ok {
		return nil, false
	}
	result := make([]map[string]interface{}, 0, len(values))
	for _, value := range values {
		entry, ok := value.(map[string]interface{})
		if !ok {
			return nil, false
		}
		result = append(result, entry)
	}
	return result, true
}

func semanticRawMember(raw []byte, key string) ([]byte, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	value, ok := object[key]
	if !ok {
		return nil, fmt.Errorf("field %q is absent", key)
	}
	return value, nil
}

func semanticStringSet(object map[string]interface{}, key string) (map[string]struct{}, error) {
	values, ok := semanticStringSlice(object, key)
	if !ok || hasDuplicateStrings(values) {
		return nil, fmt.Errorf("field %q must be a unique string roster", key)
	}
	return stringSet(values), nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func mapKeysAsSet(values map[string]fieldSecurityClassDefinition) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for value := range values {
		result[value] = struct{}{}
	}
	return result
}

func hasDuplicateStrings(values []string) bool {
	return len(stringSet(values)) != len(values)
}

func hasEmptyOrDuplicateSemanticStrings(values []string) bool {
	for _, value := range values {
		if value == "" {
			return true
		}
	}
	return hasDuplicateStrings(values)
}

func equalStringSlices(left, right []string) bool {
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

func equalStringSet(left, right []string) bool {
	if hasEmptyOrDuplicateSemanticStrings(left) || hasEmptyOrDuplicateSemanticStrings(right) {
		return false
	}
	return len(left) == len(right) && setContainsAll(stringSet(left), stringSet(right))
}

func setContainsAll(left, right map[string]struct{}) bool {
	for value := range right {
		if _, ok := left[value]; !ok {
			return false
		}
	}
	return true
}

func requireEqualStringFields(left, right map[string]interface{}, fields ...string) error {
	for _, field := range fields {
		leftValue, leftOK := semanticString(left, field)
		rightValue, rightOK := semanticString(right, field)
		if !leftOK || !rightOK || leftValue != rightValue {
			return fmt.Errorf("field %s does not equal its exact source row", field)
		}
	}
	return nil
}

func anyStringPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix != "" && strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func snakeTokenPresent(value, token string) bool {
	for _, part := range strings.Split(value, "_") {
		if part == token {
			return true
		}
	}
	return false
}

func canonicalSemanticToken(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func semanticTextContainsAll(value interface{}, fragments ...string) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	normalized := canonicalSemanticToken(text)
	for _, fragment := range fragments {
		if !strings.Contains(normalized, canonicalSemanticToken(fragment)) {
			return false
		}
	}
	return true
}

func semanticTextContainsAny(value interface{}, fragments ...string) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	normalized := canonicalSemanticToken(text)
	for _, fragment := range fragments {
		if strings.Contains(normalized, canonicalSemanticToken(fragment)) {
			return true
		}
	}
	return false
}

func semanticRosterContainsToken(values []string, token string) bool {
	want := canonicalSemanticToken(token)
	for _, value := range values {
		if canonicalSemanticToken(value) == want {
			return true
		}
	}
	return false
}

func semanticRosterContainsAnyToken(values []string, tokens ...string) bool {
	for _, token := range tokens {
		if semanticRosterContainsToken(values, token) {
			return true
		}
	}
	return false
}

func semanticRosterContainsTokenFragment(values []string, fragment string) bool {
	fragment = canonicalSemanticToken(fragment)
	for _, value := range values {
		if strings.Contains(canonicalSemanticToken(value), fragment) {
			return true
		}
	}
	return false
}

func validateExactNumericDisposition(semantics, carrier, computationPath string) error {
	if semantics == "" || carrier == "" || computationPath == "" {
		return fmt.Errorf("numeric disposition requires nonempty schema-owned semantics, carrier, and computation bindings")
	}
	if semanticNumericTextUnsafe(semantics) || semanticNumericTextUnsafe(carrier) || semanticNumericTextUnsafe(computationPath) {
		return fmt.Errorf("IEEE/FLOAT/binary/native arithmetic semantics are forbidden")
	}
	if (carrier == "not_applicable") != (computationPath == "not_applicable") {
		return fmt.Errorf("numeric carrier and computation applicability arms disagree")
	}
	return nil
}

func semanticNumericTextUnsafe(value string) bool {
	normalized := canonicalSemanticToken(value)
	for _, fragment := range []string{"ieee754", "float32", "float64", "binaryfloat", "gofloat", "nativego", "nativearithmetic", "doubleprecision"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return normalized == "float" || normalized == "double"
}

func semanticNumericPolicyTextUnsafe(value string) bool {
	if !semanticNumericTextUnsafe(value) {
		return false
	}
	normalized := canonicalSemanticToken(value)
	for _, safetyPosture := range []string{"never", "forbidden", "notauthority", "nonauthoritative"} {
		if strings.Contains(normalized, safetyPosture) {
			return false
		}
	}
	return true
}

func sortedSemanticKinds(rows dependencySemanticRows) []string {
	result := make([]string, 0, len(rows.byKind))
	for kind := range rows.byKind {
		result = append(result, kind)
	}
	sort.Strings(result)
	return result
}

func equalOrderedStrings(left, right []string) bool {
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
