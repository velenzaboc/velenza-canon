package providerplan

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"sort"
	"strconv"
	"strings"
)

// Candidate closure scanning is deliberately streaming and deterministic.
// The graph plan is first, followed by the exact dependency roles in the
// order declared by the plan contract. Transitive dependencies immediately
// follow the exact parent binding that introduces them. Content digests are
// identities, never reconstruction-order authority.
type candidateClosureItem struct {
	label string
	raw   []byte
}

type candidateClosureBinding struct {
	role   string
	digest string
}

type mappingTransitiveClosureBinding struct {
	bindingID                string
	precedenceOrdinal        uint64
	dependencyRole           string
	artifactID               string
	artifactVersion          string
	artifactDigest           string
	validationSchemaID       string
	validationSchemaVersion  string
	validationSchemaDigest   string
	validationProfileID      string
	validationProfileVersion string
	validationProfileDigest  string
}

func canonicalPlanDependencyClosure(planLabel string, planRaw []byte, plan *parsedPlan, dependencies map[string]artifactInput, semanticValidation dependencySemanticValidationResolution) ([]candidateClosureItem, error) {
	if plan == nil || plan.Manifest == nil {
		return nil, fmt.Errorf("candidate closure has no parsed plan manifest")
	}
	if err := validateDependencySemanticProof(semanticValidation.proof, semanticValidation.roleArtifacts); err != nil {
		return nil, fmt.Errorf("candidate closure: %w", err)
	}
	proof := semanticValidation.proof
	items := make([]candidateClosureItem, 0, len(dependencies)+1)
	items = append(items, candidateClosureItem{label: planLabel, raw: planRaw})
	seen := make(map[string]string, len(dependencies))
	sequenceIdentities := []string{lengthPrefixedIdentityKey("graph_plan", sha256Hex(planRaw))}

	var appendDependency func(role, digest string) error
	appendDependency = func(role, digest string) error {
		bindingName := candidateClosureRoleBindingName(role)
		if !isLowerSHA256(digest) {
			return fmt.Errorf("candidate closure binding %s has no exact lowercase dependency digest", bindingName)
		}
		if priorRole, duplicate := seen[digest]; duplicate {
			priorBinding := candidateClosureRoleBindingName(priorRole)
			if candidateClosureDirectBindingField(role) != "" && candidateClosureDirectBindingField(priorRole) != "" {
				return fmt.Errorf("plan dependency fields %s and %s alias the same exact artifact digest %s", priorBinding, bindingName, digest)
			}
			if role == "surface_family_disposition" && candidateClosureDirectBindingField(priorRole) != "" {
				return fmt.Errorf("surface_family_disposition_sha256 aliases direct dependency field %s at digest %s", priorBinding, digest)
			}
			return fmt.Errorf("candidate closure dependency %s is ambiguously bound by roles %s and %s", digest, priorRole, role)
		}
		dependency, exists := dependencies[digest]
		if !exists {
			return fmt.Errorf("candidate closure binding %s digest %s is not bound to exact supplied dependency-artifact bytes", bindingName, digest)
		}
		if dependency.SHA256 != digest || sha256Hex(dependency.Raw) != digest {
			return fmt.Errorf("candidate closure role %s digest %s does not equal its supplied exact bytes", role, digest)
		}
		seen[digest] = role
		sequenceIdentities = append(sequenceIdentities, lengthPrefixedIdentityKey(role, digest))
		items = append(items, candidateClosureItem{
			label: fmt.Sprintf("dependency role %s artifact %q (%s)", role, dependency.Path, digest),
			raw:   dependency.Raw,
		})

		switch role {
		case "field_mapping_candidate":
			surfaceDigest, ok := manifestString(dependency.Manifest, "surface_family_disposition_sha256")
			if !ok {
				return fmt.Errorf("candidate closure field-mapping dependency has no exact surface_family_disposition_sha256 binding")
			}
			if err := appendDependency("surface_family_disposition", surfaceDigest); err != nil {
				return err
			}
			securityPolicyDigest, ok := manifestString(dependency.Manifest, "field_security_policy_artifact_sha256")
			if !ok {
				return fmt.Errorf("candidate closure field-mapping dependency has no exact field_security_policy_artifact_sha256 binding")
			}
			securityPolicy, exists := dependencies[securityPolicyDigest]
			if !exists {
				return fmt.Errorf("field_security_policy artifact digest %s is not bound to exact supplied bytes", securityPolicyDigest)
			}
			if err := requireClosureSchemaProofArtifact(proof, "field_security_policy", securityPolicy); err != nil {
				return err
			}
			if err := appendDependency("field_security_policy", securityPolicyDigest); err != nil {
				return err
			}
			rosterDigest, ok := manifestString(dependency.Manifest, "mapping_transitive_dependency_roster_sha256")
			if !ok {
				return fmt.Errorf("candidate closure field-mapping dependency has no exact mapping_transitive_dependency_roster_sha256 binding")
			}
			rosterInput, exists := dependencies[rosterDigest]
			if !exists {
				return fmt.Errorf("mapping_transitive_dependency_roster digest %s is not bound to exact supplied bytes", rosterDigest)
			}
			if err := requireClosureSchemaProofArtifact(proof, "mapping_transitive_dependency_roster", rosterInput); err != nil {
				return err
			}
			if err := appendDependency("mapping_transitive_dependency_roster", rosterDigest); err != nil {
				return err
			}
			derivationDigest, ok := manifestString(dependency.Manifest, "documentation_claim_derivation_profile_sha256")
			if !ok {
				return fmt.Errorf("candidate closure field-mapping dependency has no exact documentation_claim_derivation_profile_sha256 binding")
			}
			derivationProfile, exists := dependencies[derivationDigest]
			if !exists {
				return fmt.Errorf("documentation_claim_derivation_profile digest %s is not bound to exact supplied bytes", derivationDigest)
			}
			if err := requireClosureSchemaProofArtifact(proof, "documentation_claim_derivation_profile", derivationProfile); err != nil {
				return err
			}
			if err := appendDependency("documentation_claim_derivation_profile", derivationDigest); err != nil {
				return err
			}
		case "mapping_transitive_dependency_roster":
			bindings, err := mappingTransitiveDependencyClosureBindings(dependency, proof)
			if err != nil {
				return err
			}
			profileEnvelopeSchemaPin := plan.Manifest.DependencySemanticValidation.Schema
			profileEnvelopeSchema, exists := dependencies[profileEnvelopeSchemaPin.RawSHA256]
			if !exists {
				return fmt.Errorf("mapping transitive validation profiles have no exact plan-bound generic profile-envelope schema bytes")
			}
			// The mapping artifacts themselves are the precedence-bearing
			// dependency chain. Keep them adjacent and traverse only by the
			// explicit ordinal; artifact content digests and JSON row order have
			// no ordering effect.
			for _, binding := range bindings {
				boundProfile, exists := dependencies[binding.validationProfileDigest]
				if !exists {
					return fmt.Errorf("mapping transitive dependency %s validation profile digest %s is not bound to exact supplied bytes", binding.bindingID, binding.validationProfileDigest)
				}
				if err := validateMappingTransitiveValidationProfile(boundProfile, profileEnvelopeSchema, profileEnvelopeSchemaPin, binding); err != nil {
					return err
				}
				boundArtifact, exists := dependencies[binding.artifactDigest]
				if !exists {
					return fmt.Errorf("mapping transitive dependency %s artifact digest %s is not bound to exact supplied bytes", binding.bindingID, binding.artifactDigest)
				}
				boundSchema, exists := dependencies[binding.validationSchemaDigest]
				if !exists {
					return fmt.Errorf("mapping transitive dependency %s validation schema digest %s is not bound to exact supplied bytes", binding.bindingID, binding.validationSchemaDigest)
				}
				if err := validateMappingTransitiveArtifactSchema(boundArtifact, boundSchema, binding); err != nil {
					return err
				}
				artifactRole := lengthPrefixedIdentityKey("mapping_transitive_dependency_artifact", strconv.FormatUint(binding.precedenceOrdinal, 10), binding.bindingID, binding.dependencyRole, binding.artifactID, binding.artifactVersion)
				if err := appendDependency(artifactRole, binding.artifactDigest); err != nil {
					return err
				}
			}
			// Validation authority is an exact-bound dependency too, but it is
			// not precedence input. Traverse the two closed support roles in
			// fixed role blocks after the ordered mapping chain.
			schemaBindings, err := uniqueMappingTransitiveValidationSchemaBindings(bindings)
			if err != nil {
				return err
			}
			for _, binding := range schemaBindings {
				schemaRole := lengthPrefixedIdentityKey("mapping_transitive_validation_schema", strconv.FormatUint(binding.precedenceOrdinal, 10), binding.bindingID, binding.validationSchemaID, binding.validationSchemaVersion)
				if err := appendDependency(schemaRole, binding.validationSchemaDigest); err != nil {
					return err
				}
			}
			for _, binding := range bindings {
				profileRole := lengthPrefixedIdentityKey("mapping_transitive_validation_profile", strconv.FormatUint(binding.precedenceOrdinal, 10), binding.bindingID, binding.validationProfileID, binding.validationProfileVersion)
				if err := appendDependency(profileRole, binding.validationProfileDigest); err != nil {
					return err
				}
			}
		case "evidence_selection_roster":
			rawBindings, _ := dependency.Manifest["classification_artifact_bindings"].([]interface{})
			for index, rawBinding := range rawBindings {
				binding, ok := rawBinding.(map[string]interface{})
				if !ok {
					return fmt.Errorf("candidate closure evidence-selection classification binding %d is not an object", index)
				}
				artifactID, idOK := manifestString(binding, "artifact_id")
				artifactVersion, versionOK := manifestString(binding, "artifact_version")
				artifactDigest, digestOK := manifestString(binding, "artifact_sha256")
				if !idOK || !versionOK || !digestOK {
					return fmt.Errorf("candidate closure evidence-selection classification binding %d has no exact identity", index)
				}
				roleIdentity := lengthPrefixedIdentityKey("classification_artifact", artifactID, artifactVersion)
				if err := appendDependency(roleIdentity, artifactDigest); err != nil {
					return err
				}
			}
		}
		return nil
	}

	directBindings, err := canonicalPlanDependencyBindings(plan)
	if err != nil {
		return nil, err
	}
	for _, binding := range directBindings {
		if err := appendDependency(binding.role, binding.digest); err != nil {
			return nil, err
		}
	}
	semanticValidationBinding := plan.Manifest.DependencySemanticValidation
	if err := appendDependency(semanticValidationBinding.Profile.Role, semanticValidationBinding.Profile.RawSHA256); err != nil {
		return nil, err
	}
	if err := appendDependency(semanticValidationBinding.Schema.Role, semanticValidationBinding.Schema.RawSHA256); err != nil {
		return nil, err
	}
	for _, role := range dependencySemanticRequiredRoles {
		if err := requireClosureSchemaProofArtifact(proof, role, semanticValidation.roleArtifacts[role]); err != nil {
			return nil, err
		}
	}
	type schemaCoordinate struct{ id, version string }
	seenSchemaDigests := map[string]schemaCoordinate{}
	for _, role := range dependencySemanticRequiredRoles {
		binding := proof.byRole[role]
		coordinate := schemaCoordinate{id: binding.schemaID, version: binding.schemaVersion}
		if prior, reused := seenSchemaDigests[binding.schemaSHA256]; reused {
			if prior != coordinate {
				return nil, fmt.Errorf("dependency semantic validation schema digest %s aliases coordinates %s/%s and %s/%s", binding.schemaSHA256, prior.id, prior.version, coordinate.id, coordinate.version)
			}
			continue
		}
		seenSchemaDigests[binding.schemaSHA256] = coordinate
		schemaRole := lengthPrefixedIdentityKey("dependency_semantic_artifact_schema", role, binding.schemaID, binding.schemaVersion)
		if err := appendDependency(schemaRole, binding.schemaSHA256); err != nil {
			return nil, err
		}
	}
	targetArtifactBindings, targetSchemaBindings, err := canonicalDocumentationTargetClosureBindings(semanticValidation, dependencies)
	if err != nil {
		return nil, err
	}
	for _, binding := range targetArtifactBindings {
		if err := appendDependency(binding.role, binding.digest); err != nil {
			return nil, err
		}
	}
	for _, binding := range targetSchemaBindings {
		if err := appendDependency(binding.role, binding.digest); err != nil {
			return nil, err
		}
	}
	if len(seen) != len(dependencies) {
		extras := make([]string, 0, len(dependencies)-len(seen))
		for digest, dependency := range dependencies {
			if _, bound := seen[digest]; !bound {
				extras = append(extras, fmt.Sprintf("%s:%s", digest, dependency.Path))
			}
		}
		sort.Strings(extras)
		return nil, fmt.Errorf("candidate closure dependencies are supplied but not bound by the exact semantic binding sequence: %s", strings.Join(extras, ", "))
	}
	// The exact plan and dependency digests bind this reproducible sequence into
	// the eventual receipt. Its collision-safe identity is retained in the scan
	// label so failures name the exact sequence that was evaluated.
	sequenceSHA := sha256Hex([]byte(lengthPrefixedIdentityKey(sequenceIdentities...)))
	items[0].label = fmt.Sprintf("%s (semantic closure sequence %s)", planLabel, sequenceSHA)
	return items, nil
}

// canonicalDocumentationTargetClosureBindings derives the exact target block
// from the sealed target authority. The semantic projection remains the fixed
// role artifact; a distinct materialization target follows it as a separately
// bound dependency. A same-digest fallback is already traversed through the
// semantic role and therefore contributes no second closure item.
func canonicalDocumentationTargetClosureBindings(
	semanticValidation dependencySemanticValidationResolution,
	dependencies map[string]artifactInput,
) ([]candidateClosureBinding, []candidateClosureBinding, error) {
	authority := semanticValidation.derivationTargets
	targetArtifacts := semanticValidation.derivationTargetArtifacts
	if authority.seal != dependencySemanticDerivationTargetSchemaAuthorityIdentity || len(authority.byRole) == 0 {
		return nil, nil, fmt.Errorf("candidate closure has no sealed documentation target authority")
	}
	if err := requireExactSet(
		"candidate closure documentation target artifact roster",
		stringMapKeysAsSet(targetArtifacts),
		stringMapKeysAsSet(authority.byRole),
	); err != nil {
		return nil, nil, err
	}

	type targetSchemaCoordinate struct {
		id      string
		version string
	}
	type targetSchemaBinding struct {
		ownerRole  string
		schemaRole string
		coordinate targetSchemaCoordinate
		digest     string
	}

	semanticSchemaDigestByCoordinate := make(map[targetSchemaCoordinate]string, len(semanticValidation.proof.byRole))
	semanticSchemaCoordinateByDigest := make(map[string]targetSchemaCoordinate, len(semanticValidation.proof.byRole))
	for _, role := range sortedProviderStringMapKeys(semanticValidation.proof.byRole) {
		binding := semanticValidation.proof.byRole[role]
		coordinate := targetSchemaCoordinate{id: binding.schemaID, version: binding.schemaVersion}
		if prior, duplicate := semanticSchemaDigestByCoordinate[coordinate]; duplicate && prior != binding.schemaSHA256 {
			return nil, nil, fmt.Errorf("candidate closure semantic schema coordinate %q version %q aliases different exact bytes", coordinate.id, coordinate.version)
		}
		if prior, duplicate := semanticSchemaCoordinateByDigest[binding.schemaSHA256]; duplicate && prior != coordinate {
			return nil, nil, fmt.Errorf("candidate closure semantic schema digest %s aliases coordinates %s/%s and %s/%s", binding.schemaSHA256, prior.id, prior.version, coordinate.id, coordinate.version)
		}
		semanticSchemaDigestByCoordinate[coordinate] = binding.schemaSHA256
		semanticSchemaCoordinateByDigest[binding.schemaSHA256] = coordinate
	}

	artifactBindings := make([]candidateClosureBinding, 0, len(targetArtifacts))
	schemaByDigest := make(map[string]targetSchemaBinding, len(targetArtifacts))
	schemaDigestByCoordinate := make(map[targetSchemaCoordinate]string, len(targetArtifacts))
	expectedDistinctArtifactRoles := map[string]struct{}{}
	traversedDistinctArtifactRoles := map[string]struct{}{}
	expectedDistinctSchemaDigests := map[string]struct{}{}
	traversedDistinctSchemaDigests := map[string]struct{}{}
	targetArtifactDigestOwners := map[string]string{}

	for _, role := range sortedProviderStringMapKeys(authority.byRole) {
		target := authority.byRole[role]
		if target.artifactRole != role {
			return nil, nil, fmt.Errorf("candidate closure documentation target role %q authority names artifact role %q", role, target.artifactRole)
		}
		semanticArtifact, semanticRoleExists := semanticValidation.roleArtifacts[role]
		semanticProof, semanticProofExists := semanticValidation.proof.byRole[role]
		if !semanticRoleExists || !semanticProofExists || semanticProof.artifactSHA256 != sha256Hex(semanticArtifact.Raw) {
			return nil, nil, fmt.Errorf("candidate closure documentation target role %q has no exact semantic projection binding", role)
		}
		targetArtifact := targetArtifacts[role]
		if !isLowerSHA256(target.artifactSHA256) || target.artifactSHA256 != sha256Hex(targetArtifact.Raw) || (targetArtifact.SHA256 != "" && targetArtifact.SHA256 != target.artifactSHA256) {
			return nil, nil, fmt.Errorf("candidate closure documentation target role %q does not bind its supplied exact artifact bytes", role)
		}
		if target.artifactSHA256 == semanticProof.artifactSHA256 {
			if target.schemaID != semanticProof.schemaID || target.schemaVersion != semanticProof.schemaVersion || target.schemaSHA256 != semanticProof.schemaSHA256 {
				return nil, nil, fmt.Errorf("candidate closure documentation target role %q same-artifact fallback does not bind the semantic projection schema", role)
			}
			continue
		}
		if priorRole, duplicate := targetArtifactDigestOwners[target.artifactSHA256]; duplicate {
			return nil, nil, fmt.Errorf("candidate closure documentation target digest %s aliases roles %q and %q", target.artifactSHA256, priorRole, role)
		}
		targetArtifactDigestOwners[target.artifactSHA256] = role
		expectedDistinctArtifactRoles[role] = struct{}{}
		artifactBindings = append(artifactBindings, candidateClosureBinding{
			role:   lengthPrefixedIdentityKey("documentation_derivation_exact_target_artifact", role),
			digest: target.artifactSHA256,
		})
		traversedDistinctArtifactRoles[role] = struct{}{}

		if !isCanonicalValidationProfileIdentity(target.schemaRole) {
			return nil, nil, fmt.Errorf("candidate closure documentation target role %q has no canonical schema role", role)
		}
		if _, err := newValidationProfileCoordinate("documentation target schema", target.schemaID, target.schemaVersion); err != nil {
			return nil, nil, fmt.Errorf("candidate closure documentation target role %q: %w", role, err)
		}
		if !isLowerSHA256(target.schemaSHA256) || target.schemaSHA256 != sha256Hex(target.schemaBytes) {
			return nil, nil, fmt.Errorf("candidate closure documentation target role %q has no exact sealed schema bytes", role)
		}
		schemaInput, exists := dependencies[target.schemaSHA256]
		if !exists || sha256Hex(schemaInput.Raw) != target.schemaSHA256 || (schemaInput.SHA256 != "" && schemaInput.SHA256 != target.schemaSHA256) || !bytes.Equal(schemaInput.Raw, target.schemaBytes) {
			return nil, nil, fmt.Errorf("candidate closure documentation target role %q schema digest %s does not bind its supplied exact bytes", role, target.schemaSHA256)
		}
		coordinate := targetSchemaCoordinate{id: target.schemaID, version: target.schemaVersion}
		if prior, duplicate := schemaDigestByCoordinate[coordinate]; duplicate && prior != target.schemaSHA256 {
			return nil, nil, fmt.Errorf("candidate closure documentation target schema coordinate %q version %q aliases different exact bytes", coordinate.id, coordinate.version)
		}
		schemaDigestByCoordinate[coordinate] = target.schemaSHA256
		if semanticDigest, reused := semanticSchemaDigestByCoordinate[coordinate]; reused {
			if semanticDigest != target.schemaSHA256 {
				return nil, nil, fmt.Errorf("candidate closure documentation target schema coordinate %q version %q aliases semantic schema with different exact bytes", coordinate.id, coordinate.version)
			}
			continue
		}
		if semanticCoordinate, reused := semanticSchemaCoordinateByDigest[target.schemaSHA256]; reused && semanticCoordinate != coordinate {
			return nil, nil, fmt.Errorf("candidate closure documentation target schema digest %s aliases semantic coordinate %s/%s and target coordinate %s/%s", target.schemaSHA256, semanticCoordinate.id, semanticCoordinate.version, coordinate.id, coordinate.version)
		}
		expectedDistinctSchemaDigests[target.schemaSHA256] = struct{}{}
		if prior, duplicate := schemaByDigest[target.schemaSHA256]; duplicate {
			if prior.coordinate != coordinate {
				return nil, nil, fmt.Errorf("candidate closure documentation target schema digest %s aliases coordinates %s/%s and %s/%s", target.schemaSHA256, prior.coordinate.id, prior.coordinate.version, coordinate.id, coordinate.version)
			}
			continue
		}
		schemaByDigest[target.schemaSHA256] = targetSchemaBinding{ownerRole: role, schemaRole: target.schemaRole, coordinate: coordinate, digest: target.schemaSHA256}
	}

	if err := requireExactSet("candidate closure distinct documentation target artifact traversal", traversedDistinctArtifactRoles, expectedDistinctArtifactRoles); err != nil {
		return nil, nil, err
	}
	schemaBindings := make([]candidateClosureBinding, 0, len(schemaByDigest))
	for _, role := range sortedProviderStringMapKeys(authority.byRole) {
		target := authority.byRole[role]
		binding, exists := schemaByDigest[target.schemaSHA256]
		if !exists || binding.ownerRole != role {
			continue
		}
		schemaBindings = append(schemaBindings, candidateClosureBinding{
			role: lengthPrefixedIdentityKey(
				"documentation_derivation_exact_target_schema",
				binding.ownerRole,
				binding.schemaRole,
				binding.coordinate.id,
				binding.coordinate.version,
			),
			digest: binding.digest,
		})
		traversedDistinctSchemaDigests[binding.digest] = struct{}{}
	}
	if err := requireExactSet("candidate closure distinct documentation target schema traversal", traversedDistinctSchemaDigests, expectedDistinctSchemaDigests); err != nil {
		return nil, nil, err
	}
	return artifactBindings, schemaBindings, nil
}

func candidateClosureDirectBindingField(role string) string {
	switch role {
	case "provider_neutral_compilation_profile":
		return "provider_neutral_compilation_profile_sha256"
	case "source_contract_index":
		return "source_contract_index_sha256"
	case "sample_shape_index":
		return "sample_shape_index_sha256"
	case "protocol_contract_index":
		return "protocol_contract_index_sha256"
	case "field_mapping_candidate":
		return "field_mapping_candidate_sha256"
	case dependencySemanticRoleOperationApplicability:
		return "operation_applicability_profile_sha256"
	case dependencySemanticRoleAPIGraphApplicability:
		return "api_graph_applicability_profile_sha256"
	case "evidence_selection_roster":
		return "evidence_selection_roster_sha256"
	default:
		return ""
	}
}

func candidateClosureRoleBindingName(role string) string {
	if field := candidateClosureDirectBindingField(role); field != "" {
		return field
	}
	if role == "surface_family_disposition" {
		return "surface_family_disposition_sha256"
	}
	if role == "mapping_transitive_dependency_roster" {
		return "mapping_transitive_dependency_roster_sha256"
	}
	return role
}

func mappingTransitiveDependencyClosureBindings(input artifactInput, proof dependencySemanticValidationProof) ([]mappingTransitiveClosureBinding, error) {
	if err := requireClosureSchemaProofArtifact(proof, dependencySemanticRoleMappingTransitiveRoster, input); err != nil {
		return nil, err
	}
	if !input.Structured || input.Manifest == nil {
		return nil, fmt.Errorf("mapping transitive dependency roster %q has no schema-validated artifact manifest", input.Path)
	}
	dependencyCount, countOK := manifestInteger(input.Manifest, "dependency_count")
	roleRoster, roleRosterOK := manifestStringSlice(input.Manifest, "closed_dependency_role_roster")
	if !countOK || dependencyCount <= 0 || !roleRosterOK || !canonicalUniqueOrderedOpaqueStrings(roleRoster) {
		return nil, fmt.Errorf("mapping transitive dependency roster %q manifest does not bind a nonempty exact dependency count and canonical opaque role roster", input.Path)
	}

	// Row-kind names and row shapes are schema authority. Select the traversal
	// rows only by the generic fields the scanner must interpret after the
	// sealed proof has established that every row conforms to the exact bound
	// schema. A partial traversal field set is ambiguity and fails closed.
	rows := make([]map[string]interface{}, 0, dependencyCount)
	for _, kindRows := range input.RowsByKind {
		for _, row := range kindRows {
			_, hasBindingID := row["dependency_binding_id"]
			_, hasOrdinal := row["precedence_ordinal"]
			_, hasRole := row["dependency_role"]
			if !hasBindingID && !hasOrdinal && !hasRole {
				continue
			}
			if !hasBindingID || !hasOrdinal || !hasRole {
				return nil, fmt.Errorf("mapping transitive dependency roster %q has a schema-validated row with a partial traversal identity", input.Path)
			}
			rows = append(rows, row)
		}
	}
	if dependencyCount != len(rows) || len(rows) == 0 {
		return nil, fmt.Errorf("mapping transitive dependency roster %q dependency_count %d does not equal %d schema-validated traversal rows", input.Path, dependencyCount, len(rows))
	}

	bindings := make([]mappingTransitiveClosureBinding, len(rows))
	bindingsByOrdinal := make(map[uint64]mappingTransitiveClosureBinding, len(rows))
	bindingIDs := make(map[string]struct{}, len(rows))
	realizedRoles := make(map[string]struct{}, len(roleRoster))
	for rowIndex, row := range rows {
		bindingID, bindingIDOK := manifestString(row, "dependency_binding_id")
		ordinal, ordinalOK := exactMappingPrecedenceOrdinal(row["precedence_ordinal"])
		dependencyRole, roleOK := manifestString(row, "dependency_role")
		artifactIdentity, artifactIdentityOK := row["artifact_identity"].(map[string]interface{})
		validationBinding, validationBindingOK := row["validation_binding"].(map[string]interface{})
		if !bindingIDOK || !canonicalEvidenceMetadataString(bindingID, 512) || !ordinalOK || !roleOK || !canonicalEvidenceMetadataString(dependencyRole, 512) || !scannerContainsExactString(roleRoster, dependencyRole) || !artifactIdentityOK || !validationBindingOK {
			return nil, fmt.Errorf("mapping transitive dependency roster %q row %d has no unambiguous schema-validated traversal binding", input.Path, rowIndex)
		}
		if _, duplicate := bindingIDs[bindingID]; duplicate {
			return nil, fmt.Errorf("mapping transitive dependency roster %q duplicates dependency_binding_id %q", input.Path, bindingID)
		}
		bindingIDs[bindingID] = struct{}{}
		if _, duplicate := bindingsByOrdinal[ordinal]; duplicate {
			return nil, fmt.Errorf("mapping transitive dependency roster %q duplicates precedence_ordinal %d", input.Path, ordinal)
		}
		realizedRoles[dependencyRole] = struct{}{}

		artifactID, artifactIDOK := manifestString(artifactIdentity, "artifact")
		artifactVersion, artifactVersionOK := manifestString(artifactIdentity, "artifact_version")
		artifactDigest, artifactDigestOK := manifestString(artifactIdentity, "artifact_sha256")
		validationSchemaID, schemaIDOK := manifestString(validationBinding, "validation_schema_id")
		validationSchemaVersion, schemaVersionOK := manifestString(validationBinding, "validation_schema_version")
		validationSchemaDigest, schemaDigestOK := manifestString(validationBinding, "validation_schema_sha256")
		validationProfileID, profileIDOK := manifestString(validationBinding, "validation_profile_id")
		validationProfileVersion, profileVersionOK := manifestString(validationBinding, "validation_profile_version")
		validationProfileDigest, profileDigestOK := manifestString(validationBinding, "validation_profile_sha256")
		if !artifactIDOK || !canonicalEvidenceMetadataString(artifactID, 512) || !artifactVersionOK || !canonicalEvidenceMetadataString(artifactVersion, 128) || !artifactDigestOK || !isLowerSHA256(artifactDigest) || !schemaIDOK || !canonicalEvidenceMetadataString(validationSchemaID, 512) || !schemaVersionOK || !canonicalEvidenceMetadataString(validationSchemaVersion, 128) || !schemaDigestOK || !isLowerSHA256(validationSchemaDigest) || !profileIDOK || !canonicalEvidenceMetadataString(validationProfileID, 512) || !profileVersionOK || !canonicalEvidenceMetadataString(validationProfileVersion, 128) || !profileDigestOK || !isLowerSHA256(validationProfileDigest) {
			return nil, fmt.Errorf("mapping transitive dependency roster %q row %d has an invalid exact artifact or validation binding", input.Path, rowIndex)
		}
		bindingsByOrdinal[ordinal] = mappingTransitiveClosureBinding{
			bindingID: bindingID, precedenceOrdinal: ordinal, dependencyRole: dependencyRole,
			artifactID: artifactID, artifactVersion: artifactVersion, artifactDigest: artifactDigest,
			validationSchemaID: validationSchemaID, validationSchemaVersion: validationSchemaVersion, validationSchemaDigest: validationSchemaDigest,
			validationProfileID: validationProfileID, validationProfileVersion: validationProfileVersion, validationProfileDigest: validationProfileDigest,
		}
	}
	for ordinal := range bindings {
		binding, present := bindingsByOrdinal[uint64(ordinal)]
		if !present {
			return nil, fmt.Errorf("mapping transitive dependency roster %q has a gap at precedence_ordinal %d", input.Path, ordinal)
		}
		bindings[ordinal] = binding
	}
	if len(realizedRoles) != len(roleRoster) {
		return nil, fmt.Errorf("mapping transitive dependency roster %q dependency roles are not set-equal to the closed role roster", input.Path)
	}
	return bindings, nil
}

func requireClosureSchemaProofArtifact(proof dependencySemanticValidationProof, role string, input artifactInput) error {
	if proof.seal != dependencySemanticValidationAuthority {
		return fmt.Errorf("candidate closure requires an exact dependency semantic schema-validation proof")
	}
	binding, ok := proof.byRole[role]
	if !ok {
		return fmt.Errorf("candidate closure schema-validation proof is missing role %q", role)
	}
	digest := sha256Hex(input.Raw)
	if !isLowerSHA256(binding.artifactSHA256) || binding.artifactSHA256 != digest || (input.SHA256 != "" && input.SHA256 != digest) {
		return fmt.Errorf("candidate closure schema-validation proof role %q does not bind the supplied exact artifact bytes", role)
	}
	if _, err := newValidationProfileCoordinate("schema", binding.schemaID, binding.schemaVersion); err != nil || !isLowerSHA256(binding.schemaSHA256) {
		return fmt.Errorf("candidate closure schema-validation proof role %q has no canonical exact schema coordinate", role)
	}
	return nil
}

func validateMappingTransitiveArtifactSchema(input, schemaInput artifactInput, binding mappingTransitiveClosureBinding) error {
	if schemaInput.Structured || sha256Hex(schemaInput.Raw) != binding.validationSchemaDigest || (schemaInput.SHA256 != "" && schemaInput.SHA256 != binding.validationSchemaDigest) {
		return fmt.Errorf("mapping transitive dependency %s validation schema does not bind one exact raw JSON Schema document", binding.bindingID)
	}
	role := lengthPrefixedIdentityKey("mapping_transitive_dependency_schema_validation", binding.bindingID, binding.dependencyRole)
	if err := validateValidationProfileBindings(
		[]validationProfileBinding{{
			Role:            role,
			ArtifactID:      binding.artifactID,
			ArtifactVersion: binding.artifactVersion,
			ArtifactSHA256:  binding.artifactDigest,
			SchemaID:        binding.validationSchemaID,
			SchemaVersion:   binding.validationSchemaVersion,
			SchemaSHA256:    binding.validationSchemaDigest,
		}},
		[]validationProfileArtifact{{ID: binding.artifactID, Version: binding.artifactVersion, Bytes: input.Raw}},
		[]validationProfileSchema{{ID: binding.validationSchemaID, Version: binding.validationSchemaVersion, Bytes: schemaInput.Raw}},
	); err != nil {
		return fmt.Errorf("mapping transitive dependency %s artifact/schema validation: %w", binding.bindingID, err)
	}
	return nil
}

func uniqueMappingTransitiveValidationSchemaBindings(bindings []mappingTransitiveClosureBinding) ([]mappingTransitiveClosureBinding, error) {
	type schemaCoordinate struct{ id, version string }
	digestByCoordinate := make(map[schemaCoordinate]string, len(bindings))
	coordinateByDigest := make(map[string]schemaCoordinate, len(bindings))
	result := make([]mappingTransitiveClosureBinding, 0, len(bindings))
	for _, binding := range bindings {
		coordinate := schemaCoordinate{id: binding.validationSchemaID, version: binding.validationSchemaVersion}
		if priorDigest, reused := digestByCoordinate[coordinate]; reused {
			if priorDigest != binding.validationSchemaDigest {
				return nil, fmt.Errorf("mapping transitive validation schema coordinate %s/%s aliases exact digests %s and %s", coordinate.id, coordinate.version, priorDigest, binding.validationSchemaDigest)
			}
			continue
		}
		if priorCoordinate, reused := coordinateByDigest[binding.validationSchemaDigest]; reused && priorCoordinate != coordinate {
			return nil, fmt.Errorf("mapping transitive validation schema digest %s aliases coordinates %s/%s and %s/%s", binding.validationSchemaDigest, priorCoordinate.id, priorCoordinate.version, coordinate.id, coordinate.version)
		}
		digestByCoordinate[coordinate] = binding.validationSchemaDigest
		coordinateByDigest[binding.validationSchemaDigest] = coordinate
		result = append(result, binding)
	}
	return result, nil
}

func validateMappingTransitiveValidationProfile(input, profileSchemaInput artifactInput, profileSchemaPin dependencySemanticValidationPin, binding mappingTransitiveClosureBinding) error {
	profilePin := dependencySemanticValidationPin{
		Role: binding.dependencyRole, ID: binding.validationProfileID,
		Version: binding.validationProfileVersion, RawSHA256: binding.validationProfileDigest,
	}
	parsed, err := parseArtifactValidationProfile(input, profilePin, profileSchemaInput, profileSchemaPin)
	if err != nil {
		return fmt.Errorf("mapping transitive dependency %s validation-profile envelope: %w", binding.bindingID, err)
	}
	if parsed.id != binding.validationProfileID || parsed.version != binding.validationProfileVersion || len(parsed.bindings) != 1 {
		return fmt.Errorf("mapping transitive dependency %s validation profile is not set-equal to its exact profile coordinate and one binding", binding.bindingID)
	}
	profileBinding := parsed.bindings[0]
	if profileBinding.Role != binding.dependencyRole ||
		profileBinding.ArtifactID != binding.artifactID ||
		profileBinding.ArtifactVersion != binding.artifactVersion ||
		profileBinding.ArtifactRawSHA256 != binding.artifactDigest ||
		profileBinding.SchemaID != binding.validationSchemaID ||
		profileBinding.SchemaVersion != binding.validationSchemaVersion ||
		profileBinding.SchemaRawSHA256 != binding.validationSchemaDigest {
		return fmt.Errorf("mapping transitive dependency %s validation profile binding is not set-equal to the roster artifact/schema binding", binding.bindingID)
	}
	return nil
}

func exactMappingPrecedenceOrdinal(value interface{}) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	lexeme := number.String()
	ordinal, err := strconv.ParseUint(lexeme, 10, 64)
	return ordinal, err == nil && strconv.FormatUint(ordinal, 10) == lexeme
}

func scannerContainsExactString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func canonicalUniqueOrderedOpaqueStrings(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !canonicalEvidenceMetadataString(value, 512) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func canonicalPlanDependencyBindings(plan *parsedPlan) ([]candidateClosureBinding, error) {
	// JSON object-member order is not semantic authority. The candidate
	// contract's closed direct roles therefore have one explicit,
	// content-independent closure order. A producer cannot rearrange manifest
	// members or choose artifact digests to change reconstruction order.
	bindings := []candidateClosureBinding{
		{role: "provider_neutral_compilation_profile", digest: plan.Manifest.ProviderNeutralProfileSHA256},
		{role: "source_contract_index", digest: plan.Manifest.SourceContractIndexSHA256},
		{role: "sample_shape_index", digest: plan.Manifest.SampleShapeIndexSHA256},
		{role: "protocol_contract_index", digest: plan.Manifest.ProtocolContractIndexSHA256},
		{role: "field_mapping_candidate", digest: plan.Manifest.FieldMappingCandidateSHA256},
		{role: dependencySemanticRoleOperationApplicability, digest: plan.Manifest.OperationApplicabilityProfileSHA256},
		{role: dependencySemanticRoleAPIGraphApplicability, digest: plan.Manifest.APIGraphApplicabilityProfileSHA256},
		{role: "evidence_selection_roster", digest: plan.Manifest.EvidenceSelectionRosterSHA256},
	}
	for _, binding := range bindings {
		if !isLowerSHA256(binding.digest) {
			return nil, fmt.Errorf("candidate closure binding %s has no exact lowercase dependency digest", candidateClosureRoleBindingName(binding.role))
		}
	}
	return bindings, nil
}

func validateCandidateClosureSecurity(planLabel string, planRaw []byte, plan *parsedPlan, dependencies map[string]artifactInput, semanticValidation dependencySemanticValidationResolution, bodies map[string]exactEvidenceBody, minimumFullBodyBytes int) error {
	items, err := canonicalPlanDependencyClosure(planLabel, planRaw, plan, dependencies, semanticValidation)
	if err != nil {
		return err
	}
	closureItems := make([]evidenceClosureItem, len(items))
	for index, item := range items {
		closureItems[index] = evidenceClosureItem{label: item.label, raw: item.raw, structured: true}
	}
	for _, order := range []jsonCarrierTraversal{jsonCarrierSourceOrder, jsonCarrierCanonicalObjectOrder} {
		if itemLabel, digest, encoding, found, err := detectCanonicalEvidenceBodyClosure(closureItems, order, bodies, minimumFullBodyBytes); err != nil {
			return fmt.Errorf("%s closure analysis: %w", planLabel, err)
		} else if found {
			return fmt.Errorf("%s reconstructs %s from selected evidence digest %s across the canonical plan-and-dependency closure", itemLabel, encoding, digest)
		}
		credentialScanner := newCredentialClosureScanner()
		for _, item := range items {
			if err := scanJSONLClosureItemWithOrder(item, order, func(carrier orderedJSONCarrier) error {
				if err := credentialScanner.advance(carrier); err != nil {
					return fmt.Errorf("%s: %w", item.label, err)
				}
				return nil
			}); err != nil {
				return err
			}
		}
		if err := credentialScanner.finish(); err != nil {
			return err
		}
	}
	return nil
}

func validateNoEmbeddedEvidenceBodies(label string, raw []byte, bodies map[string]exactEvidenceBody, minimumFullBodyBytes int) error {
	items := []evidenceClosureItem{{label: label, raw: raw, structured: true}}
	for _, order := range []jsonCarrierTraversal{jsonCarrierSourceOrder, jsonCarrierCanonicalObjectOrder} {
		if itemLabel, digest, encoding, found, err := detectCanonicalEvidenceBodyClosure(items, order, bodies, minimumFullBodyBytes); err != nil {
			return fmt.Errorf("%s closure analysis: %w", label, err)
		} else if found {
			return fmt.Errorf("%s reconstructs %s from selected evidence digest %s", itemLabel, encoding, digest)
		}
	}
	return nil
}

type evidenceClosureItem struct {
	label      string
	raw        []byte
	structured bool
}

func scanEvidenceClosureItemWithOrder(item evidenceClosureItem, order jsonCarrierTraversal, emit func(orderedJSONCarrier) error) error {
	return scanEvidenceClosureItemWithOrderBudget(item, order, nil, emit)
}

func scanEvidenceClosureItemWithOrderBudget(item evidenceClosureItem, order jsonCarrierTraversal, budget *canonicalEvidenceClosureWorkBudget, emit func(orderedJSONCarrier) error) error {
	if !item.structured {
		if budget != nil {
			if err := budget.consume(int64(len(item.raw))); err != nil {
				return err
			}
		}
		return emit(orderedJSONCarrier{bytes: item.raw, kind: orderedJSONStringValue})
	}
	return scanJSONLClosureItemWithOrderBudget(candidateClosureItem{label: item.label, raw: item.raw}, order, budget, emit)
}

func scanJSONLClosureItem(item candidateClosureItem, emit func(orderedJSONCarrier) error) error {
	return scanJSONLClosureItemWithOrder(item, jsonCarrierSourceOrder, emit)
}

func scanJSONLClosureItemWithOrder(item candidateClosureItem, order jsonCarrierTraversal, emit func(orderedJSONCarrier) error) error {
	return scanJSONLClosureItemWithOrderBudget(item, order, nil, emit)
}

func scanJSONLClosureItemWithOrderBudget(item candidateClosureItem, order jsonCarrierTraversal, budget *canonicalEvidenceClosureWorkBudget, emit func(orderedJSONCarrier) error) error {
	return scanJSONLClosureItemWithOrderBudgetAndProvenance(item, order, budget, nil, emit)
}

func scanJSONLClosureItemWithOrderBudgetAndProvenance(item candidateClosureItem, order jsonCarrierTraversal, budget *canonicalEvidenceClosureWorkBudget, provenance jsonCarrierProvenanceResolver, emit func(orderedJSONCarrier) error) error {
	scanner := bufio.NewScanner(bytes.NewReader(item.raw))
	scanner.Buffer(make([]byte, 64*1024), dependencySecurityMaxRowBytes)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		structure, err := validateProviderJSONStructure(line)
		if err != nil {
			return fmt.Errorf("%s line %d closure scan: %w", item.label, lineNumber, err)
		}
		if budget != nil {
			if err := budget.consume(int64(len(line)) + structure.Tokens); err != nil {
				return fmt.Errorf("%s line %d closure scan: %w", item.label, lineNumber, err)
			}
		}
		lineProvenance := provenance
		if provenance != nil {
			lineProvenance = func(_ int, pointer string, value []byte) bool {
				return provenance(lineNumber, pointer, value)
			}
		}
		if err := walkJSONCarriersValidatedWithProvenance(line, order, lineProvenance, emit); err != nil {
			return fmt.Errorf("%s line %d closure scan: %w", item.label, lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s after line %d: %w", item.label, lineNumber, err)
	}
	return nil
}

type orderedJSONCarrierKind uint8

const (
	orderedJSONStringValue orderedJSONCarrierKind = iota
	orderedJSONObjectKey
	orderedJSONByteArray
	orderedJSONByteIndexObject
	orderedJSONBooleanVector
	orderedJSONBigInteger
)

type orderedJSONCarrier struct {
	bytes                []byte
	kind                 orderedJSONCarrierKind
	placeholderBoundary  bool
	decodedAlternatives  [][]byte
	provenDigestIdentity bool
}

// jsonCarrierProvenanceResolver closes arbitrary wrapped-fragment synthesis
// only for one exact scalar at one exact JSON pointer. A nil resolver, an
// unknown pointer, or a value mismatch is deliberately open. Whole-scalar and
// exact ordered scans never consult this provenance bit.
type jsonCarrierProvenanceResolver func(row int, pointer string, value []byte) bool

func carrierRepresentationCount(carrier orderedJSONCarrier) int {
	return 1 + len(carrier.decodedAlternatives)
}

func carrierRepresentation(carrier orderedJSONCarrier, index int) []byte {
	if index == 0 {
		return carrier.bytes
	}
	return carrier.decodedAlternatives[index-1]
}

type jsonCarrierTraversal uint8

const (
	jsonCarrierSourceOrder jsonCarrierTraversal = iota
	jsonCarrierCanonicalObjectOrder
)

// walkOrderedJSONCarriers preserves lexical object/array order, while byte
// arrays and explicitly indexed byte objects are compacted into one carrier.
// This makes those common covert carriers O(N) instead of a subsequence-DP
// problem over millions of scalar positions.
func walkOrderedJSONCarriers(raw []byte, emit func(orderedJSONCarrier) error) error {
	return walkJSONCarriers(raw, jsonCarrierSourceOrder, emit)
}

func walkJSONCarriers(raw []byte, order jsonCarrierTraversal, emit func(orderedJSONCarrier) error) error {
	if _, err := validateProviderJSONStructure(raw); err != nil {
		return err
	}
	return walkJSONCarriersValidated(raw, order, emit)
}

func walkJSONCarriersValidated(raw []byte, order jsonCarrierTraversal, emit func(orderedJSONCarrier) error) error {
	return walkJSONCarriersValidatedWithProvenance(raw, order, nil, emit)
}

func walkJSONCarriersValidatedWithProvenance(raw []byte, order jsonCarrierTraversal, provenance jsonCarrierProvenanceResolver, emit func(orderedJSONCarrier) error) error {
	nodes := 0
	return walkJSONCarriersBounded(raw, order, provenance, emit, 0, 0, &nodes, "")
}

func walkJSONCarriersBounded(raw []byte, order jsonCarrierTraversal, provenance jsonCarrierProvenanceResolver, emit func(orderedJSONCarrier) error, row, depth int, nodes *int, pointer string) error {
	if depth > maxProviderJSONNestingDepth {
		return fmt.Errorf("JSON carrier walk exceeds fixed nesting depth %d", maxProviderJSONNestingDepth)
	}
	*nodes++
	if *nodes > maxProviderJSONNodesPerValue {
		return fmt.Errorf("JSON carrier walk exceeds fixed node limit %d", maxProviderJSONNodesPerValue)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return fmt.Errorf("empty JSON value")
	}
	switch trimmed[0] {
	case '"':
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return err
		}
		valueBytes := []byte(value)
		proven := provenance != nil && provenance(row, pointer, valueBytes)
		return emit(orderedJSONCarrier{bytes: valueBytes, kind: orderedJSONStringValue, placeholderBoundary: exactCredentialPlaceholder(value), provenDigestIdentity: proven})
	case '[':
		var elements []json.RawMessage
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		decoder.UseNumber()
		if err := decoder.Decode(&elements); err != nil {
			return err
		}
		if msbBytes, lsbBytes, ok := rawMessageBooleanVectors(elements); ok {
			alternatives := uniqueDecodedAlternatives(msbBytes, lsbBytes, reversedBytes(msbBytes), reversedBytes(lsbBytes))
			return emit(orderedJSONCarrier{bytes: msbBytes, kind: orderedJSONBooleanVector, decodedAlternatives: alternatives})
		}
		if byteValue, ok := rawMessageByteSlice(elements); ok {
			return emit(orderedJSONCarrier{bytes: byteValue, kind: orderedJSONByteArray, decodedAlternatives: uniqueDecodedAlternatives(byteValue, reversedBytes(byteValue))})
		}
		for index, element := range elements {
			if byteValue, ok := rawJSONByte(element); ok {
				if err := emit(orderedJSONCarrier{bytes: []byte{byteValue}, kind: orderedJSONByteArray}); err != nil {
					return err
				}
				continue
			}
			if err := walkJSONCarriersBounded(element, order, provenance, emit, row, depth+1, nodes, jsonPointerChild(pointer, strconv.Itoa(index))); err != nil {
				return err
			}
		}
		return nil
	case '{':
		pairs, err := decodeOrderedJSONObjectPairs(trimmed)
		if err != nil {
			return err
		}
		orderedPairs := orderedJSONObjectPairsForTraversal(pairs, order)
		if numericBytes, ok := denseCanonicalNumericObjectBytes(pairs); ok {
			for _, pair := range orderedPairs {
				keyBytes := []byte(pair.key)
				proven := provenance != nil && provenance(row, jsonPointerObjectKey(pointer, pair.key), keyBytes)
				if err := emit(orderedJSONCarrier{bytes: keyBytes, kind: orderedJSONObjectKey, provenDigestIdentity: proven}); err != nil {
					return err
				}
			}
			return emit(orderedJSONCarrier{bytes: numericBytes, kind: orderedJSONByteIndexObject, decodedAlternatives: uniqueDecodedAlternatives(numericBytes, reversedBytes(numericBytes))})
		}
		indexed := map[int]byte{}
		maxIndex := -1
		for _, pair := range pairs {
			index, indexedKey := byteIndexKey(pair.key)
			if !indexedKey {
				continue
			}
			value, byteValue := rawJSONByte(pair.value)
			if !byteValue {
				return fmt.Errorf("byte-index object key %q does not carry an integer byte", pair.key)
			}
			if _, duplicate := indexed[index]; duplicate {
				return fmt.Errorf("byte-index object has duplicate semantic index %d", index)
			}
			indexed[index] = value
			if index > maxIndex {
				maxIndex = index
			}
		}
		var indexedBytes []byte
		if len(indexed) != 0 {
			if maxIndex+1 != len(indexed) {
				return fmt.Errorf("byte-index object indexes are not contiguous from zero")
			}
			indexedBytes = make([]byte, len(indexed))
			for index := range indexedBytes {
				value, ok := indexed[index]
				if !ok {
					return fmt.Errorf("byte-index object is missing index %d", index)
				}
				indexedBytes[index] = value
			}
		}
		emittedIndexedBytes := false
		for _, pair := range orderedPairs {
			if _, indexedKey := byteIndexKey(pair.key); indexedKey {
				if !emittedIndexedBytes {
					emittedIndexedBytes = true
					if err := emit(orderedJSONCarrier{bytes: indexedBytes, kind: orderedJSONByteIndexObject, decodedAlternatives: uniqueDecodedAlternatives(indexedBytes, reversedBytes(indexedBytes))}); err != nil {
						return err
					}
				}
				continue
			}
			keyBytes := []byte(pair.key)
			proven := provenance != nil && provenance(row, jsonPointerObjectKey(pointer, pair.key), keyBytes)
			if err := emit(orderedJSONCarrier{bytes: keyBytes, kind: orderedJSONObjectKey, provenDigestIdentity: proven}); err != nil {
				return err
			}
			if err := walkJSONCarriersBounded(pair.value, order, provenance, emit, row, depth+1, nodes, jsonPointerChild(pointer, pair.key)); err != nil {
				return err
			}
		}
		return nil
	default:
		var scalar interface{}
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		decoder.UseNumber()
		if err := decoder.Decode(&scalar); err != nil {
			return err
		}
		if number, ok := scalar.(json.Number); ok {
			if bigEndian, littleEndian, ok := reversibleBigIntegerBytes(number); ok {
				return emit(orderedJSONCarrier{
					bytes:               bytes.Clone(trimmed),
					kind:                orderedJSONBigInteger,
					decodedAlternatives: uniqueDecodedAlternatives(nil, bigEndian, littleEndian),
				})
			}
		}
		return nil
	}
}

func jsonPointerChild(parent, token string) string {
	token = strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
	return parent + "/" + token
}

func jsonPointerObjectKey(parent, key string) string {
	// NUL cannot occur in an RFC 6901 pointer token without JSON escaping and
	// keeps the internal key-coordinate namespace disjoint from value pointers.
	return parent + "\x00key:" + key
}

func orderedJSONObjectPairsForTraversal(pairs []orderedJSONObjectPair, order jsonCarrierTraversal) []orderedJSONObjectPair {
	if order != jsonCarrierCanonicalObjectOrder {
		return pairs
	}
	ordered := append([]orderedJSONObjectPair(nil), pairs...)
	sort.SliceStable(ordered, func(left, right int) bool {
		return ordered[left].key < ordered[right].key
	})
	return ordered
}

func rawMessageBooleanVectors(values []json.RawMessage) ([]byte, []byte, bool) {
	if len(values) < 8 || len(values)%8 != 0 {
		return nil, nil, false
	}
	msb := make([]byte, len(values)/8)
	lsb := make([]byte, len(values)/8)
	for index, raw := range values {
		trimmed := bytes.TrimSpace(raw)
		var bit byte
		switch {
		case bytes.Equal(trimmed, []byte("true")):
			bit = 1
		case bytes.Equal(trimmed, []byte("false")):
		default:
			return nil, nil, false
		}
		if bit != 0 {
			msb[index/8] |= 1 << (7 - uint(index%8))
			lsb[index/8] |= 1 << uint(index%8)
		}
	}
	return msb, lsb, true
}

func denseCanonicalNumericObjectBytes(pairs []orderedJSONObjectPair) ([]byte, bool) {
	if len(pairs) < 16 {
		return nil, false
	}
	type indexedByte struct {
		index int
		value byte
	}
	indexed := make([]indexedByte, 0, len(pairs))
	prefix := ""
	width := 0
	minimalDecimalIndexes := false
	for pairIndex, pair := range pairs {
		candidatePrefix, candidateWidth, index, ok := trailingDecimalIndex(pair.key)
		if !ok {
			return nil, false
		}
		value, ok := rawJSONByte(pair.value)
		if !ok {
			return nil, false
		}
		if pairIndex == 0 {
			prefix, width = candidatePrefix, candidateWidth
			minimalDecimalIndexes = pair.key[len(candidatePrefix):] == strconv.Itoa(index)
		} else if prefix != candidatePrefix ||
			(minimalDecimalIndexes && pair.key[len(candidatePrefix):] != strconv.Itoa(index)) ||
			(!minimalDecimalIndexes && width != candidateWidth) {
			return nil, false
		}
		indexed = append(indexed, indexedByte{index: index, value: value})
	}
	sort.Slice(indexed, func(left, right int) bool { return indexed[left].index < indexed[right].index })
	result := make([]byte, len(indexed))
	for ordinal, entry := range indexed {
		if entry.index != ordinal {
			return nil, false
		}
		result[ordinal] = entry.value
	}
	return result, true
}

func trailingDecimalIndex(key string) (string, int, int, bool) {
	start := len(key)
	for start > 0 && key[start-1] >= '0' && key[start-1] <= '9' {
		start--
	}
	if start == len(key) {
		return "", 0, 0, false
	}
	index, err := strconv.Atoi(key[start:])
	if err != nil || index < 0 {
		return "", 0, 0, false
	}
	return key[:start], len(key) - start, index, true
}

func reversibleBigIntegerBytes(number json.Number) ([]byte, []byte, bool) {
	integer, ok := new(big.Int).SetString(string(number), 10)
	if !ok {
		return nil, nil, false
	}
	integer.Abs(integer)
	bigEndian := integer.Bytes()
	if len(bigEndian) < 16 {
		return nil, nil, false
	}
	return bigEndian, reversedBytes(bigEndian), true
}

func reversedBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	reversed := make([]byte, len(value))
	for index := range value {
		reversed[len(value)-1-index] = value[index]
	}
	return reversed
}

func uniqueDecodedAlternatives(primary []byte, candidates ...[]byte) [][]byte {
	alternatives := make([][]byte, 0, len(candidates))
	for _, candidate := range candidates {
		if len(candidate) == 0 || bytes.Equal(candidate, primary) {
			continue
		}
		duplicate := false
		for _, prior := range alternatives {
			if bytes.Equal(candidate, prior) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			alternatives = append(alternatives, candidate)
		}
	}
	return alternatives
}

func rawMessageByteSlice(values []json.RawMessage) ([]byte, bool) {
	if len(values) == 0 {
		return nil, false
	}
	result := make([]byte, len(values))
	for index, raw := range values {
		value, ok := rawJSONByte(raw)
		if !ok {
			return nil, false
		}
		result[index] = value
	}
	return result, true
}

func rawJSONByte(raw []byte) (byte, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return 0, false
	}
	for _, current := range trimmed {
		if current < '0' || current > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(string(trimmed), 10, 8)
	if err != nil {
		return 0, false
	}
	return byte(parsed), true
}

type orderedJSONObjectPair struct {
	key   string
	value json.RawMessage
}

func decodeOrderedJSONObjectPairs(raw []byte) ([]orderedJSONObjectPair, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		if err == nil {
			err = fmt.Errorf("missing object delimiter")
		}
		return nil, fmt.Errorf("decode JSON object: %w", err)
	}
	pairs := make([]orderedJSONObjectPair, 0)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("JSON object key token has type %T", keyToken)
		}
		var child json.RawMessage
		if err := decoder.Decode(&child); err != nil {
			return nil, err
		}
		pairs = append(pairs, orderedJSONObjectPair{key: key, value: child})
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	return pairs, nil
}

func byteIndexKey(key string) (int, bool) {
	candidate := key
	switch {
	case strings.HasPrefix(candidate, "byte_"):
		candidate = candidate[len("byte_"):]
	case strings.HasPrefix(candidate, "byte-"):
		candidate = candidate[len("byte-"):]
	case strings.HasPrefix(candidate, "byte"):
		candidate = candidate[len("byte"):]
	}
	if candidate == "" {
		return 0, false
	}
	for _, char := range candidate {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	index, err := strconv.Atoi(candidate)
	return index, err == nil && index >= 0
}

type streamingExactMatcher struct {
	target  []byte
	prefix  []uint32
	matched int
	foldHex bool
}

func newStreamingExactMatcher(target []byte, foldHex bool) (streamingExactMatcher, error) {
	if uint64(len(target)) > math.MaxUint32 {
		return streamingExactMatcher{}, fmt.Errorf("exact closure target byte length %d exceeds uint32 matcher index capacity", len(target))
	}
	if foldHex {
		for _, current := range target {
			if current >= 'A' && current <= 'F' {
				return streamingExactMatcher{}, fmt.Errorf("folded hexadecimal closure target is not canonical lowercase")
			}
		}
	}
	prefix := make([]uint32, len(target))
	for index := 1; index < len(target); index++ {
		candidate := int(prefix[index-1])
		for candidate > 0 && target[index] != target[candidate] {
			candidate = int(prefix[candidate-1])
		}
		if target[index] == target[candidate] {
			candidate++
		}
		prefix[index] = uint32(candidate)
	}
	return streamingExactMatcher{target: target, prefix: prefix, foldHex: foldHex}, nil
}

func (matcher *streamingExactMatcher) advance(value []byte) bool {
	matched, found := matcher.advanceFrom(matcher.matched, value)
	matcher.matched = matched
	return found
}

func (matcher *streamingExactMatcher) advanceFrom(matched int, value []byte) (int, bool) {
	if len(matcher.target) == 0 {
		return 0, false
	}
	for _, current := range value {
		if matcher.foldHex && current >= 'A' && current <= 'F' {
			current += 'a' - 'A'
		}
		for matched > 0 && current != matcher.target[matched] {
			matched = int(matcher.prefix[matched-1])
		}
		if current == matcher.target[matched] {
			matched++
		}
		if matched == len(matcher.target) {
			matched = int(matcher.prefix[matched-1])
			return matched, true
		}
	}
	return matched, false
}

type evidencePatternMatcher struct {
	digest           string
	encoding         string
	matcher          streamingExactMatcher
	branchStates     [credentialClosureMaxStates]int
	branchStateCount int
}

const (
	canonicalEvidenceClosureMaxWorkUnits             int64 = 1 << 30
	canonicalEvidenceClosureMaxMatcherAuxiliaryBytes int64 = 768 << 20
	canonicalEvidenceMatcherPrefixEntryBytes               = int64(4)
)

type canonicalEvidenceClosureWorkBudget struct {
	used  int64
	limit int64
}

func (budget *canonicalEvidenceClosureWorkBudget) consume(workUnits int64) error {
	limit := budget.limit
	if limit == 0 {
		limit = canonicalEvidenceClosureMaxWorkUnits
	}
	if workUnits < 0 || workUnits > limit-budget.used {
		return fmt.Errorf("analysis exceeded the deterministic aggregate work-unit limit %d", limit)
	}
	budget.used += workUnits
	return nil
}

func canonicalEvidenceMatcherAuxiliaryBytes(targetBytes int64, targetOwned bool) (int64, bool) {
	if targetBytes < 0 || targetBytes > math.MaxInt64/canonicalEvidenceMatcherPrefixEntryBytes {
		return 0, false
	}
	result := targetBytes * canonicalEvidenceMatcherPrefixEntryBytes
	if targetOwned {
		if result > math.MaxInt64-targetBytes {
			return 0, false
		}
		result += targetBytes
	}
	return result, true
}

// canonicalEvidenceClosurePeakAuxiliaryBytesForBodyLength is a structural
// bound, not a heap-sampling estimate. The analyzer holds one matcher at a
// time. The largest owned target is hexadecimal (2N bytes); its compact KMP
// prefix table is four bytes per target byte. A single reversible-carrier
// decode may coexist with that matcher and is bounded by input admission.
func canonicalEvidenceClosurePeakAuxiliaryBytesForBodyLength(bodyBytes int64) (int64, bool) {
	if bodyBytes < 0 || bodyBytes > math.MaxInt64/2 {
		return 0, false
	}
	hexBytes := bodyBytes * 2
	matcherBytes, ok := canonicalEvidenceMatcherAuxiliaryBytes(hexBytes, true)
	if !ok || matcherBytes > math.MaxInt64-maxEvidenceCarrierBytesPerFile {
		return 0, false
	}
	return matcherBytes + maxEvidenceCarrierBytesPerFile, true
}

var errCanonicalEvidenceClosureFound = errors.New("canonical evidence closure found")

type canonicalEvidenceCarrierMode uint8

const (
	canonicalEvidenceCarrierRawRepresentations canonicalEvidenceCarrierMode = iota
	canonicalEvidenceCarrierBinary
	canonicalEvidenceCarrierBase64
	canonicalEvidenceCarrierHex
)

func canonicalEvidenceDecodedCarrierCapacity(mode canonicalEvidenceCarrierMode, encodedBytes int) (int, error) {
	if encodedBytes < 0 {
		return 0, fmt.Errorf("canonical evidence carrier has negative encoded length")
	}
	switch mode {
	case canonicalEvidenceCarrierBase64:
		padded := base64.StdEncoding.DecodedLen(encodedBytes)
		raw := base64.RawStdEncoding.DecodedLen(encodedBytes)
		if raw > padded {
			return raw, nil
		}
		return padded, nil
	case canonicalEvidenceCarrierHex:
		return hex.DecodedLen(encodedBytes), nil
	default:
		return 0, fmt.Errorf("unknown canonical evidence carrier mode %d", mode)
	}
}

func detectCanonicalEvidenceBodyClosure(items []evidenceClosureItem, order jsonCarrierTraversal, bodies map[string]exactEvidenceBody, minimumFullBodyBytes int) (string, string, string, bool, error) {
	return detectCanonicalEvidenceBodyClosureWithBudget(items, order, bodies, minimumFullBodyBytes, &canonicalEvidenceClosureWorkBudget{})
}

// detectCanonicalEvidenceBodyClosureWithBudget is deliberately private test
// surface. Production always enters through detectCanonicalEvidenceBodyClosure
// and therefore always owns the fixed aggregate-work ceiling.
func detectCanonicalEvidenceBodyClosureWithBudget(items []evidenceClosureItem, order jsonCarrierTraversal, bodies map[string]exactEvidenceBody, minimumFullBodyBytes int, budget *canonicalEvidenceClosureWorkBudget) (string, string, string, bool, error) {
	if len(items) == 0 || len(bodies) == 0 {
		return "", "", "", false, nil
	}
	digests := make([]string, 0, len(bodies))
	for digest := range bodies {
		digests = append(digests, digest)
	}
	sort.Strings(digests)

	if itemLabel, digest, encoding, found, err := scanCanonicalEvidenceRawBatches(items, order, digests, bodies, minimumFullBodyBytes, budget); err != nil || found {
		if err != nil {
			err = fmt.Errorf("raw-representation closure scan: %w", err)
		}
		return itemLabel, digest, encoding, found, err
	}

	// A substantial literal fragment is itself prohibited even when it does not
	// complete a whole streaming target. Batch candidate fragments as automaton
	// targets and scan the selected body corpus once per bounded batch; never
	// rescan every body separately for every carrier.
	if itemLabel, digest, found, err := scanCanonicalEvidenceSubstantialFragmentBatches(items, order, digests, bodies, budget); err != nil || found {
		if err != nil {
			err = fmt.Errorf("substantial-fragment closure scan: %w", err)
		}
		return itemLabel, digest, "substantial exact body fragment", found, err
	}

	decodedModes := []struct {
		mode     canonicalEvidenceCarrierMode
		encoding string
	}{
		{mode: canonicalEvidenceCarrierBinary, encoding: "decoded byte-array or byte-index-object carrier body"},
		{mode: canonicalEvidenceCarrierBase64, encoding: "decoded canonical base64 carrier body"},
	}
	for _, decoded := range decodedModes {
		if itemLabel, digest, found, err := scanCanonicalEvidenceDecodedBatches(items, order, digests, bodies, minimumFullBodyBytes, decoded.mode, budget); err != nil || found {
			if err != nil {
				err = fmt.Errorf("%s closure scan: %w", decoded.encoding, err)
			}
			return itemLabel, digest, decoded.encoding, found, err
		}
	}

	// Hexadecimal carriers and numeric/boolean reversible alternatives share
	// one immutable target automaton and one structural traversal. Hexadecimal
	// state remains ordered; each reversible alternative still starts at the
	// automaton root and is therefore never concatenated with another scalar.
	if itemLabel, digest, encoding, found, err := scanCanonicalEvidenceHexAndReversibleBatches(items, order, digests, bodies, minimumFullBodyBytes, budget); err != nil || found {
		if err != nil {
			err = fmt.Errorf("hexadecimal and reversible-carrier closure scan: %w", err)
		}
		return itemLabel, digest, encoding, found, err
	}
	return "", "", "", false, nil
}

const canonicalEvidenceBatchNodeBytes int64 = 40
const canonicalEvidenceBatchEdgeBytes int64 = 8
const canonicalEvidenceBatchQueueEntryBytes int64 = 4
const canonicalEvidenceBatchTargetEntryBytes int64 = 64
const canonicalEvidenceBatchDenseTransitionThreshold uint16 = 16
const canonicalEvidenceBatchDenseTransitionBytes int64 = 256 * 4
const canonicalEvidenceBatchDenseTransitionBytesPerTargetByte int64 = canonicalEvidenceBatchDenseTransitionBytes / int64(canonicalEvidenceBatchDenseTransitionThreshold)

type canonicalEvidenceBatchTarget struct {
	digest   string
	target   []byte
	priority int
	owned    bool
}

type canonicalEvidenceBatchMatch struct {
	itemLabel string
	target    canonicalEvidenceBatchTarget
	found     bool
}

// canonicalEvidenceBatchMatcherAuxiliaryBytes is a conservative structural
// bound for the automaton's fixed-capacity node, compact sorted-edge, and
// breadth-first queue arrays, a conservative target-descriptor allowance (at
// most one nonempty target per target byte), plus the encoded target bytes the
// batch owns. It is not a heap sample.
func canonicalEvidenceBatchMatcherAuxiliaryBytes(targetBytes, ownedBytes int64) (int64, bool) {
	perTargetByte := canonicalEvidenceBatchNodeBytes + canonicalEvidenceBatchEdgeBytes + canonicalEvidenceBatchQueueEntryBytes + canonicalEvidenceBatchTargetEntryBytes + canonicalEvidenceBatchDenseTransitionBytesPerTargetByte
	if targetBytes < 0 || ownedBytes < 0 || targetBytes > (math.MaxInt64-canonicalEvidenceBatchNodeBytes)/perTargetByte {
		return 0, false
	}
	result := canonicalEvidenceBatchNodeBytes + targetBytes*perTargetByte
	if result > math.MaxInt64-ownedBytes {
		return 0, false
	}
	return result + ownedBytes, true
}

// canonicalEvidenceBatchPeakAuxiliaryBytes includes the one legal maximum
// reversible-carrier decode that may coexist with a live matcher. Production
// checks this combined peak before allocating the matcher arrays, so a batch
// can never consume the matcher ceiling and then allocate a decoder destination
// beyond it.
func canonicalEvidenceBatchPeakAuxiliaryBytes(targetBytes, ownedBytes int64) (int64, bool) {
	matcherBytes, ok := canonicalEvidenceBatchMatcherAuxiliaryBytes(targetBytes, ownedBytes)
	if !ok || matcherBytes > math.MaxInt64-maxEvidenceCarrierBytesPerFile {
		return 0, false
	}
	return matcherBytes + maxEvidenceCarrierBytesPerFile, true
}

type canonicalEvidenceSubstantialFragmentBatch struct {
	targets     []canonicalEvidenceBatchTarget
	itemLabels  []string
	targetBytes int64
}

func scanCanonicalEvidenceSubstantialFragmentBatches(items []evidenceClosureItem, order jsonCarrierTraversal, digests []string, bodies map[string]exactEvidenceBody, budget *canonicalEvidenceClosureWorkBudget) (string, string, bool, error) {
	maxBodyBytes := 0
	for _, digest := range digests {
		if bodyBytes := len(bodies[digest].Bytes); bodyBytes > maxBodyBytes {
			maxBodyBytes = bodyBytes
		}
	}
	batch := canonicalEvidenceSubstantialFragmentBatch{}
	foundItemLabel, foundDigest := "", ""
	flush := func() error {
		if len(batch.targets) == 0 {
			return nil
		}
		itemLabel, digest, found, err := scanCanonicalEvidenceSubstantialFragmentBatch(batch, digests, bodies, budget)
		if err != nil {
			return err
		}
		if found {
			foundItemLabel, foundDigest = itemLabel, digest
			return errCanonicalEvidenceClosureFound
		}
		batch = canonicalEvidenceSubstantialFragmentBatch{}
		return nil
	}

	for _, item := range items {
		err := scanEvidenceClosureItemWithOrderBudget(item, order, budget, func(carrier orderedJSONCarrier) error {
			if len(carrier.bytes) < 1024 || len(carrier.bytes) > maxBodyBytes {
				return nil
			}
			carrierBytes := int64(len(carrier.bytes))
			if carrierBytes > math.MaxInt64-batch.targetBytes {
				return fmt.Errorf("substantial exact body fragment batch byte count overflows")
			}
			peak, ok := canonicalEvidenceBatchPeakAuxiliaryBytes(batch.targetBytes+carrierBytes, batch.targetBytes+carrierBytes)
			if !ok || peak > canonicalEvidenceClosureMaxMatcherAuxiliaryBytes {
				if err := flush(); err != nil {
					return err
				}
				peak, ok = canonicalEvidenceBatchPeakAuxiliaryBytes(carrierBytes, carrierBytes)
				if !ok || peak > canonicalEvidenceClosureMaxMatcherAuxiliaryBytes {
					digest, found, err := scanCanonicalEvidenceLargeSubstantialFragment(carrier.bytes, digests, bodies, budget)
					if err != nil {
						return err
					}
					if found {
						foundItemLabel, foundDigest = item.label, digest
						return errCanonicalEvidenceClosureFound
					}
					return nil
				}
			}
			if err := budget.consume(carrierBytes); err != nil {
				return err
			}
			owned := bytes.Clone(carrier.bytes)
			priority := len(batch.targets)
			batch.targets = append(batch.targets, canonicalEvidenceBatchTarget{
				digest:   "substantial-fragment",
				target:   owned,
				priority: priority,
				owned:    true,
			})
			batch.itemLabels = append(batch.itemLabels, item.label)
			batch.targetBytes += carrierBytes
			return nil
		})
		if errors.Is(err, errCanonicalEvidenceClosureFound) {
			return foundItemLabel, foundDigest, true, nil
		}
		if err != nil {
			return "", "", false, err
		}
	}
	if err := flush(); errors.Is(err, errCanonicalEvidenceClosureFound) {
		return foundItemLabel, foundDigest, true, nil
	} else if err != nil {
		return "", "", false, err
	}
	return "", "", false, nil
}

func scanCanonicalEvidenceSubstantialFragmentBatch(batch canonicalEvidenceSubstantialFragmentBatch, digests []string, bodies map[string]exactEvidenceBody, budget *canonicalEvidenceClosureWorkBudget) (string, string, bool, error) {
	matcher, err := newCanonicalEvidenceBatchMatcher(batch.targets, false, budget)
	if err != nil {
		return "", "", false, err
	}
	bestPriority := math.MaxInt
	bestDigest := ""
	for _, digest := range digests {
		body := bodies[digest].Bytes
		if err := budget.consume(int64(len(body))); err != nil {
			return "", "", false, err
		}
		_, matched, err := matcher.advanceFrom(0, body, false, budget)
		if err != nil {
			return "", "", false, err
		}
		if matched < 0 {
			continue
		}
		priority := matcher.targets[matched].priority
		if priority < bestPriority {
			bestPriority, bestDigest = priority, digest
		}
		if priority == matcher.minimumPriority {
			return batch.itemLabels[priority], digest, true, nil
		}
	}
	if bestPriority != math.MaxInt {
		return batch.itemLabels[bestPriority], bestDigest, true, nil
	}
	return "", "", false, nil
}

func scanCanonicalEvidenceLargeSubstantialFragment(fragment []byte, digests []string, bodies map[string]exactEvidenceBody, budget *canonicalEvidenceClosureWorkBudget) (string, bool, error) {
	auxiliaryBytes, ok := canonicalEvidenceMatcherAuxiliaryBytes(int64(len(fragment)), false)
	if !ok || auxiliaryBytes > math.MaxInt64-maxEvidenceCarrierBytesPerFile || auxiliaryBytes+maxEvidenceCarrierBytesPerFile > canonicalEvidenceClosureMaxMatcherAuxiliaryBytes {
		return "", false, fmt.Errorf("substantial exact body fragment has no bounded matcher realization")
	}
	if int64(len(fragment)) > math.MaxInt64/2 {
		return "", false, fmt.Errorf("substantial exact body fragment work count overflows")
	}
	if err := budget.consume(2 * int64(len(fragment))); err != nil {
		return "", false, err
	}
	matcher, err := newStreamingExactMatcher(fragment, false)
	if err != nil {
		return "", false, err
	}
	for _, digest := range digests {
		body := bodies[digest].Bytes
		if len(body) < len(fragment) {
			continue
		}
		if int64(len(body)) > math.MaxInt64/2 {
			return "", false, fmt.Errorf("selected evidence body work count overflows")
		}
		if err := budget.consume(2 * int64(len(body))); err != nil {
			return "", false, err
		}
		if _, found := matcher.advanceFrom(0, body); found {
			return digest, true, nil
		}
	}
	return "", false, nil
}

func canonicalEvidenceRawEncodingTarget(body []byte, encodingIndex int) ([]byte, bool, bool) {
	switch encodingIndex {
	case 0:
		return body, false, false
	case 1:
		target := make([]byte, base64.StdEncoding.EncodedLen(len(body)))
		base64.StdEncoding.Encode(target, body)
		return target, false, true
	case 2:
		target := make([]byte, base64.RawStdEncoding.EncodedLen(len(body)))
		base64.RawStdEncoding.Encode(target, body)
		return target, false, true
	case 3:
		target := make([]byte, base64.URLEncoding.EncodedLen(len(body)))
		base64.URLEncoding.Encode(target, body)
		return target, false, true
	case 4:
		target := make([]byte, base64.RawURLEncoding.EncodedLen(len(body)))
		base64.RawURLEncoding.Encode(target, body)
		return target, false, true
	case 5:
		target := make([]byte, hex.EncodedLen(len(body)))
		hex.Encode(target, body)
		return target, true, true
	default:
		panic("unknown canonical evidence raw encoding")
	}
}

func canonicalEvidenceRawEncodingName(encodingIndex int) string {
	return []string{
		"complete decoded body",
		"complete padded standard base64 body",
		"complete unpadded standard base64 body",
		"complete padded URL-safe base64 body",
		"complete unpadded URL-safe base64 body",
		"complete hexadecimal body",
	}[encodingIndex]
}

func canonicalEvidenceRawEncodedLength(bodyLength int64, encodingIndex int) int64 {
	switch encodingIndex {
	case 0:
		return bodyLength
	case 1, 3:
		return int64(base64.StdEncoding.EncodedLen(int(bodyLength)))
	case 2, 4:
		return int64(base64.RawStdEncoding.EncodedLen(int(bodyLength)))
	case 5:
		return bodyLength * 2
	default:
		return -1
	}
}

func scanCanonicalEvidenceRawBatches(items []evidenceClosureItem, order jsonCarrierTraversal, digests []string, bodies map[string]exactEvidenceBody, minimumFullBodyBytes int, budget *canonicalEvidenceClosureWorkBudget) (string, string, string, bool, error) {
	for start := 0; start < len(digests); {
		if len(bodies[digests[start]].Bytes) < minimumFullBodyBytes {
			start++
			continue
		}
		end := start
		var targetBytes, ownedBytes [6]int64
		for end < len(digests) {
			body := bodies[digests[end]].Bytes
			if len(body) < minimumFullBodyBytes {
				end++
				continue
			}
			fits := true
			for encodingIndex := 0; encodingIndex < 6; encodingIndex++ {
				length := canonicalEvidenceRawEncodedLength(int64(len(body)), encodingIndex)
				owned := int64(0)
				if encodingIndex != 0 {
					owned = length
				}
				auxiliary, ok := canonicalEvidenceBatchPeakAuxiliaryBytes(targetBytes[encodingIndex]+length, ownedBytes[encodingIndex]+owned)
				if !ok || auxiliary > canonicalEvidenceClosureMaxMatcherAuxiliaryBytes {
					fits = false
					break
				}
			}
			if !fits {
				break
			}
			for encodingIndex := 0; encodingIndex < 6; encodingIndex++ {
				length := canonicalEvidenceRawEncodedLength(int64(len(body)), encodingIndex)
				targetBytes[encodingIndex] += length
				if encodingIndex != 0 {
					ownedBytes[encodingIndex] += length
				}
			}
			end++
		}
		if end == start {
			// A single admitted target too large for the automaton retains the
			// original bounded matcher rather than being omitted or widened.
			digest := digests[start]
			body := bodies[digest].Bytes
			if peak, ok := canonicalEvidenceClosurePeakAuxiliaryBytesForBodyLength(int64(len(body))); !ok || peak > canonicalEvidenceClosureMaxMatcherAuxiliaryBytes {
				return "", "", "", false, fmt.Errorf("selected evidence digest %s requires %d-byte body closure auxiliary storage above fixed limit %d", digest, peak, canonicalEvidenceClosureMaxMatcherAuxiliaryBytes)
			}
			for encodingIndex := 0; encodingIndex < 6; encodingIndex++ {
				target, foldHex, owned := canonicalEvidenceRawEncodingTarget(body, encodingIndex)
				if itemLabel, found, err := scanCanonicalEvidencePattern(items, order, digest, canonicalEvidenceRawEncodingName(encodingIndex), target, foldHex, owned, canonicalEvidenceCarrierRawRepresentations, budget); err != nil || found {
					return itemLabel, digest, canonicalEvidenceRawEncodingName(encodingIndex), found, err
				}
			}
			start++
			continue
		}
		best := canonicalEvidenceBatchMatch{}
		for encodingIndex := 0; encodingIndex < 6; encodingIndex++ {
			targets := make([]canonicalEvidenceBatchTarget, 0, end-start)
			for digestIndex := start; digestIndex < end; digestIndex++ {
				digest := digests[digestIndex]
				body := bodies[digest].Bytes
				if len(body) < minimumFullBodyBytes {
					continue
				}
				target, _, owned := canonicalEvidenceRawEncodingTarget(body, encodingIndex)
				targets = append(targets, canonicalEvidenceBatchTarget{digest: digest, target: target, priority: (digestIndex-start)*6 + encodingIndex, owned: owned})
			}
			foldHex := encodingIndex == 5
			match, err := scanCanonicalEvidenceBatch(items, order, targets, canonicalEvidenceCarrierRawRepresentations, foldHex, budget)
			if err != nil {
				return "", "", "", false, err
			}
			if match.found && (!best.found || match.target.priority < best.target.priority) {
				best = match
			}
			// Prior encoding columns are already proven clean. A match whose
			// priority is no greater than this encoding index cannot be beaten by
			// any later encoding column, so return it before later work can mask a
			// deterministic leak with an aggregate-budget refusal.
			if best.found && best.target.priority <= encodingIndex {
				return best.itemLabel, best.target.digest, canonicalEvidenceRawEncodingName(best.target.priority % 6), true, nil
			}
		}
		if best.found {
			return best.itemLabel, best.target.digest, canonicalEvidenceRawEncodingName(best.target.priority % 6), true, nil
		}
		start = end
	}
	return "", "", "", false, nil
}

func scanCanonicalEvidenceDecodedBatches(items []evidenceClosureItem, order jsonCarrierTraversal, digests []string, bodies map[string]exactEvidenceBody, minimumFullBodyBytes int, mode canonicalEvidenceCarrierMode, budget *canonicalEvidenceClosureWorkBudget) (string, string, bool, error) {
	for start := 0; start < len(digests); {
		if len(bodies[digests[start]].Bytes) < minimumFullBodyBytes {
			start++
			continue
		}
		end, total := start, int64(0)
		for end < len(digests) {
			body := bodies[digests[end]].Bytes
			if len(body) < minimumFullBodyBytes {
				end++
				continue
			}
			auxiliary, ok := canonicalEvidenceBatchPeakAuxiliaryBytes(total+int64(len(body)), 0)
			if !ok || auxiliary > canonicalEvidenceClosureMaxMatcherAuxiliaryBytes {
				break
			}
			total += int64(len(body))
			end++
		}
		if end == start {
			digest := digests[start]
			if itemLabel, found, err := scanCanonicalEvidencePattern(items, order, digest, "decoded body", bodies[digest].Bytes, false, false, mode, budget); err != nil || found {
				return itemLabel, digest, found, err
			}
			start++
			continue
		}
		targets := make([]canonicalEvidenceBatchTarget, 0, end-start)
		for digestIndex := start; digestIndex < end; digestIndex++ {
			digest := digests[digestIndex]
			if body := bodies[digest].Bytes; len(body) >= minimumFullBodyBytes {
				targets = append(targets, canonicalEvidenceBatchTarget{digest: digest, target: body, priority: digestIndex - start})
			}
		}
		match, err := scanCanonicalEvidenceBatch(items, order, targets, mode, false, budget)
		if err != nil {
			return "", "", false, err
		}
		if match.found {
			return match.itemLabel, match.target.digest, true, nil
		}
		start = end
	}
	return "", "", false, nil
}

func scanCanonicalEvidenceHexAndReversibleBatches(items []evidenceClosureItem, order jsonCarrierTraversal, digests []string, bodies map[string]exactEvidenceBody, minimumFullBodyBytes int, budget *canonicalEvidenceClosureWorkBudget) (string, string, string, bool, error) {
	bestReversible := canonicalEvidenceBatchMatch{}
	for start := 0; start < len(digests); {
		if len(bodies[digests[start]].Bytes) < minimumFullBodyBytes {
			start++
			continue
		}
		end, total := start, int64(0)
		for end < len(digests) {
			body := bodies[digests[end]].Bytes
			if len(body) < minimumFullBodyBytes {
				end++
				continue
			}
			auxiliary, ok := canonicalEvidenceBatchPeakAuxiliaryBytes(total+int64(len(body)), 0)
			if !ok || auxiliary > canonicalEvidenceClosureMaxMatcherAuxiliaryBytes {
				break
			}
			total += int64(len(body))
			end++
		}
		if end == start {
			digest := digests[start]
			if itemLabel, found, err := scanCanonicalEvidencePattern(items, order, digest, "decoded hexadecimal carrier body", bodies[digest].Bytes, false, false, canonicalEvidenceCarrierHex, budget); err != nil || found {
				return itemLabel, digest, "decoded hexadecimal carrier body", found, err
			}
			if itemLabel, found, err := scanCanonicalEvidenceSingleReversible(items, order, bodies[digest].Bytes, budget); err != nil {
				return "", "", "", false, err
			} else if found {
				bestReversible = canonicalEvidenceBatchMatch{itemLabel: itemLabel, target: canonicalEvidenceBatchTarget{digest: digest, priority: start}, found: true}
			}
			start++
			continue
		}
		targets := make([]canonicalEvidenceBatchTarget, 0, end-start)
		for digestIndex := start; digestIndex < end; digestIndex++ {
			digest := digests[digestIndex]
			if body := bodies[digest].Bytes; len(body) >= minimumFullBodyBytes {
				targets = append(targets, canonicalEvidenceBatchTarget{digest: digest, target: body, priority: digestIndex})
			}
		}
		hexMatch, reversibleMatch, err := scanCanonicalEvidenceBatchAndReversible(items, order, targets, canonicalEvidenceCarrierHex, false, budget)
		if err != nil {
			return "", "", "", false, err
		}
		if hexMatch.found {
			return hexMatch.itemLabel, hexMatch.target.digest, "decoded hexadecimal carrier body", true, nil
		}
		if reversibleMatch.found && (!bestReversible.found || reversibleMatch.target.priority < bestReversible.target.priority) {
			bestReversible = reversibleMatch
		}
		start = end
	}
	if bestReversible.found {
		return bestReversible.itemLabel, bestReversible.target.digest, "decoded reversible numeric or boolean carrier body", true, nil
	}
	return "", "", "", false, nil
}

func scanCanonicalEvidenceSingleReversible(items []evidenceClosureItem, order jsonCarrierTraversal, target []byte, budget *canonicalEvidenceClosureWorkBudget) (string, bool, error) {
	auxiliary, ok := canonicalEvidenceMatcherAuxiliaryBytes(int64(len(target)), false)
	if !ok || auxiliary > canonicalEvidenceClosureMaxMatcherAuxiliaryBytes-maxEvidenceCarrierBytesPerFile {
		return "", false, fmt.Errorf("single reversible matcher and concurrent carrier decode exceed fixed auxiliary limit %d", canonicalEvidenceClosureMaxMatcherAuxiliaryBytes)
	}

	if err := budget.consume(int64(len(target))); err != nil {
		return "", false, err
	}
	m, err := newStreamingExactMatcher(target, false)
	if err != nil {
		return "", false, err
	}
	for _, item := range items {
		found := false
		err := scanEvidenceClosureItemWithOrderBudget(item, order, budget, func(c orderedJSONCarrier) error {
			for _, a := range c.decodedAlternatives {
				if err := budget.consume(int64(len(a))); err != nil {
					return err
				}
				if _, ok := m.advanceFrom(0, a); ok {
					found = true
					return errCanonicalEvidenceClosureFound
				}
			}
			return nil
		})
		if errors.Is(err, errCanonicalEvidenceClosureFound) {
			return item.label, true, nil
		}
		if err != nil {
			return "", false, err
		}
		if found {
			return item.label, true, nil
		}
	}
	return "", false, nil
}

type canonicalEvidenceBatchNode struct {
	firstChild        uint32
	nextSibling       uint32
	failure           uint32
	denseIndexPlusOne uint32
	terminal          int
	match             int
	childCount        uint16
	value             byte
}

type canonicalEvidenceBatchEdge struct {
	child uint32
	value byte
}

type canonicalEvidenceBatchDenseTransitions [256]uint32

type canonicalEvidenceBatchMatcher struct {
	targets          []canonicalEvidenceBatchTarget
	nodes            []canonicalEvidenceBatchNode
	edges            []canonicalEvidenceBatchEdge
	denseTransitions []canonicalEvidenceBatchDenseTransitions
	directState      uint32
	branchStates     [credentialClosureMaxStates]uint32
	branchCount      int
	minimumPriority  int
}

func newCanonicalEvidenceBatchMatcher(targets []canonicalEvidenceBatchTarget, foldHex bool, budget *canonicalEvidenceClosureWorkBudget) (*canonicalEvidenceBatchMatcher, error) {
	return newCanonicalEvidenceBatchMatcherWithAuxiliaryLimit(targets, foldHex, budget, canonicalEvidenceClosureMaxMatcherAuxiliaryBytes)
}

// newCanonicalEvidenceBatchMatcherWithAuxiliaryLimit is a private boundary-test
// seam. Production always supplies the fixed scanner ceiling through the
// wrapper above.
func newCanonicalEvidenceBatchMatcherWithAuxiliaryLimit(targets []canonicalEvidenceBatchTarget, foldHex bool, budget *canonicalEvidenceClosureWorkBudget, auxiliaryLimit int64) (*canonicalEvidenceBatchMatcher, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("canonical evidence batch has no targets")
	}
	if budget == nil {
		return nil, fmt.Errorf("canonical evidence batch has no deterministic work budget")
	}
	var targetBytes, ownedBytes int64
	for _, target := range targets {
		if len(target.target) == 0 {
			return nil, fmt.Errorf("selected evidence digest %s has empty closure target", target.digest)
		}
		if int64(len(target.target)) > math.MaxInt64-targetBytes {
			return nil, fmt.Errorf("canonical evidence batch target byte count overflows")
		}
		targetBytes += int64(len(target.target))
		if target.owned {
			if int64(len(target.target)) > math.MaxInt64-ownedBytes {
				return nil, fmt.Errorf("canonical evidence batch owned target byte count overflows")
			}
			ownedBytes += int64(len(target.target))
		}
	}
	peakAuxiliary, ok := canonicalEvidenceBatchPeakAuxiliaryBytes(targetBytes, ownedBytes)
	if !ok || peakAuxiliary > auxiliaryLimit {
		return nil, fmt.Errorf("canonical evidence batch matcher and concurrent carrier decode require %d auxiliary bytes above fixed limit %d", peakAuxiliary, auxiliaryLimit)
	}
	if targetBytes > int64(math.MaxInt-1) {
		return nil, fmt.Errorf("canonical evidence batch target bytes %d exceed local index capacity", targetBytes)
	}
	if err := budget.consume(targetBytes); err != nil {
		return nil, err
	}
	matcher := &canonicalEvidenceBatchMatcher{
		targets:         targets,
		nodes:           make([]canonicalEvidenceBatchNode, 1, int(targetBytes)+1),
		minimumPriority: targets[0].priority,
	}
	matcher.nodes[0].terminal = -1
	matcher.nodes[0].match = -1
	for targetIndex, target := range targets {
		if target.priority < matcher.minimumPriority {
			matcher.minimumPriority = target.priority
		}
		if foldHex {
			for _, current := range target.target {
				if current >= 'A' && current <= 'F' {
					return nil, fmt.Errorf("folded hexadecimal closure target is not canonical lowercase")
				}
			}
		}
		if err := matcher.add(target.target, targetIndex, foldHex, budget); err != nil {
			return nil, err
		}
	}
	if err := matcher.finalizeTransitions(); err != nil {
		return nil, err
	}
	if err := matcher.buildFailures(budget); err != nil {
		return nil, err
	}
	return matcher, nil
}

func (matcher *canonicalEvidenceBatchMatcher) preferred(left, right int) int {
	if left < 0 {
		return right
	}
	if right < 0 || matcher.targets[left].priority <= matcher.targets[right].priority {
		return left
	}
	return right
}

func (matcher *canonicalEvidenceBatchMatcher) findBuildChild(node uint32, value byte, budget *canonicalEvidenceClosureWorkBudget) (uint32, uint32, error) {
	previous := uint32(0)
	for child := matcher.nodes[node].firstChild; child != 0; child = matcher.nodes[child].nextSibling {
		if err := budget.consume(1); err != nil {
			return 0, 0, err
		}
		if matcher.nodes[child].value == value {
			return child, previous, nil
		}
		if matcher.nodes[child].value > value {
			return 0, previous, nil
		}
		previous = child
	}
	return 0, previous, nil
}

func (matcher *canonicalEvidenceBatchMatcher) add(value []byte, targetIndex int, foldHex bool, budget *canonicalEvidenceClosureWorkBudget) error {
	state := uint32(0)
	for _, current := range value {
		if foldHex && current >= 'A' && current <= 'F' {
			current += 'a' - 'A'
		}
		child, previous, err := matcher.findBuildChild(state, current, budget)
		if err != nil {
			return err
		}
		if child == 0 {
			if len(matcher.nodes) == cap(matcher.nodes) {
				return fmt.Errorf("canonical evidence batch node bound exhausted")
			}
			if matcher.nodes[state].childCount == 256 {
				return fmt.Errorf("canonical evidence batch node has more than the byte alphabet's 256 transitions")
			}
			child = uint32(len(matcher.nodes))
			matcher.nodes = append(matcher.nodes, canonicalEvidenceBatchNode{terminal: -1, match: -1, value: current})
			if previous == 0 {
				matcher.nodes[child].nextSibling = matcher.nodes[state].firstChild
				matcher.nodes[state].firstChild = child
			} else {
				matcher.nodes[child].nextSibling = matcher.nodes[previous].nextSibling
				matcher.nodes[previous].nextSibling = child
			}
			matcher.nodes[state].childCount++
		}
		state = child
	}
	matcher.nodes[state].terminal = matcher.preferred(matcher.nodes[state].terminal, targetIndex)
	return nil
}

func (matcher *canonicalEvidenceBatchMatcher) finalizeTransitions() error {
	edges := make([]canonicalEvidenceBatchEdge, len(matcher.nodes)-1)
	denseCount := 0
	for nodeIndex := range matcher.nodes {
		if matcher.nodes[nodeIndex].childCount >= canonicalEvidenceBatchDenseTransitionThreshold {
			denseCount++
		}
	}
	denseTransitions := make([]canonicalEvidenceBatchDenseTransitions, denseCount)
	denseCursor := 0
	cursor := 0
	for nodeIndex := range matcher.nodes {
		child := matcher.nodes[nodeIndex].firstChild
		matcher.nodes[nodeIndex].firstChild = uint32(cursor)
		var dense *canonicalEvidenceBatchDenseTransitions
		if matcher.nodes[nodeIndex].childCount >= canonicalEvidenceBatchDenseTransitionThreshold {
			matcher.nodes[nodeIndex].denseIndexPlusOne = uint32(denseCursor + 1)
			dense = &denseTransitions[denseCursor]
			denseCursor++
		}
		count := 0
		for child != 0 {
			if cursor == len(edges) {
				return fmt.Errorf("canonical evidence batch transition count exceeds node bound")
			}
			edges[cursor] = canonicalEvidenceBatchEdge{child: child, value: matcher.nodes[child].value}
			if dense != nil {
				(*dense)[matcher.nodes[child].value] = child
			}
			cursor++
			count++
			child = matcher.nodes[child].nextSibling
		}
		if count != int(matcher.nodes[nodeIndex].childCount) {
			return fmt.Errorf("canonical evidence batch transition cardinality mismatch")
		}
	}
	if cursor != len(edges) {
		return fmt.Errorf("canonical evidence batch transition array is incomplete")
	}
	matcher.edges = edges
	matcher.denseTransitions = denseTransitions
	return nil
}

func (matcher *canonicalEvidenceBatchMatcher) findChild(node uint32, value byte, budget *canonicalEvidenceClosureWorkBudget) (uint32, error) {
	if int(node) >= len(matcher.nodes) {
		return 0, fmt.Errorf("canonical evidence batch transition state is out of range")
	}
	count := matcher.nodes[node].childCount
	if count == 0 {
		return 0, nil
	}
	if denseIndexPlusOne := matcher.nodes[node].denseIndexPlusOne; denseIndexPlusOne != 0 {
		if err := budget.consume(1); err != nil {
			return 0, err
		}
		denseIndex := int(denseIndexPlusOne - 1)
		if denseIndex >= len(matcher.denseTransitions) {
			return 0, fmt.Errorf("canonical evidence batch dense transition index is out of range")
		}
		return matcher.denseTransitions[denseIndex][value], nil
	}
	// A byte alphabet has at most 256 children. Charge the complete worst-case
	// binary-search comparison count before performing any comparison.
	if err := budget.consume(int64(bits.Len16(count))); err != nil {
		return 0, err
	}
	start := int(matcher.nodes[node].firstChild)
	end := start + int(count)
	if start < 0 || end > len(matcher.edges) {
		return 0, fmt.Errorf("canonical evidence batch transition range is out of bounds")
	}
	for low, high := start, end; low < high; {
		middle := low + (high-low)/2
		edge := matcher.edges[middle]
		if edge.value == value {
			return edge.child, nil
		}
		if edge.value < value {
			low = middle + 1
		} else {
			high = middle
		}
	}
	return 0, nil
}

func (matcher *canonicalEvidenceBatchMatcher) buildFailures(budget *canonicalEvidenceClosureWorkBudget) error {
	queue := make([]uint32, 0, len(matcher.nodes)-1)
	rootStart := int(matcher.nodes[0].firstChild)
	rootEnd := rootStart + int(matcher.nodes[0].childCount)
	for edgeIndex := rootStart; edgeIndex < rootEnd; edgeIndex++ {
		child := matcher.edges[edgeIndex].child
		matcher.nodes[child].failure = 0
		matcher.nodes[child].match = matcher.nodes[child].terminal
		queue = append(queue, child)
	}
	for head := 0; head < len(queue); head++ {
		parent := queue[head]
		start := int(matcher.nodes[parent].firstChild)
		end := start + int(matcher.nodes[parent].childCount)
		for edgeIndex := start; edgeIndex < end; edgeIndex++ {
			child := matcher.edges[edgeIndex].child
			value := matcher.edges[edgeIndex].value
			failure := matcher.nodes[parent].failure
			for {
				candidate, err := matcher.findChild(failure, value, budget)
				if err != nil {
					return err
				}
				if candidate != 0 && candidate != child {
					failure = candidate
					break
				}
				if failure == 0 {
					break
				}
				failure = matcher.nodes[failure].failure
			}
			matcher.nodes[child].failure = failure
			matcher.nodes[child].match = matcher.preferred(matcher.nodes[child].terminal, matcher.nodes[failure].match)
			queue = append(queue, child)
		}
	}
	return nil
}

func (matcher *canonicalEvidenceBatchMatcher) advanceFrom(state uint32, value []byte, foldHex bool, budget *canonicalEvidenceClosureWorkBudget) (uint32, int, error) {
	result := -1
	for _, current := range value {
		if foldHex && current >= 'A' && current <= 'F' {
			current += 'a' - 'A'
		}
		for {
			child, err := matcher.findChild(state, current, budget)
			if err != nil {
				return state, result, err
			}
			if child != 0 {
				state = child
				break
			}
			if state == 0 {
				break
			}
			state = matcher.nodes[state].failure
		}
		result = matcher.preferred(result, matcher.nodes[state].match)
		if result >= 0 && matcher.targets[result].priority == matcher.minimumPriority {
			return state, result, nil
		}
	}
	return state, result, nil
}

func (matcher *canonicalEvidenceBatchMatcher) advanceRepresentations(carrier orderedJSONCarrier, foldHex bool, budget *canonicalEvidenceClosureWorkBudget) (int, error) {
	if matcher.branchCount == 0 {
		matcher.branchCount = 1
	}
	var next [credentialClosureMaxStates]uint32
	nextCount, found := 0, -1
	for stateIndex := 0; stateIndex < matcher.branchCount; stateIndex++ {
		for representationIndex := 0; representationIndex < carrierRepresentationCount(carrier); representationIndex++ {
			representation := carrierRepresentation(carrier, representationIndex)
			if err := budget.consume(int64(len(representation))); err != nil {
				return -1, err
			}
			state, matched, err := matcher.advanceFrom(matcher.branchStates[stateIndex], representation, foldHex, budget)
			if err != nil {
				return -1, err
			}
			found = matcher.preferred(found, matched)
			if found >= 0 && matcher.targets[found].priority == matcher.minimumPriority {
				return found, nil
			}
			duplicate := false
			for prior := 0; prior < nextCount; prior++ {
				if next[prior] == state {
					duplicate = true
					break
				}
			}
			if !duplicate {
				if nextCount == len(next) {
					return -1, fmt.Errorf("ambiguous reversible carrier reconstruction")
				}
				next[nextCount] = state
				nextCount++
			}
		}
	}
	matcher.branchStates = next
	matcher.branchCount = nextCount
	return found, nil
}

func (matcher *canonicalEvidenceBatchMatcher) advanceCarrier(carrier orderedJSONCarrier, mode canonicalEvidenceCarrierMode, foldHex bool, budget *canonicalEvidenceClosureWorkBudget) (int, error) {
	if mode == canonicalEvidenceCarrierRawRepresentations {
		return matcher.advanceRepresentations(carrier, foldHex, budget)
	}
	if mode == canonicalEvidenceCarrierBinary {
		if carrier.kind != orderedJSONByteArray && carrier.kind != orderedJSONByteIndexObject && carrier.kind != orderedJSONBooleanVector {
			return -1, nil
		}
		if err := budget.consume(int64(len(carrier.bytes))); err != nil {
			return -1, err
		}
		state, found, err := matcher.advanceFrom(matcher.directState, carrier.bytes, false, budget)
		if err != nil {
			return -1, err
		}
		matcher.directState = state
		return found, nil
	}
	decodedCapacity, err := canonicalEvidenceDecodedCarrierCapacity(mode, len(carrier.bytes))
	if err != nil {
		return -1, err
	}
	decodeWork := int64(len(carrier.bytes)) + int64(decodedCapacity)
	if mode == canonicalEvidenceCarrierBase64 {
		// One reusable destination serves padded and raw decoding. Charge a
		// second complete input read because the padded attempt can fail before
		// the raw attempt succeeds.
		decodeWork += int64(len(carrier.bytes))
	}
	if err := budget.consume(decodeWork); err != nil {
		return -1, err
	}
	var decoded []byte
	var ok bool
	switch mode {
	case canonicalEvidenceCarrierBase64:
		decoded, ok = exactCanonicalBase64Carrier(carrier.bytes)
	case canonicalEvidenceCarrierHex:
		decoded, ok = exactHexCarrier(carrier.bytes)
	default:
		return -1, fmt.Errorf("unknown canonical evidence carrier mode %d", mode)
	}
	if !ok {
		return -1, nil
	}
	state, found, err := matcher.advanceFrom(matcher.directState, decoded, false, budget)
	if err != nil {
		return -1, err
	}
	matcher.directState = state
	return found, nil
}

func scanCanonicalEvidenceBatch(items []evidenceClosureItem, order jsonCarrierTraversal, targets []canonicalEvidenceBatchTarget, mode canonicalEvidenceCarrierMode, foldHex bool, budget *canonicalEvidenceClosureWorkBudget) (canonicalEvidenceBatchMatch, error) {
	var result canonicalEvidenceBatchMatch
	matcher, err := newCanonicalEvidenceBatchMatcher(targets, foldHex, budget)
	if err != nil {
		return result, err
	}
	for _, item := range items {
		err := scanEvidenceClosureItemWithOrderBudget(item, order, budget, func(carrier orderedJSONCarrier) error {
			matched, err := matcher.advanceCarrier(carrier, mode, foldHex, budget)
			if err != nil {
				return err
			}
			if matched >= 0 && (!result.found || matcher.targets[matched].priority < result.target.priority) {
				result = canonicalEvidenceBatchMatch{itemLabel: item.label, target: matcher.targets[matched], found: true}
			}
			if result.found && result.target.priority == matcher.minimumPriority {
				return errCanonicalEvidenceClosureFound
			}
			return nil
		})
		if errors.Is(err, errCanonicalEvidenceClosureFound) {
			return result, nil
		}
		if err != nil {
			return canonicalEvidenceBatchMatch{}, err
		}
	}
	return result, nil
}

func scanCanonicalEvidenceBatchAndReversible(items []evidenceClosureItem, order jsonCarrierTraversal, targets []canonicalEvidenceBatchTarget, mode canonicalEvidenceCarrierMode, foldHex bool, budget *canonicalEvidenceClosureWorkBudget) (canonicalEvidenceBatchMatch, canonicalEvidenceBatchMatch, error) {
	var primary, reversible canonicalEvidenceBatchMatch
	matcher, err := newCanonicalEvidenceBatchMatcher(targets, foldHex, budget)
	if err != nil {
		return primary, reversible, err
	}
	for _, item := range items {
		err := scanEvidenceClosureItemWithOrderBudget(item, order, budget, func(carrier orderedJSONCarrier) error {
			matched, err := matcher.advanceCarrier(carrier, mode, foldHex, budget)
			if err != nil {
				return err
			}
			if matched >= 0 && (!primary.found || matcher.targets[matched].priority < primary.target.priority) {
				primary = canonicalEvidenceBatchMatch{itemLabel: item.label, target: matcher.targets[matched], found: true}
			}
			if primary.found && primary.target.priority == matcher.minimumPriority {
				return errCanonicalEvidenceClosureFound
			}
			for _, alternative := range carrier.decodedAlternatives {
				if err := budget.consume(int64(len(alternative))); err != nil {
					return err
				}
				_, matched, err := matcher.advanceFrom(0, alternative, false, budget)
				if err != nil {
					return err
				}
				if matched >= 0 && (!reversible.found || matcher.targets[matched].priority < reversible.target.priority) {
					reversible = canonicalEvidenceBatchMatch{itemLabel: item.label, target: matcher.targets[matched], found: true}
				}
			}
			return nil
		})
		if errors.Is(err, errCanonicalEvidenceClosureFound) {
			return primary, reversible, nil
		}
		if err != nil {
			return canonicalEvidenceBatchMatch{}, canonicalEvidenceBatchMatch{}, err
		}
	}
	return primary, reversible, nil
}

func scanCanonicalEvidenceReversibleBatch(items []evidenceClosureItem, order jsonCarrierTraversal, targets []canonicalEvidenceBatchTarget, budget *canonicalEvidenceClosureWorkBudget) (canonicalEvidenceBatchMatch, error) {
	var result canonicalEvidenceBatchMatch
	matcher, err := newCanonicalEvidenceBatchMatcher(targets, false, budget)
	if err != nil {
		return result, err
	}
	for _, item := range items {
		err := scanEvidenceClosureItemWithOrderBudget(item, order, budget, func(carrier orderedJSONCarrier) error {
			for _, alternative := range carrier.decodedAlternatives {
				if err := budget.consume(int64(len(alternative))); err != nil {
					return err
				}
				_, matched, err := matcher.advanceFrom(0, alternative, false, budget)
				if err != nil {
					return err
				}
				if matched >= 0 && (!result.found || matcher.targets[matched].priority < result.target.priority) {
					result = canonicalEvidenceBatchMatch{itemLabel: item.label, target: matcher.targets[matched], found: true}
				}
				if result.found && result.target.priority == matcher.minimumPriority {
					return errCanonicalEvidenceClosureFound
				}
			}
			return nil
		})
		if errors.Is(err, errCanonicalEvidenceClosureFound) {
			return result, nil
		}
		if err != nil {
			return canonicalEvidenceBatchMatch{}, err
		}
	}
	return result, nil
}

func scanCanonicalEvidencePattern(items []evidenceClosureItem, order jsonCarrierTraversal, digest, encoding string, target []byte, foldHex, targetOwned bool, mode canonicalEvidenceCarrierMode, budget *canonicalEvidenceClosureWorkBudget) (string, bool, error) {
	auxiliaryBytes, ok := canonicalEvidenceMatcherAuxiliaryBytes(int64(len(target)), targetOwned)
	if !ok || auxiliaryBytes > math.MaxInt64-maxEvidenceCarrierBytesPerFile {
		return "", false, fmt.Errorf("selected evidence digest %s %s matcher has no finite auxiliary peak", digest, encoding)
	}
	peakAuxiliary := auxiliaryBytes + maxEvidenceCarrierBytesPerFile
	if peakAuxiliary > canonicalEvidenceClosureMaxMatcherAuxiliaryBytes {
		return "", false, fmt.Errorf("selected evidence digest %s %s matcher and concurrent carrier decode require %d auxiliary bytes above fixed limit %d", digest, encoding, peakAuxiliary, canonicalEvidenceClosureMaxMatcherAuxiliaryBytes)
	}
	if err := budget.consume(int64(len(target))); err != nil {
		return "", false, fmt.Errorf("selected evidence digest %s %s: %w", digest, encoding, err)
	}
	matcher, err := newStreamingExactMatcher(target, foldHex)
	if err != nil {
		return "", false, err
	}
	pattern := evidencePatternMatcher{digest: digest, encoding: encoding, matcher: matcher}
	for _, item := range items {
		err := scanEvidenceClosureItemWithOrderBudget(item, order, budget, func(carrier orderedJSONCarrier) error {
			found, overflow, err := pattern.advanceCarrier(carrier, mode, budget)
			if err != nil {
				return err
			}
			if found || overflow {
				if overflow {
					pattern.encoding = "ambiguous reversible carrier reconstruction"
				}
				return errCanonicalEvidenceClosureFound
			}
			return nil
		})
		if errors.Is(err, errCanonicalEvidenceClosureFound) {
			return item.label, true, nil
		}
		if err != nil {
			return "", false, err
		}
	}
	return "", false, nil
}

func (pattern *evidencePatternMatcher) advanceCarrier(carrier orderedJSONCarrier, mode canonicalEvidenceCarrierMode, budget *canonicalEvidenceClosureWorkBudget) (bool, bool, error) {
	switch mode {
	case canonicalEvidenceCarrierRawRepresentations:
		return pattern.advanceRepresentations(carrier, budget)
	case canonicalEvidenceCarrierBinary:
		if carrier.kind != orderedJSONByteArray && carrier.kind != orderedJSONByteIndexObject && carrier.kind != orderedJSONBooleanVector {
			return false, false, nil
		}
		if err := budget.consume(int64(len(carrier.bytes))); err != nil {
			return false, false, err
		}
		return pattern.matcher.advance(carrier.bytes), false, nil
	}
	decodedCapacity, err := canonicalEvidenceDecodedCarrierCapacity(mode, len(carrier.bytes))
	if err != nil {
		return false, false, err
	}
	decodeWork := int64(len(carrier.bytes)) + int64(decodedCapacity)
	if mode == canonicalEvidenceCarrierBase64 {
		decodeWork += int64(len(carrier.bytes))
	}
	if err := budget.consume(decodeWork); err != nil {
		return false, false, err
	}
	var decoded []byte
	var ok bool
	switch mode {
	case canonicalEvidenceCarrierBase64:
		decoded, ok = exactCanonicalBase64Carrier(carrier.bytes)
	case canonicalEvidenceCarrierHex:
		decoded, ok = exactHexCarrier(carrier.bytes)
	default:
		return false, false, fmt.Errorf("unknown canonical evidence carrier mode %d", mode)
	}
	if !ok {
		return false, false, nil
	}
	return pattern.matcher.advance(decoded), false, nil
}

func (pattern *evidencePatternMatcher) advanceRepresentations(carrier orderedJSONCarrier, budget *canonicalEvidenceClosureWorkBudget) (bool, bool, error) {
	if pattern.branchStateCount == 0 {
		pattern.branchStateCount = 1
	}
	var next [credentialClosureMaxStates]int
	nextCount := 0
	for stateIndex := 0; stateIndex < pattern.branchStateCount; stateIndex++ {
		for representationIndex := 0; representationIndex < carrierRepresentationCount(carrier); representationIndex++ {
			representation := carrierRepresentation(carrier, representationIndex)
			if err := budget.consume(int64(len(representation))); err != nil {
				return false, false, err
			}
			matched, found := pattern.matcher.advanceFrom(pattern.branchStates[stateIndex], representation)
			if found {
				return true, false, nil
			}
			duplicate := false
			for prior := 0; prior < nextCount; prior++ {
				if next[prior] == matched {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			if nextCount == len(next) {
				return false, true, nil
			}
			next[nextCount] = matched
			nextCount++
		}
	}
	pattern.branchStates = next
	pattern.branchStateCount = nextCount
	return false, false, nil
}

func exactBase64Carrier(encoding *base64.Encoding, value []byte) ([]byte, bool) {
	if len(value) == 0 {
		return nil, false
	}
	// encoding/base64 deliberately ignores CR/LF. Provider closure carriers do
	// not: accepting them would make one byte sequence have multiple textual
	// identities. Strict decoding also rejects non-zero trailing padding bits.
	for _, current := range value {
		if current == '\r' || current == '\n' {
			return nil, false
		}
	}
	decoded := make([]byte, encoding.DecodedLen(len(value)))
	decodedBytes, err := encoding.Strict().Decode(decoded, value)
	if err != nil {
		return nil, false
	}
	return decoded[:decodedBytes], true
}

func exactCanonicalBase64Carrier(value []byte) ([]byte, bool) {
	if len(value) == 0 {
		return nil, false
	}
	padded, raw := canonicalEvidenceBase64Alphabet(value)
	if padded == nil {
		return nil, false
	}
	for _, current := range value {
		if current == '\r' || current == '\n' {
			return nil, false
		}
	}
	capacity := padded.DecodedLen(len(value))
	if rawCapacity := raw.DecodedLen(len(value)); rawCapacity > capacity {
		capacity = rawCapacity
	}
	decoded := make([]byte, capacity)
	if decodedBytes, err := padded.Strict().Decode(decoded, value); err == nil {
		return decoded[:decodedBytes], true
	}
	decodedBytes, err := raw.Strict().Decode(decoded, value)
	if err != nil {
		return nil, false
	}
	return decoded[:decodedBytes], true
}

func canonicalEvidenceBase64Alphabet(value []byte) (*base64.Encoding, *base64.Encoding) {
	standardExclusive := false
	urlExclusive := false
	for _, current := range value {
		switch current {
		case '+', '/':
			standardExclusive = true
		case '-', '_':
			urlExclusive = true
		}
	}
	if standardExclusive && urlExclusive {
		return nil, nil
	}
	if urlExclusive {
		return base64.URLEncoding, base64.RawURLEncoding
	}
	return base64.StdEncoding, base64.RawStdEncoding
}

func exactHexCarrier(value []byte) ([]byte, bool) {
	if len(value) == 0 || len(value)%2 != 0 {
		return nil, false
	}
	for _, current := range value {
		if !((current >= '0' && current <= '9') || (current >= 'a' && current <= 'f') || (current >= 'A' && current <= 'F')) {
			return nil, false
		}
	}
	decoded := make([]byte, hex.DecodedLen(len(value)))
	decodedBytes, err := hex.Decode(decoded, value)
	if err != nil || decodedBytes != len(decoded) {
		return nil, false
	}
	return decoded, true
}

const (
	credentialClosureWindowBytes  = 8192
	credentialClosureOverlapBytes = 1024
	credentialClosureMaxStates    = 32
)

type credentialClosureState struct {
	candidate [credentialClosureWindowBytes]byte
	length    int
	kind      orderedJSONCarrierKind
}

func (state *credentialClosureState) value() []byte {
	return state.candidate[:state.length]
}

type credentialClosureScanner struct {
	states         *[credentialClosureMaxStates]credentialClosureState
	nextStates     *[credentialClosureMaxStates]credentialClosureState
	stateCount     int
	nextStateCount int
	scratch        [credentialClosureWindowBytes]byte
}

func newCredentialClosureScanner() *credentialClosureScanner {
	return &credentialClosureScanner{
		states:     &[credentialClosureMaxStates]credentialClosureState{},
		nextStates: &[credentialClosureMaxStates]credentialClosureState{},
	}
}

func (scanner *credentialClosureScanner) scanJSON(raw []byte) error {
	return scanner.scanJSONWithOrder(raw, jsonCarrierSourceOrder)
}

func (scanner *credentialClosureScanner) scanJSONWithOrder(raw []byte, order jsonCarrierTraversal) error {
	return walkJSONCarriers(raw, order, scanner.advance)
}

func (scanner *credentialClosureScanner) advance(carrier orderedJSONCarrier) error {
	if carrier.placeholderBoundary {
		if err := scanner.finish(); err != nil {
			return err
		}
		scanner.reset()
		return nil
	}
	for representationIndex := 0; representationIndex < carrierRepresentationCount(carrier); representationIndex++ {
		if credentialClosureCarrierContainsMaterial(carrierRepresentation(carrier, representationIndex)) {
			return credentialClosureMaterialError()
		}
	}

	scanner.nextStateCount = 0
	for stateIndex := 0; stateIndex < scanner.stateCount; stateIndex++ {
		state := &scanner.states[stateIndex]
		for representationIndex := 0; representationIndex < carrierRepresentationCount(carrier); representationIndex++ {
			representation := carrierRepresentation(carrier, representationIndex)
			if len(representation) == 0 {
				continue
			}
			prior := state.value()
			if state.kind != carrier.kind &&
				!credentialClosureCrossKindJoinOpen(prior) &&
				!credentialClosureCrossKindJoinStarts(representation) &&
				!credentialClosureStrictIntroducerPrefix(prior) {
				if credentialClosureWindowContainsMaterial(prior) {
					return credentialClosureMaterialError()
				}
				continue
			}
			if len(prior)+len(representation) > credentialClosureWindowBytes {
				if credentialClosureWindowContainsMaterial(prior) {
					return credentialClosureMaterialError()
				}
				// A still-plausible credential reconstruction may not outrun the
				// bounded verifier state. Reject instead of silently forgetting its
				// introducer and accepting an arbitrarily long covert carrier.
				return credentialClosureMaterialError()
			}
			copy(scanner.scratch[:], prior)
			copy(scanner.scratch[len(prior):], representation)
			combined := scanner.scratch[:len(prior)+len(representation)]
			if credentialClosureCarrierCanStart(combined) {
				if err := scanner.addNextState(combined, carrier.kind); err != nil {
					return err
				}
				continue
			}
			if credentialClosureWindowContainsMaterial(combined) {
				return credentialClosureMaterialError()
			}
		}
	}
	for representationIndex := 0; representationIndex < carrierRepresentationCount(carrier); representationIndex++ {
		representation := carrierRepresentation(carrier, representationIndex)
		if start, found := credentialClosureCarrierStartOffset(representation); found {
			if len(representation)-start > credentialClosureWindowBytes {
				return credentialClosureMaterialError()
			}
			if err := scanner.addNextState(representation[start:], carrier.kind); err != nil {
				return err
			}
		}
	}
	scanner.states, scanner.nextStates = scanner.nextStates, scanner.states
	scanner.stateCount = scanner.nextStateCount
	return nil
}

func (scanner *credentialClosureScanner) addNextState(value []byte, kind orderedJSONCarrierKind) error {
	for index := 0; index < scanner.nextStateCount; index++ {
		state := &scanner.nextStates[index]
		if state.kind == kind && bytes.Equal(state.value(), value) {
			return nil
		}
	}
	if scanner.nextStateCount == len(scanner.nextStates) {
		return credentialClosureMaterialError()
	}
	state := &scanner.nextStates[scanner.nextStateCount]
	copy(state.candidate[:], value)
	state.length = len(value)
	state.kind = kind
	scanner.nextStateCount++
	return nil
}

func (scanner *credentialClosureScanner) finish() error {
	for index := 0; index < scanner.stateCount; index++ {
		if credentialClosureWindowContainsMaterial(scanner.states[index].value()) {
			return credentialClosureMaterialError()
		}
	}
	return nil
}

func credentialClosureWindowContainsMaterial(value []byte) bool {
	return len(value) >= 16 && (credentialShapedValue(string(value)) || knownCredentialTokenAnywhere(value))
}

func credentialClosureMaterialError() error {
	return fmt.Errorf("candidate carries credential or secret material reconstructed across the canonical artifact closure")
}

func (scanner *credentialClosureScanner) reset() {
	scanner.stateCount = 0
	scanner.nextStateCount = 0
}

func credentialClosureCarrierContainsMaterial(value []byte) bool {
	if len(value) < 16 {
		return false
	}
	for start := 0; start < len(value); {
		end := start + credentialClosureWindowBytes
		if end > len(value) {
			end = len(value)
		}
		if credentialClosureWindowContainsMaterial(value[start:end]) {
			return true
		}
		if end == len(value) {
			break
		}
		start = end - credentialClosureOverlapBytes
	}
	return false
}

func credentialClosureCarrierCanStart(value []byte) bool {
	value = credentialClosureTrimLeftSpace(value)
	if len(value) == 0 {
		return false
	}

	// Only introducers whose case-folded first byte equals value[0] can match;
	// see credentialClosureStartPatternsByFirstByte for why this is exact.
	for _, pattern := range credentialClosureStartPatternsByFirstByte[credentialClosureFoldASCII(value[0])] {
		if !pattern.assignment {
			if credentialClosureStartsOrIsPrefix(value, pattern.bytes) {
				return true
			}
			continue
		}
		name := pattern.bytes
		if len(value) <= len(name) && credentialClosureEqualFoldASCII(value, name[:len(value)]) {
			return true
		}
		if len(value) < len(name) || !credentialClosureEqualFoldASCII(value[:len(name)], name) {
			continue
		}
		remainder := credentialClosureTrimLeftHorizontalSpace(value[len(name):])
		if len(remainder) == 0 || remainder[0] == '=' || remainder[0] == ':' {
			return true
		}
	}
	return false
}

// credentialClosureStartPattern is one introducer from the closed rosters
// below, converted to bytes once instead of at every scanned byte position.
// assignment selects the assignment-name arm of
// credentialClosureCarrierCanStart; every other introducer is a token, JWT, or
// header prefix.
type credentialClosureStartPattern struct {
	bytes      []byte
	assignment bool
}

// credentialClosureStartPatternsByFirstByte partitions every introducer that
// credentialClosureCarrierCanStart accepts by its ASCII-case-folded first byte.
//
// The partition is exact, not a heuristic. credentialClosureCarrierCanStart only
// evaluates a non-empty value. Every arm compares value[0] with the first byte
// of a non-empty introducer: the assignment prefix arm compares
// min(len(value), len(name)) >= 1 bytes, the assignment arm compares len(name)
// bytes, and credentialClosureStartsOrIsPrefix compares at least one byte. So an
// introducer whose folded first byte differs from value[0] can never match, and
// trying only the introducers in value[0]'s bucket returns the same boolean as
// trying all of them. The index is derived from the same rosters, and an empty
// introducer (which would break the first-byte argument) refuses at package
// initialization.
//
// credentialClosureCarrierStartOffset calls the predicate at every byte of every
// scanned carrier, so iterating the full rosters there dominated verifier and
// stage-compiler CPU.
var credentialClosureStartPatternsByFirstByte = newCredentialClosureStartPatternIndex(
	credentialClosureAssignmentNames, credentialClosureKnownTokenPrefixes, credentialClosureJWTPrefix, credentialClosureHeaderPrefixes,
)

const credentialClosureJWTPrefix = "eyj"

func newCredentialClosureStartPatternIndex(assignmentNames, tokenPrefixes []string, jwtPrefix string, headerPrefixes []string) *[256][]credentialClosureStartPattern {
	index := &[256][]credentialClosureStartPattern{}
	add := func(introducer string, assignment bool) {
		if introducer == "" {
			panic("credential closure introducer roster contains an empty introducer")
		}
		first := credentialClosureFoldASCII(introducer[0])
		index[first] = append(index[first], credentialClosureStartPattern{bytes: []byte(introducer), assignment: assignment})
	}
	for _, name := range assignmentNames {
		add(name, true)
	}
	for _, prefix := range tokenPrefixes {
		add(prefix, false)
	}
	add(jwtPrefix, false)
	for _, prefix := range headerPrefixes {
		add(prefix, false)
	}
	return index
}

func credentialClosureFoldASCII(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

var credentialClosureAssignmentNames = []string{
	"access token", "access-token", "access_token", "accesstoken",
	"refresh token", "refresh-token", "refresh_token", "refreshtoken",
	"client secret", "client-secret", "client_secret", "clientsecret",
	"api key", "api-key", "api_key", "apikey",
	"password",
	"bearer token", "bearer-token", "bearer_token", "bearertoken",
	"aws secret access key", "aws-secret-access-key", "aws_secret_access_key", "awssecretaccesskey",
	"consumer secret", "consumer-secret", "consumer_secret", "consumersecret",
	"signing secret", "signing-secret", "signing_secret", "signingsecret",
	"webhook secret", "webhook-secret", "webhook_secret", "webhooksecret",
	"verification token", "verification-token", "verification_token", "verificationtoken",
}

var credentialClosureKnownTokenPrefixes = []string{"ghp_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "sk-", "ya29.", "akia"}

var credentialClosureHeaderPrefixes = []string{
	"bearer ", "basic ",
	"-----begin private key-----", "-----begin rsa private key-----", "-----begin ec private key-----",
	"-----begin openssh private key-----", "-----begin encrypted private key-----",
}

func credentialClosureCarrierStartOffset(value []byte) (int, bool) {
	for start := 0; start < len(value); {
		// credentialClosureCarrierCanStart accepts leading JSON whitespace so
		// a separator can live in the preceding carrier. Skip each whitespace
		// run once here: calling the trimmer again at every byte would turn one
		// large whitespace scalar into quadratic work.
		for start < len(value) && credentialClosureIsSpace(value[start]) {
			start++
		}
		if start == len(value) {
			break
		}
		if credentialClosureCarrierCanStart(value[start:]) {
			return start, true
		}
		start++
	}
	return 0, false
}

func credentialClosureStrictIntroducerPrefix(value []byte) bool {
	value = credentialClosureTrimLeftSpace(value)
	for _, introducer := range credentialClosureAssignmentNames {
		if len(value) < len(introducer) && credentialClosureEqualFoldASCII(value, []byte(introducer)[:len(value)]) {
			return true
		}
	}
	for _, introducer := range credentialClosureKnownTokenPrefixes {
		if len(value) < len(introducer) && credentialClosureEqualFoldASCII(value, []byte(introducer)[:len(value)]) {
			return true
		}
	}
	if len(value) < 3 && credentialClosureEqualFoldASCII(value, []byte("eyj")[:len(value)]) {
		return true
	}
	for _, introducer := range credentialClosureHeaderPrefixes {
		if len(value) < len(introducer) && credentialClosureEqualFoldASCII(value, []byte(introducer)[:len(value)]) {
			return true
		}
	}
	return false
}

func credentialClosureStartsOrIsPrefix(value, prefix []byte) bool {
	compared := len(value)
	if compared > len(prefix) {
		compared = len(prefix)
	}
	return compared != 0 && credentialClosureEqualFoldASCII(value[:compared], prefix[:compared])
}

func credentialClosureEqualFoldASCII(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index, current := range left {
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		expected := right[index]
		if expected >= 'A' && expected <= 'Z' {
			expected += 'a' - 'A'
		}
		if current != expected {
			return false
		}
	}
	return true
}

func credentialClosureTrimLeftSpace(value []byte) []byte {
	for len(value) != 0 && credentialClosureIsSpace(value[0]) {
		value = value[1:]
	}
	return value
}

func credentialClosureIsSpace(value byte) bool {
	switch value {
	case ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

func credentialClosureTrimLeftHorizontalSpace(value []byte) []byte {
	for len(value) != 0 && (value[0] == ' ' || value[0] == '\t') {
		value = value[1:]
	}
	return value
}

func credentialClosureCrossKindJoinOpen(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	switch value[len(value)-1] {
	case '_', '-', '=', ':', '.', '/', '+', ' ', '\t':
		return true
	default:
		return false
	}
}

func credentialClosureCrossKindJoinStarts(value []byte) bool {
	value = credentialClosureTrimLeftSpace(value)
	if len(value) == 0 {
		return false
	}
	switch value[0] {
	case '_', '-', '=', ':', '.', '/', '+':
		return true
	default:
		return false
	}
}

// orderedJSONScalarByteValues remains a small compatibility surface for
// focused tests and callers. The production scanners consume the callback
// stream directly and never allocate a subsequence reachability matrix.
func orderedJSONScalarByteValues(raw []byte) ([][]byte, error) {
	var values [][]byte
	err := walkOrderedJSONCarriers(raw, func(carrier orderedJSONCarrier) error {
		values = append(values, bytes.Clone(carrier.bytes))
		return nil
	})
	return values, err
}

func rejectReconstructedCredentialMaterial(raw []byte) error {
	for _, order := range []jsonCarrierTraversal{jsonCarrierSourceOrder, jsonCarrierCanonicalObjectOrder} {
		scanner := newCredentialClosureScanner()
		if err := scanner.scanJSONWithOrder(raw, order); err != nil {
			return err
		}
		if err := scanner.finish(); err != nil {
			return err
		}
	}
	return nil
}
