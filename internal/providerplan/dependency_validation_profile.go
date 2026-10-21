package providerplan

import (
	"bytes"
	"fmt"
	"sort"
)

const (
	dependencySemanticValidationProfileArtifact = "provider_documentation_artifact_validation_profile"
	artifactValidationProfileEnvelopeVersion    = "1"
	dependencySemanticValidationProfileStatus   = "structural_candidate_not_admissible"
	dependencySemanticValidationProfileResult   = "structural_candidate_closed_artifact_schema_bindings"

	dependencySemanticRoleOperationApplicability       = "operation_applicability_profile"
	dependencySemanticRoleAPIGraphApplicability        = "api_graph_applicability_profile"
	dependencySemanticRoleFieldSecurityPolicy          = "field_security_policy"
	dependencySemanticRoleMappingTransitiveRoster      = "mapping_transitive_dependency_roster"
	dependencySemanticRoleDocumentationClaimDerivation = "documentation_claim_derivation_profile"
)

var dependencySemanticRequiredRoles = []string{
	"provider_neutral_compilation_profile",
	"source_contract_index",
	"sample_shape_index",
	"protocol_contract_index",
	"field_mapping_candidate",
	dependencySemanticRoleOperationApplicability,
	dependencySemanticRoleAPIGraphApplicability,
	"surface_family_disposition",
	dependencySemanticRoleFieldSecurityPolicy,
	dependencySemanticRoleMappingTransitiveRoster,
	dependencySemanticRoleDocumentationClaimDerivation,
}

type dependencySemanticArtifactPin struct {
	role   string
	digest string
}

type dependencySemanticValidationPin struct {
	Role      string `json:"role"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	RawSHA256 string `json:"raw_sha256"`
}

type dependencySemanticValidationPlanBinding struct {
	Profile dependencySemanticValidationPin `json:"profile"`
	Schema  dependencySemanticValidationPin `json:"schema"`
}

type dependencySemanticProfileArtifactBinding struct {
	Role              string `json:"role"`
	ArtifactID        string `json:"artifact_id"`
	ArtifactVersion   string `json:"artifact_version"`
	ArtifactRawSHA256 string `json:"artifact_raw_sha256"`
	SchemaRole        string `json:"schema_role"`
	SchemaID          string `json:"schema_id"`
	SchemaVersion     string `json:"schema_version"`
	SchemaRawSHA256   string `json:"schema_raw_sha256"`
}

type dependencySemanticValidationResolution struct {
	proof                     dependencySemanticValidationProof
	derivationTargets         dependencySemanticDerivationTargetSchemaAuthority
	derivationTargetArtifacts map[string]artifactInput
	roleArtifacts             map[string]artifactInput
	usedDependencyHashes      map[string]struct{}
}

type dependencySemanticValidationProfileResolution struct {
	proof                     dependencySemanticValidationProof
	derivationTargets         dependencySemanticDerivationTargetSchemaAuthority
	derivationTargetArtifacts map[string]artifactInput
}

type dependencySemanticDerivationTargetSchemaAuthority struct {
	seal   *dependencySemanticDerivationTargetSchemaAuthoritySeal
	byRole map[string]dependencySemanticDerivationTargetSchema
}

type dependencySemanticDerivationTargetSchemaAuthoritySeal struct{}

type dependencySemanticDerivationTargetSchema struct {
	artifactRole          string
	artifactSHA256        string
	schemaRole            string
	schemaID              string
	schemaVersion         string
	schemaSHA256          string
	schemaBytes           []byte
	discriminatorProperty string
	discriminatorValues   map[string]struct{}
}

type dependencySemanticDerivationTargetResolution struct {
	artifactRole          string
	artifactSHA256        string
	targetRowKind         string
	schemaRole            string
	schemaID              string
	schemaVersion         string
	schemaSHA256          string
	schemaBytes           []byte
	discriminatorProperty string
	discriminatorValues   []string
}

var dependencySemanticDerivationTargetSchemaAuthorityIdentity = &dependencySemanticDerivationTargetSchemaAuthoritySeal{}

type parsedArtifactValidationProfile struct {
	id       string
	version  string
	bindings []dependencySemanticProfileArtifactBinding
}

// parseArtifactValidationProfile is the single interpreter for the generic,
// body-free artifact-validation profile envelope. The profile is first
// validated against the exact plan-pinned envelope schema; only then are the
// generic artifact/schema bindings interpreted. Provider and artifact row
// vocabularies remain entirely inside the target schemas.
func parseArtifactValidationProfile(
	profileInput artifactInput,
	profilePin dependencySemanticValidationPin,
	profileSchemaInput artifactInput,
	profileSchemaPin dependencySemanticValidationPin,
) (parsedArtifactValidationProfile, error) {
	result := parsedArtifactValidationProfile{}
	if sha256Hex(profileInput.Raw) != profilePin.RawSHA256 || (profileInput.SHA256 != "" && profileInput.SHA256 != profilePin.RawSHA256) {
		return result, fmt.Errorf("artifact validation profile digest %s does not bind its exact supplied bytes", profilePin.RawSHA256)
	}
	if sha256Hex(profileSchemaInput.Raw) != profileSchemaPin.RawSHA256 || (profileSchemaInput.SHA256 != "" && profileSchemaInput.SHA256 != profileSchemaPin.RawSHA256) {
		return result, fmt.Errorf("artifact validation profile schema digest %s does not bind its exact supplied bytes", profileSchemaPin.RawSHA256)
	}
	if !profileInput.Structured || profileInput.Manifest == nil {
		return result, fmt.Errorf("artifact validation profile %q is not a structured JSONL artifact", profileInput.Path)
	}
	if profileSchemaInput.Structured {
		return result, fmt.Errorf("artifact validation profile schema %q must be one exact JSON Schema document", profileSchemaInput.Path)
	}
	if err := validateValidationProfileBindings(
		[]validationProfileBinding{{
			Role: profilePin.Role, ArtifactID: profilePin.ID, ArtifactVersion: profilePin.Version,
			ArtifactSHA256: profilePin.RawSHA256, SchemaID: profileSchemaPin.ID,
			SchemaVersion: profileSchemaPin.Version, SchemaSHA256: profileSchemaPin.RawSHA256,
		}},
		[]validationProfileArtifact{{ID: profilePin.ID, Version: profilePin.Version, Bytes: profileInput.Raw}},
		[]validationProfileSchema{{ID: profileSchemaPin.ID, Version: profileSchemaPin.Version, Bytes: profileSchemaInput.Raw}},
	); err != nil {
		return result, fmt.Errorf("plan-bound artifact validation profile: %w", err)
	}

	manifest := profileInput.Manifest
	artifact, artifactOK := manifestString(manifest, "artifact")
	artifactVersion, artifactVersionOK := manifestString(manifest, "artifact_version")
	status, statusOK := manifestString(manifest, "status")
	profileID, profileIDOK := manifestString(manifest, "profile_id")
	profileVersion, profileVersionOK := manifestString(manifest, "profile_version")
	bindingCount, bindingCountOK := manifestInteger(manifest, "binding_count")
	admissionAuthorized, admissionOK := manifestBool(manifest, "canonical_admission_authorized")
	if !artifactOK || artifact != dependencySemanticValidationProfileArtifact || !artifactVersionOK || artifactVersion != artifactValidationProfileEnvelopeVersion || !statusOK || status != dependencySemanticValidationProfileStatus || !profileIDOK || profileID != profilePin.ID || !profileVersionOK || profileVersion != profilePin.Version || !bindingCountOK || bindingCount <= 0 || !admissionOK || admissionAuthorized {
		return result, fmt.Errorf("artifact validation profile manifest does not match its exact candidate identity")
	}

	rows := profileInput.RowsByKind["artifact_schema_binding"]
	if len(rows) != bindingCount {
		return result, fmt.Errorf("artifact validation profile binding_count %d does not equal %d exact binding rows", bindingCount, len(rows))
	}
	roleBindingCounts := make(map[string]int, len(rows))
	artifactCoordinates := make(map[validationProfileCoordinate]string, len(rows))
	schemaCoordinates := make(map[validationProfileCoordinate]string, len(rows))
	for index, row := range rows {
		parsed, err := decodeDependencySemanticProfileBinding(row)
		if err != nil {
			return result, fmt.Errorf("artifact validation profile binding[%d]: %w", index, err)
		}
		roleBindingCounts[parsed.Role]++
		if roleBindingCounts[parsed.Role] > 2 {
			return result, fmt.Errorf("artifact validation profile role %q has more than one semantic projection and one documentation target binding", parsed.Role)
		}
		artifactCoordinate := validationProfileCoordinate{ID: parsed.ArtifactID, Version: parsed.ArtifactVersion}
		if prior, duplicate := artifactCoordinates[artifactCoordinate]; duplicate && prior != parsed.ArtifactRawSHA256 {
			return result, fmt.Errorf("artifact validation profile artifact coordinate %q version %q aliases different exact bytes", parsed.ArtifactID, parsed.ArtifactVersion)
		}
		artifactCoordinates[artifactCoordinate] = parsed.ArtifactRawSHA256
		schemaCoordinate := validationProfileCoordinate{ID: parsed.SchemaID, Version: parsed.SchemaVersion}
		if prior, duplicate := schemaCoordinates[schemaCoordinate]; duplicate && prior != parsed.SchemaRawSHA256 {
			return result, fmt.Errorf("artifact validation profile schema coordinate %q version %q aliases different exact bytes", parsed.SchemaID, parsed.SchemaVersion)
		}
		schemaCoordinates[schemaCoordinate] = parsed.SchemaRawSHA256
		result.bindings = append(result.bindings, parsed)
	}

	summary := profileInput.ValidationSummary
	summaryBindingCount, summaryBindingOK := manifestInteger(summary, "binding_count")
	summaryArtifactCount, summaryArtifactOK := manifestInteger(summary, "artifact_count")
	summarySchemaCount, summarySchemaOK := manifestInteger(summary, "schema_count")
	summaryAdmission, summaryAdmissionOK := manifestBool(summary, "canonical_admission_authorized")
	summaryResult, summaryResultOK := manifestString(summary, "result")
	if summary == nil || !summaryBindingOK || summaryBindingCount != len(result.bindings) || !summaryArtifactOK || summaryArtifactCount != len(artifactCoordinates) || !summarySchemaOK || summarySchemaCount != len(schemaCoordinates) || !summaryAdmissionOK || summaryAdmission || !summaryResultOK || summaryResult != dependencySemanticValidationProfileResult {
		return result, fmt.Errorf("artifact validation profile summary does not close its exact artifact/schema binding roster")
	}
	result.id = profileID
	result.version = profileVersion
	return result, nil
}

// dependencySemanticArtifactPins closes the source-neutral semantic artifact
// roster over exact plan authority. Surface disposition remains owned by the
// field-map artifact. The three field-map dependency references are redundant
// authenticated bindings and therefore must equal their direct plan pins.
func dependencySemanticArtifactPins(plan *parsedPlan, fieldMapping artifactInput) ([]dependencySemanticArtifactPin, error) {
	if plan == nil || plan.Manifest == nil {
		return nil, fmt.Errorf("dependency semantic validation has no parsed plan manifest")
	}
	if fieldMapping.Manifest == nil {
		return nil, fmt.Errorf("dependency semantic field-mapping artifact has no structured manifest")
	}

	pinsByRole := map[string]string{
		dependencySemanticRoleProfile:                      plan.Manifest.ProviderNeutralProfileSHA256,
		dependencySemanticRoleSourceContract:               plan.Manifest.SourceContractIndexSHA256,
		dependencySemanticRoleSampleShape:                  plan.Manifest.SampleShapeIndexSHA256,
		dependencySemanticRoleProtocolContract:             plan.Manifest.ProtocolContractIndexSHA256,
		dependencySemanticRoleFieldMapping:                 plan.Manifest.FieldMappingCandidateSHA256,
		dependencySemanticRoleOperationApplicability:       plan.Manifest.OperationApplicabilityProfileSHA256,
		dependencySemanticRoleAPIGraphApplicability:        plan.Manifest.APIGraphApplicabilityProfileSHA256,
		dependencySemanticRoleFieldSecurityPolicy:          plan.Manifest.FieldSecurityPolicySHA256,
		dependencySemanticRoleMappingTransitiveRoster:      plan.Manifest.MappingTransitiveDependencyRosterSHA256,
		dependencySemanticRoleDocumentationClaimDerivation: plan.Manifest.DocumentationClaimDerivationProfileSHA256,
	}

	surfaceDigest, ok := manifestString(fieldMapping.Manifest, "surface_family_disposition_sha256")
	if !ok {
		return nil, fmt.Errorf("field-mapping artifact %q has no exact surface_family_disposition_sha256 binding", fieldMapping.Path)
	}
	pinsByRole[dependencySemanticRoleSurfaceDisposition] = surfaceDigest

	for _, binding := range []struct {
		role  string
		field string
	}{
		{dependencySemanticRoleFieldSecurityPolicy, "field_security_policy_artifact_sha256"},
		{dependencySemanticRoleMappingTransitiveRoster, "mapping_transitive_dependency_roster_sha256"},
		{dependencySemanticRoleDocumentationClaimDerivation, "documentation_claim_derivation_profile_sha256"},
	} {
		nestedDigest, exists := manifestString(fieldMapping.Manifest, binding.field)
		if !exists {
			return nil, fmt.Errorf("field-mapping artifact %q has no exact %s binding", fieldMapping.Path, binding.field)
		}
		if nestedDigest != pinsByRole[binding.role] {
			return nil, fmt.Errorf("field-mapping artifact %q %s does not equal the direct plan pin for role %q", fieldMapping.Path, binding.field, binding.role)
		}
	}

	if err := requireExactSet("dependency semantic artifact pin roles", stringMapKeysAsSet(pinsByRole), stringSliceSet(dependencySemanticRequiredRoles)); err != nil {
		return nil, err
	}
	pins := make([]dependencySemanticArtifactPin, 0, len(dependencySemanticRequiredRoles))
	digestOwners := make(map[string]string, len(dependencySemanticRequiredRoles))
	for _, role := range dependencySemanticRequiredRoles {
		digest := pinsByRole[role]
		if !isLowerSHA256(digest) {
			return nil, fmt.Errorf("dependency semantic role %q has no lowercase artifact digest", role)
		}
		if priorRole, duplicate := digestOwners[digest]; duplicate {
			return nil, fmt.Errorf("dependency semantic artifact digest %s aliases roles %q and %q", digest, priorRole, role)
		}
		digestOwners[digest] = role
		pins = append(pins, dependencySemanticArtifactPin{role: role, digest: digest})
	}
	return pins, nil
}

// prepareDependencySemanticValidation resolves the exact artifact roster
// whose contents the semantic checker interprets. Every independently owned
// authority comes directly from the plan; only surface disposition is nested
// under field mapping. Artifact vocabulary and row shapes remain profile data.
func prepareDependencySemanticValidation(plan *parsedPlan, dependencies map[string]artifactInput) (dependencySemanticValidationResolution, error) {
	result := dependencySemanticValidationResolution{
		roleArtifacts:        make(map[string]artifactInput, len(dependencySemanticRequiredRoles)),
		usedDependencyHashes: map[string]struct{}{},
	}
	if plan == nil || plan.Manifest == nil {
		return result, fmt.Errorf("dependency semantic validation has no parsed plan manifest")
	}
	artifactDigestOwners := map[string]string{}
	add := func(role, digest string) error {
		if !isLowerSHA256(digest) {
			return fmt.Errorf("dependency semantic role %q has no lowercase artifact digest", role)
		}
		if priorRole, duplicate := artifactDigestOwners[digest]; duplicate {
			return fmt.Errorf("dependency semantic artifact digest %s aliases roles %q and %q", digest, priorRole, role)
		}
		input, ok := dependencies[digest]
		if !ok || sha256Hex(input.Raw) != digest {
			return fmt.Errorf("dependency semantic role %q digest %s is not bound to exact supplied bytes", role, digest)
		}
		if !input.Structured || input.Manifest == nil {
			return fmt.Errorf("dependency semantic role %q resolves to a raw input rather than a structured artifact", role)
		}
		artifactDigestOwners[digest] = role
		result.roleArtifacts[role] = input
		result.usedDependencyHashes[digest] = struct{}{}
		return nil
	}

	fieldMappingDigest := plan.Manifest.FieldMappingCandidateSHA256
	if !isLowerSHA256(fieldMappingDigest) {
		return result, fmt.Errorf("dependency semantic role %q has no lowercase artifact digest", dependencySemanticRoleFieldMapping)
	}
	fieldMapping, ok := dependencies[fieldMappingDigest]
	if !ok || sha256Hex(fieldMapping.Raw) != fieldMappingDigest {
		return result, fmt.Errorf("dependency semantic role %q digest %s is not bound to exact supplied bytes", dependencySemanticRoleFieldMapping, fieldMappingDigest)
	}
	if !fieldMapping.Structured || fieldMapping.Manifest == nil {
		return result, fmt.Errorf("dependency semantic role %q resolves to a raw input rather than a structured artifact", dependencySemanticRoleFieldMapping)
	}
	pins, err := dependencySemanticArtifactPins(plan, fieldMapping)
	if err != nil {
		return result, err
	}
	for _, pin := range pins {
		if err := add(pin.role, pin.digest); err != nil {
			return result, err
		}
	}
	if err := requireExactSet("dependency semantic artifact roles", stringMapKeysAsSet(result.roleArtifacts), stringSliceSet(dependencySemanticRequiredRoles)); err != nil {
		return result, err
	}

	profileResolution, err := resolveDependencySemanticValidationProfileWithTargets(
		plan.Manifest.DependencySemanticValidation,
		dependencies,
		result.roleArtifacts,
		result.usedDependencyHashes,
	)
	if err != nil {
		return result, err
	}
	result.proof = profileResolution.proof
	result.derivationTargets = profileResolution.derivationTargets
	result.derivationTargetArtifacts = profileResolution.derivationTargetArtifacts
	return result, nil
}

// validateDependencySemanticProfiles is the only constructor for the
// in-process proof consumed by semantic dependency checks. The caller must
// supply the complete, exact role/artifact/schema roster selected by the
// plan-bound validation profile. The generic JSON Schema validator owns row
// shapes and artifact versions; this constructor carries no provider or
// artifact-shape vocabulary.
func validateDependencySemanticProfiles(
	bindings []validationProfileBinding,
	artifacts []validationProfileArtifact,
	schemas []validationProfileSchema,
) (dependencySemanticValidationProof, error) {
	if err := validateValidationProfileBindings(bindings, artifacts, schemas); err != nil {
		return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation profile: %w", err)
	}

	byRole := make(map[string]dependencySemanticValidatedArtifact, len(bindings))
	for _, binding := range bindings {
		byRole[binding.Role] = dependencySemanticValidatedArtifact{
			artifactSHA256: binding.ArtifactSHA256,
			schemaID:       binding.SchemaID,
			schemaVersion:  binding.SchemaVersion,
			schemaSHA256:   binding.SchemaSHA256,
		}
	}
	return dependencySemanticValidationProof{
		seal:   dependencySemanticValidationAuthority,
		byRole: byRole,
	}, nil
}

// resolveDependencySemanticDerivationTargetSchemaAuthority retains the exact
// schema-proven discriminator for every validated artifact role. Artifact
// roles, discriminator names, and discriminator values are all derived from
// the plan-selected proof and exact schema bytes; this constructor carries no
// provider, artifact-role, or row-kind vocabulary.
func resolveDependencySemanticDerivationTargetSchemaAuthority(
	proof dependencySemanticValidationProof,
	dependencies map[string]artifactInput,
) (dependencySemanticDerivationTargetSchemaAuthority, error) {
	result := dependencySemanticDerivationTargetSchemaAuthority{}
	if proof.seal != dependencySemanticValidationAuthority || len(proof.byRole) == 0 {
		return result, fmt.Errorf("documentation derivation target authority requires an exact schema-validation proof")
	}

	roles := make([]string, 0, len(proof.byRole))
	for role := range proof.byRole {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	byRole := make(map[string]dependencySemanticDerivationTargetSchema, len(roles))
	for _, role := range roles {
		if !isCanonicalValidationProfileIdentity(role) {
			return result, fmt.Errorf("documentation derivation target artifact role %q is noncanonical", role)
		}
		binding := proof.byRole[role]
		if !isLowerSHA256(binding.artifactSHA256) {
			return result, fmt.Errorf("documentation derivation target role %q has no exact validated artifact digest", role)
		}
		if !isCanonicalValidationProfileIdentity(binding.schemaRole) {
			return result, fmt.Errorf("documentation derivation target role %q has no exact validation-profile schema role", role)
		}
		coordinate, err := newValidationProfileCoordinate("schema", binding.schemaID, binding.schemaVersion)
		if err != nil {
			return result, fmt.Errorf("documentation derivation target role %q: %w", role, err)
		}
		if !isLowerSHA256(binding.schemaSHA256) {
			return result, fmt.Errorf("documentation derivation target role %q has no exact schema digest", role)
		}
		schemaInput, ok := dependencies[binding.schemaSHA256]
		if !ok {
			return result, fmt.Errorf("documentation derivation target role %q schema digest %s is not supplied", role, binding.schemaSHA256)
		}
		if sha256Hex(schemaInput.Raw) != binding.schemaSHA256 || (schemaInput.SHA256 != "" && schemaInput.SHA256 != binding.schemaSHA256) {
			return result, fmt.Errorf("documentation derivation target role %q schema digest %s does not bind its exact supplied bytes", role, binding.schemaSHA256)
		}
		if schemaInput.Structured {
			return result, fmt.Errorf("documentation derivation target role %q schema %q must be one exact JSON Schema document", role, schemaInput.Path)
		}
		var targetSchemaObject map[string]interface{}
		if err := decodeOneValidationProfileJSON(schemaInput.Raw, &targetSchemaObject); err != nil {
			return result, fmt.Errorf("documentation derivation target role %q schema: decode exact JSON Schema: %w", role, err)
		}
		if err := validateDocumentationMaterializerSchemaDialect(targetSchemaObject); err != nil {
			return result, fmt.Errorf("documentation derivation target role %q schema uses a dialect outside the exact materializer subset: %w", role, err)
		}
		_, discriminator, err := resolveValidationProfileSchema(schemaInput.Raw, coordinate)
		if err != nil {
			return result, fmt.Errorf("documentation derivation target role %q schema: %w", role, err)
		}
		if !isCanonicalValidationProfileIdentity(discriminator.property) || len(discriminator.values) == 0 {
			return result, fmt.Errorf("documentation derivation target role %q schema has no finite required discriminator proof", role)
		}
		values := make(map[string]struct{}, len(discriminator.values))
		for _, value := range sortedProviderStringMapKeys(discriminator.values) {
			if !isCanonicalValidationProfileIdentity(value) {
				return result, fmt.Errorf("documentation derivation target role %q schema discriminator %q contains noncanonical value %q", role, discriminator.property, value)
			}
			values[value] = struct{}{}
		}
		byRole[role] = dependencySemanticDerivationTargetSchema{
			artifactRole: role, artifactSHA256: binding.artifactSHA256, schemaRole: binding.schemaRole,
			schemaID: coordinate.ID, schemaVersion: coordinate.Version, schemaSHA256: binding.schemaSHA256,
			schemaBytes: bytes.Clone(schemaInput.Raw), discriminatorProperty: discriminator.property, discriminatorValues: values,
		}
	}
	result.seal = dependencySemanticDerivationTargetSchemaAuthorityIdentity
	result.byRole = byRole
	return result, nil
}

// validateDocumentationMaterializerSchemaDialect prevents the generic JSON
// Schema validator and the target-member materializer from assigning different
// meaning to the same exact schema bytes. This is deliberately a closed subset
// until one shared full-dialect schema descriptor owns both validation and
// materialization traversal.
func validateDocumentationMaterializerSchemaDialect(root map[string]interface{}) error {
	if root == nil {
		return fmt.Errorf("schema root is not an object")
	}
	var walk func(interface{}, string, bool) error
	walk = func(node interface{}, path string, rootNode bool) error {
		switch typed := node.(type) {
		case bool:
			return nil
		case map[string]interface{}:
			for _, keyword := range []string{
				"$dynamicRef", "$dynamicAnchor", "$anchor", "$recursiveRef", "$recursiveAnchor",
				"allOf", "anyOf", "if", "then", "else", "not",
				"dependentSchemas", "contains", "prefixItems", "unevaluatedItems",
				"contentSchema", "patternProperties", "propertyNames",
			} {
				if _, present := typed[keyword]; present {
					return fmt.Errorf("unsupported applicator %q at %s", keyword, path)
				}
			}
			if rawRef, present := typed["$ref"]; present {
				ref, ok := rawRef.(string)
				if !ok {
					return fmt.Errorf("$ref at %s is not a string", path)
				}
				if len(typed) != 1 {
					return fmt.Errorf("$ref at %s has siblings the materializer cannot compose exactly", path)
				}
				if _, _, err := resolveValidationProfileLocalJSONPointer(root, ref); err != nil {
					return fmt.Errorf("$ref at %s is not a simple local JSON Pointer: %w", path, err)
				}
				if ref == "#" {
					return fmt.Errorf("$ref at %s forms an unsupported root-reference cycle", path)
				}
				return nil
			}
			if branches, present := typed["oneOf"]; present {
				if !rootNode {
					return fmt.Errorf("oneOf at %s is composed below the root row-variant union", path)
				}
				allowedRootSiblings := map[string]struct{}{
					"$schema": {}, "$id": {}, "$defs": {}, "definitions": {}, "oneOf": {},
					"title": {}, "description": {}, "$comment": {},
				}
				for _, keyword := range sortedProviderStringMapKeys(typed) {
					if _, allowed := allowedRootSiblings[keyword]; !allowed {
						return fmt.Errorf("root oneOf at %s has unsupported sibling %q", path, keyword)
					}
				}
				list, ok := branches.([]interface{})
				if !ok || len(list) == 0 {
					return fmt.Errorf("oneOf at %s is empty or malformed", path)
				}
				for index, branch := range list {
					if err := walk(branch, fmt.Sprintf("%s/oneOf/%d", path, index), false); err != nil {
						return err
					}
				}
			}
			if rawType, present := typed["type"]; present {
				if _, ok := rawType.(string); !ok {
					return fmt.Errorf("type at %s is composed rather than one exact materializer type", path)
				}
			}
			for _, keyword := range []string{"additionalProperties", "unevaluatedProperties"} {
				if value, present := typed[keyword]; present {
					if _, ok := value.(bool); !ok {
						return fmt.Errorf("%s at %s is schema-valued and cannot be interpreted exactly by the materializer", keyword, path)
					}
				}
			}
			if items, present := typed["items"]; present {
				if _, composed := items.([]interface{}); composed {
					return fmt.Errorf("items at %s is composed", path)
				}
				if err := walk(items, path+"/items", false); err != nil {
					return err
				}
			}
			for _, keyword := range []string{"properties", "$defs", "definitions"} {
				children, present := typed[keyword]
				if !present {
					continue
				}
				object, ok := children.(map[string]interface{})
				if !ok {
					return fmt.Errorf("%s at %s is malformed", keyword, path)
				}
				keys := make([]string, 0, len(object))
				for key := range object {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					if err := walk(object[key], path+"/"+keyword+"/"+escapeValidationProfileJSONPointerToken(key), false); err != nil {
						return err
					}
				}
			}
			return nil
		default:
			return fmt.Errorf("schema node at %s is neither an object nor boolean", path)
		}
	}
	return walk(root, "$", true)
}

// validateDocumentationDerivationTarget resolves one rule target through the
// exact artifact role and its schema-owned finite row_kind roster. The
// row_kind property is part of the documentation-derivation rule contract;
// the accepted artifact roles and row-kind values remain entirely data-driven.
func (authority dependencySemanticDerivationTargetSchemaAuthority) validateDocumentationDerivationTarget(
	targetArtifactRole string,
	targetRowKind string,
) (dependencySemanticDerivationTargetResolution, error) {
	result := dependencySemanticDerivationTargetResolution{}
	if authority.seal != dependencySemanticDerivationTargetSchemaAuthorityIdentity || len(authority.byRole) == 0 {
		return result, fmt.Errorf("documentation derivation target schema authority is absent or unsealed")
	}
	if !isCanonicalValidationProfileIdentity(targetArtifactRole) {
		return result, fmt.Errorf("documentation derivation target artifact role %q is noncanonical", targetArtifactRole)
	}
	if !isCanonicalValidationProfileIdentity(targetRowKind) {
		return result, fmt.Errorf("documentation derivation target row kind %q is noncanonical", targetRowKind)
	}
	resolved, ok := authority.byRole[targetArtifactRole]
	if !ok {
		return result, fmt.Errorf("documentation derivation target artifact role %q is not present in the exact schema-validation proof", targetArtifactRole)
	}
	if resolved.discriminatorProperty != "row_kind" {
		return result, fmt.Errorf("documentation derivation target artifact role %q schema proves discriminator %q rather than required row_kind", targetArtifactRole, resolved.discriminatorProperty)
	}
	if _, ok := resolved.discriminatorValues[targetRowKind]; !ok {
		return result, fmt.Errorf("documentation derivation target row kind %q is outside artifact role %q schema-proven finite row_kind roster", targetRowKind, targetArtifactRole)
	}
	values := make([]string, 0, len(resolved.discriminatorValues))
	for value := range resolved.discriminatorValues {
		values = append(values, value)
	}
	sort.Strings(values)
	return dependencySemanticDerivationTargetResolution{
		artifactRole: resolved.artifactRole, artifactSHA256: resolved.artifactSHA256, targetRowKind: targetRowKind,
		schemaRole: resolved.schemaRole, schemaID: resolved.schemaID,
		schemaVersion: resolved.schemaVersion, schemaSHA256: resolved.schemaSHA256,
		schemaBytes: bytes.Clone(resolved.schemaBytes), discriminatorProperty: resolved.discriminatorProperty, discriminatorValues: values,
	}, nil
}

// resolveDependencySemanticValidationProfile validates the plan-bound
// validation profile against its own exact schema, resolves every artifact
// and target schema by digest, then returns the sealed semantic proof. All
// exact structured-artifact shapes remain in the supplied JSON Schemas.
func resolveDependencySemanticValidationProfile(
	binding dependencySemanticValidationPlanBinding,
	dependencies map[string]artifactInput,
	roleArtifacts map[string]artifactInput,
	usedDependencyHashes map[string]struct{},
) (dependencySemanticValidationProof, error) {
	if err := validateDependencySemanticValidationPin("profile", binding.Profile, "dependency_semantic_validation_profile"); err != nil {
		return dependencySemanticValidationProof{}, err
	}
	if err := validateDependencySemanticValidationPin("profile schema", binding.Schema, "dependency_semantic_validation_profile_schema"); err != nil {
		return dependencySemanticValidationProof{}, err
	}
	if binding.Profile.RawSHA256 == binding.Schema.RawSHA256 {
		return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation profile aliases its schema digest")
	}

	profileInput, ok := dependencies[binding.Profile.RawSHA256]
	if !ok || sha256Hex(profileInput.Raw) != binding.Profile.RawSHA256 {
		return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation profile digest %s is not bound to exact supplied bytes", binding.Profile.RawSHA256)
	}
	profileSchemaInput, ok := dependencies[binding.Schema.RawSHA256]
	if !ok || sha256Hex(profileSchemaInput.Raw) != binding.Schema.RawSHA256 {
		return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation profile schema digest %s is not bound to exact supplied bytes", binding.Schema.RawSHA256)
	}
	if !profileInput.Structured || profileInput.Manifest == nil {
		return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation profile %q is not a structured JSONL artifact", profileInput.Path)
	}
	if profileSchemaInput.Structured {
		return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation profile schema %q must be one exact JSON Schema document", profileSchemaInput.Path)
	}
	for _, role := range sortedProviderStringMapKeys(roleArtifacts) {
		input := roleArtifacts[role]
		digest := sha256Hex(input.Raw)
		if digest == binding.Profile.RawSHA256 || digest == binding.Schema.RawSHA256 {
			return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic role %q aliases the validation profile or its schema digest", role)
		}
	}

	parsedProfile, err := parseArtifactValidationProfile(profileInput, binding.Profile, profileSchemaInput, binding.Schema)
	if err != nil {
		return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation profile: %w", err)
	}
	bindings := make([]validationProfileBinding, 0, len(parsedProfile.bindings))
	artifacts := make([]validationProfileArtifact, 0, len(parsedProfile.bindings))
	schemasByCoordinate := map[validationProfileCoordinate]validationProfileSchema{}
	roles := make(map[string]struct{}, len(parsedProfile.bindings))
	for _, parsed := range parsedProfile.bindings {
		input, exists := roleArtifacts[parsed.Role]
		if !exists {
			return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation profile binds unexpected role %q", parsed.Role)
		}
		if parsed.ArtifactRawSHA256 != sha256Hex(input.Raw) {
			// A second binding for the same logical role may name the distinct,
			// closed documentation-materialization target. It is validated and
			// consumed by resolveDependencySemanticValidationProfileWithTargets;
			// this pass mints only the enriched semantic projection proof.
			continue
		}
		if _, duplicate := roles[parsed.Role]; duplicate {
			return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation role %q has more than one binding to its exact semantic projection bytes", parsed.Role)
		}
		roles[parsed.Role] = struct{}{}
		manifestArtifact, manifestArtifactOK := manifestString(input.Manifest, "artifact")
		manifestVersion, manifestVersionOK := manifestString(input.Manifest, "artifact_version")
		if !input.Structured || input.Manifest == nil || !manifestArtifactOK || manifestArtifact != parsed.ArtifactID || !manifestVersionOK || manifestVersion != parsed.ArtifactVersion {
			return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation role %q artifact identity does not equal its structured manifest identity", parsed.Role)
		}

		schemaInput, exists := dependencies[parsed.SchemaRawSHA256]
		if !exists || sha256Hex(schemaInput.Raw) != parsed.SchemaRawSHA256 {
			return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation role %q schema digest %s is not bound to exact supplied bytes", parsed.Role, parsed.SchemaRawSHA256)
		}
		if schemaInput.Structured {
			return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation role %q schema %q must be one exact JSON Schema document", parsed.Role, schemaInput.Path)
		}
		schemaCoordinate := validationProfileCoordinate{ID: parsed.SchemaID, Version: parsed.SchemaVersion}
		if prior, duplicate := schemasByCoordinate[schemaCoordinate]; duplicate {
			if validationProfileSHA256(prior.Bytes) != parsed.SchemaRawSHA256 {
				return dependencySemanticValidationProof{}, fmt.Errorf("dependency semantic validation schema coordinate %q version %q aliases different exact bytes", parsed.SchemaID, parsed.SchemaVersion)
			}
		} else {
			schemasByCoordinate[schemaCoordinate] = validationProfileSchema{ID: parsed.SchemaID, Version: parsed.SchemaVersion, Bytes: schemaInput.Raw}
		}

		bindings = append(bindings, validationProfileBinding{
			Role: parsed.Role, ArtifactID: parsed.ArtifactID, ArtifactVersion: parsed.ArtifactVersion,
			ArtifactSHA256: parsed.ArtifactRawSHA256, SchemaID: parsed.SchemaID,
			SchemaVersion: parsed.SchemaVersion, SchemaSHA256: parsed.SchemaRawSHA256,
		})
		artifacts = append(artifacts, validationProfileArtifact{ID: parsed.ArtifactID, Version: parsed.ArtifactVersion, Bytes: input.Raw})
		usedDependencyHashes[parsed.SchemaRawSHA256] = struct{}{}
	}
	if err := requireExactSet("dependency semantic validation profile roles", roles, stringSliceSet(dependencySemanticRequiredRoles)); err != nil {
		return dependencySemanticValidationProof{}, err
	}

	schemaCoordinates := make([]validationProfileCoordinate, 0, len(schemasByCoordinate))
	for coordinate := range schemasByCoordinate {
		schemaCoordinates = append(schemaCoordinates, coordinate)
	}
	sort.Slice(schemaCoordinates, func(i, j int) bool {
		if schemaCoordinates[i].ID != schemaCoordinates[j].ID {
			return schemaCoordinates[i].ID < schemaCoordinates[j].ID
		}
		return schemaCoordinates[i].Version < schemaCoordinates[j].Version
	})
	schemas := make([]validationProfileSchema, 0, len(schemaCoordinates))
	for _, coordinate := range schemaCoordinates {
		schemas = append(schemas, schemasByCoordinate[coordinate])
	}
	proof, err := validateDependencySemanticProfiles(bindings, artifacts, schemas)
	if err != nil {
		return dependencySemanticValidationProof{}, err
	}
	for _, parsed := range parsedProfile.bindings {
		validated, exists := proof.byRole[parsed.Role]
		if !exists || validated.artifactSHA256 != parsed.ArtifactRawSHA256 {
			continue
		}
		validated.schemaRole = parsed.SchemaRole
		proof.byRole[parsed.Role] = validated
	}

	usedDependencyHashes[binding.Profile.RawSHA256] = struct{}{}
	usedDependencyHashes[binding.Schema.RawSHA256] = struct{}{}
	return proof, nil
}

// resolveDependencySemanticValidationProfileWithTargets keeps the enriched
// compiler projections and the exact documentation materialization targets as
// two separately digest-bound artifact maps. Both use the existing logical
// role and artifact_schema_binding vocabulary. The semantic binding is the
// unique binding whose digest equals the plan-pinned role artifact; a second
// binding for that role is therefore unambiguously the closed target bytes.
func resolveDependencySemanticValidationProfileWithTargets(
	binding dependencySemanticValidationPlanBinding,
	dependencies map[string]artifactInput,
	roleArtifacts map[string]artifactInput,
	usedDependencyHashes map[string]struct{},
) (dependencySemanticValidationProfileResolution, error) {
	result := dependencySemanticValidationProfileResolution{}
	proof, err := resolveDependencySemanticValidationProfile(binding, dependencies, roleArtifacts, usedDependencyHashes)
	if err != nil {
		return result, err
	}
	result.proof = proof

	profileInput := dependencies[binding.Profile.RawSHA256]
	profileSchemaInput := dependencies[binding.Schema.RawSHA256]
	parsedProfile, err := parseArtifactValidationProfile(profileInput, binding.Profile, profileSchemaInput, binding.Schema)
	if err != nil {
		return result, fmt.Errorf("dependency semantic validation profile target resolution: %w", err)
	}
	targetBindings := make([]validationProfileBinding, 0)
	targetArtifacts := make([]validationProfileArtifact, 0)
	targetArtifactsByRole := map[string]artifactInput{}
	targetSchemasByCoordinate := map[validationProfileCoordinate]validationProfileSchema{}
	targetParsedByRole := map[string]dependencySemanticProfileArtifactBinding{}
	semanticDigests := map[string]string{}
	semanticArtifactDigestsByCoordinate := map[validationProfileCoordinate]string{}
	semanticSchemaDigestsByCoordinate := map[validationProfileCoordinate]string{}
	targetArtifactDigestsByCoordinate := map[validationProfileCoordinate]string{}
	for _, role := range sortedProviderStringMapKeys(roleArtifacts) {
		semanticDigests[sha256Hex(roleArtifacts[role].Raw)] = role
	}
	for _, parsed := range parsedProfile.bindings {
		semantic, expectedRole := roleArtifacts[parsed.Role]
		if !expectedRole {
			return result, fmt.Errorf("dependency semantic validation profile target binding has unexpected role %q", parsed.Role)
		}
		if parsed.ArtifactRawSHA256 != sha256Hex(semantic.Raw) {
			continue
		}
		artifactCoordinate := validationProfileCoordinate{ID: parsed.ArtifactID, Version: parsed.ArtifactVersion}
		if prior, duplicate := semanticArtifactDigestsByCoordinate[artifactCoordinate]; duplicate && prior != parsed.ArtifactRawSHA256 {
			return result, fmt.Errorf("dependency semantic artifact coordinate %q version %q aliases different exact bytes", parsed.ArtifactID, parsed.ArtifactVersion)
		}
		semanticArtifactDigestsByCoordinate[artifactCoordinate] = parsed.ArtifactRawSHA256
		schemaCoordinate := validationProfileCoordinate{ID: parsed.SchemaID, Version: parsed.SchemaVersion}
		if prior, duplicate := semanticSchemaDigestsByCoordinate[schemaCoordinate]; duplicate && prior != parsed.SchemaRawSHA256 {
			return result, fmt.Errorf("dependency semantic schema coordinate %q version %q aliases different exact bytes", parsed.SchemaID, parsed.SchemaVersion)
		}
		semanticSchemaDigestsByCoordinate[schemaCoordinate] = parsed.SchemaRawSHA256
	}
	for _, parsed := range parsedProfile.bindings {
		semantic, expectedRole := roleArtifacts[parsed.Role]
		if !expectedRole {
			return result, fmt.Errorf("dependency semantic validation profile target binding has unexpected role %q", parsed.Role)
		}
		if parsed.ArtifactRawSHA256 == sha256Hex(semantic.Raw) {
			continue
		}
		if priorRole, aliasesSemantic := semanticDigests[parsed.ArtifactRawSHA256]; aliasesSemantic {
			return result, fmt.Errorf("documentation target role %q aliases semantic projection role %q exact bytes", parsed.Role, priorRole)
		}
		if _, duplicate := targetArtifactsByRole[parsed.Role]; duplicate {
			return result, fmt.Errorf("documentation target role %q has more than one distinct target artifact binding", parsed.Role)
		}
		artifactCoordinate := validationProfileCoordinate{ID: parsed.ArtifactID, Version: parsed.ArtifactVersion}
		if prior, aliasesSemanticCoordinate := semanticArtifactDigestsByCoordinate[artifactCoordinate]; aliasesSemanticCoordinate && prior != parsed.ArtifactRawSHA256 {
			return result, fmt.Errorf("documentation target artifact coordinate %q version %q aliases semantic projection with different exact bytes", parsed.ArtifactID, parsed.ArtifactVersion)
		}
		if prior, duplicate := targetArtifactDigestsByCoordinate[artifactCoordinate]; duplicate && prior != parsed.ArtifactRawSHA256 {
			return result, fmt.Errorf("documentation target artifact coordinate %q version %q aliases different exact bytes", parsed.ArtifactID, parsed.ArtifactVersion)
		}
		targetArtifactDigestsByCoordinate[artifactCoordinate] = parsed.ArtifactRawSHA256
		input, exists := dependencies[parsed.ArtifactRawSHA256]
		if !exists || sha256Hex(input.Raw) != parsed.ArtifactRawSHA256 || (input.SHA256 != "" && input.SHA256 != parsed.ArtifactRawSHA256) {
			return result, fmt.Errorf("documentation target role %q digest %s is not bound to exact supplied bytes", parsed.Role, parsed.ArtifactRawSHA256)
		}
		manifestArtifact, artifactOK := manifestString(input.Manifest, "artifact")
		manifestVersion, versionOK := manifestString(input.Manifest, "artifact_version")
		if !input.Structured || input.Manifest == nil || !artifactOK || manifestArtifact != parsed.ArtifactID || !versionOK || manifestVersion != parsed.ArtifactVersion {
			return result, fmt.Errorf("documentation target role %q artifact identity does not equal its structured manifest identity", parsed.Role)
		}
		schemaInput, exists := dependencies[parsed.SchemaRawSHA256]
		if !exists || sha256Hex(schemaInput.Raw) != parsed.SchemaRawSHA256 || (schemaInput.SHA256 != "" && schemaInput.SHA256 != parsed.SchemaRawSHA256) {
			return result, fmt.Errorf("documentation target role %q schema digest %s is not bound to exact supplied bytes", parsed.Role, parsed.SchemaRawSHA256)
		}
		if schemaInput.Structured {
			return result, fmt.Errorf("documentation target role %q schema %q must be one exact JSON Schema document", parsed.Role, schemaInput.Path)
		}
		targetBinding := validationProfileBinding{
			Role: parsed.Role, ArtifactID: parsed.ArtifactID, ArtifactVersion: parsed.ArtifactVersion,
			ArtifactSHA256: parsed.ArtifactRawSHA256, SchemaID: parsed.SchemaID,
			SchemaVersion: parsed.SchemaVersion, SchemaSHA256: parsed.SchemaRawSHA256,
		}
		targetBindings = append(targetBindings, targetBinding)
		targetArtifacts = append(targetArtifacts, validationProfileArtifact{ID: parsed.ArtifactID, Version: parsed.ArtifactVersion, Bytes: input.Raw})
		coordinate := validationProfileCoordinate{ID: parsed.SchemaID, Version: parsed.SchemaVersion}
		if prior, aliasesSemanticCoordinate := semanticSchemaDigestsByCoordinate[coordinate]; aliasesSemanticCoordinate && prior != parsed.SchemaRawSHA256 {
			return result, fmt.Errorf("documentation target schema coordinate %q version %q aliases semantic projection with different exact bytes", parsed.SchemaID, parsed.SchemaVersion)
		}
		if prior, duplicate := targetSchemasByCoordinate[coordinate]; duplicate && validationProfileSHA256(prior.Bytes) != parsed.SchemaRawSHA256 {
			return result, fmt.Errorf("documentation target schema coordinate %q version %q aliases different exact bytes", parsed.SchemaID, parsed.SchemaVersion)
		}
		targetSchemasByCoordinate[coordinate] = validationProfileSchema{ID: parsed.SchemaID, Version: parsed.SchemaVersion, Bytes: schemaInput.Raw}
		targetArtifactsByRole[parsed.Role] = input
		targetParsedByRole[parsed.Role] = parsed
		usedDependencyHashes[parsed.ArtifactRawSHA256] = struct{}{}
		usedDependencyHashes[parsed.SchemaRawSHA256] = struct{}{}
	}

	if len(targetBindings) == 0 {
		return result, fmt.Errorf("dependency semantic validation profile has no distinct exact documentation target artifact bindings")
	}
	targetSchemaCoordinates := make([]validationProfileCoordinate, 0, len(targetSchemasByCoordinate))
	for coordinate := range targetSchemasByCoordinate {
		targetSchemaCoordinates = append(targetSchemaCoordinates, coordinate)
	}
	sort.Slice(targetSchemaCoordinates, func(i, j int) bool {
		if targetSchemaCoordinates[i].ID != targetSchemaCoordinates[j].ID {
			return targetSchemaCoordinates[i].ID < targetSchemaCoordinates[j].ID
		}
		return targetSchemaCoordinates[i].Version < targetSchemaCoordinates[j].Version
	})
	targetSchemas := make([]validationProfileSchema, 0, len(targetSchemaCoordinates))
	for _, coordinate := range targetSchemaCoordinates {
		targetSchemas = append(targetSchemas, targetSchemasByCoordinate[coordinate])
	}
	targetProof, err := validateDependencySemanticProfiles(targetBindings, targetArtifacts, targetSchemas)
	if err != nil {
		return result, fmt.Errorf("documentation target validation profile: %w", err)
	}
	for _, role := range sortedProviderStringMapKeys(targetParsedByRole) {
		validated := targetProof.byRole[role]
		validated.schemaRole = targetParsedByRole[role].SchemaRole
		targetProof.byRole[role] = validated
	}
	result.derivationTargets, err = resolveDependencySemanticDerivationTargetSchemaAuthority(targetProof, dependencies)
	if err != nil {
		return result, err
	}
	result.derivationTargetArtifacts = targetArtifactsByRole
	return result, nil
}

func validateDependencySemanticValidationPin(label string, pin dependencySemanticValidationPin, expectedRole string) error {
	if pin.Role != expectedRole {
		return fmt.Errorf("dependency semantic validation %s role %q does not equal %q", label, pin.Role, expectedRole)
	}
	if _, err := newValidationProfileCoordinate(label, pin.ID, pin.Version); err != nil {
		return fmt.Errorf("dependency semantic validation %s: %w", label, err)
	}
	if !isLowerSHA256(pin.RawSHA256) {
		return fmt.Errorf("dependency semantic validation %s raw_sha256 %q is malformed", label, pin.RawSHA256)
	}
	return nil
}

func decodeDependencySemanticProfileBinding(row map[string]interface{}) (dependencySemanticProfileArtifactBinding, error) {
	read := func(key string) (string, error) {
		value, ok := manifestString(row, key)
		if !ok || !isCanonicalValidationProfileIdentity(value) {
			return "", fmt.Errorf("%s is absent or noncanonical", key)
		}
		return value, nil
	}
	var result dependencySemanticProfileArtifactBinding
	var err error
	if result.Role, err = read("role"); err != nil {
		return result, err
	}
	if result.ArtifactID, err = read("artifact_id"); err != nil {
		return result, err
	}
	if result.ArtifactVersion, err = read("artifact_version"); err != nil {
		return result, err
	}
	if result.ArtifactRawSHA256, err = read("artifact_raw_sha256"); err != nil || !isLowerSHA256(result.ArtifactRawSHA256) {
		return result, fmt.Errorf("artifact_raw_sha256 is absent or malformed")
	}
	if result.SchemaRole, err = read("schema_role"); err != nil {
		return result, err
	}
	if result.SchemaID, err = read("schema_id"); err != nil {
		return result, err
	}
	if result.SchemaVersion, err = read("schema_version"); err != nil {
		return result, err
	}
	if result.SchemaRawSHA256, err = read("schema_raw_sha256"); err != nil || !isLowerSHA256(result.SchemaRawSHA256) {
		return result, fmt.Errorf("schema_raw_sha256 is absent or malformed")
	}
	return result, nil
}
