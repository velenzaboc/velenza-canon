package providerplan

import "fmt"

type graphDependencyExpectation struct {
	digest string
	schema stageArtifactIdentity
}

// validateGraphDependencySemanticClosure makes graph_compile the exact
// selection authority for every artifact whose semantics the provider-plan
// verifier consumes. The roster vocabulary comes from the plan-bound generic
// validation profile, never from provider names or stage-contract Go fields.
func validateGraphDependencySemanticClosure(plan *parsedPlan, graph graphPlanSchemaBindingProof, semantic dependencySemanticValidationResolution) error {
	if plan == nil || plan.Manifest == nil || graph.seal != graphPlanSchemaBindingAuthority || semantic.proof.seal != dependencySemanticValidationAuthority {
		return fmt.Errorf("graph dependency closure requires sealed graph and semantic validation proofs")
	}
	expected := make(map[stageMaterialCoordinate]graphDependencyExpectation, len(dependencySemanticRequiredRoles)+1)
	add := func(coordinate stageMaterialCoordinate, digest string, schema stageArtifactIdentity) error {
		if err := validateStageMaterialCoordinate(coordinate); err != nil {
			return err
		}
		if !isLowerSHA256(digest) {
			return fmt.Errorf("graph dependency %s/%s/%s has malformed exact digest", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		if err := validateStageMaterialCoordinate(stageCoordinateForIdentity(schema)); err != nil {
			return fmt.Errorf("graph dependency %s/%s/%s schema: %w", coordinate.Role, coordinate.ID, coordinate.Version, err)
		}
		if !isLowerSHA256(schema.RawSHA256) {
			return fmt.Errorf("graph dependency %s/%s/%s schema has malformed exact digest", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		if _, duplicate := expected[coordinate]; duplicate {
			return fmt.Errorf("graph dependency expectation duplicates %s/%s/%s", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		expected[coordinate] = graphDependencyExpectation{digest: digest, schema: schema}
		return nil
	}

	profile := plan.Manifest.DependencySemanticValidation
	if err := add(
		stageMaterialCoordinate{Role: profile.Profile.Role, ID: profile.Profile.ID, Version: profile.Profile.Version},
		profile.Profile.RawSHA256,
		stageArtifactIdentity{Role: profile.Schema.Role, ID: profile.Schema.ID, Version: profile.Schema.Version, RawSHA256: profile.Schema.RawSHA256},
	); err != nil {
		return err
	}
	for _, role := range dependencySemanticRequiredRoles {
		input, exists := semantic.roleArtifacts[role]
		binding, validated := semantic.proof.byRole[role]
		if !exists || !validated || input.Manifest == nil {
			return fmt.Errorf("graph dependency semantic role %q has no exact artifact/schema authority", role)
		}
		artifactID, idOK := manifestString(input.Manifest, "artifact")
		artifactVersion, versionOK := manifestString(input.Manifest, "artifact_version")
		if !idOK || !versionOK || binding.schemaRole == "" {
			return fmt.Errorf("graph dependency semantic role %q has incomplete artifact or schema coordinates", role)
		}
		if err := add(
			stageMaterialCoordinate{Role: role, ID: artifactID, Version: artifactVersion},
			binding.artifactSHA256,
			stageArtifactIdentity{Role: binding.schemaRole, ID: binding.schemaID, Version: binding.schemaVersion, RawSHA256: binding.schemaSHA256},
		); err != nil {
			return err
		}
	}

	actual := make(map[stageMaterialCoordinate]stageArtifactIdentity, len(graph.dependencyArtifacts))
	for _, dependency := range graph.dependencyArtifacts {
		actual[stageCoordinateForIdentity(dependency)] = dependency
	}
	if err := requireExactSet("graph_compile semantic dependency coordinates", stringCoordinateSet(actual), stringExpectationCoordinateSet(expected)); err != nil {
		return err
	}
	for _, coordinate := range sortedStageMaterialCoordinateKeys(expected) {
		want := expected[coordinate]
		got := actual[coordinate]
		if got.RawSHA256 != want.digest {
			return fmt.Errorf("graph_compile dependency %s/%s/%s digest %s does not equal plan-bound semantic digest %s", coordinate.Role, coordinate.ID, coordinate.Version, got.RawSHA256, want.digest)
		}
		gotSchema, exists := graph.dependencySchemas[coordinate]
		if !exists || gotSchema != want.schema {
			return fmt.Errorf("graph_compile dependency %s/%s/%s target schema does not equal its plan-bound semantic schema", coordinate.Role, coordinate.ID, coordinate.Version)
		}
	}
	return nil
}

func stringCoordinateSet(values map[stageMaterialCoordinate]stageArtifactIdentity) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for coordinate := range values {
		result[lengthPrefixedIdentityKey(coordinate.Role, coordinate.ID, coordinate.Version)] = struct{}{}
	}
	return result
}

func stringExpectationCoordinateSet(values map[stageMaterialCoordinate]graphDependencyExpectation) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for coordinate := range values {
		result[lengthPrefixedIdentityKey(coordinate.Role, coordinate.ID, coordinate.Version)] = struct{}{}
	}
	return result
}
