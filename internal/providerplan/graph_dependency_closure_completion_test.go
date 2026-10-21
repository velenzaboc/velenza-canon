package providerplan

import (
	"strings"
	"testing"
)

// The closure makes graph_compile the exact selection authority for every
// semantic dependency. Each refusal below is a distinct way that authority
// could be lost, so each must fail closed rather than admit an unproven
// artifact or schema coordinate.
func TestValidateGraphDependencySemanticClosureRefusesUnprovenAuthority(t *testing.T) {
	validDigest := sha256Hex([]byte("valid replacement digest"))

	for _, test := range []struct {
		name   string
		mutate func(*parsedPlan, *graphPlanSchemaBindingProof, *dependencySemanticValidationResolution)
		want   string
	}{
		{
			name: "unsealed graph proof",
			mutate: func(_ *parsedPlan, graph *graphPlanSchemaBindingProof, _ *dependencySemanticValidationResolution) {
				graph.seal = nil
			},
			want: "requires sealed graph and semantic validation proofs",
		},
		{
			name: "unsealed semantic proof",
			mutate: func(_ *parsedPlan, _ *graphPlanSchemaBindingProof, semantic *dependencySemanticValidationResolution) {
				semantic.proof.seal = nil
			},
			want: "requires sealed graph and semantic validation proofs",
		},
		{
			name: "profile coordinate is not a stage material coordinate",
			mutate: func(plan *parsedPlan, _ *graphPlanSchemaBindingProof, _ *dependencySemanticValidationResolution) {
				plan.Manifest.DependencySemanticValidation.Profile.Role = ""
			},
			want: "",
		},
		{
			name: "profile digest is not an exact lowercase sha256",
			mutate: func(plan *parsedPlan, _ *graphPlanSchemaBindingProof, _ *dependencySemanticValidationResolution) {
				plan.Manifest.DependencySemanticValidation.Profile.RawSHA256 = "NOT-A-DIGEST"
			},
			want: "malformed exact digest",
		},
		{
			name: "profile schema coordinate is malformed",
			mutate: func(plan *parsedPlan, _ *graphPlanSchemaBindingProof, _ *dependencySemanticValidationResolution) {
				plan.Manifest.DependencySemanticValidation.Schema.Role = ""
			},
			want: "schema",
		},
		{
			name: "profile schema digest is malformed",
			mutate: func(plan *parsedPlan, _ *graphPlanSchemaBindingProof, _ *dependencySemanticValidationResolution) {
				plan.Manifest.DependencySemanticValidation.Schema.RawSHA256 = "not-a-sha256"
			},
			want: "schema has malformed exact digest",
		},
		{
			name: "semantic role has no validated artifact",
			mutate: func(_ *parsedPlan, _ *graphPlanSchemaBindingProof, semantic *dependencySemanticValidationResolution) {
				delete(semantic.roleArtifacts, dependencySemanticRequiredRoles[0])
			},
			want: "no exact artifact/schema authority",
		},
		{
			name: "semantic role artifact carries no manifest",
			mutate: func(_ *parsedPlan, _ *graphPlanSchemaBindingProof, semantic *dependencySemanticValidationResolution) {
				artifact := semantic.roleArtifacts[dependencySemanticRequiredRoles[0]]
				artifact.Manifest = nil
				semantic.roleArtifacts[dependencySemanticRequiredRoles[0]] = artifact
			},
			want: "no exact artifact/schema authority",
		},
		{
			name: "semantic role manifest omits its artifact version",
			mutate: func(_ *parsedPlan, _ *graphPlanSchemaBindingProof, semantic *dependencySemanticValidationResolution) {
				artifact := semantic.roleArtifacts[dependencySemanticRequiredRoles[0]]
				delete(artifact.Manifest, "artifact_version")
				semantic.roleArtifacts[dependencySemanticRequiredRoles[0]] = artifact
			},
			want: "incomplete artifact or schema coordinates",
		},
		{
			name: "semantic role artifact digest is malformed",
			mutate: func(_ *parsedPlan, _ *graphPlanSchemaBindingProof, semantic *dependencySemanticValidationResolution) {
				binding := semantic.proof.byRole[dependencySemanticRequiredRoles[0]]
				binding.artifactSHA256 = "not-a-sha256"
				semantic.proof.byRole[dependencySemanticRequiredRoles[0]] = binding
			},
			want: "malformed exact digest",
		},
		{
			name: "semantic role schema digest is malformed",
			mutate: func(_ *parsedPlan, _ *graphPlanSchemaBindingProof, semantic *dependencySemanticValidationResolution) {
				binding := semantic.proof.byRole[dependencySemanticRequiredRoles[0]]
				binding.schemaSHA256 = "not-a-sha256"
				semantic.proof.byRole[dependencySemanticRequiredRoles[0]] = binding
			},
			want: "schema has malformed exact digest",
		},
		{
			name: "profile duplicates a semantic role coordinate",
			mutate: func(plan *parsedPlan, _ *graphPlanSchemaBindingProof, _ *dependencySemanticValidationResolution) {
				role := dependencySemanticRequiredRoles[0]
				plan.Manifest.DependencySemanticValidation.Profile.Role = role
				plan.Manifest.DependencySemanticValidation.Profile.ID = "fixture_" + role
				plan.Manifest.DependencySemanticValidation.Profile.Version = "1"
				plan.Manifest.DependencySemanticValidation.Profile.RawSHA256 = validDigest
			},
			want: "duplicates",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, graph, semantic := graphDependencySemanticClosureFixture()
			test.mutate(plan, &graph, &semantic)
			err := validateGraphDependencySemanticClosure(plan, graph, semantic)
			if err == nil {
				t.Fatalf("closure admitted %s", test.name)
			}
			if test.want != "" && !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestValidateGraphDependencySemanticClosureRefusesANilPlan(t *testing.T) {
	_, graph, semantic := graphDependencySemanticClosureFixture()
	if err := validateGraphDependencySemanticClosure(nil, graph, semantic); err == nil ||
		!strings.Contains(err.Error(), "requires sealed graph and semantic validation proofs") {
		t.Fatalf("nil plan error = %v, want a sealed-proof refusal", err)
	}

	plan, graph, semantic := graphDependencySemanticClosureFixture()
	plan.Manifest = nil
	if err := validateGraphDependencySemanticClosure(plan, graph, semantic); err == nil ||
		!strings.Contains(err.Error(), "requires sealed graph and semantic validation proofs") {
		t.Fatalf("manifest-free plan error = %v, want a sealed-proof refusal", err)
	}
}
