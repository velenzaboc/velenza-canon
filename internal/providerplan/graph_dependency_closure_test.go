package providerplan

import (
	"strings"
	"testing"
)

func TestValidateGraphDependencySemanticClosureExactRosterAndSchemas(t *testing.T) {
	plan, graph, semantic := graphDependencySemanticClosureFixture()
	if err := validateGraphDependencySemanticClosure(plan, graph, semantic); err != nil {
		t.Fatalf("exact graph semantic closure was rejected: %v", err)
	}
}

func TestValidateGraphDependencySemanticClosureFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*parsedPlan, *graphPlanSchemaBindingProof, *dependencySemanticValidationResolution)
		want   string
	}{
		{
			name: "missing target",
			mutate: func(_ *parsedPlan, graph *graphPlanSchemaBindingProof, _ *dependencySemanticValidationResolution) {
				graph.dependencyArtifacts = graph.dependencyArtifacts[:len(graph.dependencyArtifacts)-1]
			},
			want: "coordinates",
		},
		{
			name: "orphan target",
			mutate: func(_ *parsedPlan, graph *graphPlanSchemaBindingProof, _ *dependencySemanticValidationResolution) {
				graph.dependencyArtifacts = append(graph.dependencyArtifacts, stageArtifactIdentity{Role: "orphan_role", ID: "orphan_artifact", Version: "1", RawSHA256: sha256Hex([]byte("orphan"))})
			},
			want: "coordinates",
		},
		{
			name: "artifact digest substitution",
			mutate: func(_ *parsedPlan, graph *graphPlanSchemaBindingProof, _ *dependencySemanticValidationResolution) {
				graph.dependencyArtifacts[0].RawSHA256 = sha256Hex([]byte("substitute artifact"))
			},
			want: "does not equal plan-bound semantic digest",
		},
		{
			name: "schema coordinate substitution",
			mutate: func(_ *parsedPlan, graph *graphPlanSchemaBindingProof, _ *dependencySemanticValidationResolution) {
				coordinate := stageCoordinateForIdentity(graph.dependencyArtifacts[0])
				schema := graph.dependencySchemas[coordinate]
				schema.ID += "-substitute"
				graph.dependencySchemas[coordinate] = schema
			},
			want: "target schema does not equal",
		},
		{
			name: "schema digest substitution",
			mutate: func(_ *parsedPlan, graph *graphPlanSchemaBindingProof, _ *dependencySemanticValidationResolution) {
				coordinate := stageCoordinateForIdentity(graph.dependencyArtifacts[0])
				schema := graph.dependencySchemas[coordinate]
				schema.RawSHA256 = sha256Hex([]byte("substitute schema"))
				graph.dependencySchemas[coordinate] = schema
			},
			want: "target schema does not equal",
		},
		{
			name: "semantic proof loses schema role",
			mutate: func(_ *parsedPlan, _ *graphPlanSchemaBindingProof, semantic *dependencySemanticValidationResolution) {
				binding := semantic.proof.byRole[dependencySemanticRequiredRoles[0]]
				binding.schemaRole = ""
				semantic.proof.byRole[dependencySemanticRequiredRoles[0]] = binding
			},
			want: "incomplete artifact or schema coordinates",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, graph, semantic := graphDependencySemanticClosureFixture()
			test.mutate(plan, &graph, &semantic)
			err := validateGraphDependencySemanticClosure(plan, graph, semantic)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q refusal", err, test.want)
			}
		})
	}
}

func TestGraphPlanParseProofClosesSealsDigestsAndReturnsDefensiveSets(t *testing.T) {
	raw := []byte(`{"row_kind":"fixture"}`)
	digest := sha256Hex(raw)
	structural := graphPlanSchemaBindingProof{
		seal:              graphPlanSchemaBindingAuthority,
		plan:              stageArtifactIdentity{RawSHA256: digest},
		setKindsByRowKind: map[string][]string{"fixture": {"symbols", "relationships"}},
	}
	receipt := StageReceiptReference{StageKind: stageGraphCompile, ReceiptSHA256: strings.Repeat("a", 64), OutputRootSHA256: strings.Repeat("b", 64)}
	proof, err := newGraphPlanParseProof(structural, strings.Repeat("c", 64), receipt)
	if err != nil || requireGraphPlanParseProof(proof, raw) != nil {
		t.Fatalf("sealed proof rejected: %v", err)
	}
	kinds, ok := graphPlanSetKinds(proof, "fixture")
	if !ok || len(kinds) != 2 {
		t.Fatalf("set kinds = %v, %v", kinds, ok)
	}
	kinds[0] = "mutated"
	if again, _ := graphPlanSetKinds(proof, "fixture"); again[0] != "symbols" {
		t.Fatal("graph plan set kinds leaked mutable proof storage")
	}
	if err := requireGraphPlanParseProof(proof, []byte(`{"row_kind":"other"}`)); err == nil {
		t.Fatal("proof accepted changed graph-plan bytes")
	}
}

func TestScanGraphPlanRowKindsRejectsAmbiguousOrMissingRows(t *testing.T) {
	if _, err := scanGraphPlanRowKinds([]byte("\n")); err == nil {
		t.Fatal("empty graph plan accepted")
	}
	if _, err := scanGraphPlanRowKinds([]byte(`{"row_kind":"x","row_kind":"x"}`)); err == nil {
		t.Fatal("duplicate graph-plan row key accepted")
	}
	if _, err := scanGraphPlanRowKinds([]byte(`{}`)); err == nil {
		t.Fatal("missing graph row kind accepted")
	}
}

func graphDependencySemanticClosureFixture() (*parsedPlan, graphPlanSchemaBindingProof, dependencySemanticValidationResolution) {
	profileRaw := []byte("fixture semantic validation profile")
	profileDigest := sha256Hex(profileRaw)
	profileSchemaDigest := sha256Hex([]byte("fixture semantic validation profile schema"))
	profileIdentity := stageArtifactIdentity{Role: "dependency_semantic_validation_profile", ID: "fixture_semantic_validation_profile", Version: "1", RawSHA256: profileDigest}
	profileSchema := stageArtifactIdentity{Role: "dependency_semantic_validation_profile_schema", ID: "urn:fixture:semantic-validation-profile-schema", Version: "1", RawSHA256: profileSchemaDigest}
	plan := &parsedPlan{Manifest: &artifactManifest{DependencySemanticValidation: dependencySemanticValidationPlanBinding{
		Profile: dependencySemanticValidationPin{Role: profileIdentity.Role, ID: profileIdentity.ID, Version: profileIdentity.Version, RawSHA256: profileIdentity.RawSHA256},
		Schema:  dependencySemanticValidationPin{Role: profileSchema.Role, ID: profileSchema.ID, Version: profileSchema.Version, RawSHA256: profileSchema.RawSHA256},
	}}}
	graph := graphPlanSchemaBindingProof{
		seal:              graphPlanSchemaBindingAuthority,
		dependencySchemas: map[stageMaterialCoordinate]stageArtifactIdentity{},
	}
	semantic := dependencySemanticValidationResolution{
		proof:         dependencySemanticValidationProof{seal: dependencySemanticValidationAuthority, byRole: map[string]dependencySemanticValidatedArtifact{}},
		roleArtifacts: map[string]artifactInput{},
	}
	graph.dependencyArtifacts = append(graph.dependencyArtifacts, profileIdentity)
	graph.dependencySchemas[stageCoordinateForIdentity(profileIdentity)] = profileSchema
	for _, role := range dependencySemanticRequiredRoles {
		raw := []byte("fixture semantic artifact: " + role)
		digest := sha256Hex(raw)
		identity := stageArtifactIdentity{Role: role, ID: "fixture_" + role, Version: "1", RawSHA256: digest}
		schema := stageArtifactIdentity{Role: role + "_schema", ID: "urn:fixture:" + role + ":schema", Version: "1", RawSHA256: sha256Hex([]byte("fixture semantic schema: " + role))}
		graph.dependencyArtifacts = append(graph.dependencyArtifacts, identity)
		graph.dependencySchemas[stageCoordinateForIdentity(identity)] = schema
		semantic.roleArtifacts[role] = artifactInput{Raw: raw, SHA256: digest, Structured: true, Manifest: map[string]interface{}{"artifact": identity.ID, "artifact_version": identity.Version}}
		semantic.proof.byRole[role] = dependencySemanticValidatedArtifact{
			artifactSHA256: digest,
			schemaRole:     schema.Role,
			schemaID:       schema.ID,
			schemaVersion:  schema.Version,
			schemaSHA256:   schema.RawSHA256,
		}
	}
	return plan, graph, semantic
}
