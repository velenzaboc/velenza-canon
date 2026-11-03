package providerplan

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const cloudNeutralV3Dir = "../../testdata/cloudapi/"

// Use the same pinned-document resolver and loader as composition, with an
// isolated selection for a service's response tests. The full assembly gate
// below separately enforces the cross-service closure.
func loadCloudNeutralV3Service(t *testing.T, provider, service string) (CloudSourceCandidateRequest, error) {
	t.Helper()
	var input CloudSourceCandidateInput
	raw, err := os.ReadFile(cloudNeutralV3Dir + "candidate-input-v3.json")
	if err != nil {
		return CloudSourceCandidateRequest{}, err
	}
	if err := strictUnmarshal(raw, &input); err != nil {
		return CloudSourceCandidateRequest{}, err
	}
	sel := input
	sel.Targets = nil
	sel.TargetDocuments = nil
	sel.Models = nil
	for _, m := range input.Models {
		if m.ProviderID == provider && m.ServiceID == service {
			sel.Models = append(sel.Models, m)
		}
	}
	for _, r := range input.TargetDocuments {
		if r.ProviderID == provider && r.ServiceID == service {
			sel.TargetDocuments = append(sel.TargetDocuments, r)
		}
	}
	if len(sel.Models) != 1 || len(sel.TargetDocuments) != 1 {
		t.Fatalf("expected one model and one document for %s/%s", provider, service)
	}
	sel, err = resolveCloudServiceDocuments(cloudNeutralV3Dir, sel)
	if err != nil {
		return CloudSourceCandidateRequest{}, err
	}
	return loadCloudSourceCandidateInputAt(cloudNeutralV3Dir, sel, NewCloudCatalogParser())
}

func TestCloudNeutralSuccessorOperationContracts(t *testing.T) {
	req, err := LoadCloudSourceCandidateInput(cloudNeutralV3Dir+"candidate-input-v3.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range req.Targets {
		t.Run(target.OperationID, func(t *testing.T) {
			catalog, ok := findCloudCandidateCatalog(req.Catalogs, target)
			if !ok {
				t.Fatal("missing catalog")
			}
			c := *target.MappingContract
			t.Run("contract", func(t *testing.T) {
				if err := ValidateCloudMappingContract(catalog, c); err != nil {
					t.Fatal(err)
				}
			})
			sources, err := cloudCatalogObjectFields(catalog, c.ObjectSchemaID)
			if err != nil {
				t.Fatal(err)
			}
			neutral, err := cloudNeutralFieldMap(c.Neutral)
			if err != nil {
				t.Fatal(err)
			}
			// Each occurrence has its own verdict even if a sibling mapping fails.
			check := func(f CloudMappingContractField, n *CloudNestedDecomposition) {
				t.Run(f.SourceFieldID, func(t *testing.T) {
					roster := sources
					if n != nil {
						var err error
						roster, err = cloudDecompositionLeaves(catalog, sources[n.ParentPointer])
						if err != nil {
							t.Fatal(err)
						}
					}
					source := roster[f.SourcePointer]
					if err := validateCloudMappingField(f, source, neutral); err != nil {
						target := neutral[f.TargetField]
						t.Fatalf("%s -> %s (%s/%s to %s/%s): %v", f.SourcePointer, f.TargetField, source.ValueType, source.Cardinality, target.ValueType, target.Cardinality, err)
					}
					if f.StructuredRecipe == nil {
						return
					}
					single := c
					single.Fields = nil
					single.Nested = nil
					if n == nil {
						single.Fields = []CloudMappingContractField{f}
					} else {
						d := *n
						d.Fields = []CloudMappingContractField{f}
						single.Nested = []CloudNestedDecomposition{d}
					}
					if _, err := compileCloudStructuredFields(catalog, single, sources); err != nil {
						t.Fatal(err)
					}
				})
			}
			for _, f := range c.Fields {
				check(f, nil)
			}
			for _, n := range c.Nested {
				for _, f := range n.Fields {
					check(f, &n)
				}
			}
		})
	}
}

func TestCloudNeutralSuccessorPreparesAllFourServices(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput(cloudNeutralV3Dir+"candidate-input-v3.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope(cloudNeutralV3Dir + "mapping-package-scope-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := LoadCloudAPIProfileDocument(cloudNeutralV3Dir + "provider-profiles-refreshed.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadCloudIngestionHandoffPolicy(cloudNeutralV3Dir + "ingestion-handoff-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := BuildCloudFactoryPreparation(request, scope, profiles, policy)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "prepared")
	if err := pkg.PublishExclusive(dest); err != nil {
		t.Fatal(err)
	}
	if err := pkg.VerifyDirectory(dest); err != nil {
		t.Fatal(err)
	}
	next, err := BuildCloudCoverageBacklog(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := os.ReadFile(cloudNeutralV3Dir + "neutral-v3/previous-coverage.json")
	if err != nil {
		t.Fatal(err)
	}
	audit, err := AuditCloudCoverageSuccessor(prior, cloudNeutralV3PredecessorHash, next)
	if err != nil {
		t.Fatal(err)
	}
	if audit.Preserved != 55 || len(audit.Resolutions) != 200 {
		t.Fatalf("preserved %d, resolved %d; want 55/200", audit.Preserved, len(audit.Resolutions))
	}
	counts := map[string]int{}
	for _, r := range audit.Resolutions {
		counts[r.Predecessor.ServiceID]++
	}
	if !reflect.DeepEqual(counts, map[string]int{"s3": 5, "ec2": 76, "storage": 32, "compute": 87}) {
		t.Fatalf("resolved service rosters %v", counts)
	}
}

func TestCloudNeutralSuccessorPreservesAcceptedRecipes(t *testing.T) {
	original, profiles, oldModel, freshModel, options := cloudRefreshFixture(t)
	prior, _, _, err := RefreshCloudModelCandidates(original, profiles, oldModel, freshModel, options)
	if err != nil {
		t.Fatal(err)
	}
	next, err := readCloudCandidateInput(cloudNeutralV3Dir + "candidate-input-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	type coordinate struct{ provider, service, surface, operation, resource, class string }
	key := func(t CloudSourceObjectTarget) coordinate {
		return coordinate{t.ProviderID, t.ServiceID, t.APISurfaceID, t.OperationID, t.SourceObjectType, t.RecordClassSymbol}
	}
	byTarget := map[coordinate]CloudSourceObjectTarget{}
	for _, target := range next.Targets {
		byTarget[key(target)] = target
	}
	if len(next.Targets) != 9 || len(byTarget) != len(prior.Targets) {
		t.Fatal("selected operation set changed")
	}
	preserved := 0
	for _, old := range prior.Targets {
		n, ok := byTarget[key(old)]
		if !ok || n.MappingContract == nil || n.SourceMappingVersion == old.SourceMappingVersion {
			t.Fatalf("missing versioned successor for %s", old.OperationID)
		}
		byField := map[string]CloudMappingContractField{}
		for _, f := range cloudNeutralProjectionFields(*n.MappingContract) {
			byField[f.SourcePointer] = f
		}
		for _, f := range cloudNeutralProjectionFields(*old.MappingContract) {
			if f.Disposition == CloudSourceUnsupported {
				continue
			}
			g, ok := byField[f.SourcePointer]
			if !ok || f.SourceFieldID != g.SourceFieldID || f.WirePointer != g.WirePointer || f.Disposition != g.Disposition || f.TargetField != g.TargetField ||
				f.Projection != g.Projection || f.SourceUnit != g.SourceUnit || f.UnitEvidenceRef != g.UnitEvidenceRef ||
				f.ExplicitNullDisposition != g.ExplicitNullDisposition || f.ExplicitAbsentDisposition != g.ExplicitAbsentDisposition ||
				!reflect.DeepEqual(f.LifecycleRecipe, g.LifecycleRecipe) || !reflect.DeepEqual(f.ValueRecipe, g.ValueRecipe) || g.StructuredRecipe != nil {
				t.Errorf("%s %s lost its accepted mapping or presence behavior", old.OperationID, f.SourcePointer)
			}
			preserved++
		}
		refs := map[string]CloudMappingEvidenceBinding{}
		for _, e := range n.MappingContract.EvidenceBindings {
			refs[e.ID] = e
		}
		for _, e := range old.MappingContract.EvidenceBindings {
			if refs[e.ID] != e {
				t.Errorf("%s lost accepted evidence binding %s", old.OperationID, e.ID)
			}
		}
	}
	if preserved != 55 {
		t.Fatalf("compared %d retained field contracts", preserved)
	}
}

func cloudNeutralV3Template(schema CloudNeutralRecordSchema) map[string]any {
	template := map[string]any{}
	for _, field := range schema.Fields {
		switch field.ID {
		case "record_class":
			template[field.ID] = schema.ClassSymbol
		case "observation_state":
			template[field.ID] = "observed"
		case "semantic_record_instance_identity", "scope_reference":
			continue
		default:
			for _, state := range []string{"not_observed", "unknown"} {
				value := map[string]any{"state": state}
				if validateCloudJSONSchema(field.WireSchema, schema.definitions, value, map[string]bool{}) == nil {
					template[field.ID] = value
					break
				}
			}
			if _, ok := template[field.ID]; !ok {
				panic("v3 field lacks neutral missing arm: " + field.ID)
			}
		}
	}
	return template
}
