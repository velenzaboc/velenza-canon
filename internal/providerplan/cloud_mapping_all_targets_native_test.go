package providerplan

import (
	"strconv"
	"testing"
)

// Every selected operation is an independently compiled child. Their exact
// disjoint field roster composes into the four service packages; no field is
// represented solely by an aggregate count or by a representative program.
func TestCloudMappingAllTargetsReachRealFactoryVerify(t *testing.T) {
	testCloudMappingNativeGeneration(t, "candidate-input.json", "mapping-package-scope.json", false)
}

func TestCloudMappingNeutralSuccessorReachRealFactoryVerify(t *testing.T) {
	testCloudMappingNativeGeneration(t, "candidate-input-v3.json", "mapping-package-scope-v3.json", true)
}

func testCloudMappingNativeGeneration(t *testing.T, inputName, scopeName string, successor bool) {
	t.Helper()
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/"+inputName, NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/" + scopeName)
	if err != nil {
		t.Fatal(err)
	}
	request.Catalogs = nil
	originalModelIDs := map[string]string{}
	snapshotModels := map[string]PinnedCloudModel{}
	for i := range request.retainedModels {
		model := &request.retainedModels[i]
		originalID := model.Source.ID
		if successor && originalID == "gcp-compute-model" {
			model.Source = refreshedComputeSnapshotSource(t, *model)
		} else {
			original := cloudNativeSnapshotModelByID(t, loadPinnedCloudModelsForCompilerProof(t), originalID)
			if model.ExpectedSHA256 != original.ExpectedSHA256 || model.Source != original.Source {
				t.Fatal("catalog differs from retained native snapshot")
			}
			model.Source = cloudNativeSnapshotSource(t, originalID)
		}
		originalModelIDs[model.Source.ID] = originalID
		for k := range scope.Catalogs {
			if scope.Catalogs[k].ModelSourceID == originalID {
				scope.Catalogs[k].ModelSourceID = model.Source.ID
			}
		}
		for j := range model.SupplementalEvidence {
			model.SupplementalEvidence[j].Source = cloudNativeSnapshotSupplementalSource(t, originalID, model.SupplementalEvidence[j].ID)
		}
		catalog, err := ParsePinnedCloudModel(*model)
		if err != nil {
			t.Fatal(err)
		}
		request.Catalogs = append(request.Catalogs, catalog)
		snapshotModels[model.Source.ID] = *model
	}
	roster, err := BuildCloudMappingOccurrenceRoster(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	if !successor && (len(roster.Occurrences) != 255 || roster.Totals != (CloudMappingDispositionTotals{Mapped: 31, Private: 24, Unsupported: 200})) {
		t.Fatal("selected full scope changed")
	}
	if successor && (len(scope.Targets) != 9 || len(roster.Resources) != 6 || len(roster.Occurrences) < 255 || roster.Totals != scope.ExpectedDispositionTotals || roster.Totals.Unsupported != 0 || roster.Totals.Unknown != 0 || roster.Totals.NotObserved != 0) {
		t.Fatal("successor lost selected resources, operations or resolved field coverage")
	}
	covered := map[string]bool{}
	for index, target := range scope.Targets {
		child := CloudMappingOccurrenceRoster{}
		targetKeys := map[string]bool{}
		modelID := ""
		for _, occurrence := range roster.Occurrences {
			if occurrence.ProviderID != target.ProviderID || occurrence.ServiceID != target.ServiceID || occurrence.OperationID != target.OperationID {
				continue
			}
			if covered[occurrence.FieldSourceSymbol] {
				t.Fatal("field appears in multiple native child packages")
			}
			covered[occurrence.FieldSourceSymbol] = true
			child.Occurrences = append(child.Occurrences, occurrence)
			addCloudOccurrenceDisposition(&child.Totals, occurrence.Field.Disposition)
			targetKeys[occurrence.TargetKey] = true
			modelID = occurrence.ModelSourceID
		}
		for _, resource := range roster.Resources {
			selected := resource
			selected.TargetKeys = nil
			for _, key := range resource.TargetKeys {
				if targetKeys[key] {
					selected.TargetKeys = append(selected.TargetKeys, key)
				}
			}
			if len(selected.TargetKeys) != 0 {
				child.Resources = append(child.Resources, selected)
			}
		}
		if err := ValidateCloudMappingOccurrenceRoster(child, child.Totals); err != nil {
			t.Fatal(err)
		}
		t.Run(target.ServiceID+"_"+target.OperationID, func(t *testing.T) {
			cloudMappingNativeFactoryServiceWithInputs(t, originalModelIDs[modelID], target.OperationID, "mapping_complete_"+strconv.Itoa(index), snapshotModels[modelID], request, child)
		})
	}
	if len(covered) != len(roster.Occurrences) {
		t.Fatal("native child roster did not cover every parent occurrence")
	}
}
