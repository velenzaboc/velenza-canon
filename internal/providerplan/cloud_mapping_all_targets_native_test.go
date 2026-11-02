package providerplan

import (
	"strconv"
	"testing"
)

// Every selected operation is an independently compiled child. Their exact
// disjoint field roster composes into the four service packages; no field is
// represented solely by an aggregate count or by a representative program.
func TestCloudMappingAllTargetsReachRealFactoryVerify(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	request.retainedModels = loadPinnedCloudModelsForCompilerProof(t)
	request.Catalogs = nil
	originalModelIDs := map[string]string{}
	for i := range request.retainedModels {
		model := &request.retainedModels[i]
		originalID := model.Source.ID
		model.Source = cloudNativeSnapshotSource(t, originalID)
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
	}
	roster, err := BuildCloudMappingOccurrenceRoster(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(roster.Occurrences) != 255 || roster.Totals != (CloudMappingDispositionTotals{Mapped: 31, Private: 24, Unsupported: 200}) {
		t.Fatal("selected full scope changed")
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
			cloudMappingNativeFactoryService(t, originalModelIDs[modelID], target.OperationID, "mapping_complete_"+strconv.Itoa(index), child)
		})
	}
	if len(covered) != len(roster.Occurrences) {
		t.Fatal("native child roster did not cover every parent occurrence")
	}
}
