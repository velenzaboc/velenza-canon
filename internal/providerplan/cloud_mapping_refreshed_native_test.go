package providerplan

import "testing"

func refreshedComputeSnapshotSource(t *testing.T, model PinnedCloudModel) CloudCatalogSourceIdentity {
	t.Helper()
	const pin = "ce740f987255bec9ed06e051e6df52797ddbe216bc8644b3433ccc16b0ebfe37"
	if model.ExpectedSHA256 != pin || sha256Hex(model.Raw) != pin || model.Source.ID != "gcp-compute-model" {
		t.Fatal("unrecognized native Compute source generation")
	}
	const commit = "5e43bed3fb663cac2656af984daf34194e250f6b"
	const path = "testdata/cloudapi/refresh-20261102/compute-v1.discovery.json"
	return CloudCatalogSourceIdentity{ID: "velenza-snapshot-refreshed-compute", URI: "https://raw.githubusercontent.com/velenzaboc/velenza-canon/" + commit + "/" + path, StableCoordinate: "velenza-canon@" + commit + "/" + path, FormatRevision: cloudNativeSnapshotFormat}
}

// A refresh cannot inherit a prior model's native proof. Rebuild the two
// affected operation packages using the successor bytes and rebased recipes;
// the other three models are byte-identical and covered by the all-nine test.
func TestCloudMappingRefreshedComputeTargetsReachRealFactoryVerify(t *testing.T) {
	input, profiles, old, fresh, options := cloudRefreshFixture(t)
	next, _, _, err := RefreshCloudModelCandidates(input, profiles, old, fresh, options)
	if err != nil {
		t.Fatal(err)
	}
	request, err := loadCloudSourceCandidateInputAt("../../testdata/cloudapi", next, NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	var model PinnedCloudModel
	request.Catalogs = nil
	for i := range request.retainedModels {
		m := &request.retainedModels[i]
		if m.Source.ID == options.ModelID {
			if m.Source != options.Source || m.ExpectedSHA256 != options.ExpectedSHA256 || sha256Hex(m.Raw) != options.ExpectedSHA256 {
				t.Fatal("successor lost exact origin or bytes")
			}
			m.Source = refreshedComputeSnapshotSource(t, *m)
			model = *m
			for j := range scope.Catalogs {
				if scope.Catalogs[j].ModelSourceID == options.ModelID {
					scope.Catalogs[j].ModelSourceID = m.Source.ID
				}
			}
		}
		catalog, err := ParsePinnedCloudModel(*m)
		if err != nil {
			t.Fatal(err)
		}
		request.Catalogs = append(request.Catalogs, catalog)
	}
	if len(model.Raw) == 0 {
		t.Fatal("refreshed model absent")
	}
	roster, err := BuildCloudMappingOccurrenceRoster(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(roster.Occurrences) != 255 || roster.Totals != (CloudMappingDispositionTotals{Mapped: 31, Private: 24, Unsupported: 200}) {
		t.Fatal("successor changed selected field closure")
	}
	count := 0
	for _, target := range scope.Targets {
		if target.ProviderID != model.ProviderID || target.ServiceID != model.ServiceID {
			continue
		}
		child := CloudMappingOccurrenceRoster{}
		keys := map[string]bool{}
		for _, occurrence := range roster.Occurrences {
			if occurrence.ModelSourceID == model.Source.ID && occurrence.OperationID == target.OperationID {
				child.Occurrences = append(child.Occurrences, occurrence)
				addCloudOccurrenceDisposition(&child.Totals, occurrence.Field.Disposition)
				keys[occurrence.TargetKey] = true
			}
		}
		for _, resource := range roster.Resources {
			selected := resource
			selected.TargetKeys = nil
			for _, key := range resource.TargetKeys {
				if keys[key] {
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
		count++
		t.Run(target.OperationID, func(t *testing.T) {
			cloudMappingNativeFactoryServiceWithInputs(t, options.ModelID, target.OperationID, "mapping_refreshed_compute", model, request, child)
		})
	}
	if count != 2 {
		t.Fatalf("successor operation targets = %d, want 2", count)
	}
}
