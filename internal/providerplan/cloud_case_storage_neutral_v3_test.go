package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// This is deliberately an oracle boundary test: it uses the assembled v3
// service target, the pinned catalog, and actual provider-shaped fixture
// bytes.  It does not prove a mapping by inspecting a pointer in isolation.
func TestGCSStorageNeutralV3ProjectsClosedSuccessorFacts(t *testing.T) {
	catalog, target := loadGCSStorageV3(t)
	raw, err := os.ReadFile("../../testdata/cloudapi/neutral-v3/fixtures/gcp-storage/bucket-all-successor-fields.json")
	if err != nil {
		t.Fatal(err)
	}
	recipe := gcsStorageV3Recipe(catalog, target, []CloudNeutralScopedBinding{
		{ScopeReference: "fixture-scope", ScopedNativeKey: "fixture-successor-bucket", OpaqueNeutralID: "neutral-bucket"},
		{ScopeReference: "fixture-scope", ScopedNativeKey: "US", OpaqueNeutralID: "neutral-location-us"},
		{ScopeReference: "fixture-scope", ScopedNativeKey: "US-CENTRAL1", OpaqueNeutralID: "neutral-location-central"},
		{ScopeReference: "fixture-scope", ScopedNativeKey: "US-EAST1", OpaqueNeutralID: "neutral-location-east"},
	})
	result, err := ProjectCloudNeutralResponse(recipe, raw)
	if err != nil || len(result.Records) != 1 {
		t.Fatalf("GCS v3 projection = %#v, %v", result, err)
	}
	var record map[string]any
	if err := json.Unmarshal(result.Records[0], &record); err != nil {
		t.Fatal(err)
	}
	if record["semantic_record_instance_identity"] != "neutral-bucket" {
		t.Fatalf("identity = %#v", record["semantic_record_instance_identity"])
	}
	for _, field := range []string{"access_control_configuration_observation", "automatic_storage_class_management_configuration_observation", "billing_configuration_observation", "cross_origin_request_policy_configuration_observation", "custom_placement_configuration_observation", "default_access_control_configuration_observation", "network_access_filter_configuration_observation", "object_retention_configuration_observation", "soft_delete_policy_configuration_observation", "website_configuration_observation"} {
		v, ok := record[field].(map[string]any)
		if !ok || v["state"] != "present" {
			t.Fatalf("%s = %#v, want present closed observation", field, record[field])
		}
	}
	for _, leak := range [][]byte{[]byte("project-owners-123456789012"), []byte("https://example.invalid"), []byte("private-key"), []byte("192.0.2.0/24"), []byte("fixture-log-bucket")} {
		if bytes.Contains(result.Records[0], leak) {
			t.Fatalf("neutral record leaked private GCS source value %q: %s", leak, result.Records[0])
		}
	}
}

func TestGCSStorageNeutralV3RefusesMissingOrForeignScopedLocation(t *testing.T) {
	catalog, target := loadGCSStorageV3(t)
	raw, err := os.ReadFile("../../testdata/cloudapi/neutral-v3/fixtures/gcp-storage/bucket-all-successor-fields.json")
	if err != nil {
		t.Fatal(err)
	}
	base := []CloudNeutralScopedBinding{{ScopeReference: "fixture-scope", ScopedNativeKey: "fixture-successor-bucket", OpaqueNeutralID: "neutral-bucket"}}
	if _, err := ProjectCloudNeutralResponse(gcsStorageV3Recipe(catalog, target, base), raw); err == nil {
		t.Fatal("accepted missing location binding")
	}
	foreign := append(base, CloudNeutralScopedBinding{ScopeReference: "other-scope", ScopedNativeKey: "US", OpaqueNeutralID: "neutral-location-us"})
	if _, err := ProjectCloudNeutralResponse(gcsStorageV3Recipe(catalog, target, foreign), raw); err == nil {
		t.Fatal("accepted foreign-scope location binding")
	}
}

func loadGCSStorageV3(t *testing.T) (CloudCatalog, CloudSourceObjectTarget) {
	t.Helper()
	request, err := LoadCloudSourceCandidateInput(filepath.Join("../../testdata/cloudapi", "candidate-input-v3.json"), NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range request.Targets {
		if target.ProviderID == "gcp" && target.ServiceID == "storage" && target.OperationID == "storage.buckets.list" {
			catalog, ok := findCloudCandidateCatalog(request.Catalogs, target)
			if !ok {
				t.Fatal("GCS storage catalog missing")
			}
			return catalog, target
		}
	}
	t.Fatal("GCS storage v3 target missing")
	return CloudCatalog{}, CloudSourceObjectTarget{}
}

func gcsStorageV3Recipe(catalog CloudCatalog, target CloudSourceObjectTarget, bindings []CloudNeutralScopedBinding) CloudNeutralProjectionRecipe {
	template := storageTemplate()
	for _, f := range target.MappingContract.Neutral.Fields {
		if _, ok := template[f.ID]; !ok {
			template[f.ID] = cloudUnknown()
		}
	}
	return CloudNeutralProjectionRecipe{Catalog: catalog, Target: &target, Contract: *target.MappingContract, ObjectPointer: "/", IdentitySourcePointer: "/name", IdentitySourceFieldID: "name", ScopeReference: "fixture-scope", ObservationState: "observed", Coverage: CloudSyntheticCoverageComplete, RecordTemplate: template, Bindings: bindings}
}
