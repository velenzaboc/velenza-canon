package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
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
	recipe := gcsStorageV3Recipe(catalog, target, gcsStorageV3Bindings())
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
	present := func(value any) map[string]any { return map[string]any{"state": "present", "value": value} }
	assertGCSV3Value(t, record, "access_control_configuration_observation", []any{map[string]any{"principal_reference": present("neutral-project-owners"), "role": present("owner")}})
	assertGCSV3Value(t, record, "default_access_control_configuration_observation", []any{map[string]any{"principal_reference": present("neutral-authenticated-users"), "role": present("reader")}})
	assertGCSV3Value(t, record, "cross_origin_request_policy_configuration_observation", []any{map[string]any{"methods": present([]any{"GET"}), "allowed_origin_references": present([]any{"neutral-origin"}), "response_headers": present([]any{"Content-Type"}), "max_age_seconds": present("3600")}})
	assertGCSV3Value(t, record, "network_access_filter_configuration_observation", map[string]any{"mode": present("enabled"), "public_network_source": present(map[string]any{"allowed_ip_prefix_references": present([]any{"neutral-ip-prefix"})}), "virtual_network_sources": map[string]any{"state": "not_observed"}, "allow_cross_organization_networks": map[string]any{"state": "not_observed"}, "allow_all_service_agents": map[string]any{"state": "not_observed"}})
	assertGCSV3Value(t, record, "logging_configuration_observation", map[string]any{"destination_container_reference": present("neutral-log-bucket"), "object_name_prefix": present("access/")})
	assertGCSV3Value(t, record, "container_location_relationship", "neutral-location-us")
	assertGCSV3Value(t, record, "uniform_resource_access_lock_time", "2026-02-02T03:04:05.000Z")
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
	base := gcsStorageV3Bindings()
	base = gcsStorageV3Without(base, "US")
	if _, err := ProjectCloudNeutralResponse(gcsStorageV3Recipe(catalog, target, base), raw); err == nil {
		t.Fatal("accepted missing location binding")
	}
	foreign := append(base, CloudNeutralScopedBinding{ScopeReference: "other-scope", ScopedNativeKey: "US", OpaqueNeutralID: "neutral-location-us"})
	if _, err := ProjectCloudNeutralResponse(gcsStorageV3Recipe(catalog, target, foreign), raw); err == nil {
		t.Fatal("accepted foreign-scope location binding")
	}
}

func TestGCSStorageNeutralV3RefusesMismatchedAndAcceptsAliasOnlyLockTime(t *testing.T) {
	catalog, target := loadGCSStorageV3(t)
	raw, err := os.ReadFile("../../testdata/cloudapi/neutral-v3/fixtures/gcp-storage/bucket-all-successor-fields.json")
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(raw, []byte(`"bucketPolicyOnly":{"enabled":true,"lockedTime":"2026-02-02T03:04:05.000Z"}`), []byte(`"bucketPolicyOnly":{"enabled":true,"lockedTime":"2026-02-01T03:04:05.000Z"}`), 1)
	if _, err := ProjectCloudNeutralResponse(gcsStorageV3Recipe(catalog, target, gcsStorageV3Bindings()), bad); err == nil {
		t.Fatal("accepted mismatched bucketPolicyOnly lock-time alias")
	}
	aliasOnly := bytes.Replace(raw, []byte(`"uniformBucketLevelAccess": {"enabled": true,"lockedTime":"2026-02-02T03:04:05.000Z"}`), []byte(`"uniformBucketLevelAccess": {"enabled": true}`), 1)
	result, err := ProjectCloudNeutralResponse(gcsStorageV3Recipe(catalog, target, gcsStorageV3Bindings()), aliasOnly)
	if err != nil || len(result.Records) != 1 {
		t.Fatalf("alias-only lock time = %#v, %v", result, err)
	}
	var record map[string]any
	if err := json.Unmarshal(result.Records[0], &record); err != nil {
		t.Fatal(err)
	}
	assertGCSV3Value(t, record, "uniform_resource_access_lock_time", "2026-02-02T03:04:05.000Z")
}

func gcsStorageV3Bindings() []CloudNeutralScopedBinding {
	return []CloudNeutralScopedBinding{
		{ScopeReference: "fixture-scope", ScopedNativeKey: "fixture-successor-bucket", OpaqueNeutralID: "neutral-bucket"}, {ScopeReference: "fixture-scope", ScopedNativeKey: "US", OpaqueNeutralID: "neutral-location-us"}, {ScopeReference: "fixture-scope", ScopedNativeKey: "US-CENTRAL1", OpaqueNeutralID: "neutral-location-central"}, {ScopeReference: "fixture-scope", ScopedNativeKey: "US-EAST1", OpaqueNeutralID: "neutral-location-east"}, {ScopeReference: "fixture-scope", ScopedNativeKey: "project-owners-123456789012", OpaqueNeutralID: "neutral-project-owners"}, {ScopeReference: "fixture-scope", ScopedNativeKey: "allAuthenticatedUsers", OpaqueNeutralID: "neutral-authenticated-users"}, {ScopeReference: "fixture-scope", ScopedNativeKey: "https://example.invalid", OpaqueNeutralID: "neutral-origin"}, {ScopeReference: "fixture-scope", ScopedNativeKey: "192.0.2.0/24", OpaqueNeutralID: "neutral-ip-prefix"}, {ScopeReference: "fixture-scope", ScopedNativeKey: "fixture-log-bucket", OpaqueNeutralID: "neutral-log-bucket"},
	}
}
func gcsStorageV3Without(in []CloudNeutralScopedBinding, native string) []CloudNeutralScopedBinding {
	out := make([]CloudNeutralScopedBinding, 0, len(in))
	for _, b := range in {
		if b.ScopedNativeKey != native {
			out = append(out, b)
		}
	}
	return out
}
func assertGCSV3Value(t *testing.T, record map[string]any, field string, want any) {
	t.Helper()
	got, ok := record[field].(map[string]any)
	actual, _ := json.Marshal(got["value"])
	expected, _ := json.Marshal(want)
	if !ok || got["state"] != "present" || !bytes.Equal(actual, expected) {
		t.Fatalf("%s = %#v, want present %#v", field, record[field], want)
	}
}

func loadGCSStorageV3(t *testing.T) (CloudCatalog, CloudSourceObjectTarget) {
	t.Helper()
	request, err := loadCloudNeutralV3Service(t, "gcp", "storage")
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
