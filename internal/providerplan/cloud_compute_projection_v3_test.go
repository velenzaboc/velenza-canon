package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestGCPComputeNeutralV3ProjectsInstanceAndDisk(t *testing.T) {
	request, err := loadCloudNeutralV3Service(t, "gcp", "compute")
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]CloudSourceObjectTarget{}
	var catalog CloudCatalog
	for _, target := range request.Targets {
		targets[target.SourceObjectType] = target
		var found bool
		catalog, found = findCloudCandidateCatalog(request.Catalogs, target)
		if !found {
			t.Fatal("GCP Compute catalog missing")
		}
	}
	instance, disk := targets["Instance"], targets["Disk"]
	if instance.MappingContract == nil || disk.MappingContract == nil {
		t.Fatal("GCP Compute v3 target missing")
	}
	instanceRaw := gcpComputeV3Fixture(t, "instance-all-successor-fields.json")
	diskRaw := gcpComputeV3Fixture(t, "disk-all-successor-fields.json")
	bindings := []CloudNeutralScopedBinding{
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "1000000000000000001", OpaqueNeutralID: "neutral-instance-v3"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "2000000000000000002", OpaqueNeutralID: "neutral-disk-v3"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "zones/us-central1-a", OpaqueNeutralID: "neutral-zone-a"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "regions/us-central1", OpaqueNeutralID: "neutral-region-central"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "zones/us-central1-a/machineTypes/n2-standard-4", OpaqueNeutralID: "neutral-machine-n2-standard-4"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "global/machineImages/base", OpaqueNeutralID: "neutral-machine-image-base"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "global/networks/default", OpaqueNeutralID: "neutral-network-default"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "regions/us-central1/subnetworks/default", OpaqueNeutralID: "neutral-subnetwork-default"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "regions/us-central1/resourcePolicies/fixture", OpaqueNeutralID: "neutral-resource-policy"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "fixture@p.iam.gserviceaccount.com", OpaqueNeutralID: "neutral-service-account"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "https://www.googleapis.com/auth/cloud-platform", OpaqueNeutralID: "neutral-scope-cloud-platform"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/p/zones/us-central1-a/disks/boot", OpaqueNeutralID: "neutral-boot-disk"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/p/zones/us-central1-a/disks/primary", OpaqueNeutralID: "neutral-primary-disk"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/p/zones/us-central1-b/disks/secondary", OpaqueNeutralID: "neutral-secondary-disk"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "regions/us-central1/resourcePolicies/policy", OpaqueNeutralID: "neutral-consistency-policy"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/debian-cloud/global/licenses/debian-12", OpaqueNeutralID: "neutral-license-debian-12"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "zones/us-central1-b", OpaqueNeutralID: "neutral-zone-b"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/p/zones/us-central1-a/disks/source", OpaqueNeutralID: "neutral-source-disk"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/debian-cloud/global/images/debian-12", OpaqueNeutralID: "neutral-source-image"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/p/zones/us-central1-a/instantSnapshots/snapshot", OpaqueNeutralID: "neutral-instant-snapshot"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/p/global/snapshots/snapshot", OpaqueNeutralID: "neutral-snapshot"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/p/zones/us-central1-a/storagePools/pool", OpaqueNeutralID: "neutral-storage-pool"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "gs://fixture/source", OpaqueNeutralID: "neutral-source-object"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "zones/us-central1-a/diskTypes/pd-ssd", OpaqueNeutralID: "neutral-disk-type-pd-ssd"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/p/locations/us/keyRings/r/cryptoKeys/key", OpaqueNeutralID: "neutral-kms-key"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/p/locations/us/keyRings/r/cryptoKeys/image", OpaqueNeutralID: "neutral-kms-image-key"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/p/locations/us/keyRings/r/cryptoKeys/disk", OpaqueNeutralID: "neutral-kms-disk-key"},
		{ScopeReference: "compute-v3-scope", ScopedNativeKey: "projects/p/locations/us/keyRings/r/cryptoKeys/snapshot", OpaqueNeutralID: "neutral-kms-snapshot-key"},
	}
	instanceRecipe := gcpComputeV3Recipe(catalog, instance, bindings)
	diskRecipe := gcpComputeV3Recipe(catalog, disk, bindings)
	instanceResult, err := ProjectCloudNeutralResponse(instanceRecipe, instanceRaw)
	if err != nil || len(instanceResult.Records) != 1 {
		t.Fatalf("instance v3 projection=%#v err=%v", instanceResult, err)
	}
	diskResult, err := ProjectCloudNeutralResponse(diskRecipe, diskRaw)
	if err != nil || len(diskResult.Records) != 1 {
		t.Fatalf("disk v3 projection=%#v err=%v", diskResult, err)
	}
	for _, got := range append(instanceResult.Records, diskResult.Records...) {
		if bytes.Contains(got, []byte("kmsKeyName")) || bytes.Contains(got, []byte("startup-script")) {
			t.Fatalf("provider secret/private field leaked: %s", got)
		}
	}
	assertGCPComputeV3Present(t, instanceResult.Records[0], "last_start_time", "2026-11-01T01:02:03.000Z")
	assertGCPComputeV3Present(t, diskResult.Records[0], "physical_block_size_bytes", "4096")
	if bytes.Contains(diskResult.Records[0], []byte("projects/p/")) {
		t.Fatalf("disk provider reference leaked: %s", diskResult.Records[0])
	}

	foreign := diskRecipe
	foreign.Bindings = []CloudNeutralScopedBinding{{ScopeReference: "other", ScopedNativeKey: "2000000000000000002", OpaqueNeutralID: "neutral-disk-v3"}}
	if _, err := ProjectCloudNeutralResponse(foreign, diskRaw); err == nil {
		t.Fatal("foreign scoped disk identity accepted")
	}
	var hostile map[string]json.RawMessage
	if err := json.Unmarshal(diskRaw, &hostile); err != nil {
		t.Fatal(err)
	}
	for _, number := range []string{`"-1"`, `"9223372036854775808"`} {
		hostile["physicalBlockSizeBytes"] = json.RawMessage(number)
		raw, err := json.Marshal(hostile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ProjectCloudNeutralResponse(diskRecipe, raw); err == nil {
			t.Fatal("invalid physical block size accepted")
		}
	}
	if bytes.Contains(diskResult.Records[0], []byte("synthetic-private-key-verifier")) {
		t.Fatal("key verifier escaped source boundary")
	}

}

func gcpComputeV3Fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/cloudapi/neutral-v3/fixtures/gcp-compute/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func gcpComputeV3Recipe(catalog CloudCatalog, target CloudSourceObjectTarget, bindings []CloudNeutralScopedBinding) CloudNeutralProjectionRecipe {
	return CloudNeutralProjectionRecipe{Catalog: catalog, Target: &target, Contract: *target.MappingContract, ObjectPointer: "/", IdentitySourcePointer: "/id", IdentitySourceFieldID: "id", ScopeReference: "compute-v3-scope", ObservationState: "observed", Coverage: CloudSyntheticCoverageComplete, RecordTemplate: cloudNeutralV3Template(target.MappingContract.Neutral), Bindings: bindings}
}

func assertGCPComputeV3Present(t *testing.T, raw []byte, field, want string) {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	v, ok := record[field].(map[string]any)
	if !ok || v["state"] != "present" || v["value"] != want {
		t.Fatalf("%s=%#v want %q", field, record[field], want)
	}
}
