package providerplan

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The two fixtures deliberately carry every direct Instance and Disk member
// that was unsupported in the retained Compute coverage.  They are source
// payloads, not a licence to emit provider-shaped JSON into a neutral record.
func TestGCPComputeSuccessorFixturesClosePriorUnsupportedRoster(t *testing.T) {
	if got := len(gcpComputeInstancePriorUnsupportedPointers()); got != 43 {
		t.Fatalf("Instance successor roster = %d, want 43", got)
	}
	if got := len(gcpComputeDiskPriorUnsupportedPointers()); got != 44 {
		t.Fatalf("Disk successor roster = %d, want 44", got)
	}
	for _, fixture := range []struct {
		path     string
		pointers []string
	}{
		{"../../testdata/cloudapi/neutral-v3/fixtures/gcp-compute/instance-all-successor-fields.json", gcpComputeInstancePriorUnsupportedPointers()},
		{"../../testdata/cloudapi/neutral-v3/fixtures/gcp-compute/disk-all-successor-fields.json", gcpComputeDiskPriorUnsupportedPointers()},
	} {
		raw, err := os.ReadFile(fixture.path)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		for _, pointer := range fixture.pointers {
			if _, ok := gcpComputeFixtureValue(body, pointer); !ok {
				t.Fatalf("%s omits previously unsupported member %q", fixture.path, pointer)
			}
		}
		for _, forbidden := range []string{"raw", "rawProvider", "providerBlob", "unmapped", "opaque"} {
			if _, found := body[forbidden]; found {
				t.Fatalf("%s contains provider catchall %q", fixture.path, forbidden)
			}
		}
	}
}

// This positive binding check uses the retained refreshed model, rather than
// field names or reconstructed schemas.  It makes every migration candidate
// prove it still has an exact byte range in the pinned Discovery document.
func TestGCPComputeSuccessorRosterHasExactRefreshedModelBindings(t *testing.T) {
	input, profiles, old, fresh, options := cloudRefreshFixture(t)
	next, _, _, err := RefreshCloudModelCandidates(input, profiles, old, fresh, options)
	if err != nil {
		t.Fatal(err)
	}
	request, err := loadCloudSourceCandidateInputAt("../../testdata/cloudapi", next, NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	var model PinnedCloudModel
	for _, candidate := range request.retainedModels {
		if candidate.Source.ID == options.ModelID {
			model = candidate
		}
	}
	if len(model.Raw) == 0 || model.ExpectedSHA256 != options.ExpectedSHA256 {
		t.Fatal("retained refreshed Compute model is absent or not pinned")
	}
	for _, check := range []struct {
		operation string
		pointers  []string
	}{
		{"compute.instances.aggregatedList", gcpComputeInstancePriorUnsupportedPointers()},
		{"compute.disks.aggregatedList", gcpComputeDiskPriorUnsupportedPointers()},
	} {
		var target CloudSourceObjectTarget
		for _, candidate := range request.Targets {
			if candidate.ProviderID == "gcp" && candidate.ServiceID == "compute" && candidate.OperationID == check.operation {
				target = candidate
			}
		}
		catalog, found := findCloudCandidateCatalog(request.Catalogs, target)
		if !found {
			t.Fatalf("catalog absent for %s", check.operation)
		}
		for _, pointer := range check.pointers {
			candidate, err := BuildCloudFieldDerivationCandidate(catalog, target, model, pointer, "gcp-compute-successor:"+check.operation+pointer)
			if err != nil {
				t.Fatalf("derive %s %s: %v", check.operation, pointer, err)
			}
			locator := candidate.FieldLocator
			if candidate.FieldPointer != pointer || locator.EvidenceID != "model" || locator.StartByte < 0 || locator.EndByte <= locator.StartByte || locator.EndByte > len(model.Raw) {
				t.Fatalf("invalid exact source binding for %s: %#v", pointer, candidate)
			}
		}
	}
}

func TestGCPComputeSuccessorFixturePointerLookupRefusesAbsentValue(t *testing.T) {
	copy := map[string]any{"canIpForward": true}
	if _, ok := gcpComputeFixtureValue(copy, "/deletionProtection"); ok {
		t.Fatal("fixture pointer lookup accepted an absent source member")
	}
}

func gcpComputeFixtureValue(root map[string]any, pointer string) (any, bool) {
	var current any = root
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		var found bool
		current, found = object[part]
		if !found || current == nil {
			return nil, false
		}
	}
	return current, true
}

func gcpComputeInstancePriorUnsupportedPointers() []string {
	return []string{
		"/advancedMachineFeatures", "/canIpForward", "/confidentialInstanceConfig", "/cpuPlatform", "/deletionProtection", "/disks", "/displayDevice", "/fingerprint", "/guestAccelerators", "/hostname", "/instanceEncryptionKey", "/keyRevocationActionType", "/kind", "/labelFingerprint", "/labels", "/lastStartTimestamp", "/lastStopTimestamp", "/lastSuspendedTimestamp", "/localSsdEncryptionMode", "/machineType", "/metadata", "/minCpuPlatform", "/networkInterfaces", "/networkPerformanceConfig", "/params", "/privateIpv6GoogleAccess", "/reservationAffinity", "/resourcePolicies", "/resourceStatus", "/satisfiesPzi", "/satisfiesPzs", "/scheduling", "/selfLink", "/serviceAccounts", "/shieldedInstanceConfig", "/shieldedInstanceIntegrityPolicy", "/sourceMachineImage", "/sourceMachineImageEncryptionKey", "/startRestricted", "/statusMessage", "/tags", "/workloadIdentityConfig", "/zone",
	}
}

func gcpComputeDiskPriorUnsupportedPointers() []string {
	return []string{
		"/accessMode", "/architecture", "/asyncPrimaryDisk", "/asyncSecondaryDisks", "/diskEncryptionKey", "/enableConfidentialCompute", "/guestOsFeatures", "/kind", "/labelFingerprint", "/labels", "/lastAttachTimestamp", "/lastDetachTimestamp", "/licenseCodes", "/licenses", "/locationHint", "/options", "/params", "/physicalBlockSizeBytes", "/provisionedIops", "/provisionedThroughput", "/region", "/replicaZones", "/resourcePolicies", "/resourceStatus", "/satisfiesPzi", "/satisfiesPzs", "/selfLink", "/sourceConsistencyGroupPolicy", "/sourceConsistencyGroupPolicyId", "/sourceDisk", "/sourceDiskId", "/sourceImage", "/sourceImageEncryptionKey", "/sourceImageId", "/sourceInstantSnapshot", "/sourceInstantSnapshotId", "/sourceSnapshot", "/sourceSnapshotEncryptionKey", "/sourceSnapshotId", "/sourceStorageObject", "/status", "/storagePool", "/type", "/zone",
	}
}
