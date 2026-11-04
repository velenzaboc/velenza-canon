package providerplan

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The successor fixture deliberately exercises every previously unsupported
// GCS Bucket member. It is source data, not a declaration that an arbitrary
// provider object may be copied into a neutral record.
func TestGCSStorageSuccessorFixtureClosesPriorUnsupportedRoster(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/neutral-v3/fixtures/gcp-storage/bucket-all-successor-fields.json")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	pointers := gcsStoragePriorUnsupportedPointers()
	if len(pointers) != 32 {
		t.Fatalf("successor roster=%d, want 32", len(pointers))
	}
	for _, pointer := range pointers {
		if _, ok := gcsFixtureValue(body, pointer); !ok {
			t.Fatalf("successor fixture omits prior unsupported member %q", pointer)
		}
	}
}

func TestGCSStorageSuccessorFixtureDoesNotUseOpaqueProviderCatchall(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/neutral-v3/fixtures/gcp-storage/bucket-all-successor-fields.json")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"raw", "rawProvider", "providerBlob", "unmapped", "opaque"} {
		if _, found := body[forbidden]; found {
			t.Fatalf("fixture contains forbidden provider catchall %q", forbidden)
		}
	}
	copy := map[string]any{}
	for key, value := range body {
		copy[key] = value
	}
	delete(copy, "softDeletePolicy")
	if _, ok := gcsFixtureValue(copy, "/softDeletePolicy"); ok {
		t.Fatal("fixture pointer lookup accepted absent source member")
	}
}

// This uses the production catalog parser plus its byte-span locator builder.
// A successor mapping may only assign semantics to this closed source roster.
func TestGCSStorageSuccessorRosterHasExactPinnedModelBindings(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	var target CloudSourceObjectTarget
	for _, candidate := range request.Targets {
		if candidate.ProviderID == "gcp" && candidate.ServiceID == "storage" && candidate.OperationID == "storage.buckets.list" {
			target = candidate
			break
		}
	}
	catalog, found := findCloudCandidateCatalog(request.Catalogs, target)
	if !found {
		t.Fatal("retained GCS Storage catalog is missing")
	}
	var model PinnedCloudModel
	for _, candidate := range request.retainedModels {
		if candidate.Source.ID == catalog.Source.ID {
			model = candidate
			break
		}
	}
	if len(model.Raw) == 0 || model.ExpectedSHA256 != catalog.ModelSHA256 {
		t.Fatal("retained GCS Storage model does not match catalog pin")
	}
	for _, pointer := range gcsStoragePriorUnsupportedPointers() {
		candidate, err := BuildCloudFieldDerivationCandidate(catalog, target, model, pointer, "gcs-storage-successor:"+pointer)
		if err != nil {
			t.Fatalf("derive exact source binding %s: %v", pointer, err)
		}
		locator := candidate.FieldLocator
		if candidate.FieldPointer != pointer || locator.EvidenceID != "model" || locator.StartByte < 0 || locator.EndByte <= locator.StartByte || locator.EndByte > len(model.Raw) || sha256Hex(model.Raw[locator.StartByte:locator.EndByte]) == "" {
			t.Fatalf("invalid exact source binding for %s: %#v", pointer, candidate)
		}
	}
}

func gcsStoragePriorUnsupportedPointers() []string {
	return []string{
		"/acl", "/autoclass", "/billing", "/cors", "/customPlacementConfig",
		"/defaultEventBasedHold", "/defaultObjectAcl", "/hardDeleteTime", "/hierarchicalNamespace",
		"/ipFilter", "/lifecycle", "/location", "/locationType", "/logging", "/objectRetention",
		"/rpo", "/satisfiesPZI", "/satisfiesPZS", "/softDeletePolicy", "/softDeleteTime", "/website",
		"/encryption/customerManagedEncryptionEnforcementConfig/effectiveTime",
		"/encryption/customerManagedEncryptionEnforcementConfig/restrictionMode",
		"/encryption/customerSuppliedEncryptionEnforcementConfig/effectiveTime",
		"/encryption/customerSuppliedEncryptionEnforcementConfig/restrictionMode",
		"/encryption/googleManagedEncryptionEnforcementConfig/effectiveTime",
		"/encryption/googleManagedEncryptionEnforcementConfig/restrictionMode",
		"/iamConfiguration/bucketPolicyOnly/enabled", "/iamConfiguration/bucketPolicyOnly/lockedTime",
		"/iamConfiguration/uniformBucketLevelAccess/enabled", "/iamConfiguration/uniformBucketLevelAccess/lockedTime",
		"/retentionPolicy/effectiveTime",
	}
}

func gcsFixtureValue(root map[string]any, pointer string) (any, bool) {
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
