package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// This is intentionally an end-to-end offline case: it loads the retained
// Discovery model and owner-pinned neutral schema through the normal candidate
// input, then replaces only the GCS target with the case's complete Bucket
// mapping roster. It must not be satisfied by a reduced test catalog.
func TestCloudCaseGCPStorageOfflineAcceptance(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Targets []CloudSourceObjectTarget `json:"targets"`
	}
	caseRaw, err := os.ReadFile("../../testdata/cloudapi/cases/gcp-storage.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := strictUnmarshal(caseRaw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Targets) != 1 {
		t.Fatalf("case targets=%d, want exactly one GCS Bucket target", len(fixture.Targets))
	}
	target := fixture.Targets[0]
	storageIndex := -1
	for i := range request.Targets {
		if request.Targets[i].ProviderID == "gcp" && request.Targets[i].ServiceID == "storage" && request.Targets[i].SourceObjectType == "Bucket" {
			storageIndex = i
			break
		}
	}
	if storageIndex < 0 {
		t.Fatal("candidate input has no GCS Bucket target to replace")
	}
	if target.MappingContract == nil {
		t.Fatal("case target lacks mapping contract")
	}
	// The case owns its roster; the real candidate input owns the pinned
	// neutral-owner load. Do not make a second, reduced neutral catalog.
	target.MappingContract.Neutral = request.Targets[storageIndex].MappingContract.Neutral
	target.RecordClassContractRef = target.MappingContract.Neutral.OwnerRef
	catalog, found := findCloudCandidateCatalog(request.Catalogs, target)
	if !found {
		t.Fatal("retained GCS catalog not found")
	}
	locator, err := CloudIdentityMemberEvidenceLocator(catalog, "Bucket", "name")
	if err != nil {
		t.Fatal(err)
	}
	if len(target.StableIdentityEvidence) != 1 || target.StableIdentityEvidence[0].Locator != locator {
		t.Fatalf("case must persist the exact retained name member locator: %#v", target.StableIdentityEvidence)
	}
	request.Targets[storageIndex] = target
	target = request.Targets[storageIndex]

	if err := ValidateCloudSourceIdentityContract(target, catalog); err != nil {
		t.Fatalf("exact name member evidence: %v", err)
	}
	actual, err := cloudCatalogObjectFields(catalog, "Bucket")
	if err != nil {
		t.Fatal(err)
	}
	if len(target.MappingContract.Fields) != len(actual) {
		t.Fatalf("case Bucket roster=%d, retained Discovery roster=%d", len(target.MappingContract.Fields), len(actual))
	}
	seen := map[string]bool{}
	for _, field := range target.MappingContract.Fields {
		if _, ok := actual[field.SourcePointer]; !ok {
			t.Fatalf("case includes non-Bucket field %q", field.SourcePointer)
		}
		seen[field.SourcePointer] = true
	}
	if len(seen) != len(actual) {
		t.Fatalf("case roster has duplicate or missing direct Bucket fields")
	}
	if err := ValidateCloudMappingContract(catalog, *target.MappingContract); err != nil {
		t.Fatalf("complete retained GCS Bucket contract: %v", err)
	}

	assertStorageMapping(t, target, "name", "display_name")
	assertStorageUnsupported(t, target, "storageClass")
	assertStorageUnsupported(t, target, "timeCreated")
	for _, private := range []string{"id", "selfLink", "projectNumber", "etag", "generation", "metageneration", "updated"} {
		for _, field := range target.MappingContract.Fields {
			if field.SourceFieldID == private && field.Disposition != CloudSourcePrivateOnly {
				t.Fatalf("private provider field %q has disposition %q", private, field.Disposition)
			}
		}
	}

	listRaw, err := os.ReadFile("../../testdata/cloudapi/fixtures/gcp/storage-buckets-list-page-1.json")
	if err != nil {
		t.Fatal(err)
	}
	// Make the otherwise-equal GCS id visibly private in this test response.
	listRaw = bytes.Replace(listRaw, []byte(`"id":"fixture-log-bucket"`), []byte(`"id":"provider-private-id"`), 1)
	list := storageRecipe(catalog, target, "/items", "fixture-project-scope", CloudSyntheticCoveragePartial, "incomplete", "/nextPageToken", []CloudNeutralScopedBinding{{ScopeReference: "fixture-project-scope", ScopedNativeKey: "fixture-log-bucket", OpaqueNeutralID: "opaque-storage-log-01"}})
	page, err := ProjectCloudNeutralResponse(list, listRaw)
	if err != nil {
		t.Fatal(err)
	}
	if page.Coverage != CloudSyntheticCoveragePartial || page.Continuation != "fixture-storage-page-2" || page.DeletionAuthorized || len(page.Records) != 1 {
		t.Fatalf("partial continuation must remain non-destructive: %#v", page)
	}
	assertStorageRecord(t, page.Records[0], "fixture-log-bucket", "opaque-storage-log-01")
	if bytes.Contains(page.Records[0], []byte("provider-private-id")) || bytes.Contains(page.Records[0], []byte("123456789012")) || bytes.Contains(page.Records[0], []byte("googleapis.com")) {
		t.Fatalf("private GCS provider data leaked into neutral record: %s", page.Records[0])
	}

	getRaw, err := os.ReadFile("../../testdata/cloudapi/fixtures/gcp/storage-bucket-get.json")
	if err != nil {
		t.Fatal(err)
	}
	get := storageRecipe(catalog, target, "/", "fixture-project-scope", CloudSyntheticCoverageComplete, "observed", "", []CloudNeutralScopedBinding{{ScopeReference: "fixture-project-scope", ScopedNativeKey: "fixture-archive-bucket", OpaqueNeutralID: "opaque-storage-archive-02"}})
	got, err := ProjectCloudNeutralResponse(get, getRaw)
	if err != nil || len(got.Records) != 1 || got.DeletionAuthorized {
		t.Fatalf("complete get projection=%#v err=%v", got, err)
	}
	assertStorageRecord(t, got.Records[0], "fixture-archive-bucket", "opaque-storage-archive-02")

	missing := list
	missing.Bindings = nil
	if _, err := ProjectCloudNeutralResponse(missing, listRaw); err == nil {
		t.Fatal("missing scoped opaque binding was accepted")
	}
	unresolved := list
	unresolved.Bindings[0].ScopedNativeKey = "other-bucket"
	if _, err := ProjectCloudNeutralResponse(unresolved, listRaw); err == nil {
		t.Fatal("unresolved scoped opaque binding was accepted")
	}
	wrongScope := list
	wrongScope.ScopeReference = "other-project-scope"
	if _, err := ProjectCloudNeutralResponse(wrongScope, listRaw); err == nil {
		t.Fatal("cross-scope binding was accepted")
	}
	empty, err := ProjectCloudNeutralResponse(list, []byte(`{"kind":"storage#buckets","items":[]}`))
	if err != nil || len(empty.Records) != 0 || empty.DeletionAuthorized {
		t.Fatalf("empty partial page must not delete: %#v err=%v", empty, err)
	}
	positiveTemplate := list
	positiveTemplate.RecordTemplate = storageTemplate()
	positiveTemplate.RecordTemplate["display_name"] = map[string]any{"state": "present", "value": "template-asserted-name"}
	if _, err := ProjectCloudNeutralResponse(positiveTemplate, listRaw); err == nil {
		t.Fatal("template asserted a positive provider fact")
	}
}

func assertStorageMapping(t *testing.T, target CloudSourceObjectTarget, source, destination string) {
	t.Helper()
	for _, field := range target.MappingContract.Fields {
		if field.SourceFieldID == source {
			if field.Disposition != CloudSourceMapsExactSourceFact || field.TargetField != destination || field.Projection != CloudMappingProjectionExact {
				t.Fatalf("%s must map exactly to %s: %#v", source, destination, field)
			}
			return
		}
	}
	t.Fatalf("missing mapping for %s", source)
}

func assertStorageUnsupported(t *testing.T, target CloudSourceObjectTarget, source string) {
	t.Helper()
	for _, field := range target.MappingContract.Fields {
		if field.SourceFieldID == source {
			if field.Disposition != CloudSourceUnsupported || field.TargetField != "" || field.Projection != "" {
				t.Fatalf("%s must remain explicitly unsupported until the neutral owner defines an exact field: %#v", source, field)
			}
			return
		}
	}
	t.Fatalf("missing mapping for %s", source)
}

func storageRecipe(catalog CloudCatalog, target CloudSourceObjectTarget, object, scope string, coverage CloudSyntheticCoverage, observation, continuation string, bindings []CloudNeutralScopedBinding) CloudNeutralProjectionRecipe {
	return CloudNeutralProjectionRecipe{Catalog: catalog, Target: &target, Contract: *target.MappingContract, ObjectPointer: object, IdentitySourcePointer: "/name", IdentitySourceFieldID: "name", ScopeReference: scope, ObservationState: observation, Coverage: coverage, ContinuationPointer: continuation, RecordTemplate: storageTemplate(), Bindings: bindings}
}

func storageTemplate() map[string]any {
	return map[string]any{
		"record_class":                            "storage_container",
		"display_name":                            cloudUnknown(),
		"scope_reference":                         cloudUnknown(),
		"location_class":                          cloudUnknown(),
		"lifecycle_state":                         cloudUnknown(),
		"observation_state":                       "observed",
		"versioning_state":                        cloudUnknown(),
		"encryption_configuration_observation":    cloudUnknown(),
		"public_access_configuration_observation": cloudUnknown(),
		"retention_state":                         cloudUnknown(),
	}
}

func assertStorageRecord(t *testing.T, raw []byte, name, identity string) {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record["semantic_record_instance_identity"] != identity {
		t.Fatalf("identity=%v want opaque %q", record["semantic_record_instance_identity"], identity)
	}
	for field, want := range map[string]string{"display_name": name} {
		envelope, ok := record[field].(map[string]any)
		if !ok || envelope["state"] != "present" || envelope["value"] != want {
			t.Fatalf("%s=%#v want present %q", field, record[field], want)
		}
	}
}
