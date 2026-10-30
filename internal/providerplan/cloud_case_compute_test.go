package providerplan

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestCloudCaseGCPComputeOfflineAcceptance is intentionally fixture-only.  It
// replaces just the Compute targets in the ordinary retained candidate input,
// then evaluates the real Discovery model, owner-loaded schema, and captured
// aggregated responses.  In particular, it must not use a hand-built catalog
// with only the fields this case happens to project.
func TestCloudCaseGCPComputeOfflineAcceptance(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	caseRaw, err := os.ReadFile("../../testdata/cloudapi/cases/gcp-compute.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Targets []CloudSourceObjectTarget `json:"targets"`
	}
	if err := strictUnmarshal(caseRaw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases.Targets) != 2 {
		t.Fatalf("compute case targets=%d want 2", len(cases.Targets))
	}
	export, err := os.ReadFile("../../testdata/cloudapi/semantic-owner/infrastructure-resource-record-mapping-schema.export.json")
	if err != nil {
		t.Fatal(err)
	}
	compute := map[string]CloudSourceObjectTarget{}
	computeCatalog := map[string]CloudCatalog{}
	for _, target := range cases.Targets {
		if target.ProviderID != "gcp" || target.ServiceID != "compute" || target.MappingContract == nil {
			t.Fatalf("case target is not GCP Compute: %#v", target)
		}
		catalog, ok := findCloudCandidateCatalog(request.Catalogs, target)
		if !ok {
			t.Fatalf("case target %s lacks retained catalog", target.SourceObjectType)
		}
		neutral, loadErr := LoadCloudNeutralRecordSchema(export, cloudInfrastructureSchemaExportSHA256, target.RecordClassSymbol)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		target.MappingContract.Neutral = neutral
		if err := LoadCloudMappingEvidence("../../testdata/cloudapi", target.MappingContract); err != nil {
			t.Fatal(err)
		}
		// The target's private lookup key must use the exact model-member
		// locator calculated from the parser-retained original bytes.
		wantLocator, locatorErr := CloudIdentityMemberEvidenceLocator(catalog, target.SourceObjectType, "id")
		if locatorErr != nil || len(target.StableIdentityEvidence) != 1 || target.StableIdentityEvidence[0].Locator != wantLocator {
			t.Fatalf("%s identity locator is not exact: got=%#v want=%#v err=%v", target.SourceObjectType, target.StableIdentityEvidence, wantLocator, locatorErr)
		}
		if err := ValidateCloudSourceIdentityContract(target, catalog); err != nil {
			t.Fatalf("%s identity contract: %v", target.SourceObjectType, err)
		}
		if err := ValidateCloudMappingContract(catalog, *target.MappingContract); err != nil {
			t.Fatalf("%s complete retained model contract: %v", target.SourceObjectType, err)
		}
		compute[target.SourceObjectType] = target
		computeCatalog[target.SourceObjectType] = catalog
	}
	if len(compute) != 2 || compute["Instance"].MappingContract == nil || compute["Disk"].MappingContract == nil {
		t.Fatal("case did not provide exactly Instance and Disk contracts")
	}
	retainedTargets := make([]CloudSourceObjectTarget, 0, len(request.Targets))
	for _, target := range request.Targets {
		if target.ProviderID != "gcp" || target.ServiceID != "compute" {
			retainedTargets = append(retainedTargets, target)
		}
	}
	request.Targets = retainedTargets
	for _, target := range cases.Targets {
		request.Targets = append(request.Targets, compute[target.SourceObjectType])
	}

	instance := compute["Instance"]
	disk := compute["Disk"]
	for _, field := range instance.MappingContract.Fields {
		if field.SourceFieldID == "machineType" && (field.Disposition != CloudSourceUnsupported || field.TargetField != "") {
			t.Fatal("provider machineType URL must not be projected as neutral machine_class")
		}
	}
	instanceFixture, err := os.ReadFile("../../testdata/cloudapi/fixtures/gcp/compute-instances-aggregated.json")
	if err != nil {
		t.Fatal(err)
	}
	diskFixture, err := os.ReadFile("../../testdata/cloudapi/fixtures/gcp/compute-disks-aggregated.json")
	if err != nil {
		t.Fatal(err)
	}
	instanceRecipe := gcpComputeCaseRecipe(computeCatalog["Instance"], instance, "opaque-gcp-scope-us-central1-a", CloudSyntheticCoveragePartial, "/nextPageToken", []CloudNeutralScopedBinding{
		{ScopeReference: "opaque-gcp-scope-us-central1-a", ScopedNativeKey: "1001", OpaqueNeutralID: "opaque-instance-1001"},
	})
	diskRecipe := gcpComputeCaseRecipe(computeCatalog["Disk"], disk, "opaque-gcp-scope-us-central1-a", CloudSyntheticCoveragePartial, "", []CloudNeutralScopedBinding{
		{ScopeReference: "opaque-gcp-scope-us-central1-a", ScopedNativeKey: "2001", OpaqueNeutralID: "opaque-disk-2001"},
		// Disk.users carries an opaque provider URL.  The explicit scoped lookup
		// prevents that private URL being copied to the neutral relationship.
		{ScopeReference: "opaque-gcp-scope-us-central1-a", ScopedNativeKey: "https://compute.googleapis.com/compute/v1/projects/fixture-project/zones/us-central1-a/instances/fixture-instance", OpaqueNeutralID: "opaque-instance-1001"},
	})

	instanceResult, err := ProjectCloudNeutralResponse(instanceRecipe, instanceFixture)
	if err != nil || len(instanceResult.Records) != 1 || instanceResult.DeletionAuthorized || instanceResult.Continuation == "" {
		t.Fatalf("partial/unreachable aggregated instance response=%#v err=%v", instanceResult, err)
	}
	diskResult, err := ProjectCloudNeutralResponse(diskRecipe, diskFixture)
	if err != nil || len(diskResult.Records) != 1 || diskResult.DeletionAuthorized {
		t.Fatalf("partial/unreachable aggregated disk response=%#v err=%v", diskResult, err)
	}
	for _, got := range append(instanceResult.Records, diskResult.Records...) {
		if err := ValidateCloudNeutralRecordValue(gcpComputeCaseNeutral(got, instance, disk), got); err != nil {
			t.Fatalf("owner schema rejected projected record: %v: %s", err, got)
		}
		if bytes.Contains(got, []byte("https://compute.googleapis.com")) || bytes.Contains(got, []byte("fixture-project")) || bytes.Contains(got, []byte("\"1001\"")) || bytes.Contains(got, []byte("\"2001\"")) {
			t.Fatalf("provider-private URL leaked: %s", got)
		}
	}
	if !bytes.Contains(diskResult.Records[0], []byte(`"21474836480"`)) || !bytes.Contains(diskResult.Records[0], []byte(`"opaque-instance-1001"`)) {
		t.Fatalf("disk GiB conversion or attachment binding is wrong: %s", diskResult.Records[0])
	}

	terminatedFixture, err := os.ReadFile("../../testdata/cloudapi/fixtures/gcp/compute-instances-terminated.json")
	if err != nil {
		t.Fatal(err)
	}
	terminated := gcpComputeCaseRecipe(computeCatalog["Instance"], instance, "opaque-gcp-scope-us-central1-a", CloudSyntheticCoveragePartial, "", []CloudNeutralScopedBinding{{ScopeReference: "opaque-gcp-scope-us-central1-a", ScopedNativeKey: "1002", OpaqueNeutralID: "opaque-instance-1002"}})
	terminatedResult, err := ProjectCloudNeutralResponse(terminated, terminatedFixture)
	if err != nil || len(terminatedResult.Records) != 1 || terminatedResult.DeletionAuthorized || !bytes.Contains(terminatedResult.Records[0], []byte(`"stopped"`)) || bytes.Contains(terminatedResult.Records[0], []byte(`"terminated"`)) {
		t.Fatalf("TERMINATED must remain restartable stopped, never deleted: %#v err=%v", terminatedResult, err)
	}

	// Empty list and a >1 users array are both fail-closed: neither authorizes
	// deletion, and a volume with ambiguous attachment is not projected.
	empty := []byte(`{"kind":"compute#diskAggregatedList","items":{"zones/us-central1-a":{"disks":[]},"zones/us-central1-b":{"warning":{"code":"UNREACHABLE"}}}}`)
	if result, emptyErr := ProjectCloudNeutralResponse(diskRecipe, empty); emptyErr != nil || len(result.Records) != 0 || result.DeletionAuthorized {
		t.Fatalf("empty partial aggregated response=%#v err=%v", result, emptyErr)
	}
	multiple := bytes.Replace(diskFixture, []byte(`"users":["https://compute.googleapis.com/compute/v1/projects/fixture-project/zones/us-central1-a/instances/fixture-instance"]`), []byte(`"users":["one","two"]`), 1)
	if _, multipleErr := ProjectCloudNeutralResponse(diskRecipe, multiple); multipleErr == nil {
		t.Fatal("multiple disk attachments were accepted")
	}
	unresolved := bytes.Replace(diskFixture, []byte("fixture-instance"), []byte("unbound-instance"), 1)
	if _, unresolvedErr := ProjectCloudNeutralResponse(diskRecipe, unresolved); unresolvedErr == nil {
		t.Fatal("unresolved disk attachment was accepted")
	}
}

func gcpComputeCaseRecipe(catalog CloudCatalog, target CloudSourceObjectTarget, scope string, coverage CloudSyntheticCoverage, continuation string, bindings []CloudNeutralScopedBinding) CloudNeutralProjectionRecipe {
	template := cloudInstanceTemplate()
	if target.SourceObjectType == "Disk" {
		template = cloudVolumeTemplate()
	}
	return CloudNeutralProjectionRecipe{
		Catalog: catalog, Target: &target, Contract: *target.MappingContract,
		ObjectPointer: "/items/*/" + strings.ToLower(target.SourceObjectType) + "s", IdentitySourcePointer: "/id", IdentitySourceFieldID: "id",
		ScopeReference: scope, ObservationState: "incomplete", Coverage: coverage, ContinuationPointer: continuation,
		RecordTemplate: template, Bindings: bindings,
	}
}

func gcpComputeCaseNeutral(record []byte, instance, disk CloudSourceObjectTarget) CloudNeutralRecordSchema {
	if bytes.Contains(record, []byte(`"compute_volume"`)) {
		return disk.MappingContract.Neutral
	}
	return instance.MappingContract.Neutral
}
