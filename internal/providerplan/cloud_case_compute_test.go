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

	// Empty list is partial-safe and never authorizes deletion. The expanded
	// owner collection preserves a genuine multi-attachment only when every
	// private native URL has an explicit scoped opaque binding.
	empty := []byte(`{"kind":"compute#diskAggregatedList","items":{"zones/us-central1-a":{"disks":[]},"zones/us-central1-b":{"warning":{"code":"UNREACHABLE"}}}}`)
	if result, emptyErr := ProjectCloudNeutralResponse(diskRecipe, empty); emptyErr != nil || len(result.Records) != 0 || result.DeletionAuthorized {
		t.Fatalf("empty partial aggregated response=%#v err=%v", result, emptyErr)
	}
	zeroUsers := bytes.Replace(diskFixture, []byte(`"users":["https://compute.googleapis.com/compute/v1/projects/fixture-project/zones/us-central1-a/instances/fixture-instance"]`), []byte(`"users":[]`), 1)
	zeroResult, zeroErr := ProjectCloudNeutralResponse(diskRecipe, zeroUsers)
	if zeroErr != nil || len(zeroResult.Records) != 1 || !bytes.Contains(zeroResult.Records[0], []byte(`"value":[]`)) || zeroResult.DeletionAuthorized {
		t.Fatalf("zero disk attachments were not preserved as observed empty collection: %#v err=%v", zeroResult, zeroErr)
	}
	multiple := bytes.Replace(diskFixture, []byte(`"users":["https://compute.googleapis.com/compute/v1/projects/fixture-project/zones/us-central1-a/instances/fixture-instance"]`), []byte(`"users":["https://compute.googleapis.com/compute/v1/projects/fixture-project/zones/us-central1-a/instances/one","https://compute.googleapis.com/compute/v1/projects/fixture-project/zones/us-central1-a/instances/two"]`), 1)
	multipleRecipe := diskRecipe
	multipleRecipe.Bindings = append(multipleRecipe.Bindings,
		CloudNeutralScopedBinding{ScopeReference: "opaque-gcp-scope-us-central1-a", ScopedNativeKey: "https://compute.googleapis.com/compute/v1/projects/fixture-project/zones/us-central1-a/instances/one", OpaqueNeutralID: "opaque-instance-one"},
		CloudNeutralScopedBinding{ScopeReference: "opaque-gcp-scope-us-central1-a", ScopedNativeKey: "https://compute.googleapis.com/compute/v1/projects/fixture-project/zones/us-central1-a/instances/two", OpaqueNeutralID: "opaque-instance-two"},
	)
	multipleResult, multipleErr := ProjectCloudNeutralResponse(multipleRecipe, multiple)
	if multipleErr != nil || len(multipleResult.Records) != 1 || !bytes.Contains(multipleResult.Records[0], []byte(`"opaque-instance-one"`)) || !bytes.Contains(multipleResult.Records[0], []byte(`"opaque-instance-two"`)) {
		t.Fatalf("bound multiple disk attachments were not projected as a collection: %#v err=%v", multipleResult, multipleErr)
	}
	unresolved := bytes.Replace(diskFixture, []byte("fixture-instance"), []byte("unbound-instance"), 1)
	if _, unresolvedErr := ProjectCloudNeutralResponse(diskRecipe, unresolved); unresolvedErr == nil {
		t.Fatal("unresolved disk attachment was accepted")
	}

	// Expanded fixtures exercise only source-neutral facts with direct owner
	// meaning: descriptions, report timestamps, complete lifecycle enum values,
	// capacity and scoped relationships. Provider URLs, machine SKUs and KMS
	// key material remain private even when present in the wire response.
	expandedInstance, err := os.ReadFile("../../testdata/cloudapi/fixtures/gcp/compute-instances-expanded-aggregated.json")
	if err != nil {
		t.Fatal(err)
	}
	expandedDisk, err := os.ReadFile("../../testdata/cloudapi/fixtures/gcp/compute-disks-expanded-aggregated.json")
	if err != nil {
		t.Fatal(err)
	}
	expandedInstanceRecipe := gcpComputeCaseRecipe(computeCatalog["Instance"], instance, "opaque-gcp-scope-us-central1-a", CloudSyntheticCoveragePartial, "", []CloudNeutralScopedBinding{{ScopeReference: "opaque-gcp-scope-us-central1-a", ScopedNativeKey: "1101", OpaqueNeutralID: "opaque-instance-1101"}})
	expandedDiskRecipe := gcpComputeCaseRecipe(computeCatalog["Disk"], disk, "opaque-gcp-scope-us-central1-a", CloudSyntheticCoveragePartial, "", []CloudNeutralScopedBinding{
		{ScopeReference: "opaque-gcp-scope-us-central1-a", ScopedNativeKey: "2101", OpaqueNeutralID: "opaque-disk-2101"},
		{ScopeReference: "opaque-gcp-scope-us-central1-a", ScopedNativeKey: "https://compute.googleapis.com/compute/v1/projects/fixture-project/zones/us-central1-a/instances/fixture-expanded-instance", OpaqueNeutralID: "opaque-instance-1101"},
	})
	expandedInstanceResult, err := ProjectCloudNeutralResponse(expandedInstanceRecipe, expandedInstance)
	if err != nil || len(expandedInstanceResult.Records) != 1 {
		t.Fatalf("expanded instance projection=%#v err=%v", expandedInstanceResult, err)
	}
	expandedDiskResult, err := ProjectCloudNeutralResponse(expandedDiskRecipe, expandedDisk)
	if err != nil || len(expandedDiskResult.Records) != 1 {
		t.Fatalf("expanded disk projection=%#v err=%v", expandedDiskResult, err)
	}
	instanceRecord := expandedInstanceResult.Records[0]
	diskRecord := expandedDiskResult.Records[0]
	for _, record := range [][]byte{instanceRecord, diskRecord} {
		if err := ValidateCloudNeutralRecordValue(gcpComputeCaseNeutral(record, instance, disk), record); err != nil {
			t.Fatalf("expanded owner-valid record: %v: %s", err, record)
		}
		if bytes.Contains(record, []byte("https://compute.googleapis.com")) || bytes.Contains(record, []byte("fixture-kms")) || bytes.Contains(record, []byte("n2-standard-4")) {
			t.Fatalf("expanded projection leaked provider-private URL/SKU/key reference: %s", record)
		}
	}
	for _, want := range []string{`"offline expanded Compute Engine instance"`, `"2026-10-30T12:34:56.789Z"`, `"stopping"`} {
		if !bytes.Contains(instanceRecord, []byte(want)) {
			t.Fatalf("expanded instance omitted %s: %s", want, instanceRecord)
		}
	}
	for _, want := range []string{`"offline expanded persistent disk"`, `"2026-10-30T12:00:00Z"`, `"68719476736"`, `"opaque-instance-1101"`} {
		if !bytes.Contains(diskRecord, []byte(want)) {
			t.Fatalf("expanded disk omitted %s: %s", want, diskRecord)
		}
	}
	badTimestamp := bytes.Replace(expandedInstance, []byte(`"2026-10-30T12:34:56.789Z"`), []byte(`"not-rfc3339"`), 1)
	if _, timestampErr := ProjectCloudNeutralResponse(expandedInstanceRecipe, badTimestamp); timestampErr == nil {
		t.Fatal("malformed RFC3339 source timestamp was accepted")
	}
	for source, neutral := range map[string]string{
		"PENDING": "provisioning", "PENDING_STOP": "stopping", "PROVISIONING": "provisioning", "REPAIRING": "repairing",
		"RUNNING": "running", "STAGING": "provisioning", "STOPPED": "stopped", "STOPPING": "stopping",
		"SUSPENDED": "suspended", "SUSPENDING": "suspending", "TERMINATED": "stopped",
	} {
		variant := bytes.Replace(expandedInstance, []byte(`"status": "STOPPING"`), []byte(`"status": "`+source+`"`), 1)
		result, lifecycleErr := ProjectCloudNeutralResponse(expandedInstanceRecipe, variant)
		if lifecycleErr != nil || len(result.Records) != 1 || !bytes.Contains(result.Records[0], []byte(`"`+neutral+`"`)) {
			t.Fatalf("lifecycle %s -> %s rejected: %#v err=%v", source, neutral, result, lifecycleErr)
		}
	}
	deprovisioning := bytes.Replace(expandedInstance, []byte(`"status": "STOPPING"`), []byte(`"status": "DEPROVISIONING"`), 1)
	if _, lifecycleErr := ProjectCloudNeutralResponse(expandedInstanceRecipe, deprovisioning); lifecycleErr == nil {
		t.Fatal("DEPROVISIONING was projected without a primary lifecycle meaning")
	}
}

func gcpComputeCaseRecipe(catalog CloudCatalog, target CloudSourceObjectTarget, scope string, coverage CloudSyntheticCoverage, continuation string, bindings []CloudNeutralScopedBinding) CloudNeutralProjectionRecipe {
	template := cloudInstanceTemplate()
	if target.SourceObjectType == "Disk" {
		template = cloudVolumeTemplate()
		delete(template, "attached_compute_instance_reference")
		template["attached_compute_instance_references"] = cloudUnknown()
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
