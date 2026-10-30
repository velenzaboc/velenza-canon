package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestCloudCaseAWSS3ListBuckets is a bounded, offline acceptance case.  It
// deliberately loads the retained catalog and owner schema through the public
// candidate loader; the case data supplies no authority of its own.
func TestCloudCaseAWSS3ListBuckets(t *testing.T) {
	inputPath := "../../testdata/cloudapi/candidate-input.json"
	caseRaw, err := os.ReadFile("../../testdata/cloudapi/cases/aws-s3.json")
	if err != nil {
		t.Fatal(err)
	}
	var acceptance struct {
		Targets []json.RawMessage `json:"targets"`
	}
	if err := json.Unmarshal(caseRaw, &acceptance); err != nil || len(acceptance.Targets) != 1 {
		t.Fatalf("decode bounded S3 case: %v", err)
	}
	inputRaw, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(inputRaw, &input); err != nil {
		t.Fatal(err)
	}
	var targets []json.RawMessage
	if err := json.Unmarshal(input["targets"], &targets); err != nil {
		t.Fatal(err)
	}
	replaced := false
	for i, raw := range targets {
		var target struct {
			ProviderID string `json:"provider_id"`
			ServiceID  string `json:"service_id"`
		}
		if err := json.Unmarshal(raw, &target); err != nil {
			t.Fatal(err)
		}
		if target.ProviderID == "aws" && target.ServiceID == "s3" {
			targets[i] = acceptance.Targets[0]
			replaced = true
		}
	}
	if !replaced {
		t.Fatal("candidate input has no AWS S3 target to replace")
	}
	input["targets"], err = json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(inputPath), "aws-s3-acceptance-*.json")
	if err != nil {
		t.Fatal(err)
	}
	temporaryPath := temporary.Name()
	t.Cleanup(func() { _ = os.Remove(temporaryPath) })
	if _, err := temporary.Write(merged); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}

	request, err := LoadCloudSourceCandidateInput(temporaryPath, NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	var target CloudSourceObjectTarget
	var catalog CloudCatalog
	found := false
	for _, candidate := range request.Targets {
		if candidate.ProviderID == "aws" && candidate.ServiceID == "s3" {
			target = candidate
			catalog, found = findCloudCandidateCatalog(request.Catalogs, candidate)
			break
		}
	}
	if !found || target.MappingContract == nil {
		t.Fatal("loaded request has no S3 mapping contract/catalog")
	}
	if err := ValidateCloudMappingContract(catalog, *target.MappingContract); err != nil {
		t.Fatalf("real S3 catalog mapping: %v", err)
	}
	if fields, err := cloudCatalogObjectFields(catalog, target.SourceObjectType); err != nil || len(fields) != 4 {
		t.Fatalf("retained Bucket field roster = %d, %v; want all four fields", len(fields), err)
	}
	locator, err := CloudIdentityMemberEvidenceLocator(catalog, target.SourceObjectType, "Name")
	if err != nil || len(target.StableIdentityEvidence) != 1 || target.StableIdentityEvidence[0].Locator != locator {
		t.Fatalf("Name identity member locator is not exact: %v", err)
	}
	if !slices.Equal(target.StableIdentitySourceFields, []string{"Name"}) || len(target.IncarnationEvidenceFields) != 0 {
		t.Fatalf("S3 CreationDate or another mutable fact was made identity/incarnation evidence: %#v", target)
	}
	for _, field := range target.MappingContract.Fields {
		if field.SourceFieldID == "CreationDate" && field.Disposition != CloudSourceUnsupported {
			t.Fatalf("mutable CreationDate mapping = %#v, want unsupported", field)
		}
		if field.SourceFieldID == "BucketArn" && field.Disposition != CloudSourceUnsupported {
			t.Fatalf("general-purpose ListBuckets ARN mapping = %#v, want unsupported", field)
		}
	}

	recipe := CloudNeutralProjectionRecipe{
		Catalog: catalog, Target: &target, Contract: *target.MappingContract,
		ObjectPointer: "/ListAllMyBucketsResult/Buckets/Bucket", IdentitySourcePointer: "/Name", IdentitySourceFieldID: "Name",
		ScopeReference: "ohm-scope-aws-fixture", ObservationState: "incomplete", Coverage: CloudSyntheticCoveragePartial,
		ContinuationPointer: "/ListAllMyBucketsResult/ContinuationToken", RecordTemplate: cloudContainerTemplate(),
		Bindings: []CloudNeutralScopedBinding{
			{ScopeReference: "ohm-scope-aws-fixture", ScopedNativeKey: "fixture-log-bucket", OpaqueNeutralID: "ohm-storage-container-log"},
			{ScopeReference: "ohm-scope-aws-fixture", ScopedNativeKey: "fixture-archive-bucket", OpaqueNeutralID: "ohm-storage-container-archive"},
		},
	}
	page1 := readCloudS3Fixture(t, "list-buckets-page-1.xml")
	page2 := readCloudS3Fixture(t, "list-buckets-page-2.xml")
	first, err := ProjectCloudNeutralResponse(recipe, page1)
	if err != nil || len(first.Records) != 1 || first.Continuation != "fixture-page-2" || first.Coverage != CloudSyntheticCoveragePartial || first.DeletionAuthorized {
		t.Fatalf("page one projection = %#v, %v", first, err)
	}
	second, err := ProjectCloudNeutralResponse(recipe, page2)
	if err != nil || len(second.Records) != 1 || second.Continuation != "" || second.DeletionAuthorized {
		t.Fatalf("page two projection = %#v, %v", second, err)
	}
	assertS3NeutralRecord(t, target.MappingContract.Neutral, first.Records[0], "ohm-storage-container-log", "fixture-log-bucket")
	assertS3NeutralRecord(t, target.MappingContract.Neutral, second.Records[0], "ohm-storage-container-archive", "fixture-archive-bucket")

	changed, err := ProjectCloudNeutralResponse(recipe, readCloudS3Fixture(t, "list-buckets-mutable-creation-date.xml"))
	if err != nil || !bytes.Equal(first.Records[0], changed.Records[0]) {
		t.Fatalf("mutable CreationDate changed neutral record or failed: %s / %s, %v", first.Records, changed.Records, err)
	}
	empty, err := ProjectCloudNeutralResponse(recipe, []byte(`{"ListAllMyBucketsResult":{"Buckets":{"Bucket":[]}}}`))
	if err != nil || len(empty.Records) != 0 || empty.Coverage != CloudSyntheticCoveragePartial || empty.DeletionAuthorized {
		t.Fatalf("empty ListBuckets page was not legal partial evidence: %#v, %v", empty, err)
	}
	missing := recipe
	missing.Bindings = missing.Bindings[1:]
	if _, err := ProjectCloudNeutralResponse(missing, page1); err == nil {
		t.Fatal("unbound scoped S3 native key was accepted")
	}
	hostile := recipe
	hostile.RecordTemplate = cloudContainerTemplate()
	hostile.RecordTemplate["versioning_state"] = map[string]any{"state": "present", "value": "enabled"}
	if _, err := ProjectCloudNeutralResponse(hostile, page1); err == nil {
		t.Fatal("unmapped affirmative template fact was accepted")
	}
}

func readCloudS3Fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../../testdata/cloudapi/fixtures/aws", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertS3NeutralRecord(t *testing.T, schema CloudNeutralRecordSchema, raw []byte, wantID, wantName string) {
	t.Helper()
	if err := ValidateCloudNeutralRecordValue(schema, raw); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record["semantic_record_instance_identity"] != wantID {
		t.Fatalf("opaque identity = %#v, want %q", record["semantic_record_instance_identity"], wantID)
	}
	label, ok := record["display_name"].(map[string]any)
	if !ok || label["value"] != wantName {
		t.Fatalf("display label = %#v, want exact Name %q", record["display_name"], wantName)
	}
	if bytes.Contains(raw, []byte("CreationDate")) || bytes.Contains(raw, []byte("BucketArn")) {
		t.Fatalf("S3 ListBuckets record leaked unsupported source fields: %s", raw)
	}
}
