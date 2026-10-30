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
	if err := json.Unmarshal(caseRaw, &acceptance); err != nil || len(acceptance.Targets) != 4 {
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
	filtered := make([]json.RawMessage, 0, len(targets)+len(acceptance.Targets))
	for _, raw := range targets {
		var target struct {
			ProviderID string `json:"provider_id"`
			ServiceID  string `json:"service_id"`
		}
		if err := json.Unmarshal(raw, &target); err != nil {
			t.Fatal(err)
		}
		if target.ProviderID == "aws" && target.ServiceID == "s3" {
			replaced = true
			continue
		}
		filtered = append(filtered, raw)
	}
	if !replaced {
		t.Fatal("candidate input has no AWS S3 target to replace")
	}
	filtered = append(filtered, acceptance.Targets...)
	input["targets"], err = json.Marshal(filtered)
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
	var target, versioningTarget, encryptionTarget, publicBlockTarget CloudSourceObjectTarget
	var catalog CloudCatalog
	found := false
	for _, candidate := range request.Targets {
		if candidate.ProviderID == "aws" && candidate.ServiceID == "s3" {
			if candidate.OperationID == "com.amazonaws.s3#ListBuckets" {
				target = candidate
				catalog, found = findCloudCandidateCatalog(request.Catalogs, candidate)
			}
			if candidate.OperationID == "com.amazonaws.s3#GetBucketVersioning" {
				versioningTarget = candidate
			}
			if candidate.OperationID == "com.amazonaws.s3#GetBucketEncryption" {
				encryptionTarget = candidate
			}
			if candidate.OperationID == "com.amazonaws.s3#GetPublicAccessBlock" {
				publicBlockTarget = candidate
			}
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
		if field.SourceFieldID == "CreationDate" && (field.TargetField != "reported_creation_time" || field.Projection != CloudMappingProjectionExactRFC3339) {
			t.Fatalf("mutable CreationDate must be report-only exact time, never identity: %#v", field)
		}
		if field.SourceFieldID == "BucketArn" && field.Disposition != CloudSourceUnsupported {
			t.Fatalf("general-purpose ListBuckets ARN mapping = %#v, want unsupported", field)
		}
	}

	recipe := CloudNeutralProjectionRecipe{
		Catalog: catalog, Target: &target, Contract: *target.MappingContract,
		ObjectPointer: "/ListAllMyBucketsResult/Buckets/Bucket", IdentitySourcePointer: "/Name", IdentitySourceFieldID: "Name",
		ScopeReference: "ohm-scope-aws-fixture", ObservationState: "incomplete", Coverage: CloudSyntheticCoveragePartial,
		ContinuationPointer: "/ListAllMyBucketsResult/ContinuationToken", RecordTemplate: storageTemplate(),
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
	assertS3NeutralRecord(t, target.MappingContract.Neutral, first.Records[0], "ohm-storage-container-log", "fixture-log-bucket", "2026-01-02T03:04:05.000Z")
	assertS3NeutralRecord(t, target.MappingContract.Neutral, second.Records[0], "ohm-storage-container-archive", "fixture-archive-bucket", "2026-01-03T03:04:05.000Z")

	changed, err := ProjectCloudNeutralResponse(recipe, readCloudS3Fixture(t, "list-buckets-mutable-creation-date.xml"))
	if err != nil || bytes.Equal(first.Records[0], changed.Records[0]) {
		t.Fatalf("mutable CreationDate must update only report time: %s / %s, %v", first.Records, changed.Records, err)
	}
	assertS3NeutralRecord(t, target.MappingContract.Neutral, changed.Records[0], "ohm-storage-container-log", "fixture-log-bucket", "2026-02-03T04:05:06.000Z")
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
	hostile.RecordTemplate = storageTemplate()
	hostile.RecordTemplate["versioning_state"] = map[string]any{"state": "present", "value": "enabled"}
	if _, err := ProjectCloudNeutralResponse(hostile, page1); err == nil {
		t.Fatal("unmapped affirmative template fact was accepted")
	}

	if versioningTarget.MappingContract == nil {
		t.Fatal("loaded request has no request-bound S3 versioning target")
	}
	if err := ValidateCloudMappingContract(catalog, *versioningTarget.MappingContract); err != nil {
		t.Fatalf("real S3 GetBucketVersioning mapping: %v", err)
	}
	versioning := CloudNeutralProjectionRecipe{
		Catalog: catalog, Target: &versioningTarget, Contract: *versioningTarget.MappingContract,
		ObjectPointer: "/VersioningConfiguration", ScopeReference: "ohm-scope-aws-fixture", ObservationState: "observed", Coverage: CloudSyntheticCoverageComplete,
		RequestIdentity: &CloudNeutralRequestBinding{OperationID: "com.amazonaws.s3#GetBucketVersioning", ResourceID: "com.amazonaws.s3#Bucket", ScopeReference: "ohm-scope-aws-fixture", Parameters: map[string]string{"Bucket": "fixture-log-bucket"}},
		RecordTemplate:  storageTemplate(), Bindings: []CloudNeutralScopedBinding{{ScopeReference: "ohm-scope-aws-fixture", ScopedNativeKey: "fixture-log-bucket", OpaqueNeutralID: "ohm-storage-container-log"}},
	}
	versioned, err := ProjectCloudNeutralResponse(versioning, readCloudS3Fixture(t, "get-bucket-versioning-enabled.xml"))
	if err != nil || len(versioned.Records) != 1 || versioned.DeletionAuthorized {
		t.Fatalf("request-bound versioning projection = %#v, %v", versioned, err)
	}
	assertS3VersioningRecord(t, versioningTarget.MappingContract.Neutral, versioned.Records[0], "ohm-storage-container-log", "enabled")
	suspended, err := ProjectCloudNeutralResponse(versioning, readCloudS3Fixture(t, "get-bucket-versioning-suspended.xml"))
	if err != nil || len(suspended.Records) != 1 {
		t.Fatalf("suspended versioning projection = %#v, %v", suspended, err)
	}
	assertS3VersioningRecord(t, versioningTarget.MappingContract.Neutral, suspended.Records[0], "ohm-storage-container-log", "suspended")
	badRequest := versioning
	badRequest.RequestIdentity = &CloudNeutralRequestBinding{OperationID: "com.amazonaws.s3#ListBuckets", ResourceID: "com.amazonaws.s3#Bucket", ScopeReference: "ohm-scope-aws-fixture", Parameters: map[string]string{"Bucket": "fixture-log-bucket"}}
	if _, err := ProjectCloudNeutralResponse(badRequest, readCloudS3Fixture(t, "get-bucket-versioning-enabled.xml")); err == nil {
		t.Fatal("cross-operation request identity was accepted")
	}
	if _, err := ProjectCloudNeutralResponse(versioning, []byte(`<VersioningConfiguration><Status>Future</Status></VersioningConfiguration>`)); err == nil {
		t.Fatal("unknown S3 versioning value was accepted")
	}
	if encryptionTarget.MappingContract == nil {
		t.Fatal("loaded request has no request-bound S3 encryption target")
	}
	encryption := CloudNeutralProjectionRecipe{Catalog: catalog, Target: &encryptionTarget, Contract: *encryptionTarget.MappingContract, ObjectPointer: "/", ScopeReference: "ohm-scope-aws-fixture", ObservationState: "observed", Coverage: CloudSyntheticCoverageComplete, RequestIdentity: &CloudNeutralRequestBinding{OperationID: "com.amazonaws.s3#GetBucketEncryption", ResourceID: "com.amazonaws.s3#Bucket", ScopeReference: "ohm-scope-aws-fixture", Parameters: map[string]string{"Bucket": "fixture-log-bucket"}}, RecordTemplate: storageTemplate(), Bindings: []CloudNeutralScopedBinding{{ScopeReference: "ohm-scope-aws-fixture", ScopedNativeKey: "fixture-log-bucket", OpaqueNeutralID: "ohm-storage-container-log"}}}
	encrypted, err := ProjectCloudNeutralResponse(encryption, readCloudS3Fixture(t, "get-bucket-encryption-configured.xml"))
	if err != nil || len(encrypted.Records) != 1 || encrypted.DeletionAuthorized {
		t.Fatalf("request-bound encryption projection=%#v err=%v", encrypted, err)
	}
	if err := ValidateCloudNeutralRecordValue(encryptionTarget.MappingContract.Neutral, encrypted.Records[0]); err != nil {
		t.Fatal(err)
	}
	assertS3FieldPresent(t, encrypted.Records[0], "encryption_configuration_observation", "configured")
	if _, err := ProjectCloudNeutralResponse(encryption, []byte(`<ServerSideEncryptionConfiguration><Rule></Rule></ServerSideEncryptionConfiguration>`)); err == nil {
		t.Fatal("zero encryption rules were accepted")
	}
	if _, err := ProjectCloudNeutralResponse(encryption, []byte(`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)); err == nil {
		t.Fatal("multiple encryption rules were accepted")
	}
	if _, err := ProjectCloudNeutralResponse(encryption, []byte(`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>future</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)); err == nil {
		t.Fatal("unknown encryption algorithm was accepted")
	}
	if publicBlockTarget.MappingContract == nil {
		t.Fatal("loaded request has no request-bound S3 public-access-block target")
	}
	publicBlock := CloudNeutralProjectionRecipe{Catalog: catalog, Target: &publicBlockTarget, Contract: *publicBlockTarget.MappingContract, ObjectPointer: "/", ScopeReference: "ohm-scope-aws-fixture", ObservationState: "observed", Coverage: CloudSyntheticCoverageComplete, RequestIdentity: &CloudNeutralRequestBinding{OperationID: "com.amazonaws.s3#GetPublicAccessBlock", ResourceID: "com.amazonaws.s3#Bucket", ScopeReference: "ohm-scope-aws-fixture", Parameters: map[string]string{"Bucket": "fixture-log-bucket"}}, RecordTemplate: storageTemplate(), Bindings: []CloudNeutralScopedBinding{{ScopeReference: "ohm-scope-aws-fixture", ScopedNativeKey: "fixture-log-bucket", OpaqueNeutralID: "ohm-storage-container-log"}}}
	blocked, err := ProjectCloudNeutralResponse(publicBlock, readCloudS3Fixture(t, "get-public-access-block-configured.xml"))
	if err != nil || len(blocked.Records) != 1 || blocked.DeletionAuthorized {
		t.Fatalf("request-bound public-block projection=%#v err=%v", blocked, err)
	}
	if err := ValidateCloudNeutralRecordValue(publicBlockTarget.MappingContract.Neutral, blocked.Records[0]); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"public_acl_block_state", "public_acl_ignore_state", "public_policy_block_state", "public_policy_restriction_state"} {
		assertS3FieldPresent(t, blocked.Records[0], field, "enabled")
	}
	unblocked, err := ProjectCloudNeutralResponse(publicBlock, bytes.ReplaceAll(readCloudS3Fixture(t, "get-public-access-block-configured.xml"), []byte(">true<"), []byte(">false<")))
	if err != nil || len(unblocked.Records) != 1 || unblocked.DeletionAuthorized {
		t.Fatalf("explicit false configuration projection=%#v err=%v", unblocked, err)
	}
	for _, field := range []string{"public_acl_block_state", "public_acl_ignore_state", "public_policy_block_state", "public_policy_restriction_state"} {
		assertS3FieldPresent(t, unblocked.Records[0], field, "disabled")
	}
	if bytes.Contains(blocked.Records[0], []byte("effective_")) || bytes.Contains(blocked.Records[0], []byte("public_outcome")) {
		t.Fatalf("public-block configuration was misrepresented as an effective exposure outcome: %s", blocked.Records[0])
	}
	for _, malformed := range []string{"1", "TRUE", " true "} {
		raw := []byte(`<PublicAccessBlockConfiguration><BlockPublicAcls>` + malformed + `</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`)
		if _, err := ProjectCloudNeutralResponse(publicBlock, raw); err == nil {
			t.Fatalf("coerced XML boolean %q was accepted", malformed)
		}
	}
	for _, candidate := range request.Targets {
		if candidate.ProviderID == "aws" && candidate.ServiceID == "s3" && candidate.OperationID == "com.amazonaws.s3#GetBucketPolicyStatus" {
			t.Fatal("GetBucketPolicyStatus must not become a semantic exposure target")
		}
		if candidate.MappingContract != nil {
			for _, field := range cloudNeutralProjectionFields(*candidate.MappingContract) {
				if field.TargetField == "effective_public_exposure" || field.TargetField == "public_outcome" {
					t.Fatalf("S3 target asserted an unowned effective exposure field: %#v", field)
				}
			}
		}
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

func assertS3NeutralRecord(t *testing.T, schema CloudNeutralRecordSchema, raw []byte, wantID, wantName, wantCreated string) {
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
	created, ok := record["reported_creation_time"].(map[string]any)
	if !ok || created["state"] != "present" || created["value"] != wantCreated {
		t.Fatalf("reported CreationDate = %#v, want %q", record["reported_creation_time"], wantCreated)
	}
	if bytes.Contains(raw, []byte("CreationDate")) || bytes.Contains(raw, []byte("BucketArn")) {
		t.Fatalf("S3 ListBuckets record leaked unsupported source fields: %s", raw)
	}
}

func assertS3VersioningRecord(t *testing.T, schema CloudNeutralRecordSchema, raw []byte, wantID, wantState string) {
	t.Helper()
	if err := ValidateCloudNeutralRecordValue(schema, raw); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record["semantic_record_instance_identity"] != wantID {
		t.Fatalf("request-bound identity=%#v want %q", record["semantic_record_instance_identity"], wantID)
	}
	state, ok := record["versioning_state"].(map[string]any)
	if !ok || state["state"] != "present" || state["value"] != wantState {
		t.Fatalf("versioning state=%#v want %q", record["versioning_state"], wantState)
	}
}

func assertS3FieldPresent(t *testing.T, raw []byte, field, want string) {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	v, ok := record[field].(map[string]any)
	if !ok || v["state"] != "present" || v["value"] != want {
		t.Fatalf("%s=%#v want present %q", field, record[field], want)
	}
}
