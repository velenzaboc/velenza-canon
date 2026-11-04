package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestCloudCaseAWSS3NeutralV3DocumentsFiveFormerGaps keeps the successor
// document separate from the historical v2 package.  It checks that the
// document carries all four S3 response shapes while making only the five
// bounded, owner-named assertions added by this successor.
func TestCloudCaseAWSS3NeutralV3DocumentsFiveFormerGaps(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/neutral-v3/aws-s3.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Targets []CloudSourceObjectTarget `json:"targets"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Targets) != 4 {
		t.Fatalf("S3 v3 targets = %d, want four retained response shapes", len(document.Targets))
	}
	targets := make(map[string]CloudSourceObjectTarget, len(document.Targets))
	for _, target := range document.Targets {
		if target.ProviderID != "aws" || target.ServiceID != "s3" || target.APISurfaceID != "s3" || target.RecordClassSymbol != "storage_container" || targets[target.OperationID].OperationID != "" {
			t.Fatalf("invalid or repeated S3 v3 target: %#v", target)
		}
		targets[target.OperationID] = target
	}
	list := targets["com.amazonaws.s3#ListBuckets"]
	if list.OperationID == "" || !slices.Equal(list.StableIdentitySourceFields, []string{"Name"}) {
		t.Fatalf("ListBuckets stable identity changed: %#v", list.StableIdentitySourceFields)
	}
	assertS3V3Private(t, list.MappingContract, "/BucketArn", "The S3 ARN is a provider-specific external identifier.")
	region := assertS3V3Mapping(t, list.MappingContract, "/BucketRegion", "container_location_relationship", "relationship_reference")
	if region.Disposition != CloudSourceMapsExactRelationshipFact {
		t.Fatalf("BucketRegion must require an explicit scoped opaque location binding: %#v", region)
	}
	assertS3V3Evidence(t, list.MappingContract, "aws.s3.bucket-arn", 1187386, 1187988, "e57e52b3561b2679df93ce9b622c9aabcdcc2e4b07d82cbfbd4a39243942fb92")
	assertS3V3Evidence(t, list.MappingContract, "aws.s3.bucket-region", 1187013, 1187363, "ff5a8bcf475628607911fb7eed7d30e924b49996b410fc2b362bb04674f97ed2")

	versioning := targets["com.amazonaws.s3#GetBucketVersioning"]
	mfa := assertS3V3Mapping(t, versioning.MappingContract, "/MFADelete", "versioning_delete_authorization_protection_state", "evidence_closed_scalar")
	if mfa.ValueRecipe == nil || mfa.ValueRecipe.UnknownValuePolicy != "refuse" || mfa.ValueRecipe.SourceToNeutral["Enabled"] != "enabled" || mfa.ValueRecipe.SourceToNeutral["Disabled"] != "disabled" || len(mfa.ValueRecipe.SourceToNeutral) != 2 {
		t.Fatalf("MFA delete mapping is not a closed configuration state: %#v", mfa)
	}
	assertS3V3Evidence(t, versioning.MappingContract, "aws.s3.mfa-delete", 1876410, 1876856, "9923eb1126e3065ac4035a14cdbbd34b269c37b4d6bb9e17b5e4dc27aaa2d3e3")

	encryption := targets["com.amazonaws.s3#GetBucketEncryption"]
	key := assertS3V3Mapping(t, encryption.MappingContract, "/ServerSideEncryptionConfiguration/Rules/*/BucketKeyEnabled", "encryption_key_reuse_optimization_state", "bounded_one_evidence_closed_scalar")
	if key.ValueRecipe == nil || key.ValueRecipe.UnknownValuePolicy != "refuse" || key.ValueRecipe.SourceToNeutral["true"] != "enabled" || key.ValueRecipe.SourceToNeutral["false"] != "disabled" || len(key.ValueRecipe.SourceToNeutral) != 2 {
		t.Fatalf("BucketKeyEnabled mapping is not a closed optimization state: %#v", key)
	}
	blocked := assertS3V3Mapping(t, encryption.MappingContract, "/ServerSideEncryptionConfiguration/Rules/*/BlockedEncryptionTypes/EncryptionType/*", "encryption_mode_exclusion_policy", "typed_structure")
	if blocked.StructuredRecipe == nil || blocked.StructuredRecipe.Kind != "list" || blocked.StructuredRecipe.Item == nil || blocked.StructuredRecipe.Item.Kind != "enum" || len(blocked.StructuredRecipe.Item.Values) != 1 || blocked.StructuredRecipe.Item.Values["SSE-C"] != "customer_supplied_key" {
		t.Fatalf("blocked encryption policy must be a finite closed list: %#v", blocked)
	}
	assertS3V3Evidence(t, encryption.MappingContract, "aws.s3.bucket-key", 2823129, 2825086, "a1486418c4e5b35283586cb24cc41ab005421155e551dbace1c2e56d9efba776")
	assertS3V3Evidence(t, encryption.MappingContract, "aws.s3.blocked-encryption-types", 1183755, 1184443, "02acbcf410c75df3fbc85d180524de74fa524cec83632bb91492c9817ed2b276")

	for _, target := range document.Targets {
		for _, field := range cloudNeutralProjectionFields(*target.MappingContract) {
			if field.TargetField == "effective_encryption_state" || field.TargetField == "effective_security_state" || field.TargetField == "resolved_location" || field.TargetField == "semantic_record_instance_identity" {
				t.Fatalf("S3 v3 invented an effective, resolved, or identity fact: %#v", field)
			}
		}
	}
}

func TestCloudCaseAWSS3NeutralV3FixturesCarryOnlyConfiguredFacts(t *testing.T) {
	for name, required := range map[string][][]byte{
		"list-buckets-v3-identifiers.xml":             {[]byte("<BucketArn>arn:aws:s3:::fixture-log-bucket</BucketArn>"), []byte("<BucketRegion>us-east-1</BucketRegion>")},
		"get-bucket-versioning-mfa-enabled.xml":       {[]byte("<MfaDelete>Enabled</MfaDelete>")},
		"get-bucket-encryption-policy-configured.xml": {[]byte("<BucketKeyEnabled>true</BucketKeyEnabled>"), []byte("<EncryptionType>SSE-C</EncryptionType>")},
	} {
		raw := readCloudS3Fixture(t, name)
		for _, want := range required {
			if !bytes.Contains(raw, want) {
				t.Fatalf("%s lacks configured source fact %q", name, want)
			}
		}
		if bytes.Contains(raw, []byte("effective")) || bytes.Contains(raw, []byte("resolved")) {
			t.Fatalf("fixture %s contains an inferred result", name)
		}
	}
}

// TestCloudCaseAWSS3NeutralV3ProjectsBoundedSuccessors drives the successor
// through the same offline oracle as the historical S3 case.  The candidate
// is composed by the root entrypoint so its v3 owner/schema pins remain a
// separate authority from this service-specific test.
func TestCloudCaseAWSS3NeutralV3ProjectsBoundedSuccessors(t *testing.T) {
	request, catalog, targets := loadCloudS3V3Candidate(t)
	_ = request
	list := targets["com.amazonaws.s3#ListBuckets"]
	versioning := targets["com.amazonaws.s3#GetBucketVersioning"]
	encryption := targets["com.amazonaws.s3#GetBucketEncryption"]
	if list.MappingContract == nil || versioning.MappingContract == nil || encryption.MappingContract == nil {
		t.Fatal("v3 S3 candidate omitted a required mapping contract")
	}
	regionBinding := CloudNeutralScopedBinding{ScopeReference: "fixture-scope", ScopedNativeKey: "us-east-1", OpaqueNeutralID: "neutral-location-use1"}
	bucketBinding := CloudNeutralScopedBinding{ScopeReference: "fixture-scope", ScopedNativeKey: "fixture-log-bucket", OpaqueNeutralID: "neutral-bucket-log"}
	listRecipe := CloudNeutralProjectionRecipe{Catalog: catalog, Target: &list, Contract: *list.MappingContract, ObjectPointer: "/ListAllMyBucketsResult/Buckets/Bucket", IdentitySourcePointer: "/Name", IdentitySourceFieldID: "Name", ScopeReference: "fixture-scope", ObservationState: "incomplete", Coverage: CloudSyntheticCoveragePartial, RecordTemplate: s3V3Template(list.MappingContract.Neutral), Bindings: []CloudNeutralScopedBinding{bucketBinding, regionBinding}}
	listed, err := ProjectCloudNeutralResponse(listRecipe, readCloudS3Fixture(t, "list-buckets-v3-identifiers.xml"))
	if err != nil || len(listed.Records) != 1 {
		t.Fatalf("S3 v3 location projection = %#v, %v", listed, err)
	}
	assertS3V3RecordValue(t, listed.Records[0], "container_location_relationship", "neutral-location-use1")
	if bytes.Contains(listed.Records[0], []byte("arn:aws:")) || bytes.Contains(listed.Records[0], []byte("us-east-1")) {
		t.Fatalf("S3 v3 leaked raw ARN or region instead of scoped opaque relationship: %s", listed.Records[0])
	}
	missing := listRecipe
	missing.Bindings = []CloudNeutralScopedBinding{bucketBinding}
	if _, err := ProjectCloudNeutralResponse(missing, readCloudS3Fixture(t, "list-buckets-v3-identifiers.xml")); err == nil {
		t.Fatal("S3 v3 accepted location without a scoped opaque binding")
	}
	foreign := listRecipe
	foreign.Bindings = []CloudNeutralScopedBinding{bucketBinding, CloudNeutralScopedBinding{ScopeReference: "other-scope", ScopedNativeKey: "us-east-1", OpaqueNeutralID: "neutral-location-use1"}}
	if _, err := ProjectCloudNeutralResponse(foreign, readCloudS3Fixture(t, "list-buckets-v3-identifiers.xml")); err == nil {
		t.Fatal("S3 v3 accepted a foreign-scope location binding")
	}

	versionRecipe := CloudNeutralProjectionRecipe{Catalog: catalog, Target: &versioning, Contract: *versioning.MappingContract, ObjectPointer: "/VersioningConfiguration", ScopeReference: "fixture-scope", ObservationState: "observed", Coverage: CloudSyntheticCoverageComplete, RequestIdentity: &CloudNeutralRequestBinding{OperationID: versioning.OperationID, ResourceID: "com.amazonaws.s3#Bucket", ScopeReference: "fixture-scope", Parameters: map[string]string{"Bucket": "fixture-log-bucket"}}, RecordTemplate: s3V3Template(versioning.MappingContract.Neutral), Bindings: []CloudNeutralScopedBinding{bucketBinding}}
	versioned, err := ProjectCloudNeutralResponse(versionRecipe, readCloudS3Fixture(t, "get-bucket-versioning-mfa-enabled.xml"))
	if err != nil || len(versioned.Records) != 1 {
		t.Fatalf("S3 v3 MFA projection = %#v, %v", versioned, err)
	}
	assertS3V3RecordValue(t, versioned.Records[0], "versioning_delete_authorization_protection_state", "enabled")
	if _, err := ProjectCloudNeutralResponse(versionRecipe, []byte(`<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Future</MfaDelete></VersioningConfiguration>`)); err == nil {
		t.Fatal("S3 v3 accepted an unknown MFA-delete state")
	}

	encryptionRecipe := CloudNeutralProjectionRecipe{Catalog: catalog, Target: &encryption, Contract: *encryption.MappingContract, ObjectPointer: "/", ScopeReference: "fixture-scope", ObservationState: "observed", Coverage: CloudSyntheticCoverageComplete, RequestIdentity: &CloudNeutralRequestBinding{OperationID: encryption.OperationID, ResourceID: "com.amazonaws.s3#Bucket", ScopeReference: "fixture-scope", Parameters: map[string]string{"Bucket": "fixture-log-bucket"}}, RecordTemplate: s3V3Template(encryption.MappingContract.Neutral), Bindings: []CloudNeutralScopedBinding{bucketBinding}}
	encrypted, err := ProjectCloudNeutralResponse(encryptionRecipe, readCloudS3Fixture(t, "get-bucket-encryption-policy-configured.xml"))
	if err != nil || len(encrypted.Records) != 1 {
		t.Fatalf("S3 v3 encryption policy projection = %#v, %v", encrypted, err)
	}
	assertS3V3RecordValue(t, encrypted.Records[0], "encryption_key_reuse_optimization_state", "enabled")
	assertS3V3RecordValue(t, encrypted.Records[0], "encryption_mode_exclusion_policy", []any{"customer_supplied_key"})
	if _, err := ProjectCloudNeutralResponse(encryptionRecipe, []byte(`<ServerSideEncryptionConfiguration></ServerSideEncryptionConfiguration>`)); err == nil {
		t.Fatal("S3 v3 accepted zero encryption rules")
	}
	unknownMode := bytes.ReplaceAll(readCloudS3Fixture(t, "get-bucket-encryption-policy-configured.xml"), []byte("SSE-C"), []byte("FUTURE"))
	if _, err := ProjectCloudNeutralResponse(encryptionRecipe, unknownMode); err == nil {
		t.Fatal("S3 v3 accepted an unknown excluded encryption mode")
	}
	multipleRules := bytes.Replace(readCloudS3Fixture(t, "get-bucket-encryption-policy-configured.xml"), []byte("</Rule></ServerSideEncryptionConfiguration>"), []byte("</Rule><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>false</BucketKeyEnabled><BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>"), 1)
	if _, err := ProjectCloudNeutralResponse(encryptionRecipe, multipleRules); err == nil {
		t.Fatal("S3 v3 flattened policy from multiple encryption rules")
	}
}

func loadCloudS3V3Candidate(t *testing.T) (CloudSourceCandidateRequest, CloudCatalog, map[string]CloudSourceObjectTarget) {
	t.Helper()
	request, err := loadCloudNeutralV3Service(t, "aws", "s3")
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]CloudSourceObjectTarget{}
	var catalog CloudCatalog
	for _, target := range request.Targets {
		if target.ProviderID == "aws" && target.ServiceID == "s3" {
			targets[target.OperationID] = target
			var found bool
			catalog, found = findCloudCandidateCatalog(request.Catalogs, target)
			if !found {
				t.Fatal("v3 S3 catalog is absent")
			}
		}
	}
	if len(targets) != 4 {
		t.Fatalf("v3 S3 target count = %d, want four", len(targets))
	}
	return request, catalog, targets
}

func s3V3Template(schema CloudNeutralRecordSchema) map[string]any {
	template := make(map[string]any, len(schema.Fields))
	for _, field := range schema.Fields {
		if field.ID == "record_class" {
			template[field.ID] = schema.ClassSymbol
			continue
		}
		if field.ID == "observation_state" {
			template[field.ID] = "observed"
			continue
		}
		if field.ID == "semantic_record_instance_identity" || field.ID == "scope_reference" {
			// Projection sets both from opaque fixture bindings before record validation.
			continue
		}
		for _, state := range []string{"not_observed", "unknown"} {
			value := map[string]any{"state": state}
			if validateCloudJSONSchema(field.WireSchema, schema.definitions, value, map[string]bool{}) == nil {
				template[field.ID] = value
				break
			}
		}
		if _, found := template[field.ID]; !found {
			panic("v3 storage field lacks an unknown/not_observed arm: " + field.ID)
		}
	}
	return template
}

func assertS3V3RecordValue(t *testing.T, raw []byte, field string, want any) {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	got, ok := record[field].(map[string]any)
	actual, actualErr := json.Marshal(got["value"])
	expected, expectedErr := json.Marshal(want)
	if !ok || got["state"] != "present" || actualErr != nil || expectedErr != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("%s = %#v, want present %#v", field, record[field], want)
	}
}

func assertS3V3Mapping(t *testing.T, contract *CloudMappingContract, pointer, target string, projection CloudMappingProjection) CloudMappingContractField {
	t.Helper()
	if contract == nil {
		t.Fatal("S3 v3 target has no mapping contract")
	}
	for _, field := range cloudNeutralProjectionFields(*contract) {
		if field.SourcePointer == pointer {
			if (field.Disposition != CloudSourceMapsExactSourceFact && field.Disposition != CloudSourceMapsExactRelationshipFact) || field.TargetField != target || field.Projection != projection || field.SemanticOwnerRef == "" {
				t.Fatalf("S3 v3 mapping %s = %#v", pointer, field)
			}
			return field
		}
	}
	t.Fatalf("S3 v3 document misses mapping %s", pointer)
	return CloudMappingContractField{}
}

func assertS3V3Evidence(t *testing.T, contract *CloudMappingContract, id string, start, end int, digest string) {
	t.Helper()
	if contract == nil {
		t.Fatal("S3 v3 target has no mapping contract")
	}
	for _, evidence := range contract.EvidenceBindings {
		if evidence.ID == id {
			if evidence.SourcePath != "official/aws/s3-2006-03-01.json" || evidence.ExpectedSHA256 != "73e4f75747396176053a0fcc910261cf670c7e133c1cebcfffefa703fad3ce68" || evidence.StartByte != start || evidence.EndByte != end || evidence.SliceSHA256 != digest {
				t.Fatalf("S3 v3 evidence %s = %#v", id, evidence)
			}
			return
		}
	}
	t.Fatalf("S3 v3 document misses evidence %s", id)
}

func assertS3V3Private(t *testing.T, contract *CloudMappingContract, pointer, rationale string) {
	t.Helper()
	if contract == nil {
		t.Fatal("S3 v3 target has no mapping contract")
	}
	for _, field := range cloudNeutralProjectionFields(*contract) {
		if field.SourcePointer == pointer {
			if field.Disposition != CloudSourcePrivateOnly || field.PrivateReasonCode != "provider_internal" || !strings.Contains(field.PrivateSourceOnlyRationale, rationale) || field.TargetField != "" || field.Projection != "" {
				t.Fatalf("S3 v3 private boundary %s = %#v", pointer, field)
			}
			return
		}
	}
	t.Fatalf("S3 v3 document misses private boundary %s", pointer)
}
