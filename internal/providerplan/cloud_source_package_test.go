package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCloudCandidateLocalPathAcceptsPortableSlashAndRefusesEscape(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "official"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "official", "model.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := cloudCandidateLocalPath(root, "official/model.json")
	if err != nil || got != filepath.Join(root, "official", "model.json") {
		t.Fatalf("portable slash path = %q, %v", got, err)
	}
	for _, value := range []string{"../model.json", "official\\model.json", "/model.json", "official/../model.json", "C:model.json", "C:/model.json"} {
		if _, err := cloudCandidateLocalPath(root, value); err == nil {
			t.Fatalf("accepted unsafe path %q", value)
		}
	}
}

func TestCloudAPIGraphCandidateRetainsNestedProvenanceAndClosesOperations(t *testing.T) {
	locator := CloudCatalogEvidenceLocator{EvidenceID: "model", JSONPointer: "/x", StartByte: 1, EndByte: 2}
	declaration := CloudCatalogEvidenceLocator{EvidenceID: "supplement", JSONPointer: "/declaration", StartByte: 3, EndByte: 4}
	association := CloudCatalogEvidenceLocator{EvidenceID: "supplement", JSONPointer: "/association", StartByte: 5, EndByte: 6}
	catalog := CloudCatalog{Format: CloudCatalogFormatSmithyJSON, Source: CloudCatalogSourceIdentity{ID: "source-id", URI: "urn:test", StableCoordinate: "stable", FormatRevision: "2"}, ProviderID: "aws", ServiceID: "svc", APISurfaceID: "svc", APIVersion: "1", ModelSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ProtocolBindings: []CloudCatalogProtocolBinding{{ID: "aws.protocols#restXml", Status: "documented_supported", Locators: []CloudCatalogEvidenceLocator{locator}}}, Resources: []CloudCatalogResource{{ID: "Thing", OperationIDs: []string{"Read", "Write"}, Locator: locator, DeclarationStatus: "asserted_candidate_unqualified", DeclarationEvidenceLocator: &declaration}}, Operations: []CloudCatalogOperation{{ID: "Read", ResourceIDs: []string{"Thing"}, Locator: locator, AssociationStatus: "asserted_candidate_unqualified", ResourceAssociationEvidence: []CloudCatalogResourceAssociationEvidence{{ResourceID: "Thing", EvidenceLocator: association}}}, {ID: "Write", ResourceIDs: []string{"Thing"}, Locator: locator, AssociationStatus: "asserted_candidate_unqualified"}}, SchemaShapes: []CloudCatalogSchemaShape{{ID: "Thing", DeclaredType: "structure", Locator: locator}}}
	target := CloudSourceObjectTarget{ProviderID: "aws", ServiceID: "svc", APISurfaceID: "svc", OperationID: "Read", MappingContract: &CloudMappingContract{ObjectSchemaID: "Thing"}}
	raw, err := canonicalFactoryJSON(makeCloudAPIGraphCandidate([]CloudCatalog{catalog}, []CloudSourceObjectTarget{target}))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	var resource, operation map[string]any
	for _, row := range body.Rows {
		if row["row_kind"] == "cloud_api_resource" {
			resource = row
		}
		if row["row_kind"] == "cloud_api_operation" {
			operation = row
		}
	}
	if resource == nil || operation == nil {
		t.Fatal("selected rows absent")
	}
	if resource["source"].(map[string]any)["id"] != "source-id" || resource["model_sha256"] != catalog.ModelSHA256 || len(resource["protocol_bindings"].([]any)) != 1 || resource["declaration_evidence_locator"].(map[string]any)["json_pointer"] != "/declaration" {
		t.Fatalf("resource provenance lost: %#v", resource)
	}
	if ids := resource["operation_ids"].([]any); len(ids) != 1 || ids[0] != "Read" {
		t.Fatalf("unselected operation leaked: %#v", ids)
	}
	if got := operation["resource_association_evidence"].([]any); len(got) != 1 || got[0].(map[string]any)["evidence_locator"].(map[string]any)["json_pointer"] != "/association" {
		t.Fatalf("association provenance lost: %#v", operation)
	}
}

func TestBuildCloudSourceCandidateBundleDeterministicAndCandidateOnly(t *testing.T) {
	catalog := cloudSourcePackageTestCatalog()
	target := cloudSourcePackageTestTarget()
	if _, err := BuildCloudSourceCandidateBundle(CloudSourceCandidateRequest{Catalogs: []CloudCatalog{catalog}, Targets: []CloudSourceObjectTarget{target}}); err == nil {
		t.Fatal("target without exact IRR/schema mapping contract accepted")
	}
}

func TestProjectCloudSyntheticResponseXMLAndCheckedGiBCapacity(t *testing.T) {
	target := cloudSourcePackageTestTarget()
	target.FieldMappings = []CloudSourceFieldMapping{{SourceSchemaID: "Instance", SourceFieldID: "id", SourcePointer: "/Root/ID", DeclaredType: "string", Disposition: CloudSourceMapsExactSourceFact, TargetField: "display_name", Cardinality: "one"}}
	projected, err := ProjectCloudSyntheticResponse(target, []byte(`<Root><ID>i-1</ID></Root>`), CloudSyntheticCoveragePartial)
	if err != nil || len(projected.Fields) != 1 || projected.Fields[0].State != "present" || string(projected.Fields[0].Value) != `"i-1"` {
		t.Fatalf("XML projection = %#v, %v", projected, err)
	}
	for _, value := range []any{json.Number("1"), "2"} {
		got, convertErr := cloudCheckedPositiveGiBToBytes(value)
		if convertErr != nil || got == "" {
			t.Fatalf("capacity %v = %q, %v", value, got, convertErr)
		}
	}
	for _, value := range []any{json.Number("0"), json.Number("-1"), "1.5", "18446744073709551615"} {
		if _, convertErr := cloudCheckedPositiveGiBToBytes(value); convertErr == nil {
			t.Fatalf("accepted invalid capacity %v", value)
		}
	}
	missing, err := ProjectCloudSyntheticResponse(target, []byte(`{"ID":"i-1"}`), CloudSyntheticCoveragePartial)
	if err != nil || missing.Fields[0].State != "absent" {
		t.Fatalf("valid missing pointer must be absent, got %#v, %v", missing, err)
	}
}

func TestBuildCloudSourceCandidateBundleRefusesMissingDispositionAndAssociation(t *testing.T) {
	catalog, target := cloudSourcePackageTestCatalog(), cloudSourcePackageTestTarget()
	target.FieldMappings = target.FieldMappings[:1]
	if _, err := BuildCloudSourceCandidateBundle(CloudSourceCandidateRequest{Catalogs: []CloudCatalog{catalog}, Targets: []CloudSourceObjectTarget{target}}); err == nil {
		t.Fatal("missing source field disposition accepted")
	}
	target = cloudSourcePackageTestTarget()
	catalog.Operations[0].AssociationStatus = cloudCatalogAssociationUnresolved
	if _, err := BuildCloudSourceCandidateBundle(CloudSourceCandidateRequest{Catalogs: []CloudCatalog{catalog}, Targets: []CloudSourceObjectTarget{target}}); err == nil {
		t.Fatal("unresolved resource/operation association accepted")
	}
}

func TestBuildCloudSourceCandidateBundleDoesNotMakeModelRevisionIdentity(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput(filepath.Join("..", "..", "testdata", "cloudapi", "candidate-input.json"), NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Catalogs) == 0 || len(request.Targets) == 0 {
		t.Fatal("real candidate input has no catalog or target")
	}
	first := request.Catalogs[0]
	second := first
	second.APIVersion, second.ModelSHA256 = "v2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	target := request.Targets[0]
	left, err := BuildCloudSourceCandidateBundle(CloudSourceCandidateRequest{Catalogs: []CloudCatalog{first}, Targets: []CloudSourceObjectTarget{target}})
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildCloudSourceCandidateBundle(CloudSourceCandidateRequest{Catalogs: []CloudCatalog{second}, Targets: []CloudSourceObjectTarget{target}})
	if err != nil {
		t.Fatal(err)
	}
	if cloudTargetKey(target) == "" || bytes.Equal(left.Documents[sourcePackageOutputRoleAPIGraphArtifact], right.Documents[sourcePackageOutputRoleAPIGraphArtifact]) {
		t.Fatal("model revision was not retained as catalog lineage")
	}
	if !bytes.Equal(left.Documents[sourcePackageOutputRoleSourceMapping], right.Documents[sourcePackageOutputRoleSourceMapping]) {
		t.Fatal("API/model revision leaked into stable source mapping identity")
	}
}

func TestProjectCloudSyntheticResponsePreservesFourStatesAndNeverDeletes(t *testing.T) {
	target := cloudSourcePackageTestTarget()
	target.FieldMappings = append(target.FieldMappings, CloudSourceFieldMapping{SourceSchemaID: "Instance", SourceFieldID: "unavailable", SourcePointer: "/Unavailable", DeclaredType: "string", Disposition: CloudSourceUnknown, Cardinality: "one"})
	result, err := ProjectCloudSyntheticResponse(target, []byte(`{"InstanceId":"i-1","InstanceType":null}`), CloudSyntheticCoveragePartial)
	if err != nil {
		t.Fatal(err)
	}
	if result.DeletionAuthorized || len(result.Fields) != 3 {
		t.Fatalf("projection invented deletion/field count: %#v", result)
	}
	states := map[string]string{}
	for _, field := range result.Fields {
		states[field.SourceFieldID] = field.State
	}
	if states["instance_id"] != "present" || states["instance_type"] != "null" || states["unavailable"] != "unknown" {
		t.Fatalf("four-state projection = %#v", states)
	}
	missing, err := ProjectCloudSyntheticResponse(cloudSourcePackageTestTarget(), []byte(`{"InstanceId":"i-1"}`), CloudSyntheticCoverageComplete)
	if err != nil {
		t.Fatal(err)
	}
	if missing.DeletionAuthorized || missing.Fields[1].State != "absent" {
		t.Fatalf("absence authorized deletion: %#v", missing)
	}
}

func cloudSourcePackageTestCatalog() CloudCatalog {
	return CloudCatalog{
		ProviderID: "aws", ServiceID: "ec2", APISurfaceID: "ec2", APIVersion: "2016-11-15",
		ModelSHA256:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Resources:    []CloudCatalogResource{{ID: "instance", OperationIDs: []string{"DescribeInstances"}}},
		Operations:   []CloudCatalogOperation{{ID: "DescribeInstances", ResourceIDs: []string{"instance"}, AssociationStatus: cloudCatalogAssociationAsserted}},
		SchemaShapes: []CloudCatalogSchemaShape{{ID: "Instance", DeclaredType: "structure", InterpretationStatus: "preserved_uninterpreted", RawJSON: []byte(`{"type":"structure"}`)}},
	}
}

func cloudSourcePackageTestTarget() CloudSourceObjectTarget {
	return CloudSourceObjectTarget{
		ProviderID: "aws", ServiceID: "ec2", APISurfaceID: "ec2", OperationID: "DescribeInstances", SourceObjectType: "instance",
		RecordClassSymbol: "compute_instance", RecordClassContractRef: "1729172e-44a9-48bb-b833-9591cd105516#sections.s2_record_class_declarations.compute_instance",
		SourceSchemaVersion: "1", SourceMappingVersion: "1", StableIdentitySourceFields: []string{"instance_id"}, SourceFields: []string{"instance_id", "instance_type"},
		FieldMappings: []CloudSourceFieldMapping{
			{SourceSchemaID: "Instance", SourceFieldID: "instance_id", SourcePointer: "/InstanceId", DeclaredType: "string", Disposition: CloudSourceMapsExactSourceFact, TargetField: "source_identity_reference", Cardinality: "one"},
			{SourceSchemaID: "Instance", SourceFieldID: "instance_type", SourcePointer: "/InstanceType", DeclaredType: "string", Disposition: CloudSourceMapsExactSourceFact, TargetField: "instance_type", Cardinality: "one"},
		},
	}
}
