package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type cloudCatalogTestAssociation struct{ resource, operation string }

func TestParsePinnedCloudModelOfficialInputs(t *testing.T) {
	tests := []struct {
		name, path                                 string
		format                                     CloudCatalogFormat
		provider, service, surface, version        string
		hash, uri, coordinate, operation, protocol string
	}{
		{"aws_s3", "testdata/cloudapi/official/aws/s3-2006-03-01.json", CloudCatalogFormatSmithyJSON, "aws", "s3", "s3", "2006-03-01", "73e4f75747396176053a0fcc910261cf670c7e133c1cebcfffefa703fad3ce68", "https://raw.githubusercontent.com/aws/api-models-aws/d6bbb4d64e2c82927834dfa9791bebc0000f70c0/models/s3/service/2006-03-01/s3-2006-03-01.json", "aws-api-models-aws@d6bbb4d64e2c82927834dfa9791bebc0000f70c0", "com.amazonaws.s3#ListBuckets", "aws.protocols#restXml"},
		{"aws_ec2", "testdata/cloudapi/official/aws/ec2-2016-11-15.json", CloudCatalogFormatSmithyJSON, "aws", "ec2", "ec2", "2016-11-15", "2a61258f48c9769ccd24ad8d0a439593334fbafcf2a82d49677d72a04747f85e", "https://raw.githubusercontent.com/aws/api-models-aws/d6bbb4d64e2c82927834dfa9791bebc0000f70c0/models/ec2/service/2016-11-15/ec2-2016-11-15.json", "aws-api-models-aws@d6bbb4d64e2c82927834dfa9791bebc0000f70c0", "com.amazonaws.ec2#DescribeInstances", "aws.protocols#ec2Query"},
		{"gcp_storage", "testdata/cloudapi/official/gcp/storage-v1.discovery.json", CloudCatalogFormatGoogleDiscoveryREST, "gcp", "cloud_storage", "storage", "v1", "91588de46b456618d09d202a6595ba1e4d1752658251fce0aa61e7f36781adff", "https://storage.googleapis.com/$discovery/rest?version=v1", "google-discovery-storage-v1-20261020", "storage.buckets.list", "discovery#rest_json"},
		{"gcp_compute", "testdata/cloudapi/official/gcp/compute-v1.discovery.json", CloudCatalogFormatGoogleDiscoveryREST, "gcp", "compute", "compute", "v1", "e3059e418cdd44f3ef343aa62fa4105759e450366dbe567bb827f7bf310678d7", "https://www.googleapis.com/discovery/v1/apis/compute/v1/rest", "google-discovery-compute-v1-20261016", "compute.instances.aggregatedList", "discovery#rest_json"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", test.path))
			if err != nil {
				t.Fatal(err)
			}
			model := PinnedCloudModel{Format: test.format, Source: CloudCatalogSourceIdentity{ID: "official-public-api-model", URI: test.uri, StableCoordinate: test.coordinate, FormatRevision: "1"}, ProviderID: test.provider, ServiceID: test.service, APISurfaceID: test.surface, APIVersion: test.version, Raw: raw, ExpectedSHA256: test.hash}
			catalog, err := ParsePinnedCloudModel(model)
			if err != nil {
				t.Fatal(err)
			}
			if catalog.ModelSHA256 != sha256Hex(raw) || catalog.ProviderID != test.provider || catalog.ServiceID != test.service || catalog.APISurfaceID != test.surface || catalog.APIVersion != test.version {
				t.Fatalf("catalog did not preserve provider/service/api hierarchy: %#v", catalog)
			}
			if len(catalog.Operations) == 0 || len(catalog.SchemaShapes) == 0 {
				t.Fatalf("catalog discarded official model surface: operations=%d schemas=%d", len(catalog.Operations), len(catalog.SchemaShapes))
			}
			for _, shape := range catalog.SchemaShapes {
				if len(shape.RawJSON) == 0 || shape.InterpretationStatus != "preserved_uninterpreted" {
					t.Fatalf("schema %q was not evidence-preserved", shape.ID)
				}
			}
			foundOperation := false
			for _, operation := range catalog.Operations {
				if operation.ID == test.operation {
					foundOperation = true
				}
				if operation.Locator.StartByte <= 0 || operation.Locator.EndByte >= len(raw) {
					t.Fatalf("operation %q lacks exact non-root evidence span", operation.ID)
				}
			}
			if !foundOperation {
				t.Fatalf("selected official operation %q absent", test.operation)
			}
			if catalog.Format != test.format || len(catalog.ProtocolBindings) == 0 {
				t.Fatalf("catalog did not retain model format/protocol: %#v", catalog)
			}
			foundProtocol := false
			for _, binding := range catalog.ProtocolBindings {
				if binding.ID == test.protocol && binding.Status == cloudCatalogProtocolDocumentedSupported && len(binding.Locators) > 0 {
					foundProtocol = true
				}
			}
			if !foundProtocol {
				t.Fatalf("selected protocol %q absent or unsupported: %#v", test.protocol, catalog.ProtocolBindings)
			}
			if test.format == CloudCatalogFormatSmithyJSON {
				if len(catalog.Resources) != 0 {
					t.Fatalf("Smithy resource inference is forbidden, got %#v", catalog.Resources)
				}
				if catalog.Operations[0].AssociationStatus != cloudCatalogAssociationUnresolved {
					t.Fatalf("Smithy operation must remain fail-closed absent evidence: %#v", catalog.Operations[0])
				}
			} else if len(catalog.Resources) == 0 || catalog.Operations[0].AssociationStatus != cloudCatalogAssociationDocumented {
				t.Fatalf("Discovery resource nesting was not retained")
			}
		})
	}
}

func TestParsePinnedCloudModelRejectsHashDuplicateAndUnknownAssociation(t *testing.T) {
	raw := []byte(`{"smithy":"2.0","shapes":{"example#Service":{"type":"service","version":"1","operations":[{"target":"example#Operation"}]},"example#Operation":{"type":"operation"}}}`)
	base := PinnedCloudModel{Format: CloudCatalogFormatSmithyJSON, Source: CloudCatalogSourceIdentity{ID: "model", URI: "https://example.invalid/model", StableCoordinate: "example/model", FormatRevision: "2.0"}, ProviderID: "aws", ServiceID: "example", APISurfaceID: "example", APIVersion: "1", Raw: raw, ExpectedSHA256: sha256Hex(raw)}
	wrongHash := base
	wrongHash.ExpectedSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := ParsePinnedCloudModel(wrongHash); err == nil {
		t.Fatal("hash mismatch accepted")
	}
	duplicate := base
	duplicate.Raw = []byte(`{"smithy":"2.0","smithy":"2.0","shapes":{}}`)
	duplicate.ExpectedSHA256 = sha256Hex(duplicate.Raw)
	if _, err := ParsePinnedCloudModel(duplicate); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
	evidenceRaw := []byte(`{"assertions":[{"resource_id":"not-a-resource","operation_id":"example#Operation"}]}`)
	unknown := base
	unknown.SupplementalEvidence = []CloudCatalogSupplementalEvidence{{ID: "association-evidence", Source: CloudCatalogSourceIdentity{ID: "association", URI: "https://example.invalid/evidence", StableCoordinate: "example/evidence", FormatRevision: "1"}, Raw: evidenceRaw, ExpectedSHA256: sha256Hex(evidenceRaw)}}
	unknown.ResourceOperationAssertions = []CloudCatalogResourceOperationAssertion{{ResourceID: "not-a-resource", OperationID: "example#Operation", EvidenceLocator: CloudCatalogEvidenceLocator{EvidenceID: "association-evidence", JSONPointer: "/assertions/0", StartByte: 0, EndByte: len(evidenceRaw)}}}
	if _, err := ParsePinnedCloudModel(unknown); err == nil {
		t.Fatal("unknown explicit resource association accepted")
	}
}

func TestParsePinnedCloudModelDeterministic(t *testing.T) {
	raw := []byte(`{"kind":"discovery#restDescription","name":"example","version":"v1","protocol":"rest","schemas":{"Thing":{"type":"object","properties":{"name":{"type":"string"}}}},"auth":{"oauth2":{"scopes":{"scope.b":{"description":"b"},"scope.a":{"description":"a"}}}},"resources":{"things":{"methods":{"list":{"id":"example.things.list","scopes":["scope.b","scope.a"]}}}}}`)
	model := PinnedCloudModel{Format: CloudCatalogFormatGoogleDiscoveryREST, Source: CloudCatalogSourceIdentity{ID: "model", URI: "https://example.invalid/discovery", StableCoordinate: "example/discovery", FormatRevision: "v1"}, ProviderID: "gcp", ServiceID: "example", APISurfaceID: "example", APIVersion: "v1", Raw: raw, ExpectedSHA256: sha256Hex(raw)}
	first, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 20; run++ {
		next, err := ParsePinnedCloudModel(model)
		if err != nil {
			t.Fatal(err)
		}
		nextJSON, err := json.Marshal(next)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(firstJSON, nextJSON) {
			t.Fatalf("run %d is nondeterministic", run)
		}
	}
}

func TestCloudCatalogProtocolBindingsFailClosedAndKeepExactEvidence(t *testing.T) {
	raw := []byte(`{"smithy":"2.0","shapes":{"example#Service":{"type":"service","version":"1","operations":[{"target":"example#Read"}],"traits":{"aws.protocols#jsonX":"forged"}},"example#Read":{"type":"operation"}}}`)
	model := PinnedCloudModel{Format: CloudCatalogFormatSmithyJSON, Source: CloudCatalogSourceIdentity{ID: "model", URI: "https://example.invalid/model", StableCoordinate: "example/model", FormatRevision: "2.0"}, ProviderID: "aws", ServiceID: "example", APISurfaceID: "example", APIVersion: "1", Raw: raw, ExpectedSHA256: sha256Hex(raw)}
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Format != CloudCatalogFormatSmithyJSON || len(catalog.ProtocolBindings) != 1 || catalog.ProtocolBindings[0].ID != "aws.protocols#jsonX" || catalog.ProtocolBindings[0].Status != cloudCatalogProtocolDocumentedUnsupported {
		t.Fatalf("unsupported Smithy protocol did not remain explicit/fail-closed: %#v", catalog.ProtocolBindings)
	}
	model.locatorSpans, err = cloudCatalogJSONPointerSpans(model.Raw)
	if err != nil {
		t.Fatal(err)
	}
	forged := catalog
	forged.ProtocolBindings[0].Locators[0].StartByte++
	if err := validateProducedCloudCatalogLocators(forged, model); err == nil {
		t.Fatal("forged protocol locator accepted")
	}
}

func TestParsePinnedCloudModelRequiresBoundedEvidencedSmithyAssociation(t *testing.T) {
	raw := []byte(`{"smithy":"2.0","shapes":{"example#Service":{"type":"service","version":"1","operations":[{"target":"example#Read"}]},"example#Read":{"type":"operation"},"example#Widget":{"type":"resource"}}}`)
	evidenceRaw := []byte(`{"assertion":{"resource_id":"example#Widget","operation_id":"example#Read"}}`)
	model := PinnedCloudModel{Format: CloudCatalogFormatSmithyJSON, Source: CloudCatalogSourceIdentity{ID: "model", URI: "https://example.invalid/model", StableCoordinate: "example/model", FormatRevision: "2.0"}, ProviderID: "aws", ServiceID: "example", APISurfaceID: "example", APIVersion: "1", Raw: raw, ExpectedSHA256: sha256Hex(raw), SupplementalEvidence: []CloudCatalogSupplementalEvidence{{ID: "assertion", Source: CloudCatalogSourceIdentity{ID: "evidence", URI: "https://example.invalid/evidence", StableCoordinate: "example/evidence", FormatRevision: "1"}, Raw: evidenceRaw, ExpectedSHA256: sha256Hex(evidenceRaw)}}}
	model.ResourceOperationAssertions = []CloudCatalogResourceOperationAssertion{{ResourceID: "example#Widget", OperationID: "example#Read", EvidenceLocator: CloudCatalogEvidenceLocator{EvidenceID: "assertion", JSONPointer: "", StartByte: 0, EndByte: len(evidenceRaw)}}}
	if _, err := ParsePinnedCloudModel(model); err == nil {
		t.Fatal("empty locator pointer accepted")
	}
	model.ResourceOperationAssertions[0].EvidenceLocator.JSONPointer = "/assertion"
	fragment := []byte(`{"resource_id":"example#Widget","operation_id":"example#Read"}`)
	start := bytes.Index(evidenceRaw, fragment)
	model.ResourceOperationAssertions[0].EvidenceLocator.StartByte, model.ResourceOperationAssertions[0].EvidenceLocator.EndByte = start, start+len(fragment)
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Operations[0].AssociationStatus != cloudCatalogAssociationAsserted || len(catalog.Resources[0].OperationIDs) != 1 {
		t.Fatalf("explicit candidate association was not retained: %#v", catalog)
	}
	missing := model
	missing.ResourceOperationAssertions[0].EvidenceLocator.EvidenceID = "absent"
	if _, err := ParsePinnedCloudModel(missing); err == nil {
		t.Fatal("missing evidence body accepted")
	}
}

func TestParsePinnedCloudModelAdmitsOnlyExplicitDeclaredAWSStructureCandidates(t *testing.T) {
	tests := []struct {
		name, path, service, version, hash string
		associations                       []cloudCatalogTestAssociation
	}{
		{"s3", "testdata/cloudapi/official/aws/s3-2006-03-01.json", "s3", "2006-03-01", "73e4f75747396176053a0fcc910261cf670c7e133c1cebcfffefa703fad3ce68", []cloudCatalogTestAssociation{{"com.amazonaws.s3#Bucket", "com.amazonaws.s3#ListBuckets"}}},
		{"ec2", "testdata/cloudapi/official/aws/ec2-2016-11-15.json", "ec2", "2016-11-15", "2a61258f48c9769ccd24ad8d0a439593334fbafcf2a82d49677d72a04747f85e", []cloudCatalogTestAssociation{{"com.amazonaws.ec2#Instance", "com.amazonaws.ec2#DescribeInstances"}, {"com.amazonaws.ec2#Volume", "com.amazonaws.ec2#DescribeVolumes"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", test.path))
			if err != nil {
				t.Fatal(err)
			}
			model := awsDeclaredCandidateModel(t, raw, test.service, test.version, test.hash, test.associations)
			catalog, err := ParsePinnedCloudModel(model)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range test.associations {
				resourceFound, operationFound := false, false
				for _, resource := range catalog.Resources {
					if resource.ID == want.resource {
						resourceFound = resource.DeclarationStatus == cloudCatalogAssociationAsserted && len(resource.OperationIDs) == 1 && resource.OperationIDs[0] == want.operation && resource.DeclarationEvidenceLocator != nil && resource.DeclarationEvidenceLocator.EvidenceID == "declarations"
					}
				}
				for _, operation := range catalog.Operations {
					if operation.ID == want.operation {
						operationFound = operation.AssociationStatus == cloudCatalogAssociationAsserted && len(operation.ResourceIDs) == 1 && operation.ResourceIDs[0] == want.resource && len(operation.ResourceAssociationEvidence) == 1 && operation.ResourceAssociationEvidence[0].ResourceID == want.resource && operation.ResourceAssociationEvidence[0].EvidenceLocator.EvidenceID == "declarations"
					}
				}
				if !resourceFound || !operationFound {
					t.Fatalf("explicit candidate %q/%q was not retained: %#v", want.resource, want.operation, catalog)
				}
			}
		})
	}
}

func TestPinnedCloudModelRejectsUnboundResourceDeclarations(t *testing.T) {
	raw := []byte(`{"smithy":"2.0","shapes":{"example#Service":{"type":"service","version":"1","operations":[{"target":"example#Read"}]},"example#Read":{"type":"operation"},"example#Widget":{"type":"structure"}}}`)
	model := awsDeclaredCandidateModel(t, raw, "example", "1", sha256Hex(raw), []cloudCatalogTestAssociation{{"example#Widget", "example#Read"}})
	if _, err := ParsePinnedCloudModel(model); err != nil {
		t.Fatalf("valid explicit structure candidate rejected: %v", err)
	}
	mismatchedSchema := model
	mismatchedSchema.ResourceDeclarations[0].ResourceID = "example#Read"
	mismatchedSchema.ResourceDeclarations[0].StructureShapeID = "example#Read"
	if _, err := ParsePinnedCloudModel(mismatchedSchema); err == nil {
		t.Fatal("non-structure declaration accepted")
	}
	wrongLocator := model
	wrongLocator.ResourceDeclarations[0].StructureLocator.StartByte++
	if _, err := ParsePinnedCloudModel(wrongLocator); err == nil {
		t.Fatal("imprecise retained-model structure locator accepted")
	}
	unknownOperation := model
	unknownOperation.ResourceOperationAssertions[0].OperationID = "example#Absent"
	if _, err := ParsePinnedCloudModel(unknownOperation); err == nil {
		t.Fatal("unknown operation accepted")
	}
	forgedRole := model
	forgedRole.ResourceDeclarations[0].Role = "native_smithy_resource"
	if _, err := ParsePinnedCloudModel(forgedRole); err == nil {
		t.Fatal("unbound/forged declaration role accepted")
	}
}

func awsDeclaredCandidateModel(t *testing.T, raw []byte, service, version, hash string, associations []cloudCatalogTestAssociation) PinnedCloudModel {
	t.Helper()
	declarationItems := make([]map[string]any, 0, len(associations))
	assertionItems := make([]map[string]any, 0, len(associations))
	declarations := make([]CloudCatalogResourceDeclaration, 0, len(associations))
	for _, association := range associations {
		start, end, err := cloudCatalogJSONPointerSpan(raw, "/shapes/"+cloudCatalogEscapePointer(association.resource))
		if err != nil {
			t.Fatal(err)
		}
		structureLocator := CloudCatalogEvidenceLocator{EvidenceID: "model", JSONPointer: "/shapes/" + cloudCatalogEscapePointer(association.resource), StartByte: start, EndByte: end}
		declarationItems = append(declarationItems, map[string]any{"resource_id": association.resource, "structure_shape_id": association.resource, "role": cloudCatalogAssociationAsserted, "structure_locator": structureLocator})
		assertionItems = append(assertionItems, map[string]any{"resource_id": association.resource, "operation_id": association.operation})
		declarations = append(declarations, CloudCatalogResourceDeclaration{ResourceID: association.resource, StructureShapeID: association.resource, Role: cloudCatalogAssociationAsserted, StructureLocator: structureLocator})
	}
	evidenceRaw, err := json.Marshal(map[string]any{"resource_declarations": declarationItems, "resource_operation_assertions": assertionItems})
	if err != nil {
		t.Fatal(err)
	}
	assertions := make([]CloudCatalogResourceOperationAssertion, 0, len(associations))
	for index, association := range associations {
		declarationStart, declarationEnd, err := cloudCatalogJSONPointerSpan(evidenceRaw, "/resource_declarations/"+strconv.Itoa(index))
		if err != nil {
			t.Fatal(err)
		}
		declarations[index].EvidenceLocator = CloudCatalogEvidenceLocator{EvidenceID: "declarations", JSONPointer: "/resource_declarations/" + strconv.Itoa(index), StartByte: declarationStart, EndByte: declarationEnd}
		assertionStart, assertionEnd, err := cloudCatalogJSONPointerSpan(evidenceRaw, "/resource_operation_assertions/"+strconv.Itoa(index))
		if err != nil {
			t.Fatal(err)
		}
		assertions = append(assertions, CloudCatalogResourceOperationAssertion{ResourceID: association.resource, OperationID: association.operation, EvidenceLocator: CloudCatalogEvidenceLocator{EvidenceID: "declarations", JSONPointer: "/resource_operation_assertions/" + strconv.Itoa(index), StartByte: assertionStart, EndByte: assertionEnd}})
	}
	return PinnedCloudModel{Format: CloudCatalogFormatSmithyJSON, Source: CloudCatalogSourceIdentity{ID: "model", URI: "https://example.invalid/official-model", StableCoordinate: "official/" + service, FormatRevision: "2.0"}, ProviderID: "aws", ServiceID: service, APISurfaceID: service, APIVersion: version, Raw: raw, ExpectedSHA256: hash, SupplementalEvidence: []CloudCatalogSupplementalEvidence{{ID: "declarations", Source: CloudCatalogSourceIdentity{ID: "declarations", URI: "https://example.invalid/declarations", StableCoordinate: "test/declarations", FormatRevision: "1"}, Raw: evidenceRaw, ExpectedSHA256: sha256Hex(evidenceRaw)}}, ResourceDeclarations: declarations, ResourceOperationAssertions: assertions}
}

func TestCloudCatalogDoesNotMintSourceIdentityAcrossModelRevision(t *testing.T) {
	makeModel := func(version string) PinnedCloudModel {
		raw := []byte(`{"kind":"discovery#restDescription","name":"example","version":"` + version + `","protocol":"rest","methods":{"get":{"id":"example.get"}}}`)
		return PinnedCloudModel{Format: CloudCatalogFormatGoogleDiscoveryREST, Source: CloudCatalogSourceIdentity{ID: "official-discovery", URI: "https://example.invalid/discovery/" + version, StableCoordinate: "official/discovery/" + version, FormatRevision: "discovery-v1"}, ProviderID: "gcp", ServiceID: "example", APISurfaceID: "example", APIVersion: version, Raw: raw, ExpectedSHA256: sha256Hex(raw)}
	}
	first, err := ParsePinnedCloudModel(makeModel("v1"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParsePinnedCloudModel(makeModel("v2"))
	if err != nil {
		t.Fatal(err)
	}
	if first.ProviderID != second.ProviderID || first.ServiceID != second.ServiceID || first.APISurfaceID != second.APISurfaceID {
		t.Fatal("model revision changed provider/service/api identity")
	}
	if first.APIVersion == second.APIVersion || first.ModelSHA256 == second.ModelSHA256 {
		t.Fatal("model revision was not retained as evidence-local catalog fact")
	}
}

func TestPinnedCloudModelRejectsInvalidUTF8BoundsAndImpreciseLocator(t *testing.T) {
	valid := []byte(`{"kind":"discovery#restDescription","name":"example","version":"v1","methods":{"get":{"id":"example.get"}}}`)
	base := PinnedCloudModel{Format: CloudCatalogFormatGoogleDiscoveryREST, Source: CloudCatalogSourceIdentity{ID: "model", URI: "https://example.invalid/model", StableCoordinate: "example/model", FormatRevision: "1"}, ProviderID: "gcp", ServiceID: "example", APISurfaceID: "example", APIVersion: "v1", Raw: valid, ExpectedSHA256: sha256Hex(valid)}
	invalidUTF8 := base
	invalidUTF8.Raw = append(append([]byte{}, valid[:len(valid)-1]...), 0xff, '}')
	invalidUTF8.ExpectedSHA256 = sha256Hex(invalidUTF8.Raw)
	if _, err := ParsePinnedCloudModel(invalidUTF8); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	tooLarge := base
	tooLarge.Raw = bytes.Repeat([]byte(" "), int(maxStageInputFileBytesPerFile)+1)
	tooLarge.ExpectedSHA256 = sha256Hex(tooLarge.Raw)
	if _, err := ParsePinnedCloudModel(tooLarge); err == nil {
		t.Fatal("oversize model accepted")
	}
	nested := []byte(`{"smithy":"2.0","shapes":` + strings.Repeat(`{"x":`, maxProviderJSONNestingDepth+1) + `0` + strings.Repeat(`}`, maxProviderJSONNestingDepth+1) + `}`)
	overDepth := PinnedCloudModel{Format: CloudCatalogFormatSmithyJSON, Source: base.Source, ProviderID: "aws", ServiceID: "example", APISurfaceID: "example", APIVersion: "1", Raw: nested, ExpectedSHA256: sha256Hex(nested)}
	if _, err := ParsePinnedCloudModel(overDepth); err == nil {
		t.Fatal("overdepth model accepted")
	}
	bodies := map[string][]byte{"model": valid}
	locator := CloudCatalogEvidenceLocator{EvidenceID: "model", JSONPointer: "/methods/get", StartByte: 0, EndByte: len(valid)}
	if err := validateCloudCatalogLocator(locator, bodies); err == nil {
		t.Fatal("full-body range paired with non-root pointer accepted")
	}
	if _, _, err := cloudCatalogJSONPointerSpan([]byte(`{"items":[0]}`), "/items/01"); err == nil {
		t.Fatal("noncanonical array pointer accepted")
	}
}
