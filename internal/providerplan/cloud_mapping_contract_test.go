package providerplan

import (
	"encoding/json"
	"os"
	"testing"
)

func TestLoadCloudNeutralRecordSchemaFromPinnedSemanticOwnerSnapshot(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/semantic-owner/infrastructure-resource-record-mapping-schema.export.json")
	if err != nil {
		t.Fatal(err)
	}
	const expected = cloudInfrastructureSchemaExportSHA256
	if got := sha256Hex(raw); got != expected {
		t.Fatalf("semantic-owner export sha = %s, want %s", got, expected)
	}
	for _, classSymbol := range []string{"infrastructure_scope", "storage_container", "compute_instance", "compute_volume"} {
		schema, loadErr := LoadCloudNeutralRecordSchema(raw, expected, classSymbol)
		if loadErr != nil {
			t.Fatalf("load pinned class %q: %v", classSymbol, loadErr)
		}
		if schema.ValidatorProfileSHA256 != cloudInfrastructureValidatorProfileSHA256 || schema.ValidatorProfileRef != cloudInfrastructureValidatorProfileSymbol {
			t.Fatalf("pinned class %q did not retain exact validator profile binding", classSymbol)
		}
	}
}

func TestLoadCloudNeutralRecordSchemaV3UsesOnlyPinnedOwnerProfile(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/semantic-owner/infrastructure-resource-record-v3-mapping-schema.export.json")
	if err != nil {
		t.Fatal(err)
	}
	inputRaw, err := os.ReadFile("../../testdata/cloudapi/candidate-input-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var input CloudSourceCandidateInput
	if err := strictUnmarshal(inputRaw, &input); err != nil {
		t.Fatal(err)
	}
	expected := input.NeutralSchemaExportSHA256
	if got := sha256Hex(raw); got != expected {
		t.Fatalf("v3 semantic-owner export sha = %s, want %s", got, expected)
	}
	schema, err := LoadCloudNeutralRecordSchema(raw, expected, "compute_instance")
	if err != nil {
		t.Fatalf("load v3 exact owner profile: %v", err)
	}
	if schema.ownerProfileID != "infrastructure-resource-record-v3" || len(schema.semanticOwnerFields) == 0 || schema.sealedSemanticOwnerFieldsSHA256 == "" {
		t.Fatal("v3 schema did not retain its sealed embedded semantic owner dictionary")
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-2] ^= 1
	if _, err := LoadCloudNeutralRecordSchema(tampered, expected, "compute_instance"); err == nil {
		t.Fatal("tampered v3 owner export accepted")
	}
}

func TestValidateCloudNeutralRecordValueAndFormatAssertions(t *testing.T) {
	export, err := os.ReadFile("../../testdata/cloudapi/semantic-owner/infrastructure-resource-record-mapping-schema.export.json")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := LoadCloudNeutralRecordSchema(export, cloudInfrastructureSchemaExportSHA256, "compute_volume")
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte(`{"record_class":"compute_volume","semantic_record_instance_identity":"opaque","display_name":{"state":"present","value":"volume"},"scope_reference":{"state":"present","value":"scope"},"location_class":{"state":"present","value":"zonal"},"lifecycle_state":{"state":"present","value":"available"},"observation_state":"observed","capacity_bytes":{"state":"present","value":"18446744073709551615","unit":"bytes"},"storage_class":{"state":"present","value":"solid_state"},"encryption_configuration_observation":{"state":"present","value":"configured"},"description":{"state":"absent"},"reported_creation_time":{"state":"unknown"},"attached_compute_instance_references":{"state":"present","value":[]}}`)
	if err := ValidateCloudNeutralRecordValue(schema, valid); err != nil {
		t.Fatalf("valid actual compute volume refused: %v", err)
	}
	if err := ValidateCloudNeutralRecordValue(schema, []byte(`{"record_class":"compute_volume","record_class":"compute_volume"}`)); err == nil {
		t.Fatal("duplicate-key neutral candidate accepted")
	}
	dateTimeAssertion := map[string]json.RawMessage{"format": json.RawMessage(`"date-time"`)}
	if err := validateCloudStringAssertions(dateTimeAssertion, "2026-10-29T12:34:56.123Z"); err != nil {
		t.Fatalf("valid UTC fractional timestamp refused: %v", err)
	}
	if err := validateCloudStringAssertions(dateTimeAssertion, "2026-02-30T12:34:56Z"); err == nil {
		t.Fatal("invalid calendar date accepted")
	}
	if err := validateCloudStringAssertions(dateTimeAssertion, "2026-10-29T12:34:56+00:00"); err == nil {
		t.Fatal("non-Z timezone accepted")
	}
}

func TestValidateCloudMappingContractRequiresCompleteClosedSchemas(t *testing.T) {
	catalog := CloudCatalog{
		ProviderID: "gcp", ServiceID: "compute", APISurfaceID: "compute", APIVersion: "v1",
		Resources:    []CloudCatalogResource{{ID: "instance", OperationIDs: []string{"instances.list"}}},
		Operations:   []CloudCatalogOperation{{ID: "instances.list", ResourceIDs: []string{"instance"}, AssociationStatus: cloudCatalogAssociationAsserted, RawJSON: []byte(`{"output":{"target":"Instance"}}`)}},
		SchemaShapes: []CloudCatalogSchemaShape{{ID: "Instance", RawJSON: []byte(`{"type":"object","properties":{"id":{"type":"string"},"sizeGiB":{"type":"integer","format":"uint64"},"state":{"type":"string"}}}`)}},
	}
	contract := CloudMappingContract{
		OperationID: "instances.list", ObjectSchemaID: "Instance",
		Neutral: CloudNeutralRecordSchema{OwnerRef: cloudInfrastructureRecordOwnerID + "#sections.s3_semantic_schema_and_relationships.type_and_presence_closure.machine_readable_target_schema.record_class_definitions.compute_volume", OwnerSHA256: cloudInfrastructureRecordOwnerSHA256, ClassSymbol: "compute_volume", ValidatorProfileRef: cloudInfrastructureValidatorProfileSymbol, ValidatorProfileSHA256: cloudInfrastructureValidatorProfileSHA256, loadedFromExactOwner: true, ownerProfileID: "infrastructure-resource-record-v2", Fields: []CloudNeutralFieldSchema{
			{ID: "native_identifier", ValueType: "string", Cardinality: "one"}, {ID: "capacity_bytes", ValueType: "unsigned_integer", Cardinality: "one", Unit: "bytes"}, {ID: "lifecycle_configuration", ValueType: "string", Cardinality: "one", AllowedValues: []string{"configured", "not_configured"}},
		}},
		Fields: []CloudMappingContractField{
			{SourcePointer: "/id", SourceFieldID: "id", Disposition: CloudSourceMapsExactSourceFact, TargetField: "native_identifier", Projection: CloudMappingProjectionExact, ExplicitNullDisposition: CloudExplicitNullToAbsent},
			{SourcePointer: "/sizeGiB", SourceFieldID: "sizeGiB", Disposition: CloudSourcePrivateOnly, ExplicitNullDisposition: CloudExplicitNullToPrivate},
			{SourcePointer: "/state", SourceFieldID: "state", Disposition: CloudSourcePrivateOnly, ExplicitNullDisposition: CloudExplicitNullToPrivate},
		},
	}
	sealed, err := canonicalFactoryJSON(contract.Neutral.Fields)
	if err != nil {
		t.Fatal(err)
	}
	contract.Neutral.sealedFieldsSHA256 = sha256Hex(sealed)
	if err := ValidateCloudMappingContract(catalog, contract); err != nil {
		t.Fatal(err)
	}
	forged := contract
	forged.Neutral.loadedFromExactOwner = false
	if err := ValidateCloudMappingContract(catalog, forged); err == nil {
		t.Fatal("manually constructed neutral schema accepted")
	}

	missing := contract
	missing.Fields = missing.Fields[:2]
	if err := ValidateCloudMappingContract(catalog, missing); err == nil {
		t.Fatal("partial selected object mapping was accepted")
	}
	wrongTarget := contract
	wrongTarget.Fields = append([]CloudMappingContractField(nil), contract.Fields...)
	wrongTarget.Fields[0].TargetField = "invented"
	if err := ValidateCloudMappingContract(catalog, wrongTarget); err == nil {
		t.Fatal("invented neutral target was accepted")
	}
	wrongNull := contract
	wrongNull.Fields = append([]CloudMappingContractField(nil), contract.Fields...)
	wrongNull.Fields[0].ExplicitNullDisposition = CloudExplicitNullToNeutralNull
	if err := ValidateCloudMappingContract(catalog, wrongNull); err == nil {
		t.Fatal("source non-null field mapped to neutral null")
	}
	lifecycle := contract
	lifecycle.Fields = append([]CloudMappingContractField(nil), contract.Fields...)
	lifecycle.Fields[2] = CloudMappingContractField{SourcePointer: "/state", SourceFieldID: "state", Disposition: CloudSourceMapsExactLifecycleFact, TargetField: "lifecycle_configuration", Projection: CloudMappingProjectionExact, ExplicitNullDisposition: CloudExplicitNullToAbsent}
	if err := ValidateCloudMappingContract(catalog, lifecycle); err == nil {
		t.Fatal("unproved provider lifecycle equivalence accepted")
	}
	wrongOwner := contract
	wrongOwner.Neutral.OwnerSHA256 = "not-a-hash"
	if err := ValidateCloudMappingContract(catalog, wrongOwner); err == nil {
		t.Fatal("un-pinned neutral owner was accepted")
	}
	unreachable := contract
	unreachable.ObjectSchemaID = "Other"
	unreachable.Fields = nil
	catalog.SchemaShapes = append(catalog.SchemaShapes, CloudCatalogSchemaShape{ID: "Other", RawJSON: []byte(`{"type":"object","properties":{}}`)})
	if err := ValidateCloudMappingContract(catalog, unreachable); err == nil {
		t.Fatal("object outside declared operation response accepted")
	}
}

func TestValidateCloudMappingContractLoadsActualComputeVolumeSchema(t *testing.T) {
	export, err := os.ReadFile("../../testdata/cloudapi/semantic-owner/infrastructure-resource-record-mapping-schema.export.json")
	if err != nil {
		t.Fatal(err)
	}
	neutral, err := LoadCloudNeutralRecordSchema(export, cloudInfrastructureSchemaExportSHA256, "compute_volume")
	if err != nil {
		t.Fatal(err)
	}
	catalog := CloudCatalog{Operations: []CloudCatalogOperation{{ID: "list", AssociationStatus: cloudCatalogAssociationAsserted, RawJSON: []byte(`{"output":{"target":"Volume"}}`)}}, SchemaShapes: []CloudCatalogSchemaShape{{ID: "Volume", RawJSON: []byte(`{"type":"object","properties":{"sizeGiB":{"type":"integer","format":"uint64"}}}`)}}}
	contract := CloudMappingContract{OperationID: "list", ObjectSchemaID: "Volume", Neutral: neutral, Fields: []CloudMappingContractField{{SourcePointer: "/sizeGiB", SourceFieldID: "sizeGiB", Disposition: CloudSourcePrivateOnly, ExplicitNullDisposition: CloudExplicitNullToPrivate}}}
	if err := ValidateCloudMappingContract(catalog, contract); err != nil {
		t.Fatalf("actual loaded compute_volume schema is not mapping-valid: %v", err)
	}
	contract.Fields[0].TargetField = "record_class"
	contract.Fields[0].Projection = CloudMappingProjectionExact
	contract.Fields[0].SourceUnit = ""
	if err := ValidateCloudMappingContract(catalog, contract); err == nil {
		t.Fatal("source field mapped to protected record_class")
	}
}

func TestActualNeutralNullArmsAreChecked(t *testing.T) {
	export, err := os.ReadFile("../../testdata/cloudapi/semantic-owner/infrastructure-resource-record-mapping-schema.export.json")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := LoadCloudNeutralRecordSchema(export, cloudInfrastructureSchemaExportSHA256, "compute_instance")
	if err != nil {
		t.Fatal(err)
	}
	catalog := CloudCatalog{Operations: []CloudCatalogOperation{{ID: "list", AssociationStatus: cloudCatalogAssociationAsserted, RawJSON: []byte(`{"output":{"target":"Item"}}`)}}, SchemaShapes: []CloudCatalogSchemaShape{{ID: "Item", RawJSON: []byte(`{"type":"object","properties":{"reported":{"type":"string","nullable":true}}}`)}}}
	allowed := CloudMappingContract{OperationID: "list", ObjectSchemaID: "Item", Neutral: instance, Fields: []CloudMappingContractField{{SourcePointer: "/reported", SourceFieldID: "reported", Disposition: CloudSourceMapsExactSourceFact, TargetField: "reported_creation_time", Projection: CloudMappingProjectionExact, ExplicitNullDisposition: CloudExplicitNullToNeutralNull}}}
	if err := ValidateCloudMappingContract(catalog, allowed); err != nil {
		t.Fatalf("actual nullable time arm refused: %v", err)
	}
	volume, err := LoadCloudNeutralRecordSchema(export, cloudInfrastructureSchemaExportSHA256, "compute_volume")
	if err != nil {
		t.Fatal(err)
	}
	denied := allowed
	denied.Neutral = volume
	denied.Fields[0].TargetField = "capacity_bytes"
	denied.Fields[0].Projection = CloudMappingProjectionExact
	if err := ValidateCloudMappingContract(catalog, denied); err == nil {
		t.Fatal("capacity without null arm accepted source null")
	}
}

func TestValidateCloudMappingContractRefusesUnresolvedOperationsAndUnsupportedShapes(t *testing.T) {
	base := CloudCatalog{
		Operations:   []CloudCatalogOperation{{ID: "get", AssociationStatus: cloudCatalogAssociationUnresolved}},
		SchemaShapes: []CloudCatalogSchemaShape{{ID: "Thing", RawJSON: []byte(`{"type":"object","properties":{"labels":{"type":"object","additionalProperties":{"type":"string"}}}}`)}},
	}
	contract := CloudMappingContract{OperationID: "get", ObjectSchemaID: "Thing", Neutral: CloudNeutralRecordSchema{OwnerRef: "owner", OwnerSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ClassSymbol: "thing", Fields: []CloudNeutralFieldSchema{{ID: "x", ValueType: "string", Cardinality: "one"}}}}
	if err := ValidateCloudMappingContract(base, contract); err == nil {
		t.Fatal("unresolved operation was accepted")
	}
	base.Operations[0].AssociationStatus = cloudCatalogAssociationAsserted
	if err := ValidateCloudMappingContract(base, contract); err == nil {
		t.Fatal("uninterpreted map shape was accepted")
	}
}

func TestIntegerToCanonicalDecimalRequiresExactUnitEvidenceAndCompatibleInteger(t *testing.T) {
	source := cloudResolvedField{ID: "iops", ValueType: "integer_string", Cardinality: "one", NumericMaximum: "9223372036854775807"}
	target := CloudNeutralFieldSchema{ID: "provisioned_iops", ValueType: "unsigned_integer", Cardinality: "one", Unit: "iops"}
	mapping := CloudMappingContractField{SourceFieldID: "iops", Disposition: CloudSourceMapsExactSourceFact, TargetField: target.ID, Projection: CloudMappingProjectionIntegerToCanonicalDecimal, SourceUnit: "iops", SourceNumericMaximum: "9223372036854775807", UnitEvidenceRef: "provider-model"}
	if err := validateCloudMappingField(mapping, source, map[string]CloudNeutralFieldSchema{target.ID: target}); err != nil {
		t.Fatalf("valid canonical integer projection refused: %v", err)
	}
	for _, mutate := range []func(*CloudMappingContractField){
		func(field *CloudMappingContractField) { field.UnitEvidenceRef = "" },
		func(field *CloudMappingContractField) { field.SourceUnit = "bytes" },
		func(field *CloudMappingContractField) { field.SourceNumericMaximum = "18446744073709551615" },
	} {
		bad := mapping
		mutate(&bad)
		if err := validateCloudMappingField(bad, source, map[string]CloudNeutralFieldSchema{target.ID: target}); err == nil {
			t.Fatal("canonical integer projection accepted missing evidence or wrong unit")
		}
	}
	if err := validateCloudMappingField(mapping, cloudResolvedField{ID: "iops", ValueType: "string", Cardinality: "one"}, map[string]CloudNeutralFieldSchema{target.ID: target}); err == nil {
		t.Fatal("canonical integer projection accepted an unbounded string source")
	}
}

func TestQualifiedIntegerMeasurementRequiresPinnedDiscriminatorAndEvidence(t *testing.T) {
	source := map[string]cloudResolvedField{
		"/Iops":       {ID: "Iops", Pointer: "/Iops", ValueType: "signed_integer", Cardinality: "one", NumericMaximum: "2147483647"},
		"/VolumeType": {ID: "VolumeType", Pointer: "/VolumeType", ValueType: "string", Cardinality: "one"},
	}
	target := CloudNeutralFieldSchema{ID: "reported_volume_io_rate", ValueType: "closed_object", Cardinality: "one"}
	mapping := CloudMappingContractField{SourcePointer: "/Iops", SourceFieldID: "Iops", Disposition: CloudSourceMapsExactSourceFact, TargetField: target.ID, Projection: CloudMappingProjectionQualifiedIntegerMeasurement, SourceUnit: "iops", SourceNumericMaximum: "2147483647", UnitEvidenceRef: "model", QualifiedMeasurementRecipe: &CloudQualifiedIntegerMeasurementRecipe{DiscriminatorPointer: "/VolumeType", BasisByDiscriminator: map[string]string{"gp2": "baseline", "gp3": "provisioned"}, Unit: "iops", EvidenceRefs: []string{"model", "documentation"}}}
	if err := validateCloudQualifiedIntegerMeasurement(mapping, source["/Iops"], source, map[string]CloudNeutralFieldSchema{target.ID: target}, map[string]struct{}{"model": {}, "documentation": {}}); err != nil {
		t.Fatalf("valid qualified measurement refused: %v", err)
	}
	bad := mapping
	bad.QualifiedMeasurementRecipe = &CloudQualifiedIntegerMeasurementRecipe{DiscriminatorPointer: "/VolumeType", BasisByDiscriminator: map[string]string{"gp2": "not-a-basis"}, Unit: "iops", EvidenceRefs: []string{"model"}}
	if err := validateCloudQualifiedIntegerMeasurement(bad, source["/Iops"], source, map[string]CloudNeutralFieldSchema{target.ID: target}, map[string]struct{}{"model": {}}); err == nil {
		t.Fatal("invalid qualified measurement basis accepted")
	}
}

func TestCloudResolvedNumericMaximumPreservesSourceWidth(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{`{"type":"byte"}`, "127"}, {`{"type":"short"}`, "32767"}, {`{"type":"integer"}`, "2147483647"}, {`{"type":"long"}`, "9223372036854775807"},
	} {
		if got := cloudSmithyNumericMaximum(json.RawMessage(test.raw)); got != test.want {
			t.Fatalf("Smithy %s maximum=%q want %q", test.raw, got, test.want)
		}
	}
	for _, test := range []struct{ kind, format, want string }{
		{"integer", "int32", "2147483647"}, {"string", "int64", "9223372036854775807"}, {"integer", "uint32", "4294967295"}, {"string", "uint64", "18446744073709551615"},
	} {
		if got := cloudDiscoveryNumericMaximum(test.kind, test.format); got != test.want {
			t.Fatalf("Discovery %s:%s maximum=%q want %q", test.kind, test.format, got, test.want)
		}
	}
}
