package providerplan

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestTenantRequiredEverywhereSurfacesAreExact(t *testing.T) {
	complete := map[string]interface{}{
		"forge_output_envelopes": true, "forge_request_envelopes": true, "graph_queries": true,
		"ood_graph_rows": true, "policy_decision_refs": true, "projection_artifacts": true,
		"property_graph_edge_views": true, "property_graph_node_views": true, "retrieval_outputs": true,
		"validation_evidence_refs": true, "violations": true,
	}
	if err := validateTenantRequiredEverywhereSurfaces(complete); err != nil {
		t.Fatalf("complete tenant-surface roster was rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		edit func(map[string]interface{})
	}{
		{name: "empty", edit: func(row map[string]interface{}) { clear(row) }},
		{name: "subset", edit: func(row map[string]interface{}) { delete(row, "retrieval_outputs") }},
		{name: "extra", edit: func(row map[string]interface{}) { row["provider_specific_surface"] = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := make(map[string]interface{}, len(complete)+1)
			for key, value := range complete {
				candidate[key] = value
			}
			test.edit(candidate)
			if err := validateTenantRequiredEverywhereSurfaces(candidate); err == nil {
				t.Fatal("non-exact tenant-surface roster was accepted")
			}
		})
	}
}

func TestParseDependencySemanticRowsDefersClosedShapeToSchemaProof(t *testing.T) {
	t.Parallel()
	input := artifactInput{
		Path: "fixture.jsonl",
		Raw: []byte("{\"row_kind\":\"artifact_manifest\",\"name\":\"fixture\"}\n" +
			"{\"row_kind\":\"fact\",\"identity\":\"one\",\"forged_summary_marker\":true}\n" +
			"{\"row_kind\":\"validation_summary\",\"result\":\"candidate\"}\n"),
	}
	rows, err := parseDependencySemanticRows(input)
	if err != nil {
		t.Fatalf("parseDependencySemanticRows() error = %v", err)
	}
	if len(rows.byKind["fact"]) != 1 {
		t.Fatal("generic parser discarded a schema-owned row kind")
	}
}

func TestDependencySemanticValidationProofIsMandatoryAndRoleSetEqual(t *testing.T) {
	t.Parallel()
	roles := []string{
		dependencySemanticRoleProfile,
		dependencySemanticRoleSourceContract,
		dependencySemanticRoleSampleShape,
		dependencySemanticRoleProtocolContract,
		dependencySemanticRoleFieldMapping,
		dependencySemanticRoleOperationApplicability,
		dependencySemanticRoleAPIGraphApplicability,
		dependencySemanticRoleSurfaceDisposition,
		dependencySemanticRoleFieldSecurityPolicy,
		dependencySemanticRoleMappingTransitiveRoster,
		dependencySemanticRoleDocumentationClaimDerivation,
	}
	artifacts := make(map[string]artifactInput, len(roles))
	bindings := make(map[string]dependencySemanticValidatedArtifact, len(roles))
	sharedSchemaDigest := strings.Repeat("f", 64)
	for _, role := range roles {
		raw := []byte(role + " exact bytes")
		artifacts[role] = artifactInput{Path: role + ".jsonl", Raw: raw, SHA256: sha256Hex(raw)}
		bindings[role] = dependencySemanticValidatedArtifact{
			artifactSHA256: sha256Hex(raw), schemaRole: role + "_schema", schemaID: "urn:test:shared-schema", schemaVersion: "1", schemaSHA256: sharedSchemaDigest,
		}
	}
	if err := validateDependencySemanticProof(dependencySemanticValidationProof{}, artifacts); err == nil || !strings.Contains(err.Error(), "requires an exact schema-validation proof") {
		t.Fatalf("zero proof error = %v, want mandatory-token rejection", err)
	}
	proof := dependencySemanticValidationProof{seal: dependencySemanticValidationAuthority, byRole: bindings}
	if err := validateDependencySemanticProof(proof, artifacts); err != nil {
		t.Fatalf("set-equal proof with intentionally shared schema error = %v", err)
	}
	delete(proof.byRole, dependencySemanticRoleProtocolContract)
	if err := validateDependencySemanticProof(proof, artifacts); err == nil || !strings.Contains(err.Error(), "not set-equal") {
		t.Fatalf("incomplete proof error = %v, want role-set rejection", err)
	}
}

func TestDependencySemanticProductionCheckerHasNoVendorOrInvoiceGrammar(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("dependency_semantics.go")
	if err != nil {
		t.Fatal(err)
	}
	production := strings.ToLower(string(raw))
	for _, forbidden := range []string{"quickbooks", "copy_all", "copy-all", "invoice_", "qbo_"} {
		if strings.Contains(production, forbidden) {
			t.Fatalf("production semantic checker contains forbidden provider/domain grammar %q", forbidden)
		}
	}
}

func TestValidateExactHydrationCoordinateBindsBytesRangeAndSourceCoordinate(t *testing.T) {
	t.Parallel()
	body := []byte("αbeta")
	selected := body[:2]
	coordinate := dependencyHydrationCoordinate{
		digest:   sha256Hex(body),
		start:    0,
		end:      2,
		count:    2,
		rangeSHA: sha256Hex(selected),
	}
	rows := dependencySemanticRows{path: "fixture.jsonl"}
	row := dependencySemanticRow{line: 2, kind: "fact"}
	loaded := loadedEvidence{Bodies: map[string]exactEvidenceBody{
		coordinate.digest: {
			Bytes: body,
			Coordinates: map[evidenceSourceCoordinate]string{
				{Ref: "fixture-ref", URL: "https://example.invalid/reference"}: strings.Repeat("a", 64),
			},
		},
	}}
	if err := validateExactHydrationCoordinate(rows, row, coordinate, "fixture-ref", "https://example.invalid/reference", loaded); err != nil {
		t.Fatalf("validateExactHydrationCoordinate() error = %v", err)
	}
	coordinate.rangeSHA = strings.Repeat("0", 64)
	err := validateExactHydrationCoordinate(rows, row, coordinate, "fixture-ref", "https://example.invalid/reference", loaded)
	if err == nil || !strings.Contains(err.Error(), "selected range") {
		t.Fatalf("tampered range error = %v, want exact-range rejection", err)
	}
}

func TestEvidenceConsumerIdentityClosureRejectsRoleSubstitutionWithinOneManifest(t *testing.T) {
	t.Parallel()
	manifestDigest := strings.Repeat("a", 64)
	bodyA := []byte("source document A")
	bodyB := []byte("source document B")
	digestA := sha256Hex(bodyA)
	digestB := sha256Hex(bodyB)
	identityA := evidenceBodyIdentity{ManifestSHA256: manifestDigest, SourceRef: "RecordA", ContentSHA256: digestA}
	identityB := evidenceBodyIdentity{ManifestSHA256: manifestDigest, SourceRef: "RecordB", ContentSHA256: digestB}
	loaded := loadedEvidence{
		Bodies: map[string]exactEvidenceBody{
			digestA: {Bytes: bodyA},
			digestB: {Bytes: bodyB},
		},
		MetadataByIdentity: map[evidenceBodyIdentity]evidenceBodyMetadata{
			identityA: {ManifestSHA256: manifestDigest, SourceRef: identityA.SourceRef, SourceURL: "https://example.invalid/a", ContentSHA256: digestA, ConsumerRoles: map[string]struct{}{}},
			identityB: {ManifestSHA256: manifestDigest, SourceRef: identityB.SourceRef, SourceURL: "https://example.invalid/b", ContentSHA256: digestB, ConsumerRoles: map[string]struct{}{"source_contract_index": {}}},
		},
	}
	artifact := artifactInput{Path: "source-contract.jsonl", RowsByKind: map[string][]map[string]interface{}{
		"source_document": {{
			"row_kind":      "source_document",
			"source_symbol": identityA.SourceRef,
			"source_url":    "https://example.invalid/a",
			"evidence_hydration_coordinate": map[string]interface{}{
				"source_content_sha256":     digestA,
				"byte_start_offset":         json.Number("0"),
				"byte_end_offset_exclusive": json.Number("17"),
				"selected_range_byte_count": json.Number("17"),
				"selected_range_sha256":     digestA,
			},
		}},
	}}

	err := validateEvidenceConsumerIdentityClosure(&parsedPlan{Locators: map[string]evidenceLocator{}}, loaded, map[string]artifactInput{"source_contract_index": artifact})
	if err == nil || !strings.Contains(err.Error(), "source_contract_index exact evidence identities") {
		t.Fatalf("error = %v, want per-body role-substitution refusal", err)
	}
}

func TestFieldSecurityProfileClassificationIsDataDrivenAndFailClosed(t *testing.T) {
	t.Parallel()
	profile := fieldSecurityProfile{
		registries: map[string][]string{
			"private_fields": {"PrivateDatum"},
			"standard_roles": {"exact_decimal."},
		},
		rules: []fieldSecurityRule{
			{id: "private", inputMember: "source_field", matchKind: "exact_registry_membership", registryMember: "private_fields", outputClass: "closed_private"},
			{id: "standard", inputMember: "target_role", matchKind: "prefix_registry_membership", registryMember: "standard_roles", outputClass: "closed_standard"},
			{id: "default", inputMember: "*", matchKind: "default", outputClass: "closed_private"},
		},
	}
	row := map[string]interface{}{
		"source_field":         "Amount",
		"source_provider_type": "Decimal",
		"target_role":          "exact_decimal.amount",
		"disposition":          "typed_field",
	}
	class, reason, ok := profile.classify(row)
	if !ok || class != "closed_standard" || reason != "standard" {
		t.Fatalf("classify() = (%q, %q, %t), want data-driven standard classification", class, reason, ok)
	}
	profile.rules = []fieldSecurityRule{{id: "unregistered", inputMember: "target_role", matchKind: "opaque_schema_owned_match", outputClass: "closed_standard"}}
	if _, _, ok := profile.classify(row); ok {
		t.Fatal("classify() accepted an unregistered policy rule")
	}
}

func TestMappingTransitiveSemanticRowsRejectsPrecedenceGap(t *testing.T) {
	t.Parallel()
	rows := dependencySemanticRows{path: "transitive.jsonl", byKind: map[string][]dependencySemanticRow{
		"artifact_manifest": {{line: 1, data: map[string]interface{}{"dependency_count": json.Number("2"), "canonical_admission_authorized": false}}},
		"mapping_transitive_dependency": {
			{line: 2, data: testTransitiveSemanticRow("first", 0)},
			{line: 3, data: testTransitiveSemanticRow("second", 2)},
		},
		"validation_summary": {{line: 4, data: map[string]interface{}{"dependency_count": json.Number("2"), "canonical_admission_authorized": false}}},
	}}
	if _, err := parseMappingTransitiveSemanticRows(rows); err == nil || !strings.Contains(err.Error(), "does not close contiguous position") {
		t.Fatalf("precedence-gap error = %v, want generic closure rejection", err)
	}
}

func testTransitiveSemanticRow(bindingID string, ordinal int64) map[string]interface{} {
	return map[string]interface{}{
		"dependency_binding_id": bindingID,
		"precedence_ordinal":    json.Number(strconv.FormatInt(ordinal, 10)),
		"dependency_role":       "generic_mapping_input",
		"artifact_identity": map[string]interface{}{
			"artifact": "generic_artifact_" + bindingID, "artifact_version": "1", "artifact_sha256": strings.Repeat(string('a'+rune(ordinal)), 64),
		},
		"applicability":     map[string]interface{}{"selector_kind": "schema_owned", "selector_values": []interface{}{"*"}},
		"authority_posture": "candidate", "exact_revalidation_required": true,
		"validation_binding": map[string]interface{}{
			"validation_schema_id": "schema_" + bindingID, "validation_schema_version": "1", "validation_schema_sha256": strings.Repeat(string('c'+rune(ordinal)), 64),
			"validation_profile_id": "profile_" + bindingID, "validation_profile_version": "1", "validation_profile_sha256": strings.Repeat("f", 64),
		},
	}
}

func TestFieldOccurrenceIdentityRequiresExactCoordinateAndPreservesEmptyProviderFacts(t *testing.T) {
	t.Parallel()
	coordinate := map[string]interface{}{
		"source_content_sha256":     strings.Repeat("a", 64),
		"byte_start_offset":         json.Number("1"),
		"byte_end_offset_exclusive": json.Number("2"),
		"selected_range_byte_count": json.Number("1"),
		"selected_range_sha256":     strings.Repeat("b", 64),
	}
	source := map[string]interface{}{
		"source_symbol":                 "Record",
		"surface_kind":                  "data_entity",
		"evidence_manifest_sha256":      strings.Repeat("d", 64),
		"source_ref":                    "Record.Fields",
		"source_url":                    "https://example.invalid/record/fields",
		"source_content_sha256":         strings.Repeat("a", 64),
		"evidence_locator_id":           "field_locator",
		"field_name":                    "Unknown",
		"provider_type":                 "",
		"cardinality":                   "scalar",
		"provider_requirement":          "",
		"section_path":                  []interface{}{"Record", "Fields"},
		"evidence_hydration_coordinate": coordinate,
	}
	mapping := map[string]interface{}{
		"source_symbol":                 "Record",
		"surface_kind":                  "data_entity",
		"evidence_manifest_sha256":      strings.Repeat("d", 64),
		"source_ref":                    "Record.Fields",
		"source_url":                    "https://example.invalid/record/fields",
		"source_content_sha256":         strings.Repeat("a", 64),
		"evidence_locator_id":           "field_locator",
		"source_field":                  "Unknown",
		"source_provider_type":          "",
		"source_cardinality":            "scalar",
		"source_requirement":            "",
		"source_section_path":           []interface{}{"Record", "Fields"},
		"evidence_hydration_coordinate": coordinate,
	}
	sourceID, err := sourceFieldOccurrenceIdentity(source)
	if err != nil {
		t.Fatalf("sourceFieldOccurrenceIdentity() error = %v", err)
	}
	mappingID, err := mappingFieldOccurrenceIdentity(mapping)
	if err != nil {
		t.Fatalf("mappingFieldOccurrenceIdentity() error = %v", err)
	}
	if sourceID != mappingID {
		t.Fatalf("source identity %q != mapping identity %q", sourceID, mappingID)
	}
	coordinate["selected_range_sha256"] = strings.Repeat("c", 64)
	mutatedID, err := mappingFieldOccurrenceIdentity(mapping)
	if err != nil {
		t.Fatalf("mutated mapping identity error = %v", err)
	}
	if mutatedID == sourceID {
		t.Fatal("field occurrence identity ignored exact range digest")
	}
	t.Run("same excerpt under distinct references remains distinct", func(t *testing.T) {
		left := cloneSemanticObjectForTest(t, source)
		right := cloneSemanticObjectForTest(t, source)
		right["source_ref"] = "Record.Fields.Alternate"
		right["source_url"] = "https://example.invalid/record/alternate-fields"
		leftID, leftErr := sourceFieldOccurrenceIdentity(left)
		rightID, rightErr := sourceFieldOccurrenceIdentity(right)
		if leftErr != nil || rightErr != nil || leftID == rightID {
			t.Fatalf("distinct-reference identities left=%q right=%q errors=%v/%v", leftID, rightID, leftErr, rightErr)
		}
	})
	t.Run("documentation-derived fact identity is authoritative when present", func(t *testing.T) {
		left := cloneSemanticObjectForTest(t, source)
		right := cloneSemanticObjectForTest(t, mapping)
		left[exactDocumentationDerivedFactIDField] = "docfact_field_amount"
		right[exactDocumentationDerivedFactIDField] = "docfact_field_amount"
		leftID, leftErr := sourceFieldOccurrenceIdentity(left)
		rightID, rightErr := mappingFieldOccurrenceIdentity(right)
		if leftErr != nil || rightErr != nil || leftID != rightID {
			t.Fatalf("fact-bound identities left=%q right=%q errors=%v/%v", leftID, rightID, leftErr, rightErr)
		}
		right[exactDocumentationDerivedFactIDField] = "docfact_field_other"
		otherID, otherErr := mappingFieldOccurrenceIdentity(right)
		if otherErr != nil || otherID == leftID {
			t.Fatalf("changed fact identity=%q error=%v, want distinct", otherID, otherErr)
		}
	})
}

func TestSourceOperationSemanticKeyIsDelimiterCollisionSafe(t *testing.T) {
	t.Parallel()
	leftIdentity := map[string]interface{}{"identity_kind": "queue_operation", "identity_components": map[string]interface{}{"channel": "source|heading", "operation": "operation"}}
	rightIdentity := map[string]interface{}{"identity_kind": "queue_operation", "identity_components": map[string]interface{}{"channel": "source", "operation": "heading|operation"}}
	left, err := sourceOperationSemanticKey("source", leftIdentity)
	if err != nil {
		t.Fatal(err)
	}
	right, err := sourceOperationSemanticKey("source", rightIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if left == right {
		t.Fatalf("domain-separated operation keys collided: %q", left)
	}
}

func TestSourceOperationSemanticKeyExcludesMutableEvidenceWording(t *testing.T) {
	t.Parallel()
	identity := map[string]interface{}{"identity_kind": "http_operation", "identity_components": map[string]interface{}{"method": "GET", "path": "/v3/company/{realm}/reports/ProfitAndLossDetail"}}
	first, err := sourceOperationSemanticKey("provider.report_detail", identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sourceOperationSemanticKey("provider.report_detail", identity)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("evidence wording/range digest changed semantic operation identity: %q != %q", first, second)
	}

	firstLocator := evidenceLocator{
		EvidenceManifestSHA256: "manifest_first",
		SourceContentSHA256:    strings.Repeat("a", 64),
		ByteStartOffset:        10,
		ByteEndOffsetExclusive: 20,
		SelectedRangeByteCount: 10,
		SelectedRangeSHA256:    strings.Repeat("b", 64),
		SourceRefs:             []string{"provider/reference/first"},
		SourceURLs:             []string{"https://provider.example/reference/first"},
	}
	firstLocator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(firstLocator))
	secondLocator := evidenceLocator{
		EvidenceManifestSHA256: "manifest_second",
		SourceContentSHA256:    strings.Repeat("c", 64),
		ByteStartOffset:        30,
		ByteEndOffsetExclusive: 45,
		SelectedRangeByteCount: 15,
		SelectedRangeSHA256:    strings.Repeat("d", 64),
		SourceRefs:             []string{"provider/reference/second"},
		SourceURLs:             []string{"https://provider.example/reference/second"},
	}
	secondLocator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(secondLocator))
	firstOccurrence := stableID("opocc", lengthPrefixedIdentityKey("docfact_first_wording", firstLocator.ID, candidateEvidenceLocatorIdentityKey(firstLocator)))
	secondOccurrence := stableID("opocc", lengthPrefixedIdentityKey("docfact_second_wording", secondLocator.ID, candidateEvidenceLocatorIdentityKey(secondLocator)))
	if firstOccurrence == secondOccurrence {
		t.Fatalf("mutable evidence occurrences aliased: %q", firstOccurrence)
	}
}

func cloneSemanticObjectForTest(t *testing.T, value map[string]interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var clone map[string]interface{}
	if err := decoder.Decode(&clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func TestValidateExactNumericDispositionRejectsMismatchedApplicabilityArms(t *testing.T) {
	t.Parallel()
	err := validateExactNumericDisposition("schema_owned_numeric_class", "not_applicable", "required_exact_pipeline")
	if err == nil || !strings.Contains(err.Error(), "applicability arms disagree") {
		t.Fatalf("error = %v, want numeric applicability-arm refusal", err)
	}
}

func TestSourceDocumentClosureSetEqualsTypedEvidenceMetadata(t *testing.T) {
	t.Parallel()
	body := []byte("source document")
	digest := sha256Hex(body)
	ref := "Record"
	sourceURL := "https://example.invalid/record"
	manifestSHA := strings.Repeat("a", 64)
	coordinateObject := map[string]interface{}{
		"source_content_sha256":     digest,
		"byte_start_offset":         json.Number("0"),
		"byte_end_offset_exclusive": json.Number("15"),
		"selected_range_byte_count": json.Number("15"),
		"selected_range_sha256":     digest,
	}
	document := dependencySemanticRow{line: 2, kind: "source_document", data: map[string]interface{}{
		"row_kind":                        "source_document",
		"evidence_manifest_sha256":        manifestSHA,
		"source_ref":                      ref,
		"source_url":                      sourceURL,
		"content_sha256":                  digest,
		"content_bytes":                   json.Number("15"),
		"source_content_hash_profile":     sourceContentHashProfile,
		"observed_line_delimiter_profile": "none",
		"representation":                  "selected_machine_export_text",
		"representation_coordinate":       "export-control",
		"source_representation_kind":      supportedEvidenceRepresentationKind,
		"component_byte_domain_profile":   componentByteDomainProfile,
		"evidence_hydration_coordinate":   coordinateObject,
	}}
	manifest := dependencySemanticRow{line: 1, kind: "artifact_manifest", data: map[string]interface{}{"consumer_contract": "source blind", "financial_value_contract": "exact values"}}
	summary := dependencySemanticRow{line: 3, kind: "validation_summary", data: map[string]interface{}{
		"expected_source_documents": json.Number("1"), "parsed_source_documents": json.Number("1"), "section_count": json.Number("0"), "field_contract_count": json.Number("0"), "documentation_table_row_count": json.Number("0"), "api_operation_count": json.Number("0"), "parse_issue_count": json.Number("0"),
		"exact_evidence_hydration_coordinates_present": true, "diagnostic_line_and_section_coordinates_are_authority": false, "source_neutral_targets_admitted": false,
	}}
	rows := dependencySemanticRows{path: "source.jsonl", byKind: map[string][]dependencySemanticRow{"artifact_manifest": {manifest}, "source_document": {document}, "validation_summary": {summary}}}
	locatorID := "locator"
	plan := &parsedPlan{
		Locators: map[string]evidenceLocator{locatorID: {
			ID: locatorID, EvidenceManifestSHA256: manifestSHA, SourceContentSHA256: digest, ByteStartOffset: 0, ByteEndOffsetExclusive: 15,
			SelectedRangeByteCount: 15, SelectedRangeSHA256: digest, SourceRefs: []string{ref}, SourceURLs: []string{sourceURL},
		}},
		Symbols: map[string]apiSymbol{"resource": {
			ID: "resource", Role: "resource", SemanticKey: "resource:" + ref, EvidenceLocatorIDs: []string{locatorID},
		}},
	}
	coordinate := evidenceSourceCoordinate{Ref: ref, URL: sourceURL}
	loaded := loadedEvidence{
		Bodies: map[string]exactEvidenceBody{digest: {Bytes: body, Coordinates: map[evidenceSourceCoordinate]string{coordinate: strings.Repeat("a", 64)}}},
		MetadataByCoordinate: map[evidenceSourceCoordinate]evidenceBodyMetadata{coordinate: {
			ManifestSHA256: manifestSHA, SourceRef: ref, SourceURL: sourceURL, ConsumerRoles: map[string]struct{}{"source_contract_index": {}},
			ContentSHA256: digest, ContentBytes: 15,
			Representation: "selected_machine_export_text", RepresentationCoordinate: "export-control", SourceRepresentationKind: supportedEvidenceRepresentationKind,
			ComponentByteDomainProfile: componentByteDomainProfile, SourceContentHashProfile: sourceContentHashProfile,
		}},
		ClassificationsBySourceSymbol:  map[string][]sourceClassificationOccurrence{ref: {{SourceSymbol: ref, SurfaceKind: "data_entity", Locator: plan.Locators[locatorID]}}},
		CandidateSymbolsBySourceSymbol: map[string]string{ref: "resource"},
	}
	ood := minimalSourceSemanticOOD()
	operationState := operationApplicabilityState{
		byOperationID: map[string]operationApplicabilityEntry{}, bySemanticIdentity: map[string]operationApplicabilityEntry{},
		resourceBindingsByID: map[string]string{}, resourceSourceSymbolsByID: map[string]string{}, sourceContractOperationIDs: map[string]struct{}{}, operationKindCounts: map[string]int{},
	}
	if _, err := validateSourceContractSemanticRows(rows, plan, ood, loaded, &operationState, apiGraphApplicabilityState{}); err != nil {
		t.Fatalf("validateSourceContractSemanticRows() error = %v", err)
	}
	metadata := loaded.MetadataByCoordinate[coordinate]
	metadata.RepresentationCoordinate = "other-export-control"
	loaded.MetadataByCoordinate[coordinate] = metadata
	if _, err := validateSourceContractSemanticRows(rows, plan, ood, loaded, &operationState, apiGraphApplicabilityState{}); err == nil || !strings.Contains(err.Error(), "roster-bound source-contract evidence metadata") {
		t.Fatalf("metadata mismatch error = %v, want exact typed-metadata rejection", err)
	}
}

func TestSourceContractSeparatesDocumentsFromManyToManySemanticOccurrences(t *testing.T) {
	t.Parallel()
	type documentFixture struct {
		ref, url, manifestSHA, digest, locatorID string
		body                                     []byte
		coordinate                               evidenceSourceCoordinate
		locator                                  evidenceLocator
		row                                      dependencySemanticRow
	}
	newDocument := func(index int, bodyText string) documentFixture {
		body := []byte(bodyText)
		digest := sha256Hex(body)
		ref := fmt.Sprintf("document.%d", index)
		url := fmt.Sprintf("https://example.invalid/document/%d", index)
		manifestSHA := strings.Repeat(fmt.Sprintf("%x", index), 64)
		locatorID := fmt.Sprintf("locator_%d", index)
		coordinate := evidenceSourceCoordinate{Ref: ref, URL: url}
		locator := evidenceLocator{ID: locatorID, EvidenceManifestSHA256: manifestSHA, SourceContentSHA256: digest, ByteStartOffset: 0, ByteEndOffsetExclusive: int64(len(body)), SelectedRangeByteCount: int64(len(body)), SelectedRangeSHA256: digest, SourceRefs: []string{ref}, SourceURLs: []string{url}}
		coordinateObject := map[string]interface{}{"source_content_sha256": digest, "byte_start_offset": json.Number("0"), "byte_end_offset_exclusive": json.Number(fmt.Sprintf("%d", len(body))), "selected_range_byte_count": json.Number(fmt.Sprintf("%d", len(body))), "selected_range_sha256": digest}
		row := dependencySemanticRow{line: index + 1, kind: "source_document", data: map[string]interface{}{
			"row_kind": "source_document", "evidence_manifest_sha256": manifestSHA, "source_ref": ref, "source_url": url, "content_sha256": digest, "content_bytes": json.Number(fmt.Sprintf("%d", len(body))), "source_content_hash_profile": sourceContentHashProfile, "observed_line_delimiter_profile": "none", "representation": "selected_machine_export_text", "representation_coordinate": "export-control", "source_representation_kind": supportedEvidenceRepresentationKind, "component_byte_domain_profile": componentByteDomainProfile, "evidence_hydration_coordinate": coordinateObject,
		}}
		return documentFixture{ref: ref, url: url, manifestSHA: manifestSHA, digest: digest, locatorID: locatorID, body: body, coordinate: coordinate, locator: locator, row: row}
	}
	first := newDocument(1, "first source document")
	second := newDocument(2, "second source document")
	loaded := loadedEvidence{
		Bodies: map[string]exactEvidenceBody{
			first.digest:  {Bytes: first.body, Coordinates: map[evidenceSourceCoordinate]string{first.coordinate: first.manifestSHA}},
			second.digest: {Bytes: second.body, Coordinates: map[evidenceSourceCoordinate]string{second.coordinate: second.manifestSHA}},
		},
		MetadataByCoordinate: map[evidenceSourceCoordinate]evidenceBodyMetadata{
			first.coordinate:  {ManifestSHA256: first.manifestSHA, SourceRef: first.ref, SourceURL: first.url, ContentSHA256: first.digest, ContentBytes: int64(len(first.body)), Representation: "selected_machine_export_text", RepresentationCoordinate: "export-control", SourceRepresentationKind: supportedEvidenceRepresentationKind, ComponentByteDomainProfile: componentByteDomainProfile, SourceContentHashProfile: sourceContentHashProfile, ConsumerRoles: map[string]struct{}{"source_contract_index": {}}},
			second.coordinate: {ManifestSHA256: second.manifestSHA, SourceRef: second.ref, SourceURL: second.url, ContentSHA256: second.digest, ContentBytes: int64(len(second.body)), Representation: "selected_machine_export_text", RepresentationCoordinate: "export-control", SourceRepresentationKind: supportedEvidenceRepresentationKind, ComponentByteDomainProfile: componentByteDomainProfile, SourceContentHashProfile: sourceContentHashProfile, ConsumerRoles: map[string]struct{}{"source_contract_index": {}}},
		},
		ClassificationsBySourceSymbol: map[string][]sourceClassificationOccurrence{
			"alpha": {{SourceSymbol: "alpha", SurfaceKind: "data_entity", Locator: first.locator}, {SourceSymbol: "alpha", SurfaceKind: "data_entity", Locator: second.locator}},
			"beta":  {{SourceSymbol: "beta", SurfaceKind: "data_entity", Locator: first.locator}},
			"gamma": {{SourceSymbol: "gamma", SurfaceKind: "data_entity", Locator: second.locator}},
		},
		CandidateSymbolsBySourceSymbol: map[string]string{"alpha": "alpha", "beta": "beta", "gamma": "gamma"},
	}
	manifest := dependencySemanticRow{line: 1, kind: "artifact_manifest", data: map[string]interface{}{"consumer_contract": "source blind", "financial_value_contract": "exact values"}}
	summary := dependencySemanticRow{line: 4, kind: "validation_summary", data: map[string]interface{}{
		"expected_source_documents": json.Number("2"), "parsed_source_documents": json.Number("2"), "section_count": json.Number("0"), "field_contract_count": json.Number("0"), "documentation_table_row_count": json.Number("0"), "api_operation_count": json.Number("0"), "parse_issue_count": json.Number("0"),
		"exact_evidence_hydration_coordinates_present": true, "diagnostic_line_and_section_coordinates_are_authority": false, "source_neutral_targets_admitted": false,
	}}
	rows := dependencySemanticRows{path: "source.jsonl", byKind: map[string][]dependencySemanticRow{"artifact_manifest": {manifest}, "source_document": {first.row, second.row}, "validation_summary": {summary}}}
	plan := &parsedPlan{
		Locators: map[string]evidenceLocator{first.locatorID: first.locator, second.locatorID: second.locator},
		Symbols: map[string]apiSymbol{
			"alpha": {ID: "alpha", Role: "resource", SemanticKey: "resource:alpha", EvidenceLocatorIDs: []string{first.locatorID, second.locatorID}},
			"beta":  {ID: "beta", Role: "resource", SemanticKey: "resource:beta", EvidenceLocatorIDs: []string{first.locatorID}},
			"gamma": {ID: "gamma", Role: "resource", SemanticKey: "resource:gamma", EvidenceLocatorIDs: []string{second.locatorID}},
		},
	}
	operationState := operationApplicabilityState{byOperationID: map[string]operationApplicabilityEntry{}, bySemanticIdentity: map[string]operationApplicabilityEntry{}, resourceBindingsByID: map[string]string{}, resourceSourceSymbolsByID: map[string]string{}, sourceContractOperationIDs: map[string]struct{}{}, operationKindCounts: map[string]int{}}
	if _, err := validateSourceContractSemanticRows(rows, plan, minimalSourceSemanticOOD(), loaded, &operationState, apiGraphApplicabilityState{}); err != nil {
		t.Fatalf("many-to-many document/classification closure rejected: %v", err)
	}
}

func TestSourceContractConsolidatesManyDocumentOperationOccurrencesWithoutAccessCrossProduct(t *testing.T) {
	t.Parallel()
	validate := func(f manyDocumentOperationSemanticFixture) error {
		_, err := validateSourceContractSemanticRows(f.rows, f.plan, f.ood, f.loaded, &f.operations, f.applicability)
		return err
	}
	if err := validate(newManyDocumentOperationSemanticFixture(t)); err != nil {
		t.Fatalf("joint many-document/classification/access fixture rejected: %v", err)
	}
	t.Run("swapped relationship locator rosters", func(t *testing.T) {
		f := newManyDocumentOperationSemanticFixture(t)
		read := f.plan.Relationships[f.readRelationshipID]
		write := f.plan.Relationships[f.writeRelationshipID]
		read.LocatorIDs = append([]string(nil), write.LocatorIDs...)
		f.plan.Relationships[f.readRelationshipID] = read
		if err := validate(f); err == nil || !strings.Contains(err.Error(), "locator roster does not equal its exact access claim roster") {
			t.Fatalf("error = %v, want swapped access-locator refusal", err)
		}
	})
	t.Run("same fact aliases distinct references", func(t *testing.T) {
		f := newManyDocumentOperationSemanticFixture(t)
		occurrences, _ := semanticObjectSlice(f.rows.byKind["api_operation"][0].data, "operation_evidence_occurrences")
		firstFact, _ := semanticString(occurrences[0], "documentation_derived_fact_id")
		occurrences[1]["documentation_derived_fact_id"] = firstFact
		locatorID, _ := semanticString(occurrences[1], "evidence_locator_id")
		locator := f.plan.Locators[locatorID]
		occurrences[1]["occurrence_id"] = stableID("opocc", lengthPrefixedIdentityKey(firstFact, locatorID, candidateEvidenceLocatorIdentityKey(locator)))
		sort.Slice(occurrences, func(left, right int) bool {
			leftID, _ := semanticString(occurrences[left], "occurrence_id")
			rightID, _ := semanticString(occurrences[right], "occurrence_id")
			return leftID < rightID
		})
		f.rows.byKind["api_operation"][0].data["operation_evidence_occurrences"] = operationEvidenceOccurrencesAsInterfaces(occurrences)
		if err := validate(f); err == nil || !strings.Contains(err.Error(), "aliases documentation-derived fact") {
			t.Fatalf("error = %v, want distinct-ref fact-alias refusal", err)
		}
	})
	t.Run("omitted source role partition", func(t *testing.T) {
		f := newManyDocumentOperationSemanticFixture(t)
		entry := f.operations.byOperationID["operation"]
		entry.resourceAccesses = append([]operationResourceAccess(nil), entry.resourceAccesses[:1]...)
		f.operations.byOperationID["operation"] = entry
		f.operations.bySemanticIdentity[entry.semanticIdentity] = entry
		if err := validate(f); err == nil || !strings.Contains(err.Error(), "source access partition") {
			t.Fatalf("error = %v, want omitted source-role partition refusal", err)
		}
	})
	t.Run("duplicate source role partition", func(t *testing.T) {
		f := newManyDocumentOperationSemanticFixture(t)
		entry := f.operations.byOperationID["operation"]
		entry.resourceAccesses = append(entry.resourceAccesses, entry.resourceAccesses[0])
		entry.resourceAccesses[len(entry.resourceAccesses)-1].id = "duplicate_read_access"
		f.operations.byOperationID["operation"] = entry
		f.operations.bySemanticIdentity[entry.semanticIdentity] = entry
		if err := validate(f); err == nil || !strings.Contains(err.Error(), "duplicates source-contract access") {
			t.Fatalf("error = %v, want duplicate source-role partition refusal", err)
		}
	})
	t.Run("omitted classification occurrence", func(t *testing.T) {
		f := newManyDocumentOperationSemanticFixture(t)
		f.loaded.ClassificationsBySourceSymbol["operation_source"] = f.loaded.ClassificationsBySourceSymbol["operation_source"][:1]
		if err := validate(f); err == nil || !strings.Contains(err.Error(), "covering classification occurrences") {
			t.Fatalf("error = %v, want omitted classification occurrence refusal", err)
		}
	})
}

type manyDocumentOperationSemanticFixture struct {
	rows                dependencySemanticRows
	plan                *parsedPlan
	ood                 oodContract
	loaded              loadedEvidence
	operations          operationApplicabilityState
	applicability       apiGraphApplicabilityState
	readRelationshipID  string
	writeRelationshipID string
}

func operationEvidenceOccurrencesAsInterfaces(values []map[string]interface{}) []interface{} {
	result := make([]interface{}, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func newManyDocumentOperationSemanticFixture(t *testing.T) manyDocumentOperationSemanticFixture {
	t.Helper()
	type document struct {
		ref, url, manifest, digest string
		body                       []byte
		coordinate                 evidenceSourceCoordinate
		whole, read, write         evidenceLocator
		documentRow                dependencySemanticRow
	}
	newLocator := func(id, manifest, ref, url string, body []byte, start, end int64) evidenceLocator {
		selected := body[start:end]
		return evidenceLocator{ID: id, EvidenceManifestSHA256: manifest, SourceContentSHA256: sha256Hex(body), ByteStartOffset: start, ByteEndOffsetExclusive: end, SelectedRangeByteCount: end - start, SelectedRangeSHA256: sha256Hex(selected), SourceRefs: []string{ref}, SourceURLs: []string{url}}
	}
	identity := map[string]interface{}{"identity_kind": "http_operation", "identity_components": map[string]interface{}{"method": "POST", "path": "/records/transform"}}
	semanticKey, err := sourceOperationSemanticKey("operation_source", identity)
	if err != nil {
		t.Fatal(err)
	}
	newDocument := func(index int) document {
		body := []byte("read_a then write_b")
		ref := fmt.Sprintf("operation.document.%d", index)
		url := fmt.Sprintf("https://example.invalid/operation/%d", index)
		manifest := strings.Repeat(fmt.Sprintf("%x", index), 64)
		digest := sha256Hex(body)
		coordinate := evidenceSourceCoordinate{Ref: ref, URL: url}
		whole := newLocator(fmt.Sprintf("whole_%d", index), manifest, ref, url, body, 0, int64(len(body)))
		read := newLocator(fmt.Sprintf("read_%d", index), manifest, ref, url, body, 0, 6)
		write := newLocator(fmt.Sprintf("write_%d", index), manifest, ref, url, body, 12, 19)
		fullCoordinate := map[string]interface{}{"source_content_sha256": digest, "byte_start_offset": json.Number("0"), "byte_end_offset_exclusive": json.Number(fmt.Sprintf("%d", len(body))), "selected_range_byte_count": json.Number(fmt.Sprintf("%d", len(body))), "selected_range_sha256": digest}
		documentData := map[string]interface{}{
			"row_kind": "source_document", "evidence_manifest_sha256": manifest, "source_ref": ref, "source_url": url, "content_sha256": digest, "content_bytes": json.Number(fmt.Sprintf("%d", len(body))), "source_content_hash_profile": sourceContentHashProfile, "observed_line_delimiter_profile": "none", "representation": "selected_machine_export_text", "representation_coordinate": fmt.Sprintf("copy-all-%d", index), "source_representation_kind": supportedEvidenceRepresentationKind, "component_byte_domain_profile": componentByteDomainProfile, "evidence_hydration_coordinate": fullCoordinate,
		}
		return document{ref: ref, url: url, manifest: manifest, digest: digest, body: body, coordinate: coordinate, whole: whole, read: read, write: write,
			documentRow: dependencySemanticRow{line: index, kind: "source_document", data: documentData}}
	}
	first := newDocument(1)
	second := newDocument(2)
	locators := map[string]evidenceLocator{}
	for _, locator := range []evidenceLocator{first.whole, first.read, first.write, second.whole, second.read, second.write} {
		locators[locator.ID] = locator
	}
	readLocators := []string{first.read.ID, second.read.ID}
	writeLocators := []string{first.write.ID, second.write.ID}
	sort.Strings(readLocators)
	sort.Strings(writeLocators)
	operationLocators := append(append([]string(nil), readLocators...), writeLocators...)
	sort.Strings(operationLocators)
	occurrenceObjects := make([]map[string]interface{}, 0, 4)
	for _, occurrence := range []struct {
		factID  string
		locator evidenceLocator
	}{
		{"docfact_read_1", first.read}, {"docfact_read_2", second.read}, {"docfact_write_1", first.write}, {"docfact_write_2", second.write},
	} {
		occurrenceObjects = append(occurrenceObjects, map[string]interface{}{
			"occurrence_id":       stableID("opocc", lengthPrefixedIdentityKey(occurrence.factID, occurrence.locator.ID, candidateEvidenceLocatorIdentityKey(occurrence.locator))),
			"evidence_locator_id": occurrence.locator.ID, "documentation_derived_fact_id": occurrence.factID,
		})
	}
	sort.Slice(occurrenceObjects, func(left, right int) bool {
		leftID, _ := semanticString(occurrenceObjects[left], "occurrence_id")
		rightID, _ := semanticString(occurrenceObjects[right], "occurrence_id")
		return leftID < rightID
	})
	operationData := map[string]interface{}{
		"row_kind": "api_operation", "source_symbol": "operation_source", "source_ref": first.ref, "surface_kind": "operation", "source_url": first.url, "source_operation_identity": identity, "evidence_hydration_coordinate": first.documentRow.data["evidence_hydration_coordinate"],
		"operation_evidence_occurrences": operationEvidenceOccurrencesAsInterfaces(occurrenceObjects),
		"resource_accesses": []interface{}{
			map[string]interface{}{"source_symbol": "resource_a", "relationship_label": "operation_reads_resource", "evidence_locator_ids": []interface{}{first.read.ID, second.read.ID}, "documentation_derived_fact_ids": []interface{}{"docfact_read_1", "docfact_read_2"}},
			map[string]interface{}{"source_symbol": "resource_b", "relationship_label": "operation_writes_resource", "evidence_locator_ids": []interface{}{first.write.ID, second.write.ID}, "documentation_derived_fact_ids": []interface{}{"docfact_write_1", "docfact_write_2"}},
		},
	}
	operationRaw, err := json.Marshal(operationData)
	if err != nil {
		t.Fatal(err)
	}
	operationRow := dependencySemanticRow{line: 4, kind: "api_operation", raw: operationRaw, data: operationData}
	readRelationshipID := stableID("capi_rel", lengthPrefixedIdentityKey("operation_reads_resource", "operation", "resource_a"))
	writeRelationshipID := stableID("capi_rel", lengthPrefixedIdentityKey("operation_writes_resource", "operation", "resource_b"))
	plan := &parsedPlan{Locators: locators, Symbols: map[string]apiSymbol{
		"operation":  {ID: "operation", Role: "operation", SemanticKey: semanticKey, EvidenceLocatorIDs: operationLocators},
		"resource_a": {ID: "resource_a", Role: "resource", SemanticKey: "resource:resource_a", EvidenceLocatorIDs: []string{first.whole.ID, second.whole.ID}},
		"resource_b": {ID: "resource_b", Role: "resource", SemanticKey: "resource:resource_b", EvidenceLocatorIDs: []string{first.whole.ID, second.whole.ID}},
	}, Relationships: map[string]apiRelationship{
		readRelationshipID:  {ID: readRelationshipID, Label: "operation_reads_resource", SourceID: "operation", TargetID: "resource_a", LocatorIDs: readLocators},
		writeRelationshipID: {ID: writeRelationshipID, Label: "operation_writes_resource", SourceID: "operation", TargetID: "resource_b", LocatorIDs: writeLocators},
	}, Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{}}
	loaded := loadedEvidence{
		Bodies: map[string]exactEvidenceBody{first.digest: {Bytes: first.body, Coordinates: map[evidenceSourceCoordinate]string{first.coordinate: first.manifest, second.coordinate: second.manifest}}},
		MetadataByCoordinate: map[evidenceSourceCoordinate]evidenceBodyMetadata{
			first.coordinate:  {ManifestSHA256: first.manifest, SourceRef: first.ref, SourceURL: first.url, ContentSHA256: first.digest, ContentBytes: int64(len(first.body)), Representation: "selected_machine_export_text", RepresentationCoordinate: "copy-all-1", SourceRepresentationKind: supportedEvidenceRepresentationKind, ComponentByteDomainProfile: componentByteDomainProfile, SourceContentHashProfile: sourceContentHashProfile, ConsumerRoles: map[string]struct{}{"source_contract_index": {}}},
			second.coordinate: {ManifestSHA256: second.manifest, SourceRef: second.ref, SourceURL: second.url, ContentSHA256: second.digest, ContentBytes: int64(len(second.body)), Representation: "selected_machine_export_text", RepresentationCoordinate: "copy-all-2", SourceRepresentationKind: supportedEvidenceRepresentationKind, ComponentByteDomainProfile: componentByteDomainProfile, SourceContentHashProfile: sourceContentHashProfile, ConsumerRoles: map[string]struct{}{"source_contract_index": {}}},
		},
		ClassificationsBySourceSymbol: map[string][]sourceClassificationOccurrence{
			"operation_source": {{SourceSymbol: "operation_source", SurfaceKind: "operation", Locator: first.whole}, {SourceSymbol: "operation_source", SurfaceKind: "operation", Locator: second.whole}},
			"resource_a":       {{SourceSymbol: "resource_a", SurfaceKind: "resource", Locator: first.whole}, {SourceSymbol: "resource_a", SurfaceKind: "resource", Locator: second.whole}},
			"resource_b":       {{SourceSymbol: "resource_b", SurfaceKind: "resource", Locator: first.whole}, {SourceSymbol: "resource_b", SurfaceKind: "resource", Locator: second.whole}},
		},
		CandidateSymbolsBySourceSymbol: map[string]string{"operation_source": "operation", "resource_a": "resource_a", "resource_b": "resource_b"},
	}
	manifest := dependencySemanticRow{line: 1, kind: "artifact_manifest", data: map[string]interface{}{"consumer_contract": "source blind", "financial_value_contract": "exact values"}}
	summary := dependencySemanticRow{line: 6, kind: "validation_summary", data: map[string]interface{}{
		"expected_source_documents": json.Number("2"), "parsed_source_documents": json.Number("2"), "section_count": json.Number("0"), "field_contract_count": json.Number("0"), "documentation_table_row_count": json.Number("0"), "api_operation_count": json.Number("1"), "parse_issue_count": json.Number("0"), "exact_evidence_hydration_coordinates_present": true, "diagnostic_line_and_section_coordinates_are_authority": false, "source_neutral_targets_admitted": false,
	}}
	rows := dependencySemanticRows{path: "source.jsonl", byKind: map[string][]dependencySemanticRow{"artifact_manifest": {manifest}, "source_document": {first.documentRow, second.documentRow}, "api_operation": {operationRow}, "validation_summary": {summary}}}
	entry := operationApplicabilityEntry{operationID: "operation", semanticIdentity: semanticKey, sourceSymbol: "operation_source", sourceIdentity: identity, evidenceLocatorIDs: stringSliceSet(operationLocators), evidenceFactIDs: stringSet([]string{"docfact_read_1", "docfact_read_2", "docfact_write_1", "docfact_write_2"}), resourceAccesses: []operationResourceAccess{
		{id: "read_access", resourceID: "resource_a", resourceSemanticIdentity: "resource:resource_a", resourceSourceSymbol: "resource_a", relationshipLabel: "operation_reads_resource", classifierInputBinding: operationClassifierInputBinding{artifactRole: operationClassifierSourceArtifactRole}, evidenceLocatorIDs: stringSliceSet(readLocators), evidenceFactIDs: stringSet([]string{"docfact_read_1", "docfact_read_2"})},
		{id: "write_access", resourceID: "resource_b", resourceSemanticIdentity: "resource:resource_b", resourceSourceSymbol: "resource_b", relationshipLabel: "operation_writes_resource", classifierInputBinding: operationClassifierInputBinding{artifactRole: operationClassifierSourceArtifactRole}, evidenceLocatorIDs: stringSliceSet(writeLocators), evidenceFactIDs: stringSet([]string{"docfact_write_1", "docfact_write_2"})},
	}}
	operations := operationApplicabilityState{byOperationID: map[string]operationApplicabilityEntry{"operation": entry}, bySemanticIdentity: map[string]operationApplicabilityEntry{semanticKey: entry}, resourceBindingsByID: map[string]string{"resource_a": "resource:resource_a", "resource_b": "resource:resource_b"}, resourceSourceSymbolsByID: map[string]string{"resource_a": "resource_a", "resource_b": "resource_b"}, sourceContractOperationIDs: map[string]struct{}{}, operationKindCounts: map[string]int{}}
	ood := minimalSourceSemanticOOD()
	ood.Sections.EdgeModel.Relationships.Constraints = append(ood.Sections.EdgeModel.Relationships.Constraints, relationshipConstraint{EdgeLabel: "operation_reads_resource", SourceRole: "operation", TargetRole: "resource"})
	return manyDocumentOperationSemanticFixture{rows: rows, plan: plan, ood: ood, loaded: loaded, operations: operations, applicability: apiGraphApplicabilityState{}, readRelationshipID: readRelationshipID, writeRelationshipID: writeRelationshipID}
}

func TestSourceOperationAccessRejectsCrossResourceRetarget(t *testing.T) {
	t.Parallel()
	body := []byte("source document")
	digest := sha256Hex(body)
	ref := "Record"
	sourceURL := "https://example.invalid/record"
	manifestSHA := strings.Repeat("a", 64)
	coordinateObject := map[string]interface{}{
		"source_content_sha256": digest, "byte_start_offset": json.Number("0"), "byte_end_offset_exclusive": json.Number("15"), "selected_range_byte_count": json.Number("15"), "selected_range_sha256": digest,
	}
	document := dependencySemanticRow{line: 2, kind: "source_document", data: map[string]interface{}{
		"row_kind": "source_document", "evidence_manifest_sha256": manifestSHA, "source_ref": ref, "source_url": sourceURL, "content_sha256": digest, "content_bytes": json.Number("15"), "source_content_hash_profile": sourceContentHashProfile, "observed_line_delimiter_profile": "none", "representation": "selected_machine_export_text", "representation_coordinate": "export-control", "source_representation_kind": supportedEvidenceRepresentationKind, "component_byte_domain_profile": componentByteDomainProfile, "evidence_hydration_coordinate": coordinateObject,
	}}
	operationIdentity := map[string]interface{}{"identity_kind": "message_queue_producer", "identity_components": map[string]interface{}{"delivery_mode": "at_least_once", "topic": "records"}}
	operationKey, keyErr := sourceOperationSemanticKey(ref, operationIdentity)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	operation := dependencySemanticRow{line: 3, kind: "api_operation", data: map[string]interface{}{
		"row_kind": "api_operation", "source_symbol": ref, "source_ref": ref, "surface_kind": "data_entity", "source_url": sourceURL, "content_sha256": digest, "line_number": json.Number("1"), "section_path": []interface{}{"Record", "Operations"}, "source_operation_identity": operationIdentity, "source_neutral_capability": "candidate_write", "resource_accesses": []interface{}{map[string]interface{}{"source_symbol": ref, "relationship_label": "operation_writes_resource"}}, "evidence_hydration_coordinate": coordinateObject,
	}}
	manifest := dependencySemanticRow{line: 1, kind: "artifact_manifest", data: map[string]interface{}{"consumer_contract": "source blind", "financial_value_contract": "exact values"}}
	summary := dependencySemanticRow{line: 4, kind: "validation_summary", data: map[string]interface{}{
		"expected_source_documents": json.Number("1"), "parsed_source_documents": json.Number("1"), "section_count": json.Number("0"), "field_contract_count": json.Number("0"), "documentation_table_row_count": json.Number("0"), "api_operation_count": json.Number("1"), "parse_issue_count": json.Number("0"), "exact_evidence_hydration_coordinates_present": true, "diagnostic_line_and_section_coordinates_are_authority": false, "source_neutral_targets_admitted": false,
	}}
	rows := dependencySemanticRows{path: "source.jsonl", byKind: map[string][]dependencySemanticRow{"artifact_manifest": {manifest}, "source_document": {document}, "api_operation": {operation}, "validation_summary": {summary}}}
	locatorID := "locator"
	plan := &parsedPlan{
		Locators: map[string]evidenceLocator{locatorID: {ID: locatorID, EvidenceManifestSHA256: manifestSHA, SourceContentSHA256: digest, ByteStartOffset: 0, ByteEndOffsetExclusive: 15, SelectedRangeByteCount: 15, SelectedRangeSHA256: digest, SourceRefs: []string{ref}, SourceURLs: []string{sourceURL}}},
		Symbols: map[string]apiSymbol{
			"resource":  {ID: "resource", Role: "resource", SemanticKey: "resource:" + ref, EvidenceLocatorIDs: []string{locatorID}},
			"other":     {ID: "other", Role: "resource", SemanticKey: "webhook_resource:Other", EvidenceLocatorIDs: []string{}},
			"operation": {ID: "operation", Role: "operation", SemanticKey: operationKey, EvidenceLocatorIDs: []string{locatorID}},
		},
		Relationships: map[string]apiRelationship{"retargeted": {ID: "retargeted", Label: "operation_writes_resource", SourceID: "operation", TargetID: "other", LocatorIDs: []string{locatorID}}},
	}
	coordinate := evidenceSourceCoordinate{Ref: ref, URL: sourceURL}
	loaded := loadedEvidence{
		Bodies:                        map[string]exactEvidenceBody{digest: {Bytes: body, Coordinates: map[evidenceSourceCoordinate]string{coordinate: strings.Repeat("a", 64)}}},
		MetadataByCoordinate:          map[evidenceSourceCoordinate]evidenceBodyMetadata{coordinate: {ManifestSHA256: manifestSHA, SourceRef: ref, SourceURL: sourceURL, ContentSHA256: digest, ContentBytes: 15, Representation: "selected_machine_export_text", RepresentationCoordinate: "export-control", SourceRepresentationKind: supportedEvidenceRepresentationKind, ComponentByteDomainProfile: componentByteDomainProfile, SourceContentHashProfile: sourceContentHashProfile, ConsumerRoles: map[string]struct{}{"source_contract_index": {}}}},
		ClassificationsBySourceSymbol: map[string][]sourceClassificationOccurrence{ref: {{SourceSymbol: ref, SurfaceKind: "data_entity", Locator: plan.Locators[locatorID]}}},
	}
	entry := operationApplicabilityEntry{operationID: "operation", semanticIdentity: operationKey, sourceSymbol: ref, sourceIdentity: operationIdentity, resourceAccesses: []operationResourceAccess{{resourceID: "resource", resourceSemanticIdentity: "resource:" + ref, resourceSourceSymbol: ref, relationshipLabel: "operation_writes_resource"}}}
	operationState := operationApplicabilityState{
		byOperationID:        map[string]operationApplicabilityEntry{"operation": entry},
		bySemanticIdentity:   map[string]operationApplicabilityEntry{operationKey: entry},
		resourceBindingsByID: map[string]string{"resource": "resource:" + ref, "other": "webhook_resource:Other"}, resourceSourceSymbolsByID: map[string]string{"resource": ref, "other": "Other"}, sourceContractOperationIDs: map[string]struct{}{}, operationKindCounts: map[string]int{"fixture_operation": 1},
	}
	_, err := validateSourceContractSemanticRows(rows, plan, minimalSourceSemanticOOD(), loaded, &operationState, apiGraphApplicabilityState{relationshipByLabel: map[string]relationshipApplicabilityRule{"operation_writes_resource": {id: "fixture_write_rule"}}})
	if err == nil || !strings.Contains(err.Error(), "without a sealed typed API-symbol derivation") {
		t.Fatalf("retarget error = %v, want earliest exact typed-index retarget refusal", err)
	}
}

func minimalSourceSemanticOOD() oodContract {
	var ood oodContract
	ood.Sections.ObjectModel.Roles.Roles = []string{"operation", "resource"}
	ood.Sections.ObjectModel.Roles.CardinalityRule = "exactly one immutable role"
	ood.Sections.ObjectModel.Roles.AuthorityRule = "bound role is authoritative"
	ood.Sections.ObjectModel.Properties.EligibleSubjects = []string{"api_symbol_object", "api_relationship_edge"}
	ood.Sections.ObjectModel.Properties.Families = []string{"fixture_property"}
	ood.Sections.ObjectModel.Properties.SchemaGovernanceRule = "schema bound"
	ood.Sections.ObjectModel.Properties.EvidenceRule = "exact evidence bound"
	ood.Sections.ObjectModel.Properties.AuthorityExclusions = []string{"search_payload"}
	ood.Sections.ObjectModel.ExternalRelationshipAuthorityBoundary.MaterializationRule = "absence means optional"
	ood.Sections.EdgeModel.Relationships.Family = "api_relationship"
	ood.Sections.EdgeModel.Relationships.SourceClass = "api_symbol"
	ood.Sections.EdgeModel.Relationships.TargetClass = "api_symbol"
	ood.Sections.EdgeModel.Relationships.Constraints = []relationshipConstraint{{EdgeLabel: "operation_writes_resource", SourceRole: "operation", TargetRole: "resource"}}
	ood.Sections.GraphMaterialization.ExternalReferenceIngestion.CanonicalIngestionExecutionModel.CapabilitySequence = []string{"docgraph.source.authorize"}
	ood.Sections.GraphMaterialization.ExternalReferenceIngestion.CanonicalIngestionExecutionModel.EntryCapability = "docgraph.source.authorize"
	ood.Sections.GraphMaterialization.ExternalReferenceIngestion.ObjectClassesCreated = []string{"api_symbol"}
	ood.Sections.GraphMaterialization.ExternalReferenceIngestion.EdgeLabelsCreated = []string{"documents"}
	ood.Sections.GraphMaterialization.ExternalReferenceIngestion.SourceAuthorityPolicy.AllowedSourceClasses = []string{"official_vendor_documentation"}
	ood.Sections.GraphMaterialization.ExternalReferenceIngestion.SourceAuthorityPolicy.ForbiddenSourceClasses = []string{"unofficial_blog"}
	ood.Sections.GraphMaterialization.ExternalReferenceIngestion.SourceAuthorityPolicy.Rule = "exact source binding"
	return ood
}
