//go:build externalfixture

package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"testing"
)

const (
	xeroAssetsOpenAPIByteCount = 37955
	xeroAssetsOpenAPISHA256    = "bab9cd4bc391cba01fb57fea0503d9c4cd50b4f8bbcb590a112e5676e6143c81"
	xeroAssetsOpenAPICommit    = "853dc01a99c179d21df3a0b4f870ed612aebf3e3"
	xeroAssetsSourceRef        = "xero.openapi.assets.v17"
	xeroAssetsSourceURL        = "https://raw.githubusercontent.com/XeroAPI/Xero-OpenAPI/853dc01a99c179d21df3a0b4f870ed612aebf3e3/xero_assets.yaml"

	xeroDocumentSource    = "xero_assets_openapi_document"
	xeroOperationSource   = "xero_assets_get_assets_operation"
	xeroPagingSource      = "xero_assets_pagination_parameters"
	xeroMoneySampleSource = "xero_assets_exact_money_samples"
	xeroErrorSource       = "xero_assets_error_response"
	xeroOAuthSource       = "xero_assets_oauth2_authorization_code"
	xeroTenantSource      = "xero_assets_required_tenant_header"
	xeroMoneyFieldSource  = "xero_assets_money_field_contract"

	xeroDocumentationClaimKind = "provider_documentation_fact"
)

type xeroAssetsEvidenceRange struct {
	Name                   string
	SourceSymbol           string
	SurfaceKind            string
	ByteStartOffset        int64
	ByteEndOffsetExclusive int64
	SelectedRangeSHA256    string
}

type xeroTargetBranchContract struct {
	Role            string
	RowKind         string
	FactKind        string
	StringFields    []string
	StringConstants map[string]string
}

var xeroAssetsEvidenceRanges = []xeroAssetsEvidenceRange{
	{Name: "document", SourceSymbol: xeroDocumentSource, SurfaceKind: "document", ByteStartOffset: 0, ByteEndOffsetExclusive: 636, SelectedRangeSHA256: "70bcff33cbfa32bacbc04372fddd1461d032ba614021eabd871c6cdac2c34c3d"},
	{Name: "operation", SourceSymbol: xeroOperationSource, SurfaceKind: "operation", ByteStartOffset: 725, ByteEndOffsetExclusive: 1021, SelectedRangeSHA256: "eed1295da9685c4c9bbe4d8d32fa0c72181cb8b38776e87a45778c6f628d3952"},
	{Name: "paging", SourceSymbol: xeroPagingSource, SurfaceKind: "query_parameter", ByteStartOffset: 1283, ByteEndOffsetExclusive: 1762, SelectedRangeSHA256: "242edbf33729c665249cce31f3d559b1232349c21fb977ffbf564287deeb9599"},
	{Name: "money_sample", SourceSymbol: xeroMoneySampleSource, SurfaceKind: "sample_shape", ByteStartOffset: 3894, ByteEndOffsetExclusive: 5043, SelectedRangeSHA256: "86bf019e4c5c862e87b2c420c6ee5d0b579761693dbc11dbf82342fe6e1305c3"},
	{Name: "error", SourceSymbol: xeroErrorSource, SurfaceKind: "error_response", ByteStartOffset: 6569, ByteEndOffsetExclusive: 6627, SelectedRangeSHA256: "df4a96d3ec19920e3d2d77a4cdfec28627c39957e5720a70d48a946d153a7e22"},
	{Name: "oauth", SourceSymbol: xeroOAuthSource, SurfaceKind: "authorization", ByteStartOffset: 23276, ByteEndOffsetExclusive: 23828, SelectedRangeSHA256: "6682bea809593d8b9bd9da387cce3d2b1733dc3e66f13ca9579b95fc7e115449"},
	{Name: "tenant_header", SourceSymbol: xeroTenantSource, SurfaceKind: "request_header", ByteStartOffset: 23842, ByteEndOffsetExclusive: 24073, SelectedRangeSHA256: "1afb6d2165bcc04961f5126e4bab54d94aef3dc0f7ab1f2804825120b73aaa19"},
	{Name: "money_field", SourceSymbol: xeroMoneyFieldSource, SurfaceKind: "schema_element", ByteStartOffset: 25721, ByteEndOffsetExclusive: 25905, SelectedRangeSHA256: "6f4998f529664c3381c37b90b73dd349f9a68be671d9a4b1d9bc6fc668f4da2a"},
}

// TestXeroAssetsOpenAPIDocumentationDerivation proves that a second provider
// and a second source representation execute through the same generic exact
// documentation derivation/profile/materialization path. The official source
// bytes remain outside the repository; this fixture produces candidate facts
// only and makes no authority-selection, admission, install, or runtime claim.
func TestXeroAssetsOpenAPIDocumentationDerivation(t *testing.T) {
	path := os.Getenv("XERO_ASSETS_OPENAPI_FIXTURE")
	if path == "" {
		t.Fatal("XERO_ASSETS_OPENAPI_FIXTURE must select the exact pinned Xero Assets OpenAPI body")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != xeroAssetsOpenAPIByteCount {
		t.Fatalf("Xero OpenAPI byte count = %d, want %d", len(body), xeroAssetsOpenAPIByteCount)
	}
	if got := sha256Hex(body); got != xeroAssetsOpenAPISHA256 {
		t.Fatalf("Xero OpenAPI SHA-256 = %s, want %s", got, xeroAssetsOpenAPISHA256)
	}

	manifestSHA, proof, bodies := xeroAssetsExactEvidenceFixture(t, body)
	programValue := xeroAssetsDerivationProgram()
	programCanonical := xeroMustCanonicalJSON(t, programValue)
	reference := dependencyProfileReference{id: "xero_assets_openapi_documentation_derivation", version: "1", digest: sha256Hex(programCanonical)}
	program, err := parseExactDocumentationDerivationProgram(programCanonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	if len(program.OrderedRules) != 9 {
		t.Fatalf("Xero derivation rule count = %d, want 9", len(program.OrderedRules))
	}

	profileRows := xeroExecutableProfileRows(t, reference, programValue)
	profiles, err := parseExecutableDocumentationDerivationProfiles(profileRows)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := executeDocumentationDerivationProfileSet(profiles, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(execution.Results) != 1 || len(execution.Profiles) != 1 || execution.Status != documentationDerivationProfileExecutionSetComplete {
		t.Fatalf("Xero executable profile closure is incomplete: %#v", execution)
	}
	result := execution.Results[0]
	if result.Provider != "xero" || result.Status != exactDocumentationDerivationComplete || result.EvidenceRosterSHA256 != proof.evidenceSelectionRosterSHA256 || result.ClassificationProofSHA256 != proof.contentSHA256 {
		t.Fatalf("Xero result does not bind its exact candidate evidence authority: %#v", result)
	}
	if len(result.Outcomes) != 9 || len(result.Facts) != 21 || result.PageCount <= 1 || !isLowerSHA256(result.ResultRootSHA256) {
		t.Fatalf("Xero result closure counts/roots are incomplete: %#v", result)
	}
	xeroAssertDerivedFacts(t, body, manifestSHA, result.Facts)

	targetAuthority, roleArtifacts, roleRows := xeroTargetMaterializationFixture(t, profiles, result.Facts)
	materializations, wholeRows, rowMembers, err := validateExactDocumentationTargetMaterializations(profiles, result.Facts, targetAuthority, roleArtifacts, roleRows)
	if err != nil {
		t.Fatal(err)
	}
	if len(materializations) != 21 || wholeRows != 21 || rowMembers != 0 {
		t.Fatalf("Xero candidate materialization closure = %d/%d/%d, want 21/21/0", len(materializations), wholeRows, rowMembers)
	}
	derivationState, err := parseDocumentationClaimDerivationRows(profileRows)
	if err != nil {
		t.Fatal(err)
	}
	closure, err := executeAndValidateDocumentationDerivationClosure(profileRows, derivationState, targetAuthority, roleArtifacts, roleRows, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDocumentationDerivationClosureProof(closure); err != nil {
		t.Fatal(err)
	}
	if closure.profileCount != 1 || closure.outcomeCount != 9 || closure.factCount != 21 || closure.wholeRowBindingCount != 21 || closure.rowMemberBindingCount != 0 || len(closure.materializationBindingSHA256ByFact) != 21 {
		t.Fatalf("Xero sealed candidate closure counts are incomplete: %#v", closure)
	}

	second, err := executeDocumentationDerivationProfileSet(profiles, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if second.ExecutionSetRootSHA256 != execution.ExecutionSetRootSHA256 || second.ProfilePageSetRootSHA256 != execution.ProfilePageSetRootSHA256 || second.ProfileResultSetRootSHA256 != execution.ProfileResultSetRootSHA256 || second.Results[0].ResultRootSHA256 != result.ResultRootSHA256 {
		t.Fatal("reexecuting the exact Xero fixture changed its sealed roots")
	}
}

// TestXeroAssetsOpenAPIDocumentationDerivationRejectsMutations applies the
// provider checkpoint's negative roster at this fixture's generic
// derivation/materialization boundary. Stage-order and receipt mutations are
// exercised by the separately owned whole-run factory runner.
func TestXeroAssetsOpenAPIDocumentationDerivationRejectsMutations(t *testing.T) {
	path := os.Getenv("XERO_ASSETS_OPENAPI_FIXTURE")
	if path == "" {
		t.Fatal("XERO_ASSETS_OPENAPI_FIXTURE must select the exact pinned Xero Assets OpenAPI body")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != xeroAssetsOpenAPIByteCount || sha256Hex(body) != xeroAssetsOpenAPISHA256 {
		t.Fatal("Xero negative fixtures require the exact pinned official source bytes")
	}
	_, proof, bodies := xeroAssetsExactEvidenceFixture(t, body)
	programValue := xeroAssetsDerivationProgram()
	programCanonical := xeroMustCanonicalJSON(t, programValue)
	reference := dependencyProfileReference{id: "xero_assets_openapi_documentation_derivation", version: "1", digest: sha256Hex(programCanonical)}
	profileRows := xeroExecutableProfileRows(t, reference, programValue)
	profiles, err := parseExecutableDocumentationDerivationProfiles(profileRows)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := executeDocumentationDerivationProfileSet(profiles, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	facts := execution.Results[0].Facts
	targetAuthority, roleArtifacts, roleRows := xeroTargetMaterializationFixture(t, profiles, facts)

	t.Run("wrong_digest", func(t *testing.T) {
		mutatedBody := bytes.Clone(body)
		mutatedBody[0] ^= 1
		wrongBodies := map[string]exactEvidenceBody{xeroAssetsOpenAPISHA256: {
			Bytes: mutatedBody, Coordinates: map[evidenceSourceCoordinate]string{{Ref: xeroAssetsSourceRef, URL: xeroAssetsSourceURL}: facts[0].EvidenceLocator.EvidenceManifestSHA256},
		}}
		if _, err := executeDocumentationDerivationProfileSet(profiles, proof, wrongBodies); err == nil {
			t.Fatal("wrong source-body digest was accepted")
		}
	})

	t.Run("wrong_range", func(t *testing.T) {
		classifications := xeroCloneClassifications(proof.classificationsBySourceSymbol)
		occurrence := classifications[xeroPagingSource][0]
		occurrence.Locator.ByteStartOffset++
		occurrence.Locator.SelectedRangeByteCount--
		occurrence.Locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(occurrence.Locator))
		classifications[xeroPagingSource][0] = occurrence
		wrongProof := newSourceClassificationSelectionProof("xero", proof.evidenceSelectionRosterSHA256, classifications)
		if _, err := executeDocumentationDerivationProfileSet(profiles, wrongProof, bodies); err == nil {
			t.Fatal("wrong evidence range was accepted")
		}
	})

	t.Run("omitted_dependency", func(t *testing.T) {
		incompleteArtifacts := make(map[string]artifactInput, len(roleArtifacts)-1)
		for role, artifact := range roleArtifacts {
			if role != "protocol_contract_index" {
				incompleteArtifacts[role] = artifact
			}
		}
		if _, _, _, err := validateExactDocumentationTargetMaterializations(profiles, facts, targetAuthority, incompleteArtifacts, roleRows); err == nil {
			t.Fatal("omitted target dependency was accepted")
		}
	})

	t.Run("role_mismatch", func(t *testing.T) {
		fact := xeroFactByKind(t, facts, "required_header")
		row := xeroDependencyRowForFact(t, fact)
		if err := validateExactDocumentationDerivedSemanticRow("source_contract_index", row, fact); err == nil {
			t.Fatal("target artifact role mismatch was accepted")
		}
	})

	t.Run("unlisted_relationship", func(t *testing.T) {
		fact := xeroFactByKind(t, facts, "api_operation")
		row := xeroDependencyRowForFact(t, fact)
		row.data["relationship_kind"] = "operation_reads_unlisted_resource"
		row = xeroDependencyRowFromObject(t, row.data, fact.TargetRowKind)
		if err := validateExactDocumentationDerivedSemanticRow(fact.TargetArtifactRole, row, fact); err == nil {
			t.Fatal("unlisted relationship output was accepted")
		}
	})

	t.Run("binary_float_authority", func(t *testing.T) {
		fact := xeroFactByKind(t, facts, "exact_money_lexeme")
		row := xeroDependencyRowForFact(t, fact)
		row.data["source_lexeme"] = json.Number("100.0000")
		row = xeroDependencyRowFromObject(t, row.data, fact.TargetRowKind)
		if err := validateExactDocumentationDerivedSemanticRow(fact.TargetArtifactRole, row, fact); err == nil {
			t.Fatal("binary/numeric money authority replaced the exact source lexeme")
		}
	})

	t.Run("source_metadata_leakage", func(t *testing.T) {
		fact := xeroFactByKind(t, facts, "provider_document")
		row := xeroDependencyRowForFact(t, fact)
		row.data["source_commit"] = xeroAssetsOpenAPICommit
		row = xeroDependencyRowFromObject(t, row.data, fact.TargetRowKind)
		if err := validateExactDocumentationDerivedSemanticRow(fact.TargetArtifactRole, row, fact); err == nil {
			t.Fatal("source-only acquisition metadata leaked into the candidate semantic row")
		}
	})
}

func xeroAssetsExactEvidenceFixture(t *testing.T, body []byte) (string, sourceClassificationSelectionProof, map[string]exactEvidenceBody) {
	t.Helper()
	ranges := make([]officialProviderEvidenceRange, len(xeroAssetsEvidenceRanges))
	for index, selected := range xeroAssetsEvidenceRanges {
		ranges[index] = officialProviderEvidenceRange{
			Name: selected.Name, SourceSymbol: selected.SourceSymbol, SurfaceKind: selected.SurfaceKind,
			ByteStartOffset: selected.ByteStartOffset, ByteEndOffsetExclusive: selected.ByteEndOffsetExclusive,
			SelectedRangeSHA256: selected.SelectedRangeSHA256,
		}
	}
	fixture := buildOfficialProviderEvidenceFixture(t, body, officialProviderEvidenceConfig{
		Provider: "xero", ArtifactPrefix: "xero_assets_openapi",
		SourceRef: xeroAssetsSourceRef, SourceURL: xeroAssetsSourceURL,
		Representation: "openapi_yaml_raw_bytes", RepresentationCoordinate: "git_commit:" + xeroAssetsOpenAPICommit + ":xero_assets.yaml",
		BodySHA256: xeroAssetsOpenAPISHA256, BodyByteCount: xeroAssetsOpenAPIByteCount, Ranges: ranges,
	})
	return fixture.ManifestSHA256, fixture.Proof, fixture.Bodies
}

func xeroAssetsDerivationProgram() map[string]interface{} {
	sources := []string{xeroDocumentSource, xeroErrorSource, xeroMoneyFieldSource, xeroMoneySampleSource, xeroOAuthSource, xeroOperationSource, xeroPagingSource, xeroTenantSource}
	sort.Strings(sources)
	rules := make([]interface{}, 0, 9)
	add := func(rule map[string]interface{}) {
		rule["ordinal"] = json.Number(strconv.Itoa(len(rules)))
		rules = append(rules, rule)
	}
	add(xeroDerivationRule("document_identity", xeroDocumentSource, "source_contract_index", "provider_document",
		`(?ms)^openapi: (?P<openapi_version>[0-9.]{1,16})\r?\ninfo:\r?\n  version: (?P<api_version>[0-9.]{1,16})\r?\n  title: (?P<title>[^\r\n]{1,128})\r?\n[\x00-\x7f]{1,1000}$`, 2048, 1, 1,
		map[string]interface{}{"api_version": "${api_version}", "fact_kind": "provider_document", "openapi_version": "${openapi_version}", "representation_kind": "openapi_yaml", "title": "${title}"}))
	add(xeroDerivationRule("get_assets_operation", xeroOperationSource, "source_contract_index", "api_operation",
		`(?ms)^    (?P<http_method>get):\r?\n      security:\r?\n        - OAuth2:\r?\n            - assets\r?\n            - assets\.read\r?\n      tags:\r?\n        - Asset\r?\n      summary: (?P<summary>[^\r\n]{1,256})\r?\n      operationId: (?P<operation_id>getAssets)\r?\n      description: (?P<description>[^\r\n]{1,512})\r?\n$`, 4096, 1, 1,
		map[string]interface{}{"description": "${description}", "fact_kind": "api_operation", "http_method": "${http_method}", "operation_id": "${operation_id}", "operation_semantics": "read_fixed_assets", "summary": "${summary}"}))
	add(xeroDerivationRule("pagination_parameters", xeroPagingSource, "protocol_contract_index", "pagination_parameter_contract",
		`(?m)^        - name: (?P<parameter_name>page|pageSize)\r?\n(?:          x-snake: page_size\r?\n)?          in: (?P<parameter_location>query)\r?\n          description: (?P<description>[^\r\n]{1,512})\r?\n          schema:\r?\n            type: (?P<provider_type>integer)\r?\n            example: (?P<example_lexeme>[0-9]{1,8})\r?$`, 4096, 2, 2,
		map[string]interface{}{"description": "${description}", "example_lexeme": "${example_lexeme}", "fact_kind": "pagination_parameter", "pagination_semantics": "page_selector", "parameter_location": "${parameter_location}", "parameter_name": "${parameter_name}", "provider_type": "${provider_type}"}))
	add(xeroDerivationRule("exact_money_lexemes", xeroMoneySampleSource, "sample_shape_index", "exact_money_sample",
		`(?m)^[ ]{1,64}(?P<field_name>purchasePrice|disposalPrice|depreciationRate|priorAccumDepreciationAmount|currentAccumDepreciationAmount|currentCapitalGain|currentGainLoss|accountingBookValue): (?P<source_lexeme>-?[0-9]{1,18}\.[0-9]{1,12})\r?$`, 256, 8, 8,
		map[string]interface{}{"fact_kind": "exact_money_lexeme", "field_name": "${field_name}", "lexical_kind": "source_decimal_lexeme", "source_lexeme": "${source_lexeme}"}))
	add(xeroDerivationRule("error_response", xeroErrorSource, "protocol_contract_index", "error_response_contract",
		`(?m)^        "(?P<status_code>400)":\r?\n          description: (?P<description>[^\r\n]{1,256})\r?$`, 2048, 1, 1,
		map[string]interface{}{"description": "${description}", "fact_kind": "error_response", "status_code": "${status_code}"}))
	add(xeroDerivationRule("oauth2_authorization_code", xeroOAuthSource, "protocol_contract_index", "oauth2_authorization_code_contract",
		`(?ms)^    OAuth2:\r?\n      type: (?P<oauth_type>oauth2)\r?\n      description: [^\r\n]{1,256}\r?\n      flows:\r?\n        (?P<flow>authorizationCode):\r?\n          authorizationUrl: (?P<authorization_url>https://[^\r\n ]{1,256})\r?\n          tokenUrl: (?P<token_url>https://[^\r\n ]{1,256})\r?\n          scopes:\r?\n[\x00-\x7f]{1,1000}$`, 8192, 1, 1,
		map[string]interface{}{"authorization_url": "${authorization_url}", "fact_kind": "oauth2_authorization_code", "flow": "${flow}", "oauth_type": "${oauth_type}", "token_url": "${token_url}"}))
	add(xeroDerivationRule("oauth2_scopes", xeroOAuthSource, "protocol_contract_index", "oauth_scope_contract",
		`(?m)^            (?P<scope_name>email|openid|profile|assets|assets\.read): (?P<scope_description>[^\r\n]{1,256})\r?$`, 2048, 5, 5,
		map[string]interface{}{"fact_kind": "oauth_scope", "scope_description": "${scope_description}", "scope_name": "${scope_name}"}))
	add(xeroDerivationRule("required_tenant_header", xeroTenantSource, "protocol_contract_index", "required_header_contract",
		`(?ms)^    requiredHeader:\r?\n      in: (?P<parameter_location>header)\r?\n      name: (?P<header_name>xero-tenant-id)\r?\n      x-snake: xero_tenant_id\r?\n      description: (?P<description>[^\r\n]{1,256})\r?\n      example: (?P<example_lexeme>[^\r\n]{1,256})\r?\n      schema:\r?\n        type: (?P<provider_type>string)\r?\n      required: (?P<provider_requirement>true)\r?\n$`, 4096, 1, 1,
		map[string]interface{}{"description": "${description}", "example_lexeme": "${example_lexeme}", "fact_kind": "required_header", "header_name": "${header_name}", "parameter_location": "${parameter_location}", "provider_requirement": "${provider_requirement}", "provider_type": "${provider_type}"}))
	add(xeroDerivationRule("money_field_contract", xeroMoneyFieldSource, "source_contract_index", "money_field_contract",
		`(?ms)^        (?P<field_name>purchasePrice):\r?\n          type: (?P<provider_type>number)\r?\n          format: (?P<provider_format>double)\r?\n          x-is-money: (?P<money_marker>true)\r?\n          description: (?P<description>[^\r\n]{1,256})\r?\n          example: "(?P<example_lexeme>-?[0-9]{1,18}\.[0-9]{1,12})"\r?\n$`, 2048, 1, 1,
		map[string]interface{}{"description": "${description}", "example_lexeme": "${example_lexeme}", "fact_kind": "money_field_contract", "field_name": "${field_name}", "money_marker": "${money_marker}", "provider_format": "${provider_format}", "provider_type": "${provider_type}"}))

	return map[string]interface{}{
		"program_kind": exactDocumentationDerivationProgramKind, "input_encoding": exactDocumentationDerivationEncodingUTF8,
		"max_parse_bytes": json.Number("8192"), "max_output_bytes_per_fact": json.Number("65536"),
		"max_output_facts_per_page": json.Number("4"), "max_output_bytes_per_page": json.Number("1048576"),
		"max_output_facts_per_run": json.Number("128"), "max_output_bytes_per_run": json.Number("8388608"),
		"max_output_pages_per_run": json.Number("64"), "max_matcher_evaluations_per_input_unit": json.Number("64"),
		"max_matcher_evaluations_per_run": json.Number("4096"), "max_occurrence_outcomes_per_run": json.Number("64"),
		"max_matcher_input_bytes_per_input_unit": json.Number("1048576"), "max_matcher_input_bytes_per_run": json.Number("67108864"),
		"max_canonical_outcome_bytes_per_run": json.Number("1048576"),
		"input_source_symbols":                xeroStringsAsInterfaces(sources), "ordered_rules": rules,
	}
}

func xeroDerivationRule(ruleID, inputSourceSymbol, targetArtifactRole, targetRowKind, pattern string, maximumMatchBytes, minimum, maximum int64, output map[string]interface{}) map[string]interface{} {
	fields := make([]string, 0, len(output))
	for field := range output {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return map[string]interface{}{
		"rule_id": ruleID, "input_source_symbol": inputSourceSymbol,
		"target_artifact_role": targetArtifactRole, "target_row_kind": targetRowKind, "pattern": pattern,
		"target_binding_kind": exactDocumentationTargetWholeRow, "target_member_json_pointer": "",
		"target_row_selector": []interface{}{}, "target_member_identity_json_pointers": []interface{}{},
		"maximum_match_bytes":            json.Number(strconv.FormatInt(maximumMatchBytes, 10)),
		"minimum_matches_per_occurrence": json.Number(strconv.FormatInt(minimum, 10)), "maximum_matches_per_occurrence": json.Number(strconv.FormatInt(maximum, 10)),
		"output_fields": output, "exact_output_field_names": xeroStringsAsInterfaces(fields),
	}
}

func xeroExecutableProfileRows(t *testing.T, reference dependencyProfileReference, program map[string]interface{}) dependencySemanticRows {
	t.Helper()
	schemaID := "urn:provider-documentation:xero:assets:claim:v1"
	schemaCanonical := xeroMustCanonicalJSON(t, xeroClaimSchema(schemaID))
	schemaReference := dependencyProfileReference{id: schemaID, version: "1", digest: sha256Hex(schemaCanonical)}
	objects := []map[string]interface{}{
		{
			"row_kind": "artifact_manifest", "artifact": "xero_assets_documentation_derivation", "artifact_version": "1",
			"canonical_admission_authorized": false, "authority_selected": false, "independent_generic_reexecution_required": true,
		},
		{
			"row_kind": "validation_schema", "validation_schema_id": schemaReference.id,
			"validation_schema_version": schemaReference.version, "validation_schema_sha256": schemaReference.digest,
			"claim_kind": xeroDocumentationClaimKind, "schema_dialect": validationProfileDraft202012, "canonical_schema_json": string(schemaCanonical),
		},
		{
			"row_kind": "derivation_profile", "derivation_profile_id": reference.id,
			"derivation_profile_version": reference.version, "derivation_profile_sha256": reference.digest,
			"claim_kind": xeroDocumentationClaimKind,
			"validation_schema_binding": map[string]interface{}{
				"validation_schema_id": schemaReference.id, "validation_schema_version": schemaReference.version, "validation_schema_sha256": schemaReference.digest,
			},
			"program": program,
		},
		{
			"row_kind": "validation_summary", "validation_schema_count": json.Number("1"), "derivation_profile_count": json.Number("1"),
			"classifier_profile_count": json.Number("0"), "dependency_resolution_profile_count": json.Number("0"),
			"canonical_admission_authorized": false, "authority_selected": false, "independent_generic_reexecution_required": true,
		},
	}
	raw := make([]byte, 0)
	for _, object := range objects {
		encoded, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, encoded...)
		raw = append(raw, '\n')
	}
	input := artifactInput{Path: "xero_assets_documentation_derivation.jsonl", Raw: raw, SHA256: sha256Hex(raw), Structured: true}
	rows, err := parseDependencySemanticRows(input)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func xeroTargetContracts() []xeroTargetBranchContract {
	contracts := []xeroTargetBranchContract{
		{Role: "source_contract_index", RowKind: "provider_document", FactKind: "provider_document", StringFields: []string{"api_version", "openapi_version", "title"}, StringConstants: map[string]string{"representation_kind": "openapi_yaml"}},
		{Role: "source_contract_index", RowKind: "api_operation", FactKind: "api_operation", StringFields: []string{"description", "http_method", "operation_id", "summary"}, StringConstants: map[string]string{"operation_semantics": "read_fixed_assets"}},
		{Role: "source_contract_index", RowKind: "money_field_contract", FactKind: "money_field_contract", StringFields: []string{"description", "example_lexeme", "field_name", "money_marker", "provider_format", "provider_type"}},
		{Role: "protocol_contract_index", RowKind: "pagination_parameter_contract", FactKind: "pagination_parameter", StringFields: []string{"description", "example_lexeme", "parameter_location", "parameter_name", "provider_type"}, StringConstants: map[string]string{"pagination_semantics": "page_selector"}},
		{Role: "protocol_contract_index", RowKind: "error_response_contract", FactKind: "error_response", StringFields: []string{"description", "status_code"}},
		{Role: "protocol_contract_index", RowKind: "oauth2_authorization_code_contract", FactKind: "oauth2_authorization_code", StringFields: []string{"authorization_url", "flow", "oauth_type", "token_url"}},
		{Role: "protocol_contract_index", RowKind: "oauth_scope_contract", FactKind: "oauth_scope", StringFields: []string{"scope_description", "scope_name"}},
		{Role: "protocol_contract_index", RowKind: "required_header_contract", FactKind: "required_header", StringFields: []string{"description", "example_lexeme", "header_name", "parameter_location", "provider_requirement", "provider_type"}},
		{Role: "sample_shape_index", RowKind: "exact_money_sample", FactKind: "exact_money_lexeme", StringFields: []string{"field_name", "source_lexeme"}, StringConstants: map[string]string{"lexical_kind": "source_decimal_lexeme"}},
	}
	sort.Slice(contracts, func(i, j int) bool {
		if contracts[i].Role != contracts[j].Role {
			return contracts[i].Role < contracts[j].Role
		}
		return contracts[i].RowKind < contracts[j].RowKind
	})
	return contracts
}

func xeroClaimSchema(id string) map[string]interface{} {
	branches := make([]interface{}, 0, len(xeroTargetContracts()))
	for _, contract := range xeroTargetContracts() {
		properties := map[string]interface{}{"fact_kind": map[string]interface{}{"const": contract.FactKind}}
		required := []string{"fact_kind"}
		for _, field := range contract.StringFields {
			properties[field] = map[string]interface{}{"type": "string", "minLength": json.Number("1")}
			required = append(required, field)
		}
		constantNames := xeroSortedMapKeys(contract.StringConstants)
		for _, field := range constantNames {
			properties[field] = map[string]interface{}{"const": contract.StringConstants[field]}
			required = append(required, field)
		}
		sort.Strings(required)
		branches = append(branches, map[string]interface{}{
			"type": "object", "additionalProperties": false,
			"required": xeroStringsAsInterfaces(required), "properties": properties,
		})
	}
	return map[string]interface{}{"$schema": validationProfileDraft202012, "$id": id, "oneOf": branches}
}

func xeroTargetMaterializationFixture(t *testing.T, profiles map[string]executableDocumentationDerivationProfile, facts []exactDocumentationDerivedFact) (dependencySemanticDerivationTargetSchemaAuthority, map[string]artifactInput, map[string]dependencySemanticRows) {
	t.Helper()
	const version = "1"
	roleRawRows := map[string][][]byte{}
	for _, fact := range facts {
		output, err := decodeExactDocumentationFactOutputFields(fact)
		if err != nil {
			t.Fatal(err)
		}
		row := make(map[string]interface{}, len(output)+len(exactDocumentationDerivedRowEnvelopeFields))
		for field, value := range output {
			row[field] = value
		}
		locator := fact.EvidenceLocator
		row["row_kind"] = fact.TargetRowKind
		row[exactDocumentationDerivedFactIDField] = fact.FactID
		row["source_ref"] = locator.SourceRefs[0]
		row["source_url"] = locator.SourceURLs[0]
		row["source_content_sha256"] = locator.SourceContentSHA256
		row["evidence_hydration_coordinate"] = map[string]interface{}{
			"source_content_sha256":     locator.SourceContentSHA256,
			"byte_start_offset":         json.Number(strconv.FormatInt(locator.ByteStartOffset, 10)),
			"byte_end_offset_exclusive": json.Number(strconv.FormatInt(locator.ByteEndOffsetExclusive, 10)),
			"selected_range_byte_count": json.Number(strconv.FormatInt(locator.SelectedRangeByteCount, 10)),
			"selected_range_sha256":     locator.SelectedRangeSHA256,
		}
		roleRawRows[fact.TargetArtifactRole] = append(roleRawRows[fact.TargetArtifactRole], xeroMustCanonicalJSON(t, row))
	}

	declaredRoles := map[string]struct{}{}
	for _, profile := range profiles {
		for _, rule := range profile.Program.OrderedRules {
			declaredRoles[rule.TargetArtifactRole] = struct{}{}
		}
	}
	roles := []string{"protocol_contract_index", "sample_shape_index", "source_contract_index"}
	if err := requireExactSet("Xero declared target roles", declaredRoles, stringSet(roles)); err != nil {
		t.Fatal(err)
	}

	authority := dependencySemanticDerivationTargetSchemaAuthority{seal: dependencySemanticDerivationTargetSchemaAuthorityIdentity, byRole: map[string]dependencySemanticDerivationTargetSchema{}}
	roleArtifacts := make(map[string]artifactInput, len(roles))
	roleRows := make(map[string]dependencySemanticRows, len(roles))
	bindings := make([]validationProfileBinding, 0, len(roles))
	artifacts := make([]validationProfileArtifact, 0, len(roles))
	schemas := make([]validationProfileSchema, 0, len(roles))
	for _, role := range roles {
		artifactID := "xero_assets_" + role
		derivedRowCount := len(roleRawRows[role])
		rows := append([][]byte(nil), roleRawRows[role]...)
		rows = append(rows,
			xeroMustCanonicalJSON(t, map[string]interface{}{
				"row_kind": "artifact_manifest", "artifact": artifactID, "artifact_version": version,
				"canonical_admission_authorized": false, "authority_selected": false, "materialization_authority": "exact_documentation_derivation",
			}),
			xeroMustCanonicalJSON(t, map[string]interface{}{
				"row_kind": "validation_summary", "documentation_derived_row_count": json.Number(strconv.Itoa(derivedRowCount)),
				"canonical_admission_authorized": false, "authority_selected": false, "result": "exact_documentation_target_fixture_complete",
			}),
		)
		sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i], rows[j]) < 0 })
		artifactBytes := make([]byte, 0)
		for _, row := range rows {
			artifactBytes = append(artifactBytes, row...)
			artifactBytes = append(artifactBytes, '\n')
		}
		artifactSHA := sha256Hex(artifactBytes)
		artifact := artifactInput{Path: artifactID + ".jsonl", Raw: artifactBytes, SHA256: artifactSHA, Structured: true}
		parsedRows, err := parseDependencySemanticRows(artifact)
		if err != nil {
			t.Fatal(err)
		}
		roleArtifacts[role] = artifact
		roleRows[role] = parsedRows

		schemaID := "urn:provider-documentation:xero:assets:target:" + role + ":v1"
		schemaBytes := xeroMustCanonicalJSON(t, xeroTargetSchema(schemaID, artifactID, derivedRowCount, role))
		schemaSHA := sha256Hex(schemaBytes)
		schemaRole := role + "_schema"
		rowKinds := map[string]struct{}{"artifact_manifest": {}, "validation_summary": {}}
		for _, contract := range xeroContractsForRole(role) {
			rowKinds[contract.RowKind] = struct{}{}
		}
		authority.byRole[role] = dependencySemanticDerivationTargetSchema{
			artifactRole: role, artifactSHA256: artifactSHA,
			schemaRole: schemaRole, schemaID: schemaID, schemaVersion: version, schemaSHA256: schemaSHA,
			schemaBytes: schemaBytes, discriminatorProperty: "row_kind", discriminatorValues: rowKinds,
		}
		bindings = append(bindings, validationProfileBinding{Role: role, ArtifactID: artifactID, ArtifactVersion: version, ArtifactSHA256: artifactSHA, SchemaID: schemaID, SchemaVersion: version, SchemaSHA256: schemaSHA})
		artifacts = append(artifacts, validationProfileArtifact{ID: artifactID, Version: version, Bytes: artifactBytes})
		schemas = append(schemas, validationProfileSchema{ID: schemaID, Version: version, Bytes: schemaBytes})
	}
	if err := validateValidationProfileBindings(bindings, artifacts, schemas); err != nil {
		t.Fatalf("Xero exact candidate target artifacts do not pass their bound target schemas: %v", err)
	}
	return authority, roleArtifacts, roleRows
}

func xeroTargetSchema(id, artifactID string, derivedRowCount int, role string) map[string]interface{} {
	branchesByRowKind := map[string]map[string]interface{}{}
	for _, contract := range xeroContractsForRole(role) {
		properties := map[string]interface{}{
			"row_kind":                           map[string]interface{}{"const": contract.RowKind},
			exactDocumentationDerivedFactIDField: map[string]interface{}{"type": "string", "minLength": json.Number("1")},
			"source_ref":                         map[string]interface{}{"const": xeroAssetsSourceRef},
			"source_url":                         map[string]interface{}{"const": xeroAssetsSourceURL},
			"source_content_sha256":              map[string]interface{}{"const": xeroAssetsOpenAPISHA256},
			"evidence_hydration_coordinate": map[string]interface{}{
				"type": "object", "additionalProperties": false,
				"required": []interface{}{"byte_end_offset_exclusive", "byte_start_offset", "selected_range_byte_count", "selected_range_sha256", "source_content_sha256"},
				"properties": map[string]interface{}{
					"source_content_sha256":     map[string]interface{}{"const": xeroAssetsOpenAPISHA256},
					"byte_start_offset":         map[string]interface{}{"type": "integer", "minimum": json.Number("0")},
					"byte_end_offset_exclusive": map[string]interface{}{"type": "integer", "minimum": json.Number("1")},
					"selected_range_byte_count": map[string]interface{}{"type": "integer", "minimum": json.Number("1")},
					"selected_range_sha256":     map[string]interface{}{"type": "string", "pattern": "^[0-9a-f]{64}$"},
				},
			},
			"fact_kind": map[string]interface{}{"const": contract.FactKind},
		}
		required := []string{"documentation_derived_fact_id", "evidence_hydration_coordinate", "fact_kind", "row_kind", "source_content_sha256", "source_ref", "source_url"}
		for _, field := range contract.StringFields {
			properties[field] = map[string]interface{}{"type": "string", "minLength": json.Number("1")}
			required = append(required, field)
		}
		for _, field := range xeroSortedMapKeys(contract.StringConstants) {
			properties[field] = map[string]interface{}{"const": contract.StringConstants[field]}
			required = append(required, field)
		}
		sort.Strings(required)
		branchesByRowKind[contract.RowKind] = map[string]interface{}{
			"type": "object", "additionalProperties": false,
			"required": xeroStringsAsInterfaces(required), "properties": properties,
		}
	}
	branchesByRowKind["artifact_manifest"] = map[string]interface{}{
		"type": "object", "additionalProperties": false,
		"required": []interface{}{"artifact", "artifact_version", "authority_selected", "canonical_admission_authorized", "materialization_authority", "row_kind"},
		"properties": map[string]interface{}{
			"row_kind": map[string]interface{}{"const": "artifact_manifest"}, "artifact": map[string]interface{}{"const": artifactID},
			"artifact_version": map[string]interface{}{"const": "1"}, "authority_selected": map[string]interface{}{"const": false},
			"canonical_admission_authorized": map[string]interface{}{"const": false}, "materialization_authority": map[string]interface{}{"const": "exact_documentation_derivation"},
		},
	}
	branchesByRowKind["validation_summary"] = map[string]interface{}{
		"type": "object", "additionalProperties": false,
		"required": []interface{}{"authority_selected", "canonical_admission_authorized", "documentation_derived_row_count", "result", "row_kind"},
		"properties": map[string]interface{}{
			"row_kind": map[string]interface{}{"const": "validation_summary"}, "authority_selected": map[string]interface{}{"const": false},
			"canonical_admission_authorized":  map[string]interface{}{"const": false},
			"documentation_derived_row_count": map[string]interface{}{"const": json.Number(strconv.Itoa(derivedRowCount))},
			"result":                          map[string]interface{}{"const": "exact_documentation_target_fixture_complete"},
		},
	}
	rowKinds := xeroSortedMapKeys(branchesByRowKind)
	branches := make([]interface{}, len(rowKinds))
	for index, rowKind := range rowKinds {
		branches[index] = branchesByRowKind[rowKind]
	}
	return map[string]interface{}{"$schema": validationProfileDraft202012, "$id": id, "oneOf": branches}
}

func xeroContractsForRole(role string) []xeroTargetBranchContract {
	result := []xeroTargetBranchContract{}
	for _, contract := range xeroTargetContracts() {
		if contract.Role == role {
			result = append(result, contract)
		}
	}
	return result
}

func xeroAssertDerivedFacts(t *testing.T, body []byte, manifestSHA string, facts []exactDocumentationDerivedFact) {
	t.Helper()
	kindCounts := map[string]int{}
	moneyLexemes := map[string]int{}
	scopes := map[string]struct{}{}
	paging := map[string]string{}
	for _, fact := range facts {
		if err := validateExactDocumentationDerivedFactIntegrity(fact); err != nil {
			t.Fatalf("Xero fact %q: %v", fact.FactID, err)
		}
		locator := fact.EvidenceLocator
		if locator.EvidenceManifestSHA256 != manifestSHA || locator.SourceContentSHA256 != xeroAssetsOpenAPISHA256 || locator.ByteEndOffsetExclusive > int64(len(body)) || locator.SelectedRangeSHA256 != sha256Hex(body[locator.ByteStartOffset:locator.ByteEndOffsetExclusive]) {
			t.Fatalf("fact %s is not hydrated by the exact pinned Xero bytes", fact.FactID)
		}
		output, err := decodeExactDocumentationFactOutputFields(fact)
		if err != nil {
			t.Fatal(err)
		}
		kind, ok := output["fact_kind"].(string)
		if !ok {
			t.Fatalf("fact %s has no string fact_kind", fact.FactID)
		}
		kindCounts[kind]++
		switch kind {
		case "provider_document":
			if output["title"] != "Xero Assets API" || output["openapi_version"] != "3.0.0" || output["api_version"] != "17.0.0" || output["representation_kind"] != "openapi_yaml" {
				t.Fatalf("Xero document identity fact = %#v", output)
			}
		case "api_operation":
			if output["operation_id"] != "getAssets" || output["http_method"] != "get" || output["operation_semantics"] != "read_fixed_assets" {
				t.Fatalf("Xero operation fact = %#v", output)
			}
		case "pagination_parameter":
			name, nameOK := output["parameter_name"].(string)
			example, exampleOK := output["example_lexeme"].(string)
			if !nameOK || !exampleOK || output["parameter_location"] != "query" || output["provider_type"] != "integer" {
				t.Fatalf("Xero pagination fact = %#v", output)
			}
			paging[name] = example
		case "exact_money_lexeme":
			lexeme, ok := output["source_lexeme"].(string)
			if !ok {
				t.Fatalf("Xero money lexeme was coerced out of its exact source string: %#v", output)
			}
			moneyLexemes[lexeme]++
		case "error_response":
			if output["status_code"] != "400" || output["description"] != "bad input parameter" {
				t.Fatalf("Xero error fact = %#v", output)
			}
		case "oauth2_authorization_code":
			if output["oauth_type"] != "oauth2" || output["flow"] != "authorizationCode" || output["authorization_url"] != "https://login.xero.com/identity/connect/authorize" || output["token_url"] != "https://identity.xero.com/connect/token" {
				t.Fatalf("Xero OAuth fact = %#v", output)
			}
		case "oauth_scope":
			scope, ok := output["scope_name"].(string)
			if !ok {
				t.Fatalf("Xero OAuth scope fact = %#v", output)
			}
			scopes[scope] = struct{}{}
		case "required_header":
			if output["header_name"] != "xero-tenant-id" || output["parameter_location"] != "header" || output["provider_requirement"] != "true" || output["provider_type"] != "string" {
				t.Fatalf("Xero required tenant header fact = %#v", output)
			}
		case "money_field_contract":
			if output["field_name"] != "purchasePrice" || output["provider_type"] != "number" || output["provider_format"] != "double" || output["money_marker"] != "true" || output["example_lexeme"] != "1000.0000" {
				t.Fatalf("Xero money field fact = %#v", output)
			}
		default:
			t.Fatalf("Xero fixture produced unknown fact kind %q", kind)
		}
	}
	wantCounts := map[string]int{
		"provider_document": 1, "api_operation": 1, "pagination_parameter": 2, "exact_money_lexeme": 8,
		"error_response": 1, "oauth2_authorization_code": 1, "oauth_scope": 5, "required_header": 1, "money_field_contract": 1,
	}
	if len(kindCounts) != len(wantCounts) {
		t.Fatalf("Xero fact kinds = %#v, want %#v", kindCounts, wantCounts)
	}
	for kind, want := range wantCounts {
		if kindCounts[kind] != want {
			t.Fatalf("Xero fact kind %q count = %d, want %d (all=%#v)", kind, kindCounts[kind], want, kindCounts)
		}
	}
	wantMoneyLexemes := map[string]int{"100.0000": 1, "0.0": 1, "0.50": 1, "0.000000": 4, "100.000000": 1}
	if !xeroEqualStringIntMaps(moneyLexemes, wantMoneyLexemes) {
		t.Fatalf("Xero exact money lexeme roster = %#v, want %#v", moneyLexemes, wantMoneyLexemes)
	}
	if !xeroEqualStringMaps(scopes, stringSet([]string{"assets", "assets.read", "email", "openid", "profile"})) {
		t.Fatalf("Xero OAuth scope roster = %#v", scopes)
	}
	if !xeroEqualStringStringMaps(paging, map[string]string{"page": "1", "pageSize": "5"}) {
		t.Fatalf("Xero pagination roster = %#v", paging)
	}
}

func xeroCloneClassifications(input map[string][]sourceClassificationOccurrence) map[string][]sourceClassificationOccurrence {
	result := make(map[string][]sourceClassificationOccurrence, len(input))
	for symbol, occurrences := range input {
		result[symbol] = make([]sourceClassificationOccurrence, len(occurrences))
		for index, occurrence := range occurrences {
			occurrence.Locator.SourceRefs = append([]string(nil), occurrence.Locator.SourceRefs...)
			occurrence.Locator.SourceURLs = append([]string(nil), occurrence.Locator.SourceURLs...)
			result[symbol][index] = occurrence
		}
	}
	return result
}

func xeroFactByKind(t *testing.T, facts []exactDocumentationDerivedFact, wanted string) exactDocumentationDerivedFact {
	t.Helper()
	var matched []exactDocumentationDerivedFact
	for _, fact := range facts {
		output, err := decodeExactDocumentationFactOutputFields(fact)
		if err != nil {
			t.Fatal(err)
		}
		if output["fact_kind"] == wanted {
			matched = append(matched, fact)
		}
	}
	if len(matched) == 0 {
		t.Fatalf("Xero candidate fixture has no fact kind %q", wanted)
	}
	return matched[0]
}

func xeroDependencyRowForFact(t *testing.T, fact exactDocumentationDerivedFact) dependencySemanticRow {
	t.Helper()
	output, err := decodeExactDocumentationFactOutputFields(fact)
	if err != nil {
		t.Fatal(err)
	}
	row := make(map[string]interface{}, len(output)+len(exactDocumentationDerivedRowEnvelopeFields))
	for field, value := range output {
		row[field] = value
	}
	locator := fact.EvidenceLocator
	row["row_kind"] = fact.TargetRowKind
	row[exactDocumentationDerivedFactIDField] = fact.FactID
	row["source_ref"] = locator.SourceRefs[0]
	row["source_url"] = locator.SourceURLs[0]
	row["source_content_sha256"] = locator.SourceContentSHA256
	row["evidence_hydration_coordinate"] = map[string]interface{}{
		"source_content_sha256":     locator.SourceContentSHA256,
		"byte_start_offset":         json.Number(strconv.FormatInt(locator.ByteStartOffset, 10)),
		"byte_end_offset_exclusive": json.Number(strconv.FormatInt(locator.ByteEndOffsetExclusive, 10)),
		"selected_range_byte_count": json.Number(strconv.FormatInt(locator.SelectedRangeByteCount, 10)),
		"selected_range_sha256":     locator.SelectedRangeSHA256,
	}
	return xeroDependencyRowFromObject(t, row, fact.TargetRowKind)
}

func xeroDependencyRowFromObject(t *testing.T, object map[string]interface{}, rowKind string) dependencySemanticRow {
	t.Helper()
	raw := xeroMustCanonicalJSON(t, object)
	return dependencySemanticRow{kind: rowKind, raw: raw, data: object}
}

func xeroMustCanonicalJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func xeroStringsAsInterfaces(values []string) []interface{} {
	result := make([]interface{}, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func xeroSortedMapKeys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func xeroEqualStringIntMaps(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range right {
		if left[key] != value {
			return false
		}
	}
	return true
}

func xeroEqualStringMaps(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range right {
		if _, ok := left[key]; !ok {
			return false
		}
	}
	return true
}

func xeroEqualStringStringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range right {
		if left[key] != value {
			return false
		}
	}
	return true
}
