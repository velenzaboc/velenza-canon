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
	intuitProfitAndLossDetailCopyAllByteCount = 31512
	intuitProfitAndLossDetailCopyAllSHA256    = "d9546c927273cdb4f1da618addb8ca6de696b48305a452bc68613fde2059537a"
	intuitProfitAndLossDetailSourceRef        = "intuit.qbo.profit_and_loss_detail.copy_all"
	intuitProfitAndLossDetailSourceURL        = "https://developer.intuit.com/app/developer/qbo/docs/api/accounting/report-entities/profitandlossdetail"

	intuitReportResourceSource        = "quickbooks_profit_and_loss_detail_resource"
	intuitResponseFieldsSource        = "quickbooks_profit_and_loss_detail_response_fields"
	intuitOperationSource             = "quickbooks_profit_and_loss_detail_query_operation"
	intuitQueryParametersSource       = "quickbooks_profit_and_loss_detail_query_parameters"
	intuitRequestExampleSource        = "quickbooks_profit_and_loss_detail_request_example"
	intuitFirstResponseExampleSource  = "quickbooks_profit_and_loss_detail_response_example_one"
	intuitSecondResponseExampleSource = "quickbooks_profit_and_loss_detail_response_example_two"
	intuitHeadingsSource              = "quickbooks_profit_and_loss_detail_headings"
	intuitReturnSemanticsSource       = "quickbooks_profit_and_loss_detail_return_semantics"

	intuitDocumentationClaimKind = "provider_documentation_fact"
)

type intuitCopyAllEvidenceRange struct {
	Name                   string
	SourceSymbol           string
	SurfaceKind            string
	ByteStartOffset        int64
	ByteEndOffsetExclusive int64
	SelectedRangeSHA256    string
}

type intuitCopyAllTargetBranchContract struct {
	RowKind               string
	FactKind              string
	StringFields          []string
	DigestFields          []string
	PositiveIntegerFields []string
	StringConstants       map[string]string
}

var intuitCopyAllEvidenceRanges = []intuitCopyAllEvidenceRange{
	{Name: "report_resource", SourceSymbol: intuitReportResourceSource, SurfaceKind: "resource", ByteStartOffset: 25, ByteEndOffsetExclusive: 161, SelectedRangeSHA256: "772bac9dd5063ee3ec21c3c30a7c4d3a4e6f2a3f916f07648954d637ffa2991d"},
	{Name: "response_field_table", SourceSymbol: intuitResponseFieldsSource, SurfaceKind: "schema_element", ByteStartOffset: 599, ByteEndOffsetExclusive: 5162, SelectedRangeSHA256: "29c3ed57322a854f42a86a4612ab8e56a22007b74ff57a21a16d161840ae6694"},
	{Name: "query_operation", SourceSymbol: intuitOperationSource, SurfaceKind: "operation", ByteStartOffset: 15754, ByteEndOffsetExclusive: 15830, SelectedRangeSHA256: "a5a75c05ef81b99e44c83d7703d2bb5ba46d41405430b2d767f82732d265c908"},
	{Name: "query_parameter_table", SourceSymbol: intuitQueryParametersSource, SurfaceKind: "schema_element", ByteStartOffset: 16089, ByteEndOffsetExclusive: 20652, SelectedRangeSHA256: "29c3ed57322a854f42a86a4612ab8e56a22007b74ff57a21a16d161840ae6694"},
	{Name: "request_example", SourceSymbol: intuitRequestExampleSource, SurfaceKind: "request_response_envelope_shape", ByteStartOffset: 20785, ByteEndOffsetExclusive: 20938, SelectedRangeSHA256: "f041a01c07230bde916c33e4953c2be8dc41bdddadc849aef782a6251c6e0c58"},
	{Name: "response_example_one", SourceSymbol: intuitFirstResponseExampleSource, SurfaceKind: "request_response_envelope_shape", ByteStartOffset: 5201, ByteEndOffsetExclusive: 15706, SelectedRangeSHA256: "d2195ee361a1196881cdc9e17ab1c73004b072b5402437f5562c65e8fce22b48"},
	{Name: "response_example_two", SourceSymbol: intuitSecondResponseExampleSource, SurfaceKind: "request_response_envelope_shape", ByteStartOffset: 21002, ByteEndOffsetExclusive: 31507, SelectedRangeSHA256: "d2195ee361a1196881cdc9e17ab1c73004b072b5402437f5562c65e8fce22b48"},
	{Name: "heading_document", SourceSymbol: intuitHeadingsSource, SurfaceKind: "documentation_heading", ByteStartOffset: 0, ByteEndOffsetExclusive: 21, SelectedRangeSHA256: "233b294d8ed234365a1885d83f34640261586f0677f90de87877a88fef3255de"},
	{Name: "heading_report_object", SourceSymbol: intuitHeadingsSource, SurfaceKind: "documentation_heading", ByteStartOffset: 165, ByteEndOffsetExclusive: 208, SelectedRangeSHA256: "312289bce9d7e2b6ae85cfe8ef50bedb5c21bddfd7b057fd39d820bf53982e86"},
	{Name: "heading_sample_object", SourceSymbol: intuitHeadingsSource, SurfaceKind: "documentation_heading", ByteStartOffset: 5164, ByteEndOffsetExclusive: 5188, SelectedRangeSHA256: "8587d31ced1a21e2fec41725e388475f3d036b9dad0cd099deb2bf8949a06a0a"},
	{Name: "heading_operations", SourceSymbol: intuitHeadingsSource, SurfaceKind: "documentation_heading", ByteStartOffset: 15715, ByteEndOffsetExclusive: 15728, SelectedRangeSHA256: "b10e154178dbf47fabc937d9ac0712580f8374412aad9975e376c2666e190037"},
	{Name: "heading_query_report", SourceSymbol: intuitHeadingsSource, SurfaceKind: "documentation_heading", ByteStartOffset: 15732, ByteEndOffsetExclusive: 15750, SelectedRangeSHA256: "9d434f7097b153512e23804aaa6fc34e983c38db93698fd38aba45c5d915d1e4"},
	{Name: "heading_query_parameters", SourceSymbol: intuitHeadingsSource, SurfaceKind: "documentation_heading", ByteStartOffset: 15834, ByteEndOffsetExclusive: 15855, SelectedRangeSHA256: "eb7044208139106d88d6f4ba70f9b28662b46af880c0b492e8a72807bf3e875e"},
	{Name: "heading_sample_query", SourceSymbol: intuitHeadingsSource, SurfaceKind: "documentation_heading", ByteStartOffset: 20654, ByteEndOffsetExclusive: 20671, SelectedRangeSHA256: "6d64df71cbce40339b66f079d8c7022a02b5ec812ea924eb97d83d32eb330089"},
	{Name: "heading_returns", SourceSymbol: intuitHeadingsSource, SurfaceKind: "documentation_heading", ByteStartOffset: 20947, ByteEndOffsetExclusive: 20959, SelectedRangeSHA256: "5f7d2c9d4b551deeb870a5447e2b79adcb9e70b6ee391cf0d7088cb15aa7371a"},
	{Name: "return_semantics", SourceSymbol: intuitReturnSemanticsSource, SurfaceKind: "request_response_envelope_shape", ByteStartOffset: 20963, ByteEndOffsetExclusive: 20989, SelectedRangeSHA256: "1854dadd5b6ad9fab0558c85a1c87395aac957a163e7388ae00b36544377eabb"},
}

// TestIntuitProfitAndLossDetailCopyAllDerivation is the exact external-fixture
// gate for Intuit's Copy all for AI representation. Copy-all is the evidence,
// not an aid used to reconstruct evidence from headings, DOM state, or prose.
// The exact bytes remain outside the repository under evidence/archive custody;
// QBO_COPY_ALL_FIXTURE opts this test into the retained fixture body.
func TestIntuitProfitAndLossDetailCopyAllDerivation(t *testing.T) {
	path := os.Getenv("QBO_COPY_ALL_FIXTURE")
	if path == "" {
		t.Fatal("QBO_COPY_ALL_FIXTURE must select the exact Intuit Copy-all evidence body")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != intuitProfitAndLossDetailCopyAllByteCount {
		t.Fatalf("Copy-all evidence byte count = %d, want %d", len(body), intuitProfitAndLossDetailCopyAllByteCount)
	}
	if got := sha256Hex(body); got != intuitProfitAndLossDetailCopyAllSHA256 {
		t.Fatalf("Copy-all evidence SHA-256 = %s, want %s", got, intuitProfitAndLossDetailCopyAllSHA256)
	}

	manifestSHA, proof, bodies, locatorRoot := intuitCopyAllExactEvidenceFixture(t, body)
	programValue := intuitCopyAllDerivationProgram()
	programCanonical := intuitMustCanonicalJSON(t, programValue)
	reference := dependencyProfileReference{id: "intuit_qbo_profit_and_loss_detail_copy_all", version: "1", digest: sha256Hex(programCanonical)}
	program, err := parseExactDocumentationDerivationProgram(programCanonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	if len(program.OrderedRules) != 22 {
		t.Fatalf("Copy-all rule count = %d, want 22", len(program.OrderedRules))
	}

	profileRows := intuitCopyAllExecutableProfileRows(t, reference, programValue)
	profiles, err := parseExecutableDocumentationDerivationProfiles(profileRows)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := executeDocumentationDerivationProfileSet(profiles, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(execution.Results) != 1 || len(execution.Profiles) != 1 {
		t.Fatalf("Copy-all executable profile closure = %#v, want one profile/result", execution)
	}
	result := execution.Results[0]
	if result.Status != exactDocumentationDerivationComplete || result.PageCount <= 1 || !isLowerSHA256(result.PageSetRootSHA256) || !isLowerSHA256(result.OutcomeSetRootSHA256) || !isLowerSHA256(result.FactSetRootSHA256) || !isLowerSHA256(result.ResultRootSHA256) {
		t.Fatalf("Copy-all execution closure is incomplete: %#v", result)
	}
	if result.Provider != "quickbooks_online" || result.EvidenceRosterSHA256 != proof.evidenceSelectionRosterSHA256 || result.ClassificationProofSHA256 != proof.contentSHA256 || execution.ClassificationProofSHA256 != proof.contentSHA256 {
		t.Fatalf("Copy-all result does not bind its exact provider/evidence/classification authority: %#v", result)
	}

	assertIntuitCopyAllOutcomes(t, result.Outcomes)
	assertIntuitCopyAllFacts(t, body, manifestSHA, result.Facts)
	targetAuthority, roleArtifacts, roleRows, targetBindingRoot := intuitCopyAllTargetMaterializationFixture(t, profiles, result.Facts)
	materializations, wholeRows, rowMembers, err := validateExactDocumentationTargetMaterializations(profiles, result.Facts, targetAuthority, roleArtifacts, roleRows)
	if err != nil {
		t.Fatal(err)
	}
	if len(materializations) != 100 || wholeRows != 100 || rowMembers != 0 {
		t.Fatalf("Copy-all target materialization closure = %d/%d/%d, want 100/100/0", len(materializations), wholeRows, rowMembers)
	}
	materializationRoleCounts := map[string]int{}
	for _, materialization := range materializations {
		materializationRoleCounts[materialization.identity.TargetArtifactRole]++
	}
	for role, want := range map[string]int{"source_contract_index": 26, "protocol_contract_index": 17, "sample_shape_index": 57} {
		if materializationRoleCounts[role] != want {
			t.Fatalf("Copy-all target role %q materialization count = %d, want %d (all=%#v)", role, materializationRoleCounts[role], want, materializationRoleCounts)
		}
	}
	if len(materializationRoleCounts) != 3 {
		t.Fatalf("Copy-all target materialization roles = %#v, want exact three-role closure", materializationRoleCounts)
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
	if closure.profileCount != 1 || closure.outcomeCount != 29 || closure.factCount != 100 || closure.wholeRowBindingCount != 100 || closure.rowMemberBindingCount != 0 || len(closure.materializationBindingSHA256ByFact) != 100 {
		t.Fatalf("Copy-all sealed closure counts are incomplete: %#v", closure)
	}
	if closure.targetMaterializationRootSHA256 != documentationTargetMaterializationRoot(materializations) || closure.targetMaterializationBindingRosterRootSHA256 != documentationTargetMaterializationBindingRosterRoot(materializations) {
		t.Fatal("Copy-all sealed closure does not equal the independently validated target materialization set")
	}
	assertIntuitCopyAllDeterministicRoots(t, locatorRoot, targetBindingRoot, execution, result, materializations, closure)

	second, err := executeDocumentationDerivationProfileSet(profiles, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if second.ProfilePageSetRootSHA256 != execution.ProfilePageSetRootSHA256 || second.ProfileResultSetRootSHA256 != execution.ProfileResultSetRootSHA256 || second.Results[0].ResultRootSHA256 != result.ResultRootSHA256 {
		t.Fatal("reexecuting the exact Copy-all fixture changed its sealed roots")
	}
}

func intuitCopyAllExactEvidenceFixture(t *testing.T, body []byte) (string, sourceClassificationSelectionProof, map[string]exactEvidenceBody, string) {
	t.Helper()
	ranges := make([]officialProviderEvidenceRange, len(intuitCopyAllEvidenceRanges))
	for index, selected := range intuitCopyAllEvidenceRanges {
		ranges[index] = officialProviderEvidenceRange{
			Name: selected.Name, SourceSymbol: selected.SourceSymbol, SurfaceKind: selected.SurfaceKind,
			ByteStartOffset: selected.ByteStartOffset, ByteEndOffsetExclusive: selected.ByteEndOffsetExclusive,
			SelectedRangeSHA256: selected.SelectedRangeSHA256,
		}
	}
	fixture := buildOfficialProviderEvidenceFixture(t, body, officialProviderEvidenceConfig{
		Provider: "quickbooks_online", ArtifactPrefix: "intuit_qbo_profit_and_loss_detail_copy_all",
		SourceRef: intuitProfitAndLossDetailSourceRef, SourceURL: intuitProfitAndLossDetailSourceURL,
		Representation: "source_declared_copy_all_for_ai_markdown", RepresentationCoordinate: "button[aria-label=Copy all for AI]",
		BodySHA256: intuitProfitAndLossDetailCopyAllSHA256, BodyByteCount: intuitProfitAndLossDetailCopyAllByteCount, Ranges: ranges,
	})
	return fixture.ManifestSHA256, fixture.Proof, fixture.Bodies, fixture.LocatorRootSHA256
}

func intuitCopyAllDerivationProgram() map[string]interface{} {
	sources := []string{
		intuitFirstResponseExampleSource, intuitHeadingsSource, intuitOperationSource, intuitQueryParametersSource,
		intuitReportResourceSource, intuitRequestExampleSource, intuitResponseFieldsSource, intuitReturnSemanticsSource,
		intuitSecondResponseExampleSource,
	}
	sort.Strings(sources)
	rules := make([]interface{}, 0, 22)
	add := func(rule map[string]interface{}) {
		rule["ordinal"] = json.Number(strconv.Itoa(len(rules)))
		rules = append(rules, rule)
	}
	add(intuitCopyAllRule("report_resource", intuitReportResourceSource, "source_contract_index", "report_resource",
		`(?m)^The information below provides a reference on how to access the (?P<report_display_name>Profit and Loss Detail) report from the (?P<service_name>QuickBooks Online Report Service)\.$`, 256, 1, 1,
		map[string]interface{}{"fact_kind": "report_resource", "report_display_name": "${report_display_name}", "service_name": "${service_name}", "source_neutral_resource_kind": "financial_report"}))
	add(intuitCopyAllRule("response_field_contracts", intuitResponseFieldsSource, "source_contract_index", "field_contract",
		`(?m)^\| (?P<field_name>[a-z_]{1,128}) \| (?P<provider_type>[A-Za-z]{1,64}) \| (?P<provider_requirement>Required|Optional) \| (?P<provider_description>[^\r\n|]{1,1000}) \|\r?$`, 8192, 16, 16,
		map[string]interface{}{"fact_kind": "response_field", "field_name": "${field_name}", "provider_description": "${provider_description}", "provider_requirement": "${provider_requirement}", "provider_type": "${provider_type}", "table_context": "response_attributes"}))
	add(intuitCopyAllRule("query_operation", intuitOperationSource, "source_contract_index", "api_operation",
		"(?m)^`(?P<http_method>GET) (?P<uri_template>/v3/company/<realmID>/reports/ProfitAndLossDetail\\?<name>=<value>\\[&\\.\\.\\.\\])`$", 256, 1, 1,
		map[string]interface{}{"fact_kind": "api_operation", "http_method": "${http_method}", "operation_semantics": "read_financial_report", "uri_template": "${uri_template}"}))
	add(intuitCopyAllRule("query_parameter_contracts", intuitQueryParametersSource, "protocol_contract_index", "query_parameter_contract",
		`(?m)^\| (?P<parameter_name>[a-z_]{1,128}) \| (?P<provider_type>[A-Za-z]{1,64}) \| (?P<provider_requirement>Required|Optional) \| (?P<provider_description>[^\r\n|]{1,1000}) \|\r?$`, 8192, 16, 16,
		map[string]interface{}{"fact_kind": "query_parameter", "parameter_location": "query", "parameter_name": "${parameter_name}", "provider_description": "${provider_description}", "provider_requirement": "${provider_requirement}", "provider_type": "${provider_type}", "table_context": "query_parameters"}))
	add(intuitCopyAllRule("request_example", intuitRequestExampleSource, "sample_shape_index", "request_example_block",
		`(?m)^"(?P<request_url>BaseURL/v3/company/(?P<realm_id>[0-9]{1,20})/reports/ProfitAndLossDetail\?start_date=(?P<start_date>[0-9]{4}-[0-9]{2}-[0-9]{2})&end_date=(?P<end_date>[0-9]{4}-[0-9]{2}-[0-9]{2})&customer=(?P<customer_id>[0-9]{1,20})&columns=(?P<columns>[A-Za-z0-9_%]{1,128}))"$`, 512, 1, 1,
		map[string]interface{}{"block_content_bytes": intuitExactMatchByteCountOperand(), "block_content_sha256": intuitExactMatchSHA256Operand(), "columns_lexeme": "${columns}", "customer_identifier_lexeme": "${customer_id}", "end_date_lexeme": "${end_date}", "fact_kind": "request_example", "realm_identifier_lexeme": "${realm_id}", "request_url": "${request_url}", "start_date_lexeme": "${start_date}"}))

	for _, response := range []struct{ suffix, source string }{{"one", intuitFirstResponseExampleSource}, {"two", intuitSecondResponseExampleSource}} {
		add(intuitCopyAllRule("response_example_"+response.suffix, response.source, "sample_shape_index", "response_example_block",
			`(?ms)^\{\r\n  "Header": \{[\x00-\x7f]{0,1000}[\x00-\x7f]{0,1000}[\x00-\x7f]{0,1000}[\x00-\x7f]{0,1000}[\x00-\x7f]{0,1000}[\x00-\x7f]{0,1000}[\x00-\x7f]{0,1000}[\x00-\x7f]{0,1000}[\x00-\x7f]{0,1000}[\x00-\x7f]{0,1000}[\x00-\x7f]{0,1000}\r\n\}$`, 12000, 1, 1,
			map[string]interface{}{"block_content_bytes": intuitExactMatchByteCountOperand(), "block_content_sha256": intuitExactMatchSHA256Operand(), "fact_kind": "response_example", "report_name": "ProfitAndLossDetail", "sample_context": "response"}))
		add(intuitCopyAllRule("response_date_lexemes_"+response.suffix, response.source, "sample_shape_index", "date_lexical_shape",
			`(?m)^[ ]{1,64}"(?P<json_key>StartPeriod|EndPeriod|value)": "(?P<source_lexeme>[0-9]{4}-[0-9]{2}-[0-9]{2})",?[ ]{0,8}\r?$`, 128, 6, 6,
			map[string]interface{}{"fact_kind": "date_lexeme", "json_key": "${json_key}", "lexical_kind": "iso8601_full_date_string", "source_lexeme": "${source_lexeme}"}))
		add(intuitCopyAllRule("response_timestamp_lexeme_"+response.suffix, response.source, "sample_shape_index", "timestamp_lexical_shape",
			`(?m)^[ ]{1,64}"(?P<json_key>Time)": "(?P<source_lexeme>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[-+][0-9]{2}:[0-9]{2})",?[ ]{0,8}\r?$`, 128, 1, 1,
			map[string]interface{}{"fact_kind": "timestamp_lexeme", "json_key": "${json_key}", "lexical_kind": "iso8601_offset_datetime_string", "source_lexeme": "${source_lexeme}"}))
		add(intuitCopyAllRule("response_currency_lexeme_"+response.suffix, response.source, "sample_shape_index", "currency_lexical_shape",
			`(?m)^[ ]{1,64}"(?P<json_key>Currency)": "(?P<source_lexeme>[A-Z]{3})",?[ ]{0,8}\r?$`, 128, 1, 1,
			map[string]interface{}{"fact_kind": "currency_lexeme", "json_key": "${json_key}", "lexical_kind": "iso4217_currency_code_string", "source_lexeme": "${source_lexeme}"}))
		add(intuitCopyAllRule("response_decimal_lexemes_"+response.suffix, response.source, "sample_shape_index", "decimal_lexical_shape",
			`(?m)^[ ]{1,64}"(?P<json_key>value)": "(?P<source_lexeme>-?[0-9]{1,18}\.[0-9]{1,9})",?[ ]{0,8}\r?$`, 128, 11, 11,
			map[string]interface{}{"fact_kind": "decimal_lexeme", "json_key": "${json_key}", "lexical_kind": "string_encoded_decimal", "source_lexeme": "${source_lexeme}"}))
		add(intuitCopyAllRule("response_id_lexemes_"+response.suffix, response.source, "sample_shape_index", "identifier_lexical_shape",
			`(?m)^[ ]{1,64}"(?P<json_key>id)": "(?P<source_lexeme>[0-9]{1,20})",?[ ]{0,8}\r?$`, 128, 7, 7,
			map[string]interface{}{"fact_kind": "identifier_lexeme", "json_key": "${json_key}", "lexical_kind": "string_encoded_identifier", "source_lexeme": "${source_lexeme}"}))
		add(intuitCopyAllRule("response_customer_identifier_"+response.suffix, response.source, "sample_shape_index", "identifier_lexical_shape",
			`(?m)^[ ]{1,64}"(?P<json_key>Customer)": "(?P<source_lexeme>[0-9]{1,20})",?[ ]{0,8}\r?$`, 128, 1, 1,
			map[string]interface{}{"fact_kind": "identifier_lexeme", "json_key": "${json_key}", "lexical_kind": "string_encoded_identifier", "source_lexeme": "${source_lexeme}"}))
	}
	add(intuitCopyAllRule("documentation_headings", intuitHeadingsSource, "source_contract_index", "documentation_heading",
		`(?m)^(?P<heading_marker>#{1,4}) (?P<heading_text>[A-Za-z0-9 ()]{1,64})$`, 128, 1, 1,
		map[string]interface{}{"fact_kind": "heading", "heading_marker": "${heading_marker}", "heading_text": "${heading_text}"}))
	add(intuitCopyAllRule("return_semantics", intuitReturnSemanticsSource, "protocol_contract_index", "return_contract",
		`(?m)^(?P<return_semantics>Returns the report object\.)$`, 64, 1, 1,
		map[string]interface{}{"fact_kind": "return_semantics", "return_semantics": "${return_semantics}"}))
	add(intuitCopyAllRule("optional_pagination_semantics", intuitReturnSemanticsSource, "protocol_contract_index", "pagination_contract",
		`(?m)^Returns an asynchronously paginated cursor\.$`, 64, 0, 1,
		map[string]interface{}{"fact_kind": "optional_pagination_semantics", "pagination_semantics": "asynchronous_cursor"}))

	return map[string]interface{}{
		"program_kind": exactDocumentationDerivationProgramKind, "input_encoding": exactDocumentationDerivationEncodingUTF8,
		"max_parse_bytes": json.Number("16384"), "max_output_bytes_per_fact": json.Number("65536"),
		"max_output_facts_per_page": json.Number("5"), "max_output_bytes_per_page": json.Number("1048576"),
		"max_output_facts_per_run": json.Number("256"), "max_output_bytes_per_run": json.Number("16777216"),
		"max_output_pages_per_run": json.Number("128"), "max_matcher_evaluations_per_input_unit": json.Number("512"),
		"max_matcher_evaluations_per_run": json.Number("65536"), "max_occurrence_outcomes_per_run": json.Number("128"),
		"max_matcher_input_bytes_per_input_unit": json.Number("16777216"), "max_matcher_input_bytes_per_run": json.Number("1073741824"),
		"max_canonical_outcome_bytes_per_run": json.Number("1048576"),
		"input_source_symbols":                stringsAsInterfaces(sources), "ordered_rules": rules,
	}
}

func intuitCopyAllRule(ruleID, inputSourceSymbol, targetArtifactRole, targetRowKind, pattern string, maximumMatchBytes, minimum, maximum int64, output map[string]interface{}) map[string]interface{} {
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
		"output_fields": output, "exact_output_field_names": stringsAsInterfaces(fields),
	}
}

// These two closed objects are executor-owned typed operands. They let a
// provider-neutral program bind sample metadata to the exact selected match
// without copying a potentially large provider body into semantic output.
func intuitExactMatchSHA256Operand() map[string]interface{} {
	return map[string]interface{}{"$exact_match_property": "selected_range_sha256"}
}

func intuitExactMatchByteCountOperand() map[string]interface{} {
	return map[string]interface{}{"$exact_match_property": "selected_range_byte_count"}
}

func intuitCopyAllExecutableProfileRows(t *testing.T, reference dependencyProfileReference, program map[string]interface{}) dependencySemanticRows {
	t.Helper()
	schemaID := "urn:provider-documentation:intuit:qbo:profit-and-loss-detail:claim:v1"
	schemaCanonical := intuitMustCanonicalJSON(t, intuitCopyAllClaimSchema(schemaID))
	schemaReference := dependencyProfileReference{id: schemaID, version: "1", digest: sha256Hex(schemaCanonical)}
	objects := []map[string]interface{}{
		{
			"row_kind": "artifact_manifest", "artifact": "intuit_qbo_profit_and_loss_detail_documentation_derivation", "artifact_version": "1",
			"canonical_admission_authorized": false, "independent_generic_reexecution_required": true,
		},
		{
			"row_kind": "validation_schema", "validation_schema_id": schemaReference.id,
			"validation_schema_version": schemaReference.version, "validation_schema_sha256": schemaReference.digest,
			"claim_kind": intuitDocumentationClaimKind, "schema_dialect": validationProfileDraft202012, "canonical_schema_json": string(schemaCanonical),
		},
		{
			"row_kind": "derivation_profile", "derivation_profile_id": reference.id,
			"derivation_profile_version": reference.version, "derivation_profile_sha256": reference.digest,
			"claim_kind": intuitDocumentationClaimKind,
			"validation_schema_binding": map[string]interface{}{
				"validation_schema_id": schemaReference.id, "validation_schema_version": schemaReference.version, "validation_schema_sha256": schemaReference.digest,
			},
			"program": program,
		},
		{
			"row_kind": "validation_summary", "validation_schema_count": json.Number("1"), "derivation_profile_count": json.Number("1"),
			"classifier_profile_count": json.Number("0"), "dependency_resolution_profile_count": json.Number("0"),
			"canonical_admission_authorized": false, "independent_generic_reexecution_required": true,
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
	input := artifactInput{Path: "intuit_qbo_profit_and_loss_detail_documentation_derivation.jsonl", Raw: raw, SHA256: sha256Hex(raw), Structured: true}
	rows, err := parseDependencySemanticRows(input)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func intuitCopyAllClaimSchema(id string) map[string]interface{} {
	stringProperty := func() map[string]interface{} {
		return map[string]interface{}{"type": "string", "minLength": json.Number("1")}
	}
	digestProperty := func() map[string]interface{} {
		return map[string]interface{}{"type": "string", "pattern": "^[0-9a-f]{64}$"}
	}
	integerProperty := func() map[string]interface{} {
		return map[string]interface{}{"type": "integer", "minimum": json.Number("1")}
	}
	branch := func(kind string, fields map[string]interface{}) map[string]interface{} {
		properties := map[string]interface{}{"fact_kind": map[string]interface{}{"const": kind}}
		required := []string{"fact_kind"}
		for name, schema := range fields {
			properties[name] = schema
			required = append(required, name)
		}
		sort.Strings(required)
		return map[string]interface{}{"type": "object", "additionalProperties": false, "required": stringsAsInterfaces(required), "properties": properties}
	}
	stringFields := func(names ...string) map[string]interface{} {
		result := make(map[string]interface{}, len(names))
		for _, name := range names {
			result[name] = stringProperty()
		}
		return result
	}
	branches := []interface{}{
		branch("report_resource", stringFields("report_display_name", "service_name", "source_neutral_resource_kind")),
		branch("response_field", stringFields("field_name", "provider_description", "provider_requirement", "provider_type", "table_context")),
		branch("api_operation", stringFields("http_method", "operation_semantics", "uri_template")),
		branch("query_parameter", stringFields("parameter_location", "parameter_name", "provider_description", "provider_requirement", "provider_type", "table_context")),
		branch("request_example", map[string]interface{}{
			"block_content_bytes": integerProperty(), "block_content_sha256": digestProperty(), "columns_lexeme": stringProperty(),
			"customer_identifier_lexeme": stringProperty(), "end_date_lexeme": stringProperty(), "realm_identifier_lexeme": stringProperty(),
			"request_url": stringProperty(), "start_date_lexeme": stringProperty(),
		}),
		branch("response_example", map[string]interface{}{
			"block_content_bytes": integerProperty(), "block_content_sha256": digestProperty(), "report_name": stringProperty(), "sample_context": stringProperty(),
		}),
		branch("date_lexeme", stringFields("json_key", "lexical_kind", "source_lexeme")),
		branch("timestamp_lexeme", stringFields("json_key", "lexical_kind", "source_lexeme")),
		branch("currency_lexeme", stringFields("json_key", "lexical_kind", "source_lexeme")),
		branch("decimal_lexeme", stringFields("json_key", "lexical_kind", "source_lexeme")),
		branch("identifier_lexeme", stringFields("json_key", "lexical_kind", "source_lexeme")),
		branch("heading", stringFields("heading_marker", "heading_text")),
		branch("return_semantics", stringFields("return_semantics")),
		branch("optional_pagination_semantics", stringFields("pagination_semantics")),
	}
	return map[string]interface{}{"$schema": validationProfileDraft202012, "$id": id, "oneOf": branches}
}

func intuitCopyAllTargetMaterializationFixture(
	t *testing.T,
	profiles map[string]executableDocumentationDerivationProfile,
	facts []exactDocumentationDerivedFact,
) (
	dependencySemanticDerivationTargetSchemaAuthority,
	map[string]artifactInput,
	map[string]dependencySemanticRows,
	string,
) {
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
		canonical := intuitMustCanonicalJSON(t, row)
		roleRawRows[fact.TargetArtifactRole] = append(roleRawRows[fact.TargetArtifactRole], canonical)
	}

	declaredRoles := map[string]struct{}{}
	for _, profile := range profiles {
		for _, rule := range profile.Program.OrderedRules {
			declaredRoles[rule.TargetArtifactRole] = struct{}{}
		}
	}
	roles := []string{"protocol_contract_index", "sample_shape_index", "source_contract_index"}
	if err := requireExactSet("Copy-all declared target roles", declaredRoles, stringSet(roles)); err != nil {
		t.Fatal(err)
	}

	authority := dependencySemanticDerivationTargetSchemaAuthority{
		seal:   dependencySemanticDerivationTargetSchemaAuthorityIdentity,
		byRole: map[string]dependencySemanticDerivationTargetSchema{},
	}
	roleArtifacts := make(map[string]artifactInput, len(roles))
	roleRows := make(map[string]dependencySemanticRows, len(roles))
	bindings := make([]validationProfileBinding, 0, len(roles))
	artifacts := make([]validationProfileArtifact, 0, len(roles))
	schemas := make([]validationProfileSchema, 0, len(roles))
	bindingRows := make([][]byte, 0, len(roles))
	for _, role := range roles {
		artifactID := "intuit_qbo_profit_and_loss_detail_" + role
		derivedRowCount := len(roleRawRows[role])
		rows := append([][]byte(nil), roleRawRows[role]...)
		rows = append(rows,
			intuitMustCanonicalJSON(t, map[string]interface{}{
				"row_kind": "artifact_manifest", "artifact": artifactID, "artifact_version": version,
				"canonical_admission_authorized": false, "materialization_authority": "exact_documentation_derivation",
			}),
			intuitMustCanonicalJSON(t, map[string]interface{}{
				"row_kind": "validation_summary", "documentation_derived_row_count": json.Number(strconv.Itoa(derivedRowCount)),
				"canonical_admission_authorized": false, "result": "exact_documentation_target_fixture_complete",
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

		schemaID := "urn:provider-documentation:intuit:qbo:profit-and-loss-detail:target:" + role + ":v1"
		schemaBytes := intuitMustCanonicalJSON(t, intuitCopyAllTargetSchema(t, schemaID, artifactID, derivedRowCount, role))
		schemaSHA := sha256Hex(schemaBytes)
		schemaRole := role + "_schema"
		rowKinds := map[string]struct{}{}
		rowKinds["artifact_manifest"] = struct{}{}
		rowKinds["validation_summary"] = struct{}{}
		for _, contract := range intuitCopyAllTargetBranchContracts(t, role) {
			rowKinds[contract.RowKind] = struct{}{}
		}
		authority.byRole[role] = dependencySemanticDerivationTargetSchema{
			artifactRole: role, artifactSHA256: artifactSHA,
			schemaRole: schemaRole, schemaID: schemaID, schemaVersion: version, schemaSHA256: schemaSHA,
			schemaBytes: schemaBytes, discriminatorProperty: "row_kind", discriminatorValues: rowKinds,
		}
		bindings = append(bindings, validationProfileBinding{
			Role: role, ArtifactID: artifactID, ArtifactVersion: version, ArtifactSHA256: artifactSHA,
			SchemaID: schemaID, SchemaVersion: version, SchemaSHA256: schemaSHA,
		})
		artifacts = append(artifacts, validationProfileArtifact{ID: artifactID, Version: version, Bytes: artifactBytes})
		schemas = append(schemas, validationProfileSchema{ID: schemaID, Version: version, Bytes: schemaBytes})
		bindingRows = append(bindingRows, []byte(lengthPrefixedIdentityKey(role, artifactID, version, artifactSHA, schemaRole, schemaID, version, schemaSHA)))
	}
	if err := validateValidationProfileBindings(bindings, artifacts, schemas); err != nil {
		t.Fatalf("Copy-all exact target artifacts do not pass their bound target schemas: %v", err)
	}
	return authority, roleArtifacts, roleRows, stageCanonicalSetRoot(bindingRows)
}

func intuitCopyAllTargetBranchContracts(t *testing.T, role string) []intuitCopyAllTargetBranchContract {
	t.Helper()
	var contracts []intuitCopyAllTargetBranchContract
	switch role {
	case "source_contract_index":
		contracts = []intuitCopyAllTargetBranchContract{
			{
				RowKind:         "api_operation",
				FactKind:        "api_operation",
				StringFields:    []string{"http_method", "uri_template"},
				StringConstants: map[string]string{"operation_semantics": "read_financial_report"},
			},
			{
				RowKind:      "documentation_heading",
				FactKind:     "heading",
				StringFields: []string{"heading_marker", "heading_text"},
			},
			{
				RowKind:      "field_contract",
				FactKind:     "response_field",
				StringFields: []string{"field_name", "provider_description", "provider_requirement", "provider_type"},
				StringConstants: map[string]string{
					"table_context": "response_attributes",
				},
			},
			{
				RowKind:      "report_resource",
				FactKind:     "report_resource",
				StringFields: []string{"report_display_name", "service_name"},
				StringConstants: map[string]string{
					"source_neutral_resource_kind": "financial_report",
				},
			},
		}
	case "protocol_contract_index":
		contracts = []intuitCopyAllTargetBranchContract{
			{
				RowKind:  "pagination_contract",
				FactKind: "optional_pagination_semantics",
				StringConstants: map[string]string{
					"pagination_semantics": "asynchronous_cursor",
				},
			},
			{
				RowKind:      "query_parameter_contract",
				FactKind:     "query_parameter",
				StringFields: []string{"parameter_name", "provider_description", "provider_requirement", "provider_type"},
				StringConstants: map[string]string{
					"parameter_location": "query",
					"table_context":      "query_parameters",
				},
			},
			{
				RowKind:      "return_contract",
				FactKind:     "return_semantics",
				StringFields: []string{"return_semantics"},
			},
		}
	case "sample_shape_index":
		contracts = []intuitCopyAllTargetBranchContract{
			{
				RowKind:      "currency_lexical_shape",
				FactKind:     "currency_lexeme",
				StringFields: []string{"json_key", "source_lexeme"},
				StringConstants: map[string]string{
					"lexical_kind": "iso4217_currency_code_string",
				},
			},
			{
				RowKind:      "date_lexical_shape",
				FactKind:     "date_lexeme",
				StringFields: []string{"json_key", "source_lexeme"},
				StringConstants: map[string]string{
					"lexical_kind": "iso8601_full_date_string",
				},
			},
			{
				RowKind:      "decimal_lexical_shape",
				FactKind:     "decimal_lexeme",
				StringFields: []string{"json_key", "source_lexeme"},
				StringConstants: map[string]string{
					"lexical_kind": "string_encoded_decimal",
				},
			},
			{
				RowKind:      "identifier_lexical_shape",
				FactKind:     "identifier_lexeme",
				StringFields: []string{"json_key", "source_lexeme"},
				StringConstants: map[string]string{
					"lexical_kind": "string_encoded_identifier",
				},
			},
			{
				RowKind:               "request_example_block",
				FactKind:              "request_example",
				StringFields:          []string{"columns_lexeme", "customer_identifier_lexeme", "end_date_lexeme", "realm_identifier_lexeme", "request_url", "start_date_lexeme"},
				DigestFields:          []string{"block_content_sha256"},
				PositiveIntegerFields: []string{"block_content_bytes"},
			},
			{
				RowKind:               "response_example_block",
				FactKind:              "response_example",
				DigestFields:          []string{"block_content_sha256"},
				PositiveIntegerFields: []string{"block_content_bytes"},
				StringConstants: map[string]string{
					"report_name":    "ProfitAndLossDetail",
					"sample_context": "response",
				},
			},
			{
				RowKind:      "timestamp_lexical_shape",
				FactKind:     "timestamp_lexeme",
				StringFields: []string{"json_key", "source_lexeme"},
				StringConstants: map[string]string{
					"lexical_kind": "iso8601_offset_datetime_string",
				},
			},
		}
	default:
		t.Fatalf("Copy-all target role %q has no independent target-schema contract", role)
	}
	sort.Slice(contracts, func(i, j int) bool { return contracts[i].RowKind < contracts[j].RowKind })
	for index, contract := range contracts {
		if contract.RowKind == "" || contract.FactKind == "" {
			t.Fatalf("Copy-all target role %q contract %d has incomplete identity: %#v", role, index, contract)
		}
		if index > 0 && contracts[index-1].RowKind == contract.RowKind {
			t.Fatalf("Copy-all target role %q repeats row_kind %q", role, contract.RowKind)
		}
	}
	return contracts
}

func intuitCopyAllTargetSchema(t *testing.T, id, artifactID string, derivedRowCount int, role string) map[string]interface{} {
	t.Helper()
	branchesByRowKind := map[string]map[string]interface{}{}
	for _, contract := range intuitCopyAllTargetBranchContracts(t, role) {
		properties := map[string]interface{}{
			"row_kind":                           map[string]interface{}{"const": contract.RowKind},
			exactDocumentationDerivedFactIDField: map[string]interface{}{"type": "string", "minLength": json.Number("1")},
			"source_ref":                         map[string]interface{}{"const": intuitProfitAndLossDetailSourceRef},
			"source_url":                         map[string]interface{}{"const": intuitProfitAndLossDetailSourceURL},
			"source_content_sha256":              map[string]interface{}{"const": intuitProfitAndLossDetailCopyAllSHA256},
			"evidence_hydration_coordinate": map[string]interface{}{
				"type": "object", "additionalProperties": false,
				"required": []interface{}{"byte_end_offset_exclusive", "byte_start_offset", "selected_range_byte_count", "selected_range_sha256", "source_content_sha256"},
				"properties": map[string]interface{}{
					"source_content_sha256":     map[string]interface{}{"const": intuitProfitAndLossDetailCopyAllSHA256},
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
		for _, field := range contract.DigestFields {
			properties[field] = map[string]interface{}{"type": "string", "pattern": "^[0-9a-f]{64}$"}
			required = append(required, field)
		}
		for _, field := range contract.PositiveIntegerFields {
			properties[field] = map[string]interface{}{"type": "integer", "minimum": json.Number("1")}
			required = append(required, field)
		}
		constantNames := make([]string, 0, len(contract.StringConstants))
		for field := range contract.StringConstants {
			constantNames = append(constantNames, field)
		}
		sort.Strings(constantNames)
		for _, field := range constantNames {
			properties[field] = map[string]interface{}{"const": contract.StringConstants[field]}
			required = append(required, field)
		}
		sort.Strings(required)
		branch := map[string]interface{}{
			"type": "object", "additionalProperties": false,
			"required": stringsAsInterfaces(required), "properties": properties,
		}
		branchesByRowKind[contract.RowKind] = branch
	}
	branchesByRowKind["artifact_manifest"] = map[string]interface{}{
		"type": "object", "additionalProperties": false,
		"required": []interface{}{"artifact", "artifact_version", "canonical_admission_authorized", "materialization_authority", "row_kind"},
		"properties": map[string]interface{}{
			"row_kind": map[string]interface{}{"const": "artifact_manifest"}, "artifact": map[string]interface{}{"const": artifactID},
			"artifact_version": map[string]interface{}{"const": "1"}, "canonical_admission_authorized": map[string]interface{}{"const": false},
			"materialization_authority": map[string]interface{}{"const": "exact_documentation_derivation"},
		},
	}
	branchesByRowKind["validation_summary"] = map[string]interface{}{
		"type": "object", "additionalProperties": false,
		"required": []interface{}{"canonical_admission_authorized", "documentation_derived_row_count", "result", "row_kind"},
		"properties": map[string]interface{}{
			"row_kind": map[string]interface{}{"const": "validation_summary"}, "canonical_admission_authorized": map[string]interface{}{"const": false},
			"documentation_derived_row_count": map[string]interface{}{"const": json.Number(strconv.Itoa(derivedRowCount))},
			"result":                          map[string]interface{}{"const": "exact_documentation_target_fixture_complete"},
		},
	}
	rowKinds := sortedSetKeys(stringMapKeysAsSet(branchesByRowKind))
	branches := make([]interface{}, len(rowKinds))
	for index, rowKind := range rowKinds {
		branches[index] = branchesByRowKind[rowKind]
	}
	return map[string]interface{}{"$schema": validationProfileDraft202012, "$id": id, "oneOf": branches}
}

func assertIntuitCopyAllOutcomes(t *testing.T, outcomes []exactDocumentationDerivationOccurrenceOutcome) {
	t.Helper()
	if len(outcomes) != 29 {
		t.Fatalf("Copy-all occurrence outcome count = %d, want 29", len(outcomes))
	}
	matched, zero := 0, 0
	for _, outcome := range outcomes {
		if !isLowerSHA256(outcome.DerivedFactSetRootSHA256) || outcome.OutcomeID == "" {
			t.Fatalf("Copy-all outcome is not sealed: %#v", outcome)
		}
		switch outcome.Disposition {
		case exactDocumentationDerivationMatched:
			matched++
			if outcome.MatchCount <= 0 || int64(len(outcome.DerivedFactIDs)) != outcome.MatchCount {
				t.Fatalf("matched Copy-all outcome has incomplete facts: %#v", outcome)
			}
		case exactDocumentationDerivationZeroMatchAllowed:
			zero++
			if outcome.RuleID != "optional_pagination_semantics" || outcome.InputSourceSymbol != intuitReturnSemanticsSource || outcome.MatchCount != 0 || len(outcome.DerivedFactIDs) != 0 {
				t.Fatalf("unexpected zero-match Copy-all outcome: %#v", outcome)
			}
		default:
			t.Fatalf("Copy-all outcome has unknown disposition: %#v", outcome)
		}
	}
	if matched != 28 || zero != 1 {
		t.Fatalf("Copy-all outcome dispositions matched=%d zero=%d, want 28/1", matched, zero)
	}
}

func assertIntuitCopyAllFacts(t *testing.T, body []byte, manifestSHA string, facts []exactDocumentationDerivedFact) {
	t.Helper()
	if len(facts) != 100 {
		t.Fatalf("Copy-all fact count = %d, want 100", len(facts))
	}
	kindCounts := map[string]int{}
	lexemes := map[string]map[string]int{}
	fieldNames := map[string]map[string]struct{}{"response_field": {}, "query_parameter": {}}
	responseBlocks := make([]exactDocumentationDerivedFact, 0, 2)
	requestBlocks := make([]exactDocumentationDerivedFact, 0, 1)
	for _, fact := range facts {
		if err := validateExactDocumentationDerivedFactIntegrity(fact); err != nil {
			t.Fatalf("Copy-all fact %q: %v", fact.FactID, err)
		}
		locator := fact.EvidenceLocator
		if locator.EvidenceManifestSHA256 != manifestSHA || locator.SourceContentSHA256 != intuitProfitAndLossDetailCopyAllSHA256 || locator.ByteEndOffsetExclusive > int64(len(body)) || locator.SelectedRangeSHA256 != sha256Hex(body[locator.ByteStartOffset:locator.ByteEndOffsetExclusive]) {
			t.Fatalf("fact %s is not hydrated by exact Copy-all bytes", fact.FactID)
		}
		output, err := decodeExactDocumentationFactOutputFields(fact)
		if err != nil {
			t.Fatal(err)
		}
		kind, ok := output["fact_kind"].(string)
		if !ok {
			t.Fatalf("fact %s has no fact_kind", fact.FactID)
		}
		kindCounts[kind]++
		if value, ok := output["source_lexeme"].(string); ok {
			if lexemes[kind] == nil {
				lexemes[kind] = map[string]int{}
			}
			lexemes[kind][value]++
		}
		if kind == "response_field" {
			fieldNames[kind][output["field_name"].(string)] = struct{}{}
		}
		if kind == "query_parameter" {
			fieldNames[kind][output["parameter_name"].(string)] = struct{}{}
		}
		switch kind {
		case "response_example":
			responseBlocks = append(responseBlocks, fact)
			assertIntuitBlockOutput(t, output, locator)
		case "request_example":
			requestBlocks = append(requestBlocks, fact)
			assertIntuitBlockOutput(t, output, locator)
		}
	}
	wantCounts := map[string]int{
		"report_resource": 1, "response_field": 16, "api_operation": 1, "query_parameter": 16,
		"request_example": 1, "response_example": 2, "date_lexeme": 12, "timestamp_lexeme": 2,
		"currency_lexeme": 2, "decimal_lexeme": 22, "identifier_lexeme": 16, "heading": 8, "return_semantics": 1,
	}
	for kind, count := range wantCounts {
		if kindCounts[kind] != count {
			t.Fatalf("Copy-all fact kind %q count = %d, want %d (all=%#v)", kind, kindCounts[kind], count, kindCounts)
		}
	}
	if len(kindCounts) != len(wantCounts) {
		t.Fatalf("Copy-all fact kinds = %#v, want %#v", kindCounts, wantCounts)
	}
	if len(fieldNames["response_field"]) != 16 || len(fieldNames["query_parameter"]) != 16 || !equalStringSets(fieldNames["response_field"], fieldNames["query_parameter"]) {
		t.Fatalf("context-distinct response/query field rosters do not preserve the two exact tables: %#v", fieldNames)
	}
	assertIntuitLexemeCounts(t, lexemes["date_lexeme"], map[string]int{"2015-06-01": 2, "2015-06-27": 8, "2015-06-30": 2})
	assertIntuitLexemeCounts(t, lexemes["timestamp_lexeme"], map[string]int{"2016-03-11T14:53:39-08:00": 2})
	assertIntuitLexemeCounts(t, lexemes["currency_lexeme"], map[string]int{"USD": 2})
	assertIntuitLexemeCounts(t, lexemes["decimal_lexeme"], map[string]int{"1750.0": 8, "20.0": 2, "24.0": 2, "44.0": 2, "400.0": 4, "2194.0": 4})
	assertIntuitLexemeCounts(t, lexemes["identifier_lexeme"], map[string]int{"1": 2, "3": 10, "49": 2, "79": 2})
	if len(responseBlocks) != 2 || responseBlocks[0].EvidenceLocator.SelectedRangeSHA256 != responseBlocks[1].EvidenceLocator.SelectedRangeSHA256 || responseBlocks[0].EvidenceLocatorID == responseBlocks[1].EvidenceLocatorID || responseBlocks[0].InputSourceSymbol == responseBlocks[1].InputSourceSymbol {
		t.Fatalf("two exact response examples were not preserved as distinct occurrences: %#v", responseBlocks)
	}
	if len(requestBlocks) != 1 || requestBlocks[0].EvidenceLocator.SelectedRangeByteCount != 153 || requestBlocks[0].EvidenceLocator.SelectedRangeSHA256 != "f041a01c07230bde916c33e4953c2be8dc41bdddadc849aef782a6251c6e0c58" {
		t.Fatalf("request example exact block = %#v", requestBlocks)
	}
}

func assertIntuitBlockOutput(t *testing.T, output map[string]interface{}, locator evidenceLocator) {
	t.Helper()
	digest, digestOK := output["block_content_sha256"].(string)
	byteCount, countOK := output["block_content_bytes"].(json.Number)
	if !countOK {
		if number, ok := output["block_content_bytes"].(float64); ok {
			byteCount = json.Number(strconv.FormatInt(int64(number), 10))
			countOK = true
		}
	}
	parsedCount, err := strconv.ParseInt(string(byteCount), 10, 64)
	if !digestOK || !countOK || err != nil || digest != locator.SelectedRangeSHA256 || parsedCount != locator.SelectedRangeByteCount {
		t.Fatalf("sample block output does not equal its executor-owned exact range: output=%#v locator=%#v", output, locator)
	}
}

func assertIntuitLexemeCounts(t *testing.T, got, want map[string]int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("lexeme roster = %#v, want %#v", got, want)
	}
	for lexeme, count := range want {
		if got[lexeme] != count {
			t.Fatalf("lexeme %q count = %d, want %d (all=%#v)", lexeme, got[lexeme], count, got)
		}
	}
}

func assertIntuitCopyAllDeterministicRoots(
	t *testing.T,
	locatorRoot string,
	targetBindingRoot string,
	execution exactDocumentationDerivationProfileExecutionSet,
	result exactDocumentationDerivationExecutionResult,
	materializations []documentationTargetMaterialization,
	closure documentationDerivationClosureProof,
) {
	t.Helper()
	bindingRows := make([][]byte, len(materializations))
	for index, materialization := range materializations {
		bindingRows[index] = []byte(lengthPrefixedIdentityKey(
			materialization.identity.FactID,
			materialization.bindingSHA256,
			strconv.FormatInt(materialization.canonicalBytes, 10),
		))
	}
	independentlyRecomputedBindingRoot := stageCanonicalSetRoot(bindingRows)
	if got := documentationTargetMaterializationBindingRosterRoot(materializations); got != independentlyRecomputedBindingRoot {
		t.Fatalf("Copy-all target materialization binding root = %s, independently recomputed length-prefixed set root %s", got, independentlyRecomputedBindingRoot)
	}
	// These values are intentionally literal fixture pins. Any change means the
	// selected bytes, classification, executable profile, outcomes, facts,
	// pagination, or target-schema contract changed and must be explained and
	// independently revalidated before the pins move.
	want := map[string]string{
		"classification_locator_root":                "e5ca422c15de90fcc06ec9fffaea48cfbab1e8133a052246e184b06a9714c032",
		"target_schema_binding_root":                 "309ad6ba0497492098dcb9cbb86901b47a2b317536a04783c6339989cbff3d3e",
		"profile_page_set_root":                      "35ffcd6cacc5a13ec06f73889360904869cb68cef973546eb32ef9751216effd",
		"profile_result_set_root":                    "20291c2cbb648f905e11fecc97433874de766b03fbbe128d208ea60bfe2252bf",
		"outcome_set_root":                           "b74955a8a38dbfaaa43420529f55e2b126f42ac1f05d743f06250b1aca866254",
		"fact_set_root":                              "ddb25c7d8725197534a963714fe2774a1626973b7752435a511eaa2a60cea23f",
		"page_set_root":                              "cf3ab95f90c06642cea22b99246c9e7c3e2ac7a670441150ad2f5db39eef8f10",
		"result_root":                                "334b7df4410e7f0b0141fe9e99af08614f1cac3f8dbc7b7cc1707a4cebb26f34",
		"target_materialization_root":                "0ccf7aa62330f9b57e0ab59c3f015fb677c45f7ee3c39312594071ec0470e768",
		"target_materialization_binding_roster_root": "96df1fe51b9154ee2aa3317d696202313b8510891e362a7eea6541759b97f0d6",
		"closure_proof_sha256":                       "0d1b36ae5ba7532a10233864373abfc063cef678581f1766d2cfc310be789130",
	}
	got := map[string]string{
		"classification_locator_root":                locatorRoot,
		"target_schema_binding_root":                 targetBindingRoot,
		"profile_page_set_root":                      execution.ProfilePageSetRootSHA256,
		"profile_result_set_root":                    execution.ProfileResultSetRootSHA256,
		"outcome_set_root":                           result.OutcomeSetRootSHA256,
		"fact_set_root":                              result.FactSetRootSHA256,
		"page_set_root":                              result.PageSetRootSHA256,
		"result_root":                                result.ResultRootSHA256,
		"target_materialization_root":                documentationTargetMaterializationRoot(materializations),
		"target_materialization_binding_roster_root": documentationTargetMaterializationBindingRosterRoot(materializations),
		"closure_proof_sha256":                       closure.proofSHA256,
	}
	for name, expected := range want {
		if got[name] != expected {
			t.Fatalf("Copy-all %s = %s, want %s (all=%#v)", name, got[name], expected, got)
		}
	}
}

func intuitMustCanonicalJSON(t *testing.T, value interface{}) []byte {
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

func stringsAsInterfaces(values []string) []interface{} {
	result := make([]interface{}, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func equalStringSets(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, exists := right[value]; !exists {
			return false
		}
	}
	return true
}

func TestIntuitProfitAndLossDetailCopyAllRangesStayNonOverlappingBySemanticIdentity(t *testing.T) {
	bySymbol := map[string][]intuitCopyAllEvidenceRange{}
	for _, selected := range intuitCopyAllEvidenceRanges {
		bySymbol[selected.SourceSymbol] = append(bySymbol[selected.SourceSymbol], selected)
		if selected.ByteStartOffset == 0 && selected.ByteEndOffsetExclusive == intuitProfitAndLossDetailCopyAllByteCount {
			t.Fatalf("source symbol %q falls back to full-page classification", selected.SourceSymbol)
		}
	}
	if len(bySymbol) != 9 || len(bySymbol[intuitHeadingsSource]) != 8 {
		t.Fatalf("Copy-all semantic classification = %#v, want nine symbols and eight exact heading occurrences", bySymbol)
	}
	for symbol, ranges := range bySymbol {
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].ByteStartOffset < ranges[j].ByteStartOffset })
		for index := 1; index < len(ranges); index++ {
			if ranges[index].ByteStartOffset < ranges[index-1].ByteEndOffsetExclusive {
				t.Fatalf("source symbol %q has overlapping semantic occurrences %q and %q", symbol, ranges[index-1].Name, ranges[index].Name)
			}
		}
	}
	first := intuitCopyAllEvidenceRanges[5]
	second := intuitCopyAllEvidenceRanges[6]
	if first.SelectedRangeSHA256 != second.SelectedRangeSHA256 || first.ByteStartOffset == second.ByteStartOffset || first.SourceSymbol == second.SourceSymbol {
		t.Fatal("byte-identical response examples are not distinct exact source occurrences")
	}
}

func TestIntuitCopyAllTypedMatchOperandsAreRequiredForExactSampleMetadata(t *testing.T) {
	output := map[string]interface{}{
		"block_content_bytes":  intuitExactMatchByteCountOperand(),
		"block_content_sha256": intuitExactMatchSHA256Operand(),
	}
	canonical := intuitMustCanonicalJSON(t, output)
	if !bytes.Contains(canonical, []byte(`"$exact_match_property":"selected_range_sha256"`)) || !bytes.Contains(canonical, []byte(`"$exact_match_property":"selected_range_byte_count"`)) {
		t.Fatalf("exact sample metadata operands are not closed and explicit: %s", canonical)
	}
}
