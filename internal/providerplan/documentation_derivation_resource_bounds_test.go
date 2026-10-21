package providerplan

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestDocumentationDerivationRejectsCaptureFanoutBeforeExecution(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, _, _ := exactDocumentationProgramFixture(t, body, 1, 1)
	object := decodeDocumentationProgramObject(t, raw)
	rule := documentationProgramRuleObject(t, object, 0)
	rule["output_fields"].(map[string]interface{})["field_name"] = strings.Repeat("${field_name}", 200)
	canonical := encodeDocumentationProgramObject(t, object, &reference)
	if _, err := parseExactDocumentationDerivationProgram(canonical, reference); err == nil || !strings.Contains(err.Error(), "conservative canonical output expansion bound") {
		t.Fatalf("error = %v, want pre-execution expansion-bound refusal", err)
	}
}

func TestDocumentationDerivationExactMatchPropertiesAreTypedWholeValues(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	object := decodeDocumentationProgramObject(t, raw)
	rule := documentationProgramRuleObject(t, object, 0)
	outputs := rule["output_fields"].(map[string]interface{})
	outputs["block_content_bytes"] = map[string]interface{}{documentationExactMatchPropertyKey: documentationExactMatchPropertyByteCount}
	outputs["block_content_sha256"] = map[string]interface{}{documentationExactMatchPropertyKey: documentationExactMatchPropertySHA256}
	rule["exact_output_field_names"] = []interface{}{"block_content_bytes", "block_content_sha256", "field_name", "provider_requirement", "provider_type"}
	canonical := encodeDocumentationProgramObject(t, object, &reference)
	program, err := parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := executeExactDocumentationDerivationProgram(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Fatalf("facts = %d, want 1", len(facts))
	}
	output, err := decodeExactDocumentationFactOutputFields(facts[0])
	if err != nil {
		t.Fatal(err)
	}
	if output["block_content_sha256"] != facts[0].SelectedMatchSHA256 {
		t.Fatalf("selected-range digest = %#v", output["block_content_sha256"])
	}
	if count, ok := output["block_content_bytes"].(json.Number); !ok || count.String() != strconv.FormatInt(facts[0].EvidenceLocator.SelectedRangeByteCount, 10) {
		t.Fatalf("selected-range byte count = %#v", output["block_content_bytes"])
	}

	for name, operand := range map[string]interface{}{
		"unknown":          map[string]interface{}{documentationExactMatchPropertyKey: "raw_bytes"},
		"not exact object": map[string]interface{}{documentationExactMatchPropertyKey: documentationExactMatchPropertySHA256, "extra": true},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := decodeDocumentationProgramObject(t, raw)
			candidateRule := documentationProgramRuleObject(t, candidate, 0)
			candidateRule["output_fields"].(map[string]interface{})["field_name"] = operand
			candidateCanonical := encodeDocumentationProgramObject(t, candidate, &reference)
			if _, err := parseExactDocumentationDerivationProgram(candidateCanonical, reference); err == nil {
				t.Fatal("invalid exact-match-property operand parsed")
			}
		})
	}
}

func TestDocumentationDerivationRowMemberCoordinatesAreResolvedAndContentAddressed(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	object := decodeDocumentationProgramObject(t, raw)
	rule := documentationProgramRuleObject(t, object, 0)
	rule["target_binding_kind"] = exactDocumentationTargetRowMember
	rule["target_member_json_pointer"] = "/resource_accesses"
	rule["target_row_selector"] = []interface{}{map[string]interface{}{"target_row_json_pointer": "/source_symbol", "expected_string_template": "operation.${field_name}"}}
	rule["target_member_identity_json_pointers"] = []interface{}{"/field_name"}
	canonical := encodeDocumentationProgramObject(t, object, &reference)
	program, err := parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := executeExactDocumentationDerivationProgram(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	fact := facts[0]
	if len(fact.TargetRowSelector) != 1 || fact.TargetRowSelector[0].ExpectedString != "operation.amount" || !isLowerSHA256(fact.TargetRowSelectorSHA256) || len(fact.TargetMemberIdentity) != 1 || fact.TargetMemberIdentity[0].ExpectedString != "amount" || !isLowerSHA256(fact.TargetMemberIdentitySHA256) {
		t.Fatalf("resolved row-member coordinates = %#v / %#v", fact.TargetRowSelector, fact.TargetMemberIdentity)
	}
	tampered := fact
	tampered.TargetRowSelector = append([]exactDocumentationResolvedTargetRowSelector(nil), fact.TargetRowSelector...)
	tampered.TargetRowSelector[0].ExpectedString = "operation.memo"
	if err := validateExactDocumentationDerivedFactTargetIdentity(tampered); err == nil {
		t.Fatal("selector-only fact mutation retained a valid identity")
	}
	tampered = fact
	tampered.TargetMemberIdentity = append([]exactDocumentationResolvedMemberIdentity(nil), fact.TargetMemberIdentity...)
	tampered.TargetMemberIdentity[0].ExpectedString = "memo"
	if err := validateExactDocumentationDerivedFactTargetIdentity(tampered); err == nil {
		t.Fatal("member-identity-only fact mutation retained a valid identity")
	}
	paged, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	forgedPages := cloneExactDocumentationPages(paged.Pages)
	forged := &forgedPages[0].Facts[0]
	forged.TargetRowSelector = append([]exactDocumentationResolvedTargetRowSelector(nil), forged.TargetRowSelector...)
	forged.TargetRowSelector[0].ExpectedString = "operation.memo"
	forged.TargetRowSelectorSHA256, err = canonicalDocumentationDigest(forged.TargetRowSelector)
	if err != nil {
		t.Fatal(err)
	}
	forged.FactID = exactDocumentationDerivedFactID(*forged)
	if _, err := sealExactDocumentationDerivationPageSet(reference, program, proof, bodies, forgedPages); err == nil || !strings.Contains(err.Error(), "bounded deterministic replay") {
		t.Fatalf("error = %v, want deterministic replay refusal of self-consistent forged selector", err)
	}
}

func TestDocumentationDerivationRowMemberDeclarationRejectsUnsafeShapes(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, _, _ := exactDocumentationProgramFixture(t, body, 0, 1)
	for name, mutate := range map[string]func(map[string]interface{}){
		"capture selector on zero match": func(rule map[string]interface{}) {
			rule["target_row_selector"] = []interface{}{map[string]interface{}{"target_row_json_pointer": "/source_symbol", "expected_string_template": "${field_name}"}}
			rule["target_member_identity_json_pointers"] = []interface{}{"/field_name"}
		},
		"overlapping selector": func(rule map[string]interface{}) {
			rule["target_row_selector"] = []interface{}{map[string]interface{}{"target_row_json_pointer": "/resource_accesses/id", "expected_string_template": "literal"}}
			rule["target_member_identity_json_pointers"] = []interface{}{"/field_name"}
		},
		"unsorted selectors": func(rule map[string]interface{}) {
			rule["target_row_selector"] = []interface{}{
				map[string]interface{}{"target_row_json_pointer": "/z", "expected_string_template": "z"},
				map[string]interface{}{"target_row_json_pointer": "/a", "expected_string_template": "a"},
			}
			rule["target_member_identity_json_pointers"] = []interface{}{"/field_name"}
		},
		"envelope member identity": func(rule map[string]interface{}) {
			rule["target_row_selector"] = []interface{}{map[string]interface{}{"target_row_json_pointer": "/source_symbol", "expected_string_template": "literal"}}
			rule["target_member_identity_json_pointers"] = []interface{}{"/documentation_derived_fact_id"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			object := decodeDocumentationProgramObject(t, raw)
			rule := documentationProgramRuleObject(t, object, 0)
			rule["target_binding_kind"] = exactDocumentationTargetRowMember
			rule["target_member_json_pointer"] = "/resource_accesses"
			mutate(rule)
			canonical := encodeDocumentationProgramObject(t, object, &reference)
			if _, err := parseExactDocumentationDerivationProgram(canonical, reference); err == nil {
				t.Fatal("unsafe row-member declaration parsed")
			}
		})
	}
}

func TestDocumentationDerivationMatcherUsesComputedWidthAndAggregateBudget(t *testing.T) {
	body := []byte(strings.Repeat("noise ", 400) + "\n| amount | Decimal | Required |\ntrailing")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	object := decodeDocumentationProgramObject(t, raw)
	object["max_parse_bytes"] = json.Number(strconv.Itoa(len(body)))
	rule := documentationProgramRuleObject(t, object, 0)
	rule["maximum_match_bytes"] = json.Number(strconv.Itoa(len(body)))
	canonical := encodeDocumentationProgramObject(t, object, &reference)
	program, err := parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	result, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	var evaluations int64
	for _, page := range result.Pages {
		evaluations += page.Descriptor.MatcherEvaluationCount
	}
	if evaluations != 2 {
		t.Fatalf("matcher evaluations = %d, want one earliest-match lookup plus one terminal lookup independent of declared maximum_match_bytes", evaluations)
	}

	object["max_matcher_evaluations_per_input_unit"] = json.Number("1")
	canonical = encodeDocumentationProgramObject(t, object, &reference)
	program, err = parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies); err == nil || !strings.Contains(err.Error(), "max_matcher_evaluations_per_input_unit") {
		t.Fatalf("error = %v, want aggregate matcher-budget refusal", err)
	}
}

func TestDocumentationDerivationStreamingAdvancesTrustedCheckpointWithoutReplay(t *testing.T) {
	body := []byte(strings.Repeat("| amount | Decimal | Required |\n", 5))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 5, 5, 512, 1, 4096)
	runtime, err := prepareExactDocumentationExecution(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := runtime.initialCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	first, err := runtime.generatePage(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runtime.generatePage(first.Continuation.NextCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	if first.Descriptor.MatcherEvaluationCount != 1 || second.Descriptor.MatcherEvaluationCount != 1 {
		t.Fatalf("per-page matcher work = %d/%d, want independent one-step progress", first.Descriptor.MatcherEvaluationCount, second.Descriptor.MatcherEvaluationCount)
	}
	if second.ParserState.MatcherEvaluationsInInputUnit != 2 || second.Continuation.NextCheckpoint.CandidateByteOffset <= first.Continuation.NextCheckpoint.CandidateByteOffset {
		t.Fatalf("resume checkpoint did not advance exactly: first=%#v second=%#v", first.Continuation.NextCheckpoint, second.Continuation.NextCheckpoint)
	}
}

func TestDocumentationDerivationStreamingAndConvenienceCapsFailClosed(t *testing.T) {
	body := []byte(strings.Repeat("| amount | Decimal | Required |\n", 3))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 3, 3, 512, 1, 4096)
	program.MaxOutputFactsPerRun = 2
	raw, err := json.Marshal(program)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	reference.digest = sha256Hex(canonical)
	program, err = parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	var streamedPages int
	err = streamExactDocumentationDerivationPages(reference, program, proof, bodies, func(exactDocumentationDerivationPage) error {
		streamedPages++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "max_output_facts_per_run") || streamedPages != 2 {
		t.Fatalf("stream result pages/error = %d/%v, want refusal before a third page is retained", streamedPages, err)
	}
	if _, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies); err == nil || !strings.Contains(err.Error(), "max_output_facts_per_run") {
		t.Fatalf("convenience execution error = %v, want same aggregate refusal", err)
	}
}

func TestDocumentationDerivationPreflightsZeroMatchOutcomeCrossProduct(t *testing.T) {
	body := []byte("no matching field rows\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 0, 1)
	object := decodeDocumentationProgramObject(t, raw)
	rules := object["ordered_rules"].([]interface{})
	cloneBytes, err := json.Marshal(rules[0])
	if err != nil {
		t.Fatal(err)
	}
	var second map[string]interface{}
	if err := decodeOneValidationProfileJSON(cloneBytes, &second); err != nil {
		t.Fatal(err)
	}
	second["ordinal"] = json.Number("1")
	second["rule_id"] = "extract_second_field_rows"
	object["ordered_rules"] = append(rules, second)
	object["max_occurrence_outcomes_per_run"] = json.Number("1")
	canonical := encodeDocumentationProgramObject(t, object, &reference)
	program, err := parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareExactDocumentationExecution(reference, program, proof, bodies); err == nil || !strings.Contains(err.Error(), "cross-product 2 exceeds max_occurrence_outcomes_per_run 1 before execution") {
		t.Fatalf("error = %v, want allocation-before-execution cross-product refusal even though both outcomes have zero facts", err)
	}
}

func TestDocumentationDerivationRejectsMissingOrEmergencyCeilingRunBudgets(t *testing.T) {
	body := []byte("no matching field rows\n")
	raw, reference, _, _ := exactDocumentationProgramFixture(t, body, 0, 1)
	for name, mutation := range map[string]interface{}{
		"missing matcher run":                nil,
		"matcher run above emergency":        json.Number(strconv.FormatInt(maxDocumentationMatcherEvaluationsPerRun+1, 10)),
		"matcher input unit above emergency": json.Number(strconv.FormatInt(maxDocumentationMatcherInputBytesPerUnit+1, 10)),
		"matcher input run above emergency":  json.Number(strconv.FormatInt(maxDocumentationMatcherInputBytesPerRun+1, 10)),
		"outcomes above emergency":           json.Number(strconv.FormatInt(maxDocumentationOccurrenceOutcomesPerRun+1, 10)),
		"outcome bytes above emergency":      json.Number(strconv.FormatInt(maxDocumentationCanonicalOutcomeBytesPerRun+1, 10)),
	} {
		t.Run(name, func(t *testing.T) {
			object := decodeDocumentationProgramObject(t, raw)
			field := map[string]string{
				"missing matcher run":                "max_matcher_evaluations_per_run",
				"matcher run above emergency":        "max_matcher_evaluations_per_run",
				"matcher input unit above emergency": "max_matcher_input_bytes_per_input_unit",
				"matcher input run above emergency":  "max_matcher_input_bytes_per_run",
				"outcomes above emergency":           "max_occurrence_outcomes_per_run",
				"outcome bytes above emergency":      "max_canonical_outcome_bytes_per_run",
			}[name]
			if mutation == nil {
				delete(object, field)
			} else {
				object[field] = mutation
			}
			candidateReference := reference
			canonical := encodeDocumentationProgramObject(t, object, &candidateReference)
			if _, err := parseExactDocumentationDerivationProgram(canonical, candidateReference); err == nil {
				t.Fatal("invalid or absent run budget parsed")
			}
		})
	}
}

func TestDocumentationDerivationEnforcesRunWideMatcherBudgetAcrossInputUnits(t *testing.T) {
	unit := strings.Repeat("x", 159) + "\n"
	body := []byte(strings.Repeat(unit, 3))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 0, 1, 160, 4, 4096)
	raw, err := json.Marshal(program)
	if err != nil {
		t.Fatal(err)
	}
	object := decodeDocumentationProgramObject(t, raw)
	object["max_matcher_evaluations_per_input_unit"] = json.Number("1")
	object["max_matcher_evaluations_per_run"] = json.Number("2")
	canonical := encodeDocumentationProgramObject(t, object, &reference)
	program, err = parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies); err == nil || !strings.Contains(err.Error(), "max_matcher_evaluations_per_run 2") {
		t.Fatalf("error = %v, want streaming run-wide matcher refusal after two independently valid units", err)
	}
}

func TestDocumentationDerivationRejectsOutcomeBytesBeforeCanonicalAllocation(t *testing.T) {
	body := []byte("no matching field rows\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 0, 1)
	object := decodeDocumentationProgramObject(t, raw)
	object["max_canonical_outcome_bytes_per_run"] = json.Number("1024")
	canonical := encodeDocumentationProgramObject(t, object, &reference)
	program, err := parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies); err == nil || !strings.Contains(err.Error(), "before allocation") {
		t.Fatalf("error = %v, want conservative outcome-envelope refusal before canonical allocation", err)
	}
}

func TestDocumentationDerivationHighPageCountCursorStateIsConstantSize(t *testing.T) {
	body := []byte(strings.Repeat("| amount | Decimal | Required |\n", 128))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 128, 128, int64(len(body)), 1, 4096)
	runtime, err := prepareExactDocumentationExecution(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := runtime.initialCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	minimumCursorBytes, maximumCursorBytes := int64(1<<62), int64(0)
	pages := 0
	for {
		page, err := runtime.generatePage(checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if page.Continuation == nil {
			break
		}
		canonical, err := canonicalDocumentationBytes(page.Continuation)
		if err != nil {
			t.Fatal(err)
		}
		cursorBytes := int64(len(canonical))
		if cursorBytes < minimumCursorBytes {
			minimumCursorBytes = cursorBytes
		}
		if cursorBytes > maximumCursorBytes {
			maximumCursorBytes = cursorBytes
		}
		checkpoint = cloneExactDocumentationCheckpoint(page.Continuation.NextCheckpoint)
	}
	if pages != 129 || maximumCursorBytes >= 4096 || maximumCursorBytes-minimumCursorBytes >= 128 {
		t.Fatalf("pages/cursor bytes = %d/%d..%d, want 128 fact pages plus one terminal page and constant-size sequence-root checkpoints", pages, minimumCursorBytes, maximumCursorBytes)
	}
}

func TestDocumentationDerivationProductionStreamWorkIsLinearAtHighPageCount(t *testing.T) {
	const factCount = 256
	body := []byte(strings.Repeat("| amount | Decimal | Required |\n", factCount))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, factCount, factCount, int64(len(body)), 1, 4096)
	var pages, evaluations int64
	err := streamExactDocumentationDerivationPages(reference, program, proof, bodies, func(page exactDocumentationDerivationPage) error {
		pages++
		evaluations += page.Descriptor.MatcherEvaluationCount
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// One lookup emits each non-overlapping fact; line-boundary progress proves
	// the final terminal page without another regexp call. Neither work nor
	// cursor state grows with page history.
	if pages != factCount+1 || evaluations != factCount {
		t.Fatalf("production stream pages/evaluations = %d/%d, want exact linear %d/%d", pages, evaluations, factCount+1, factCount)
	}
}

func TestDocumentationDerivationProductionRuntimeHydratesOccurrenceOnceBeforePaging(t *testing.T) {
	body := []byte(strings.Repeat("x", 160*64))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 0, 1, 160, 1, 4096)
	runtime, err := prepareExactDocumentationExecution(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.selectedBytes) != 1 {
		t.Fatalf("validated selected occurrence cache = %d, want 1", len(runtime.selectedBytes))
	}
	// The production runtime pins a once-validated byte view during prepare.
	// Zero-match paging therefore does not rehydrate, rehash, or UTF-8 scan the
	// whole selected occurrence for every later page.
	runtime.bodies = nil
	checkpoint, err := runtime.initialCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	var pages int
	for {
		page, err := runtime.generatePage(checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if page.Continuation == nil {
			break
		}
		checkpoint = cloneExactDocumentationCheckpoint(page.Continuation.NextCheckpoint)
	}
	if pages != 64 {
		t.Fatalf("production zero-match pages = %d, want 64 independently bounded units from one validated occurrence hydration", pages)
	}
}

func TestDocumentationDerivationChargesExactMatcherInputBytesBeforeRegexp(t *testing.T) {
	body := []byte(strings.Repeat("x", 80))
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 0, 1)
	object := decodeDocumentationProgramObject(t, raw)
	object["max_parse_bytes"] = json.Number("10")
	rule := documentationProgramRuleObject(t, object, 0)
	rule["pattern"] = `z{1}`
	rule["maximum_match_bytes"] = json.Number("1")
	rule["output_fields"] = map[string]interface{}{"assertion": "absent"}
	rule["exact_output_field_names"] = []interface{}{"assertion"}

	for name, limits := range map[string][2]string{
		"per input unit": {"5", "100"},
		"per run":        {"20", "25"},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := decodeDocumentationProgramObject(t, encodeDocumentationProgramObject(t, object, &reference))
			candidate["max_matcher_input_bytes_per_input_unit"] = json.Number(limits[0])
			candidate["max_matcher_input_bytes_per_run"] = json.Number(limits[1])
			canonical := encodeDocumentationProgramObject(t, candidate, &reference)
			program, err := parseExactDocumentationDerivationProgram(canonical, reference)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies); err == nil || !strings.Contains(err.Error(), "max_matcher_input_bytes_per_") {
				t.Fatalf("error = %v, want matcher input-byte refusal before regexp evaluation", err)
			}
		})
	}
}

func TestDocumentationDerivationChargesLineAnchorSearchAgainstMatcherInputBudget(t *testing.T) {
	body := []byte("abc" + strings.Repeat("x", 77))
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	object := decodeDocumentationProgramObject(t, raw)
	object["max_parse_bytes"] = json.Number(strconv.Itoa(len(body)))
	object["max_matcher_input_bytes_per_input_unit"] = json.Number("16")
	object["max_matcher_input_bytes_per_run"] = json.Number("16")
	rule := documentationProgramRuleObject(t, object, 0)
	rule["pattern"] = `(?m)^(?P<field_name>a)(?P<provider_type>b)(?P<provider_requirement>c)`
	rule["maximum_match_bytes"] = json.Number("3")
	canonical := encodeDocumentationProgramObject(t, object, &reference)
	program, err := parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies); err == nil || !strings.Contains(err.Error(), "before matcher scan") {
		t.Fatalf("error = %v, want line-anchor search refusal before its uncharged input scan", err)
	}
}

func decodeDocumentationProgramObject(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	var object map[string]interface{}
	if err := decodeOneValidationProfileJSON(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func documentationProgramRuleObject(t *testing.T, object map[string]interface{}, index int) map[string]interface{} {
	t.Helper()
	rules, ok := object["ordered_rules"].([]interface{})
	if !ok || index < 0 || index >= len(rules) {
		t.Fatal("program fixture has no requested rule")
	}
	rule, ok := rules[index].(map[string]interface{})
	if !ok {
		t.Fatal("program fixture rule is not an object")
	}
	return rule
}

func encodeDocumentationProgramObject(t *testing.T, object map[string]interface{}, reference *dependencyProfileReference) []byte {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	reference.digest = sha256Hex(canonical)
	return canonical
}
