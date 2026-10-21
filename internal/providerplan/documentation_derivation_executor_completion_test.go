package providerplan

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestDocumentationDerivationCompletionProgramParseRejectsMalformedAndNoncanonicalShapes(t *testing.T) {
	validRaw, reference, _, _ := exactDocumentationProgramFixture(t, []byte("| amount | Decimal | Required |\n"), 1, 1)
	if _, err := parseExactDocumentationDerivationProgram(nil, reference); err == nil || !strings.Contains(err.Error(), "byte count") {
		t.Fatalf("empty program error = %v, want byte-bound refusal", err)
	}
	if _, err := parseExactDocumentationDerivationProgram(json.RawMessage("{"), reference); err == nil || !strings.Contains(err.Error(), "canonicalize") {
		t.Fatalf("malformed program error = %v, want canonicalization refusal", err)
	}
	nonInteger := json.RawMessage(strings.Replace(string(validRaw), `"max_parse_bytes":512`, `"max_parse_bytes":512.5`, 1))
	canonical, err := canonicalizeCandidateJSON(nonInteger)
	if err != nil {
		t.Fatal(err)
	}
	reference.digest = sha256Hex(canonical)
	if _, err := parseExactDocumentationDerivationProgram(canonical, reference); err == nil || !strings.Contains(err.Error(), "binary-float") {
		t.Fatalf("fractional budget error = %v, want binary-float refusal", err)
	}
	unsupported := json.RawMessage(strings.Replace(string(validRaw), exactDocumentationDerivationProgramKind, "other_program", 1))
	canonical, err = canonicalizeCandidateJSON(unsupported)
	if err != nil {
		t.Fatal(err)
	}
	reference.digest = sha256Hex(canonical)
	if _, err := parseExactDocumentationDerivationProgram(canonical, reference); err == nil || !strings.Contains(err.Error(), "unsupported kind") {
		t.Fatalf("unsupported kind error = %v, want kind refusal", err)
	}
	var object map[string]interface{}
	if err := json.Unmarshal(validRaw, &object); err != nil {
		t.Fatal(err)
	}
	object["input_source_symbols"] = []interface{}{}
	mutated, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err = canonicalizeCandidateJSON(mutated)
	if err != nil {
		t.Fatal(err)
	}
	reference.digest = sha256Hex(canonical)
	if _, err := parseExactDocumentationDerivationProgram(canonical, reference); err == nil || !strings.Contains(err.Error(), "strict canonical roster") {
		t.Fatalf("empty source roster error = %v, want refusal", err)
	}
}

func TestDocumentationDerivationCompletionCaptureWidthAnalysisRejectsUnsafePatterns(t *testing.T) {
	widths, err := documentationNamedCaptureMaximumUTF8Widths(`(?P<field>[a-z]{1,4})-(?P<kind>[0-9]{2})`)
	if err != nil {
		t.Fatal(err)
	}
	if widths["field"] != 4 || widths["kind"] != 2 {
		t.Fatalf("widths = %#v, want finite named capture widths", widths)
	}
	for _, pattern := range []string{`(?P<field>.*)`, `(?P<field>a)(?P<field>b)`} {
		if _, err := documentationNamedCaptureMaximumUTF8Widths(pattern); err == nil {
			t.Fatalf("pattern %q was accepted despite unsafe named capture semantics", pattern)
		}
	}
}

func TestDocumentationDerivationCompletionPointerAndTargetCoordinateValidation(t *testing.T) {
	if err := validateExactDocumentationTargetBinding(exactDocumentationTargetWholeRow, ""); err != nil {
		t.Fatalf("whole-row target binding rejected: %v", err)
	}
	if err := validateExactDocumentationTargetBinding(exactDocumentationTargetRowMember, "/properties/name"); err != nil {
		t.Fatalf("row-member target binding rejected: %v", err)
	}
	if err := validateExactDocumentationTargetBinding("unknown", ""); err == nil || !strings.Contains(err.Error(), "closed structural set") {
		t.Fatalf("unknown target binding error = %v, want refusal", err)
	}
	tokens, err := exactDocumentationJSONPointerTokens(`/properties/a~1b~0c`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(tokens, ","), "properties,a/b~c"; got != want {
		t.Fatalf("decoded pointer tokens = %q, want %q", got, want)
	}
	if _, err := exactDocumentationJSONPointerTokens(`/properties/a~2b`); err == nil || !strings.Contains(err.Error(), "noncanonical") {
		t.Fatalf("noncanonical pointer error = %v, want refusal", err)
	}
	captures := map[string]struct{}{"field": {}}
	for _, test := range []struct {
		name string
		rule exactDocumentationDerivationRule
		want string
	}{
		{name: "whole row carries selectors", rule: exactDocumentationDerivationRule{RuleID: "rule", TargetBindingKind: exactDocumentationTargetWholeRow, TargetRowSelector: []exactDocumentationTargetRowSelectorTemplate{{TargetRowJSONPointer: "/field", ExpectedStringTemplate: "literal"}}}, want: "whole_row requires"},
		{name: "row member lacks identity", rule: exactDocumentationDerivationRule{RuleID: "rule", TargetBindingKind: exactDocumentationTargetRowMember, TargetMemberJSONPointer: "/value", TargetRowSelector: []exactDocumentationTargetRowSelectorTemplate{{TargetRowJSONPointer: "/key", ExpectedStringTemplate: "literal"}}}, want: "requires nonempty"},
		{name: "overlapping selector", rule: exactDocumentationDerivationRule{RuleID: "rule", TargetBindingKind: exactDocumentationTargetRowMember, TargetMemberJSONPointer: "/key/value", TargetRowSelector: []exactDocumentationTargetRowSelectorTemplate{{TargetRowJSONPointer: "/key", ExpectedStringTemplate: "literal"}}, TargetMemberIdentityJSONPointers: []string{"/value"}}, want: "overlaps target"},
		{name: "unknown selector capture", rule: exactDocumentationDerivationRule{RuleID: "rule", TargetBindingKind: exactDocumentationTargetRowMember, TargetMemberJSONPointer: "/value", TargetRowSelector: []exactDocumentationTargetRowSelectorTemplate{{TargetRowJSONPointer: "/key", ExpectedStringTemplate: "${missing}"}}, TargetMemberIdentityJSONPointers: []string{"/value"}}, want: "unknown capture"},
		{name: "optional rule capture selector", rule: exactDocumentationDerivationRule{RuleID: "rule", TargetBindingKind: exactDocumentationTargetRowMember, TargetMemberJSONPointer: "/value", MinimumMatches: 0, TargetRowSelector: []exactDocumentationTargetRowSelectorTemplate{{TargetRowJSONPointer: "/key", ExpectedStringTemplate: "${field}"}}, TargetMemberIdentityJSONPointers: []string{"/value"}}, want: "literal-only"},
		{name: "reserved identity", rule: exactDocumentationDerivationRule{RuleID: "rule", TargetBindingKind: exactDocumentationTargetRowMember, TargetMemberJSONPointer: "/value", TargetRowSelector: []exactDocumentationTargetRowSelectorTemplate{{TargetRowJSONPointer: "/key", ExpectedStringTemplate: "literal"}}, TargetMemberIdentityJSONPointers: []string{"/source_ref"}}, want: "executor-owned"},
		{name: "unsupported binding", rule: exactDocumentationDerivationRule{RuleID: "rule", TargetBindingKind: "other"}, want: "unsupported"},
	} {
		t.Run(test.name, func(t *testing.T) {
			used := map[string]struct{}{}
			err := validateExactDocumentationRuleTargetCoordinates(test.rule, captures, used)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDocumentationDerivationCompletionRuleCaptureValidationRejectsClosedSetViolations(t *testing.T) {
	compiled := regexp.MustCompile(`(?P<field>[a-z]{1,4})`)
	base := exactDocumentationDerivationRule{
		RuleID: "rule", OutputFields: map[string]interface{}{"field": "${field}"}, ExactOutputFieldNames: []string{"field"},
		TargetBindingKind: exactDocumentationTargetWholeRow, captureMaximumUTF8Bytes: map[string]int64{"field": 4},
	}
	if err := validateDocumentationDerivationRuleCaptures(&base, compiled); err != nil {
		t.Fatalf("valid closed capture rule rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*exactDocumentationDerivationRule)
		want   string
	}{
		{name: "empty roster", mutate: func(rule *exactDocumentationDerivationRule) { rule.ExactOutputFieldNames = nil }, want: "canonical output field roster"},
		{name: "mismatched roster", mutate: func(rule *exactDocumentationDerivationRule) { rule.ExactOutputFieldNames = []string{"other"} }, want: "output fields"},
		{name: "unknown output capture", mutate: func(rule *exactDocumentationDerivationRule) { rule.OutputFields["field"] = "${missing}" }, want: "unknown capture"},
		{name: "malformed template", mutate: func(rule *exactDocumentationDerivationRule) { rule.OutputFields["field"] = "${field" }, want: "malformed capture"},
		{name: "unsupported exact property", mutate: func(rule *exactDocumentationDerivationRule) {
			rule.OutputFields["field"] = map[string]interface{}{documentationExactMatchPropertyKey: "other"}
		}, want: "outside the closed set"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rule := base
			rule.OutputFields = map[string]interface{}{"field": "${field}"}
			rule.ExactOutputFieldNames = []string{"field"}
			test.mutate(&rule)
			if err := validateDocumentationDerivationRuleCaptures(&rule, compiled); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDocumentationDerivationCompletionResolvesBoundedTemplatesAndPointers(t *testing.T) {
	sha := strings.Repeat("a", 64)
	budget := &documentationTemplateExpansionBudget{remaining: 256}
	resolved, err := resolveDocumentationOutputTemplate(map[string]interface{}{
		"name":   "prefix-${field}",
		"digest": map[string]interface{}{documentationExactMatchPropertyKey: documentationExactMatchPropertySHA256},
		"bytes":  map[string]interface{}{documentationExactMatchPropertyKey: documentationExactMatchPropertyByteCount},
		"nested": []interface{}{map[string]interface{}{"kind": "literal"}},
	}, map[string]string{"field": "amount"}, documentationExactMatchProperties{selectedRangeSHA256: sha, selectedRangeByteCount: 6}, budget)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := resolved["name"], "prefix-amount"; got != want {
		t.Fatalf("resolved name = %#v, want %#v", got, want)
	}
	if got, want := resolved["digest"], sha; got != want {
		t.Fatalf("resolved digest = %#v, want %#v", got, want)
	}
	if got, err := exactDocumentationStringAtJSONPointer(resolved, "/name"); err != nil || got != "prefix-amount" {
		t.Fatalf("resolved pointer = %q, %v", got, err)
	}
	for _, pointer := range []string{"/missing", "/nested/kind", "/bytes"} {
		if _, err := exactDocumentationStringAtJSONPointer(resolved, pointer); err == nil {
			t.Fatalf("pointer %q unexpectedly resolved to a required string", pointer)
		}
	}
	if _, err := resolveDocumentationTemplateStringBounded("${missing}", map[string]string{}, &documentationTemplateExpansionBudget{remaining: 16}); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing capture error = %v, want refusal", err)
	}
	if _, err := resolveDocumentationTemplateStringBounded("abcdef", map[string]string{}, &documentationTemplateExpansionBudget{remaining: 1}); err == nil || !strings.Contains(err.Error(), "preallocation") {
		t.Fatalf("budget error = %v, want refusal", err)
	}
}

func TestDocumentationDerivationCompletionRejectsAbsentRegexCapture(t *testing.T) {
	compiled := regexp.MustCompile(`(?P<required>a)?`)
	match := compiled.FindSubmatchIndex([]byte(""))
	if _, err := exactDocumentationMatchCaptures(compiled, []byte(""), match); err == nil || !strings.Contains(err.Error(), "did not participate") {
		t.Fatalf("absent capture error = %v, want refusal", err)
	}
}

func TestDocumentationDerivationCompletionFailsClosedOnImpossibleOutputShapes(t *testing.T) {
	budget := &documentationTemplateExpansionBudget{remaining: 1}
	if err := budget.consume(-1); err == nil || !strings.Contains(err.Error(), "preallocation") {
		t.Fatalf("negative budget consumption error = %v, want refusal", err)
	}
	if _, err := resolveDocumentationOutputTemplate(map[string]interface{}{}, map[string]string{}, documentationExactMatchProperties{}, &documentationTemplateExpansionBudget{remaining: 1}); err == nil || !strings.Contains(err.Error(), "nonempty object") {
		t.Fatalf("empty output error = %v, want refusal", err)
	}
	if _, err := resolveDocumentationTemplateValue(1.5, 0, map[string]string{}, documentationExactMatchProperties{}, &documentationTemplateExpansionBudget{remaining: 1}); err == nil || !strings.Contains(err.Error(), "unsupported value type") {
		t.Fatalf("unsupported value error = %v, want refusal", err)
	}
	if _, err := resolveDocumentationTemplateValue(map[string]interface{}{documentationExactMatchPropertyKey: documentationExactMatchPropertySHA256}, 0, map[string]string{}, documentationExactMatchProperties{}, &documentationTemplateExpansionBudget{remaining: 100}); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing exact-match digest error = %v, want refusal", err)
	}
	if _, ok := documentationExactMatchPropertyOperand(map[string]interface{}{documentationExactMatchPropertyKey: documentationExactMatchPropertySHA256, "extra": "forbidden"}); ok {
		t.Fatal("non-exact exact-match operand was accepted")
	}
}
