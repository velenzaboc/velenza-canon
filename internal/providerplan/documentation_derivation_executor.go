package providerplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
)

const (
	exactDocumentationDerivationProgramKind  = "exact_documentation_derivation_program_v1"
	exactDocumentationDerivationEncodingUTF8 = "utf8_strict"
	exactDocumentationTargetWholeRow         = "whole_row"
	exactDocumentationTargetRowMember        = "row_member"
	maxDocumentationDerivationRules          = 4096
	maxDocumentationFactsPerOccurrence       = 65536
	maxDocumentationDerivationProgramBytes   = 64 << 20
	maxDocumentationDerivationPatternBytes   = 64 << 10
	maxDocumentationDerivationCaptures       = 256
	maxDocumentationDerivationOutputFields   = 256
	maxDocumentationDerivationTemplateDepth  = 64
	// These are emergency shape ceilings for one independently resumable work
	// unit or output page. The content-addressed program supplies the smaller
	// positive run-pinned budgets; none of these bounds the total corpus.
	maxDocumentationParseBytesPerUnit           = int64(64 << 20)
	maxDocumentationFactsPerOutputPage          = int64(65536)
	maxDocumentationBytesPerOutputPage          = int64(64 << 20)
	maxDocumentationBytesPerOutputFact          = int64(8 << 20)
	maxDocumentationFactsPerRun                 = int64(1 << 20)
	maxDocumentationBytesPerRun                 = int64(1 << 30)
	maxDocumentationPagesPerRun                 = int64(1 << 20)
	maxDocumentationMatcherEvaluations          = int64(1 << 24)
	maxDocumentationMatcherEvaluationsPerRun    = int64(1 << 28)
	maxDocumentationMatcherInputBytesPerUnit    = int64(1 << 28)
	maxDocumentationMatcherInputBytesPerRun     = int64(1 << 32)
	maxDocumentationOccurrenceOutcomesPerRun    = int64(1 << 20)
	maxDocumentationCanonicalOutcomeBytesPerRun = int64(1 << 30)
)

var documentationTemplateCapturePattern = regexp.MustCompile(`\$\{([a-z][a-z0-9]*(?:_[a-z0-9]+)*)\}`)

const (
	documentationExactMatchPropertyKey       = "$exact_match_property"
	documentationExactMatchPropertySHA256    = "selected_range_sha256"
	documentationExactMatchPropertyByteCount = "selected_range_byte_count"
)

// exactDocumentationDerivationProgram is a provider-neutral deterministic
// extractor program. Provider vocabulary belongs in admitted program data;
// this executor only matches exact selected bytes and substitutes exact named
// captures into a closed JSON output template.
type exactDocumentationDerivationProgram struct {
	ProgramKind                       string                             `json:"program_kind"`
	InputEncoding                     string                             `json:"input_encoding"`
	MaxParseBytes                     int64                              `json:"max_parse_bytes"`
	MaxOutputBytesPerFact             int64                              `json:"max_output_bytes_per_fact"`
	MaxOutputFactsPerPage             int64                              `json:"max_output_facts_per_page"`
	MaxOutputBytesPerPage             int64                              `json:"max_output_bytes_per_page"`
	MaxOutputFactsPerRun              int64                              `json:"max_output_facts_per_run"`
	MaxOutputBytesPerRun              int64                              `json:"max_output_bytes_per_run"`
	MaxOutputPagesPerRun              int64                              `json:"max_output_pages_per_run"`
	MaxMatcherEvaluationsPerInputUnit int64                              `json:"max_matcher_evaluations_per_input_unit"`
	MaxMatcherEvaluationsPerRun       int64                              `json:"max_matcher_evaluations_per_run"`
	MaxMatcherInputBytesPerInputUnit  int64                              `json:"max_matcher_input_bytes_per_input_unit"`
	MaxMatcherInputBytesPerRun        int64                              `json:"max_matcher_input_bytes_per_run"`
	MaxOccurrenceOutcomesPerRun       int64                              `json:"max_occurrence_outcomes_per_run"`
	MaxCanonicalOutcomeBytesPerRun    int64                              `json:"max_canonical_outcome_bytes_per_run"`
	InputSourceSymbols                []string                           `json:"input_source_symbols"`
	OrderedRules                      []exactDocumentationDerivationRule `json:"ordered_rules"`
}

type exactDocumentationTargetRowSelectorTemplate struct {
	TargetRowJSONPointer   string `json:"target_row_json_pointer"`
	ExpectedStringTemplate string `json:"expected_string_template"`
}

type exactDocumentationResolvedTargetRowSelector struct {
	TargetRowJSONPointer string `json:"target_row_json_pointer"`
	ExpectedString       string `json:"expected_string"`
}

type exactDocumentationResolvedMemberIdentity struct {
	OutputJSONPointer string `json:"output_json_pointer"`
	ExpectedString    string `json:"expected_string"`
}

type exactDocumentationDerivationRule struct {
	Ordinal                          int64                                         `json:"ordinal"`
	RuleID                           string                                        `json:"rule_id"`
	InputSourceSymbol                string                                        `json:"input_source_symbol"`
	TargetArtifactRole               string                                        `json:"target_artifact_role"`
	TargetRowKind                    string                                        `json:"target_row_kind"`
	TargetBindingKind                string                                        `json:"target_binding_kind"`
	TargetMemberJSONPointer          string                                        `json:"target_member_json_pointer"`
	TargetRowSelector                []exactDocumentationTargetRowSelectorTemplate `json:"target_row_selector"`
	TargetMemberIdentityJSONPointers []string                                      `json:"target_member_identity_json_pointers"`
	Pattern                          string                                        `json:"pattern"`
	MaximumMatchBytes                int64                                         `json:"maximum_match_bytes"`
	MinimumMatches                   int64                                         `json:"minimum_matches_per_occurrence"`
	MaximumMatches                   int64                                         `json:"maximum_matches_per_occurrence"`
	OutputFields                     map[string]interface{}                        `json:"output_fields"`
	ExactOutputFieldNames            []string                                      `json:"exact_output_field_names"`

	maximumCanonicalOutputBytes int64
	captureMaximumUTF8Bytes     map[string]int64
}

type exactDocumentationDerivedFact struct {
	FactID                     string
	Profile                    dependencyProfileReference
	Provider                   string
	EvidenceRosterSHA256       string
	ClassificationBinding      classificationArtifactBinding
	ClassificationRole         string
	RuleID                     string
	TargetArtifactRole         string
	TargetRowKind              string
	TargetBindingKind          string
	TargetMemberJSONPointer    string
	TargetRowSelector          []exactDocumentationResolvedTargetRowSelector
	TargetRowSelectorSHA256    string
	TargetMemberIdentity       []exactDocumentationResolvedMemberIdentity
	TargetMemberIdentitySHA256 string
	InputSourceSymbol          string
	PredecessorLocatorID       string
	EvidenceLocatorID          string
	EvidenceLocator            evidenceLocator
	MatchOrdinal               int64
	ByteStartOffset            int64
	ByteEndOffsetExclusive     int64
	SelectedMatchSHA256        string
	ExactOutputFieldNames      []string
	CanonicalOutputFields      []byte
}

func parseExactDocumentationDerivationProgram(raw json.RawMessage, reference dependencyProfileReference) (exactDocumentationDerivationProgram, error) {
	var program exactDocumentationDerivationProgram
	if len(raw) == 0 || len(raw) > maxDocumentationDerivationProgramBytes {
		return program, fmt.Errorf("documentation derivation program byte count %d is outside the closed execution bound", len(raw))
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		return program, fmt.Errorf("canonicalize documentation derivation program: %w", err)
	}
	if !isLowerSHA256(reference.digest) || sha256Hex(canonical) != reference.digest {
		return program, fmt.Errorf("documentation derivation profile digest does not equal the RFC-canonical executable program bytes")
	}
	if err := rejectNonIntegerNumbers(canonical); err != nil {
		return program, fmt.Errorf("documentation derivation program: %w", err)
	}
	if err := strictUnmarshal(canonical, &program); err != nil {
		return program, fmt.Errorf("decode documentation derivation program: %w", err)
	}
	if program.ProgramKind != exactDocumentationDerivationProgramKind || program.InputEncoding != exactDocumentationDerivationEncodingUTF8 {
		return program, fmt.Errorf("documentation derivation program has an unsupported kind or input encoding")
	}
	if program.MaxParseBytes <= 0 || program.MaxParseBytes > maxDocumentationParseBytesPerUnit ||
		program.MaxOutputBytesPerFact <= 0 || program.MaxOutputBytesPerFact > maxDocumentationBytesPerOutputFact || program.MaxOutputBytesPerFact > program.MaxOutputBytesPerPage ||
		program.MaxOutputFactsPerPage <= 0 || program.MaxOutputFactsPerPage > maxDocumentationFactsPerOutputPage ||
		program.MaxOutputBytesPerPage <= 0 || program.MaxOutputBytesPerPage > maxDocumentationBytesPerOutputPage ||
		program.MaxOutputFactsPerRun <= 0 || program.MaxOutputFactsPerRun > maxDocumentationFactsPerRun || program.MaxOutputFactsPerRun < program.MaxOutputFactsPerPage ||
		program.MaxOutputBytesPerRun <= 0 || program.MaxOutputBytesPerRun > maxDocumentationBytesPerRun || program.MaxOutputBytesPerRun < program.MaxOutputBytesPerPage ||
		program.MaxOutputPagesPerRun <= 0 || program.MaxOutputPagesPerRun > maxDocumentationPagesPerRun ||
		program.MaxMatcherEvaluationsPerInputUnit <= 0 || program.MaxMatcherEvaluationsPerInputUnit > maxDocumentationMatcherEvaluations ||
		program.MaxMatcherEvaluationsPerRun <= 0 || program.MaxMatcherEvaluationsPerRun > maxDocumentationMatcherEvaluationsPerRun || program.MaxMatcherEvaluationsPerRun < program.MaxMatcherEvaluationsPerInputUnit ||
		program.MaxMatcherInputBytesPerInputUnit <= 0 || program.MaxMatcherInputBytesPerInputUnit > maxDocumentationMatcherInputBytesPerUnit ||
		program.MaxMatcherInputBytesPerRun <= 0 || program.MaxMatcherInputBytesPerRun > maxDocumentationMatcherInputBytesPerRun || program.MaxMatcherInputBytesPerRun < program.MaxMatcherInputBytesPerInputUnit ||
		program.MaxOccurrenceOutcomesPerRun <= 0 || program.MaxOccurrenceOutcomesPerRun > maxDocumentationOccurrenceOutcomesPerRun ||
		program.MaxCanonicalOutcomeBytesPerRun <= 0 || program.MaxCanonicalOutcomeBytesPerRun > maxDocumentationCanonicalOutcomeBytesPerRun {
		return program, fmt.Errorf("documentation derivation program has invalid run-pinned work-unit or output-page budgets")
	}
	if len(program.InputSourceSymbols) == 0 || hasEmptyOrDuplicateSemanticStrings(program.InputSourceSymbols) || !sort.StringsAreSorted(program.InputSourceSymbols) {
		return program, fmt.Errorf("documentation derivation program input_source_symbols is not a nonempty strict canonical roster")
	}
	if len(program.OrderedRules) == 0 || len(program.OrderedRules) > maxDocumentationDerivationRules {
		return program, fmt.Errorf("documentation derivation program has %d rules outside the closed execution bound", len(program.OrderedRules))
	}
	declaredSources := stringSet(program.InputSourceSymbols)
	usedSources := map[string]struct{}{}
	seenRuleIDs := map[string]struct{}{}
	for index, rule := range program.OrderedRules {
		if rule.Ordinal != int64(index) {
			return program, fmt.Errorf("documentation derivation rule %d ordinal %d is not contiguous", index, rule.Ordinal)
		}
		if !canonicalSurfaceKindPattern.MatchString(rule.RuleID) || !canonicalEvidenceMetadataString(rule.InputSourceSymbol, 512) || !canonicalSurfaceKindPattern.MatchString(rule.TargetArtifactRole) || !canonicalSurfaceKindPattern.MatchString(rule.TargetRowKind) {
			return program, fmt.Errorf("documentation derivation rule %d has an invalid identity or target coordinate", index)
		}
		if err := validateExactDocumentationTargetBinding(rule.TargetBindingKind, rule.TargetMemberJSONPointer); err != nil {
			return program, fmt.Errorf("documentation derivation rule %q target binding: %w", rule.RuleID, err)
		}
		if _, exists := declaredSources[rule.InputSourceSymbol]; !exists {
			return program, fmt.Errorf("documentation derivation rule %q uses undeclared input source_symbol %q", rule.RuleID, rule.InputSourceSymbol)
		}
		if _, duplicate := seenRuleIDs[rule.RuleID]; duplicate {
			return program, fmt.Errorf("documentation derivation program duplicates rule_id %q", rule.RuleID)
		}
		seenRuleIDs[rule.RuleID] = struct{}{}
		usedSources[rule.InputSourceSymbol] = struct{}{}
		if rule.MinimumMatches < 0 || rule.MaximumMatches < 1 || rule.MinimumMatches > rule.MaximumMatches || rule.MaximumMatches > maxDocumentationFactsPerOccurrence {
			return program, fmt.Errorf("documentation derivation rule %q has invalid per-occurrence cardinality [%d,%d]", rule.RuleID, rule.MinimumMatches, rule.MaximumMatches)
		}
		if len(rule.Pattern) == 0 || len(rule.Pattern) > maxDocumentationDerivationPatternBytes {
			return program, fmt.Errorf("documentation derivation rule %q pattern byte count %d is outside the closed execution bound", rule.RuleID, len(rule.Pattern))
		}
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return program, fmt.Errorf("documentation derivation rule %q pattern: %w", rule.RuleID, err)
		}
		if compiled.MatchString("") {
			return program, fmt.Errorf("documentation derivation rule %q pattern matches an empty input", rule.RuleID)
		}
		if compiled.NumSubexp() > maxDocumentationDerivationCaptures {
			return program, fmt.Errorf("documentation derivation rule %q capture count %d exceeds the closed execution bound", rule.RuleID, compiled.NumSubexp())
		}
		analysis, err := analyzeFiniteDocumentationPattern(rule.Pattern)
		if err != nil {
			return program, fmt.Errorf("documentation derivation rule %q pattern is not page-safe: %w", rule.RuleID, err)
		}
		if rule.MaximumMatchBytes <= 0 || rule.MaximumMatchBytes < analysis.MaximumUTF8Bytes || rule.MaximumMatchBytes > program.MaxParseBytes {
			return program, fmt.Errorf("documentation derivation rule %q maximum_match_bytes %d does not cover computed finite UTF-8 width %d within max_parse_bytes %d", rule.RuleID, rule.MaximumMatchBytes, analysis.MaximumUTF8Bytes, program.MaxParseBytes)
		}
		captureWidths, err := documentationNamedCaptureMaximumUTF8Widths(rule.Pattern)
		if err != nil {
			return program, fmt.Errorf("documentation derivation rule %q capture widths: %w", rule.RuleID, err)
		}
		program.OrderedRules[index].captureMaximumUTF8Bytes = captureWidths
		if err := validateDocumentationDerivationRuleCaptures(&program.OrderedRules[index], compiled); err != nil {
			return program, err
		}
		if program.OrderedRules[index].maximumCanonicalOutputBytes > program.MaxOutputBytesPerFact {
			return program, fmt.Errorf("documentation derivation rule %q conservative canonical output expansion bound %d exceeds max_output_bytes_per_fact %d", rule.RuleID, program.OrderedRules[index].maximumCanonicalOutputBytes, program.MaxOutputBytesPerFact)
		}
	}
	if int64(len(program.OrderedRules)) > program.MaxMatcherEvaluationsPerInputUnit {
		return program, fmt.Errorf("documentation derivation program matcher evaluation budget cannot evaluate every rule once per input unit")
	}
	if err := requireExactSet("documentation derivation program source-symbol coverage", usedSources, declaredSources); err != nil {
		return program, err
	}
	return program, nil
}

func documentationNamedCaptureMaximumUTF8Widths(pattern string) (map[string]int64, error) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, err
	}
	result := map[string]int64{}
	var walk func(*syntax.Regexp) error
	walk = func(expression *syntax.Regexp) error {
		if expression.Op == syntax.OpCapture && expression.Name != "" {
			width, bounded := maximumRegexpUTF8Width(expression.Sub[0])
			if !bounded {
				return fmt.Errorf("named capture %q has unbounded UTF-8 width", expression.Name)
			}
			if _, duplicate := result[expression.Name]; duplicate {
				return fmt.Errorf("duplicate named capture %q", expression.Name)
			}
			result[expression.Name] = width
		}
		for _, child := range expression.Sub {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(parsed); err != nil {
		return nil, err
	}
	return result, nil
}

func validateExactDocumentationTargetBinding(kind, pointer string) error {
	switch kind {
	case exactDocumentationTargetWholeRow:
		if pointer != "" {
			return fmt.Errorf("whole_row requires an empty target_member_json_pointer")
		}
		return nil
	case exactDocumentationTargetRowMember:
		return validateExactDocumentationJSONPointer(pointer, "row_member target_member_json_pointer")
	default:
		return fmt.Errorf("target_binding_kind %q is outside the closed structural set", kind)
	}
}

func validateExactDocumentationJSONPointer(pointer, name string) error {
	if pointer == "" || pointer[0] != '/' {
		return fmt.Errorf("%s requires a nonempty canonical RFC6901 property path", name)
	}
	for _, token := range strings.Split(pointer[1:], "/") {
		if token == "" {
			return fmt.Errorf("%s has an empty property token", name)
		}
	}
	for index := 0; index < len(pointer); index++ {
		if pointer[index] != '~' {
			continue
		}
		if index+1 >= len(pointer) || (pointer[index+1] != '0' && pointer[index+1] != '1') {
			return fmt.Errorf("%s has a noncanonical RFC6901 escape", name)
		}
		index++
	}
	return nil
}

func exactDocumentationJSONPointerTokens(pointer string) ([]string, error) {
	if err := validateExactDocumentationJSONPointer(pointer, "JSON pointer"); err != nil {
		return nil, err
	}
	encoded := strings.Split(pointer[1:], "/")
	result := make([]string, len(encoded))
	for index, token := range encoded {
		token = strings.ReplaceAll(token, "~1", "/")
		token = strings.ReplaceAll(token, "~0", "~")
		result[index] = token
	}
	return result, nil
}

func exactDocumentationPointersOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func exactDocumentationDerivedFactID(fact exactDocumentationDerivedFact) string {
	return stableID("docfact", lengthPrefixedIdentityKey(
		fact.Profile.id, fact.Profile.version, fact.Profile.digest,
		fact.Provider, fact.EvidenceRosterSHA256,
		fact.ClassificationBinding.ArtifactID, fact.ClassificationBinding.ArtifactVersion, fact.ClassificationBinding.ArtifactSHA256,
		fact.ClassificationRole,
		fact.RuleID, fact.TargetArtifactRole, fact.TargetRowKind,
		fact.TargetBindingKind, fact.TargetMemberJSONPointer, fact.TargetRowSelectorSHA256, fact.TargetMemberIdentitySHA256,
		fact.InputSourceSymbol, fact.PredecessorLocatorID, fact.EvidenceLocatorID, fmt.Sprint(fact.MatchOrdinal),
		fact.EvidenceLocator.RowKind,
		fmt.Sprint(fact.ByteStartOffset), fmt.Sprint(fact.ByteEndOffsetExclusive), fact.SelectedMatchSHA256, sha256Hex(fact.CanonicalOutputFields),
	))
}

func validateExactDocumentationDerivedFactTargetIdentity(fact exactDocumentationDerivedFact) error {
	if err := validateExactDocumentationTargetBinding(fact.TargetBindingKind, fact.TargetMemberJSONPointer); err != nil {
		return err
	}
	if err := validateExactDocumentationResolvedTargetCoordinates(fact); err != nil {
		return err
	}
	if fact.FactID != exactDocumentationDerivedFactID(fact) {
		return fmt.Errorf("fact ID is not content-derived from the exact target binding coordinate")
	}
	return nil
}

func validateDocumentationDerivationRuleCaptures(rule *exactDocumentationDerivationRule, compiled *regexp.Regexp) error {
	if len(rule.OutputFields) == 0 || len(rule.OutputFields) > maxDocumentationDerivationOutputFields || len(rule.ExactOutputFieldNames) == 0 || len(rule.ExactOutputFieldNames) > maxDocumentationDerivationOutputFields || hasEmptyOrDuplicateSemanticStrings(rule.ExactOutputFieldNames) || !sort.StringsAreSorted(rule.ExactOutputFieldNames) {
		return fmt.Errorf("documentation derivation rule %q has no closed canonical output field roster", rule.RuleID)
	}
	if err := requireExactSet("documentation derivation rule "+rule.RuleID+" output fields", stringMapKeysAsSet(rule.OutputFields), stringSet(rule.ExactOutputFieldNames)); err != nil {
		return err
	}
	captureNames := map[string]struct{}{}
	for index, name := range compiled.SubexpNames() {
		if index == 0 || name == "" {
			continue
		}
		if !canonicalSurfaceKindPattern.MatchString(name) {
			return fmt.Errorf("documentation derivation rule %q has invalid capture name %q", rule.RuleID, name)
		}
		if _, duplicate := captureNames[name]; duplicate {
			return fmt.Errorf("documentation derivation rule %q duplicates capture name %q", rule.RuleID, name)
		}
		captureNames[name] = struct{}{}
	}
	usedCaptures := map[string]struct{}{}
	if err := walkDocumentationTemplateCaptures(rule.OutputFields, 0, func(name string) error {
		if _, exists := captureNames[name]; !exists {
			return fmt.Errorf("documentation derivation rule %q output references unknown capture %q", rule.RuleID, name)
		}
		usedCaptures[name] = struct{}{}
		return nil
	}); err != nil {
		return err
	}
	if err := validateDocumentationExactMatchPropertyOperands(rule.OutputFields, 0); err != nil {
		return fmt.Errorf("documentation derivation rule %q output fields: %w", rule.RuleID, err)
	}
	if err := validateExactDocumentationRuleTargetCoordinates(*rule, captureNames, usedCaptures); err != nil {
		return err
	}
	if err := requireExactSet("documentation derivation rule "+rule.RuleID+" capture use", usedCaptures, captureNames); err != nil {
		return err
	}
	canonical, err := json.Marshal(rule.OutputFields)
	if err != nil {
		return fmt.Errorf("documentation derivation rule %q output fields: %w", rule.RuleID, err)
	}
	if err := rejectNonIntegerNumbers(canonical); err != nil {
		return fmt.Errorf("documentation derivation rule %q output fields: %w", rule.RuleID, err)
	}
	bound, err := conservativeDocumentationTemplateJSONExpansionBound(rule.OutputFields, rule.captureMaximumUTF8Bytes)
	if err != nil {
		return fmt.Errorf("documentation derivation rule %q output expansion bound: %w", rule.RuleID, err)
	}
	for _, selector := range rule.TargetRowSelector {
		selectorBound, err := conservativeDocumentationStringJSONExpansionBound(selector.ExpectedStringTemplate, rule.captureMaximumUTF8Bytes)
		if err != nil {
			return fmt.Errorf("documentation derivation rule %q selector expansion bound: %w", rule.RuleID, err)
		}
		if bound > math.MaxInt64-selectorBound {
			return fmt.Errorf("documentation derivation rule %q expansion bound overflows INT64", rule.RuleID)
		}
		bound += selectorBound
	}
	rule.maximumCanonicalOutputBytes = bound
	return nil
}

func validateExactDocumentationRuleTargetCoordinates(rule exactDocumentationDerivationRule, captureNames, usedCaptures map[string]struct{}) error {
	switch rule.TargetBindingKind {
	case exactDocumentationTargetWholeRow:
		if len(rule.TargetRowSelector) != 0 || len(rule.TargetMemberIdentityJSONPointers) != 0 {
			return fmt.Errorf("documentation derivation rule %q whole_row requires empty target_row_selector and target_member_identity_json_pointers", rule.RuleID)
		}
		return nil
	case exactDocumentationTargetRowMember:
		if len(rule.TargetRowSelector) == 0 || len(rule.TargetMemberIdentityJSONPointers) == 0 {
			return fmt.Errorf("documentation derivation rule %q row_member requires nonempty target_row_selector and target_member_identity_json_pointers", rule.RuleID)
		}
		prior := ""
		for index, selector := range rule.TargetRowSelector {
			if err := validateExactDocumentationJSONPointer(selector.TargetRowJSONPointer, "target_row_selector target_row_json_pointer"); err != nil {
				return fmt.Errorf("documentation derivation rule %q selector %d: %w", rule.RuleID, index, err)
			}
			if selector.TargetRowJSONPointer <= prior {
				return fmt.Errorf("documentation derivation rule %q target_row_selector is not strictly pointer-sorted and unique", rule.RuleID)
			}
			if exactDocumentationPointersOverlap(selector.TargetRowJSONPointer, rule.TargetMemberJSONPointer) {
				return fmt.Errorf("documentation derivation rule %q selector pointer %q overlaps target member pointer %q", rule.RuleID, selector.TargetRowJSONPointer, rule.TargetMemberJSONPointer)
			}
			matchedCapture := false
			if err := walkDocumentationTemplateCaptures(selector.ExpectedStringTemplate, 0, func(name string) error {
				if _, exists := captureNames[name]; !exists {
					return fmt.Errorf("documentation derivation rule %q selector references unknown capture %q", rule.RuleID, name)
				}
				matchedCapture = true
				usedCaptures[name] = struct{}{}
				return nil
			}); err != nil {
				return err
			}
			if rule.MinimumMatches == 0 && matchedCapture {
				return fmt.Errorf("documentation derivation rule %q with minimum_matches_per_occurrence=0 requires literal-only target_row_selector templates", rule.RuleID)
			}
			prior = selector.TargetRowJSONPointer
		}
		prior = ""
		for index, pointer := range rule.TargetMemberIdentityJSONPointers {
			if err := validateExactDocumentationJSONPointer(pointer, "target_member_identity_json_pointers member"); err != nil {
				return fmt.Errorf("documentation derivation rule %q member identity %d: %w", rule.RuleID, index, err)
			}
			if pointer <= prior {
				return fmt.Errorf("documentation derivation rule %q target_member_identity_json_pointers is not strictly sorted and unique", rule.RuleID)
			}
			tokens, _ := exactDocumentationJSONPointerTokens(pointer)
			if _, reserved := exactDocumentationDerivedRowEnvelopeFields[tokens[0]]; reserved {
				return fmt.Errorf("documentation derivation rule %q member identity pointer %q names executor-owned envelope field %q", rule.RuleID, pointer, tokens[0])
			}
			prior = pointer
		}
		return nil
	default:
		return fmt.Errorf("documentation derivation rule %q target binding kind is unsupported", rule.RuleID)
	}
}

func conservativeDocumentationTemplateJSONExpansionBound(value interface{}, captureWidths map[string]int64) (int64, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return 0, err
	}
	bound := int64(len(raw))
	err = walkDocumentationTemplateCaptures(value, 0, func(name string) error {
		width, exists := captureWidths[name]
		if !exists {
			return fmt.Errorf("capture %q has no computed finite width", name)
		}
		tokenBytes := int64(len("${" + name + "}"))
		if width > math.MaxInt64/6 {
			return fmt.Errorf("capture %q JSON expansion overflows INT64", name)
		}
		escaped := width * 6
		if escaped > tokenBytes {
			if bound > math.MaxInt64-(escaped-tokenBytes) {
				return fmt.Errorf("JSON expansion bound overflows INT64")
			}
			bound += escaped - tokenBytes
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	err = walkDocumentationExactMatchPropertyOperands(value, 0, func(object map[string]interface{}, property string) error {
		encoded, marshalErr := json.Marshal(object)
		if marshalErr != nil {
			return marshalErr
		}
		resolvedBound := int64(20)
		if property == documentationExactMatchPropertySHA256 {
			resolvedBound = 66 // quotes plus 64 lowercase hexadecimal bytes
		}
		if resolvedBound > int64(len(encoded)) {
			if bound > math.MaxInt64-(resolvedBound-int64(len(encoded))) {
				return fmt.Errorf("exact match property expansion bound overflows INT64")
			}
			bound += resolvedBound - int64(len(encoded))
		}
		return nil
	})
	return bound, err
}

func conservativeDocumentationStringJSONExpansionBound(value string, captureWidths map[string]int64) (int64, error) {
	return conservativeDocumentationTemplateJSONExpansionBound(value, captureWidths)
}

func walkDocumentationTemplateCaptures(value interface{}, depth int, visit func(string) error) error {
	if depth > maxDocumentationDerivationTemplateDepth {
		return fmt.Errorf("documentation derivation output exceeds the closed nesting-depth bound")
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		for _, child := range typed {
			if err := walkDocumentationTemplateCaptures(child, depth+1, visit); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, child := range typed {
			if err := walkDocumentationTemplateCaptures(child, depth+1, visit); err != nil {
				return err
			}
		}
	case string:
		matches := documentationTemplateCapturePattern.FindAllStringSubmatch(typed, -1)
		for _, match := range matches {
			if err := visit(match[1]); err != nil {
				return err
			}
		}
		if strings.Contains(documentationTemplateCapturePattern.ReplaceAllString(typed, ""), "${") {
			return fmt.Errorf("documentation derivation output contains a malformed capture template")
		}
	}
	return nil
}

func executeExactDocumentationDerivationProgram(reference dependencyProfileReference, program exactDocumentationDerivationProgram, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody) ([]exactDocumentationDerivedFact, error) {
	result, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		return nil, err
	}
	return result.Facts, nil
}

func exactDocumentationMatchCaptures(compiled *regexp.Regexp, selected []byte, match []int) (map[string]string, error) {
	result := map[string]string{}
	for index, name := range compiled.SubexpNames() {
		if index == 0 || name == "" {
			continue
		}
		startIndex := match[index*2]
		endIndex := match[index*2+1]
		if startIndex < 0 || endIndex < startIndex {
			return nil, fmt.Errorf("required capture %q did not participate", name)
		}
		result[name] = string(selected[startIndex:endIndex])
	}
	return result, nil
}

type documentationExactMatchProperties struct {
	selectedRangeSHA256    string
	selectedRangeByteCount int64
}

func resolveDocumentationOutputTemplate(template map[string]interface{}, captures map[string]string, matchProperties documentationExactMatchProperties, budget *documentationTemplateExpansionBudget) (map[string]interface{}, error) {
	resolved, err := resolveDocumentationTemplateValue(template, 0, captures, matchProperties, budget)
	if err != nil {
		return nil, err
	}
	object, ok := resolved.(map[string]interface{})
	if !ok || len(object) == 0 {
		return nil, fmt.Errorf("resolved documentation output is not a nonempty object")
	}
	return object, nil
}

type documentationTemplateExpansionBudget struct {
	remaining int64
}

func (budget *documentationTemplateExpansionBudget) consume(byteCount int64) error {
	if byteCount < 0 || byteCount > budget.remaining {
		return fmt.Errorf("resolved documentation template exceeds its preallocation byte bound")
	}
	budget.remaining -= byteCount
	return nil
}

func resolveDocumentationTemplateValue(value interface{}, depth int, captures map[string]string, matchProperties documentationExactMatchProperties, budget *documentationTemplateExpansionBudget) (interface{}, error) {
	if depth > maxDocumentationDerivationTemplateDepth {
		return nil, fmt.Errorf("documentation derivation output exceeds the closed nesting-depth bound")
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		if property, ok := documentationExactMatchPropertyOperand(typed); ok {
			switch property {
			case documentationExactMatchPropertySHA256:
				if !isLowerSHA256(matchProperties.selectedRangeSHA256) {
					return nil, fmt.Errorf("selected_range_sha256 exact match property is unavailable")
				}
				if err := budget.consume(int64(len(matchProperties.selectedRangeSHA256))); err != nil {
					return nil, err
				}
				return matchProperties.selectedRangeSHA256, nil
			case documentationExactMatchPropertyByteCount:
				if matchProperties.selectedRangeByteCount <= 0 {
					return nil, fmt.Errorf("selected_range_byte_count exact match property is unavailable")
				}
				return json.Number(fmt.Sprint(matchProperties.selectedRangeByteCount)), nil
			}
		}
		result := make(map[string]interface{}, len(typed))
		for key, child := range typed {
			resolved, err := resolveDocumentationTemplateValue(child, depth+1, captures, matchProperties, budget)
			if err != nil {
				return nil, err
			}
			result[key] = resolved
		}
		return result, nil
	case []interface{}:
		result := make([]interface{}, len(typed))
		for index, child := range typed {
			resolved, err := resolveDocumentationTemplateValue(child, depth+1, captures, matchProperties, budget)
			if err != nil {
				return nil, err
			}
			result[index] = resolved
		}
		return result, nil
	case string:
		return resolveDocumentationTemplateStringBounded(typed, captures, budget)
	case nil, bool, json.Number:
		return typed, nil
	default:
		return nil, fmt.Errorf("documentation output template contains unsupported value type %T", value)
	}
}

func documentationExactMatchPropertyOperand(value map[string]interface{}) (string, bool) {
	property, exists := value[documentationExactMatchPropertyKey].(string)
	return property, exists && len(value) == 1
}

func validateDocumentationExactMatchPropertyOperands(value interface{}, depth int) error {
	return walkDocumentationExactMatchPropertyOperands(value, depth, func(_ map[string]interface{}, property string) error {
		if property != documentationExactMatchPropertySHA256 && property != documentationExactMatchPropertyByteCount {
			return fmt.Errorf("exact match property %q is outside the closed set", property)
		}
		return nil
	})
}

func walkDocumentationExactMatchPropertyOperands(value interface{}, depth int, visit func(map[string]interface{}, string) error) error {
	if depth > maxDocumentationDerivationTemplateDepth {
		return fmt.Errorf("documentation derivation output exceeds the closed nesting-depth bound")
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		if raw, present := typed[documentationExactMatchPropertyKey]; present {
			property, ok := raw.(string)
			if !ok || len(typed) != 1 {
				return fmt.Errorf("%s operand must be an exact one-property object", documentationExactMatchPropertyKey)
			}
			return visit(typed, property)
		}
		for _, child := range typed {
			if err := walkDocumentationExactMatchPropertyOperands(child, depth+1, visit); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, child := range typed {
			if err := walkDocumentationExactMatchPropertyOperands(child, depth+1, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveDocumentationTemplateStringBounded(template string, captures map[string]string, budget *documentationTemplateExpansionBudget) (string, error) {
	matches := documentationTemplateCapturePattern.FindAllStringSubmatchIndex(template, -1)
	resultBytes := int64(len(template))
	for _, match := range matches {
		name := template[match[2]:match[3]]
		value, exists := captures[name]
		if !exists {
			return "", fmt.Errorf("capture %q is unavailable", name)
		}
		tokenBytes := int64(match[1] - match[0])
		valueBytes := int64(len(value))
		if valueBytes >= tokenBytes {
			if resultBytes > math.MaxInt64-(valueBytes-tokenBytes) {
				return "", fmt.Errorf("resolved documentation template byte count overflows INT64")
			}
			resultBytes += valueBytes - tokenBytes
		} else {
			resultBytes -= tokenBytes - valueBytes
		}
	}
	if err := budget.consume(resultBytes); err != nil {
		return "", err
	}
	if resultBytes > int64(math.MaxInt) {
		return "", fmt.Errorf("resolved documentation template cannot be allocated on this platform")
	}
	var builder strings.Builder
	builder.Grow(int(resultBytes))
	prior := 0
	for _, match := range matches {
		builder.WriteString(template[prior:match[0]])
		builder.WriteString(captures[template[match[2]:match[3]]])
		prior = match[1]
	}
	builder.WriteString(template[prior:])
	return builder.String(), nil
}

func resolveExactDocumentationTargetCoordinates(rule exactDocumentationDerivationRule, output map[string]interface{}, captures map[string]string, budget *documentationTemplateExpansionBudget) ([]exactDocumentationResolvedTargetRowSelector, string, []exactDocumentationResolvedMemberIdentity, string, error) {
	emptyRoot := sha256Hex(nil)
	if rule.TargetBindingKind == exactDocumentationTargetWholeRow {
		return []exactDocumentationResolvedTargetRowSelector{}, emptyRoot, []exactDocumentationResolvedMemberIdentity{}, emptyRoot, nil
	}
	selectors := make([]exactDocumentationResolvedTargetRowSelector, len(rule.TargetRowSelector))
	for index, selector := range rule.TargetRowSelector {
		expected, err := resolveDocumentationTemplateStringBounded(selector.ExpectedStringTemplate, captures, budget)
		if err != nil {
			return nil, "", nil, "", fmt.Errorf("resolve target row selector %q: %w", selector.TargetRowJSONPointer, err)
		}
		selectors[index] = exactDocumentationResolvedTargetRowSelector{TargetRowJSONPointer: selector.TargetRowJSONPointer, ExpectedString: expected}
	}
	selectorRoot, err := canonicalDocumentationDigest(selectors)
	if err != nil {
		return nil, "", nil, "", err
	}
	identities := make([]exactDocumentationResolvedMemberIdentity, len(rule.TargetMemberIdentityJSONPointers))
	for index, pointer := range rule.TargetMemberIdentityJSONPointers {
		value, err := exactDocumentationStringAtJSONPointer(output, pointer)
		if err != nil {
			return nil, "", nil, "", fmt.Errorf("resolve target member identity pointer %q: %w", pointer, err)
		}
		identities[index] = exactDocumentationResolvedMemberIdentity{OutputJSONPointer: pointer, ExpectedString: value}
	}
	identityRoot, err := canonicalDocumentationDigest(identities)
	if err != nil {
		return nil, "", nil, "", err
	}
	return selectors, selectorRoot, identities, identityRoot, nil
}

func exactDocumentationStringAtJSONPointer(root map[string]interface{}, pointer string) (string, error) {
	tokens, err := exactDocumentationJSONPointerTokens(pointer)
	if err != nil {
		return "", err
	}
	var current interface{} = root
	for _, token := range tokens {
		object, ok := current.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("path traverses non-object value")
		}
		current, ok = object[token]
		if !ok {
			return "", fmt.Errorf("path names absent required property %q", token)
		}
	}
	value, ok := current.(string)
	if !ok || value == "" {
		return "", fmt.Errorf("path does not resolve to a nonempty required string")
	}
	return value, nil
}

func validateExactDocumentationResolvedTargetCoordinates(fact exactDocumentationDerivedFact) error {
	emptyRoot := sha256Hex(nil)
	switch fact.TargetBindingKind {
	case exactDocumentationTargetWholeRow:
		if len(fact.TargetRowSelector) != 0 || fact.TargetRowSelectorSHA256 != emptyRoot || len(fact.TargetMemberIdentity) != 0 || fact.TargetMemberIdentitySHA256 != emptyRoot {
			return fmt.Errorf("whole-row fact carries nonempty row selector or member identity")
		}
		return nil
	case exactDocumentationTargetRowMember:
		if len(fact.TargetRowSelector) == 0 || len(fact.TargetMemberIdentity) == 0 {
			return fmt.Errorf("row-member fact has empty row selector or member identity")
		}
		prior := ""
		for _, selector := range fact.TargetRowSelector {
			if err := validateExactDocumentationJSONPointer(selector.TargetRowJSONPointer, "resolved target row selector"); err != nil {
				return err
			}
			if selector.TargetRowJSONPointer <= prior || selector.ExpectedString == "" {
				return fmt.Errorf("resolved target row selector is not strictly sorted, unique, and nonempty")
			}
			prior = selector.TargetRowJSONPointer
		}
		root, err := canonicalDocumentationDigest(fact.TargetRowSelector)
		if err != nil || root != fact.TargetRowSelectorSHA256 {
			return fmt.Errorf("resolved target row selector digest does not equal its canonical entries")
		}
		output, err := decodeExactDocumentationFactOutputFields(fact)
		if err != nil {
			return err
		}
		prior = ""
		for _, identity := range fact.TargetMemberIdentity {
			if err := validateExactDocumentationJSONPointer(identity.OutputJSONPointer, "resolved target member identity"); err != nil {
				return err
			}
			if identity.OutputJSONPointer <= prior || identity.ExpectedString == "" {
				return fmt.Errorf("resolved target member identity is not strictly sorted, unique, and nonempty")
			}
			actual, err := exactDocumentationStringAtJSONPointer(output, identity.OutputJSONPointer)
			if err != nil || actual != identity.ExpectedString {
				return fmt.Errorf("resolved target member identity does not equal canonical output at %q", identity.OutputJSONPointer)
			}
			prior = identity.OutputJSONPointer
		}
		root, err = canonicalDocumentationDigest(fact.TargetMemberIdentity)
		if err != nil || root != fact.TargetMemberIdentitySHA256 {
			return fmt.Errorf("resolved target member identity digest does not equal its canonical entries")
		}
		return nil
	default:
		return fmt.Errorf("unsupported target binding kind")
	}
}

func decodeExactDocumentationFactOutputFields(fact exactDocumentationDerivedFact) (map[string]interface{}, error) {
	var output map[string]interface{}
	if err := decodeOneValidationProfileJSON(fact.CanonicalOutputFields, &output); err != nil {
		return nil, fmt.Errorf("decode canonical documentation fact output: %w", err)
	}
	if len(output) == 0 {
		return nil, fmt.Errorf("canonical documentation fact output is empty")
	}
	return output, nil
}

func exactDocumentationFactRoot(facts []exactDocumentationDerivedFact) string {
	rows := make([][]byte, len(facts))
	for index, fact := range facts {
		envelope, err := canonicalExactDocumentationFactEnvelopeBytes(fact)
		if err != nil {
			return ""
		}
		rows[index] = []byte(lengthPrefixedIdentityKey(fact.FactID, sha256Hex(envelope)))
	}
	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i], rows[j]) < 0 })
	return stageCanonicalSetRoot(rows)
}
