package providerplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"sort"
	"unicode"
	"unicode/utf8"
)

const (
	exactDocumentationDerivationCursorKind       = "exact_documentation_derivation_cursor_v3"
	exactDocumentationDerivationPageKind         = "exact_documentation_derivation_page_v3"
	exactDocumentationDerivationParserStateKind  = "exact_documentation_derivation_parser_state_v3"
	exactDocumentationDerivationCheckpointKind   = "exact_documentation_derivation_checkpoint_v2"
	exactDocumentationDerivationFactEnvelopeKind = "exact_documentation_derived_fact_envelope_v1"
	exactDocumentationDerivationPageSetKind      = "exact_documentation_derivation_page_set_v3"
	exactDocumentationDerivationResumable        = "resumable_incomplete"
	exactDocumentationDerivationPagingComplete   = "complete"
	exactDocumentationNoOutputKind               = "none"
)

type exactDocumentationExecutionCheckpoint struct {
	CheckpointKind                    string                           `json:"checkpoint_kind"`
	OccurrenceIndex                   int64                            `json:"occurrence_index"`
	SourceMemberSHA256                string                           `json:"source_member_sha256"`
	PredecessorLocatorID              string                           `json:"predecessor_locator_id"`
	SelectedOccurrenceID              string                           `json:"selected_occurrence_id"`
	InputStartByteOffset              int64                            `json:"input_start_byte_offset"`
	InputEndByteOffsetExclusive       int64                            `json:"input_end_byte_offset_exclusive"`
	RuleIndex                         int64                            `json:"rule_index"`
	CandidateByteOffset               int64                            `json:"candidate_byte_offset"`
	RuleProgress                      []exactDocumentationRuleProgress `json:"rule_progress"`
	RuleDerivedFactRoots              []string                         `json:"rule_derived_fact_roots"`
	MatcherEvaluationsInInputUnit     int64                            `json:"matcher_evaluations_in_input_unit"`
	MatcherEvaluationsInRun           int64                            `json:"matcher_evaluations_in_run"`
	MatcherInputBytesInInputUnit      int64                            `json:"matcher_input_bytes_in_input_unit"`
	MatcherInputBytesInRun            int64                            `json:"matcher_input_bytes_in_run"`
	MatcherInputByteLimitPerInputUnit int64                            `json:"matcher_input_byte_limit_per_input_unit"`
	MatcherInputByteLimitPerRun       int64                            `json:"matcher_input_byte_limit_per_run"`
	OutputPageOrdinal                 int64                            `json:"output_page_ordinal"`
	CumulativeFactCount               int64                            `json:"cumulative_fact_count"`
	CumulativeCanonicalFactBytes      int64                            `json:"cumulative_canonical_fact_bytes"`
	CumulativeOutcomeCount            int64                            `json:"cumulative_outcome_count"`
	CumulativeCanonicalOutcomeBytes   int64                            `json:"cumulative_canonical_outcome_bytes"`
	PredecessorParserStateDigest      string                           `json:"predecessor_parser_state_digest"`
}

type exactDocumentationDerivationContinuation struct {
	CursorKind                string                                `json:"cursor_kind"`
	ProfileID                 string                                `json:"profile_id"`
	ProfileVersion            string                                `json:"profile_version"`
	ProfileSHA256             string                                `json:"profile_sha256"`
	ClassificationProofSHA256 string                                `json:"classification_proof_sha256"`
	SourceManifestRootSHA256  string                                `json:"source_manifest_root_sha256"`
	LastOutputKind            string                                `json:"last_output_kind"`
	LastOutputIdentityHash    string                                `json:"last_output_identity_hash"`
	OutputPageOrdinal         int64                                 `json:"output_page_ordinal"`
	NextCheckpoint            exactDocumentationExecutionCheckpoint `json:"next_checkpoint"`
	ContinuationCursorSHA256  string                                `json:"continuation_cursor_sha256"`
}

type exactDocumentationDerivationPageDescriptor struct {
	PageKind                          string `json:"page_kind"`
	PageSHA256                        string `json:"page_sha256"`
	ProfileID                         string `json:"profile_id"`
	ProfileVersion                    string `json:"profile_version"`
	ProfileSHA256                     string `json:"profile_sha256"`
	Provider                          string `json:"provider"`
	ClassificationProofSHA256         string `json:"classification_proof_sha256"`
	SourceManifestRootSHA256          string `json:"source_manifest_root_sha256"`
	SourceMemberSHA256                string `json:"source_member_sha256"`
	PredecessorLocatorID              string `json:"predecessor_locator_id"`
	SelectedOccurrenceID              string `json:"selected_occurrence_id"`
	InputStartByteOffset              int64  `json:"input_start_byte_offset"`
	InputEndByteOffsetExclusive       int64  `json:"input_end_byte_offset_exclusive"`
	InputUnitLength                   int64  `json:"input_unit_length"`
	ParserStatePredecessorDigest      string `json:"parser_state_predecessor_digest"`
	ParserStateDigest                 string `json:"parser_state_digest"`
	OutputPageOrdinal                 int64  `json:"output_page_ordinal"`
	FactIdentityRootSHA256            string `json:"fact_identity_root_sha256"`
	FactCount                         int64  `json:"fact_count"`
	CanonicalFactBytes                int64  `json:"canonical_fact_bytes"`
	MatcherEvaluationCount            int64  `json:"matcher_evaluation_count"`
	CumulativeMatcherEvaluationCount  int64  `json:"cumulative_matcher_evaluation_count"`
	MatcherInputByteCount             int64  `json:"matcher_input_byte_count"`
	MatcherInputBytesInInputUnit      int64  `json:"matcher_input_bytes_in_input_unit"`
	CumulativeMatcherInputByteCount   int64  `json:"cumulative_matcher_input_byte_count"`
	MatcherInputByteLimitPerInputUnit int64  `json:"matcher_input_byte_limit_per_input_unit"`
	MatcherInputByteLimitPerRun       int64  `json:"matcher_input_byte_limit_per_run"`
	OutcomeIdentityRootSHA256         string `json:"outcome_identity_root_sha256"`
	OutcomeCount                      int64  `json:"outcome_count"`
	CanonicalOutcomeBytes             int64  `json:"canonical_outcome_bytes"`
	CumulativeOutcomeCount            int64  `json:"cumulative_outcome_count"`
	CumulativeCanonicalOutcomeBytes   int64  `json:"cumulative_canonical_outcome_bytes"`
	LastOutputKind                    string `json:"last_output_kind"`
	LastOutputIdentityHash            string `json:"last_output_identity_hash"`
	ContinuationCursorSHA256          string `json:"continuation_cursor_sha256"`
	TerminalForInputUnit              bool   `json:"terminal_for_input_unit"`
	TerminalForSourceMember           bool   `json:"terminal_for_source_member"`
	TerminalForExecution              bool   `json:"terminal_for_execution"`
}

type exactDocumentationDerivationPage struct {
	Descriptor   exactDocumentationDerivationPageDescriptor
	ParserState  exactDocumentationParserStateIdentity
	Facts        []exactDocumentationDerivedFact
	Outcomes     []exactDocumentationDerivationOccurrenceOutcome
	Status       string
	Continuation *exactDocumentationDerivationContinuation
}

type exactDocumentationDerivationPageWireEnvelope struct {
	Descriptor   exactDocumentationDerivationPageDescriptor      `json:"descriptor"`
	ParserState  exactDocumentationParserStateIdentity           `json:"parser_state"`
	Facts        []exactDocumentationFactEnvelope                `json:"facts"`
	Outcomes     []exactDocumentationDerivationOccurrenceOutcome `json:"outcomes"`
	Status       string                                          `json:"status"`
	Continuation *exactDocumentationDerivationContinuation       `json:"continuation"`
}

func exactDocumentationPageWireEnvelopeFor(page exactDocumentationDerivationPage) exactDocumentationDerivationPageWireEnvelope {
	facts := make([]exactDocumentationFactEnvelope, len(page.Facts))
	for index, fact := range page.Facts {
		facts[index] = exactDocumentationFactEnvelopeFor(fact)
	}
	return exactDocumentationDerivationPageWireEnvelope{
		Descriptor: page.Descriptor, ParserState: page.ParserState,
		Facts:    facts,
		Outcomes: append([]exactDocumentationDerivationOccurrenceOutcome(nil), page.Outcomes...),
		Status:   page.Status, Continuation: page.Continuation,
	}
}

type exactDocumentationDerivationPageSetSeal struct {
	PageSetKind                       string
	Profile                           dependencyProfileReference
	Provider                          string
	ClassificationProofSHA256         string
	SourceManifestRootSHA256          string
	PageCount                         int64
	FactCount                         int64
	CanonicalFactBytes                int64
	MatcherEvaluationCount            int64
	MatcherInputByteCount             int64
	MatcherInputByteLimitPerInputUnit int64
	MatcherInputByteLimitPerRun       int64
	OutcomeCount                      int64
	CanonicalOutcomeBytes             int64
	OutcomeSetRootSHA256              string
	OrderedPageChainRootSHA256        string
	PageSetRootSHA256                 string
	Status                            string
}

type exactDocumentationDerivationPagedExecution struct {
	Pages    []exactDocumentationDerivationPage
	Facts    []exactDocumentationDerivedFact
	Outcomes []exactDocumentationDerivationOccurrenceOutcome
	Seal     exactDocumentationDerivationPageSetSeal
}

type exactDocumentationPatternAnalysis struct {
	MaximumUTF8Bytes  int64
	RequiresLineStart bool
}

type compiledExactDocumentationRule struct {
	rule     exactDocumentationDerivationRule
	compiled *regexp.Regexp
	analysis exactDocumentationPatternAnalysis
}

type exactDocumentationSelectedOccurrence struct {
	id           string
	sourceSymbol string
	binding      classificationArtifactBinding
	surfaceKind  string
	locator      evidenceLocator
}

type exactDocumentationRuleProgress struct {
	RuleID                string `json:"rule_id"`
	MatchCount            int64  `json:"match_count"`
	LastAcceptedEndOffset int64  `json:"last_accepted_end_offset"`
}

type exactDocumentationRuntimeDerivedFactAccumulator struct {
	ids  []string
	root string
}

type exactDocumentationParserStateIdentity struct {
	StateKind                         string                           `json:"state_kind"`
	PredecessorStateDigest            string                           `json:"predecessor_state_digest"`
	ProfileSHA256                     string                           `json:"profile_sha256"`
	ClassificationProofSHA256         string                           `json:"classification_proof_sha256"`
	SelectedOccurrenceID              string                           `json:"selected_occurrence_id"`
	InputStartByteOffset              int64                            `json:"input_start_byte_offset"`
	InputEndByteOffsetExclusive       int64                            `json:"input_end_byte_offset_exclusive"`
	OutputPageOrdinal                 int64                            `json:"output_page_ordinal"`
	FactIdentityRootSHA256            string                           `json:"fact_identity_root_sha256"`
	RuleProgress                      []exactDocumentationRuleProgress `json:"rule_progress"`
	MatcherEvaluationsInInputUnit     int64                            `json:"matcher_evaluations_in_input_unit"`
	MatcherEvaluationCount            int64                            `json:"matcher_evaluation_count"`
	CumulativeMatcherEvaluationCount  int64                            `json:"cumulative_matcher_evaluation_count"`
	MatcherInputBytesInInputUnit      int64                            `json:"matcher_input_bytes_in_input_unit"`
	MatcherInputByteCount             int64                            `json:"matcher_input_byte_count"`
	CumulativeMatcherInputByteCount   int64                            `json:"cumulative_matcher_input_byte_count"`
	MatcherInputByteLimitPerInputUnit int64                            `json:"matcher_input_byte_limit_per_input_unit"`
	MatcherInputByteLimitPerRun       int64                            `json:"matcher_input_byte_limit_per_run"`
	OutcomeIdentityRootSHA256         string                           `json:"outcome_identity_root_sha256"`
	OutcomeCount                      int64                            `json:"outcome_count"`
	CanonicalOutcomeBytes             int64                            `json:"canonical_outcome_bytes"`
	CumulativeOutcomeCount            int64                            `json:"cumulative_outcome_count"`
	CumulativeCanonicalOutcomeBytes   int64                            `json:"cumulative_canonical_outcome_bytes"`
	TerminalForInputUnit              bool                             `json:"terminal_for_input_unit"`
}

type exactDocumentationContinuationIdentity struct {
	CursorKind                string                                `json:"cursor_kind"`
	ProfileID                 string                                `json:"profile_id"`
	ProfileVersion            string                                `json:"profile_version"`
	ProfileSHA256             string                                `json:"profile_sha256"`
	ClassificationProofSHA256 string                                `json:"classification_proof_sha256"`
	SourceManifestRootSHA256  string                                `json:"source_manifest_root_sha256"`
	LastOutputKind            string                                `json:"last_output_kind"`
	LastOutputIdentityHash    string                                `json:"last_output_identity_hash"`
	OutputPageOrdinal         int64                                 `json:"output_page_ordinal"`
	NextCheckpoint            exactDocumentationExecutionCheckpoint `json:"next_checkpoint"`
}

type exactDocumentationPageIdentity struct {
	PageKind                          string `json:"page_kind"`
	ProfileID                         string `json:"profile_id"`
	ProfileVersion                    string `json:"profile_version"`
	ProfileSHA256                     string `json:"profile_sha256"`
	Provider                          string `json:"provider"`
	ClassificationProofSHA256         string `json:"classification_proof_sha256"`
	SourceManifestRootSHA256          string `json:"source_manifest_root_sha256"`
	SourceMemberSHA256                string `json:"source_member_sha256"`
	PredecessorLocatorID              string `json:"predecessor_locator_id"`
	SelectedOccurrenceID              string `json:"selected_occurrence_id"`
	InputStartByteOffset              int64  `json:"input_start_byte_offset"`
	InputEndByteOffsetExclusive       int64  `json:"input_end_byte_offset_exclusive"`
	InputUnitLength                   int64  `json:"input_unit_length"`
	ParserStatePredecessorDigest      string `json:"parser_state_predecessor_digest"`
	ParserStateDigest                 string `json:"parser_state_digest"`
	OutputPageOrdinal                 int64  `json:"output_page_ordinal"`
	FactIdentityRootSHA256            string `json:"fact_identity_root_sha256"`
	FactCount                         int64  `json:"fact_count"`
	CanonicalFactBytes                int64  `json:"canonical_fact_bytes"`
	MatcherEvaluationCount            int64  `json:"matcher_evaluation_count"`
	CumulativeMatcherEvaluationCount  int64  `json:"cumulative_matcher_evaluation_count"`
	MatcherInputByteCount             int64  `json:"matcher_input_byte_count"`
	MatcherInputBytesInInputUnit      int64  `json:"matcher_input_bytes_in_input_unit"`
	CumulativeMatcherInputByteCount   int64  `json:"cumulative_matcher_input_byte_count"`
	MatcherInputByteLimitPerInputUnit int64  `json:"matcher_input_byte_limit_per_input_unit"`
	MatcherInputByteLimitPerRun       int64  `json:"matcher_input_byte_limit_per_run"`
	OutcomeIdentityRootSHA256         string `json:"outcome_identity_root_sha256"`
	OutcomeCount                      int64  `json:"outcome_count"`
	CanonicalOutcomeBytes             int64  `json:"canonical_outcome_bytes"`
	CumulativeOutcomeCount            int64  `json:"cumulative_outcome_count"`
	CumulativeCanonicalOutcomeBytes   int64  `json:"cumulative_canonical_outcome_bytes"`
	LastOutputKind                    string `json:"last_output_kind"`
	LastOutputIdentityHash            string `json:"last_output_identity_hash"`
	ContinuationCursorSHA256          string `json:"continuation_cursor_sha256"`
	TerminalForInputUnit              bool   `json:"terminal_for_input_unit"`
	TerminalForSourceMember           bool   `json:"terminal_for_source_member"`
	TerminalForExecution              bool   `json:"terminal_for_execution"`
}

type exactDocumentationPageSetIdentity struct {
	PageSetKind                       string `json:"page_set_kind"`
	ProfileID                         string `json:"profile_id"`
	ProfileVersion                    string `json:"profile_version"`
	ProfileSHA256                     string `json:"profile_sha256"`
	Provider                          string `json:"provider"`
	ClassificationProofSHA256         string `json:"classification_proof_sha256"`
	SourceManifestRootSHA256          string `json:"source_manifest_root_sha256"`
	PageCount                         int64  `json:"page_count"`
	FactCount                         int64  `json:"fact_count"`
	CanonicalFactBytes                int64  `json:"canonical_fact_bytes"`
	MatcherEvaluationCount            int64  `json:"matcher_evaluation_count"`
	MatcherInputByteCount             int64  `json:"matcher_input_byte_count"`
	MatcherInputByteLimitPerInputUnit int64  `json:"matcher_input_byte_limit_per_input_unit"`
	MatcherInputByteLimitPerRun       int64  `json:"matcher_input_byte_limit_per_run"`
	OutcomeCount                      int64  `json:"outcome_count"`
	CanonicalOutcomeBytes             int64  `json:"canonical_outcome_bytes"`
	OutcomeSetRootSHA256              string `json:"outcome_set_root_sha256"`
	OrderedPageChainRootSHA256        string `json:"ordered_page_chain_root_sha256"`
	Status                            string `json:"status"`
}

type exactDocumentationFactEnvelope struct {
	EnvelopeKind                  string                                        `json:"envelope_kind"`
	FactID                        string                                        `json:"fact_id"`
	ProfileID                     string                                        `json:"profile_id"`
	ProfileVersion                string                                        `json:"profile_version"`
	ProfileSHA256                 string                                        `json:"profile_sha256"`
	Provider                      string                                        `json:"provider"`
	EvidenceRosterSHA256          string                                        `json:"evidence_roster_sha256"`
	ClassificationArtifactID      string                                        `json:"classification_artifact_id"`
	ClassificationArtifactVersion string                                        `json:"classification_artifact_version"`
	ClassificationArtifactSHA256  string                                        `json:"classification_artifact_sha256"`
	ClassificationRole            string                                        `json:"classification_role"`
	RuleID                        string                                        `json:"rule_id"`
	TargetArtifactRole            string                                        `json:"target_artifact_role"`
	TargetRowKind                 string                                        `json:"target_row_kind"`
	TargetBindingKind             string                                        `json:"target_binding_kind"`
	TargetMemberJSONPointer       string                                        `json:"target_member_json_pointer"`
	TargetRowSelector             []exactDocumentationResolvedTargetRowSelector `json:"target_row_selector"`
	TargetRowSelectorSHA256       string                                        `json:"target_row_selector_sha256"`
	TargetMemberIdentity          []exactDocumentationResolvedMemberIdentity    `json:"target_member_identity"`
	TargetMemberIdentitySHA256    string                                        `json:"target_member_identity_sha256"`
	InputSourceSymbol             string                                        `json:"input_source_symbol"`
	PredecessorLocatorID          string                                        `json:"predecessor_locator_id"`
	EvidenceLocatorID             string                                        `json:"evidence_locator_id"`
	EvidenceLocator               evidenceLocator                               `json:"evidence_locator"`
	MatchOrdinal                  int64                                         `json:"match_ordinal"`
	ByteStartOffset               int64                                         `json:"byte_start_offset"`
	ByteEndOffsetExclusive        int64                                         `json:"byte_end_offset_exclusive"`
	SelectedMatchSHA256           string                                        `json:"selected_match_sha256"`
	ExactOutputFieldNames         []string                                      `json:"exact_output_field_names"`
	CanonicalOutputFields         json.RawMessage                               `json:"canonical_output_fields"`
}

func analyzeFiniteDocumentationPattern(pattern string) (exactDocumentationPatternAnalysis, error) {
	var analysis exactDocumentationPatternAnalysis
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return analysis, err
	}
	if regexpSyntaxContainsAny(parsed, syntax.OpBeginText, syntax.OpEndText) {
		return analysis, fmt.Errorf("whole-text anchors are unsupported by bounded work-unit execution")
	}
	if regexpSyntaxContainsAny(parsed, syntax.OpWordBoundary, syntax.OpNoWordBoundary) {
		return analysis, fmt.Errorf("word-boundary assertions are unsupported by bounded work-unit execution")
	}
	if regexpSyntaxContainsAny(parsed, syntax.OpBeginLine) && !regexpSyntaxRequiresLeadingLineStart(parsed) {
		return analysis, fmt.Errorf("multiline begin anchors must lead every alternative")
	}
	width, bounded := maximumRegexpUTF8Width(parsed)
	if !bounded {
		return analysis, fmt.Errorf("pattern has unbounded UTF-8 match width")
	}
	analysis.MaximumUTF8Bytes = width
	analysis.RequiresLineStart = regexpSyntaxContainsAny(parsed, syntax.OpBeginLine)
	return analysis, nil
}

func maximumRegexpUTF8Width(expression *syntax.Regexp) (int64, bool) {
	switch expression.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, true
	case syntax.OpLiteral:
		var total int64
		for _, candidate := range expression.Rune {
			width := int64(maxFoldedRuneUTF8Len(candidate, expression.Flags&syntax.FoldCase != 0))
			if total > math.MaxInt64-width {
				return 0, false
			}
			total += width
		}
		return total, true
	case syntax.OpCharClass:
		maximum := 1
		for index := 0; index+1 < len(expression.Rune); index += 2 {
			if width := utf8.RuneLen(expression.Rune[index+1]); width > maximum {
				maximum = width
			}
		}
		return int64(maximum), true
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return utf8.UTFMax, true
	case syntax.OpCapture:
		return maximumRegexpUTF8Width(expression.Sub[0])
	case syntax.OpConcat:
		var total int64
		for _, child := range expression.Sub {
			width, bounded := maximumRegexpUTF8Width(child)
			if !bounded || total > math.MaxInt64-width {
				return 0, false
			}
			total += width
		}
		return total, true
	case syntax.OpAlternate:
		var maximum int64
		for _, child := range expression.Sub {
			width, bounded := maximumRegexpUTF8Width(child)
			if !bounded {
				return 0, false
			}
			if width > maximum {
				maximum = width
			}
		}
		return maximum, true
	case syntax.OpQuest:
		return maximumRegexpUTF8Width(expression.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		width, bounded := maximumRegexpUTF8Width(expression.Sub[0])
		if !bounded || width != 0 {
			return 0, false
		}
		return 0, true
	case syntax.OpRepeat:
		width, bounded := maximumRegexpUTF8Width(expression.Sub[0])
		if !bounded || expression.Max < 0 || (width != 0 && int64(expression.Max) > math.MaxInt64/width) {
			return 0, false
		}
		return width * int64(expression.Max), true
	default:
		return 0, false
	}
}

func maxFoldedRuneUTF8Len(candidate rune, folded bool) int {
	maximum := utf8.RuneLen(candidate)
	if maximum < 1 {
		maximum = utf8.RuneLen(utf8.RuneError)
	}
	if !folded {
		return maximum
	}
	for next := unicode.SimpleFold(candidate); next != candidate; next = unicode.SimpleFold(next) {
		if width := utf8.RuneLen(next); width > maximum {
			maximum = width
		}
	}
	return maximum
}

func regexpSyntaxContainsAny(expression *syntax.Regexp, operations ...syntax.Op) bool {
	for _, operation := range operations {
		if expression.Op == operation {
			return true
		}
	}
	for _, child := range expression.Sub {
		if regexpSyntaxContainsAny(child, operations...) {
			return true
		}
	}
	return false
}

func regexpSyntaxRequiresLeadingLineStart(expression *syntax.Regexp) bool {
	switch expression.Op {
	case syntax.OpCapture:
		return regexpSyntaxRequiresLeadingLineStart(expression.Sub[0])
	case syntax.OpAlternate:
		if len(expression.Sub) == 0 {
			return false
		}
		for _, child := range expression.Sub {
			if !regexpSyntaxRequiresLeadingLineStart(child) {
				return false
			}
		}
		return true
	case syntax.OpConcat:
		for _, child := range expression.Sub {
			if child.Op == syntax.OpEmptyMatch {
				continue
			}
			return child.Op == syntax.OpBeginLine || regexpSyntaxRequiresLeadingLineStart(child)
		}
		return false
	case syntax.OpBeginLine:
		return true
	default:
		return false
	}
}

type exactDocumentationExecutionRuntime struct {
	reference            dependencyProfileReference
	program              exactDocumentationDerivationProgram
	proof                sourceClassificationSelectionProof
	bodies               map[string]exactEvidenceBody
	rules                map[string][]compiledExactDocumentationRule
	occurrences          []exactDocumentationSelectedOccurrence
	selectedBytes        map[string][]byte
	expectedOutcomeCount int64
	derivedFacts         map[string]*exactDocumentationRuntimeDerivedFactAccumulator
}

func prepareExactDocumentationExecution(reference dependencyProfileReference, program exactDocumentationDerivationProgram, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody) (exactDocumentationExecutionRuntime, error) {
	var runtime exactDocumentationExecutionRuntime
	if err := validateSourceClassificationSelectionProof(proof); err != nil {
		return runtime, fmt.Errorf("documentation derivation execution requires a sealed exact classification-selection proof: %w", err)
	}
	encodedProgram, err := json.Marshal(program)
	if err != nil {
		return runtime, fmt.Errorf("marshal documentation derivation program for execution: %w", err)
	}
	program, err = parseExactDocumentationDerivationProgram(encodedProgram, reference)
	if err != nil {
		return runtime, fmt.Errorf("revalidate documentation derivation program for execution: %w", err)
	}
	expectedOutcomeCount, err := exactDocumentationOutcomeCrossProductCount(program, proof)
	if err != nil {
		return runtime, err
	}
	if expectedOutcomeCount > program.MaxOccurrenceOutcomesPerRun {
		return runtime, fmt.Errorf("documentation derivation rule/classified-occurrence cross-product %d exceeds max_occurrence_outcomes_per_run %d before execution", expectedOutcomeCount, program.MaxOccurrenceOutcomesPerRun)
	}
	rules := make(map[string][]compiledExactDocumentationRule)
	for _, rule := range program.OrderedRules {
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return runtime, fmt.Errorf("documentation derivation rule %q pattern changed after validation: %w", rule.RuleID, err)
		}
		analysis, err := analyzeFiniteDocumentationPattern(rule.Pattern)
		if err != nil {
			return runtime, fmt.Errorf("documentation derivation rule %q pattern changed after validation: %w", rule.RuleID, err)
		}
		rules[rule.InputSourceSymbol] = append(rules[rule.InputSourceSymbol], compiledExactDocumentationRule{rule: rule, compiled: compiled, analysis: analysis})
	}
	occurrences, err := exactDocumentationSelectedOccurrences(program, proof)
	if err != nil {
		return runtime, err
	}
	selectedBytes := make(map[string][]byte, len(occurrences))
	for _, occurrence := range occurrences {
		if err := validateLocator(occurrence.locator, bodies); err != nil {
			return runtime, fmt.Errorf("documentation derivation locator %s: %w", occurrence.locator.ID, err)
		}
		body := bodies[occurrence.locator.SourceContentSHA256].Bytes
		selected := body[occurrence.locator.ByteStartOffset:occurrence.locator.ByteEndOffsetExclusive]
		if !utf8.Valid(selected) {
			return runtime, fmt.Errorf("documentation derivation selected occurrence %s cannot use utf8_strict", occurrence.locator.ID)
		}
		selectedBytes[occurrence.id] = selected
	}
	return exactDocumentationExecutionRuntime{reference: reference, program: program, proof: proof, bodies: bodies, rules: rules, occurrences: occurrences, selectedBytes: selectedBytes, expectedOutcomeCount: expectedOutcomeCount, derivedFacts: make(map[string]*exactDocumentationRuntimeDerivedFactAccumulator)}, nil
}

func exactDocumentationDerivedFactSequenceGenesis(reference dependencyProfileReference, proof sourceClassificationSelectionProof, occurrence exactDocumentationSelectedOccurrence, ruleID string) string {
	return sha256Hex([]byte(lengthPrefixedIdentityKey("exact_documentation_derived_fact_sequence_v1", reference.digest, proof.contentSHA256, occurrence.id, ruleID)))
}

func exactDocumentationDerivedFactSequenceNext(root, factID string) string {
	return sha256Hex([]byte(lengthPrefixedIdentityKey(root, factID)))
}

func exactDocumentationRuntimeOutcomeKey(occurrence exactDocumentationSelectedOccurrence, rule exactDocumentationDerivationRule) string {
	return exactDocumentationDerivationOutcomeKey(rule.RuleID, rule.InputSourceSymbol, occurrence.binding, occurrence.surfaceKind, occurrence.locator.ID)
}

func exactDocumentationOutcomeCrossProductCount(program exactDocumentationDerivationProgram, proof sourceClassificationSelectionProof) (int64, error) {
	rulesBySource := make(map[string]int64, len(program.InputSourceSymbols))
	for _, rule := range program.OrderedRules {
		if rulesBySource[rule.InputSourceSymbol] == math.MaxInt64 {
			return 0, fmt.Errorf("documentation derivation rule count overflows INT64")
		}
		rulesBySource[rule.InputSourceSymbol]++
	}
	var total int64
	for sourceSymbol, ruleCount := range rulesBySource {
		occurrenceCount := int64(len(proof.classificationsBySourceSymbol[sourceSymbol]))
		if ruleCount != 0 && occurrenceCount > math.MaxInt64/ruleCount {
			return 0, fmt.Errorf("documentation derivation rule/classified-occurrence cross-product overflows INT64 for source_symbol %q", sourceSymbol)
		}
		product := ruleCount * occurrenceCount
		if total > math.MaxInt64-product {
			return 0, fmt.Errorf("documentation derivation rule/classified-occurrence cross-product overflows INT64")
		}
		total += product
	}
	if total <= 0 {
		return 0, fmt.Errorf("documentation derivation rule/classified-occurrence cross-product is empty")
	}
	return total, nil
}

func exactDocumentationParserGenesis(reference dependencyProfileReference, proof sourceClassificationSelectionProof) (string, error) {
	return canonicalDocumentationDigest(struct {
		Kind       string `json:"kind"`
		Profile    string `json:"profile_sha256"`
		Proof      string `json:"classification_proof_sha256"`
		SourceRoot string `json:"source_manifest_root_sha256"`
	}{"exact_documentation_derivation_parser_genesis_v2", reference.digest, proof.contentSHA256, proof.evidenceSelectionRosterSHA256})
}

func (runtime exactDocumentationExecutionRuntime) initialCheckpoint() (exactDocumentationExecutionCheckpoint, error) {
	genesis, err := exactDocumentationParserGenesis(runtime.reference, runtime.proof)
	if err != nil {
		return exactDocumentationExecutionCheckpoint{}, err
	}
	if len(runtime.occurrences) == 0 {
		return exactDocumentationExecutionCheckpoint{}, fmt.Errorf("documentation derivation has no selected occurrences")
	}
	return runtime.checkpointForUnit(0, runtime.occurrences[0].locator.ByteStartOffset, 0, 0, 0, 0, 0, 0, 0, genesis)
}

func (runtime exactDocumentationExecutionRuntime) checkpointForUnit(occurrenceIndex, unitStart, outputPageOrdinal, factCount, factBytes, matcherEvaluations, matcherInputBytes, outcomeCount, outcomeBytes int64, predecessor string) (exactDocumentationExecutionCheckpoint, error) {
	if occurrenceIndex < 0 || occurrenceIndex >= int64(len(runtime.occurrences)) {
		return exactDocumentationExecutionCheckpoint{}, fmt.Errorf("documentation execution checkpoint occurrence index is outside the selected roster")
	}
	occurrence := runtime.occurrences[occurrenceIndex]
	rules := runtime.rules[occurrence.sourceSymbol]
	if len(rules) == 0 {
		return exactDocumentationExecutionCheckpoint{}, fmt.Errorf("documentation derivation selected occurrence %s has no executable rule", occurrence.id)
	}
	remaining := occurrence.locator.ByteEndOffsetExclusive - unitStart
	if remaining <= 0 {
		return exactDocumentationExecutionCheckpoint{}, fmt.Errorf("documentation execution checkpoint unit has no input bytes")
	}
	unitEnd, err := runtime.exactUTF8UnitEnd(occurrence, unitStart)
	if err != nil {
		return exactDocumentationExecutionCheckpoint{}, err
	}
	progress := make([]exactDocumentationRuleProgress, len(rules))
	factRoots := make([]string, len(rules))
	for index, rule := range rules {
		progress[index] = exactDocumentationRuleProgress{RuleID: rule.rule.RuleID, LastAcceptedEndOffset: occurrence.locator.ByteStartOffset}
		factRoots[index] = exactDocumentationDerivedFactSequenceGenesis(runtime.reference, runtime.proof, occurrence, rule.rule.RuleID)
	}
	return exactDocumentationExecutionCheckpoint{
		CheckpointKind:  exactDocumentationDerivationCheckpointKind,
		OccurrenceIndex: occurrenceIndex, SourceMemberSHA256: occurrence.locator.SourceContentSHA256,
		PredecessorLocatorID: occurrence.locator.ID, SelectedOccurrenceID: occurrence.id,
		InputStartByteOffset: unitStart, InputEndByteOffsetExclusive: unitEnd,
		RuleIndex: 0, CandidateByteOffset: unitStart, RuleProgress: progress, RuleDerivedFactRoots: factRoots,
		MatcherEvaluationsInRun: matcherEvaluations, MatcherInputBytesInRun: matcherInputBytes,
		MatcherInputByteLimitPerInputUnit: runtime.program.MaxMatcherInputBytesPerInputUnit,
		MatcherInputByteLimitPerRun:       runtime.program.MaxMatcherInputBytesPerRun,
		OutputPageOrdinal:                 outputPageOrdinal, CumulativeFactCount: factCount,
		CumulativeCanonicalFactBytes: factBytes, CumulativeOutcomeCount: outcomeCount,
		CumulativeCanonicalOutcomeBytes: outcomeBytes, PredecessorParserStateDigest: predecessor,
	}, nil
}

func (runtime exactDocumentationExecutionRuntime) exactUTF8UnitEnd(occurrence exactDocumentationSelectedOccurrence, unitStart int64) (int64, error) {
	if unitStart < occurrence.locator.ByteStartOffset || unitStart >= occurrence.locator.ByteEndOffsetExclusive {
		return 0, fmt.Errorf("documentation execution UTF-8 unit start is outside the selected occurrence")
	}
	selected, exists := runtime.selectedBytes[occurrence.id]
	if !exists || int64(len(selected)) != occurrence.locator.ByteEndOffsetExclusive-occurrence.locator.ByteStartOffset {
		return 0, fmt.Errorf("documentation execution UTF-8 unit cannot hydrate its validated selected occurrence")
	}
	end := unitStart + runtime.program.MaxParseBytes
	if end >= occurrence.locator.ByteEndOffsetExclusive {
		return occurrence.locator.ByteEndOffsetExclusive, nil
	}
	for end > unitStart && !utf8.RuneStart(selected[end-occurrence.locator.ByteStartOffset]) {
		end--
	}
	if end == unitStart {
		return 0, fmt.Errorf("documentation derivation max_parse_bytes %d cannot contain the next complete UTF-8 rune", runtime.program.MaxParseBytes)
	}
	return end, nil
}

// executeExactDocumentationDerivationPageTestOnly exercises transport-style
// standalone resume. Because an untrusted self-contained cursor has identity
// but no external authority, every call proves reachability by bounded genesis
// replay. Production execution must use streamExactDocumentationDerivationPages,
// which carries the reached checkpoint and advances each unit exactly once.
func executeExactDocumentationDerivationPageTestOnly(reference dependencyProfileReference, program exactDocumentationDerivationProgram, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody, continuation *exactDocumentationDerivationContinuation) (exactDocumentationDerivationPage, error) {
	runtime, err := prepareExactDocumentationExecution(reference, program, proof, bodies)
	if err != nil {
		return exactDocumentationDerivationPage{}, err
	}
	if continuation == nil {
		checkpoint, err := runtime.initialCheckpoint()
		if err != nil {
			return exactDocumentationDerivationPage{}, err
		}
		return runtime.generatePage(checkpoint)
	}
	if err := validateExactDocumentationContinuation(*continuation, reference, program, proof); err != nil {
		return exactDocumentationDerivationPage{}, err
	}

	// A continuation digest gives the checkpoint a content identity; it does
	// not prove the checkpoint was ever reached. Standalone resume therefore
	// reexecutes the bounded deterministic prefix and accepts only an exact
	// continuation emitted by that execution. The in-process streaming path
	// below carries its already-reached checkpoint directly and does not replay.
	checkpoint, err := runtime.initialCheckpoint()
	if err != nil {
		return exactDocumentationDerivationPage{}, err
	}
	for {
		page, err := runtime.generatePage(checkpoint)
		if err != nil {
			return exactDocumentationDerivationPage{}, err
		}
		if page.Continuation != nil && equalDocumentationContinuations(page.Continuation, continuation) {
			return runtime.generatePage(cloneExactDocumentationCheckpoint(page.Continuation.NextCheckpoint))
		}
		if page.Descriptor.TerminalForExecution {
			return exactDocumentationDerivationPage{}, fmt.Errorf("documentation derivation continuation is not an exact reachable predecessor page")
		}
		checkpoint = cloneExactDocumentationCheckpoint(page.Continuation.NextCheckpoint)
	}
}

func streamExactDocumentationDerivationPages(reference dependencyProfileReference, program exactDocumentationDerivationProgram, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody, visit func(exactDocumentationDerivationPage) error) error {
	runtime, err := prepareExactDocumentationExecution(reference, program, proof, bodies)
	if err != nil {
		return err
	}
	checkpoint, err := runtime.initialCheckpoint()
	if err != nil {
		return err
	}
	for {
		page, err := runtime.generatePage(checkpoint)
		if err != nil {
			return err
		}
		if err := visit(page); err != nil {
			return err
		}
		if page.Status == exactDocumentationDerivationPagingComplete {
			return nil
		}
		checkpoint = cloneExactDocumentationCheckpoint(page.Continuation.NextCheckpoint)
	}
}

func generateExactDocumentationDerivationPages(reference dependencyProfileReference, program exactDocumentationDerivationProgram, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody, visit func(exactDocumentationDerivationPage) error) error {
	return streamExactDocumentationDerivationPages(reference, program, proof, bodies, visit)
}

func executeExactDocumentationDerivationAllPages(reference dependencyProfileReference, program exactDocumentationDerivationProgram, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody) (exactDocumentationDerivationPagedExecution, error) {
	var result exactDocumentationDerivationPagedExecution
	accumulator, err := newExactDocumentationPageSetAccumulator(reference, program, proof, bodies)
	if err != nil {
		return result, err
	}
	err = streamExactDocumentationDerivationPages(reference, program, proof, bodies, func(page exactDocumentationDerivationPage) error {
		if err := accumulator.add(page); err != nil {
			return err
		}
		result.Pages = append(result.Pages, page)
		result.Facts = append(result.Facts, page.Facts...)
		result.Outcomes = append(result.Outcomes, page.Outcomes...)
		return nil
	})
	if err != nil {
		return exactDocumentationDerivationPagedExecution{}, err
	}
	seal, err := accumulator.finish()
	if err != nil {
		return exactDocumentationDerivationPagedExecution{}, err
	}
	sort.Slice(result.Facts, func(i, j int) bool { return result.Facts[i].FactID < result.Facts[j].FactID })
	sort.Slice(result.Outcomes, func(i, j int) bool { return result.Outcomes[i].OutcomeID < result.Outcomes[j].OutcomeID })
	result.Seal = seal
	return result, nil
}

type exactDocumentationPageBuilder struct {
	runtime               *exactDocumentationExecutionRuntime
	checkpoint            exactDocumentationExecutionCheckpoint
	facts                 []exactDocumentationDerivedFact
	factEnvelopes         [][]byte
	canonicalFactBytes    int64
	outcomes              []exactDocumentationDerivationOccurrenceOutcome
	outcomeEnvelopes      [][]byte
	canonicalOutcomeBytes int64
	matcherEvaluationBase int64
	matcherInputByteBase  int64
}

func (runtime exactDocumentationExecutionRuntime) generatePage(checkpoint exactDocumentationExecutionCheckpoint) (exactDocumentationDerivationPage, error) {
	if err := runtime.validateCheckpoint(checkpoint); err != nil {
		return exactDocumentationDerivationPage{}, err
	}
	builder := exactDocumentationPageBuilder{runtime: &runtime, checkpoint: cloneExactDocumentationCheckpoint(checkpoint), matcherEvaluationBase: checkpoint.MatcherEvaluationsInInputUnit, matcherInputByteBase: checkpoint.MatcherInputBytesInInputUnit}
	occurrence := runtime.occurrences[checkpoint.OccurrenceIndex]
	selected, err := runtime.selectedOccurrenceBytes(occurrence)
	if err != nil {
		return exactDocumentationDerivationPage{}, err
	}
	rules := runtime.rules[occurrence.sourceSymbol]
	if err := runtime.validateDerivedFactAccumulators(builder.checkpoint, occurrence, rules); err != nil {
		return exactDocumentationDerivationPage{}, err
	}
	for builder.checkpoint.RuleIndex < int64(len(rules)) {
		if builder.checkpoint.CandidateByteOffset < builder.checkpoint.InputEndByteOffsetExclusive && len(builder.facts) > 0 && (int64(len(builder.facts)) >= runtime.program.MaxOutputFactsPerPage || builder.canonicalFactBytes > runtime.program.MaxOutputBytesPerPage-runtime.program.MaxOutputBytesPerFact) {
			return builder.flush(false, false, false)
		}
		ruleIndex := builder.checkpoint.RuleIndex
		compiledRule := rules[ruleIndex]
		progress := &builder.checkpoint.RuleProgress[ruleIndex]
		matched, fact, err := runtime.nextFact(referenceAndProof{runtime.reference, runtime.proof}, occurrence, selected, compiledRule, progress, &builder.checkpoint)
		if err != nil {
			return exactDocumentationDerivationPage{}, err
		}
		if !matched {
			builder.checkpoint.RuleIndex++
			builder.checkpoint.CandidateByteOffset = builder.checkpoint.InputStartByteOffset
			continue
		}
		envelope, err := canonicalExactDocumentationFactEnvelopeBytes(fact)
		if err != nil {
			return exactDocumentationDerivationPage{}, err
		}
		if int64(len(envelope)) > runtime.program.MaxOutputBytesPerFact {
			return exactDocumentationDerivationPage{}, fmt.Errorf("documentation-derived fact %s canonical envelope bytes %d exceed max_output_bytes_per_fact %d", fact.FactID, len(envelope), runtime.program.MaxOutputBytesPerFact)
		}
		if len(builder.facts) > 0 && builder.canonicalFactBytes > runtime.program.MaxOutputBytesPerPage-int64(len(envelope)) {
			return exactDocumentationDerivationPage{}, fmt.Errorf("internal documentation page reservation did not leave the run-pinned per-fact ceiling")
		}
		builder.facts = append(builder.facts, fact)
		builder.factEnvelopes = append(builder.factEnvelopes, envelope)
		builder.canonicalFactBytes += int64(len(envelope))
		if err := runtime.recordDerivedFact(&builder.checkpoint, occurrence, rules[ruleIndex].rule, int(ruleIndex), fact.FactID); err != nil {
			return exactDocumentationDerivationPage{}, err
		}
	}
	terminalOccurrence := builder.checkpoint.InputEndByteOffsetExclusive == occurrence.locator.ByteEndOffsetExclusive
	if terminalOccurrence {
		for index, rule := range rules {
			count := builder.checkpoint.RuleProgress[index].MatchCount
			if count < rule.rule.MinimumMatches || count > rule.rule.MaximumMatches {
				return exactDocumentationDerivationPage{}, fmt.Errorf("documentation derivation rule %q selected occurrence %s produced %d matches outside [%d,%d]", rule.rule.RuleID, occurrence.locator.ID, count, rule.rule.MinimumMatches, rule.rule.MaximumMatches)
			}
			if builder.checkpoint.CumulativeOutcomeCount+int64(len(builder.outcomes)) >= runtime.program.MaxOccurrenceOutcomesPerRun {
				return exactDocumentationDerivationPage{}, fmt.Errorf("documentation derivation exceeds max_occurrence_outcomes_per_run %d before outcome allocation", runtime.program.MaxOccurrenceOutcomesPerRun)
			}
			factIDs, err := runtime.derivedFactIDsForOutcome(builder.checkpoint, occurrence, rule.rule, index)
			if err != nil {
				return exactDocumentationDerivationPage{}, err
			}
			conservativeBytes, err := conservativeExactDocumentationOutcomeBytes(rule.rule, occurrence, factIDs)
			if err != nil {
				return exactDocumentationDerivationPage{}, err
			}
			if conservativeBytes > runtime.program.MaxCanonicalOutcomeBytesPerRun-builder.checkpoint.CumulativeCanonicalOutcomeBytes-builder.canonicalOutcomeBytes {
				return exactDocumentationDerivationPage{}, fmt.Errorf("documentation derivation conservative occurrence outcome expansion exceeds max_canonical_outcome_bytes_per_run %d before allocation", runtime.program.MaxCanonicalOutcomeBytesPerRun)
			}
			outcome, canonical, err := newExactDocumentationDerivationOccurrenceOutcome(runtime.reference, runtime.proof, rule.rule, occurrence, factIDs)
			if err != nil {
				return exactDocumentationDerivationPage{}, err
			}
			if int64(len(canonical)) > runtime.program.MaxCanonicalOutcomeBytesPerRun-builder.checkpoint.CumulativeCanonicalOutcomeBytes-builder.canonicalOutcomeBytes {
				return exactDocumentationDerivationPage{}, fmt.Errorf("documentation derivation exceeds max_canonical_outcome_bytes_per_run %d before outcome append", runtime.program.MaxCanonicalOutcomeBytesPerRun)
			}
			builder.outcomes = append(builder.outcomes, outcome)
			builder.outcomeEnvelopes = append(builder.outcomeEnvelopes, canonical)
			builder.canonicalOutcomeBytes += int64(len(canonical))
		}
		sort.Slice(builder.outcomes, func(i, j int) bool { return builder.outcomes[i].OutcomeID < builder.outcomes[j].OutcomeID })
		sort.Slice(builder.outcomeEnvelopes, func(i, j int) bool {
			return bytes.Compare(builder.outcomeEnvelopes[i], builder.outcomeEnvelopes[j]) < 0
		})
		for _, rule := range rules {
			delete(runtime.derivedFacts, exactDocumentationRuntimeOutcomeKey(occurrence, rule.rule))
		}
	}
	terminalExecution := terminalOccurrence && builder.checkpoint.OccurrenceIndex == int64(len(runtime.occurrences)-1)
	return builder.flush(true, terminalOccurrence, terminalExecution)
}

type referenceAndProof struct {
	reference dependencyProfileReference
	proof     sourceClassificationSelectionProof
}

func (runtime exactDocumentationExecutionRuntime) nextFact(authority referenceAndProof, occurrence exactDocumentationSelectedOccurrence, selected []byte, compiledRule compiledExactDocumentationRule, progress *exactDocumentationRuleProgress, checkpoint *exactDocumentationExecutionCheckpoint) (bool, exactDocumentationDerivedFact, error) {
	rule := compiledRule.rule
	candidate := checkpoint.CandidateByteOffset
	if progress.LastAcceptedEndOffset > candidate {
		candidate = progress.LastAcceptedEndOffset
	}
	if candidate < checkpoint.InputStartByteOffset {
		candidate = checkpoint.InputStartByteOffset
	}
	if candidate >= checkpoint.InputEndByteOffsetExclusive {
		checkpoint.CandidateByteOffset = checkpoint.InputEndByteOffsetExclusive
		return false, exactDocumentationDerivedFact{}, nil
	}
	if compiledRule.analysis.RequiresLineStart && candidate != occurrence.locator.ByteStartOffset {
		relative := candidate - occurrence.locator.ByteStartOffset
		if relative > 0 && selected[relative-1] != '\n' {
			lineSearch := selected[relative : checkpoint.InputEndByteOffsetExclusive-occurrence.locator.ByteStartOffset]
			if err := runtime.chargeMatcherInputBytes(checkpoint, int64(len(lineSearch))); err != nil {
				return false, exactDocumentationDerivedFact{}, err
			}
			next := bytes.IndexByte(lineSearch, '\n')
			if next < 0 || candidate+int64(next)+1 >= checkpoint.InputEndByteOffsetExclusive {
				checkpoint.CandidateByteOffset = checkpoint.InputEndByteOffsetExclusive
				return false, exactDocumentationDerivedFact{}, nil
			}
			candidate += int64(next) + 1
		}
	}
	if checkpoint.MatcherEvaluationsInInputUnit >= runtime.program.MaxMatcherEvaluationsPerInputUnit {
		return false, exactDocumentationDerivedFact{}, fmt.Errorf("documentation derivation input unit exceeds max_matcher_evaluations_per_input_unit %d", runtime.program.MaxMatcherEvaluationsPerInputUnit)
	}
	if checkpoint.MatcherEvaluationsInRun >= runtime.program.MaxMatcherEvaluationsPerRun {
		return false, exactDocumentationDerivedFact{}, fmt.Errorf("documentation derivation execution exceeds max_matcher_evaluations_per_run %d", runtime.program.MaxMatcherEvaluationsPerRun)
	}
	lookaheadEnd := checkpoint.InputEndByteOffsetExclusive
	if compiledRule.analysis.MaximumUTF8Bytes > 0 {
		// A match may start at the final byte owned by this unit and extend by
		// its full computed width. Preserve one complete following UTF-8 rune
		// as assertion context so (?m)$ cannot mistake an artificial slice end
		// for the selected occurrence's real end. Matches starting outside this
		// unit are still rejected below.
		extra := compiledRule.analysis.MaximumUTF8Bytes - 1 + utf8.UTFMax
		if lookaheadEnd <= math.MaxInt64-extra {
			lookaheadEnd += extra
		}
	}
	if lookaheadEnd > occurrence.locator.ByteEndOffsetExclusive {
		lookaheadEnd = occurrence.locator.ByteEndOffsetExclusive
	}
	windowStart := candidate - occurrence.locator.ByteStartOffset
	windowEnd := lookaheadEnd - occurrence.locator.ByteStartOffset
	windowBytes := windowEnd - windowStart
	if windowBytes <= 0 {
		return false, exactDocumentationDerivedFact{}, fmt.Errorf("documentation derivation matcher window has no exact input bytes")
	}
	if err := runtime.chargeMatcherInputBytes(checkpoint, windowBytes); err != nil {
		return false, exactDocumentationDerivedFact{}, err
	}
	checkpoint.MatcherEvaluationsInInputUnit++
	checkpoint.MatcherEvaluationsInRun++
	match := compiledRule.compiled.FindSubmatchIndex(selected[windowStart:windowEnd])
	if match == nil {
		checkpoint.CandidateByteOffset = checkpoint.InputEndByteOffsetExclusive
		return false, exactDocumentationDerivedFact{}, nil
	}
	matchStart := candidate + int64(match[0])
	if matchStart >= checkpoint.InputEndByteOffsetExclusive {
		checkpoint.CandidateByteOffset = checkpoint.InputEndByteOffsetExclusive
		return false, exactDocumentationDerivedFact{}, nil
	}
	if match[1] <= match[0] {
		return false, exactDocumentationDerivedFact{}, fmt.Errorf("documentation derivation rule %q produced an empty runtime match", rule.RuleID)
	}
	matchLength := int64(match[1] - match[0])
	if matchLength > compiledRule.analysis.MaximumUTF8Bytes || matchLength > rule.MaximumMatchBytes {
		return false, exactDocumentationDerivedFact{}, fmt.Errorf("documentation derivation rule %q runtime match byte count %d exceeds its computed or declared finite bound", rule.RuleID, matchLength)
	}
	if progress.MatchCount >= rule.MaximumMatches {
		return false, exactDocumentationDerivedFact{}, fmt.Errorf("documentation derivation rule %q selected occurrence %s produced more than maximum %d matches", rule.RuleID, occurrence.locator.ID, rule.MaximumMatches)
	}
	adjusted := append([]int(nil), match...)
	for index := range adjusted {
		if adjusted[index] >= 0 {
			adjusted[index] += int(windowStart)
		}
	}
	fact, err := exactDocumentationFactFromMatch(authority.reference, authority.proof, occurrence, rule, compiledRule.compiled, selected, adjusted, progress.MatchCount, runtime.bodies, runtime.program.MaxOutputBytesPerFact)
	if err != nil {
		return false, exactDocumentationDerivedFact{}, err
	}
	progress.MatchCount++
	progress.LastAcceptedEndOffset = matchStart + matchLength
	checkpoint.CandidateByteOffset = progress.LastAcceptedEndOffset
	return true, fact, nil
}

func (runtime exactDocumentationExecutionRuntime) chargeMatcherInputBytes(checkpoint *exactDocumentationExecutionCheckpoint, byteCount int64) error {
	if byteCount <= 0 {
		return fmt.Errorf("documentation derivation matcher scan has no exact input bytes")
	}
	if byteCount > runtime.program.MaxMatcherInputBytesPerInputUnit-checkpoint.MatcherInputBytesInInputUnit {
		return fmt.Errorf("documentation derivation input unit exceeds max_matcher_input_bytes_per_input_unit %d before matcher scan", runtime.program.MaxMatcherInputBytesPerInputUnit)
	}
	if byteCount > runtime.program.MaxMatcherInputBytesPerRun-checkpoint.MatcherInputBytesInRun {
		return fmt.Errorf("documentation derivation execution exceeds max_matcher_input_bytes_per_run %d before matcher scan", runtime.program.MaxMatcherInputBytesPerRun)
	}
	checkpoint.MatcherInputBytesInInputUnit += byteCount
	checkpoint.MatcherInputBytesInRun += byteCount
	return nil
}

func (runtime exactDocumentationExecutionRuntime) validateDerivedFactAccumulators(checkpoint exactDocumentationExecutionCheckpoint, occurrence exactDocumentationSelectedOccurrence, rules []compiledExactDocumentationRule) error {
	for index, rule := range rules {
		key := exactDocumentationRuntimeOutcomeKey(occurrence, rule.rule)
		state := runtime.derivedFacts[key]
		if state == nil {
			if checkpoint.RuleProgress[index].MatchCount != 0 || checkpoint.RuleDerivedFactRoots[index] != exactDocumentationDerivedFactSequenceGenesis(runtime.reference, runtime.proof, occurrence, rule.rule.RuleID) {
				return fmt.Errorf("documentation derivation runtime has no reachable fact-sequence state for checkpoint rule %q", rule.rule.RuleID)
			}
			continue
		}
		if int64(len(state.ids)) != checkpoint.RuleProgress[index].MatchCount || state.root != checkpoint.RuleDerivedFactRoots[index] {
			return fmt.Errorf("documentation derivation runtime fact-sequence state disagrees with checkpoint rule %q", rule.rule.RuleID)
		}
	}
	return nil
}

func (runtime exactDocumentationExecutionRuntime) recordDerivedFact(checkpoint *exactDocumentationExecutionCheckpoint, occurrence exactDocumentationSelectedOccurrence, rule exactDocumentationDerivationRule, ruleIndex int, factID string) error {
	if factID == "" {
		return fmt.Errorf("documentation derivation cannot accumulate an empty fact identity")
	}
	key := exactDocumentationRuntimeOutcomeKey(occurrence, rule)
	state := runtime.derivedFacts[key]
	if state == nil {
		state = &exactDocumentationRuntimeDerivedFactAccumulator{root: exactDocumentationDerivedFactSequenceGenesis(runtime.reference, runtime.proof, occurrence, rule.RuleID)}
		runtime.derivedFacts[key] = state
	}
	if int64(len(state.ids)) >= runtime.program.MaxOutputFactsPerRun {
		return fmt.Errorf("documentation derivation runtime fact-sequence state exceeds max_output_facts_per_run")
	}
	state.ids = append(state.ids, factID)
	state.root = exactDocumentationDerivedFactSequenceNext(state.root, factID)
	checkpoint.RuleDerivedFactRoots[ruleIndex] = state.root
	return nil
}

func (runtime exactDocumentationExecutionRuntime) derivedFactIDsForOutcome(checkpoint exactDocumentationExecutionCheckpoint, occurrence exactDocumentationSelectedOccurrence, rule exactDocumentationDerivationRule, ruleIndex int) ([]string, error) {
	state := runtime.derivedFacts[exactDocumentationRuntimeOutcomeKey(occurrence, rule)]
	if state == nil {
		if checkpoint.RuleProgress[ruleIndex].MatchCount != 0 || checkpoint.RuleDerivedFactRoots[ruleIndex] != exactDocumentationDerivedFactSequenceGenesis(runtime.reference, runtime.proof, occurrence, rule.RuleID) {
			return nil, fmt.Errorf("documentation derivation outcome has no reachable fact-sequence state for rule %q", rule.RuleID)
		}
		return nil, nil
	}
	if int64(len(state.ids)) != checkpoint.RuleProgress[ruleIndex].MatchCount || state.root != checkpoint.RuleDerivedFactRoots[ruleIndex] {
		return nil, fmt.Errorf("documentation derivation outcome fact-sequence state disagrees for rule %q", rule.RuleID)
	}
	return state.ids, nil
}

func (runtime exactDocumentationExecutionRuntime) selectedOccurrenceBytes(occurrence exactDocumentationSelectedOccurrence) ([]byte, error) {
	selected, exists := runtime.selectedBytes[occurrence.id]
	if !exists || int64(len(selected)) != occurrence.locator.ByteEndOffsetExclusive-occurrence.locator.ByteStartOffset {
		return nil, fmt.Errorf("documentation derivation selected occurrence %s has no once-validated byte view", occurrence.locator.ID)
	}
	return selected, nil
}

func (runtime exactDocumentationExecutionRuntime) validateCheckpoint(checkpoint exactDocumentationExecutionCheckpoint) error {
	if checkpoint.CheckpointKind != exactDocumentationDerivationCheckpointKind || checkpoint.OccurrenceIndex < 0 || checkpoint.OccurrenceIndex >= int64(len(runtime.occurrences)) || checkpoint.OutputPageOrdinal < 0 || checkpoint.OutputPageOrdinal >= runtime.program.MaxOutputPagesPerRun || checkpoint.CumulativeFactCount < 0 || checkpoint.CumulativeFactCount > runtime.program.MaxOutputFactsPerRun || checkpoint.CumulativeCanonicalFactBytes < 0 || checkpoint.CumulativeCanonicalFactBytes > runtime.program.MaxOutputBytesPerRun || checkpoint.MatcherEvaluationsInRun < 0 || checkpoint.MatcherEvaluationsInRun > runtime.program.MaxMatcherEvaluationsPerRun || checkpoint.MatcherInputBytesInRun < 0 || checkpoint.MatcherInputBytesInRun > runtime.program.MaxMatcherInputBytesPerRun || checkpoint.MatcherInputByteLimitPerInputUnit != runtime.program.MaxMatcherInputBytesPerInputUnit || checkpoint.MatcherInputByteLimitPerRun != runtime.program.MaxMatcherInputBytesPerRun || checkpoint.CumulativeOutcomeCount < 0 || checkpoint.CumulativeOutcomeCount > runtime.program.MaxOccurrenceOutcomesPerRun || checkpoint.CumulativeCanonicalOutcomeBytes < 0 || checkpoint.CumulativeCanonicalOutcomeBytes > runtime.program.MaxCanonicalOutcomeBytesPerRun || !isLowerSHA256(checkpoint.PredecessorParserStateDigest) {
		return fmt.Errorf("documentation derivation checkpoint is structurally invalid or exceeds run-pinned aggregate caps")
	}
	occurrence := runtime.occurrences[checkpoint.OccurrenceIndex]
	if checkpoint.SourceMemberSHA256 != occurrence.locator.SourceContentSHA256 || checkpoint.PredecessorLocatorID != occurrence.locator.ID || checkpoint.SelectedOccurrenceID != occurrence.id {
		return fmt.Errorf("documentation derivation checkpoint names the wrong selected occurrence")
	}
	if checkpoint.InputStartByteOffset < occurrence.locator.ByteStartOffset || checkpoint.InputEndByteOffsetExclusive <= checkpoint.InputStartByteOffset || checkpoint.InputEndByteOffsetExclusive > occurrence.locator.ByteEndOffsetExclusive || checkpoint.InputEndByteOffsetExclusive-checkpoint.InputStartByteOffset > runtime.program.MaxParseBytes {
		return fmt.Errorf("documentation derivation checkpoint has an invalid bounded input unit")
	}
	expectedUnitEnd, err := runtime.exactUTF8UnitEnd(occurrence, checkpoint.InputStartByteOffset)
	if err != nil || checkpoint.InputEndByteOffsetExclusive != expectedUnitEnd {
		return fmt.Errorf("documentation derivation checkpoint does not align to the exact bounded UTF-8 rune boundary")
	}
	rules := runtime.rules[occurrence.sourceSymbol]
	if checkpoint.RuleIndex < 0 || checkpoint.RuleIndex > int64(len(rules)) || len(checkpoint.RuleProgress) != len(rules) || len(checkpoint.RuleDerivedFactRoots) != len(rules) || checkpoint.MatcherEvaluationsInInputUnit < 0 || checkpoint.MatcherEvaluationsInInputUnit > runtime.program.MaxMatcherEvaluationsPerInputUnit || checkpoint.MatcherInputBytesInInputUnit < 0 || checkpoint.MatcherInputBytesInInputUnit > runtime.program.MaxMatcherInputBytesPerInputUnit || checkpoint.CandidateByteOffset < checkpoint.InputStartByteOffset || checkpoint.CandidateByteOffset > checkpoint.InputEndByteOffsetExclusive {
		return fmt.Errorf("documentation derivation checkpoint has invalid rule or matcher progress")
	}
	for index, progress := range checkpoint.RuleProgress {
		if progress.RuleID != rules[index].rule.RuleID || progress.MatchCount < 0 || progress.MatchCount > rules[index].rule.MaximumMatches || progress.LastAcceptedEndOffset < occurrence.locator.ByteStartOffset || progress.LastAcceptedEndOffset > occurrence.locator.ByteEndOffsetExclusive {
			return fmt.Errorf("documentation derivation checkpoint rule progress %d is invalid", index)
		}
		if !isLowerSHA256(checkpoint.RuleDerivedFactRoots[index]) {
			return fmt.Errorf("documentation derivation checkpoint rule %d has an invalid fact-sequence accumulator", index)
		}
	}
	return nil
}

func (builder *exactDocumentationPageBuilder) flush(terminalForInputUnit, terminalForSourceMember, terminalForExecution bool) (exactDocumentationDerivationPage, error) {
	runtime := builder.runtime
	checkpoint := builder.checkpoint
	if checkpoint.OutputPageOrdinal >= runtime.program.MaxOutputPagesPerRun {
		return exactDocumentationDerivationPage{}, fmt.Errorf("documentation derivation exceeds max_output_pages_per_run %d", runtime.program.MaxOutputPagesPerRun)
	}
	pageFactCount := int64(len(builder.facts))
	if checkpoint.CumulativeFactCount > runtime.program.MaxOutputFactsPerRun-pageFactCount {
		return exactDocumentationDerivationPage{}, fmt.Errorf("documentation derivation exceeds max_output_facts_per_run %d", runtime.program.MaxOutputFactsPerRun)
	}
	if checkpoint.CumulativeCanonicalFactBytes > runtime.program.MaxOutputBytesPerRun-builder.canonicalFactBytes {
		return exactDocumentationDerivationPage{}, fmt.Errorf("documentation derivation exceeds max_output_bytes_per_run %d", runtime.program.MaxOutputBytesPerRun)
	}
	pageOutcomeCount := int64(len(builder.outcomes))
	if checkpoint.CumulativeOutcomeCount > runtime.program.MaxOccurrenceOutcomesPerRun-pageOutcomeCount {
		return exactDocumentationDerivationPage{}, fmt.Errorf("documentation derivation exceeds max_occurrence_outcomes_per_run %d", runtime.program.MaxOccurrenceOutcomesPerRun)
	}
	if checkpoint.CumulativeCanonicalOutcomeBytes > runtime.program.MaxCanonicalOutcomeBytesPerRun-builder.canonicalOutcomeBytes {
		return exactDocumentationDerivationPage{}, fmt.Errorf("documentation derivation exceeds max_canonical_outcome_bytes_per_run %d", runtime.program.MaxCanonicalOutcomeBytesPerRun)
	}
	cumulativeOutcomeCount := checkpoint.CumulativeOutcomeCount + pageOutcomeCount
	cumulativeOutcomeBytes := checkpoint.CumulativeCanonicalOutcomeBytes + builder.canonicalOutcomeBytes
	if terminalForExecution && cumulativeOutcomeCount != runtime.expectedOutcomeCount {
		return exactDocumentationDerivationPage{}, fmt.Errorf("documentation derivation terminal outcome count %d does not equal preflight rule/classified-occurrence cross-product %d", cumulativeOutcomeCount, runtime.expectedOutcomeCount)
	}
	factRoot := exactDocumentationOrderedFactEnvelopeRoot(builder.factEnvelopes)
	outcomeRoot := stageCanonicalSetRoot(builder.outcomeEnvelopes)
	matcherCount := checkpoint.MatcherEvaluationsInInputUnit - builder.matcherEvaluationBase
	matcherInputBytes := checkpoint.MatcherInputBytesInInputUnit - builder.matcherInputByteBase
	state := exactDocumentationParserStateIdentity{
		StateKind: exactDocumentationDerivationParserStateKind, PredecessorStateDigest: checkpoint.PredecessorParserStateDigest,
		ProfileSHA256: runtime.reference.digest, ClassificationProofSHA256: runtime.proof.contentSHA256,
		SelectedOccurrenceID: checkpoint.SelectedOccurrenceID,
		InputStartByteOffset: checkpoint.InputStartByteOffset, InputEndByteOffsetExclusive: checkpoint.InputEndByteOffsetExclusive,
		OutputPageOrdinal: checkpoint.OutputPageOrdinal, FactIdentityRootSHA256: factRoot,
		RuleProgress:                      append([]exactDocumentationRuleProgress(nil), checkpoint.RuleProgress...),
		MatcherEvaluationsInInputUnit:     checkpoint.MatcherEvaluationsInInputUnit,
		MatcherEvaluationCount:            matcherCount,
		CumulativeMatcherEvaluationCount:  checkpoint.MatcherEvaluationsInRun,
		MatcherInputBytesInInputUnit:      checkpoint.MatcherInputBytesInInputUnit,
		MatcherInputByteCount:             matcherInputBytes,
		CumulativeMatcherInputByteCount:   checkpoint.MatcherInputBytesInRun,
		MatcherInputByteLimitPerInputUnit: runtime.program.MaxMatcherInputBytesPerInputUnit,
		MatcherInputByteLimitPerRun:       runtime.program.MaxMatcherInputBytesPerRun,
		OutcomeIdentityRootSHA256:         outcomeRoot, OutcomeCount: pageOutcomeCount,
		CanonicalOutcomeBytes:  builder.canonicalOutcomeBytes,
		CumulativeOutcomeCount: cumulativeOutcomeCount, CumulativeCanonicalOutcomeBytes: cumulativeOutcomeBytes,
		TerminalForInputUnit: terminalForInputUnit,
	}
	stateDigest, err := canonicalDocumentationDigest(state)
	if err != nil {
		return exactDocumentationDerivationPage{}, err
	}
	lastKind := exactDocumentationNoOutputKind
	lastIdentity := sha256Hex(nil)
	if len(builder.facts) > 0 {
		last := builder.facts[len(builder.facts)-1]
		lastKind = last.TargetRowKind
		lastIdentity = sha256Hex([]byte(last.FactID))
	}
	status := exactDocumentationDerivationResumable
	continuationDigest := sha256Hex(nil)
	var continuation *exactDocumentationDerivationContinuation
	if terminalForExecution {
		status = exactDocumentationDerivationPagingComplete
	} else {
		next, err := runtime.nextCheckpointAfterPage(checkpoint, terminalForInputUnit, terminalForSourceMember, stateDigest, pageFactCount, builder.canonicalFactBytes, pageOutcomeCount, builder.canonicalOutcomeBytes)
		if err != nil {
			return exactDocumentationDerivationPage{}, err
		}
		cursor := exactDocumentationDerivationContinuation{
			CursorKind: exactDocumentationDerivationCursorKind,
			ProfileID:  runtime.reference.id, ProfileVersion: runtime.reference.version, ProfileSHA256: runtime.reference.digest,
			ClassificationProofSHA256: runtime.proof.contentSHA256, SourceManifestRootSHA256: runtime.proof.evidenceSelectionRosterSHA256,
			LastOutputKind: lastKind, LastOutputIdentityHash: lastIdentity,
			OutputPageOrdinal: checkpoint.OutputPageOrdinal, NextCheckpoint: next,
		}
		cursor.ContinuationCursorSHA256, err = canonicalDocumentationDigest(exactDocumentationContinuationIdentityFor(cursor))
		if err != nil {
			return exactDocumentationDerivationPage{}, err
		}
		continuationDigest = cursor.ContinuationCursorSHA256
		continuation = &cursor
	}
	descriptor := exactDocumentationDerivationPageDescriptor{
		PageKind:  exactDocumentationDerivationPageKind,
		ProfileID: runtime.reference.id, ProfileVersion: runtime.reference.version, ProfileSHA256: runtime.reference.digest,
		Provider: runtime.proof.provider, ClassificationProofSHA256: runtime.proof.contentSHA256,
		SourceManifestRootSHA256: runtime.proof.evidenceSelectionRosterSHA256,
		SourceMemberSHA256:       checkpoint.SourceMemberSHA256, PredecessorLocatorID: checkpoint.PredecessorLocatorID,
		SelectedOccurrenceID: checkpoint.SelectedOccurrenceID,
		InputStartByteOffset: checkpoint.InputStartByteOffset, InputEndByteOffsetExclusive: checkpoint.InputEndByteOffsetExclusive,
		InputUnitLength:              checkpoint.InputEndByteOffsetExclusive - checkpoint.InputStartByteOffset,
		ParserStatePredecessorDigest: checkpoint.PredecessorParserStateDigest, ParserStateDigest: stateDigest,
		OutputPageOrdinal: checkpoint.OutputPageOrdinal, FactIdentityRootSHA256: factRoot,
		FactCount: pageFactCount, CanonicalFactBytes: builder.canonicalFactBytes, MatcherEvaluationCount: matcherCount,
		CumulativeMatcherEvaluationCount:  checkpoint.MatcherEvaluationsInRun,
		MatcherInputByteCount:             matcherInputBytes,
		MatcherInputBytesInInputUnit:      checkpoint.MatcherInputBytesInInputUnit,
		CumulativeMatcherInputByteCount:   checkpoint.MatcherInputBytesInRun,
		MatcherInputByteLimitPerInputUnit: runtime.program.MaxMatcherInputBytesPerInputUnit,
		MatcherInputByteLimitPerRun:       runtime.program.MaxMatcherInputBytesPerRun,
		OutcomeIdentityRootSHA256:         outcomeRoot, OutcomeCount: pageOutcomeCount,
		CanonicalOutcomeBytes:  builder.canonicalOutcomeBytes,
		CumulativeOutcomeCount: cumulativeOutcomeCount, CumulativeCanonicalOutcomeBytes: cumulativeOutcomeBytes,
		LastOutputKind: lastKind, LastOutputIdentityHash: lastIdentity, ContinuationCursorSHA256: continuationDigest,
		TerminalForInputUnit: terminalForInputUnit, TerminalForSourceMember: terminalForSourceMember, TerminalForExecution: terminalForExecution,
	}
	descriptor.PageSHA256, err = canonicalDocumentationDigest(exactDocumentationPageIdentityFor(descriptor))
	if err != nil {
		return exactDocumentationDerivationPage{}, err
	}
	return exactDocumentationDerivationPage{Descriptor: descriptor, ParserState: state, Facts: append([]exactDocumentationDerivedFact(nil), builder.facts...), Outcomes: append([]exactDocumentationDerivationOccurrenceOutcome(nil), builder.outcomes...), Status: status, Continuation: continuation}, nil
}

func (runtime exactDocumentationExecutionRuntime) nextCheckpointAfterPage(current exactDocumentationExecutionCheckpoint, terminalForInputUnit, terminalForSourceMember bool, predecessor string, addedFacts, addedBytes, addedOutcomes, addedOutcomeBytes int64) (exactDocumentationExecutionCheckpoint, error) {
	pageOrdinal := current.OutputPageOrdinal + 1
	if pageOrdinal <= current.OutputPageOrdinal {
		return exactDocumentationExecutionCheckpoint{}, fmt.Errorf("documentation derivation output page ordinal overflows INT64")
	}
	facts := current.CumulativeFactCount + addedFacts
	factBytes := current.CumulativeCanonicalFactBytes + addedBytes
	outcomes := current.CumulativeOutcomeCount + addedOutcomes
	outcomeBytes := current.CumulativeCanonicalOutcomeBytes + addedOutcomeBytes
	if !terminalForInputUnit {
		next := cloneExactDocumentationCheckpoint(current)
		next.OutputPageOrdinal = pageOrdinal
		next.CumulativeFactCount = facts
		next.CumulativeCanonicalFactBytes = factBytes
		next.CumulativeOutcomeCount = outcomes
		next.CumulativeCanonicalOutcomeBytes = outcomeBytes
		next.PredecessorParserStateDigest = predecessor
		return next, nil
	}
	if !terminalForSourceMember {
		next, err := runtime.checkpointForUnit(current.OccurrenceIndex, current.InputEndByteOffsetExclusive, pageOrdinal, facts, factBytes, current.MatcherEvaluationsInRun, current.MatcherInputBytesInRun, outcomes, outcomeBytes, predecessor)
		if err != nil {
			return exactDocumentationExecutionCheckpoint{}, err
		}
		next.RuleProgress = append([]exactDocumentationRuleProgress(nil), current.RuleProgress...)
		next.RuleDerivedFactRoots = append([]string(nil), current.RuleDerivedFactRoots...)
		return next, nil
	}
	return runtime.checkpointForUnit(current.OccurrenceIndex+1, runtime.occurrences[current.OccurrenceIndex+1].locator.ByteStartOffset, pageOrdinal, facts, factBytes, current.MatcherEvaluationsInRun, current.MatcherInputBytesInRun, outcomes, outcomeBytes, predecessor)
}

func exactDocumentationFactFromMatch(reference dependencyProfileReference, proof sourceClassificationSelectionProof, occurrence exactDocumentationSelectedOccurrence, rule exactDocumentationDerivationRule, compiled *regexp.Regexp, selected []byte, match []int, matchOrdinal int64, bodies map[string]exactEvidenceBody, maximumOutputBytes int64) (exactDocumentationDerivedFact, error) {
	var fact exactDocumentationDerivedFact
	captures, err := exactDocumentationMatchCaptures(compiled, selected, match)
	if err != nil {
		return fact, fmt.Errorf("documentation derivation rule %q match %d: %w", rule.RuleID, matchOrdinal, err)
	}
	matchStart := occurrence.locator.ByteStartOffset + int64(match[0])
	matchEnd := occurrence.locator.ByteStartOffset + int64(match[1])
	matchBytes := selected[match[0]:match[1]]
	matchProperties := documentationExactMatchProperties{selectedRangeSHA256: sha256Hex(matchBytes), selectedRangeByteCount: int64(len(matchBytes))}
	expansionBudget := &documentationTemplateExpansionBudget{remaining: maximumOutputBytes}
	resolved, err := resolveDocumentationOutputTemplate(rule.OutputFields, captures, matchProperties, expansionBudget)
	if err != nil {
		return fact, fmt.Errorf("documentation derivation rule %q match %d: %w", rule.RuleID, matchOrdinal, err)
	}
	output, err := json.Marshal(resolved)
	if err != nil {
		return fact, fmt.Errorf("documentation derivation rule %q output: %w", rule.RuleID, err)
	}
	canonicalOutput, err := canonicalizeCandidateJSON(output)
	if err != nil {
		return fact, fmt.Errorf("documentation derivation rule %q canonical output: %w", rule.RuleID, err)
	}
	if int64(len(canonicalOutput)) > maximumOutputBytes {
		return fact, fmt.Errorf("documentation derivation rule %q canonical output exceeds max_output_bytes_per_fact before fact-envelope allocation", rule.RuleID)
	}
	selectors, selectorRoot, memberIdentity, memberIdentityRoot, err := resolveExactDocumentationTargetCoordinates(rule, resolved, captures, expansionBudget)
	if err != nil {
		return fact, fmt.Errorf("documentation derivation rule %q target coordinates: %w", rule.RuleID, err)
	}
	matchSHA256 := sha256Hex(matchBytes)
	claimLocator := evidenceLocator{
		RowKind: "candidate_evidence_locator", EvidenceManifestSHA256: occurrence.locator.EvidenceManifestSHA256,
		SourceContentSHA256: occurrence.locator.SourceContentSHA256,
		ByteStartOffset:     matchStart, ByteEndOffsetExclusive: matchEnd,
		SelectedRangeByteCount: int64(len(matchBytes)), SelectedRangeSHA256: matchSHA256,
		SourceRefs: append([]string(nil), occurrence.locator.SourceRefs...), SourceURLs: append([]string(nil), occurrence.locator.SourceURLs...),
		LocatorSemantics: occurrence.locator.LocatorSemantics, SourceBytesPresent: false,
	}
	claimLocator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(claimLocator))
	if err := validateLocator(claimLocator, bodies); err != nil {
		return fact, fmt.Errorf("documentation derivation rule %q match %d claim locator: %w", rule.RuleID, matchOrdinal, err)
	}
	fact = exactDocumentationDerivedFact{
		Profile: reference, Provider: proof.provider, EvidenceRosterSHA256: proof.evidenceSelectionRosterSHA256,
		ClassificationBinding: occurrence.binding, ClassificationRole: occurrence.surfaceKind,
		RuleID: rule.RuleID, TargetArtifactRole: rule.TargetArtifactRole, TargetRowKind: rule.TargetRowKind,
		TargetBindingKind: rule.TargetBindingKind, TargetMemberJSONPointer: rule.TargetMemberJSONPointer,
		TargetRowSelector: selectors, TargetRowSelectorSHA256: selectorRoot,
		TargetMemberIdentity: memberIdentity, TargetMemberIdentitySHA256: memberIdentityRoot,
		InputSourceSymbol: rule.InputSourceSymbol, PredecessorLocatorID: occurrence.locator.ID,
		EvidenceLocatorID: claimLocator.ID, EvidenceLocator: claimLocator,
		MatchOrdinal: matchOrdinal, ByteStartOffset: matchStart, ByteEndOffsetExclusive: matchEnd,
		SelectedMatchSHA256: matchSHA256, ExactOutputFieldNames: append([]string(nil), rule.ExactOutputFieldNames...),
		CanonicalOutputFields: canonicalOutput,
	}
	fact.FactID = exactDocumentationDerivedFactID(fact)
	return fact, nil
}

func exactDocumentationSelectedOccurrences(program exactDocumentationDerivationProgram, proof sourceClassificationSelectionProof) ([]exactDocumentationSelectedOccurrence, error) {
	occurrences := make([]exactDocumentationSelectedOccurrence, 0)
	seen := map[string]struct{}{}
	for _, sourceSymbol := range program.InputSourceSymbols {
		selected := proof.classificationsBySourceSymbol[sourceSymbol]
		if len(selected) == 0 {
			return nil, fmt.Errorf("documentation derivation program has no selected classification occurrence for source_symbol %q", sourceSymbol)
		}
		for _, occurrence := range selected {
			if occurrence.SourceSymbol != sourceSymbol {
				return nil, fmt.Errorf("documentation derivation classification occurrence source_symbol does not equal its proof index")
			}
			id := stableID("dococc", lengthPrefixedIdentityKey(proof.contentSHA256, sourceSymbol, occurrence.Binding.ArtifactID, occurrence.Binding.ArtifactVersion, occurrence.Binding.ArtifactSHA256, occurrence.SurfaceKind, occurrence.Locator.ID))
			if _, duplicate := seen[id]; duplicate {
				return nil, fmt.Errorf("documentation derivation duplicates selected occurrence identity %s", id)
			}
			seen[id] = struct{}{}
			occurrences = append(occurrences, exactDocumentationSelectedOccurrence{id: id, sourceSymbol: sourceSymbol, binding: occurrence.Binding, surfaceKind: occurrence.SurfaceKind, locator: occurrence.Locator})
		}
	}
	sort.Slice(occurrences, func(i, j int) bool {
		left, right := occurrences[i], occurrences[j]
		if left.locator.SourceContentSHA256 != right.locator.SourceContentSHA256 {
			return left.locator.SourceContentSHA256 < right.locator.SourceContentSHA256
		}
		if left.locator.ByteStartOffset != right.locator.ByteStartOffset {
			return left.locator.ByteStartOffset < right.locator.ByteStartOffset
		}
		if left.locator.ByteEndOffsetExclusive != right.locator.ByteEndOffsetExclusive {
			return left.locator.ByteEndOffsetExclusive < right.locator.ByteEndOffsetExclusive
		}
		return lengthPrefixedIdentityKey(left.locator.ID, left.sourceSymbol, left.binding.ArtifactID, left.binding.ArtifactVersion, left.binding.ArtifactSHA256, left.surfaceKind) < lengthPrefixedIdentityKey(right.locator.ID, right.sourceSymbol, right.binding.ArtifactID, right.binding.ArtifactVersion, right.binding.ArtifactSHA256, right.surfaceKind)
	})
	return occurrences, nil
}

func exactDocumentationFactEnvelopeFor(fact exactDocumentationDerivedFact) exactDocumentationFactEnvelope {
	return exactDocumentationFactEnvelope{
		EnvelopeKind: exactDocumentationDerivationFactEnvelopeKind, FactID: fact.FactID,
		ProfileID: fact.Profile.id, ProfileVersion: fact.Profile.version, ProfileSHA256: fact.Profile.digest,
		Provider: fact.Provider, EvidenceRosterSHA256: fact.EvidenceRosterSHA256,
		ClassificationArtifactID: fact.ClassificationBinding.ArtifactID, ClassificationArtifactVersion: fact.ClassificationBinding.ArtifactVersion,
		ClassificationArtifactSHA256: fact.ClassificationBinding.ArtifactSHA256, ClassificationRole: fact.ClassificationRole,
		RuleID: fact.RuleID, TargetArtifactRole: fact.TargetArtifactRole, TargetRowKind: fact.TargetRowKind,
		TargetBindingKind: fact.TargetBindingKind, TargetMemberJSONPointer: fact.TargetMemberJSONPointer,
		TargetRowSelector: append([]exactDocumentationResolvedTargetRowSelector(nil), fact.TargetRowSelector...), TargetRowSelectorSHA256: fact.TargetRowSelectorSHA256,
		TargetMemberIdentity: append([]exactDocumentationResolvedMemberIdentity(nil), fact.TargetMemberIdentity...), TargetMemberIdentitySHA256: fact.TargetMemberIdentitySHA256,
		InputSourceSymbol: fact.InputSourceSymbol, PredecessorLocatorID: fact.PredecessorLocatorID,
		EvidenceLocatorID: fact.EvidenceLocatorID, EvidenceLocator: fact.EvidenceLocator,
		MatchOrdinal: fact.MatchOrdinal, ByteStartOffset: fact.ByteStartOffset, ByteEndOffsetExclusive: fact.ByteEndOffsetExclusive,
		SelectedMatchSHA256: fact.SelectedMatchSHA256, ExactOutputFieldNames: append([]string(nil), fact.ExactOutputFieldNames...),
		CanonicalOutputFields: json.RawMessage(fact.CanonicalOutputFields),
	}
}

func canonicalExactDocumentationFactEnvelopeBytes(fact exactDocumentationDerivedFact) ([]byte, error) {
	return canonicalDocumentationBytes(exactDocumentationFactEnvelopeFor(fact))
}

func exactDocumentationOrderedFactEnvelopeRoot(envelopes [][]byte) string {
	root := sha256Hex([]byte(exactDocumentationDerivationFactEnvelopeKind))
	for _, envelope := range envelopes {
		root = sha256Hex([]byte(lengthPrefixedIdentityKey(root, sha256Hex(envelope))))
	}
	return root
}

func exactDocumentationOrderedFactRoot(facts []exactDocumentationDerivedFact) string {
	envelopes := make([][]byte, len(facts))
	for index, fact := range facts {
		envelope, err := canonicalExactDocumentationFactEnvelopeBytes(fact)
		if err != nil {
			return ""
		}
		envelopes[index] = envelope
	}
	return exactDocumentationOrderedFactEnvelopeRoot(envelopes)
}

func equalExactDocumentationStringRosters(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type exactDocumentationPageSetAccumulator struct {
	reference                   dependencyProfileReference
	program                     exactDocumentationDerivationProgram
	proof                       sourceClassificationSelectionProof
	bodies                      map[string]exactEvidenceBody
	chainRoot                   string
	pageCount                   int64
	factCount                   int64
	factBytes                   int64
	matcherEvaluations          int64
	matcherInputBytes           int64
	outcomeCount                int64
	outcomeBytes                int64
	outcomeRows                 [][]byte
	seenFacts                   map[string]struct{}
	seenOutcomes                map[string]struct{}
	seenOutcomeCoordinates      map[string]struct{}
	factIDsByOutcomeCoordinate  map[string][]string
	ordinalsByOutcomeCoordinate map[string][]int64
	expectedOutcomeCoordinates  map[string]struct{}
	expectedOutcomeAuthorities  map[string]exactDocumentationOutcomeAuthority
	expectedOutcomeCount        int64
	replayRuntime               exactDocumentationExecutionRuntime
	replayCheckpoint            exactDocumentationExecutionCheckpoint
	replayComplete              bool
	priorDescriptor             *exactDocumentationDerivationPageDescriptor
	priorStatus                 string
	priorContinuation           *exactDocumentationDerivationContinuation
}

type exactDocumentationOutcomeAuthority struct {
	rule       exactDocumentationDerivationRule
	occurrence exactDocumentationSelectedOccurrence
}

func newExactDocumentationPageSetAccumulator(reference dependencyProfileReference, program exactDocumentationDerivationProgram, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody) (*exactDocumentationPageSetAccumulator, error) {
	expectedOutcomeCount, err := exactDocumentationOutcomeCrossProductCount(program, proof)
	if err != nil {
		return nil, err
	}
	if expectedOutcomeCount > program.MaxOccurrenceOutcomesPerRun {
		return nil, fmt.Errorf("documentation derivation rule/classified-occurrence cross-product %d exceeds max_occurrence_outcomes_per_run %d before page-set allocation", expectedOutcomeCount, program.MaxOccurrenceOutcomesPerRun)
	}
	expectedCoordinates := make(map[string]struct{}, expectedOutcomeCount)
	expectedAuthorities := make(map[string]exactDocumentationOutcomeAuthority, expectedOutcomeCount)
	selectedOccurrences, err := exactDocumentationSelectedOccurrences(program, proof)
	if err != nil {
		return nil, err
	}
	for _, rule := range program.OrderedRules {
		for _, occurrence := range selectedOccurrences {
			if occurrence.sourceSymbol != rule.InputSourceSymbol {
				continue
			}
			coordinate := exactDocumentationRuntimeOutcomeKey(occurrence, rule)
			if _, duplicate := expectedCoordinates[coordinate]; duplicate {
				return nil, fmt.Errorf("documentation derivation program/proof duplicates occurrence outcome coordinate")
			}
			expectedCoordinates[coordinate] = struct{}{}
			expectedAuthorities[coordinate] = exactDocumentationOutcomeAuthority{rule: rule, occurrence: occurrence}
		}
	}
	seed, err := canonicalDocumentationDigest(struct {
		Kind       string `json:"kind"`
		Profile    string `json:"profile_sha256"`
		Proof      string `json:"classification_proof_sha256"`
		SourceRoot string `json:"source_manifest_root_sha256"`
	}{exactDocumentationDerivationPageSetKind, reference.digest, proof.contentSHA256, proof.evidenceSelectionRosterSHA256})
	if err != nil {
		return nil, err
	}
	replayRuntime, err := prepareExactDocumentationExecution(reference, program, proof, bodies)
	if err != nil {
		return nil, fmt.Errorf("prepare documentation page-set deterministic replay: %w", err)
	}
	replayCheckpoint, err := replayRuntime.initialCheckpoint()
	if err != nil {
		return nil, fmt.Errorf("initialize documentation page-set deterministic replay: %w", err)
	}
	return &exactDocumentationPageSetAccumulator{reference: reference, program: program, proof: proof, bodies: bodies, chainRoot: seed, seenFacts: map[string]struct{}{}, seenOutcomes: map[string]struct{}{}, seenOutcomeCoordinates: map[string]struct{}{}, factIDsByOutcomeCoordinate: map[string][]string{}, ordinalsByOutcomeCoordinate: map[string][]int64{}, expectedOutcomeCoordinates: expectedCoordinates, expectedOutcomeAuthorities: expectedAuthorities, expectedOutcomeCount: expectedOutcomeCount, replayRuntime: replayRuntime, replayCheckpoint: replayCheckpoint}, nil
}

func (accumulator *exactDocumentationPageSetAccumulator) validateFactAuthority(fact exactDocumentationDerivedFact, authority exactDocumentationOutcomeAuthority) error {
	rule := authority.rule
	occurrence := authority.occurrence
	if fact.Profile.id != accumulator.reference.id || fact.Profile.version != accumulator.reference.version || fact.Profile.digest != accumulator.reference.digest || fact.Provider != accumulator.proof.provider || fact.EvidenceRosterSHA256 != accumulator.proof.evidenceSelectionRosterSHA256 {
		return fmt.Errorf("profile, provider, or evidence-roster coordinate differs from page-set authority")
	}
	if fact.RuleID != rule.RuleID || fact.InputSourceSymbol != rule.InputSourceSymbol || fact.TargetArtifactRole != rule.TargetArtifactRole || fact.TargetRowKind != rule.TargetRowKind || fact.TargetBindingKind != rule.TargetBindingKind || fact.TargetMemberJSONPointer != rule.TargetMemberJSONPointer || !equalExactDocumentationStringRosters(fact.ExactOutputFieldNames, rule.ExactOutputFieldNames) {
		return fmt.Errorf("rule or exact target coordinate differs from the admitted program")
	}
	if fact.ClassificationBinding != occurrence.binding || fact.ClassificationRole != occurrence.surfaceKind || fact.PredecessorLocatorID != occurrence.locator.ID {
		return fmt.Errorf("classification binding or selected occurrence differs from the sealed proof")
	}
	locator := fact.EvidenceLocator
	if locator.EvidenceManifestSHA256 != occurrence.locator.EvidenceManifestSHA256 || locator.SourceContentSHA256 != occurrence.locator.SourceContentSHA256 || locator.ByteStartOffset < occurrence.locator.ByteStartOffset || locator.ByteEndOffsetExclusive > occurrence.locator.ByteEndOffsetExclusive || locator.LocatorSemantics != occurrence.locator.LocatorSemantics || !equalExactDocumentationStringRosters(locator.SourceRefs, occurrence.locator.SourceRefs) || !equalExactDocumentationStringRosters(locator.SourceURLs, occurrence.locator.SourceURLs) {
		return fmt.Errorf("claim locator is outside or differs from its exact selected evidence occurrence")
	}
	if err := validateLocator(locator, accumulator.bodies); err != nil {
		return fmt.Errorf("claim locator does not hydrate to its exact body range: %w", err)
	}
	return nil
}

func (accumulator *exactDocumentationPageSetAccumulator) add(page exactDocumentationDerivationPage) error {
	if accumulator.replayComplete {
		return fmt.Errorf("documentation derivation page set supplies a page after deterministic replay completed")
	}
	expectedPage, err := accumulator.replayRuntime.generatePage(cloneExactDocumentationCheckpoint(accumulator.replayCheckpoint))
	if err != nil {
		return fmt.Errorf("documentation derivation page %d deterministic replay: %w", accumulator.pageCount, err)
	}
	expectedBytes, err := canonicalDocumentationBytes(exactDocumentationPageWireEnvelopeFor(expectedPage))
	if err != nil {
		return err
	}
	actualBytes, err := canonicalDocumentationBytes(exactDocumentationPageWireEnvelopeFor(page))
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedBytes, actualBytes) {
		return fmt.Errorf("documentation derivation page %d does not equal bounded deterministic replay of its exact program, proof, and evidence bytes", accumulator.pageCount)
	}
	if expectedPage.Descriptor.TerminalForExecution {
		accumulator.replayComplete = true
	} else {
		accumulator.replayCheckpoint = cloneExactDocumentationCheckpoint(expectedPage.Continuation.NextCheckpoint)
	}
	if page.Descriptor.OutputPageOrdinal != accumulator.pageCount || page.Descriptor.ProfileID != accumulator.reference.id || page.Descriptor.ProfileVersion != accumulator.reference.version || page.Descriptor.ProfileSHA256 != accumulator.reference.digest || page.Descriptor.Provider != accumulator.proof.provider || page.Descriptor.ClassificationProofSHA256 != accumulator.proof.contentSHA256 || page.Descriptor.SourceManifestRootSHA256 != accumulator.proof.evidenceSelectionRosterSHA256 {
		return fmt.Errorf("documentation derivation page %d has the wrong authority or ordinal", accumulator.pageCount)
	}
	if accumulator.pageCount >= accumulator.program.MaxOutputPagesPerRun {
		return fmt.Errorf("documentation derivation page set exceeds max_output_pages_per_run")
	}
	if accumulator.priorDescriptor == nil {
		genesis, err := exactDocumentationParserGenesis(accumulator.reference, accumulator.proof)
		if err != nil {
			return err
		}
		if page.Descriptor.ParserStatePredecessorDigest != genesis {
			return fmt.Errorf("documentation derivation first page is not rooted at parser genesis")
		}
	} else {
		if accumulator.priorContinuation == nil || page.Descriptor.ParserStatePredecessorDigest != accumulator.priorDescriptor.ParserStateDigest || !pageStartsAtCheckpoint(page.Descriptor, accumulator.priorContinuation.NextCheckpoint) {
			return fmt.Errorf("documentation derivation page %d does not start at its predecessor checkpoint", accumulator.pageCount)
		}
	}
	envelopes := make([][]byte, len(page.Facts))
	var bytesTotal int64
	for index, fact := range page.Facts {
		if err := validateExactDocumentationDerivedFactIntegrity(fact); err != nil {
			return fmt.Errorf("documentation derivation page %d fact %d: %w", accumulator.pageCount, index, err)
		}
		envelope, err := canonicalExactDocumentationFactEnvelopeBytes(fact)
		if err != nil {
			return err
		}
		if int64(len(envelope)) > accumulator.program.MaxOutputBytesPerFact {
			return fmt.Errorf("documentation derivation page fact exceeds per-fact byte cap")
		}
		envelopes[index] = envelope
		bytesTotal += int64(len(envelope))
		if _, duplicate := accumulator.seenFacts[fact.FactID]; duplicate {
			return fmt.Errorf("documentation derivation page set duplicates fact identity %s", fact.FactID)
		}
		accumulator.seenFacts[fact.FactID] = struct{}{}
		coordinate := exactDocumentationDerivationOutcomeKey(fact.RuleID, fact.InputSourceSymbol, fact.ClassificationBinding, fact.ClassificationRole, fact.PredecessorLocatorID)
		if _, expected := accumulator.expectedOutcomeCoordinates[coordinate]; !expected {
			return fmt.Errorf("documentation derivation page %d fact %d has no preflight rule/classified-occurrence coordinate", accumulator.pageCount, index)
		}
		if err := accumulator.validateFactAuthority(fact, accumulator.expectedOutcomeAuthorities[coordinate]); err != nil {
			return fmt.Errorf("documentation derivation page %d fact %d authority: %w", accumulator.pageCount, index, err)
		}
		accumulator.factIDsByOutcomeCoordinate[coordinate] = append(accumulator.factIDsByOutcomeCoordinate[coordinate], fact.FactID)
		accumulator.ordinalsByOutcomeCoordinate[coordinate] = append(accumulator.ordinalsByOutcomeCoordinate[coordinate], fact.MatchOrdinal)
	}
	root := exactDocumentationOrderedFactEnvelopeRoot(envelopes)
	if page.Descriptor.FactCount != int64(len(page.Facts)) || page.Descriptor.CanonicalFactBytes != bytesTotal || page.Descriptor.FactIdentityRootSHA256 != root || page.Descriptor.FactCount > accumulator.program.MaxOutputFactsPerPage || bytesTotal > accumulator.program.MaxOutputBytesPerPage {
		return fmt.Errorf("documentation derivation page %d fact envelope bytes/root/count disagree", accumulator.pageCount)
	}
	if page.Descriptor.MatcherEvaluationCount < 0 || accumulator.matcherEvaluations > accumulator.program.MaxMatcherEvaluationsPerRun-page.Descriptor.MatcherEvaluationCount || page.Descriptor.CumulativeMatcherEvaluationCount != accumulator.matcherEvaluations+page.Descriptor.MatcherEvaluationCount {
		return fmt.Errorf("documentation derivation page %d matcher totals exceed or disagree with max_matcher_evaluations_per_run", accumulator.pageCount)
	}
	if page.Descriptor.MatcherInputByteCount < 0 || accumulator.matcherInputBytes > accumulator.program.MaxMatcherInputBytesPerRun-page.Descriptor.MatcherInputByteCount || page.Descriptor.CumulativeMatcherInputByteCount != accumulator.matcherInputBytes+page.Descriptor.MatcherInputByteCount || page.Descriptor.MatcherInputBytesInInputUnit < page.Descriptor.MatcherInputByteCount || page.Descriptor.MatcherInputBytesInInputUnit > accumulator.program.MaxMatcherInputBytesPerInputUnit || page.Descriptor.MatcherInputByteLimitPerInputUnit != accumulator.program.MaxMatcherInputBytesPerInputUnit || page.Descriptor.MatcherInputByteLimitPerRun != accumulator.program.MaxMatcherInputBytesPerRun {
		return fmt.Errorf("documentation derivation page %d matcher input-byte totals or limits disagree with the run-pinned program", accumulator.pageCount)
	}
	outcomeRows := make([][]byte, 0, len(page.Outcomes))
	var outcomeBytes int64
	for index, outcome := range page.Outcomes {
		coordinate := exactDocumentationDerivationOutcomeKey(outcome.RuleID, outcome.InputSourceSymbol, classificationArtifactBinding{ArtifactID: outcome.ClassificationArtifactID, ArtifactVersion: outcome.ClassificationVersion, ArtifactSHA256: outcome.ClassificationSHA256}, outcome.ClassificationRole, outcome.PredecessorLocatorID)
		if _, expected := accumulator.expectedOutcomeCoordinates[coordinate]; !expected {
			return fmt.Errorf("documentation derivation page %d outcome %d has no preflight rule/classified-occurrence coordinate", accumulator.pageCount, index)
		}
		if _, duplicate := accumulator.seenOutcomeCoordinates[coordinate]; duplicate {
			return fmt.Errorf("documentation derivation page set duplicates occurrence outcome coordinate")
		}
		canonical, err := validateExactDocumentationDerivationOccurrenceOutcome(accumulator.reference, accumulator.proof, outcome)
		if err != nil {
			return fmt.Errorf("documentation derivation page %d outcome %d: %w", accumulator.pageCount, index, err)
		}
		if int64(len(canonical)) > accumulator.program.MaxCanonicalOutcomeBytesPerRun-outcomeBytes || accumulator.outcomeBytes > accumulator.program.MaxCanonicalOutcomeBytesPerRun-outcomeBytes-int64(len(canonical)) {
			return fmt.Errorf("documentation derivation page set exceeds max_canonical_outcome_bytes_per_run before outcome append")
		}
		if accumulator.outcomeCount+int64(len(outcomeRows)) >= accumulator.program.MaxOccurrenceOutcomesPerRun {
			return fmt.Errorf("documentation derivation page set exceeds max_occurrence_outcomes_per_run before outcome append")
		}
		if _, duplicate := accumulator.seenOutcomes[outcome.OutcomeID]; duplicate {
			return fmt.Errorf("documentation derivation page set duplicates outcome identity %s", outcome.OutcomeID)
		}
		expectedFactIDs := append([]string(nil), accumulator.factIDsByOutcomeCoordinate[coordinate]...)
		sort.Strings(expectedFactIDs)
		if !equalExactDocumentationStringRosters(expectedFactIDs, outcome.DerivedFactIDs) {
			return fmt.Errorf("documentation derivation page %d outcome %d fact roster disagrees with emitted facts", accumulator.pageCount, index)
		}
		ordinals := accumulator.ordinalsByOutcomeCoordinate[coordinate]
		sort.Slice(ordinals, func(i, j int) bool { return ordinals[i] < ordinals[j] })
		for ordinalIndex, ordinal := range ordinals {
			if ordinal != int64(ordinalIndex) {
				return fmt.Errorf("documentation derivation page %d outcome %d match ordinals are not exact contiguous execution progress", accumulator.pageCount, index)
			}
		}
		accumulator.seenOutcomes[outcome.OutcomeID] = struct{}{}
		accumulator.seenOutcomeCoordinates[coordinate] = struct{}{}
		delete(accumulator.factIDsByOutcomeCoordinate, coordinate)
		delete(accumulator.ordinalsByOutcomeCoordinate, coordinate)
		outcomeRows = append(outcomeRows, canonical)
		outcomeBytes += int64(len(canonical))
	}
	outcomeRoot := stageCanonicalSetRoot(outcomeRows)
	if page.Descriptor.OutcomeCount != int64(len(page.Outcomes)) || page.Descriptor.CanonicalOutcomeBytes != outcomeBytes || page.Descriptor.OutcomeIdentityRootSHA256 != outcomeRoot || page.Descriptor.CumulativeOutcomeCount != accumulator.outcomeCount+int64(len(page.Outcomes)) || page.Descriptor.CumulativeCanonicalOutcomeBytes != accumulator.outcomeBytes+outcomeBytes {
		return fmt.Errorf("documentation derivation page %d outcome envelope bytes/root/count disagree", accumulator.pageCount)
	}
	if page.ParserState.StateKind != exactDocumentationDerivationParserStateKind || page.ParserState.PredecessorStateDigest != page.Descriptor.ParserStatePredecessorDigest || page.ParserState.ProfileSHA256 != page.Descriptor.ProfileSHA256 || page.ParserState.ClassificationProofSHA256 != page.Descriptor.ClassificationProofSHA256 || page.ParserState.SelectedOccurrenceID != page.Descriptor.SelectedOccurrenceID || page.ParserState.InputStartByteOffset != page.Descriptor.InputStartByteOffset || page.ParserState.InputEndByteOffsetExclusive != page.Descriptor.InputEndByteOffsetExclusive || page.ParserState.OutputPageOrdinal != page.Descriptor.OutputPageOrdinal || page.ParserState.FactIdentityRootSHA256 != root || page.ParserState.MatcherEvaluationCount != page.Descriptor.MatcherEvaluationCount || page.ParserState.CumulativeMatcherEvaluationCount != page.Descriptor.CumulativeMatcherEvaluationCount || page.ParserState.MatcherInputBytesInInputUnit != page.Descriptor.MatcherInputBytesInInputUnit || page.ParserState.MatcherInputByteCount != page.Descriptor.MatcherInputByteCount || page.ParserState.CumulativeMatcherInputByteCount != page.Descriptor.CumulativeMatcherInputByteCount || page.ParserState.MatcherInputByteLimitPerInputUnit != page.Descriptor.MatcherInputByteLimitPerInputUnit || page.ParserState.MatcherInputByteLimitPerRun != page.Descriptor.MatcherInputByteLimitPerRun || page.ParserState.OutcomeIdentityRootSHA256 != outcomeRoot || page.ParserState.OutcomeCount != page.Descriptor.OutcomeCount || page.ParserState.CanonicalOutcomeBytes != page.Descriptor.CanonicalOutcomeBytes || page.ParserState.CumulativeOutcomeCount != page.Descriptor.CumulativeOutcomeCount || page.ParserState.CumulativeCanonicalOutcomeBytes != page.Descriptor.CumulativeCanonicalOutcomeBytes || page.ParserState.TerminalForInputUnit != page.Descriptor.TerminalForInputUnit {
		return fmt.Errorf("documentation derivation page %d parser state does not equal its descriptor", accumulator.pageCount)
	}
	stateDigest, err := canonicalDocumentationDigest(page.ParserState)
	if err != nil || stateDigest != page.Descriptor.ParserStateDigest {
		return fmt.Errorf("documentation derivation page %d parser state digest mismatch", accumulator.pageCount)
	}
	pageDigest, err := canonicalDocumentationDigest(exactDocumentationPageIdentityFor(page.Descriptor))
	if err != nil || pageDigest != page.Descriptor.PageSHA256 {
		return fmt.Errorf("documentation derivation page %d digest mismatch", accumulator.pageCount)
	}
	if page.Descriptor.TerminalForExecution {
		if page.Status != exactDocumentationDerivationPagingComplete || page.Continuation != nil || page.Descriptor.ContinuationCursorSHA256 != sha256Hex(nil) {
			return fmt.Errorf("documentation derivation terminal page has an invalid continuation posture")
		}
	} else {
		if page.Status != exactDocumentationDerivationResumable || page.Continuation == nil {
			return fmt.Errorf("documentation derivation nonterminal page has no continuation")
		}
		if err := validateExactDocumentationContinuation(*page.Continuation, accumulator.reference, accumulator.program, accumulator.proof); err != nil {
			return err
		}
		if page.Continuation.ContinuationCursorSHA256 != page.Descriptor.ContinuationCursorSHA256 {
			return fmt.Errorf("documentation derivation page continuation digest mismatch")
		}
		next := page.Continuation.NextCheckpoint
		if next.MatcherEvaluationsInRun != page.Descriptor.CumulativeMatcherEvaluationCount || next.MatcherInputBytesInRun != page.Descriptor.CumulativeMatcherInputByteCount || next.CumulativeFactCount != accumulator.factCount+int64(len(page.Facts)) || next.CumulativeCanonicalFactBytes != accumulator.factBytes+bytesTotal || next.CumulativeOutcomeCount != page.Descriptor.CumulativeOutcomeCount || next.CumulativeCanonicalOutcomeBytes != page.Descriptor.CumulativeCanonicalOutcomeBytes {
			return fmt.Errorf("documentation derivation page continuation does not carry its exact cumulative resource totals")
		}
	}
	if accumulator.factCount > accumulator.program.MaxOutputFactsPerRun-int64(len(page.Facts)) || accumulator.factBytes > accumulator.program.MaxOutputBytesPerRun-bytesTotal {
		return fmt.Errorf("documentation derivation page set exceeds run-pinned aggregate caps")
	}
	accumulator.factCount += int64(len(page.Facts))
	accumulator.factBytes += bytesTotal
	accumulator.matcherEvaluations += page.Descriptor.MatcherEvaluationCount
	accumulator.matcherInputBytes += page.Descriptor.MatcherInputByteCount
	accumulator.outcomeCount += int64(len(page.Outcomes))
	accumulator.outcomeBytes += outcomeBytes
	accumulator.outcomeRows = append(accumulator.outcomeRows, outcomeRows...)
	accumulator.pageCount++
	accumulator.chainRoot = sha256Hex([]byte(lengthPrefixedIdentityKey(accumulator.chainRoot, page.Descriptor.PageSHA256)))
	descriptorCopy := page.Descriptor
	accumulator.priorDescriptor = &descriptorCopy
	accumulator.priorStatus = page.Status
	if page.Continuation == nil {
		accumulator.priorContinuation = nil
	} else {
		continuationCopy := *page.Continuation
		continuationCopy.NextCheckpoint = cloneExactDocumentationCheckpoint(page.Continuation.NextCheckpoint)
		accumulator.priorContinuation = &continuationCopy
	}
	return nil
}

func (accumulator *exactDocumentationPageSetAccumulator) finish() (exactDocumentationDerivationPageSetSeal, error) {
	if accumulator.pageCount == 0 || accumulator.priorDescriptor == nil || !accumulator.priorDescriptor.TerminalForExecution || accumulator.priorStatus != exactDocumentationDerivationPagingComplete || !accumulator.replayComplete {
		return exactDocumentationDerivationPageSetSeal{}, fmt.Errorf("documentation derivation page set has no exact terminal page")
	}
	if accumulator.outcomeCount != accumulator.expectedOutcomeCount {
		return exactDocumentationDerivationPageSetSeal{}, fmt.Errorf("documentation derivation page set outcome count %d does not equal preflight rule/classified-occurrence cross-product %d", accumulator.outcomeCount, accumulator.expectedOutcomeCount)
	}
	if len(accumulator.seenOutcomeCoordinates) != len(accumulator.expectedOutcomeCoordinates) || len(accumulator.factIDsByOutcomeCoordinate) != 0 || len(accumulator.ordinalsByOutcomeCoordinate) != 0 {
		return exactDocumentationDerivationPageSetSeal{}, fmt.Errorf("documentation derivation page set does not close every exact rule/classified-occurrence fact roster")
	}
	outcomeRoot := stageCanonicalSetRoot(accumulator.outcomeRows)
	identity := exactDocumentationPageSetIdentity{PageSetKind: exactDocumentationDerivationPageSetKind, ProfileID: accumulator.reference.id, ProfileVersion: accumulator.reference.version, ProfileSHA256: accumulator.reference.digest, Provider: accumulator.proof.provider, ClassificationProofSHA256: accumulator.proof.contentSHA256, SourceManifestRootSHA256: accumulator.proof.evidenceSelectionRosterSHA256, PageCount: accumulator.pageCount, FactCount: accumulator.factCount, CanonicalFactBytes: accumulator.factBytes, MatcherEvaluationCount: accumulator.matcherEvaluations, MatcherInputByteCount: accumulator.matcherInputBytes, MatcherInputByteLimitPerInputUnit: accumulator.program.MaxMatcherInputBytesPerInputUnit, MatcherInputByteLimitPerRun: accumulator.program.MaxMatcherInputBytesPerRun, OutcomeCount: accumulator.outcomeCount, CanonicalOutcomeBytes: accumulator.outcomeBytes, OutcomeSetRootSHA256: outcomeRoot, OrderedPageChainRootSHA256: accumulator.chainRoot, Status: exactDocumentationDerivationPagingComplete}
	root, err := canonicalDocumentationDigest(identity)
	if err != nil {
		return exactDocumentationDerivationPageSetSeal{}, err
	}
	return exactDocumentationDerivationPageSetSeal{PageSetKind: exactDocumentationDerivationPageSetKind, Profile: accumulator.reference, Provider: accumulator.proof.provider, ClassificationProofSHA256: accumulator.proof.contentSHA256, SourceManifestRootSHA256: accumulator.proof.evidenceSelectionRosterSHA256, PageCount: accumulator.pageCount, FactCount: accumulator.factCount, CanonicalFactBytes: accumulator.factBytes, MatcherEvaluationCount: accumulator.matcherEvaluations, MatcherInputByteCount: accumulator.matcherInputBytes, MatcherInputByteLimitPerInputUnit: accumulator.program.MaxMatcherInputBytesPerInputUnit, MatcherInputByteLimitPerRun: accumulator.program.MaxMatcherInputBytesPerRun, OutcomeCount: accumulator.outcomeCount, CanonicalOutcomeBytes: accumulator.outcomeBytes, OutcomeSetRootSHA256: outcomeRoot, OrderedPageChainRootSHA256: accumulator.chainRoot, PageSetRootSHA256: root, Status: exactDocumentationDerivationPagingComplete}, nil
}

func sealExactDocumentationDerivationPageSet(reference dependencyProfileReference, program exactDocumentationDerivationProgram, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody, pages []exactDocumentationDerivationPage) (exactDocumentationDerivationPageSetSeal, error) {
	_ = bodies // Deliberately corpus-scan-free: supplied pages carry exact envelopes and chained checkpoints.
	accumulator, err := newExactDocumentationPageSetAccumulator(reference, program, proof, bodies)
	if err != nil {
		return exactDocumentationDerivationPageSetSeal{}, err
	}
	for _, page := range pages {
		if err := accumulator.add(page); err != nil {
			return exactDocumentationDerivationPageSetSeal{}, err
		}
	}
	return accumulator.finish()
}

func pageStartsAtCheckpoint(descriptor exactDocumentationDerivationPageDescriptor, checkpoint exactDocumentationExecutionCheckpoint) bool {
	return descriptor.OutputPageOrdinal == checkpoint.OutputPageOrdinal && descriptor.SourceMemberSHA256 == checkpoint.SourceMemberSHA256 && descriptor.PredecessorLocatorID == checkpoint.PredecessorLocatorID && descriptor.SelectedOccurrenceID == checkpoint.SelectedOccurrenceID && descriptor.InputStartByteOffset == checkpoint.InputStartByteOffset && descriptor.InputEndByteOffsetExclusive == checkpoint.InputEndByteOffsetExclusive && descriptor.ParserStatePredecessorDigest == checkpoint.PredecessorParserStateDigest
}

func validateExactDocumentationContinuation(cursor exactDocumentationDerivationContinuation, reference dependencyProfileReference, program exactDocumentationDerivationProgram, proof sourceClassificationSelectionProof) error {
	if cursor.CursorKind != exactDocumentationDerivationCursorKind || cursor.ProfileID != reference.id || cursor.ProfileVersion != reference.version || cursor.ProfileSHA256 != reference.digest {
		return fmt.Errorf("documentation derivation continuation has the wrong profile coordinate")
	}
	if cursor.ClassificationProofSHA256 != proof.contentSHA256 || cursor.SourceManifestRootSHA256 != proof.evidenceSelectionRosterSHA256 {
		return fmt.Errorf("documentation derivation continuation has the wrong sealed classification proof")
	}
	if !isLowerSHA256(cursor.ProfileSHA256) || !isLowerSHA256(cursor.ClassificationProofSHA256) || !isLowerSHA256(cursor.SourceManifestRootSHA256) || !isLowerSHA256(cursor.LastOutputIdentityHash) || !isLowerSHA256(cursor.ContinuationCursorSHA256) || cursor.OutputPageOrdinal < 0 || cursor.LastOutputKind == "" || cursor.NextCheckpoint.OutputPageOrdinal != cursor.OutputPageOrdinal+1 || cursor.NextCheckpoint.OutputPageOrdinal >= program.MaxOutputPagesPerRun {
		return fmt.Errorf("documentation derivation continuation is structurally invalid")
	}
	expected, err := canonicalDocumentationDigest(exactDocumentationContinuationIdentityFor(cursor))
	if err != nil {
		return err
	}
	if cursor.ContinuationCursorSHA256 != expected {
		return fmt.Errorf("documentation derivation continuation hash does not equal its canonical tuple")
	}
	return nil
}

func exactDocumentationContinuationIdentityFor(cursor exactDocumentationDerivationContinuation) exactDocumentationContinuationIdentity {
	return exactDocumentationContinuationIdentity{CursorKind: cursor.CursorKind, ProfileID: cursor.ProfileID, ProfileVersion: cursor.ProfileVersion, ProfileSHA256: cursor.ProfileSHA256, ClassificationProofSHA256: cursor.ClassificationProofSHA256, SourceManifestRootSHA256: cursor.SourceManifestRootSHA256, LastOutputKind: cursor.LastOutputKind, LastOutputIdentityHash: cursor.LastOutputIdentityHash, OutputPageOrdinal: cursor.OutputPageOrdinal, NextCheckpoint: cloneExactDocumentationCheckpoint(cursor.NextCheckpoint)}
}

func exactDocumentationPageIdentityFor(descriptor exactDocumentationDerivationPageDescriptor) exactDocumentationPageIdentity {
	return exactDocumentationPageIdentity{PageKind: descriptor.PageKind, ProfileID: descriptor.ProfileID, ProfileVersion: descriptor.ProfileVersion, ProfileSHA256: descriptor.ProfileSHA256, Provider: descriptor.Provider, ClassificationProofSHA256: descriptor.ClassificationProofSHA256, SourceManifestRootSHA256: descriptor.SourceManifestRootSHA256, SourceMemberSHA256: descriptor.SourceMemberSHA256, PredecessorLocatorID: descriptor.PredecessorLocatorID, SelectedOccurrenceID: descriptor.SelectedOccurrenceID, InputStartByteOffset: descriptor.InputStartByteOffset, InputEndByteOffsetExclusive: descriptor.InputEndByteOffsetExclusive, InputUnitLength: descriptor.InputUnitLength, ParserStatePredecessorDigest: descriptor.ParserStatePredecessorDigest, ParserStateDigest: descriptor.ParserStateDigest, OutputPageOrdinal: descriptor.OutputPageOrdinal, FactIdentityRootSHA256: descriptor.FactIdentityRootSHA256, FactCount: descriptor.FactCount, CanonicalFactBytes: descriptor.CanonicalFactBytes, MatcherEvaluationCount: descriptor.MatcherEvaluationCount, CumulativeMatcherEvaluationCount: descriptor.CumulativeMatcherEvaluationCount, MatcherInputByteCount: descriptor.MatcherInputByteCount, MatcherInputBytesInInputUnit: descriptor.MatcherInputBytesInInputUnit, CumulativeMatcherInputByteCount: descriptor.CumulativeMatcherInputByteCount, MatcherInputByteLimitPerInputUnit: descriptor.MatcherInputByteLimitPerInputUnit, MatcherInputByteLimitPerRun: descriptor.MatcherInputByteLimitPerRun, OutcomeIdentityRootSHA256: descriptor.OutcomeIdentityRootSHA256, OutcomeCount: descriptor.OutcomeCount, CanonicalOutcomeBytes: descriptor.CanonicalOutcomeBytes, CumulativeOutcomeCount: descriptor.CumulativeOutcomeCount, CumulativeCanonicalOutcomeBytes: descriptor.CumulativeCanonicalOutcomeBytes, LastOutputKind: descriptor.LastOutputKind, LastOutputIdentityHash: descriptor.LastOutputIdentityHash, ContinuationCursorSHA256: descriptor.ContinuationCursorSHA256, TerminalForInputUnit: descriptor.TerminalForInputUnit, TerminalForSourceMember: descriptor.TerminalForSourceMember, TerminalForExecution: descriptor.TerminalForExecution}
}

func exactDocumentationCursorForPage(page exactDocumentationDerivationPage) exactDocumentationDerivationContinuation {
	if page.Continuation == nil {
		return exactDocumentationDerivationContinuation{}
	}
	return *page.Continuation
}

func equalDocumentationContinuations(left, right *exactDocumentationDerivationContinuation) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftBytes, leftErr := canonicalDocumentationBytes(left)
	rightBytes, rightErr := canonicalDocumentationBytes(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func cloneExactDocumentationCheckpoint(input exactDocumentationExecutionCheckpoint) exactDocumentationExecutionCheckpoint {
	clone := input
	clone.RuleProgress = append([]exactDocumentationRuleProgress(nil), input.RuleProgress...)
	clone.RuleDerivedFactRoots = append([]string(nil), input.RuleDerivedFactRoots...)
	return clone
}

func canonicalDocumentationBytes(value interface{}) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical documentation paging value: %w", err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize documentation paging value: %w", err)
	}
	return canonical, nil
}

func canonicalDocumentationDigest(value interface{}) (string, error) {
	canonical, err := canonicalDocumentationBytes(value)
	if err != nil {
		return "", err
	}
	return sha256Hex(canonical), nil
}
