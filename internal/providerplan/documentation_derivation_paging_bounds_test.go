package providerplan

import (
	"errors"
	"regexp/syntax"
	"strings"
	"testing"
)

func TestExactDocumentationPatternAnalysisBoundsAndRefusals(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pattern    string
		wantWidth  int64
		wantLine   bool
		wantErrSub string
	}{
		{name: "utf8 literal", pattern: "é", wantWidth: 2},
		{name: "character class", pattern: "[a界]", wantWidth: 3},
		{name: "any rune", pattern: ".", wantWidth: 4},
		{name: "bounded repeat", pattern: "ab{2,3}", wantWidth: 4},
		{name: "case folded literal", pattern: "(?i)k", wantWidth: 3},
		{name: "leading multiline alternatives", pattern: "(?m)(?:^a|^b)", wantWidth: 1, wantLine: true},
		{name: "whole text anchor", pattern: "^a", wantErrSub: "whole-text anchors"},
		{name: "word boundary", pattern: `\ba`, wantErrSub: "word-boundary"},
		{name: "misplaced multiline anchor", pattern: "(?m)(?:^a|b)", wantErrSub: "must lead every alternative"},
		{name: "unbounded width", pattern: "a+", wantErrSub: "unbounded"},
		{name: "invalid syntax", pattern: "(", wantErrSub: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			analysis, err := analyzeFiniteDocumentationPattern(tc.pattern)
			if tc.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("analyze(%q) error=%v, want %q", tc.pattern, err, tc.wantErrSub)
				}
				return
			}
			if err != nil || analysis.MaximumUTF8Bytes != tc.wantWidth || analysis.RequiresLineStart != tc.wantLine {
				t.Fatalf("analyze(%q)=%+v err=%v, want width=%d line=%t", tc.pattern, analysis, err, tc.wantWidth, tc.wantLine)
			}
		})
	}
	if got := maxFoldedRuneUTF8Len(-1, false); got != 3 {
		t.Fatalf("invalid rune width=%d, want RuneError width 3", got)
	}
	parsed, err := syntax.Parse("(?m)(?:^a|^b)", syntax.Perl)
	if err != nil || !regexpSyntaxRequiresLeadingLineStart(parsed) {
		t.Fatalf("leading multiline alternatives parsed=%v err=%v", parsed, err)
	}
}

func TestExactDocumentationPagingCanonicalHelpersRejectTampering(t *testing.T) {
	if equalDocumentationContinuations(nil, &exactDocumentationDerivationContinuation{}) || !equalDocumentationContinuations(nil, nil) {
		t.Fatal("nil continuation equality is not exact")
	}
	left := &exactDocumentationDerivationContinuation{CursorKind: "cursor", OutputPageOrdinal: 1}
	right := *left
	if !equalDocumentationContinuations(left, &right) {
		t.Fatal("identical continuations compare unequal")
	}
	right.OutputPageOrdinal++
	if equalDocumentationContinuations(left, &right) {
		t.Fatal("tampered continuation compared equal")
	}
	checkpoint := exactDocumentationExecutionCheckpoint{RuleProgress: []exactDocumentationRuleProgress{{RuleID: "r"}}, RuleDerivedFactRoots: []string{"root"}}
	clone := cloneExactDocumentationCheckpoint(checkpoint)
	clone.RuleProgress[0].RuleID = "changed"
	clone.RuleDerivedFactRoots[0] = "changed"
	if checkpoint.RuleProgress[0].RuleID != "r" || checkpoint.RuleDerivedFactRoots[0] != "root" {
		t.Fatal("checkpoint clone aliases mutable execution state")
	}
	bytes, err := canonicalDocumentationBytes(map[string]interface{}{"z": 1, "a": "value"})
	if err != nil || string(bytes) != `{"a":"value","z":1}` {
		t.Fatalf("canonical bytes=%q err=%v", bytes, err)
	}
	if digest, err := canonicalDocumentationDigest(map[string]interface{}{"a": "value", "z": 1}); err != nil || !isLowerSHA256(digest) {
		t.Fatalf("canonical digest=%q err=%v", digest, err)
	}
	if _, err := canonicalDocumentationBytes(func() {}); err == nil || !strings.Contains(err.Error(), "marshal") {
		t.Fatalf("function value canonicalization error=%v", err)
	}
}

func TestExactDocumentationRuntimeRefusesUnreachableUnitsAndMalformedSelection(t *testing.T) {
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, []byte("| amount | Decimal | Required |\n"), 1, 1, 160, 8, 4096)
	runtime, err := prepareExactDocumentationExecution(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.initialCheckpoint(); err != nil {
		t.Fatalf("initial checkpoint: %v", err)
	}
	if _, err := runtime.checkpointForUnit(-1, 0, 0, 0, 0, 0, 0, 0, 0, "predecessor"); err == nil || !strings.Contains(err.Error(), "occurrence index") {
		t.Fatalf("negative occurrence checkpoint error=%v", err)
	}
	occurrence := runtime.occurrences[0]
	if _, err := runtime.exactUTF8UnitEnd(occurrence, occurrence.locator.ByteEndOffsetExclusive); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("end-boundary unit error=%v", err)
	}
	delete(runtime.selectedBytes, occurrence.id)
	if _, err := runtime.exactUTF8UnitEnd(occurrence, occurrence.locator.ByteStartOffset); err == nil || !strings.Contains(err.Error(), "cannot hydrate") {
		t.Fatalf("missing selected bytes error=%v", err)
	}
	if _, err := runtime.selectedOccurrenceBytes(occurrence); err == nil || !strings.Contains(err.Error(), "no once-validated") {
		t.Fatalf("missing selected occurrence bytes error=%v", err)
	}

	missingSource := program
	missingSource.InputSourceSymbols = append([]string{"missing_source"}, program.InputSourceSymbols...)
	if _, err := exactDocumentationSelectedOccurrences(missingSource, proof); err == nil || !strings.Contains(err.Error(), "no selected") {
		t.Fatalf("missing source selection error=%v", err)
	}
	wrongIndexProof := proof
	wrongIndexProof.classificationsBySourceSymbol = make(map[string][]sourceClassificationOccurrence, len(proof.classificationsBySourceSymbol))
	for source, rows := range proof.classificationsBySourceSymbol {
		wrongIndexProof.classificationsBySourceSymbol[source] = append([]sourceClassificationOccurrence(nil), rows...)
	}
	for source, rows := range wrongIndexProof.classificationsBySourceSymbol {
		rows[0].SourceSymbol = source + "_tampered"
		wrongIndexProof.classificationsBySourceSymbol[source] = rows
		break
	}
	if _, err := exactDocumentationSelectedOccurrences(program, wrongIndexProof); err == nil || !strings.Contains(err.Error(), "does not equal") {
		t.Fatalf("wrong proof index error=%v", err)
	}
	duplicateProof := proof
	duplicateProof.classificationsBySourceSymbol = make(map[string][]sourceClassificationOccurrence, len(proof.classificationsBySourceSymbol))
	for source, rows := range proof.classificationsBySourceSymbol {
		duplicateProof.classificationsBySourceSymbol[source] = append(append([]sourceClassificationOccurrence(nil), rows...), rows[0])
	}
	if _, err := exactDocumentationSelectedOccurrences(program, duplicateProof); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("duplicate selected occurrence error=%v", err)
	}
	if _, err := exactDocumentationOutcomeCrossProductCount(exactDocumentationDerivationProgram{}, proof); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty cross product error=%v", err)
	}
}

func TestExactDocumentationRuntimeAccountingAndCheckpointRefusals(t *testing.T) {
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, []byte("| amount | Decimal | Required |\n"), 1, 1, 160, 8, 4096)
	newRuntime := func() exactDocumentationExecutionRuntime {
		runtime, err := prepareExactDocumentationExecution(reference, program, proof, bodies)
		if err != nil {
			t.Fatal(err)
		}
		return runtime
	}

	runtime := newRuntime()
	checkpoint, err := runtime.initialCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.chargeMatcherInputBytes(&checkpoint, 0); err == nil || !strings.Contains(err.Error(), "no exact") {
		t.Fatalf("zero-byte matcher charge error=%v", err)
	}
	if selected, err := runtime.selectedOccurrenceBytes(runtime.occurrences[0]); err != nil || len(selected) == 0 {
		t.Fatalf("validated selected occurrence bytes=%q err=%v", selected, err)
	}
	short := runtime.selectedBytes[runtime.occurrences[0].id][:1]
	runtime.selectedBytes[runtime.occurrences[0].id] = short
	if _, err := runtime.selectedOccurrenceBytes(runtime.occurrences[0]); err == nil || !strings.Contains(err.Error(), "no once-validated") {
		t.Fatalf("short selected occurrence error=%v", err)
	}
	runtime.program.MaxMatcherInputBytesPerInputUnit = 1
	if err := runtime.chargeMatcherInputBytes(&checkpoint, 2); err == nil || !strings.Contains(err.Error(), "input unit exceeds") {
		t.Fatalf("per-unit matcher charge error=%v", err)
	}

	runtime = newRuntime()
	checkpoint, err = runtime.initialCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	runtime.program.MaxMatcherInputBytesPerRun = 1
	if err := runtime.chargeMatcherInputBytes(&checkpoint, 2); err == nil || !strings.Contains(err.Error(), "execution exceeds") {
		t.Fatalf("per-run matcher charge error=%v", err)
	}

	runtime = newRuntime()
	checkpoint, err = runtime.initialCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	occurrence := runtime.occurrences[0]
	rule := runtime.rules[occurrence.sourceSymbol][0].rule
	if err := runtime.recordDerivedFact(&checkpoint, occurrence, rule, 0, ""); err == nil || !strings.Contains(err.Error(), "empty fact") {
		t.Fatalf("empty fact identity error=%v", err)
	}
	if err := runtime.recordDerivedFact(&checkpoint, occurrence, rule, 0, "fact-a"); err != nil {
		t.Fatalf("record fact: %v", err)
	}
	checkpoint.RuleProgress[0].MatchCount = 1
	ids, err := runtime.derivedFactIDsForOutcome(checkpoint, occurrence, rule, 0)
	if err != nil || len(ids) != 1 || ids[0] != "fact-a" {
		t.Fatalf("derived fact IDs=%v err=%v", ids, err)
	}
	if err := runtime.validateDerivedFactAccumulators(checkpoint, occurrence, runtime.rules[occurrence.sourceSymbol]); err != nil {
		t.Fatalf("valid derived fact accumulators: %v", err)
	}
	tampered := cloneExactDocumentationCheckpoint(checkpoint)
	tampered.RuleDerivedFactRoots[0] = strings.Repeat("0", 64)
	if _, err := runtime.derivedFactIDsForOutcome(tampered, occurrence, rule, 0); err == nil || !strings.Contains(err.Error(), "disagrees") {
		t.Fatalf("tampered derived fact root error=%v", err)
	}
	if err := runtime.validateDerivedFactAccumulators(tampered, occurrence, runtime.rules[occurrence.sourceSymbol]); err == nil || !strings.Contains(err.Error(), "disagrees") {
		t.Fatalf("tampered accumulator validation error=%v", err)
	}

	runtime = newRuntime()
	checkpoint, err = runtime.initialCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.validateCheckpoint(checkpoint); err != nil {
		t.Fatalf("valid checkpoint: %v", err)
	}
	tampered = cloneExactDocumentationCheckpoint(checkpoint)
	tampered.CheckpointKind = "wrong"
	if err := runtime.validateCheckpoint(tampered); err == nil || !strings.Contains(err.Error(), "structurally invalid") {
		t.Fatalf("wrong checkpoint kind error=%v", err)
	}
	tampered = cloneExactDocumentationCheckpoint(checkpoint)
	tampered.SelectedOccurrenceID = "invented"
	if err := runtime.validateCheckpoint(tampered); err == nil || !strings.Contains(err.Error(), "wrong selected") {
		t.Fatalf("wrong selected occurrence error=%v", err)
	}
	tampered = cloneExactDocumentationCheckpoint(checkpoint)
	tampered.InputEndByteOffsetExclusive--
	if err := runtime.validateCheckpoint(tampered); err == nil || !strings.Contains(err.Error(), "UTF-8 rune boundary") {
		t.Fatalf("misaligned unit boundary error=%v", err)
	}
	tampered = cloneExactDocumentationCheckpoint(checkpoint)
	tampered.RuleIndex = int64(len(runtime.rules[occurrence.sourceSymbol])) + 1
	if err := runtime.validateCheckpoint(tampered); err == nil || !strings.Contains(err.Error(), "invalid rule") {
		t.Fatalf("invalid rule index error=%v", err)
	}
	if !equalExactDocumentationStringRosters([]string{"one", "two"}, []string{"one", "two"}) || equalExactDocumentationStringRosters([]string{"one"}, []string{"one", "two"}) || equalExactDocumentationStringRosters([]string{"one", "two"}, []string{"two", "one"}) {
		t.Fatal("string roster equality is not ordered and exact")
	}
}

func TestExactDocumentationPagingWrapperAndSealAreDeterministic(t *testing.T) {
	body := []byte(strings.Repeat("| amount | Decimal | Required |\n", 3))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 3, 3, 160, 1, 4096)
	var streamed []exactDocumentationDerivationPage
	if err := generateExactDocumentationDerivationPages(reference, program, proof, bodies, func(page exactDocumentationDerivationPage) error {
		streamed = append(streamed, page)
		return nil
	}); err != nil {
		t.Fatalf("stream pages: %v", err)
	}
	if len(streamed) < 2 || !streamed[len(streamed)-1].Descriptor.TerminalForExecution {
		t.Fatalf("streamed pages do not terminate deterministically: %d", len(streamed))
	}
	stop := errors.New("stop visitor")
	if err := generateExactDocumentationDerivationPages(reference, program, proof, bodies, func(exactDocumentationDerivationPage) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("visitor refusal error=%v", err)
	}
	seal, err := sealExactDocumentationDerivationPageSet(reference, program, proof, bodies, streamed)
	if err != nil {
		t.Fatalf("seal streamed pages: %v", err)
	}
	expected, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatalf("execute all pages: %v", err)
	}
	if len(expected.Pages) != len(streamed) || seal.PageSetRootSHA256 != expected.Seal.PageSetRootSHA256 {
		t.Fatalf("replay seal root=%q expected=%q pages=%d/%d", seal.PageSetRootSHA256, expected.Seal.PageSetRootSHA256, len(streamed), len(expected.Pages))
	}
	accumulator, err := newExactDocumentationPageSetAccumulator(reference, program, proof, bodies)
	if err != nil {
		t.Fatalf("new empty accumulator: %v", err)
	}
	if _, err := accumulator.finish(); err == nil || !strings.Contains(err.Error(), "no exact terminal") {
		t.Fatalf("empty accumulator finish error=%v", err)
	}
}
