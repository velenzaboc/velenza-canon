package providerplan

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestStageEvidenceWrappedScalarIndexSharesCorpusWorkAcrossTargets(t *testing.T) {
	const (
		occurrences       = 16
		representationLen = 64 * 1024
	)
	carriers := make([]stageEvidenceCarrierOccurrence, occurrences)
	for occurrence := range carriers {
		carriers[occurrence].representations = [][]byte{bytes.Repeat([]byte{'z'}, representationLen)}
	}
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatal(err)
	}
	windows := int64(occurrences * (representationLen - stageEvidenceWrappedMinFragmentBytes + 1))
	chunks := int64(occurrences * ((representationLen - stageEvidenceWrappedMinFragmentBytes + 1 + stageEvidenceWrappedOffsetMask) / (stageEvidenceWrappedOffsetMask + 1)))
	relevanceWords := (chunks + 63) / 64
	wantWork := 2*chunks + relevanceWords + windows*8 + 2*(1<<16) + int64(len(index.pages))*(3*257+256) + 3*occurrences
	if budget.scalarIndexWorkUsed != wantWork {
		t.Fatalf("shared scalar index work = %d, want exact linear charge %d", budget.scalarIndexWorkUsed, wantWork)
	}
	comparisonStart := budget.comparisonsRemaining
	workStart := budget.scalarIndexWorkUsed
	for targetNumber := 0; targetNumber < 128; targetNumber++ {
		target := []byte("authority-body-target-with-no-z-trigram")
		if reconstructed, err := stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithIndex(target, &index, false, budget); err != nil || reconstructed {
			t.Fatalf("target %d two-occurrence result = %v, %v", targetNumber, reconstructed, err)
		}
		if reconstructed, err := stageEvidenceTargetHasWrappedSegmentationWithIndex(target, &index, false, budget); err != nil || reconstructed {
			t.Fatalf("target %d general result = %v, %v", targetNumber, reconstructed, err)
		}
	}
	wantTargetWork := int64(128 * (3 + 3*occurrences))
	if budget.comparisonsRemaining != comparisonStart || budget.scalarIndexWorkUsed-workStart != wantTargetWork {
		t.Fatalf("absent target trigrams used comparisons %d -> %d and scalar work delta %d, want zero corpus comparisons and exact linear target/occurrence work %d",
			comparisonStart, budget.comparisonsRemaining, budget.scalarIndexWorkUsed-workStart, wantTargetWork)
	}
}

func TestStageEvidenceWrappedScalarIndexReuseMatchesFreshAfterPrecedingTargetSequence(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("prefix-DEAD-suffix")}},
		{representations: [][]byte{[]byte("prefix-beef-suffix")}},
		{representations: [][]byte{[]byte("prefix-CAFE-suffix")}},
		{representations: [][]byte{[]byte("prefix-babe-suffix")}},
	}
	build := func() stageEvidenceWrappedIndex {
		t.Helper()
		index, err := newStageEvidenceWrappedIndexBounded(carriers, &stageEvidenceSegmentationBudget{})
		if err != nil {
			t.Fatalf("build wrapped scalar index: %v", err)
		}
		return index
	}
	query := func(index *stageEvidenceWrappedIndex, target []byte, foldHex bool) bool {
		t.Helper()
		budget := &stageEvidenceSegmentationBudget{
			statesRemaining:      stageEvidenceSegmentationMaxStates,
			comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
		}
		reconstructed, err := stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex(target, index, foldHex, budget)
		if err != nil {
			t.Fatalf("query %q foldHex=%v: %v", target, foldHex, err)
		}
		return reconstructed
	}

	reusedIndex := build()
	precedingTargets := [][]byte{
		[]byte("DEADxxxx"),
		[]byte("beefxxxx"),
		[]byte("CAFEbabe0000"),
		[]byte("DEADbeefCAFE0000"),
		[]byte("0000DEADbeefCAFE"),
	}
	for targetIndex, target := range precedingTargets {
		if query(&reusedIndex, target, false) {
			t.Fatalf("preceding target %d unexpectedly reconstructed", targetIndex)
		}
	}

	hexTarget := []byte("deadbeefcafebabe")
	reusedResult := query(&reusedIndex, hexTarget, true)
	freshIndex := build()
	freshResult := query(&freshIndex, hexTarget, true)
	if reusedResult != freshResult {
		t.Fatalf("reused wrapped index result = %v, fresh result = %v", reusedResult, freshResult)
	}
	if !reusedResult {
		t.Fatal("both reused and fresh wrapped indexes missed the exact folded-hex reconstruction")
	}
}

func TestStageEvidenceWrappedScalarIndexDetectsLateLeakAndMutationWithinFixedWork(t *testing.T) {
	body := []byte("late scalar carrier leak remains detectable after a large unrelated authority corpus")
	target := []byte(base64.StdEncoding.EncodeToString(body))
	split := len(target) / 2
	build := func(mutate bool) ([]stageEvidenceCarrierOccurrence, *stageEvidenceSegmentationBudget, stageEvidenceWrappedIndex) {
		carriers := make([]stageEvidenceCarrierOccurrence, 33)
		for occurrence := 0; occurrence < 31; occurrence++ {
			carriers[occurrence].representations = [][]byte{bytes.Repeat([]byte{'z'}, 32*1024)}
		}
		first := append([]byte("wrapper["), target[:split]...)
		first = append(first, ']')
		secondBody := bytes.Clone(target[split:])
		if mutate {
			secondBody[len(secondBody)/2] ^= 1
		}
		second := append([]byte("wrapper["), secondBody...)
		second = append(second, ']')
		carriers[31].representations = [][]byte{first}
		carriers[32].representations = [][]byte{second}
		budget := &stageEvidenceSegmentationBudget{
			statesRemaining:      stageEvidenceSegmentationMaxStates,
			comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
		}
		index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
		if err != nil {
			t.Fatal(err)
		}
		return carriers, budget, index
	}

	_, exactBudget, exactIndex := build(false)
	comparisonStart := exactBudget.comparisonsRemaining
	reconstructed, err := stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithIndex(target, &exactIndex, false, exactBudget)
	if err != nil || !reconstructed {
		t.Fatalf("late exact leak result = %v, %v", reconstructed, err)
	}
	comparisonsUsed := comparisonStart - exactBudget.comparisonsRemaining
	if comparisonsUsed <= 0 || comparisonsUsed > int64(len(target))*4 {
		t.Fatalf("late exact leak comparisons = %d, want positive bounded candidate verification", comparisonsUsed)
	}

	_, mutatedBudget, mutatedIndex := build(true)
	comparisonStart = mutatedBudget.comparisonsRemaining
	reconstructed, err = stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithIndex(target, &mutatedIndex, false, mutatedBudget)
	if err != nil || reconstructed {
		t.Fatalf("late mutated leak result = %v, %v", reconstructed, err)
	}
	comparisonsUsed = comparisonStart - mutatedBudget.comparisonsRemaining
	if comparisonsUsed <= 0 || comparisonsUsed > int64(len(target))*4 {
		t.Fatalf("late mutated leak comparisons = %d, want positive bounded candidate verification", comparisonsUsed)
	}
}

func TestStageEvidenceWrappedScalarIndexSharesCanonicalRepresentationMatchesAcrossOccurrences(t *testing.T) {
	target := make([]byte, 256)
	for index := range target {
		target[index] = byte(index % 251)
	}
	target[0], target[1], target[2] = 251, 252, 253
	shared := append([]byte("wrapper["), target...)
	shared = append(shared, ']')
	const occurrences = 256
	carriers := make([]stageEvidenceCarrierOccurrence, occurrences)
	for occurrence := range carriers {
		// The closure scanner canonicalizes byte-identical scalar
		// representations onto this exact shared allocation. They remain 256
		// distinct scalar occurrences, but matching the bytes is one operation.
		carriers[occurrence].representations = [][]byte{shared}
	}
	constructionBudget := &stageEvidenceSegmentationBudget{}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, constructionBudget)
	if err != nil {
		t.Fatal(err)
	}
	exactMatchComparisons := int64(len(target) - stageEvidenceWrappedMinFragmentBytes)
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: exactMatchComparisons}
	candidates, err := stageEvidenceIndexedWrappedCandidates(target, 0, &index, false, false, budget)
	if err != nil {
		t.Fatalf("shared canonical representation candidates: %v", err)
	}
	if len(candidates) != occurrences {
		t.Fatalf("shared canonical representation candidates = %d, want %d distinct occurrences", len(candidates), occurrences)
	}
	if budget.comparisonsRemaining != 0 {
		t.Fatalf("shared canonical representation left %d comparisons, want one exact post-trigram %d-byte match", budget.comparisonsRemaining, exactMatchComparisons)
	}
	for occurrence, candidate := range candidates {
		if candidate.occurrence != occurrence || candidate.length != len(target) {
			t.Fatalf("candidate %d = %+v, want occurrence %d length %d", occurrence, candidate, occurrence, len(target))
		}
	}

	witnessBudget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: int64(len(target)) * 4,
	}
	reconstructed, err := stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithIndex(target, &index, false, witnessBudget)
	if err != nil || !reconstructed {
		t.Fatalf("distinct shared-byte occurrence witness result = %v, %v", reconstructed, err)
	}
}

func TestStageEvidenceWrappedCascadeReusesTwoOccurrencePrefixCandidates(t *testing.T) {
	target := make([]byte, 48)
	for index := range target {
		target[index] = byte(index + 1)
	}
	shared := append([]byte{200, 201}, target[:24]...)
	shared = append(shared, 202)
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{shared}},
		{representations: [][]byte{shared}},
	}
	build := func() stageEvidenceWrappedIndex {
		index, err := newStageEvidenceWrappedIndexBounded(carriers, &stageEvidenceSegmentationBudget{})
		if err != nil {
			t.Fatal(err)
		}
		return index
	}

	cascadeBudget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	cascadeIndex := build()
	reconstructed, err := stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex(target, &cascadeIndex, false, cascadeBudget)
	if err != nil || reconstructed {
		t.Fatalf("cascade no-match result = %v, %v", reconstructed, err)
	}
	cascadeComparisons := stageEvidenceAggregateMaxComparisons - cascadeBudget.comparisonsRemaining

	directBudget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	directIndex := build()
	reconstructed, err = stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithIndex(target, &directIndex, false, directBudget)
	if err != nil || reconstructed {
		t.Fatalf("direct two-occurrence no-match result = %v, %v", reconstructed, err)
	}
	reconstructed, err = stageEvidenceTargetHasWrappedSegmentationWithIndex(target, &directIndex, false, directBudget)
	if err != nil || reconstructed {
		t.Fatalf("direct general no-match result = %v, %v", reconstructed, err)
	}
	directComparisons := stageEvidenceAggregateMaxComparisons - directBudget.comparisonsRemaining
	if saved := directComparisons - cascadeComparisons; saved < 24 {
		t.Fatalf("cascade comparisons = %d versus direct %d, saved %d; want at least one exact 24-byte prefix scan", cascadeComparisons, directComparisons, saved)
	}
}

func TestStageEvidenceWrappedLengthUpperBoundGateIsSoundAndComparisonFree(t *testing.T) {
	target := []byte("abcdefghi")
	build := func(carriers []stageEvidenceCarrierOccurrence) stageEvidenceWrappedIndex {
		index, err := newStageEvidenceWrappedIndexBounded(carriers, &stageEvidenceSegmentationBudget{})
		if err != nil {
			t.Fatal(err)
		}
		return index
	}
	query := func(index *stageEvidenceWrappedIndex) bool {
		budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 0}
		reachable, err := stageEvidenceTargetReachableWithWrappedLengthUpperBounds(target, index, false, budget)
		if err != nil {
			t.Fatal(err)
		}
		if budget.comparisonsRemaining != 0 {
			t.Fatalf("wrapped length upper-bound gate consumed %d equality comparisons", -budget.comparisonsRemaining)
		}
		return reachable
	}

	unreachable := build([]stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("wrap-abcXXXX")}},
		{representations: [][]byte{[]byte("unrelated-capacity")}},
	})
	if query(&unreachable) {
		t.Fatal("trigram/length upper-bound graph reached a target with no continuation trigram")
	}

	legal := build([]stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("wrap-abc")}},
		{representations: [][]byte{[]byte("wrap-def")}},
		{representations: [][]byte{[]byte("wrap-ghi")}},
	})
	if !query(&legal) {
		t.Fatal("trigram/length upper-bound graph rejected a legal three-occurrence reconstruction")
	}

	// The upper-bound graph deliberately admits lengths whose bytes were not
	// compared. That false positive must continue into, and be rejected by, the
	// exact occurrence-aware cascade rather than being accepted as a witness.
	overapproximation := build([]stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("wrap-abcXXXX")}},
		{representations: [][]byte{[]byte("wrap-ghi")}},
	})
	if !query(&overapproximation) {
		t.Fatal("expected the deliberately loose upper-bound graph to remain reachable")
	}
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	reconstructed, err := stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex(target, &overapproximation, false, budget)
	if err != nil || reconstructed {
		t.Fatalf("exact cascade accepted upper-bound-only path: reconstructed=%v error=%v", reconstructed, err)
	}
}

func TestStageEvidenceWrappedScalarIndexStorageAndLinearWorkBounds(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("abc")}}}
	const exactBytes = int64((1<<16)*4 + 8 + 16 + 128 + 128 + 8 + 8 + 48 + 4 + (257+256)*4)
	const exactWork = int64(1 + 1 + 1 + 1 + 10 + 2*(1<<16) + 3*257 + 256)
	budget := &stageEvidenceSegmentationBudget{indexBytesLimit: exactBytes, scalarIndexWorkLimit: exactWork}
	if _, err := newStageEvidenceWrappedIndexBounded(carriers, budget); err != nil {
		t.Fatalf("wrapped scalar index at exact storage/work bounds: %v", err)
	}
	if budget.indexBytesUsed != exactBytes || budget.scalarIndexWorkUsed != exactWork {
		t.Fatalf("wrapped scalar index charged bytes/work %d/%d, want %d/%d", budget.indexBytesUsed, budget.scalarIndexWorkUsed, exactBytes, exactWork)
	}
	budget = &stageEvidenceSegmentationBudget{indexBytesLimit: exactBytes - 1, scalarIndexWorkLimit: exactWork}
	if _, err := newStageEvidenceWrappedIndexBounded(carriers, budget); err == nil {
		t.Fatal("wrapped scalar index accepted storage bound minus one")
	}
	budget = &stageEvidenceSegmentationBudget{indexBytesLimit: exactBytes, scalarIndexWorkLimit: exactWork - 1}
	if _, err := newStageEvidenceWrappedIndexBounded(carriers, budget); err == nil {
		t.Fatal("wrapped scalar index accepted linear-work bound minus one")
	}
	budget = &stageEvidenceSegmentationBudget{indexBytesLimit: 7}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err == nil || index.profile.maxLengths != nil || index.longestScratch != nil || index.touchedScratch != nil {
		t.Fatalf("wrapped scalar index allocated before profile debit: index=%+v error=%v", index, err)
	}
	budget = &stageEvidenceSegmentationBudget{indexBytesLimit: 8 + 16 - 1}
	index, err = newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err == nil || index.profile.maxLengths == nil || index.longestScratch != nil || index.touchedScratch != nil {
		t.Fatalf("wrapped scalar scratch allocated before debit: index=%+v error=%v", index, err)
	}
}

func TestStageEvidenceWrappedTrigramFilterIsTargetCompleteAndDropsIrrelevantCorpus(t *testing.T) {
	bodies := map[string]exactEvidenceBody{
		"body": {Bytes: []byte("abcabc")},
		"hex":  {Bytes: []byte{0xde, 0xad}},
	}
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{bytes.Repeat([]byte{'z'}, 1<<20)}},
		{representations: [][]byte{[]byte("left[abc]tail")}},
		{representations: [][]byte{[]byte("right[abc]tail")}},
	}

	unfilteredBudget := &stageEvidenceSegmentationBudget{indexBytesLimit: 3 << 20}
	if _, err := newStageEvidenceWrappedIndexBounded(carriers, unfilteredBudget); err == nil {
		t.Fatal("unfiltered wrapped index unexpectedly fit the target-aware storage bound")
	}

	filteredBudget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
		indexBytesLimit:      3 << 20,
	}
	filter, err := newStageEvidenceWrappedTrigramFilter(bodies, filteredBudget)
	if err != nil {
		t.Fatalf("build target trigram filter: %v", err)
	}
	for _, key := range []uint32{
		stageEvidenceWrappedRawTrigram([]byte("abc"), 0),
		stageEvidenceWrappedRawTrigram([]byte("YWJ"), 0),
		stageEvidenceWrappedRawTrigram([]byte("DEA"), 0),
	} {
		if !filter.contains(key) {
			t.Fatalf("target trigram filter omitted governed key %06x", key)
		}
	}
	if filter.contains(stageEvidenceWrappedRawTrigram([]byte("zzz"), 0)) {
		t.Fatal("target trigram filter retained unrelated corpus trigram zzz")
	}

	index, err := newStageEvidenceWrappedIndexFilteredBounded(carriers, &filter, filteredBudget)
	if err != nil {
		t.Fatalf("target-filtered wrapped index: %v", err)
	}
	if postings := index.offsetsForTrigram(stageEvidenceWrappedRawTrigram([]byte("zzz"), 0)); len(postings) != 0 {
		t.Fatalf("target-filtered wrapped index retained %d unrelated zzz postings", len(postings))
	}
	reconstructed, err := stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithIndex([]byte("abcabc"), &index, false, filteredBudget)
	if err != nil || !reconstructed {
		t.Fatalf("target-filtered exact two-occurrence witness = %v, %v", reconstructed, err)
	}
}

func TestStageEvidenceWrappedTrigramFilterCanonicalizesHexTargetsOnce(t *testing.T) {
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	bodies := map[string]exactEvidenceBody{"body": {Bytes: body}}
	wantWork := int64(stageEvidenceWrappedFilterBytes)
	for encodingIndex := 0; encodingIndex < 6; encodingIndex++ {
		target, _, _ := canonicalEvidenceRawEncodingTarget(body, encodingIndex)
		wantWork += int64(len(target))
		if len(target) >= stageEvidenceWrappedMinFragmentBytes {
			wantWork += int64(len(target) - stageEvidenceWrappedMinFragmentBytes + 1)
		}
	}
	budget := &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: wantWork}
	filter, err := newStageEvidenceWrappedTrigramFilter(bodies, budget)
	if err != nil {
		t.Fatalf("canonical folded-hex filter at exact linear-work bound: %v", err)
	}
	if budget.scalarIndexWorkUsed != wantWork {
		t.Fatalf("canonical folded-hex filter work = %d, want %d", budget.scalarIndexWorkUsed, wantWork)
	}
	for _, value := range []string{"dea", "DEA", "dEa", "Bee", "bEE"} {
		if !filter.contains(stageEvidenceWrappedRawTrigram([]byte(value), 0)) {
			t.Fatalf("canonical folded-hex filter omitted case variant %q", value)
		}
	}
}

func TestStageEvidenceWrappedIndexKeysCanonicalizeHexEquivalenceClassOnce(t *testing.T) {
	for _, foldHex := range []bool{false, true} {
		budget := &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: 1}
		var keys []uint32
		err := stageEvidenceWrappedIndexKeys([]byte("DeA"), foldHex, budget, func(key uint32) error {
			keys = append(keys, key)
			return nil
		})
		if err != nil {
			t.Fatalf("foldHex=%v canonical key at exact work bound: %v", foldHex, err)
		}
		want := stageEvidenceWrappedRawTrigram([]byte("dea"), 0)
		if len(keys) != 1 || keys[0] != want {
			t.Fatalf("foldHex=%v keys = %06x, want one canonical key %06x", foldHex, keys, want)
		}
	}
}

func TestStageEvidenceWrappedScalarIndexIsLexicographicAndStable(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("zzzabcabc")}},
		{representations: [][]byte{[]byte("abcaaa")}},
	}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, &stageEvidenceSegmentationBudget{})
	if err != nil {
		t.Fatal(err)
	}
	var previousKey uint32
	var previousOffset uint32
	for position, offset := range index.offsets {
		key := index.trigram(offset)
		if position > 0 && (key < previousKey || key == previousKey && offset < previousOffset) {
			t.Fatalf("offset %d key/identity %06x/%08x follows %06x/%08x", position, key, offset, previousKey, previousOffset)
		}
		previousKey, previousOffset = key, offset
	}
	postings := index.offsetsForTrigram(uint32('a')<<16 | uint32('b')<<8 | uint32('c'))
	if len(postings) != 3 {
		t.Fatalf("abc postings = %d, want 3", len(postings))
	}
	for position, offset := range postings {
		wantOccurrence := 0
		if position == 2 {
			wantOccurrence = 1
		}
		occurrences := index.occurrencesForRepresentation(index.representationForOffset(offset))
		if len(occurrences) != 1 || occurrences[0] != wantOccurrence {
			t.Fatalf("abc posting %d occurrences = %v, want source-order occurrence %d", position, occurrences, wantOccurrence)
		}
	}
}

func TestStageEvidenceIndexedWrappedEndsGuardsAuxiliaryAllocationsLocally(t *testing.T) {
	exactOccurrences := int(stageEvidenceMaxOccurrenceAuxiliaryBytes / 16)
	index := stageEvidenceWrappedIndex{
		profile: stageEvidenceSegmentationProfile{maxLengths: make([]int, exactOccurrences)},
	}
	prefixLengths, suffixLengths, err := stageEvidenceIndexedWrappedEnds(nil, &index, false, &stageEvidenceSegmentationBudget{})
	if err != nil || len(prefixLengths) != exactOccurrences || len(suffixLengths) != exactOccurrences {
		t.Fatalf("wrapped ends exact auxiliary bound lengths=%d/%d error=%v", len(prefixLengths), len(suffixLengths), err)
	}

	index.profile.maxLengths = make([]int, exactOccurrences+1)
	prefixLengths, suffixLengths, err = stageEvidenceIndexedWrappedEnds(nil, &index, false, &stageEvidenceSegmentationBudget{})
	if err == nil || prefixLengths != nil || suffixLengths != nil {
		t.Fatalf("wrapped ends limit+1 allocated auxiliary slices: lengths=%v/%v error=%v", prefixLengths, suffixLengths, err)
	}
}

func TestStageEvidenceWrappedCandidateScratchIsPreGatedAndReset(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("prefix-abcdef-suffix")}},
		{representations: [][]byte{[]byte("second-abcdef-tail")}},
	}
	constructionBudget := &stageEvidenceSegmentationBudget{comparisonsRemaining: stageEvidenceAggregateMaxComparisons}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, constructionBudget)
	if err != nil {
		t.Fatal(err)
	}
	assertScratchReset := func() {
		t.Helper()
		if len(index.touchedScratch) != 0 {
			t.Fatalf("touched scratch retained %d occurrences", len(index.touchedScratch))
		}
		for occurrence, length := range index.longestScratch {
			if length != 0 {
				t.Fatalf("longest scratch occurrence %d retained length %d", occurrence, length)
			}
		}
	}

	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 1024, candidateBytesLimit: 63}
	candidates, err := stageEvidenceIndexedWrappedCandidates([]byte("abcdef"), 0, &index, false, false, budget)
	if err == nil || candidates != nil || budget.candidateBytesUsed != 0 {
		t.Fatalf("candidate backing allocation was not pre-gated: candidates=%v used=%d error=%v", candidates, budget.candidateBytesUsed, err)
	}
	assertScratchReset()

	budget = &stageEvidenceSegmentationBudget{comparisonsRemaining: 1024, candidateBytesLimit: 64}
	candidates, err = stageEvidenceIndexedWrappedCandidates([]byte("abcdef"), 0, &index, false, false, budget)
	if err != nil || len(candidates) != 2 || budget.candidateBytesUsed != 64 {
		t.Fatalf("exact candidate reservation result=%v used=%d error=%v", candidates, budget.candidateBytesUsed, err)
	}
	if candidates[0].occurrence != 0 || candidates[1].occurrence != 1 {
		t.Fatalf("candidate order = %v, want source occurrence order", candidates)
	}
	assertScratchReset()

	budget = &stageEvidenceSegmentationBudget{comparisonsRemaining: 5, candidateBytesLimit: 64}
	if candidates, err = stageEvidenceIndexedWrappedCandidates([]byte("abcdef"), 0, &index, false, false, budget); err == nil || candidates != nil {
		t.Fatalf("mid-scan comparison exhaustion result=%v error=%v", candidates, err)
	}
	assertScratchReset()
}

func TestStageEvidenceWrappedScalarIndexRetainsEveryLegalFragmentLength(t *testing.T) {
	target := []byte("abcdef")
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("wrap-abcX-abcd-wrap")}},
		{representations: [][]byte{[]byte("wrap-def-wrap")}},
	}
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatal(err)
	}
	reconstructed, err := stageEvidenceTargetHasWrappedSegmentationWithIndex(target, &index, false, budget)
	if err != nil || !reconstructed {
		t.Fatalf("legal shorter abc + def segmentation result = %v, %v", reconstructed, err)
	}
}

func TestStageEvidenceWrappedTwoOccurrenceCheckChargesOnlyLinearWork(t *testing.T) {
	const occurrences = 4096
	target := []byte("abcTTTTTTxyz")
	carriers := make([]stageEvidenceCarrierOccurrence, occurrences)
	for occurrence := range carriers {
		carriers[occurrence].representations = [][]byte{[]byte("abcq---rxyz")}
	}
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatal(err)
	}
	workBefore := budget.scalarIndexWorkUsed
	reconstructed, err := stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithIndex(target, &index, false, budget)
	if err != nil || reconstructed {
		t.Fatalf("two-occurrence linear no-match result = %v, %v", reconstructed, err)
	}
	// Two key constructions, two indexed posting scans, one end-normalization
	// scan, and two linear distinct-occurrence selection scans.
	wantDelta := int64(2 + 5*occurrences)
	if got := budget.scalarIndexWorkUsed - workBefore; got != wantDelta {
		t.Fatalf("two-occurrence work delta = %d, want exact linear charge %d", got, wantDelta)
	}
}

func TestStageEvidenceWrappedTwoOccurrenceCheckRejectsBelowTwoFragmentFloor(t *testing.T) {
	target := []byte("abcde")
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("wrap-abc-wrap")}},
		{representations: [][]byte{[]byte("wrap-cde-wrap")}},
	}
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatal(err)
	}
	reconstructed, err := stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithIndex(target, &index, false, budget)
	if err != nil || reconstructed {
		t.Fatalf("five-byte target cannot be composed from two three-byte-minimum fragments: result=%v error=%v", reconstructed, err)
	}
}

func TestPublicStageCompileDiagnosticClassifiesStateBoundWithoutReflectingDetails(t *testing.T) {
	want := "stage validation failed: analysis exceeded the deterministic state bound"
	for _, stateBound := range []error{
		stageEvidenceStateBoundError,
		stageEvidenceAggregateStateBoundError,
	} {
		secret := "ActualOpaqueCredentialValue123456"
		err := fmt.Errorf("selected material %s: %w", secret, stateBound)
		got := PublicStageCompileDiagnostic(err)
		if got != want {
			t.Fatalf("public state-bound diagnostic = %q, want %q", got, want)
		}
		if strings.Contains(got, secret) {
			t.Fatalf("public state-bound diagnostic reflected wrapped detail: %q", got)
		}
	}

	secret := "ActualOpaqueCredentialValue123456"
	got := PublicStageCompileDiagnostic(fmt.Errorf("stage material %s is invalid", secret))
	if got != "stage validation failed" {
		t.Fatalf("ordinary public validation diagnostic = %q, want generic content-neutral failure", got)
	}
	if strings.Contains(got, secret) {
		t.Fatalf("ordinary public validation diagnostic reflected wrapped detail: %q", got)
	}
}
