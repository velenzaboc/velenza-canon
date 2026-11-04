package providerplan

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func bodyFreeScalabilityTarget() []byte {
	target := make([]byte, 0, stageEvidenceWrappedStreamingTargetBytes+1024)
	for block := 0; len(target) < stageEvidenceWrappedStreamingTargetBytes+1024; block++ {
		sum := sha256.Sum256([]byte(string(rune(block))))
		target = append(target, sum[:]...)
	}
	return target[:stageEvidenceWrappedStreamingTargetBytes+1024]
}

func TestBodyFreeWrappedStreamingRejectsLargeMultiOccurrenceLeak(t *testing.T) {
	target := bodyFreeScalabilityTarget()
	target = target[:len(target)-len(target)%3]
	carriers := make([]stageEvidenceCarrierOccurrence, 0, len(target)/3)
	for offset := 0; offset < len(target); offset += 3 {
		carriers = append(carriers, stageEvidenceCarrierOccurrence{representations: [][]byte{target[offset : offset+3]}, multiplicity: 1})
	}
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
		candidateBytesLimit:  512, // proves candidates are not retained by offset
	}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	reconstructed, err := stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex(target, &index, false, budget)
	if err != nil {
		t.Fatalf("streaming multi-occurrence leak scan: %v", err)
	}
	if !reconstructed {
		t.Fatal("large two-occurrence scalar leak was accepted")
	}
	if budget.candidateBytesUsed != 0 {
		t.Fatalf("streaming scan retained %d candidate bytes", budget.candidateBytesUsed)
	}
}

func TestBodyFreeWrappedStreamingProvesAbsenceWithoutCandidateCacheGrowth(t *testing.T) {
	target := bytes.Repeat([]byte("abcdef"), (stageEvidenceWrappedStreamingTargetBytes/6)+32)
	// This one occurrence matches every repeating target position, but its
	// multiplicity is one. It cannot be reused to reconstruct the body.
	carriers := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("abcdef")}, multiplicity: 1}}
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
		candidateBytesLimit:  512,
	}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	reconstructed, err := stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex(target, &index, false, budget)
	if err != nil {
		t.Fatalf("streaming harmless multi-profile scan: %v", err)
	}
	if reconstructed {
		t.Fatal("single scalar occurrence was incorrectly reusable")
	}
	if budget.candidateBytesUsed != 0 {
		t.Fatalf("streaming absence proof retained %d candidate bytes", budget.candidateBytesUsed)
	}
}

func TestBodyFreeWrappedStreamingRefusesTransientCandidateOverBudget(t *testing.T) {
	target := bytes.Repeat([]byte("abcdef"), (stageEvidenceWrappedStreamingTargetBytes/6)+32)
	carriers := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("abcdef")}, multiplicity: 12_000}}
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
		candidateBytesLimit:  31,
	}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	_, err = stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex(target, &index, false, budget)
	if err == nil || !strings.Contains(err.Error(), "candidate cache exceeds fixed auxiliary byte limit") {
		t.Fatalf("error = %v, want bounded transient-candidate refusal", err)
	}
}

func TestBodyFreeExactThreeFlowHonorsOccurrenceMultiplicity(t *testing.T) {
	// Two distinct scalar occurrences with the same value are independently
	// usable. The fixed-width flow edge must therefore carry the occurrence
	// group's multiplicity, rather than treating its target trigram edge as a
	// one-shot choice.
	carriers := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("abc")}, multiplicity: 2}}
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	handled, reconstructed, err := stageEvidenceTargetHasExactThreeWrappedSegmentation([]byte("abcabc"), &index, true, budget)
	if err != nil {
		t.Fatalf("fixed-width flow: %v", err)
	}
	if !handled || !reconstructed {
		t.Fatalf("fixed-width duplicate-occurrence reconstruction = handled:%t reconstructed:%t, want true/true", handled, reconstructed)
	}
	// The cascade uses the same fixed-width proof before it chooses cached or
	// streaming general search, so short association bodies cannot bypass it.
	cascadeBudget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	cascadeIndex, err := newStageEvidenceWrappedIndexBounded(carriers, cascadeBudget)
	if err != nil {
		t.Fatalf("build cascade wrapped index: %v", err)
	}
	reconstructed, err = stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex([]byte("abcabc"), &cascadeIndex, true, cascadeBudget)
	if err != nil || !reconstructed {
		t.Fatalf("cascade fixed-width duplicate-occurrence reconstruction = %t, %v", reconstructed, err)
	}
}

func TestBodyFreeExactThreeFlowProvesMultiplicityAbsence(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("abc")}, multiplicity: 1}}
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	handled, reconstructed, err := stageEvidenceTargetHasExactThreeWrappedSegmentation([]byte("abcabc"), &index, true, budget)
	if err != nil {
		t.Fatalf("fixed-width flow: %v", err)
	}
	if handled || reconstructed {
		t.Fatalf("fixed-width one-occurrence absence = handled:%t reconstructed:%t, want false/false fallthrough", handled, reconstructed)
	}
}

func TestBodyFreeExactThreeFlowFindsTerminalResidualCertificate(t *testing.T) {
	// A hexadecimal target need not be divisible by three.  The compressed
	// certificate keeps three-nibble grid cells and assigns the final 4/5-byte
	// residual to one distinct occurrence.
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("abc")}},
		{representations: [][]byte{[]byte("def12")}},
	}
	budget := &stageEvidenceSegmentationBudget{statesRemaining: stageEvidenceSegmentationMaxStates, comparisonsRemaining: stageEvidenceAggregateMaxComparisons}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	handled, reconstructed, err := stageEvidenceTargetHasExactThreeWrappedSegmentation([]byte("abcdef12"), &index, true, budget)
	if err != nil || !handled || !reconstructed {
		t.Fatalf("terminal residual certificate = handled:%t reconstructed:%t err:%v", handled, reconstructed, err)
	}
}

func TestBodyFreeTargetSpecificWrappedCapacityPrunesLooseScalarLengths(t *testing.T) {
	// Raw carrier length is deliberately not capacity: these long values share
	// only one three-byte target substring, so no segmentation can cover six.
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("xxxxxxxxabcxxxxxxxx")}},
	}
	budget := &stageEvidenceSegmentationBudget{statesRemaining: stageEvidenceSegmentationMaxStates, comparisonsRemaining: stageEvidenceAggregateMaxComparisons}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	feasible, err := stageEvidenceTargetHasWrappedMatchCapacity([]byte("abcdef"), &index, false, budget)
	if err != nil || feasible {
		t.Fatalf("target-specific capacity = %t, %v; want false, nil", feasible, err)
	}
}

func TestBodyFreeTargetSpecificWrappedSuffixCapacityPrunesBeforeMatching(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("xxxxxxxxabcxxxxxxxx")}}}
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: stageEvidenceAggregateMaxComparisons}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	feasible, err := stageEvidenceTargetHasWrappedMatchCapacity([]byte("abcdefgh"), &index, false, budget)
	if err != nil || feasible {
		t.Fatalf("target-specific suffix capacity = %t, %v; want false, nil", feasible, err)
	}
}

func bodyFreeBruteLongestCommonSubstring(target, representation []byte, foldHex bool) int {
	longest := 0
	for targetStart := range target {
		for representationStart := range representation {
			length := 0
			for targetStart+length < len(target) && representationStart+length < len(representation) {
				left, right := target[targetStart+length], representation[representationStart+length]
				if foldHex {
					left, right = stageEvidenceFoldHexByte(left), stageEvidenceFoldHexByte(right)
				}
				if left != right {
					break
				}
				length++
			}
			if length > longest {
				longest = length
			}
		}
	}
	return longest
}

// This oracle deliberately follows the compact index fan-out, rather than the
// input carrier slice. It catches a regression where a byte-deduplicated
// representation is attributed only to its first occurrence group.
func bodyFreeIndexedSuffixCapacityOracle(target []byte, index *stageEvidenceWrappedIndex, foldHex bool) int64 {
	maximums := make([]int, len(index.multiplicities))
	for _, representation := range index.representations {
		longest := bodyFreeBruteLongestCommonSubstring(target, representation.raw, foldHex)
		for occurrenceRef := representation.occurrenceStart; occurrenceRef < representation.occurrenceEnd; occurrenceRef++ {
			occurrence := index.occurrences[occurrenceRef]
			if longest > maximums[occurrence] {
				maximums[occurrence] = longest
			}
		}
	}
	var capacity int64
	for occurrence, longest := range maximums {
		capacity += int64(longest * index.multiplicities[occurrence])
	}
	return capacity
}

func TestBodyFreeTargetSpecificWrappedSuffixCapacityMatchesBruteForce(t *testing.T) {
	// This includes duplicate occurrence groups, alternate representations and
	// a longer nonmatching tail. The capacity must use the best alternative for
	// each group, not the raw length or an independently reusable alternative.
	target := []byte("abcdefghijk")
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("zzabczz"), []byte("defgh")}, multiplicity: 2},
		{representations: [][]byte{[]byte("ijk-very-long-nonmatching-tail")}},
	}
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 1}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	feasible, err := stageEvidenceTargetHasWrappedMatchCapacity(target, &index, false, budget)
	if err != nil {
		t.Fatalf("suffix capacity: %v", err)
	}
	wantCapacity := bodyFreeIndexedSuffixCapacityOracle(target, &index, false)
	if feasible != (wantCapacity >= int64(len(target))) {
		t.Fatalf("feasible = %t, want capacity %d against target %d", feasible, wantCapacity, len(target))
	}
	if budget.comparisonsRemaining != 1 {
		t.Fatalf("suffix automaton consumed comparison budget: %d", budget.comparisonsRemaining)
	}
}

func TestBodyFreeTargetSuffixAutomatonMatchesBruteForce(t *testing.T) {
	// Repetitions force clone states; checking every small target/carrier pair
	// against the direct quadratic definition protects the packed transition
	// representation from a subtle clone-edge aliasing regression.
	values := [][]byte{
		[]byte("ababa"), []byte("banana"), []byte("abcabc"), []byte("aaaaab"),
		[]byte("zzabcy"), []byte("cab"), []byte("nomatch"),
	}
	for _, target := range values {
		budget := &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: 1 << 20}
		automaton := stageEvidenceTargetSuffixAutomaton{
			states: make([]stageEvidenceTargetSuffixState, 1, 2*len(target)-1),
			edges:  make([]stageEvidenceTargetSuffixEdge, 0, 3*len(target)),
		}
		automaton.states[0].link, automaton.states[0].firstEdge = -1, -1
		for _, value := range target {
			if err := automaton.extend(value, budget); err != nil {
				t.Fatalf("build %q: %v", target, err)
			}
		}
		for _, representation := range values {
			got, err := automaton.longestCommonSubstring(representation, false, budget)
			if err != nil {
				t.Fatalf("scan %q / %q: %v", target, representation, err)
			}
			want := bodyFreeBruteLongestCommonSubstring(target, representation, false)
			if int(got) != want {
				t.Fatalf("longest(%q, %q) = %d, want %d", target, representation, got, want)
			}
		}
	}
}

func TestBodyFreeTargetSpecificWrappedSuffixCapacityFoldsHexAndHonorsDuplicates(t *testing.T) {
	// "AbCd" is shared by two groups but has different alternate
	// representations. The oracle validates both index fan-out and foldHex.
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("AbCd"), []byte("zzzz")}, multiplicity: 2},
		{representations: [][]byte{[]byte("AbCd"), []byte("efgh")}, multiplicity: 1},
	}
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 1}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	target := []byte("abcdefghijk")
	feasible, err := stageEvidenceTargetHasWrappedMatchCapacity(target, &index, true, budget)
	if err != nil || !feasible {
		t.Fatalf("folded duplicate suffix capacity = %t, %v; want true, nil", feasible, err)
	}
	if want := bodyFreeIndexedSuffixCapacityOracle(target, &index, true); want != 12 {
		t.Fatalf("folded index oracle capacity = %d, want 12", want)
	}
	if budget.comparisonsRemaining != 1 {
		t.Fatalf("suffix automaton consumed comparison budget: %d", budget.comparisonsRemaining)
	}
}

func TestBodyFreeTargetSpecificWrappedSuffixCapacityDeclinesOverLimit(t *testing.T) {
	// A declined optional proof must leave the exact matcher available, rather
	// than claiming an inconclusive oversized target is clean.
	target := bytes.Repeat([]byte("a"), 600_000)
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 1}
	index, err := newStageEvidenceWrappedIndexBounded([]stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("aaa")}, multiplicity: 2}}, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	workBefore := budget.scalarIndexWorkUsed
	feasible, err := stageEvidenceTargetHasWrappedMatchCapacity(target, &index, false, budget)
	if err != nil || !feasible {
		t.Fatalf("over-limit optional suffix gate = %t, %v; want true, nil", feasible, err)
	}
	if budget.scalarIndexWorkUsed != workBefore {
		t.Fatalf("declined optional gate consumed %d work", budget.scalarIndexWorkUsed-workBefore)
	}
}

func TestBodyFreeTargetSpecificWrappedSuffixCapacityUsesTwoChunksSafely(t *testing.T) {
	// A deliberately tiny bound forces [abcde][fghij]. The eight-byte carrier
	// crosses that boundary; treating its LCS as belonging to only one chunk
	// would incorrectly prune this real two-occurrence witness.
	target := []byte("abcdefghij")
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("cdefghij"), []byte("xxxxxxxx")}},
		{representations: [][]byte{[]byte("zzabcd"), []byte("nomatch")}},
	}
	budget := &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: 1 << 20}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	// 8 bytes for one uint32 occurrence-maxima vector plus 240 bytes permits
	// only five target bytes per packed SAM chunk.
	feasible, err := stageEvidenceTargetHasWrappedMatchCapacityBounded(target, &index, false, budget, 308)
	if err != nil || !feasible {
		t.Fatalf("two-chunk boundary capacity = %t, %v; want true, nil", feasible, err)
	}
	if got, err := stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex(target, &index, false, &stageEvidenceSegmentationBudget{statesRemaining: stageEvidenceSegmentationMaxStates, comparisonsRemaining: stageEvidenceAggregateMaxComparisons}); err != nil || !got {
		t.Fatalf("boundary witness = %t, %v; want true, nil", got, err)
	}
}

func TestBodyFreeEC2ShapedPerOffsetCapacityTightensTwoChunkBound(t *testing.T) {
	// Long supplemental scalar alternatives can have useful runs in both
	// target chunks while no occurrence can contribute their sum contiguously.
	// Multiplicity scales the one-offset maximum; it cannot reuse those runs.
	target := []byte("abcdefghijklmnopqrst")
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("abcdefXklmnop"), []byte("unrelated-long-alternate")}},
		{representations: [][]byte{[]byte("ghijYqrst"), []byte("another-long-alternate")}, multiplicity: 2},
	}
	budget := &stageEvidenceSegmentationBudget{statesRemaining: stageEvidenceSegmentationMaxStates, comparisonsRemaining: stageEvidenceAggregateMaxComparisons, scalarIndexWorkLimit: 1 << 20}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	// 16 bytes for the two retained maxima vectors plus 600 bytes for a
	// reusable 10-byte chunk SAM.
	loose, err := stageEvidenceTargetHasWrappedMatchCapacityBounded(target, &index, false, budget, 616)
	if err != nil || !loose {
		t.Fatalf("two-chunk capacity = %t, %v; want true, nil", loose, err)
	}
	tight, err := stageEvidenceTargetHasWrappedPerOffsetCapacity(target, &index, false, budget)
	if err != nil || tight {
		t.Fatalf("per-offset capacity = %t, %v; want false, nil", tight, err)
	}
}

func TestBodyFreeSingleChunkSuffixCapacityMatchesPerOffsetLegalFloor(t *testing.T) {
	// On one chunk the SAM LCS is exactly the per-offset maximum. In
	// particular, one- and two-byte coincidences must not become capacity.
	target := []byte("abcdefghijkl")
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("abXghi"), []byte("zzzz")}, multiplicity: 2},
		{representations: [][]byte{[]byte("def")}},
	}
	first := &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: 1 << 20, comparisonsRemaining: stageEvidenceAggregateMaxComparisons}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, first)
	if err != nil {
		t.Fatalf("build wrapped index: %v", err)
	}
	global, err := stageEvidenceTargetHasWrappedMatchCapacityBounded(target, &index, false, first, 2_000)
	if err != nil {
		t.Fatalf("single-chunk suffix capacity: %v", err)
	}
	second := &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: 1 << 20, comparisonsRemaining: stageEvidenceAggregateMaxComparisons}
	perOffset, err := stageEvidenceTargetHasWrappedPerOffsetCapacity(target, &index, false, second)
	if err != nil {
		t.Fatalf("single-chunk per-offset capacity: %v", err)
	}
	if global != perOffset || global {
		t.Fatalf("single chunk global/per-offset = %t/%t, want false/false", global, perOffset)
	}
}
