package providerplan

import (
	"fmt"
	"math"
	"sort"
)

// stageEvidenceSegmentationProfile is a target-independent capacity upper
// bound. It deliberately over-approximates representations that are too long
// for one particular target. That can only retain search work; it can never
// hide a legal segmentation.
type stageEvidenceSegmentationProfile struct {
	maxLengths    []int
	totalCapacity int64
	available     [256]int64
	hasFrequency  bool
}

type stageEvidenceWrappedRepresentation struct {
	occurrenceStart int
	occurrenceEnd   int
	base            int
	raw             []byte
}

type stageEvidenceWrappedCanonicalKey struct {
	start  *byte
	length int
}

type stageEvidenceWrappedRepresentationGroup struct {
	raw                []byte
	occurrenceCount    int
	occurrenceStart    int
	occurrenceNext     int
	lastOccurrenceSeen int
}

type stageEvidenceWrappedPrefixPage struct {
	starts       [257]uint32
	maxAvailable [256]uint32
}

// stageEvidenceWrappedIndex stores every eligible three-byte window of each
// canonical representation as one compact uint32 offset. Byte-identical scalar
// values already share one immutable allocation in the closure scanner, so
// their windows and exact byte comparisons are indexed once. The complete
// occurrence roster remains separate and is fanned out after a match; distinct
// occurrences therefore remain distinct for the one-use witness search.
type stageEvidenceWrappedIndex struct {
	representations []stageEvidenceWrappedRepresentation
	occurrences     []int
	multiplicities  []int
	offsets         []uint32
	prefixPages     []uint32
	pages           []stageEvidenceWrappedPrefixPage
	profile         stageEvidenceSegmentationProfile
	longestScratch  []int
	touchedScratch  []int
	trigramFilter   *stageEvidenceWrappedTrigramFilter
}

const (
	stageEvidenceWrappedOffsetBits  = 11
	stageEvidenceWrappedOffsetMask  = 1<<stageEvidenceWrappedOffsetBits - 1
	stageEvidenceWrappedMaxChunks   = 1 << (32 - stageEvidenceWrappedOffsetBits)
	stageEvidenceWrappedFilterBytes = 1 << 21
)

type stageEvidenceWrappedTrigramFilter struct {
	bits []byte
}

func newStageEvidenceWrappedTrigramFilter(bodies map[string]exactEvidenceBody, budget *stageEvidenceSegmentationBudget) (stageEvidenceWrappedTrigramFilter, error) {
	result := stageEvidenceWrappedTrigramFilter{}
	if err := budget.consumeIndexBytes(stageEvidenceWrappedFilterBytes); err != nil {
		return result, err
	}
	if err := budget.consumeScalarIndexWork(stageEvidenceWrappedFilterBytes); err != nil {
		return result, err
	}
	result.bits = make([]byte, stageEvidenceWrappedFilterBytes)
	digests := make([]string, 0, len(bodies))
	for digest := range bodies {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	for _, digest := range digests {
		body := bodies[digest].Bytes
		for encodingIndex := 0; encodingIndex < 6; encodingIndex++ {
			target, foldHex, _ := canonicalEvidenceRawEncodingTarget(body, encodingIndex)
			if err := budget.consumeScalarIndexWork(int64(len(target))); err != nil {
				return stageEvidenceWrappedTrigramFilter{}, err
			}
			for offset := 0; offset+stageEvidenceWrappedMinFragmentBytes <= len(target); offset++ {
				if foldHex {
					// Hex targets are already emitted in canonical lower case. Retain
					// one canonical key per target window; contains folds an indexed
					// carrier trigram before consulting the same bounded bitset. This
					// preserves every mixed-case witness without expanding as many as
					// eight equivalent case variants during target-filter creation.
					if err := budget.consumeScalarIndexWork(1); err != nil {
						return stageEvidenceWrappedTrigramFilter{}, err
					}
					result.add(stageEvidenceWrappedRawTrigram(target, offset))
					continue
				}
				if err := stageEvidenceWrappedIndexKeys(target[offset:], foldHex, budget, func(key uint32) error {
					result.add(key)
					return nil
				}); err != nil {
					return stageEvidenceWrappedTrigramFilter{}, err
				}
			}
		}
	}
	return result, nil
}

func (filter *stageEvidenceWrappedTrigramFilter) add(key uint32) {
	filter.bits[key>>3] |= byte(1) << uint(key&7)
}

func (filter *stageEvidenceWrappedTrigramFilter) contains(key uint32) bool {
	if filter == nil || filter.bits[key>>3]&(byte(1)<<uint(key&7)) != 0 {
		return true
	}
	folded, isHex := stageEvidenceWrappedFoldedHexTrigram(key)
	return isHex && filter.bits[folded>>3]&(byte(1)<<uint(folded&7)) != 0
}

func stageEvidenceWrappedRawTrigram(raw []byte, offset int) uint32 {
	return uint32(raw[offset])<<16 | uint32(raw[offset+1])<<8 | uint32(raw[offset+2])
}

func stageEvidenceWrappedFoldedHexTrigram(key uint32) (uint32, bool) {
	var folded uint32
	for shift := 16; shift >= 0; shift -= 8 {
		current := stageEvidenceFoldHexByte(byte(key >> uint(shift)))
		if !((current >= '0' && current <= '9') || (current >= 'a' && current <= 'f')) {
			return 0, false
		}
		folded = folded<<8 | uint32(current)
	}
	return folded, true
}

func stageEvidenceWrappedCanonicalTrigram(key uint32) uint32 {
	if folded, isHex := stageEvidenceWrappedFoldedHexTrigram(key); isHex {
		return folded
	}
	return key
}

func newStageEvidenceWrappedIndexBounded(carriers []stageEvidenceCarrierOccurrence, budget *stageEvidenceSegmentationBudget) (stageEvidenceWrappedIndex, error) {
	return newStageEvidenceWrappedIndexFilteredBounded(carriers, nil, budget)
}

func newStageEvidenceWrappedIndexFilteredBounded(carriers []stageEvidenceCarrierOccurrence, filter *stageEvidenceWrappedTrigramFilter, budget *stageEvidenceSegmentationBudget) (stageEvidenceWrappedIndex, error) {
	result := stageEvidenceWrappedIndex{}
	result.trigramFilter = filter
	if len(carriers) > stageEvidenceMaxCarrierOccurrences {
		return result, fmt.Errorf("body-free wrapped scalar index exceeds fixed occurrence-group limit %d", stageEvidenceMaxCarrierOccurrences)
	}
	if err := budget.consumeIndexBytes(int64(len(carriers)) * 8); err != nil {
		return result, err
	}
	result.multiplicities = make([]int, len(carriers))
	result.profile.maxLengths = make([]int, len(carriers))
	if err := budget.consumeIndexBytes(int64(len(carriers)) * 16); err != nil {
		return result, err
	}
	result.longestScratch = make([]int, len(carriers))
	result.touchedScratch = make([]int, 0, len(carriers))
	if err := budget.consumeIndexBytes(int64(1<<16) * 4); err != nil {
		return result, err
	}
	if err := budget.consumeScalarIndexWork(1 << 16); err != nil {
		return result, err
	}
	result.prefixPages = make([]uint32, 1<<16)
	var groupsByCanonical map[stageEvidenceWrappedCanonicalKey]int
	groups := []stageEvidenceWrappedRepresentationGroup{}
	var eligibleOccurrenceRefs int64
	for occurrence, carrier := range carriers {
		multiplicity := stageEvidenceCarrierOccurrenceMultiplicity(carrier)
		if multiplicity <= 0 {
			return result, fmt.Errorf("body-free wrapped scalar index occurrence group has nonpositive multiplicity")
		}
		result.multiplicities[occurrence] = multiplicity
		if len(carrier.representations) > stageEvidenceMaxRepresentationsPerOccurrence {
			return result, fmt.Errorf("body-free wrapped scalar index occurrence exceeds fixed representation limit %d", stageEvidenceMaxRepresentationsPerOccurrence)
		}
		for _, representation := range carrier.representations {
			if err := budget.consumeScalarIndexWork(1); err != nil {
				return result, err
			}
			if len(representation) > result.profile.maxLengths[occurrence] {
				result.profile.maxLengths[occurrence] = len(representation)
			}
			if len(representation) < stageEvidenceWrappedMinFragmentBytes {
				continue
			}
			key := stageEvidenceWrappedCanonicalKey{start: &representation[0], length: len(representation)}
			groupIndex, exists := groupsByCanonical[key]
			if !exists {
				if groupsByCanonical == nil {
					// Fixed map header/bucket allowance, charged before the first
					// canonical grouping allocation.
					if err := budget.consumeIndexBytes(128); err != nil {
						return result, err
					}
					groupsByCanonical = map[stageEvidenceWrappedCanonicalKey]int{}
				}
				// Conservative map-entry plus growable group-slice allowance.
				if err := budget.consumeIndexBytes(128); err != nil {
					return result, err
				}
				groupIndex = len(groups)
				groupsByCanonical[key] = groupIndex
				groups = append(groups, stageEvidenceWrappedRepresentationGroup{
					raw: representation, lastOccurrenceSeen: -1,
				})
			}
			group := &groups[groupIndex]
			if group.lastOccurrenceSeen == occurrence {
				continue
			}
			group.lastOccurrenceSeen = occurrence
			if eligibleOccurrenceRefs == math.MaxInt64 {
				return result, fmt.Errorf("body-free wrapped scalar occurrence roster overflows int64")
			}
			eligibleOccurrenceRefs++
			group.occurrenceCount++
		}
		length := result.profile.maxLengths[occurrence]
		if length != 0 && int64(multiplicity) > math.MaxInt64/int64(length) {
			return result, fmt.Errorf("body-free wrapped scalar index capacity overflows int64")
		}
		groupCapacity := int64(length) * int64(multiplicity)
		if groupCapacity > math.MaxInt64-result.profile.totalCapacity {
			return result, fmt.Errorf("body-free wrapped scalar index capacity overflows int64")
		}
		result.profile.totalCapacity += groupCapacity
	}
	if eligibleOccurrenceRefs > math.MaxInt64/8 {
		return result, fmt.Errorf("body-free wrapped scalar occurrence roster storage overflows int64")
	}
	if err := budget.consumeIndexBytes(eligibleOccurrenceRefs * 8); err != nil {
		return result, err
	}
	if err := budget.consumeScalarIndexWork(int64(len(groups))); err != nil {
		return result, err
	}
	var allWindows, candidateChunks int64
	for groupIndex := range groups {
		windowCount := len(groups[groupIndex].raw) - stageEvidenceWrappedMinFragmentBytes + 1
		if int64(windowCount) > math.MaxInt64-allWindows {
			return result, fmt.Errorf("body-free wrapped scalar index size overflows int64")
		}
		allWindows += int64(windowCount)
		groupChunks := int64((windowCount + stageEvidenceWrappedOffsetMask) / (stageEvidenceWrappedOffsetMask + 1))
		if groupChunks > math.MaxInt64-candidateChunks {
			return result, fmt.Errorf("body-free wrapped scalar index chunk roster overflows int64")
		}
		candidateChunks += groupChunks
	}
	if candidateChunks > math.MaxInt64-63 {
		return result, fmt.Errorf("body-free wrapped scalar index relevance bitmap overflows int64")
	}
	relevanceWordCount := (candidateChunks + 63) / 64
	if relevanceWordCount > int64(^uint(0)>>1) {
		return result, fmt.Errorf("body-free wrapped scalar index relevance bitmap exceeds local integer capacity")
	}
	if err := budget.consumeIndexBytes(relevanceWordCount * 8); err != nil {
		return result, err
	}
	if err := budget.consumeScalarIndexWork(relevanceWordCount); err != nil {
		return result, err
	}
	relevantChunks := make([]uint64, int(relevanceWordCount))
	var relevantChunkCandidateWindows, totalWindows, totalChunks int64
	var candidateChunk int64
	occurrenceCursor := 0
	for groupIndex := range groups {
		group := &groups[groupIndex]
		group.occurrenceStart = occurrenceCursor
		occurrenceCursor += group.occurrenceCount
		group.lastOccurrenceSeen = -1
		windowCount := len(group.raw) - stageEvidenceWrappedMinFragmentBytes + 1
		for chunkStart := 0; chunkStart < windowCount; chunkStart += stageEvidenceWrappedOffsetMask + 1 {
			chunkWindows := windowCount - chunkStart
			if chunkWindows > stageEvidenceWrappedOffsetMask+1 {
				chunkWindows = stageEvidenceWrappedOffsetMask + 1
			}
			relevant := false
			for local := 0; local < chunkWindows; local++ {
				if filter.contains(stageEvidenceWrappedRawTrigram(group.raw, chunkStart+local)) {
					relevant = true
					if totalWindows == math.MaxInt64 {
						return result, fmt.Errorf("body-free wrapped scalar index size overflows int64")
					}
					totalWindows++
				}
			}
			if relevant {
				relevantChunks[candidateChunk>>6] |= uint64(1) << uint(candidateChunk&63)
			}
			candidateChunk++
			if !relevant {
				continue
			}
			if totalChunks == math.MaxInt64 || int64(chunkWindows) > math.MaxInt64-relevantChunkCandidateWindows {
				return result, fmt.Errorf("body-free wrapped scalar index size overflows int64")
			}
			totalChunks++
			relevantChunkCandidateWindows += int64(chunkWindows)
		}
	}
	if candidateChunk != candidateChunks {
		return result, fmt.Errorf("body-free wrapped scalar index candidate chunk count mismatch: visited %d, expected %d", candidateChunk, candidateChunks)
	}
	if totalChunks > stageEvidenceWrappedMaxChunks {
		return result, fmt.Errorf("body-free wrapped scalar index exceeds fixed chunk limit %d", stageEvidenceWrappedMaxChunks)
	}
	if totalChunks > math.MaxInt64/48 || totalWindows > (math.MaxInt64-totalChunks*48)/4 {
		return result, fmt.Errorf("body-free wrapped scalar index storage overflows int64")
	}
	if err := budget.consumeIndexBytes(totalChunks*48 + totalWindows*4); err != nil {
		return result, err
	}
	if allWindows > math.MaxInt64-candidateChunks {
		return result, fmt.Errorf("body-free wrapped scalar index work overflows int64")
	}
	constructionWork := allWindows + candidateChunks
	if relevantChunkCandidateWindows > (math.MaxInt64-constructionWork)/3 {
		return result, fmt.Errorf("body-free wrapped scalar index work overflows int64")
	}
	constructionWork += 3 * relevantChunkCandidateWindows
	if totalWindows > (math.MaxInt64-constructionWork)/4 {
		return result, fmt.Errorf("body-free wrapped scalar index work overflows int64")
	}
	constructionWork += 4 * totalWindows
	if totalChunks > math.MaxInt64-constructionWork-(1<<16) {
		return result, fmt.Errorf("body-free wrapped scalar index work overflows int64")
	}
	// Exact globally bounded construction work before page allocation: one
	// complete relevance scan, one bitmap lookup per candidate chunk, three
	// relevance checks for each window in a retained chunk, one representation
	// append per retained chunk, four fixed operations per retained posting
	// (prefix count, suffix count, maximum-length update, and final placement),
	// initialization of the fixed prefix directory (charged before its
	// allocation above), and one complete directory scan. Bitmap initialization
	// was charged before its allocation. The sparse page work is charged after
	// the populated page count is known.
	if err := budget.consumeScalarIndexWork(constructionWork + totalChunks + (1 << 16)); err != nil {
		return result, err
	}
	result.representations = make([]stageEvidenceWrappedRepresentation, 0, int(totalChunks))
	result.occurrences = make([]int, int(eligibleOccurrenceRefs))
	result.offsets = make([]uint32, int(totalWindows))
	for occurrence, carrier := range carriers {
		for _, representation := range carrier.representations {
			if len(representation) < stageEvidenceWrappedMinFragmentBytes {
				continue
			}
			if err := budget.consumeScalarIndexWork(1); err != nil {
				return result, err
			}
			key := stageEvidenceWrappedCanonicalKey{start: &representation[0], length: len(representation)}
			group := &groups[groupsByCanonical[key]]
			if group.lastOccurrenceSeen == occurrence {
				continue
			}
			group.lastOccurrenceSeen = occurrence
			destination := group.occurrenceStart + group.occurrenceNext
			result.occurrences[destination] = occurrence
			group.occurrenceNext++
		}
	}
	candidateChunk = 0
	for groupIndex := range groups {
		group := &groups[groupIndex]
		windowCount := len(group.raw) - stageEvidenceWrappedMinFragmentBytes + 1
		for chunkStart := 0; chunkStart < windowCount; chunkStart += stageEvidenceWrappedOffsetMask + 1 {
			relevant := relevantChunks[candidateChunk>>6]&(uint64(1)<<uint(candidateChunk&63)) != 0
			candidateChunk++
			if !relevant {
				continue
			}
			result.representations = append(result.representations, stageEvidenceWrappedRepresentation{
				occurrenceStart: group.occurrenceStart,
				occurrenceEnd:   group.occurrenceStart + group.occurrenceCount,
				base:            chunkStart,
				raw:             group.raw,
			})
		}
	}
	if err := result.buildSortedOffsetsAndPrefixPages(budget); err != nil {
		return result, err
	}
	return result, nil
}

func (index *stageEvidenceWrappedIndex) buildSortedOffsetsAndPrefixPages(budget *stageEvidenceSegmentationBudget) error {
	// Count two-byte prefixes without retaining an unsorted offset copy.
	for chunk, representation := range index.representations {
		chunkWindows := len(representation.raw) - stageEvidenceWrappedMinFragmentBytes + 1 - representation.base
		if chunkWindows > stageEvidenceWrappedOffsetMask+1 {
			chunkWindows = stageEvidenceWrappedOffsetMask + 1
		}
		for local := 0; local < chunkWindows; local++ {
			offset := uint32(chunk)<<stageEvidenceWrappedOffsetBits | uint32(local)
			key := index.trigram(offset)
			if !index.trigramFilter.contains(key) {
				continue
			}
			index.prefixPages[uint16(key>>8)]++
		}
	}

	pageCount := 0
	for prefix, count := range index.prefixPages {
		if count != 0 {
			pageCount++
			index.prefixPages[prefix] = uint32(pageCount)
		}
	}
	if err := budget.consumeIndexBytes(int64(pageCount * (257 + 256) * 4)); err != nil {
		return err
	}
	// Each page is fixed-size and is visited once to establish global suffix
	// starts and once to restore those starts after source-order placement. One
	// further fixed page charge conservatively covers zero initialization.
	if err := budget.consumeScalarIndexWork(int64(pageCount * (3*257 + 256))); err != nil {
		return err
	}
	index.pages = make([]stageEvidenceWrappedPrefixPage, pageCount)

	// Count suffixes inside their sparse prefix pages.
	for chunk, representation := range index.representations {
		chunkWindows := len(representation.raw) - stageEvidenceWrappedMinFragmentBytes + 1 - representation.base
		if chunkWindows > stageEvidenceWrappedOffsetMask+1 {
			chunkWindows = stageEvidenceWrappedOffsetMask + 1
		}
		for local := 0; local < chunkWindows; local++ {
			offset := uint32(chunk)<<stageEvidenceWrappedOffsetBits | uint32(local)
			key := index.trigram(offset)
			if !index.trigramFilter.contains(key) {
				continue
			}
			page := &index.pages[index.prefixPages[uint16(key>>8)]-1]
			page.starts[byte(key)]++
			representationOffset := representation.base + local
			available := len(representation.raw) - representationOffset
			if uint64(available) > uint64(math.MaxUint32) {
				return fmt.Errorf("body-free wrapped scalar index maximum available length exceeds uint32")
			}
			if uint32(available) > page.maxAvailable[byte(key)] {
				page.maxAvailable[byte(key)] = uint32(available)
			}
		}
	}

	position := uint32(0)
	for pageNumber := range index.pages {
		page := &index.pages[pageNumber]
		for suffix := 0; suffix < 256; suffix++ {
			count := page.starts[suffix]
			page.starts[suffix] = position
			position += count
		}
		page.starts[256] = position
	}
	if uint64(position) != uint64(len(index.offsets)) {
		return fmt.Errorf("body-free wrapped scalar index retained posting count mismatch: counted %d, allocated %d", position, len(index.offsets))
	}

	// Place offsets in source order. Incrementing each suffix start makes equal
	// trigrams stable while the page order makes the complete offset array
	// lexicographic by trigram.
	for chunk, representation := range index.representations {
		chunkWindows := len(representation.raw) - stageEvidenceWrappedMinFragmentBytes + 1 - representation.base
		if chunkWindows > stageEvidenceWrappedOffsetMask+1 {
			chunkWindows = stageEvidenceWrappedOffsetMask + 1
		}
		for local := 0; local < chunkWindows; local++ {
			offset := uint32(chunk)<<stageEvidenceWrappedOffsetBits | uint32(local)
			key := index.trigram(offset)
			if !index.trigramFilter.contains(key) {
				continue
			}
			page := &index.pages[index.prefixPages[uint16(key>>8)]-1]
			destination := page.starts[byte(key)]
			index.offsets[destination] = offset
			page.starts[byte(key)]++
		}
	}

	pageBegin := uint32(0)
	for pageNumber := range index.pages {
		page := &index.pages[pageNumber]
		pageEnd := page.starts[256]
		for suffix := 256; suffix > 0; suffix-- {
			page.starts[suffix] = page.starts[suffix-1]
		}
		page.starts[0] = pageBegin
		pageBegin = pageEnd
	}
	return nil
}

func (index *stageEvidenceWrappedIndex) trigram(offset uint32) uint32 {
	representation := index.representationForOffset(offset)
	local := representation.base + int(offset&stageEvidenceWrappedOffsetMask)
	return stageEvidenceWrappedCanonicalTrigram(stageEvidenceWrappedRawTrigram(representation.raw, local))
}

func (index *stageEvidenceWrappedIndex) representationForOffset(offset uint32) *stageEvidenceWrappedRepresentation {
	return &index.representations[offset>>stageEvidenceWrappedOffsetBits]
}

func (index *stageEvidenceWrappedIndex) occurrencesForRepresentation(representation *stageEvidenceWrappedRepresentation) []int {
	return index.occurrences[representation.occurrenceStart:representation.occurrenceEnd]
}

func (index *stageEvidenceWrappedIndex) offsetsForTrigram(key uint32) []uint32 {
	pageNumber := index.prefixPages[uint16(key>>8)]
	if pageNumber == 0 {
		return nil
	}
	page := &index.pages[pageNumber-1]
	suffix := byte(key)
	return index.offsets[page.starts[suffix]:page.starts[int(suffix)+1]]
}

func (index *stageEvidenceWrappedIndex) maximumAvailableForTrigram(key uint32) int {
	pageNumber := index.prefixPages[uint16(key>>8)]
	if pageNumber == 0 {
		return 0
	}
	return int(index.pages[pageNumber-1].maxAvailable[byte(key)])
}

func stageEvidenceFoldHexByte(value byte) byte {
	if value >= 'A' && value <= 'F' {
		return value + ('a' - 'A')
	}
	return value
}

// stageEvidenceTargetReachableWithWrappedLengthUpperBounds is an impossibility
// gate, never a reconstruction witness. Every exact wrapped match must begin at
// an indexed trigram and cannot outgrow the remaining bytes in that carrier
// representation. The gate retains every length from the three-byte minimum
// through that unverified maximum, ignores occurrence identity, and permits
// reuse. Its graph is therefore a strict superset of the legal graph: failure
// to reach the target end proves that the exact search cannot succeed.
func stageEvidenceTargetReachableWithWrappedLengthUpperBounds(target []byte, index *stageEvidenceWrappedIndex, foldHex bool, budget *stageEvidenceSegmentationBudget) (bool, error) {
	if len(target) < 2*stageEvidenceWrappedMinFragmentBytes {
		return false, nil
	}
	scratchLength := len(target) + 1
	if cap(budget.prefixScratch) < scratchLength {
		budget.prefixScratch = make([]uint32, scratchLength)
	} else {
		budget.prefixScratch = budget.prefixScratch[:scratchLength]
		clear(budget.prefixScratch)
	}
	if err := budget.consumeScalarIndexWork(int64(scratchLength) * 2); err != nil {
		return false, err
	}
	starts := budget.prefixScratch
	furthestCovered := -1
	for offset := 0; offset <= len(target); offset++ {
		if scheduled := starts[offset]; scheduled != 0 && int(scheduled-1) > furthestCovered {
			furthestCovered = int(scheduled - 1)
		}
		reachable := offset == 0 || offset <= furthestCovered
		if offset == len(target) {
			return reachable, nil
		}
		if !reachable {
			continue
		}
		maximum, err := stageEvidenceIndexedWrappedMaximumAvailable(target[offset:], index, foldHex, offset == 0, budget)
		if err != nil {
			return false, err
		}
		if maximum < stageEvidenceWrappedMinFragmentBytes {
			continue
		}
		start := offset + stageEvidenceWrappedMinFragmentBytes
		end := offset + maximum
		if end > len(target) {
			end = len(target)
		}
		encodedEnd := uint32(end + 1)
		if encodedEnd > starts[start] {
			starts[start] = encodedEnd
		}
	}
	return false, nil
}

func stageEvidenceIndexedWrappedMaximumAvailable(remaining []byte, index *stageEvidenceWrappedIndex, foldHex, initial bool, budget *stageEvidenceSegmentationBudget) (int, error) {
	maximum := 0
	err := stageEvidenceWrappedIndexKeys(remaining, foldHex, budget, func(key uint32) error {
		available := index.maximumAvailableForTrigram(key)
		if available > len(remaining) {
			available = len(remaining)
		}
		if initial && available == len(remaining) {
			available--
		}
		if available > maximum {
			maximum = available
		}
		return nil
	})
	return maximum, err
}

func stageEvidenceProfileFeasible(target []byte, profile stageEvidenceSegmentationProfile, budget *stageEvidenceSegmentationBudget) (int64, bool, error) {
	if profile.totalCapacity < int64(len(target)) {
		return profile.totalCapacity, false, nil
	}
	if !profile.hasFrequency {
		return profile.totalCapacity, true, nil
	}
	var required [256]int64
	// Counting target-byte frequencies is bounded index bookkeeping, not a
	// byte-equality comparison against candidate content. Keep it under the
	// independent deterministic scalar-work ceiling so the aggregate equality
	// budget is reserved for exact candidate verification.
	if err := budget.consumeScalarIndexWork(int64(len(target))); err != nil {
		return 0, false, err
	}
	for _, current := range target {
		required[current]++
	}
	for current, count := range required {
		if profile.available[current] < count {
			return profile.totalCapacity, false, nil
		}
	}
	return profile.totalCapacity, true, nil
}

func stageEvidenceWrappedIndexKeys(value []byte, _ bool, budget *stageEvidenceSegmentationBudget, visit func(uint32) error) error {
	if len(value) < stageEvidenceWrappedMinFragmentBytes {
		return nil
	}
	// The index stores every all-hex trigram under one lower-case equivalence
	// key. Exact non-hex-mode queries may therefore receive mixed-case false
	// candidates, but the existing forward/backward byte comparison rejects
	// them before they can become a witness. Folded-hex queries reach the same
	// complete posting set with one fixed key instead of enumerating up to eight
	// case variants.
	if err := budget.consumeScalarIndexWork(1); err != nil {
		return err
	}
	key := stageEvidenceWrappedCanonicalTrigram(stageEvidenceWrappedRawTrigram(value, 0))
	return visit(key)
}

func stageEvidenceIndexedForwardMatch(target []byte, representation *stageEvidenceWrappedRepresentation, globalOffset uint32, foldHex bool, budget *stageEvidenceSegmentationBudget) (int, error) {
	local := representation.base + int(globalOffset&stageEvidenceWrappedOffsetMask)
	limit := len(target)
	if available := len(representation.raw) - local; available < limit {
		limit = available
	}
	// A non-hex trigram key proves its first three bytes exactly. All-hex keys
	// share one lower-case posting class; exact-mode queries must therefore
	// verify those three bytes, while folded-hex queries already proved them.
	start := stageEvidenceWrappedMinFragmentBytes
	if !foldHex {
		key := stageEvidenceWrappedRawTrigram(target, 0)
		if _, isHex := stageEvidenceWrappedFoldedHexTrigram(key); isHex {
			start = 0
		}
	}
	for index := start; index < limit; index++ {
		left, right := target[index], representation.raw[local+index]
		if foldHex {
			left, right = stageEvidenceFoldHexByte(left), stageEvidenceFoldHexByte(right)
		}
		equal, err := stageEvidenceBudgetedByteEqual(left, right, budget)
		if err != nil {
			return 0, err
		}
		if !equal {
			return index, nil
		}
	}
	return limit, nil
}

func stageEvidenceIndexedBackwardMatch(target []byte, representation *stageEvidenceWrappedRepresentation, globalOffset uint32, foldHex bool, budget *stageEvidenceSegmentationBudget) (int, error) {
	localEnd := representation.base + int(globalOffset&stageEvidenceWrappedOffsetMask) + stageEvidenceWrappedMinFragmentBytes - 1
	limit := len(target)
	if available := localEnd + 1; available < limit {
		limit = available
	}
	// As in the forward matcher, an all-hex exact-mode key is an overinclusive
	// posting class and its first three reverse-direction bytes need verification.
	start := stageEvidenceWrappedMinFragmentBytes
	if !foldHex {
		key := stageEvidenceWrappedRawTrigram(target, len(target)-stageEvidenceWrappedMinFragmentBytes)
		if _, isHex := stageEvidenceWrappedFoldedHexTrigram(key); isHex {
			start = 0
		}
	}
	for index := start; index < limit; index++ {
		left, right := target[len(target)-1-index], representation.raw[localEnd-index]
		if foldHex {
			left, right = stageEvidenceFoldHexByte(left), stageEvidenceFoldHexByte(right)
		}
		equal, err := stageEvidenceBudgetedByteEqual(left, right, budget)
		if err != nil {
			return 0, err
		}
		if !equal {
			return index, nil
		}
	}
	return limit, nil
}

func stageEvidenceIndexedWrappedCandidates(target []byte, offset int, index *stageEvidenceWrappedIndex, foldHex, initial bool, budget *stageEvidenceSegmentationBudget) ([]stageEvidenceWrappedCandidate, error) {
	remaining := target[offset:]
	touched := index.touchedScratch[:0]
	defer func() {
		for _, occurrence := range touched {
			index.longestScratch[occurrence] = 0
		}
		index.touchedScratch = touched[:0]
	}()
	err := stageEvidenceWrappedIndexKeys(remaining, foldHex, budget, func(key uint32) error {
		postings := index.offsetsForTrigram(key)
		if err := budget.consumeScalarIndexWork(int64(len(postings))); err != nil {
			return err
		}
		for _, globalOffset := range postings {
			representation := index.representationForOffset(globalOffset)
			length, err := stageEvidenceIndexedForwardMatch(remaining, representation, globalOffset, foldHex, budget)
			if err != nil {
				return err
			}
			occurrences := index.occurrencesForRepresentation(representation)
			if err := budget.consumeScalarIndexWork(int64(len(occurrences) - 1)); err != nil {
				return err
			}
			for _, occurrence := range occurrences {
				if length > index.longestScratch[occurrence] {
					if index.longestScratch[occurrence] == 0 {
						// Reserve the eventual reset before this occurrence enters
						// reusable scratch. Any later error can then clean it without
						// doing unaccounted variable work.
						if err := budget.consumeScalarIndexWork(1); err != nil {
							return err
						}
						touched = append(touched, occurrence)
					}
					index.longestScratch[occurrence] = length
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// One complete touched-occurrence pass counts candidates and one emits
	// them. Reset work was charged when each occurrence was first touched.
	if err := budget.consumeScalarIndexWork(int64(len(touched)) * 2); err != nil {
		return nil, err
	}
	candidateCount := 0
	for _, occurrence := range touched {
		length := index.longestScratch[occurrence]
		if length >= len(remaining) && initial {
			length = len(remaining) - 1
		}
		if length >= stageEvidenceWrappedMinFragmentBytes {
			candidateCount++
		}
	}
	if err := budget.consumeCandidateBytes(int64(candidateCount) * 32); err != nil {
		return nil, err
	}
	candidates := make([]stageEvidenceWrappedCandidate, 0, candidateCount)
	for _, occurrence := range touched {
		length := index.longestScratch[occurrence]
		if length >= len(remaining) && initial {
			length = len(remaining) - 1
		}
		if length >= stageEvidenceWrappedMinFragmentBytes {
			candidates = append(candidates, stageEvidenceWrappedCandidate{occurrence: occurrence, length: length})
		}
	}
	if err := budget.consumeScalarIndexWork(stageEvidenceSortComparisonBound(len(candidates))); err != nil {
		return nil, err
	}
	sort.SliceStable(candidates, func(left, right int) bool {
		if candidates[left].length != candidates[right].length {
			return candidates[left].length > candidates[right].length
		}
		return candidates[left].occurrence < candidates[right].occurrence
	})
	return candidates, nil
}

func stageEvidenceIndexedWrappedEnds(target []byte, index *stageEvidenceWrappedIndex, foldHex bool, budget *stageEvidenceSegmentationBudget) ([]int, []int, error) {
	if int64(len(index.profile.maxLengths)) > stageEvidenceMaxOccurrenceAuxiliaryBytes/16 {
		return nil, nil, fmt.Errorf("body-free two-occurrence segmentation exceeds fixed occurrence auxiliary byte limit %d", stageEvidenceMaxOccurrenceAuxiliaryBytes)
	}
	prefixLengths := make([]int, len(index.profile.maxLengths))
	suffixLengths := make([]int, len(index.profile.maxLengths))
	if len(target) < stageEvidenceWrappedMinFragmentBytes {
		return prefixLengths, suffixLengths, nil
	}
	if err := stageEvidenceWrappedIndexKeys(target, foldHex, budget, func(key uint32) error {
		postings := index.offsetsForTrigram(key)
		if err := budget.consumeScalarIndexWork(int64(len(postings))); err != nil {
			return err
		}
		for _, globalOffset := range postings {
			representation := index.representationForOffset(globalOffset)
			length, err := stageEvidenceIndexedForwardMatch(target, representation, globalOffset, foldHex, budget)
			if err != nil {
				return err
			}
			occurrences := index.occurrencesForRepresentation(representation)
			if err := budget.consumeScalarIndexWork(int64(len(occurrences) - 1)); err != nil {
				return err
			}
			for _, occurrence := range occurrences {
				if length > prefixLengths[occurrence] {
					prefixLengths[occurrence] = length
				}
			}
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	ending := target[len(target)-stageEvidenceWrappedMinFragmentBytes:]
	if err := stageEvidenceWrappedIndexKeys(ending, foldHex, budget, func(key uint32) error {
		postings := index.offsetsForTrigram(key)
		if err := budget.consumeScalarIndexWork(int64(len(postings))); err != nil {
			return err
		}
		for _, globalOffset := range postings {
			representation := index.representationForOffset(globalOffset)
			length, err := stageEvidenceIndexedBackwardMatch(target, representation, globalOffset, foldHex, budget)
			if err != nil {
				return err
			}
			occurrences := index.occurrencesForRepresentation(representation)
			if err := budget.consumeScalarIndexWork(int64(len(occurrences) - 1)); err != nil {
				return err
			}
			for _, occurrence := range occurrences {
				if length > suffixLengths[occurrence] {
					suffixLengths[occurrence] = length
				}
			}
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	if err := budget.consumeScalarIndexWork(int64(len(prefixLengths))); err != nil {
		return nil, nil, err
	}
	for occurrence := range prefixLengths {
		if prefixLengths[occurrence] >= len(target) {
			prefixLengths[occurrence] = len(target) - 1
		}
		if suffixLengths[occurrence] >= len(target) {
			suffixLengths[occurrence] = len(target) - 1
		}
	}
	return prefixLengths, suffixLengths, nil
}

// stageEvidenceIndexedWrappedBestSuffixes returns the best suffix occurrence
// and the best length available from any different occurrence. It reuses the
// index's bounded per-occurrence scratch, so the cascade can retain its already
// materialized prefix candidates without allocating two full occurrence-sized
// end arrays or repeating the prefix byte comparisons.
func stageEvidenceIndexedWrappedBestSuffixes(target []byte, index *stageEvidenceWrappedIndex, foldHex bool, budget *stageEvidenceSegmentationBudget) (int, int, int, error) {
	if len(target) < stageEvidenceWrappedMinFragmentBytes {
		return -1, 0, 0, nil
	}
	touched := index.touchedScratch[:0]
	defer func() {
		for _, occurrence := range touched {
			index.longestScratch[occurrence] = 0
		}
		index.touchedScratch = touched[:0]
	}()
	ending := target[len(target)-stageEvidenceWrappedMinFragmentBytes:]
	err := stageEvidenceWrappedIndexKeys(ending, foldHex, budget, func(key uint32) error {
		postings := index.offsetsForTrigram(key)
		if err := budget.consumeScalarIndexWork(int64(len(postings))); err != nil {
			return err
		}
		for _, globalOffset := range postings {
			representation := index.representationForOffset(globalOffset)
			length, err := stageEvidenceIndexedBackwardMatch(target, representation, globalOffset, foldHex, budget)
			if err != nil {
				return err
			}
			occurrences := index.occurrencesForRepresentation(representation)
			if err := budget.consumeScalarIndexWork(int64(len(occurrences) - 1)); err != nil {
				return err
			}
			for _, occurrence := range occurrences {
				if length <= index.longestScratch[occurrence] {
					continue
				}
				if index.longestScratch[occurrence] == 0 {
					// Pre-charge the eventual reset before retaining the touched
					// occurrence in reusable scratch.
					if err := budget.consumeScalarIndexWork(1); err != nil {
						return err
					}
					touched = append(touched, occurrence)
				}
				index.longestScratch[occurrence] = length
			}
		}
		return nil
	})
	if err != nil {
		return -1, 0, 0, err
	}
	if err := budget.consumeScalarIndexWork(int64(len(touched))); err != nil {
		return -1, 0, 0, err
	}
	bestOccurrence, bestLength, secondLength := -1, 0, 0
	for _, occurrence := range touched {
		length := index.longestScratch[occurrence]
		if length >= len(target) {
			length = len(target) - 1
		}
		if length > bestLength {
			secondLength = bestLength
			bestOccurrence = occurrence
			bestLength = length
		} else if length > secondLength {
			secondLength = length
		}
	}
	return bestOccurrence, bestLength, secondLength, nil
}
