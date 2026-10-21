package providerplan

import (
	"strings"
	"testing"
)

func stageEvidenceWrappedCarrierFixture() []stageEvidenceCarrierOccurrence {
	return []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("alpha-carrier-value"), []byte("ALPHA-CARRIER-VALUE")}, multiplicity: 1},
		{representations: [][]byte{[]byte("beta-carrier-value")}, multiplicity: 3},
		{representations: [][]byte{[]byte("gamma-carrier")}, multiplicity: 2},
	}
}

// The wrapped scalar index is built from attacker-influenced carrier rosters, so
// its fixed structural limits must refuse oversized input rather than allocate
// against it.
func TestNewStageEvidenceWrappedIndexRefusesOversizedCarrierRosters(t *testing.T) {
	t.Run("occurrence group roster beyond the fixed limit", func(t *testing.T) {
		carriers := make([]stageEvidenceCarrierOccurrence, stageEvidenceMaxCarrierOccurrences+1)
		if _, err := newStageEvidenceWrappedIndexBounded(carriers, &stageEvidenceSegmentationBudget{}); err == nil ||
			!strings.Contains(err.Error(), "occurrence-group limit") {
			t.Fatalf("error = %v, want a fixed occurrence-group limit refusal", err)
		}
	})

	t.Run("representations per occurrence beyond the fixed limit", func(t *testing.T) {
		representations := make([][]byte, stageEvidenceMaxRepresentationsPerOccurrence+1)
		for index := range representations {
			representations[index] = []byte("carrier-representation")
		}
		carriers := []stageEvidenceCarrierOccurrence{{representations: representations, multiplicity: 1}}
		if _, err := newStageEvidenceWrappedIndexBounded(carriers, &stageEvidenceSegmentationBudget{}); err == nil ||
			!strings.Contains(err.Error(), "representation limit") {
			t.Fatalf("error = %v, want a fixed representation-limit refusal", err)
		}
	})

	t.Run("nonpositive occurrence multiplicity", func(t *testing.T) {
		// A nonpositive multiplicity would let a carrier claim capacity it does
		// not have, so it must refuse rather than be clamped.
		carriers := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("carrier")}, multiplicity: -1}}
		if _, err := newStageEvidenceWrappedIndexBounded(carriers, &stageEvidenceSegmentationBudget{}); err == nil ||
			!strings.Contains(err.Error(), "nonpositive multiplicity") {
			t.Fatalf("error = %v, want a nonpositive-multiplicity refusal", err)
		}
	})
}

// Index construction declares its auxiliary byte and linear-work consumption up
// front. Every budget strictly below what a successful build consumes must be
// refused, at whichever accounting site the shortfall is first observed.
func TestNewStageEvidenceWrappedIndexFailsClosedBelowItsDeclaredBudget(t *testing.T) {
	carriers := stageEvidenceWrappedCarrierFixture()

	reference := &stageEvidenceSegmentationBudget{}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, reference)
	if err != nil {
		t.Fatalf("the default budget rejected an ordinary carrier roster: %v", err)
	}
	if len(index.multiplicities) != len(carriers) {
		t.Fatalf("index retained %d multiplicities, want one per occurrence group", len(index.multiplicities))
	}
	if reference.indexBytesUsed <= 0 || reference.scalarIndexWorkUsed <= 0 {
		t.Fatalf("construction consumed no declared budget (bytes=%d work=%d)", reference.indexBytesUsed, reference.scalarIndexWorkUsed)
	}

	for _, test := range []struct {
		name  string
		used  int64
		build func(limit int64) *stageEvidenceSegmentationBudget
		want  string
	}{
		{
			name: "auxiliary index bytes",
			used: reference.indexBytesUsed,
			build: func(limit int64) *stageEvidenceSegmentationBudget {
				return &stageEvidenceSegmentationBudget{indexBytesLimit: limit}
			},
			want: "auxiliary byte limit",
		},
		{
			name: "linear scalar index work",
			used: reference.scalarIndexWorkUsed,
			build: func(limit int64) *stageEvidenceSegmentationBudget {
				return &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: limit}
			},
			want: "linear-work limit",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits := []int64{test.used - 1}
			for limit := int64(1); limit < test.used; limit *= 2 {
				limits = append(limits, limit)
			}
			for _, limit := range limits {
				if limit < 1 {
					continue
				}
				_, err := newStageEvidenceWrappedIndexBounded(carriers, test.build(limit))
				if err == nil {
					t.Fatalf("limit %d is below the %d actually consumed, but construction succeeded", limit, test.used)
				}
				if !strings.Contains(err.Error(), test.want) {
					t.Fatalf("limit %d error = %v, want a refusal containing %q", limit, err, test.want)
				}
			}
		})
	}
}

func TestNewStageEvidenceWrappedTrigramFilterFailsClosedBelowItsDeclaredBudget(t *testing.T) {
	bodies := map[string]exactEvidenceBody{
		sha256Hex([]byte("first evidence body")):  {Bytes: []byte("first evidence body")},
		sha256Hex([]byte("second evidence body")): {Bytes: []byte("second evidence body")},
	}

	reference := &stageEvidenceSegmentationBudget{}
	if _, err := newStageEvidenceWrappedTrigramFilter(bodies, reference); err != nil {
		t.Fatalf("the default budget rejected ordinary evidence bodies: %v", err)
	}

	for _, test := range []struct {
		name   string
		budget *stageEvidenceSegmentationBudget
		want   string
	}{
		{
			name:   "no auxiliary bytes for the filter bitset",
			budget: &stageEvidenceSegmentationBudget{indexBytesLimit: 1},
			want:   "auxiliary byte limit",
		},
		{
			name:   "bitset allocation allowed but no linear work",
			budget: &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: 1},
			want:   "linear-work limit",
		},
		{
			name: "linear work exhausted after the bitset is charged",
			// Enough work to charge the bitset itself, but nothing left for the
			// per-target window scan that follows it.
			budget: &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: stageEvidenceWrappedFilterBytes + 1},
			want:   "linear-work limit",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newStageEvidenceWrappedTrigramFilter(bodies, test.budget); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

// The trigram filter may only ever retain search work. A nil filter, and any
// folded-hex equivalent of an indexed window, must report membership so a legal
// segmentation can never be filtered away.
func TestStageEvidenceWrappedTrigramFilterNeverHidesALegalWitness(t *testing.T) {
	var absent *stageEvidenceWrappedTrigramFilter
	if !absent.contains(stageEvidenceWrappedRawTrigram([]byte("abc"), 0)) {
		t.Fatalf("a nil filter excluded a window; it must admit every candidate")
	}

	bodies := map[string]exactEvidenceBody{
		sha256Hex([]byte("0a1b2c")): {Bytes: []byte("0a1b2c")},
	}
	filter, err := newStageEvidenceWrappedTrigramFilter(bodies, &stageEvidenceSegmentationBudget{})
	if err != nil {
		t.Fatal(err)
	}
	// The body is indexed in canonical lower case, so the upper-case spelling of
	// the same hex window must still be reported as present.
	lower := stageEvidenceWrappedRawTrigram([]byte("0a1"), 0)
	upper := stageEvidenceWrappedRawTrigram([]byte("0A1"), 0)
	if !filter.contains(lower) {
		t.Fatalf("filter excluded the canonical lower-case window it indexed")
	}
	if !filter.contains(upper) {
		t.Fatalf("filter excluded the upper-case spelling of an indexed hex window")
	}
}

func TestStageEvidenceWrappedHexTrigramFoldingIsExact(t *testing.T) {
	for _, test := range []struct {
		name   string
		window string
		want   string
		isHex  bool
	}{
		{name: "upper-case hex folds to lower case", window: "ABC", want: "abc", isHex: true},
		{name: "mixed-case hex folds to lower case", window: "0Af", want: "0af", isHex: true},
		{name: "already canonical hex is unchanged", window: "0af", want: "0af", isHex: true},
		{name: "non-hex letters do not fold", window: "xyz", isHex: false},
		{name: "partially hex window does not fold", window: "abz", isHex: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := stageEvidenceWrappedRawTrigram([]byte(test.window), 0)
			folded, isHex := stageEvidenceWrappedFoldedHexTrigram(key)
			if isHex != test.isHex {
				t.Fatalf("isHex = %v, want %v", isHex, test.isHex)
			}
			if !test.isHex {
				// A window that is not entirely hex must stay exactly itself, or a
				// non-hex carrier could be matched against an unrelated target.
				if got := stageEvidenceWrappedCanonicalTrigram(key); got != key {
					t.Fatalf("canonical trigram = %d, want the unfolded key %d", got, key)
				}
				return
			}
			if want := stageEvidenceWrappedRawTrigram([]byte(test.want), 0); folded != want {
				t.Fatalf("folded = %d, want %d", folded, want)
			}
			if got := stageEvidenceWrappedCanonicalTrigram(key); got != folded {
				t.Fatalf("canonical trigram = %d, want the folded key %d", got, folded)
			}
		})
	}
}
