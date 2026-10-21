package providerplan

import (
	"strings"
	"testing"
)

// An occurrence outcome is completeness evidence: it must be refused unless its
// identity is derived from its full canonical state, so a rewritten match count
// or disposition cannot pass as an executed result.
func TestValidateExactDocumentationDerivationOccurrenceOutcomeRefusesRewrittenState(t *testing.T) {
	digest := sha256Hex([]byte("fixture"))
	reference := dependencyProfileReference{id: "profile", version: "1", digest: digest}
	proof := sourceClassificationSelectionProof{contentSHA256: digest}

	structurallyComplete := func() exactDocumentationDerivationOccurrenceOutcome {
		return exactDocumentationDerivationOccurrenceOutcome{
			OutcomeKind:              exactDocumentationDerivationOutcomeKind,
			RuleID:                   "decimal_provider_type",
			InputSourceSymbol:        "amount",
			ClassificationArtifactID: "artifact",
			ClassificationVersion:    "1",
			ClassificationSHA256:     digest,
			ClassificationRole:       "documentation_surface",
			PredecessorLocatorID:     "locator",
			MatchCount:               0,
			Disposition:              exactDocumentationDerivationZeroMatchAllowed,
			DerivedFactSetRootSHA256: stageCanonicalSetRoot(make([][]byte, 0)),
		}
	}

	for _, test := range []struct {
		name   string
		mutate func(*exactDocumentationDerivationOccurrenceOutcome)
		want   string
	}{
		{
			name: "no state at all",
			mutate: func(o *exactDocumentationDerivationOccurrenceOutcome) {
				*o = exactDocumentationDerivationOccurrenceOutcome{}
			},
			want: "structurally invalid",
		},
		{
			name:   "wrong outcome kind",
			mutate: func(o *exactDocumentationDerivationOccurrenceOutcome) { o.OutcomeKind = "some_other_kind" },
			want:   "structurally invalid",
		},
		{
			name:   "malformed classification digest",
			mutate: func(o *exactDocumentationDerivationOccurrenceOutcome) { o.ClassificationSHA256 = "not-a-sha256" },
			want:   "structurally invalid",
		},
		{
			name:   "negative match count",
			mutate: func(o *exactDocumentationDerivationOccurrenceOutcome) { o.MatchCount = -1 },
			want:   "structurally invalid",
		},
		{
			name: "match count disagrees with the fact roster",
			mutate: func(o *exactDocumentationDerivationOccurrenceOutcome) {
				o.MatchCount = 2
				o.DerivedFactIDs = []string{"docfact_a"}
			},
			want: "structurally invalid",
		},
		{
			name: "fact identities are not strictly sorted",
			mutate: func(o *exactDocumentationDerivationOccurrenceOutcome) {
				o.DerivedFactIDs = []string{"docfact_b", "docfact_a"}
				o.MatchCount = 2
			},
			want: "not strictly sorted and unique",
		},
		{
			name: "fact identities repeat",
			mutate: func(o *exactDocumentationDerivationOccurrenceOutcome) {
				o.DerivedFactIDs = []string{"docfact_a", "docfact_a"}
				o.MatchCount = 2
			},
			want: "not strictly sorted and unique",
		},
		{
			name: "empty fact identity",
			mutate: func(o *exactDocumentationDerivationOccurrenceOutcome) {
				o.DerivedFactIDs = []string{""}
				o.MatchCount = 1
			},
			want: "not strictly sorted and unique",
		},
		{
			name: "disposition claims a match with no facts",
			mutate: func(o *exactDocumentationDerivationOccurrenceOutcome) {
				o.Disposition = exactDocumentationDerivationMatched
			},
			want: "disposition or fact-set root disagrees",
		},
		{
			name: "fact set root does not cover the fact roster",
			mutate: func(o *exactDocumentationDerivationOccurrenceOutcome) {
				o.DerivedFactSetRootSHA256 = sha256Hex([]byte("unrelated root"))
			},
			want: "disposition or fact-set root disagrees",
		},
		{
			name:   "identity is not derived from the canonical state",
			mutate: func(o *exactDocumentationDerivationOccurrenceOutcome) { o.OutcomeID = "docout_rewritten" },
			want:   "identity disagrees with its full canonical state",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			outcome := structurallyComplete()
			test.mutate(&outcome)
			canonical, err := validateExactDocumentationDerivationOccurrenceOutcome(reference, proof, outcome)
			if err == nil {
				t.Fatalf("a rewritten occurrence outcome was accepted")
			}
			if canonical != nil {
				t.Fatalf("a refused outcome returned %d canonical bytes, want none", len(canonical))
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestExactDocumentationDerivationOutcomeKeyIsLengthPrefixed(t *testing.T) {
	binding := classificationArtifactBinding{ArtifactID: "artifact", ArtifactVersion: "1", ArtifactSHA256: sha256Hex([]byte("fixture"))}
	// Length prefixing is what stops two different coordinate tuples from
	// colliding by moving a separator into a neighbouring field.
	first := exactDocumentationDerivationOutcomeKey("rule", "amount:extra", binding, "surface", "locator")
	second := exactDocumentationDerivationOutcomeKey("rule", "amount", binding, "extra:surface", "locator")
	if first == second {
		t.Fatal("two distinct outcome coordinates produced the same key")
	}
}
