package providerplan

import (
	"strings"
	"testing"
)

func sourceClassificationOccurrenceFixture(sourceSymbol, locatorID string) sourceClassificationOccurrence {
	return sourceClassificationOccurrence{
		SourceSymbol: sourceSymbol,
		SurfaceKind:  "documentation_surface",
		Binding: classificationArtifactBinding{
			ArtifactID:      "source_contract_index",
			ArtifactVersion: "1",
			ArtifactSHA256:  sha256Hex([]byte("classification artifact")),
		},
		Locator: evidenceLocator{ID: locatorID},
	}
}

// The selection proof is in-process authority that candidate graph rows cannot
// manufacture. Its content identity must refuse every roster that is not an
// exact, non-aliasing set of classified occurrences.
func TestValidateSourceClassificationSelectionProofRefusesUnsealedAndInexactRosters(t *testing.T) {
	roster := sha256Hex([]byte("evidence selection roster"))

	if err := validateSourceClassificationSelectionProof(sourceClassificationSelectionProof{}); err == nil ||
		!strings.Contains(err.Error(), "no in-process authority seal") {
		t.Fatalf("unsealed proof error = %v, want an authority-seal refusal", err)
	}

	for _, test := range []struct {
		name            string
		provider        string
		roster          string
		classifications map[string][]sourceClassificationOccurrence
		want            string
	}{
		{
			name:            "empty provider",
			provider:        "",
			roster:          roster,
			classifications: map[string][]sourceClassificationOccurrence{"list_invoices": {sourceClassificationOccurrenceFixture("list_invoices", "evloc_one")}},
			want:            "invalid provider or evidence-selection roster coordinate",
		},
		{
			name:            "malformed evidence-selection roster digest",
			provider:        "quickbooks",
			roster:          "not-a-sha256",
			classifications: map[string][]sourceClassificationOccurrence{"list_invoices": {sourceClassificationOccurrenceFixture("list_invoices", "evloc_one")}},
			want:            "invalid provider or evidence-selection roster coordinate",
		},
		{
			name:            "no classified source symbols",
			provider:        "quickbooks",
			roster:          roster,
			classifications: map[string][]sourceClassificationOccurrence{},
			want:            "no classified source symbols",
		},
		{
			name:            "source symbol with an empty occurrence roster",
			provider:        "quickbooks",
			roster:          roster,
			classifications: map[string][]sourceClassificationOccurrence{"list_invoices": {}},
			want:            "invalid or empty occurrence roster",
		},
		{
			name:     "occurrence filed under a different source symbol",
			provider: "quickbooks",
			roster:   roster,
			classifications: map[string][]sourceClassificationOccurrence{
				"list_invoices": {sourceClassificationOccurrenceFixture("a_different_symbol", "evloc_one")},
			},
			want: "invalid occurrence coordinate",
		},
		{
			name:     "occurrence with a malformed classification digest",
			provider: "quickbooks",
			roster:   roster,
			classifications: map[string][]sourceClassificationOccurrence{
				"list_invoices": func() []sourceClassificationOccurrence {
					occurrence := sourceClassificationOccurrenceFixture("list_invoices", "evloc_one")
					occurrence.Binding.ArtifactSHA256 = "not-a-sha256"
					return []sourceClassificationOccurrence{occurrence}
				}(),
			},
			want: "invalid occurrence coordinate",
		},
		{
			name:     "roster repeats one exact occurrence",
			provider: "quickbooks",
			roster:   roster,
			classifications: map[string][]sourceClassificationOccurrence{
				"list_invoices": {
					sourceClassificationOccurrenceFixture("list_invoices", "evloc_one"),
					sourceClassificationOccurrenceFixture("list_invoices", "evloc_one"),
				},
			},
			want: "duplicates locator",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := newSourceClassificationSelectionProof(test.provider, test.roster, test.classifications)
			err := validateSourceClassificationSelectionProof(proof)
			if err == nil {
				t.Fatalf("an inexact classification selection roster was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestNewSourceClassificationSelectionProofSealsAndDefensivelyCopies(t *testing.T) {
	roster := sha256Hex([]byte("evidence selection roster"))
	occurrence := sourceClassificationOccurrenceFixture("list_invoices", "evloc_one")
	occurrence.Locator.SourceRefs = []string{"ref-one"}
	occurrence.Locator.SourceURLs = []string{"https://example.test/one"}
	classifications := map[string][]sourceClassificationOccurrence{"list_invoices": {occurrence}}

	proof := newSourceClassificationSelectionProof("quickbooks", roster, classifications)
	if err := validateSourceClassificationSelectionProof(proof); err != nil {
		t.Fatalf("an exact classification selection roster was rejected: %v", err)
	}
	if !isLowerSHA256(proof.contentSHA256) {
		t.Fatalf("sealed content digest = %q, want an exact lowercase sha256", proof.contentSHA256)
	}

	// The proof copies the caller's locator slices, so mutating them afterwards
	// cannot change what the sealed identity covers.
	occurrence.Locator.SourceRefs[0] = "mutated-ref"
	if got := proof.classificationsBySourceSymbol["list_invoices"][0].Locator.SourceRefs[0]; got != "ref-one" {
		t.Fatalf("retained source ref = %q, want the copy taken when the proof was sealed", got)
	}
	if err := validateSourceClassificationSelectionProof(proof); err != nil {
		t.Fatalf("caller mutation invalidated the sealed proof: %v", err)
	}
}
