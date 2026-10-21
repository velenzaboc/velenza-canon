package providerplan

import (
	"strings"
	"testing"
)

func TestRequireExactCanonicalDocumentationRowMemberRefusesInexactValues(t *testing.T) {
	for _, test := range []struct {
		name     string
		raw      string
		field    string
		expected interface{}
		want     string
	}{
		{
			name:     "absent field",
			raw:      `{"row_kind":"field_contract"}`,
			field:    "source_ref",
			expected: "ref",
			want:     `field "source_ref"`,
		},
		{
			name:     "value differs from the derived fact value",
			raw:      `{"source_ref":"other"}`,
			field:    "source_ref",
			expected: "ref",
			want:     "does not equal its exact documentation-derived fact value",
		},
		{
			name:     "expected value cannot be encoded",
			raw:      `{"source_ref":"ref"}`,
			field:    "source_ref",
			expected: make(chan int),
			want:     "expected value cannot be encoded",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := requireExactCanonicalDocumentationRowMember([]byte(test.raw), test.field, test.expected)
			if err == nil {
				t.Fatalf("inexact row member %q was accepted", test.field)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestRequireExactCanonicalDocumentationRowMemberAcceptsAnExactValue(t *testing.T) {
	if err := requireExactCanonicalDocumentationRowMember([]byte(`{"byte_start_offset":12}`), "byte_start_offset", int64(12)); err != nil {
		t.Fatalf("an exact canonical integer member was rejected: %v", err)
	}
	if err := requireExactCanonicalDocumentationRowMember([]byte(`{"source_ref":"ref"}`), "source_ref", "ref"); err != nil {
		t.Fatalf("an exact canonical string member was rejected: %v", err)
	}
}

func TestValidateExactDocumentationDerivedFactIntegrityRefusesIncompleteFacts(t *testing.T) {
	digest := sha256Hex([]byte("fixture"))

	complete := func() exactDocumentationDerivedFact {
		return exactDocumentationDerivedFact{
			FactID:                "docfact_fixture",
			Profile:               dependencyProfileReference{id: "profile", version: "1", digest: digest},
			TargetArtifactRole:    "field_mapping_candidate",
			TargetRowKind:         "field_contract",
			Provider:              "fixture_provider",
			ClassificationBinding: classificationArtifactBinding{ArtifactID: "artifact", ArtifactVersion: "1", ArtifactSHA256: digest},
			ClassificationRole:    "documentation_surface",
			RuleID:                "decimal_provider_type",
			InputSourceSymbol:     "amount",
			PredecessorLocatorID:  "locator",
			EvidenceLocatorID:     "evloc_fixture",
			EvidenceRosterSHA256:  digest,
			MatchOrdinal:          0,
			ExactOutputFieldNames: []string{"field_name", "provider_type"},
		}
	}

	for _, test := range []struct {
		name   string
		mutate func(*exactDocumentationDerivedFact)
		want   string
	}{
		{
			name:   "no identity at all",
			mutate: func(fact *exactDocumentationDerivedFact) { *fact = exactDocumentationDerivedFact{} },
			want:   "identity or target coordinate is incomplete",
		},
		{
			name:   "absent fact identity",
			mutate: func(fact *exactDocumentationDerivedFact) { fact.FactID = "" },
			want:   "identity or target coordinate is incomplete",
		},
		{
			name:   "negative match ordinal",
			mutate: func(fact *exactDocumentationDerivedFact) { fact.MatchOrdinal = -1 },
			want:   "identity or target coordinate is incomplete",
		},
		{
			name:   "target role is not canonical",
			mutate: func(fact *exactDocumentationDerivedFact) { fact.TargetArtifactRole = "Not Canonical" },
			want:   "is not canonical",
		},
		{
			name:   "rule coordinate is not canonical",
			mutate: func(fact *exactDocumentationDerivedFact) { fact.RuleID = "Not Canonical" },
			want:   "is not canonical",
		},
		{
			name:   "profile digest is malformed",
			mutate: func(fact *exactDocumentationDerivedFact) { fact.Profile.digest = "not-a-sha256" },
			want:   "digest is malformed",
		},
		{
			name:   "evidence roster digest is malformed",
			mutate: func(fact *exactDocumentationDerivedFact) { fact.EvidenceRosterSHA256 = "not-a-sha256" },
			want:   "digest is malformed",
		},
		{
			name:   "output field roster is empty",
			mutate: func(fact *exactDocumentationDerivedFact) { fact.ExactOutputFieldNames = nil },
			want:   "nonempty, unique, and sorted",
		},
		{
			name: "output field roster is unsorted",
			mutate: func(fact *exactDocumentationDerivedFact) {
				fact.ExactOutputFieldNames = []string{"provider_type", "field_name"}
			},
			want: "nonempty, unique, and sorted",
		},
		{
			name: "output field roster duplicates a field",
			mutate: func(fact *exactDocumentationDerivedFact) {
				fact.ExactOutputFieldNames = []string{"field_name", "field_name"}
			},
			want: "nonempty, unique, and sorted",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fact := complete()
			test.mutate(&fact)
			err := validateExactDocumentationDerivedFactIntegrity(fact)
			if err == nil {
				t.Fatalf("an incomplete documentation-derived fact was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestValidateExactDocumentationDerivedSemanticRowSetRefusesUnusableRosters(t *testing.T) {
	// An invalid fact must be refused by the set validator itself rather than
	// being trusted because some row happens to reference it.
	invalid := []exactDocumentationDerivedFact{{FactID: "docfact_invalid"}}
	if err := validateExactDocumentationDerivedSemanticRowSet("field_mapping_candidate", nil, invalid); err == nil ||
		!strings.Contains(err.Error(), "is invalid") {
		t.Fatalf("invalid fact roster error = %v, want an integrity refusal", err)
	}

	// A row carrying no fact identity cannot be bound to any fact.
	rows := []dependencySemanticRow{{
		kind: "field_contract",
		raw:  []byte(`{"row_kind":"field_contract"}`),
		data: map[string]interface{}{"row_kind": "field_contract"},
	}}
	err := validateExactDocumentationDerivedSemanticRowSet("field_mapping_candidate", rows, nil)
	if err == nil || !strings.Contains(err.Error(), exactDocumentationDerivedFactIDField) {
		t.Fatalf("fact-identity-free row error = %v, want a missing-identity refusal", err)
	}
}
