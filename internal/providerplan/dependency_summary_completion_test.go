package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func dependencySummaryInput(summary map[string]interface{}) artifactInput {
	return artifactInput{Path: "dependency.jsonl", ValidationSummary: summary}
}

func exactDependencySummary() map[string]interface{} {
	return map[string]interface{}{
		"row_kind": "validation_summary",
		"result":   "an_exact_declared_result",
	}
}

// The validation summary is the artifact's own claim about itself, so every
// declared field must be exactly the body-free, issue-free posture or the
// artifact is refused. A summary that merely omits a field is acceptable; one
// that declares it with the wrong value is not.
func TestValidateDependencySummaryCommonRefusesEveryInexactDeclaredPosture(t *testing.T) {
	const expected = "an_exact_declared_result"

	for _, test := range []struct {
		name    string
		summary map[string]interface{}
		want    string
	}{
		{
			name:    "absent summary",
			summary: nil,
			want:    "is missing",
		},
		{
			name: "wrong row kind",
			summary: map[string]interface{}{
				"row_kind": "not_a_validation_summary",
				"result":   expected,
			},
			want: "invalid row_kind",
		},
		{
			name: "absent row kind",
			summary: map[string]interface{}{
				"result": expected,
			},
			want: "invalid row_kind",
		},
		{
			name: "result does not equal the expected result",
			summary: map[string]interface{}{
				"row_kind": "validation_summary",
				"result":   "a_different_result",
			},
			want: "must equal",
		},
		{
			name: "declares that source bytes are present",
			summary: func() map[string]interface{} {
				summary := exactDependencySummary()
				summary["source_bytes_present"] = true
				return summary
			}(),
			want: "source_bytes_present=false",
		},
		{
			name: "declares source_bytes_present as a non-boolean",
			summary: func() map[string]interface{} {
				summary := exactDependencySummary()
				summary["source_bytes_present"] = "false"
				return summary
			}(),
			want: "source_bytes_present=false",
		},
		{
			name: "declares a nonzero issue count",
			summary: func() map[string]interface{} {
				summary := exactDependencySummary()
				summary["issue_count"] = json.Number("1")
				return summary
			}(),
			want: "issue_count=0",
		},
		{
			name: "declares issue_count as a non-integer",
			summary: func() map[string]interface{} {
				summary := exactDependencySummary()
				summary["issue_count"] = "0"
				return summary
			}(),
			want: "issue_count=0",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateDependencySummaryCommon(dependencySummaryInput(test.summary), expected)
			if err == nil {
				t.Fatalf("an inexact validation summary was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}

	// The exact posture is accepted, including when the optional fields are
	// declared with their only permitted values.
	for _, summary := range []map[string]interface{}{
		exactDependencySummary(),
		func() map[string]interface{} {
			summary := exactDependencySummary()
			summary["source_bytes_present"] = false
			// Counts arrive from JSON decoding, so the integer accessor only
			// recognises a json.Number; a native int is not a declared integer.
			summary["issue_count"] = json.Number("0")
			return summary
		}(),
	} {
		got, err := validateDependencySummaryCommon(dependencySummaryInput(summary), expected)
		if err != nil {
			t.Fatalf("an exact validation summary was rejected: %v", err)
		}
		if got == nil {
			t.Fatalf("an accepted summary returned no summary map")
		}
	}
}

// A refused summary must stop the profile check before any count comparison, so
// the refusal cannot be masked by a later field-by-field mismatch.
func TestValidateProfileValidationSummaryPropagatesTheSummaryRefusal(t *testing.T) {
	err := validateProfileValidationSummary(dependencySummaryInput(nil), "", nil)
	if err == nil || !strings.Contains(err.Error(), "is missing") {
		t.Fatalf("error = %v, want the absent-summary refusal to propagate", err)
	}
}

// Credential recognition must not depend on the token being pure ASCII. A token
// carrying a non-ASCII byte still discloses a secret, so the non-ASCII path has
// to reach the same verdict as the ASCII one.
func TestKnownCredentialTokenRecognisesNonASCIIAndQuotedTokens(t *testing.T) {
	for _, test := range []struct {
		name  string
		token string
		want  bool
	}{
		{name: "prefixed token carrying a non-ASCII byte", token: "ghp_ABCDEFGHIJKLMNé0123456", want: true},
		{name: "aws key carrying a non-ASCII byte", token: "AKIAIOSFODNN7EXAMPé", want: true},
		{name: "non-ASCII payload with no credential prefix", token: "café not a credential at all", want: false},
		{name: "non-ASCII prefixed value too short to be a token", token: "ghp_éshort", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if stringIsASCII(test.token) {
				t.Fatalf("control failed: fixture %q is pure ASCII and cannot exercise the non-ASCII path", test.token)
			}
			if got := knownCredentialToken(test.token); got != test.want {
				t.Fatalf("knownCredentialToken(%q) = %v, want %v", test.token, got, test.want)
			}
		})
	}

	// A quoted assignment value is unwrapped before the credential-shape test,
	// so wrapping a secret in quotes does not hide it. The unquoted spelling
	// must reach the same verdict, which is what proves the unwrapping happened
	// rather than the value passing for some unrelated reason.
	const quoted = `ghp_"ABCDEFGHIJKLMNOP1"`
	if !knownCredentialToken(quoted) {
		t.Fatalf("a quoted credential value was not recognised")
	}
	if !knownCredentialToken("ghp_ABCDEFGHIJKLMNOP1") {
		t.Fatalf("control failed: the unquoted spelling is not recognised either")
	}
}
