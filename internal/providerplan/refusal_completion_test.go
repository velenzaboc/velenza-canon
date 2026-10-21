package providerplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateStructuredDependencySecurityLabelsMemoryInputAndBoundsNesting(t *testing.T) {
	// A dependency validated straight from memory has no path, and its refusal
	// must still name something a reader can act on.
	deep := []byte(strings.Repeat("[", maxProviderJSONNestingDepth+1) + "0" + strings.Repeat("]", maxProviderJSONNestingDepth+1))
	err := validateStructuredDependencySecurity(artifactInput{Raw: deep})
	if err == nil {
		t.Fatal("a structured dependency past the fixed nesting depth was accepted")
	}
	if !strings.Contains(err.Error(), "<memory>") {
		t.Fatalf("error = %v, want the in-memory dependency labelled", err)
	}

	// The same bytes from a named artifact name that artifact instead.
	named := validateStructuredDependencySecurity(artifactInput{Raw: deep, Path: "dependency.jsonl"})
	if named == nil || !strings.Contains(named.Error(), "dependency.jsonl") {
		t.Fatalf("error = %v, want the named dependency labelled", named)
	}
}

func TestValidateStructuredDependencySecurityRejectsInvalidUTF8Rows(t *testing.T) {
	err := validateStructuredDependencySecurity(artifactInput{Raw: []byte{'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'}})
	if err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("error = %v, want an invalid UTF-8 refusal", err)
	}
}

func TestValidateDocumentationFactoryProductionSourceRunReceiptRefusesNonCandidatePosture(t *testing.T) {
	candidateOnly := func() DocumentationFactoryProductionSourceRunReceipt {
		return DocumentationFactoryProductionSourceRunReceipt{
			ReceiptKind:    documentationFactoryProductionSourceRunReceiptKind,
			ReceiptVersion: documentationFactoryProductionSourceRunReceiptVersion,
			Result:         documentationFactoryProductionSourceRunReceiptResult,
			Scope:          documentationFactoryProductionSourceRunReceiptScope,
			BodyFree:       true,
			ReceiptSHA256:  sha256Hex([]byte("receipt")),
		}
	}

	for _, test := range []struct {
		name   string
		mutate func(*DocumentationFactoryProductionSourceRunReceipt)
		want   string
	}{
		{
			name: "no identity at all",
			mutate: func(r *DocumentationFactoryProductionSourceRunReceipt) {
				*r = DocumentationFactoryProductionSourceRunReceipt{}
			},
			want: "identity or candidate-only posture is invalid",
		},
		{
			name:   "wrong receipt kind",
			mutate: func(r *DocumentationFactoryProductionSourceRunReceipt) { r.ReceiptKind = "some_other_receipt" },
			want:   "identity or candidate-only posture is invalid",
		},
		{
			name:   "receipt claims it carries bodies",
			mutate: func(r *DocumentationFactoryProductionSourceRunReceipt) { r.BodyFree = false },
			want:   "identity or candidate-only posture is invalid",
		},
		{
			name:   "receipt claims authority selection",
			mutate: func(r *DocumentationFactoryProductionSourceRunReceipt) { r.AuthoritySelected = true },
			want:   "identity or candidate-only posture is invalid",
		},
		{
			name:   "receipt claims admission authorization",
			mutate: func(r *DocumentationFactoryProductionSourceRunReceipt) { r.AdmissionAuthorized = true },
			want:   "identity or candidate-only posture is invalid",
		},
		{
			name:   "receipt claims factory completion",
			mutate: func(r *DocumentationFactoryProductionSourceRunReceipt) { r.FactoryComplete = true },
			want:   "identity or candidate-only posture is invalid",
		},
		{
			name:   "malformed receipt digest",
			mutate: func(r *DocumentationFactoryProductionSourceRunReceipt) { r.ReceiptSHA256 = "not-a-sha256" },
			want:   "digest is invalid",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			receipt := candidateOnly()
			test.mutate(&receipt)
			if err := ValidateDocumentationFactoryProductionSourceRunReceipt(receipt); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestResolveFactoryOutputPathRefusesPathsThatNameNoFile(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{name: "empty", path: "", want: "empty or padded"},
		{name: "blank", path: "   ", want: "empty or padded"},
		{name: "padded", path: " receipt.json", want: "empty or padded"},
		{name: "separator only", path: string(filepath.Separator), want: "does not name a file"},
		{name: "parent traversal component", path: filepath.Join("a", "..", "receipt.json"), want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := resolveFactoryOutputPath(test.path)
			if test.want == "" {
				// A cleaned traversal either resolves or is refused, but it must
				// never retain a traversal component in the parent chain.
				if err == nil {
					for _, component := range resolved.components {
						if component == ".." || component == "." || component == "" {
							t.Fatalf("resolved parent components %v retain a traversal component", resolved.components)
						}
					}
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestWriteFactoryReceiptExclusiveRefusesEmptyReceiptBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "factory-receipt.json")
	if err := writeFactoryReceiptExclusive(path, nil); err == nil ||
		!strings.Contains(err.Error(), "provider receipt bytes are empty") {
		t.Fatalf("empty receipt error = %v, want an empty-bytes refusal", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("a refused empty receipt still created %q: %v", path, err)
	}

	if err := writeFactoryReceiptExclusive(path, []byte{}); err == nil ||
		!strings.Contains(err.Error(), "provider receipt bytes are empty") {
		t.Fatalf("zero-length receipt error = %v, want an empty-bytes refusal", err)
	}
}
