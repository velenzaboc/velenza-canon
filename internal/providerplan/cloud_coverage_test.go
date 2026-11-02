package providerplan

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloudCoverageBacklogAccountsForEverySelectedOccurrence(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	first, err := BuildCloudCoverageBacklog(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildCloudCoverageBacklog(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Document, second.Document) || first.DocumentSHA256 != sha256Hex(first.Document) {
		t.Fatal("coverage output is not deterministic and exact-byte bound")
	}
	if len(first.Entries) != 255 || first.DispositionTotals != (CloudMappingDispositionTotals{Mapped: 31, Private: 24, Unsupported: 200}) {
		t.Fatalf("coverage closure = %d %+v", len(first.Entries), first.DispositionTotals)
	}
	private, unsupported, nested := 0, 0, 0
	seen := map[string]bool{}
	for _, entry := range first.Entries {
		key := cloudCoverageEntryKey(entry)
		if seen[key] {
			t.Fatalf("duplicate coverage occurrence %q", key)
		}
		seen[key] = true
		if entry.ModelSourceID == "" || !isLowerSHA256(entry.ModelSHA256) || entry.RecordClassContractRef == "" || entry.AccountableOwnerRef != entry.RecordClassContractRef || !isLowerSHA256(entry.AccountableOwnerSHA256) || entry.SourcePointer == "" || entry.DispositionReason == "" || entry.NextOwnerAction == "" {
			t.Fatalf("incomplete coverage entry: %+v", entry)
		}
		if entry.DerivationProfileID == "" && entry.DerivationGapReason == "" {
			t.Fatalf("coverage omitted derivation coordinate: %+v", entry)
		}
		if entry.Disposition == CloudSourcePrivateOnly {
			private++
			if entry.NextOwnerAction == "" {
				t.Fatal("private occurrence has no owner action")
			}
		}
		if entry.Disposition == CloudSourceUnsupported {
			unsupported++
			if entry.NextOwnerAction == "" {
				t.Fatal("unsupported occurrence has no owner action")
			}
		}
		if entry.SourcePointer != "/" && len(entry.SourcePointer) > len("/x") && bytes.Count([]byte(entry.SourcePointer), []byte("/")) > 1 {
			nested++
		}
	}
	if private != 24 || unsupported != 200 || nested == 0 {
		t.Fatalf("private/unsupported/nested=%d/%d/%d", private, unsupported, nested)
	}
	if err := ValidateCloudCoverageBacklog(first.Document, request, scope); err != nil {
		t.Fatalf("validate exact coverage: %v", err)
	}
}

func TestCloudCoverageBacklogRefusesTamperingAndPublishesExclusively(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	backlog, err := BuildCloudCoverageBacklog(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte){
		"field disposition": func(raw []byte) { raw[bytes.Index(raw, []byte("unsupported"))] = 'x' },
		"field pointer":     func(raw []byte) { raw[bytes.Index(raw, []byte("source_pointer"))] = 'x' },
	} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), backlog.Document...)
			mutate(raw)
			if err := ValidateCloudCoverageBacklog(raw, request, scope); err == nil {
				t.Fatal("accepted tampered coverage bytes")
			}
		})
	}
	root := filepath.Join(t.TempDir(), "coverage")
	if err := WriteCloudCoverageBacklogExclusive(root, backlog); err != nil {
		t.Fatal(err)
	}
	forged := backlog
	forged.Document = []byte("forged\n")
	forged.DocumentSHA256 = sha256Hex(forged.Document)
	if err := WriteCloudCoverageBacklogExclusive(filepath.Join(t.TempDir(), "forged"), forged); err == nil {
		t.Fatal("coverage writer accepted body bytes not issued by the coverage compiler")
	}
	for _, mutate := range []struct {
		name   string
		change func(*CloudCoverageBacklog)
	}{
		{"scope metadata", func(value *CloudCoverageBacklog) { value.ScopeID = "substituted" }},
		{"declared totals", func(value *CloudCoverageBacklog) { value.DispositionTotals.Mapped++ }},
		{"entry owner", func(value *CloudCoverageBacklog) { value.Entries[0].AccountableOwnerSHA256 = strings.Repeat("0", 64) }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			mutated := backlog
			mutated.Entries = append([]CloudCoverageEntry(nil), backlog.Entries...)
			mutate.change(&mutated)
			if err := WriteCloudCoverageBacklogExclusive(filepath.Join(t.TempDir(), "mutated"), mutated); err == nil {
				t.Fatalf("coverage writer accepted mutated %s with an old sealed document", mutate.name)
			}
		})
	}
	if err := WriteCloudCoverageBacklogExclusive(root, backlog); err == nil {
		t.Fatal("coverage overwrote existing output")
	}
}
