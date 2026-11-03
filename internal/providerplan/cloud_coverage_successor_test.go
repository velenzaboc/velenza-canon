package providerplan

import (
	"os"
	"testing"
)

const cloudNeutralV3PredecessorHash = "906348b967d473a2fa7aa66fdab891ee8d90c3705a14473b4e74cea540dfae47"

func TestCloudCoverageSuccessorClosesExactPredecessorCoordinates(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/neutral-v3/previous-coverage.json")
	if err != nil {
		t.Fatal(err)
	}
	var prior CloudCoverageBacklog
	if err := strictUnmarshal(raw, &prior); err != nil {
		t.Fatal(err)
	}
	resolved := append([]CloudCoverageEntry(nil), prior.Entries...)
	split := -1
	preserved := -1
	for i := range resolved {
		if resolved[i].Disposition == CloudSourceUnsupported {
			resolved[i].Disposition = CloudSourceMapsExactSourceFact
			resolved[i].TargetField = "example"
			resolved[i].SemanticOwnerRef = "fixture/example"
			if split < 0 {
				split = i
			}
		} else {
			preserved = i
		}
	}
	// Test the comparison boundary with a one-to-many successor. Native
	// package tests exercise construction/validation of the new field proofs.
	part := resolved[split]
	resolved[split].SourcePointer += "/a"
	part.SourcePointer += "/b"
	resolved = append(resolved, part)
	seal := func(entries []CloudCoverageEntry) CloudCoverageBacklog {
		t.Helper()
		next := prior
		next.Entries = entries
		next.DispositionTotals, err = cloudCoverageTotals(entries)
		if err != nil {
			t.Fatal(err)
		}
		next.Document, err = canonicalCloudCoverageDocument(next)
		if err != nil {
			t.Fatal(err)
		}
		next.DocumentSHA256 = sha256Hex(next.Document)
		next.publicationSeal = cloudCoveragePublicationSeal(next.DocumentSHA256, next.ScopeSHA256)
		return next
	}
	ok := seal(resolved)
	audit, err := AuditCloudCoverageSuccessor(raw, cloudNeutralV3PredecessorHash, ok)
	if err != nil || audit.Preserved != 55 || len(audit.Resolutions) != 200 || len(audit.Resolutions[0].Successors) != 2 {
		t.Fatalf("wrong transition counts or grouping: %v", err)
	}
	for name, mutate := range map[string]func([]CloudCoverageEntry) []CloudCoverageEntry{
		"lost original": func(entries []CloudCoverageEntry) []CloudCoverageEntry {
			return append(entries[:preserved], entries[preserved+1:]...)
		},
		"foreign model": func(entries []CloudCoverageEntry) []CloudCoverageEntry {
			entries[split].ModelSHA256 = sha256Hex([]byte("other"))
			return entries
		},
		"foreign operation": func(entries []CloudCoverageEntry) []CloudCoverageEntry {
			entries[split].OperationID = "another-operation"
			return entries
		},
		"changed old disposition": func(entries []CloudCoverageEntry) []CloudCoverageEntry {
			entries[preserved].Disposition = CloudSourceUnknown
			return entries
		},
		"reused field name with other range": func(entries []CloudCoverageEntry) []CloudCoverageEntry {
			entries[preserved].SelectedRangeSHA256 = sha256Hex([]byte("other"))
			return entries
		},
		"unresolved child": func(entries []CloudCoverageEntry) []CloudCoverageEntry {
			entries[split].Disposition = CloudSourceUnsupported
			return entries
		},
		"missing neutral owner": func(entries []CloudCoverageEntry) []CloudCoverageEntry {
			entries[split].SemanticOwnerRef = ""
			return entries
		},
		"unjustified private": func(entries []CloudCoverageEntry) []CloudCoverageEntry {
			entries[split].Disposition = CloudSourcePrivateOnly
			return entries
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := mutate(append([]CloudCoverageEntry(nil), resolved...))
			if _, err := AuditCloudCoverageSuccessor(raw, cloudNeutralV3PredecessorHash, seal(bad)); err == nil {
				t.Fatal("accepted invalid successor")
			}
		})
	}
	if _, err := AuditCloudCoverageSuccessor(raw, sha256Hex([]byte("different")), ok); err == nil {
		t.Fatal("accepted wrong predecessor pin")
	}
}
