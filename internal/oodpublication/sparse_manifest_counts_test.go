package oodpublication

import (
	"strings"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
)

func TestSparseManifestRejectsRehashedFalseCanonicalCounts(t *testing.T) {
	p := oodcanon.SparsePatriciaMembershipNodeV1()
	for _, kind := range []string{"sparse_empty", "sparse_branch"} {
		t.Run(kind, func(t *testing.T) {
			n := ManifestNodeV8{Kind: "object", NodeKind: kind, CanonicalizationProfile: p.Name}
			if kind == "sparse_branch" {
				n.Entries = []ManifestEntryV8{{BranchNibble: 1, EntryKind: "object", MemberID: "11111111-1111-4111-8111-111111111111", MemberHash: strings.Repeat("a", 64)}}
				n.EntryCount, n.TransitiveMemberCount = 1, 1
				r := sparseNodeRecord(n)
				b, err := oodcanon.EncodeNestedRecord(p.Fields[len(p.Fields)-1].Element.Nested, r["ordered_present_slot_tuples"].Elements[0].Fields)
				if err != nil {
					t.Fatal(err)
				}
				n.Entries[0].CanonicalByteCount = int64(len(b))
			}
			b, err := oodcanon.Encode(p, sparseNodeRecord(n))
			if err != nil {
				t.Fatal(err)
			}
			n.CanonicalByteCount = int64(len(b))
			n.Hash, err = oodcanon.DigestHexOf(p, sparseNodeRecord(n))
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyNodeHash(n, map[string]ManifestNodeV8{n.Hash: n}); err != nil {
				t.Fatalf("valid sparse node: %v", err)
			}
			bad := n
			bad.CanonicalByteCount++
			bad.Hash, _ = oodcanon.DigestHexOf(p, sparseNodeRecord(bad))
			if err := verifyNodeHash(bad, map[string]ManifestNodeV8{bad.Hash: bad}); err == nil {
				t.Fatal("rehashing accepted a false node byte count")
			}
			if len(n.Entries) != 0 {
				bad = n
				bad.Entries = append([]ManifestEntryV8(nil), n.Entries...)
				bad.Entries[0].CanonicalByteCount++
				bad.Hash, _ = oodcanon.DigestHexOf(p, sparseNodeRecord(bad))
				if err := verifyNodeHash(bad, map[string]ManifestNodeV8{bad.Hash: bad}); err == nil {
					t.Fatal("rehashing accepted a false slot byte count")
				}
			}
		})
	}
}
