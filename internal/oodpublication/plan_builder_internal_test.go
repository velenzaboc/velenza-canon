package oodpublication

import (
	"fmt"
	"testing"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
)

func TestNativePlanManifestMeasuresEveryEntryAndNodeAndBuildsBoundedTree(t *testing.T) {
	members := make([]ManifestMemberV8, nativeManifestMaxEntries+1)
	for i := range members {
		members[i] = ManifestMemberV8{ManifestKind: "object", EntryKind: "object", MemberID: fmt.Sprintf("member-%04d", i), ClaimedHash: fmt.Sprintf("%064x", i+1)}
	}
	nodes, root, rows, err := nativePlanManifest("org", "object", members, time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if root.NodeKind != "internal" || len(nodes) != 3 || root.EntryCount != 2 || root.TransitiveMemberCount != int64(len(members)) {
		t.Fatalf("unbounded or wrong manifest topology: root=%+v nodes=%d", root, len(nodes))
	}
	if len(rows) != len(nodes)+len(members)+2 { // three nodes, then 1025 leaf plus two parent entries
		t.Fatalf("wrong physical manifest row count: %d", len(rows))
	}
	byHash := map[string]ManifestNodeV8{}
	for _, n := range nodes {
		byHash[n.Hash] = n
		if n.EntryCount > nativeManifestMaxEntries || n.CanonicalByteCount <= 1 {
			t.Fatalf("node did not use measured bounded canonical bytes: %+v", n)
		}
		for _, e := range n.Entries {
			if e.CanonicalByteCount <= 1 {
				t.Fatalf("entry did not use nested-record byte count: %+v", e)
			}
			encoded, err := oodcanon.EncodeNestedRecord(nativeOrdinaryEntryFields(n.NodeKind), nativeOrdinaryEntryValues(e, byHash))
			if err != nil || int64(len(encoded)) != e.CanonicalByteCount {
				t.Fatalf("entry byte count does not recompute: %v %d != %d", err, len(encoded), e.CanonicalByteCount)
			}
		}
		encoded, err := oodcanon.Encode(nativeOrdinaryProfile(n.NodeKind), ordinaryNodeRecord(n, byHash))
		if err != nil || int64(len(encoded)) != n.CanonicalByteCount {
			t.Fatalf("node byte count does not recompute: %v %d != %d", err, len(encoded), n.CanonicalByteCount)
		}
	}
}
