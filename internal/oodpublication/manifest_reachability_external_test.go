package oodpublication_test

import (
	"context"
	"strings"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

func TestManifestClosureRejectsCanonicalButUnreferencedNode(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	in := oodpublication.CloneManifestClosureInput(f.Closure)
	var row oodpublication.SpannerRow
	for _, r := range in.ImmutableRows {
		if r.Table == "OODGraphManifestNodes" && r.Columns["manifest_kind"] == "object" {
			row = r
			break
		}
	}
	if row.Table == "" {
		t.Fatal("fixture manifest absent")
	}
	r := oodcanon.RecordValue{"manifest_kind": oodcanon.String("object"), "entry_count": oodcanon.I64(0), "transitive_member_count": oodcanon.I64(0), "canonical_byte_count": oodcanon.I64(0), "ordered_entry_tuples": {Type: oodcanon.Array, Presence: oodcanon.Present, Elements: []oodcanon.Value{}}}
	b, err := oodcanon.Encode(oodcanon.ManifestLeafV1(), r)
	if err != nil {
		t.Fatal(err)
	}
	r["canonical_byte_count"] = oodcanon.I64(int64(len(b)))
	h, err := oodcanon.DigestHexOf(oodcanon.ManifestLeafV1(), r)
	if err != nil {
		t.Fatal(err)
	}
	row.Columns = mapCopyForReachability(row.Columns)
	row.Columns["manifest_node_hash"], row.Columns["entry_count"], row.Columns["transitive_member_count"], row.Columns["canonical_byte_count"] = h, int64(0), int64(0), int64(len(b))
	in.Nodes = append(in.Nodes, oodpublication.ManifestNodeV8{Hash: h, OrganizationID: f.Certificate.OrganizationID, Kind: "object", NodeKind: "leaf", HashAlgorithm: "SHA-256", CanonicalizationProfile: "ood_graph_manifest_node_v1", CanonicalByteCount: int64(len(b)), Sealed: true, Row: &row})
	in.ImmutableRows = append(in.ImmutableRows, row)
	if err := oodpublication.VerifyManifestClosureV8(f.Certificate, in); err == nil || !strings.Contains(err.Error(), "unreferenced manifest node") {
		t.Fatalf("unreferenced canonical node rejection: %v", err)
	}
}

func mapCopyForReachability(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
