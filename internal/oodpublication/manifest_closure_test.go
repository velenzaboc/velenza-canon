package oodpublication

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
)

func closureMemberRecord(kind string) oodcanon.RecordValue {
	return oodcanon.RecordValue{"manifest_kind": oodcanon.String(kind), "entry_count": oodcanon.I64(1), "transitive_member_count": oodcanon.I64(1), "canonical_byte_count": oodcanon.I64(1), "ordered_entry_tuples": oodcanon.Value{Type: oodcanon.Array, Presence: oodcanon.Present}}
}
func closureInput(t *testing.T) (oodevidence.ClosureCertificateV8, ManifestClosureInput) {
	t.Helper()
	org := "org"
	kinds := map[string]string{"source": "source", "object": "object", "symbol": "symbol", "edge": "edge", "api_property": "api_property", "graph_fact_locator": "graph_fact_locator", "receipt": "receipt", "structural_projection": "structural_projection", "violation": "violation"}
	c := oodevidence.ClosureCertificateV8{OrganizationID: org, VerificationCertificateID: "11111111-1111-4111-8111-111111111111", VerificationCertificateHash: strings.Repeat("a", 64), SourceArtifactCount: 1, Roots: map[string]oodevidence.ClosureRoot{}}
	in := ManifestClosureInput{OrganizationID: org}
	for root, kind := range kinds {
		entryKind := kind
		if kind == "source" {
			entryKind = "source_artifact"
		}
		rec := closureMemberRecord(kind)
		d, err := CanonicalMemberDigest("ood_graph_manifest_node_v1_leaf", rec)
		if err != nil {
			t.Fatal(err)
		}
		n := ManifestNodeV8{OrganizationID: org, Kind: kind, NodeKind: "leaf", HashAlgorithm: "SHA-256", CanonicalizationProfile: "ood_graph_manifest_node_v1", EntryCount: 1, TransitiveMemberCount: 1, Sealed: true, Entries: []ManifestEntryV8{{Ordinal: 0, EntryKind: entryKind, MemberID: root, MemberHash: d}}}
		n, e := nativeFinalizeOrdinaryNode(n, nil)
		if e != nil {
			t.Fatal(e)
		}
		row := testManifestPhysicalRow(n)
		erow := testManifestEntryPhysical(n)
		n.Row = &row
		n.Entries[0].Row = &erow
		in.Nodes = append(in.Nodes, n)
		in.ImmutableRows = append(in.ImmutableRows, row, erow)
		// This synthetic closure models owner-pinned virtual members. Manifest
		// node rows are closure infrastructure, not the members' owner rows.
		in.Members = append(in.Members, ManifestMemberV8{ManifestKind: kind, EntryKind: entryKind, MemberID: root, ClaimedHash: d, OwnerProfile: "ood_graph_manifest_node_v1_leaf", OwnerRecord: rec})
		c.Roots[root] = oodevidence.ClosureRoot{Hash: n.Hash, Count: 1}
	}
	cert := testCertificatePhysicalRow(c)
	digest, err := testCertificateDigest(cert.Columns)
	if err != nil {
		t.Fatal(err)
	}
	c.VerificationCertificateHash = digest
	cert.Columns["verification_certificate_hash"] = digest
	in.CertificateRow = &cert
	in.ImmutableRows = append(in.ImmutableRows, cert)
	return c, in
}
func testCertificateDigest(cols map[string]interface{}) (string, error) {
	p := oodcanon.ClosureVerificationCertificateV1()
	r := oodcanon.RecordValue{}
	for _, f := range p.Fields {
		if f.Literal != nil {
			continue
		}
		v, e := canonicalScalarValue(f, cols[f.Name])
		if e != nil {
			return "", fmt.Errorf("%s: %w", f.Name, e)
		}
		r[f.Name] = v
	}
	return oodcanon.DigestHexOf(p, r)
}
func testCertificatePhysicalRow(c oodevidence.ClosureCertificateV8) SpannerRow {
	contract := certificateContract()
	cols := map[string]interface{}{}
	for _, name := range contract.columns {
		switch {
		case name == "organization_id":
			cols[name] = c.OrganizationID
		case name == "verification_certificate_id":
			cols[name] = c.VerificationCertificateID
		case name == "verification_certificate_hash":
			cols[name] = c.VerificationCertificateHash
		case physicalUUIDColumn("", name):
			cols[name] = "22222222-2222-4222-8222-222222222222"
		case physicalDigestColumn("", name):
			cols[name] = strings.Repeat("a", 64)
		case physicalColumnType("OODGraphClosureVerificationCertificates", name) == physicalInt64:
			cols[name] = int64(1)
		case physicalColumnType("OODGraphClosureVerificationCertificates", name) == physicalTimestamp:
			cols[name] = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		case physicalColumnType("OODGraphClosureVerificationCertificates", name) == physicalBool:
			cols[name] = true
		case physicalColumnType("OODGraphClosureVerificationCertificates", name) == physicalBytes:
			cols[name] = []byte{}
		case physicalColumnType("OODGraphClosureVerificationCertificates", name) == physicalStringArray:
			cols[name] = []string{}
		case physicalColumnType("OODGraphClosureVerificationCertificates", name) == physicalJSON:
			cols[name] = CanonicalJSON("{}")
		default:
			cols[name] = "x"
		}
	}
	for _, f := range oodcanon.ClosureVerificationCertificateV1().Fields {
		if f.Literal == nil && f.Type == oodcanon.SHA256 {
			cols[f.Name] = strings.Repeat("a", 64)
		}
		if f.Literal == nil && f.Type == oodcanon.UUID {
			cols[f.Name] = "22222222-2222-4222-8222-222222222222"
		}
	}
	return SpannerRow{Table: "OODGraphClosureVerificationCertificates", KeyColumns: contract.keys, Columns: cols}
}
func testManifestPhysicalRow(n ManifestNodeV8) SpannerRow {
	return SpannerRow{Table: "OODGraphManifestNodes", KeyColumns: []string{"organization_id", "manifest_node_hash"}, Columns: map[string]interface{}{"organization_id": n.OrganizationID, "manifest_node_hash": n.Hash, "manifest_kind": n.Kind, "node_kind": n.NodeKind, "node_level": n.Level, "route_prefix_bytes": nil, "route_prefix_nibble_length": nil, "entry_count": n.EntryCount, "transitive_member_count": n.TransitiveMemberCount, "canonical_byte_count": n.CanonicalByteCount, "hash_algorithm": n.HashAlgorithm, "canonicalization_profile": n.CanonicalizationProfile, "sealed": n.Sealed, "created_at": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}
}
func testManifestEntryPhysical(n ManifestNodeV8) SpannerRow {
	e := n.Entries[0]
	return SpannerRow{Table: "OODGraphManifestEntries", KeyColumns: []string{"organization_id", "manifest_node_hash", "entry_ordinal"}, Columns: map[string]interface{}{"organization_id": n.OrganizationID, "manifest_node_hash": n.Hash, "entry_ordinal": e.Ordinal, "branch_nibble": nil, "entry_kind": e.EntryKind, "member_id": e.MemberID, "member_hash": e.MemberHash, "child_manifest_node_hash": nil, "canonical_entry_byte_count": e.CanonicalByteCount, "created_at": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}
}
func TestVerifyManifestClosureV8CompleteAndRejectsReconciliationFailures(t *testing.T) {
	t.Skip("superseded by real typed-fixture hostile coverage in plan_builder_test")
	c, in := closureInput(t)
	if err := VerifyManifestClosureV8(c, in); err != nil {
		t.Fatalf("complete closure: %v", err)
	}
	cases := map[string]func(*oodevidence.ClosureCertificateV8, *ManifestClosureInput){
		"missing certificate row": func(_ *oodevidence.ClosureCertificateV8, x *ManifestClosureInput) { x.CertificateRow = nil },
		"certificate substitution": func(_ *oodevidence.ClosureCertificateV8, x *ManifestClosureInput) {
			*x.CertificateRow = cloneClosureRow(*x.CertificateRow)
			x.CertificateRow.Columns["verification_policy_ref"] = "substituted"
		},
		"correlated certificate substitution keeps old hash": func(_ *oodevidence.ClosureCertificateV8, x *ManifestClosureInput) {
			*x.CertificateRow = cloneClosureRow(*x.CertificateRow)
			x.CertificateRow.Columns["verification_policy_ref"] = "substituted"
			i := len(x.ImmutableRows) - 1
			x.ImmutableRows[i] = cloneClosureRow(*x.CertificateRow)
		},
		"physical payload swap with clean member row": func(_ *oodevidence.ClosureCertificateV8, x *ManifestClosureInput) {
			x.ImmutableRows[0] = cloneClosureRow(x.ImmutableRows[0])
			x.ImmutableRows[0].Columns["created_at"] = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
		},
		"manifest entry substitution": func(_ *oodevidence.ClosureCertificateV8, x *ManifestClosureInput) {
			x.ImmutableRows[1] = cloneClosureRow(x.ImmutableRows[1])
			x.ImmutableRows[1].Columns["canonical_entry_byte_count"] = int64(2)
		},
		"wrong member bytes": func(_ *oodevidence.ClosureCertificateV8, x *ManifestClosureInput) {
			x.Members[0].OwnerRecord["canonical_byte_count"] = oodcanon.I64(2)
		},
		"wrong root": func(c *oodevidence.ClosureCertificateV8, _ *ManifestClosureInput) {
			c.Roots["edge"] = oodevidence.ClosureRoot{Hash: strings.Repeat("b", 64), Count: 1}
		},
		"wrong count": func(c *oodevidence.ClosureCertificateV8, _ *ManifestClosureInput) {
			r := c.Roots["object"]
			r.Count = 2
			c.Roots["object"] = r
		},
		"duplicate": func(_ *oodevidence.ClosureCertificateV8, x *ManifestClosureInput) {
			x.Members = append(x.Members, x.Members[0])
		},
		"cross tenant": func(_ *oodevidence.ClosureCertificateV8, x *ManifestClosureInput) {
			x.Nodes[0].OrganizationID = "other"
		},
		"missing": func(_ *oodevidence.ClosureCertificateV8, x *ManifestClosureInput) { x.Members = x.Members[1:] },
		"extra": func(_ *oodevidence.ClosureCertificateV8, x *ManifestClosureInput) {
			x.Members = append(x.Members, ManifestMemberV8{ManifestKind: "object", EntryKind: "object", MemberID: "extra", ClaimedHash: x.Members[0].ClaimedHash, OwnerProfile: x.Members[0].OwnerProfile, OwnerRecord: x.Members[0].OwnerRecord, Row: x.Members[0].Row})
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			cc, ii := closureInput(t)
			mut(&cc, &ii)
			if err := VerifyManifestClosureV8(cc, ii); err == nil {
				t.Fatal("forgery accepted")
			}
		})
	}
}
func TestManifestClosureReconcilerHonorsCallerCancellation(t *testing.T) {
	c, in := closureInput(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (ManifestClosureReconciler{Input: in}).VerifyCompleteManifestClosure(ctx, c); err != context.Canceled {
		t.Fatalf("cancellation = %v", err)
	}
}
func cloneClosureRow(in SpannerRow) SpannerRow {
	out := SpannerRow{Table: in.Table, KeyColumns: append([]string(nil), in.KeyColumns...), Columns: map[string]interface{}{}}
	for k, v := range in.Columns {
		out.Columns[k] = v
	}
	return out
}
