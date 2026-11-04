package oodpublication_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

func TestBuildNativePlanConstructsAndVerifiesAllNineRoots(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	rows := fixturePlanRows(t, f)
	out, err := oodpublication.BuildNativePlan(context.Background(), oodpublication.NativePlanBuildInput{OrganizationID: f.Certificate.OrganizationID, SnapshotKind: f.Certificate.SnapshotKind, SnapshotID: f.Plan.SnapshotID, RunID: f.Certificate.MaterializationRunID, Certificate: f.Certificate, Members: f.Closure.Members, ImmutableRows: rows, AuxiliaryNodes: fixtureAuxiliaryNodes(f), MemberVerifier: f.Closure.MemberVerifier, Attestor: f.Attestor, CreatedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("construct native plan: %v", err)
	}
	if out.Plan.ClosureHash != out.VerifiedClosure.ClosureHash() || out.Certificate.Roots["violation"].Count != 0 || len(out.Plan.ImmutableRows) == 0 {
		t.Fatalf("native construction did not close plan: %+v", out.Certificate.Roots["violation"])
	}
}

func TestNativePlanDraftThenFinalizeBindsNewContentBeforeAttestation(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	rows := fixturePlanRows(t, f)
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	draft, err := oodpublication.BuildNativePlanDraft(context.Background(), oodpublication.NativePlanDraftInput{
		OrganizationID: f.Certificate.OrganizationID, SnapshotKind: f.Certificate.SnapshotKind,
		Certificate: f.Certificate, Members: f.Closure.Members, ImmutableRows: rows, AuxiliaryNodes: fixtureAuxiliaryNodes(f),
		MemberVerifier: f.Closure.MemberVerifier, CreatedAt: now,
	})
	if err != nil || draft.Certificate.ClosureHash == "" || len(draft.ImmutableRoster) == 0 {
		t.Fatalf("build exact successor draft: %v", err)
	}
	out, err := oodpublication.FinalizeNativePlan(context.Background(), draft, oodpublication.NativePlanBuildInput{
		OrganizationID: f.Certificate.OrganizationID, SnapshotKind: f.Certificate.SnapshotKind,
		SnapshotID: f.Plan.SnapshotID, RunID: f.Certificate.MaterializationRunID,
		Certificate: f.Certificate, Attestor: f.Attestor, CreatedAt: now,
	})
	if err != nil || out.Certificate.ClosureHash != draft.Certificate.ClosureHash {
		t.Fatalf("finalize issued draft: %v", err)
	}
	// Finalization must reject a different boot allocation timestamp before it
	// can replay construction or ask the closure attestor to verify anything.
	_, err = oodpublication.FinalizeNativePlan(context.Background(), draft, oodpublication.NativePlanBuildInput{
		OrganizationID: f.Certificate.OrganizationID, SnapshotKind: f.Certificate.SnapshotKind,
		SnapshotID: f.Plan.SnapshotID, RunID: f.Certificate.MaterializationRunID,
		Certificate: f.Certificate, Attestor: f.Attestor, CreatedAt: now.Add(time.Microsecond),
	})
	if err == nil {
		t.Fatal("different successor allocation reached finalization")
	}
}

func TestBuildNativeLocatorManifestRejectsDuplicateAndBuildsClaimRoot(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	var locator oodpublication.SpannerRow
	for _, m := range f.Closure.Members {
		if m.ManifestKind == "graph_fact_locator" {
			locator = *m.Row
			break
		}
	}
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	out, err := oodpublication.BuildNativeLocatorManifest(oodpublication.NativeLocatorManifestInput{OrganizationID: f.Certificate.OrganizationID, Locators: []oodpublication.SpannerRow{locator}, CreatedAt: now})
	if err != nil || out.RootHash == "" || len(out.ImmutableRows) != 2 {
		t.Fatalf("build claim locator root: %v", err)
	}
	if _, err = oodpublication.BuildNativeLocatorManifest(oodpublication.NativeLocatorManifestInput{OrganizationID: f.Certificate.OrganizationID, Locators: []oodpublication.SpannerRow{locator, locator}, CreatedAt: now}); err == nil {
		t.Fatal("duplicate locator formed a claim root")
	}
}

func TestRealClosureRejectsRehashedCanonicalCountSubstitution(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	in := oodpublication.CloneManifestClosureInput(f.Closure)
	// A count is part of the owner-pinned preimage, but it must also equal the
	// independently encoded range. Rehashing a changed count cannot bless it.
	for i := range in.Nodes {
		if in.Nodes[i].CanonicalizationProfile == "ood_graph_manifest_node_v1" {
			in.Nodes[i].CanonicalByteCount++
			break
		}
	}
	if err := (oodpublication.ManifestClosureReconciler{Input: in}).VerifyCompleteManifestClosure(context.Background(), f.Certificate); err == nil {
		t.Fatal("rehashed-style canonical count substitution reached closure verification")
	}
}

func TestBuildNativePlanRejectsTamperedTypedMember(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	rows := planMemberRows(t, f.Closure.Members)
	members := append([]oodpublication.ManifestMemberV8(nil), f.Closure.Members...)
	for i := range members {
		if members[i].ManifestKind == "object" {
			members[i].ClaimedHash = strings.Repeat("0", 64)
			break
		}
	}
	_, err := oodpublication.BuildNativePlan(context.Background(), oodpublication.NativePlanBuildInput{OrganizationID: f.Certificate.OrganizationID, SnapshotKind: f.Certificate.SnapshotKind, SnapshotID: f.Plan.SnapshotID, RunID: f.Certificate.MaterializationRunID, Certificate: f.Certificate, Members: members, ImmutableRows: rows, AuxiliaryNodes: fixtureAuxiliaryNodes(f), MemberVerifier: f.Closure.MemberVerifier, Attestor: f.Attestor, CreatedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)})
	if err == nil {
		t.Fatal("tampered member reached plan construction")
	}
}

// These are correlated substitutions: each hostile arm rehashes its changed
// typed member and lets BuildNativePlan rebuild every manifest root and the
// closure certificate.  Rejection therefore proves cross-member closure, not
// a stale member/root/certificate assertion.
func TestBuildNativePlanRejectsRehashedDisconnectedCrossMembers(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	bad := strings.Repeat("b", 64)
	cases := map[string]func(*oodpublication.ManifestMemberV8){
		"locator source artifact": func(m *oodpublication.ManifestMemberV8) { m.Row.Columns["source_artifact_member_hash"] = bad },
		"relationship locator":    func(m *oodpublication.ManifestMemberV8) { m.Row.Columns["graph_fact_locator_manifest_hash"] = bad },
		"relationship archive binding": func(m *oodpublication.ManifestMemberV8) {
			m.Row.Columns["evidence_archive_record_id"] = "11111111-1111-4111-8111-111111111111"
		},
		"property locator root": func(m *oodpublication.ManifestMemberV8) { m.Row.Columns["graph_fact_locator_manifest_hash"] = bad },
		"property object subject": func(m *oodpublication.ManifestMemberV8) {
			m.Row.Columns["graph_object_id"], m.Row.Columns["subject_graph_row_hash"] = "11111111-1111-4111-8111-111111111111", bad
		},
		"symbol owner": func(m *oodpublication.ManifestMemberV8) {
			m.Row.Columns["graph_object_id"] = "11111111-1111-4111-8111-111111111111"
		},
		"edge endpoint": func(m *oodpublication.ManifestMemberV8) {
			m.Row.Columns["target_endpoint_id"] = "11111111-1111-4111-8111-111111111111"
		},
	}
	kinds := map[string]string{"locator source artifact": "graph_fact_locator", "relationship locator": "source", "relationship archive binding": "source", "property locator root": "api_property", "property object subject": "api_property", "symbol owner": "symbol", "edge endpoint": "edge"}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			members := clonePlanMembers(f.Closure.Members)
			for i := range members {
				if members[i].ManifestKind == kinds[name] && (kinds[name] != "source" || members[i].EntryKind == "relationship_evidence") {
					mutate(&members[i])
					if members[i].ManifestKind == "graph_fact_locator" {
						l := f.Locator
						l.SourceArtifactMemberHash = bad
						var e error
						l.LocatorHash, e = l.ComputedHash()
						if e != nil {
							t.Fatal(e)
						}
						members[i].Row.Columns["graph_fact_locator_hash"] = l.LocatorHash
					}
					var err error
					if members[i].ManifestKind == "api_property" {
						members[i].ClaimedHash, err = f.Closure.MemberVerifier.CanonicalMemberDigestFromPhysicalRow(context.Background(), *members[i].Row)
					} else {
						members[i].ClaimedHash, err = oodpublication.CanonicalMemberDigestFromPhysicalRow(*members[i].Row)
					}
					if err != nil {
						t.Fatal(err)
					}
					switch members[i].ManifestKind {
					case "source":
						members[i].Row.Columns["relationship_evidence_hash"] = members[i].ClaimedHash
					case "object", "symbol", "edge":
						members[i].Row.Columns["graph_row_hash"] = members[i].ClaimedHash
					case "api_property":
						members[i].Row.Columns["api_property_fact_hash"] = members[i].ClaimedHash
					}
					break
				}
			}
			rows := planMemberRows(t, members)
			_, err := oodpublication.BuildNativePlan(context.Background(), oodpublication.NativePlanBuildInput{OrganizationID: f.Certificate.OrganizationID, SnapshotKind: f.Certificate.SnapshotKind, SnapshotID: f.Plan.SnapshotID, RunID: f.Certificate.MaterializationRunID, Certificate: f.Certificate, Members: members, ImmutableRows: rows, MemberVerifier: f.Closure.MemberVerifier, Attestor: f.Attestor, CreatedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)})
			if err == nil {
				t.Fatal("rehashed disconnected member reached plan construction")
			}
		})
	}
	t.Run("source receipt omitted from receipt root", func(t *testing.T) {
		members := clonePlanMembers(f.Closure.Members)
		out := members[:0]
		for _, m := range members {
			if m.ManifestKind != "receipt" {
				out = append(out, m)
			}
		}
		_, err := oodpublication.BuildNativePlan(context.Background(), oodpublication.NativePlanBuildInput{OrganizationID: f.Certificate.OrganizationID, SnapshotKind: f.Certificate.SnapshotKind, SnapshotID: f.Plan.SnapshotID, RunID: f.Certificate.MaterializationRunID, Certificate: f.Certificate, Members: out, ImmutableRows: planMemberRows(t, out), MemberVerifier: f.Closure.MemberVerifier, Attestor: f.Attestor, CreatedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)})
		if err == nil {
			t.Fatal("virtual source receipt without receipt-root member reached plan construction")
		}
	})
	t.Run("coordinated foreign locator archive tuple", func(t *testing.T) {
		members := clonePlanMembers(f.Closure.Members)
		foreignArchive := "11111111-1111-4111-8111-111111111111"
		locator := f.Locator
		locator.EvidenceArchiveRecordID = foreignArchive
		var err error
		locator.LocatorHash, err = locator.ComputedHash()
		if err != nil {
			t.Fatal(err)
		}
		var oldRoleRoot string
		for _, m := range members {
			if m.ManifestKind == "object" && m.Row.Columns["object_class"] == "api_symbol" {
				oldRoleRoot, _ = m.Row.Columns["api_element_role_locator_manifest_hash"].(string)
				break
			}
		}
		if oldRoleRoot == "" {
			t.Fatal("fixture role claim root absent")
		}
		var roleLocatorRow oodpublication.SpannerRow
		for i := range members {
			if members[i].ManifestKind != "graph_fact_locator" || members[i].Row.Columns["graph_fact_locator_hash"] != f.Locator.LocatorHash {
				continue
			}
			members[i].Row.Columns["evidence_archive_record_id"], members[i].Row.Columns["graph_fact_locator_hash"] = foreignArchive, locator.LocatorHash
			members[i].ClaimedHash, err = oodpublication.CanonicalMemberDigestFromPhysicalRow(*members[i].Row)
			if err != nil {
				t.Fatal(err)
			}
			roleLocatorRow = *members[i].Row
		}
		if roleLocatorRow.Table == "" {
			t.Fatal("fixture role locator absent")
		}
		claim, err := oodpublication.BuildNativeLocatorManifest(oodpublication.NativeLocatorManifestInput{OrganizationID: f.Certificate.OrganizationID, Locators: []oodpublication.SpannerRow{roleLocatorRow}, CreatedAt: time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)})
		if err != nil {
			t.Fatal(err)
		}
		objectHashes := map[string]string{}
		for i := range members {
			if members[i].ManifestKind != "object" {
				continue
			}
			if members[i].Row.Columns["object_class"] != "api_symbol" {
				continue
			}
			members[i].Row.Columns["api_element_role_locator_manifest_hash"] = claim.RootHash
			members[i].ClaimedHash, err = oodpublication.CanonicalMemberDigestFromPhysicalRow(*members[i].Row)
			if err != nil {
				t.Fatal(err)
			}
			members[i].Row.Columns["graph_row_hash"] = members[i].ClaimedHash
			objectHashes[members[i].Row.Columns["graph_object_id"].(string)] = members[i].ClaimedHash
		}
		for i := range members {
			switch members[i].ManifestKind {
			case "source":
				if members[i].EntryKind != "relationship_evidence" {
					continue
				}
				if members[i].Row.Columns["edge_label"] == "documents" {
					continue
				}
				members[i].Row.Columns["graph_fact_locator_manifest_hash"], members[i].Row.Columns["evidence_archive_record_id"] = claim.RootHash, foreignArchive
				members[i].ClaimedHash, err = oodpublication.CanonicalMemberDigestFromPhysicalRow(*members[i].Row)
				if err != nil {
					t.Fatal(err)
				}
				members[i].Row.Columns["relationship_evidence_hash"] = members[i].ClaimedHash
			case "api_property":
				members[i].Row.Columns["graph_fact_locator_manifest_hash"] = claim.RootHash
				members[i].Row.Columns["subject_graph_row_hash"] = objectHashes[members[i].Row.Columns["graph_object_id"].(string)]
				members[i].ClaimedHash, err = f.Closure.MemberVerifier.CanonicalMemberDigestFromPhysicalRow(context.Background(), *members[i].Row)
				if err != nil {
					t.Fatal(err)
				}
				members[i].Row.Columns["api_property_fact_hash"] = members[i].ClaimedHash
			}
		}
		auxiliary := fixtureAuxiliaryNodes(f)
		kept := auxiliary[:0]
		for _, n := range auxiliary {
			if n.Hash != oldRoleRoot {
				kept = append(kept, n)
			}
		}
		auxiliary = append(kept, claim.Nodes...)
		rows := planMemberRows(t, members)
		for _, row := range fixturePlanRows(t, f) {
			if (row.Table == "OODGraphManifestNodes" || row.Table == "OODGraphManifestEntries") && row.Columns["manifest_node_hash"] == oldRoleRoot {
				continue
			}
			if row.Table == "OODGraphManifestNodes" || row.Table == "OODGraphManifestEntries" {
				rows = append(rows, row)
			}
		}
		rows = append(rows, claim.ImmutableRows...)
		_, err = oodpublication.BuildNativePlan(context.Background(), oodpublication.NativePlanBuildInput{OrganizationID: f.Certificate.OrganizationID, SnapshotKind: f.Certificate.SnapshotKind, SnapshotID: f.Plan.SnapshotID, RunID: f.Certificate.MaterializationRunID, Certificate: f.Certificate, Members: members, ImmutableRows: rows, AuxiliaryNodes: auxiliary, MemberVerifier: f.Closure.MemberVerifier, Attestor: f.Attestor, CreatedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)})
		if err == nil {
			t.Fatal("coordinated foreign locator archive tuple reached plan construction")
		}
	})
}

func clonePlanMembers(in []oodpublication.ManifestMemberV8) []oodpublication.ManifestMemberV8 {
	out := append([]oodpublication.ManifestMemberV8(nil), in...)
	for i := range out {
		if out[i].Row == nil {
			continue
		}
		r := *out[i].Row
		r.Columns = map[string]interface{}{}
		for k, v := range out[i].Row.Columns {
			r.Columns[k] = v
		}
		out[i].Row = &r
	}
	return out
}

func planMemberRows(t *testing.T, members []oodpublication.ManifestMemberV8) []oodpublication.SpannerRow {
	t.Helper()
	rows := []oodpublication.SpannerRow{}
	seen := map[string]bool{}
	for _, m := range members {
		candidate := append([]oodpublication.SpannerRow(nil), m.EvidenceRows...)
		if m.Row != nil {
			candidate = append(candidate, *m.Row)
		}
		for _, row := range candidate {
			b, err := oodpublication.CanonicalImmutableRowBytes(row)
			if err != nil {
				t.Fatal(err)
			}
			if !seen[string(b)] {
				seen[string(b)] = true
				rows = append(rows, row)
			}
		}
	}
	return rows
}

// fixtureAuxiliaryNodes retains the fixture's claim submanifests separately
// from the fixed nine certificate roots. The native builder must receive both
// so relationship/property/documentation claim roots remain traversable.
func fixtureAuxiliaryNodes(f oodtestfixture.Fixture) []oodpublication.ManifestNodeV8 {
	root := map[string]bool{}
	for _, x := range f.Certificate.Roots {
		root[x.Hash] = true
	}
	out := []oodpublication.ManifestNodeV8{}
	for _, n := range f.Closure.Nodes {
		if !root[n.Hash] {
			out = append(out, n)
		}
	}
	return out
}

func fixturePlanRows(t *testing.T, f oodtestfixture.Fixture) []oodpublication.SpannerRow {
	t.Helper()
	rows := planMemberRows(t, f.Closure.Members)
	aux := map[string]bool{}
	for _, n := range fixtureAuxiliaryNodes(f) {
		aux[n.Hash] = true
	}
	for _, row := range f.Closure.ImmutableRows {
		if row.Table != "OODGraphManifestNodes" && row.Table != "OODGraphManifestEntries" {
			continue
		}
		hash, _ := row.Columns["manifest_node_hash"].(string)
		if aux[hash] {
			rows = append(rows, row)
		}
	}
	return rows
}
