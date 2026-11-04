package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

// Rehash the changed facts, all nine roots and the certificate: this exercises
// semantic proof binding rather than rejection of a stale row digest.
func TestOOD8APIMaterializationRejectsRehashedAPIContentTriple(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	if _, err := BuildVerifiedOOD8APIMaterializationFromClosureInput(context.Background(), OOD8APIClosureMaterializationInput{Certificate: f.Certificate, Closure: f.Closure, Attestor: f.Attestor, Factory: OOD8APIFactoryOutput{Plan: f.Plan, LocatorProofs: f.LocatorProofs, EvidenceLocatorProofs: f.EvidenceLocatorProofs}}); err != nil {
		t.Fatalf("valid baseline rejected before hostile rehash: %v", err)
	}
	closure := oodpublication.CloneManifestClosureInput(f.Closure)
	var objectID, objectHash string
	for i := range closure.Members {
		m := &closure.Members[i]
		if m.Row != nil && m.Row.Table == "OODGraphObjects" && m.Row.Columns["api_element_role"] == "operation" {
			m.Row.Columns["source_content_hash_algorithm"] = "sha256"
			m.Row.Columns["source_content_hash_profile"] = "rehashed-canonical"
			m.Row.Columns["source_content_hash"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			objectID = m.Row.Columns["graph_object_id"].(string)
			var err error
			objectHash, err = oodpublication.CanonicalMemberDigestFromPhysicalRow(*m.Row)
			if err != nil {
				t.Fatal(err)
			}
			m.Row.Columns["graph_row_hash"], m.ClaimedHash = objectHash, objectHash
		}
	}
	if objectID == "" {
		t.Fatal("fixture operation absent")
	}
	for i := range closure.Members {
		m := &closure.Members[i]
		if m.Row != nil && m.Row.Table == "OODGraphAPIPropertyFacts" && m.Row.Columns["graph_object_id"] == objectID {
			m.Row.Columns["subject_graph_row_hash"] = objectHash
			d, err := closure.MemberVerifier.CanonicalMemberDigestFromPhysicalRow(context.Background(), *m.Row)
			if err != nil {
				t.Fatal(err)
			}
			m.Row.Columns["api_property_fact_hash"], m.MemberID, m.ClaimedHash = d, d, d
		}
	}
	rows := map[string]oodpublication.SpannerRow{}
	var locators []oodpublication.SpannerRow
	for _, m := range closure.Members {
		memberRows := m.EvidenceRows
		if m.Row != nil {
			memberRows = []oodpublication.SpannerRow{*m.Row}
		}
		for _, r := range memberRows {
			x, err := oodpublication.BuildImmutableRow(r.Table, r.Columns)
			if err != nil {
				t.Fatal(err)
			}
			rows[x.Key()] = x.Row()
			if r.Table == "OODGraphGraphFactEvidenceLocators" {
				locators = append(locators, r)
			}
		}
	}
	// Narrow role and documentation claim roots are auxiliary to the global
	// locator root rebuilt below. Preserve exactly their manifest rows, without
	// duplicating the certificate or global manifest rows BuildNativePlan makes.
	claimRoots := map[string]bool{}
	for _, row := range rows {
		switch row.Table {
		case "OODGraphObjects":
			if root, ok := row.Columns["api_element_role_locator_manifest_hash"].(string); ok && root != "" {
				claimRoots[root] = true
			}
		case "OODGraphRelationshipEvidence", "OODGraphAPIPropertyFacts":
			if root, ok := row.Columns["graph_fact_locator_manifest_hash"].(string); ok && root != "" {
				claimRoots[root] = true
			}
		}
	}
	preserveNodes := map[string]bool{}
	for root := range claimRoots {
		preserveNodes[root] = true
	}
	for changed := true; changed; {
		changed = false
		for _, row := range closure.ImmutableRows {
			if row.Table != "OODGraphManifestEntries" || !preserveNodes[row.Columns["manifest_node_hash"].(string)] {
				continue
			}
			if child, ok := row.Columns["child_manifest_node_hash"].(string); ok && child != "" && !preserveNodes[child] {
				preserveNodes[child] = true
				changed = true
			}
		}
	}
	for _, row := range closure.ImmutableRows {
		keep := (row.Table == "OODGraphManifestNodes" && preserveNodes[row.Columns["manifest_node_hash"].(string)]) || (row.Table == "OODGraphManifestEntries" && preserveNodes[row.Columns["manifest_node_hash"].(string)])
		if !keep {
			continue
		}
		x, err := oodpublication.BuildImmutableRow(row.Table, row.Columns)
		if err != nil {
			t.Fatal(err)
		}
		rows[x.Key()] = x.Row()
	}
	uniqueLocators := map[string]oodpublication.SpannerRow{}
	for _, locator := range locators {
		uniqueLocators[locator.Columns["graph_fact_locator_hash"].(string)] = locator
	}
	locators = locators[:0]
	for _, locator := range uniqueLocators {
		locators = append(locators, locator)
	}
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	claim, err := oodpublication.BuildNativeLocatorManifest(oodpublication.NativeLocatorManifestInput{OrganizationID: f.Certificate.OrganizationID, Locators: locators, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range claim.ImmutableRows {
		x, err := oodpublication.BuildImmutableRow(r.Table, r.Columns)
		if err != nil {
			t.Fatal(err)
		}
		rows[x.Key()] = x.Row()
	}
	physical := make([]oodpublication.SpannerRow, 0, len(rows))
	for _, r := range rows {
		physical = append(physical, r)
	}
	auxiliary := []oodpublication.ManifestNodeV8{}
	for _, node := range closure.Nodes {
		if preserveNodes[node.Hash] {
			auxiliary = append(auxiliary, node)
		}
	}
	auxiliary = append(auxiliary, claim.Nodes...)
	plan, err := oodpublication.BuildNativePlan(context.Background(), oodpublication.NativePlanBuildInput{OrganizationID: f.Certificate.OrganizationID, SnapshotKind: f.Certificate.SnapshotKind, SnapshotID: f.Plan.SnapshotID, RunID: f.Certificate.MaterializationRunID, Certificate: f.Certificate, Members: closure.Members, ImmutableRows: physical, AuxiliaryNodes: auxiliary, MemberVerifier: closure.MemberVerifier, Attestor: f.Attestor, CreatedAt: now})
	if err != nil {
		t.Fatalf("rehash coherent candidate before role proof check: %v", err)
	}
	if _, err := BuildVerifiedOOD8APIMaterialization(context.Background(), OOD8APINativeMaterializationOutput{Closure: plan.VerifiedClosure, Roster: plan.VerifiedRoster, Factory: OOD8APIFactoryOutput{Plan: plan.Plan, LocatorProofs: f.LocatorProofs, EvidenceLocatorProofs: f.EvidenceLocatorProofs}}); err == nil || !strings.Contains(err.Error(), "API role lacks matching verified locator") {
		t.Fatalf("rehashed source body inherited role proof: %v", err)
	}
}
