package oodapi

import (
	"context"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

func TestDeriveRejectsForeignAndIncompletePhysicalRoster(t *testing.T) {
	proof := oodevidence.VerifiedClosureV8{}
	foreign := []oodpublication.SpannerRow{{Table: "OODGraphObjects", Columns: map[string]interface{}{"organization_id": "other"}}}
	if _, _, err := derive(proof, foreign); err == nil {
		t.Fatal("foreign immutable row accepted")
	}
	incomplete := []oodpublication.SpannerRow{{Table: "OODGraphObjects", Columns: map[string]interface{}{"organization_id": ""}}}
	if _, _, err := derive(proof, incomplete); err == nil {
		t.Fatal("incomplete immutable graph roster accepted")
	}
}

func TestDeriveAllowsStandaloneAPISymbolWithoutAPIRelationship(t *testing.T) {
	const root = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	proof := oodevidence.VerifiedClosureV8{}
	rows := []oodpublication.SpannerRow{
		{Table: "OODGraphObjects", Columns: map[string]interface{}{"organization_id": "", "graph_object_id": "standalone", "object_class": "api_symbol", "api_element_role": "operation", "api_element_role_locator_manifest_hash": root}},
		{Table: "OODGraphSymbols", Columns: map[string]interface{}{"organization_id": ""}},
		{Table: "OODGraphEdges", Columns: map[string]interface{}{"organization_id": ""}},
		{Table: "OODGraphGraphFactEvidenceLocators", Columns: map[string]interface{}{"organization_id": ""}},
		{Table: "OODGraphManifestNodes", Columns: map[string]interface{}{"organization_id": ""}},
		{Table: "OODGraphManifestEntries", Columns: map[string]interface{}{"organization_id": ""}},
		{Table: "OODGraphClosureVerificationCertificates", Columns: map[string]interface{}{"organization_id": ""}},
	}
	objects, edges, err := derive(proof, rows)
	if err != nil {
		t.Fatalf("standalone API symbol rejected: %v", err)
	}
	if len(objects) != 1 || len(edges) != 0 {
		t.Fatalf("standalone API derivation = objects=%d edges=%d, want 1/0", len(objects), len(edges))
	}
}

func TestRoleManifestBindsObjectContentTriple(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	var object oodpublication.SpannerRow
	locators := map[string]oodpublication.SpannerRow{}
	for _, row := range f.Plan.ImmutableRows {
		switch row.Table {
		case "OODGraphObjects":
			if row.Columns["api_element_role"] == "operation" {
				object = row
			}
		case "OODGraphGraphFactEvidenceLocators":
			locators[row.Columns["graph_fact_locator_hash"].(string)] = row
		}
	}
	if object.Table == "" || len(locators) == 0 {
		t.Fatal("fixture lacks API object/locator")
	}
	root := object.Columns["api_element_role_locator_manifest_hash"].(string)
	members, err := oodpublication.ResolveGraphFactLocatorManifestMembers(f.Plan.ImmutableRows, f.Proof.OrganizationID(), root)
	if err != nil || len(members) == 0 {
		t.Fatalf("fixture role manifest members: %v", err)
	}
	locator, ok := locators[members[0]]
	if !ok {
		t.Fatal("fixture role manifest lacks physical locator")
	}
	// Make the unit subject the exact qualified source body retained by the
	// claim locator. The shared fixture is intentionally assembled by another
	// owner and may have a different API-object source in this narrow helper
	// test; full materialization tests exercise the canonical fixture chain.
	columns := make(map[string]interface{}, len(object.Columns))
	for key, value := range object.Columns {
		columns[key] = value
	}
	object.Columns = columns
	for _, field := range []string{"source_content_hash_algorithm", "source_content_hash_profile", "source_content_hash"} {
		object.Columns[field] = locator.Columns[field]
	}
	if !roleManifestBindsObjectContent(f.Plan.ImmutableRows, f.Proof.OrganizationID(), root, object, locators) {
		t.Fatal("exact fixture role root does not bind object content")
	}
	columns = make(map[string]interface{}, len(object.Columns))
	for key, value := range object.Columns {
		columns[key] = value
	}
	object.Columns = columns
	object.Columns["source_content_hash"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if roleManifestBindsObjectContent(f.Plan.ImmutableRows, f.Proof.OrganizationID(), root, object, locators) {
		t.Fatal("source-content substitution inherited role manifest authority")
	}
}

func TestDocumentsEvidenceRequiresExactExternalDocumentJoin(t *testing.T) {
	const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	source := oodpublication.SpannerRow{Columns: map[string]interface{}{
		"object_class": "external_reference_doc", "source_authority_id": "provider", "source_ref_kind": "url", "source_stable_reference": "https://provider.example/doc", "version_coordinate": "2026-11-02", "section_path": "/operation", "source_content_hash_algorithm": "sha256", "source_content_hash_profile": "canonical", "source_content_hash": hash,
	}}
	target := oodpublication.SpannerRow{Columns: map[string]interface{}{
		"object_class": "api_symbol", "source_authority_id": "provider", "source_ref_kind": "url", "source_stable_reference": "https://provider.example/api", "version_coordinate": "v1", "section_path": "/operation",
	}}
	edge := oodpublication.SpannerRow{Columns: map[string]interface{}{
		"edge_label": "documents", "edge_family": "external_reference", "authoring_source_path": "/operation", "source_authority_id": "provider", "source_stable_reference": "https://provider.example/doc", "source_content_hash_algorithm": "sha256", "source_content_hash_profile": "canonical", "source_content_hash": hash,
	}}
	evidence := oodpublication.SpannerRow{Columns: map[string]interface{}{
		"evidence_source_kind": "external_document_evidence", "edge_label": "documents", "authoring_source_path": "/operation", "source_object_class": "external_reference_doc", "source_authority_id": "provider", "source_ref_kind": "url", "source_stable_reference": "https://provider.example/doc", "source_version_coordinate": "2026-11-02", "source_section_path": "/operation", "target_object_class": "api_symbol", "target_authority_id": "provider", "target_ref_kind": "url", "target_stable_reference": "https://provider.example/api", "target_version_coordinate": "v1", "target_section_path": "/operation", "evidence_authority_id": "provider", "evidence_stable_reference": "https://provider.example/doc", "evidence_version_coordinate": "2026-11-02", "evidence_content_hash_algorithm": "sha256", "evidence_content_hash_profile": "canonical", "evidence_content_hash": hash,
	}}
	if !documentsEvidenceMatchesEdge(evidence, edge, source, target) {
		t.Fatal("exact external-document evidence join rejected")
	}
	for name, mutate := range map[string]func(*oodpublication.SpannerRow, *oodpublication.SpannerRow){
		"wrong evidence kind": func(e, _ *oodpublication.SpannerRow) { e.Columns["evidence_source_kind"] = "external_fetch" },
		"wrong endpoint":      func(e, _ *oodpublication.SpannerRow) { e.Columns["target_section_path"] = "/substituted" },
		"rehashed source": func(e, edge *oodpublication.SpannerRow) {
			edge.Columns["source_content_hash"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			e.Columns["evidence_content_hash"] = edge.Columns["source_content_hash"]
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := oodpublication.SpannerRow{Columns: cloneRowColumns(evidence.Columns)}
			x := oodpublication.SpannerRow{Columns: cloneRowColumns(edge.Columns)}
			mutate(&e, &x)
			if documentsEvidenceMatchesEdge(e, x, source, target) {
				t.Fatal("substituted external-document evidence join accepted")
			}
		})
	}
}

func cloneRowColumns(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
