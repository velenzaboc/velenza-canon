package providerplan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

func TestDocumentationProvenanceRowsAreExternalReferenceNotAPIRoleProof(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	var batchRow oodpublication.SpannerRow
	for _, row := range f.ImmutableRows {
		if row.Table == "OODGraphExternalFetchBatches" {
			batchRow = row
			break
		}
	}
	batch, err := oodpublication.BatchV8FromPhysicalRow(batchRow)
	if err != nil {
		t.Fatal(err)
	}
	q := nativeQualifiedLocator{receipt: f.Receipt, batch: batch}
	d := documentationFactoryResolvedDocumentationBinding{DocumentationFactoryNativeDocumentationProvenance: DocumentationFactoryNativeDocumentationProvenance{
		DocumentObjectClass: "external_reference_doc", DocSectionPath: "/reference", DocumentsAuthoringSourcePath: "native.symbol.source.documents",
	}, DocumentationFactoryNativeDocumentationIdentity: DocumentationFactoryNativeDocumentationIdentity{
		NativeSymbolID: "source", DocGraphObjectID: uuid.NewString(), DocGraphAddress: "docs://provider/reference", DocumentsGraphEdgeID: uuid.NewString(),
	}}
	if err := d.validate(); err != nil {
		t.Fatal(err)
	}
	doc, err := documentationObjectRow(f.Receipt.OrganizationID, d, q)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Columns["api_element_role"] != nil || doc.Columns["api_element_role_locator_manifest_hash"] != nil {
		t.Fatal("document acquired API role proof")
	}
	target := doc
	target.Columns = map[string]interface{}{}
	for k, v := range doc.Columns {
		target.Columns[k] = v
	}
	target.Columns["graph_object_id"], target.Columns["object_class"], target.Columns["api_element_role"], target.Columns["api_element_role_locator_manifest_hash"] = uuid.NewString(), "api_symbol", "operation", sha256Hex([]byte("role-root"))
	target, err = nativeHashedRow(target, "graph_row_hash")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := documentationRelationshipEvidenceRow(f.Receipt.OrganizationID, time.Date(2026, 11, 2, 13, 0, 0, 0, time.UTC), d, doc, target, q, sha256Hex([]byte("single-primary-locator")))
	if err != nil {
		t.Fatal(err)
	}
	edge, err := documentationEdgeRow(f.Receipt.OrganizationID, d, doc, target, q)
	if err != nil {
		t.Fatal(err)
	}
	if edge.Columns["edge_family"] != "external_reference" || edge.Columns["edge_label"] != "documents" || evidence.Columns["edge_label"] != "documents" {
		t.Fatalf("documents provenance mislabeled: %#v %#v", edge.Columns["edge_family"], evidence.Columns["edge_label"])
	}
	for _, row := range []oodpublication.SpannerRow{doc, target, edge, evidence} {
		if _, err := oodpublication.BuildImmutableRow(row.Table, row.Columns); err != nil {
			t.Fatalf("strict %s row: %v", row.Table, err)
		}
	}
}

func TestDocumentationBindingIsClosedAndComplete(t *testing.T) {
	if err := (DocumentationFactoryNativeDocumentationProvenance{}).validate(); err == nil {
		t.Fatal("accepted empty document binding")
	}
	d := DocumentationFactoryNativeDocumentationProvenance{DocumentObjectClass: "api_symbol", DocSectionPath: "/", DocumentsAuthoringSourcePath: "p"}
	if err := d.validate(); err == nil {
		t.Fatal("accepted API object class as document")
	}
}

func TestDocumentationCoordinateRosterIsExactAndSeparateFromFacts(t *testing.T) {
	p := DocumentationFactorySourcePackageOODNativeProjection{Symbols: []DocumentationFactoryNativeAPISymbol{{ID: "one"}, {ID: "two"}}}
	base := DocumentationFactoryOODSuccessorCoordinates{
		Symbols:       []DocumentationFactoryNativeSymbolIdentity{{NativeSymbolID: "one"}, {NativeSymbolID: "two"}},
		Documentation: []DocumentationFactoryNativeDocumentationIdentity{{NativeSymbolID: "one", DocGraphObjectID: uuid.NewString(), DocGraphAddress: "docs://one", DocumentsGraphEdgeID: uuid.NewString()}, {NativeSymbolID: "two", DocGraphObjectID: uuid.NewString(), DocGraphAddress: "docs://two", DocumentsGraphEdgeID: uuid.NewString()}},
	}
	if err := verifySuccessorCoordinateRoster(p, base); err != nil {
		t.Fatalf("exact documentation roster rejected: %v", err)
	}
	base.Documentation[1].NativeSymbolID = "substituted"
	if err := verifySuccessorCoordinateRoster(p, base); err == nil {
		t.Fatal("accepted substituted documentation coordinate")
	}
}

func TestDocumentationProvenanceBuilderRejectsForeignRosterAndConflictingReuse(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	p, bindings := provenanceTestInput(t, f)
	p.Symbols[0].Role, p.Symbols[0].DisplayName = "operation", "source"
	p.Symbols[1].Role, p.Symbols[1].DisplayName = "resource", "target"
	p.Relationships[0].SourceID, p.Relationships[0].TargetID, p.Relationships[0].Label = "source", "target", "operation_reads_resource"
	provenance := provenanceTestVerified(t, f.Receipt.OrganizationID, p, bindings)
	ctx := DocumentationFactorySourcePackageOODNativeGraphRowsContext{
		OrganizationID: f.Receipt.OrganizationID, CreatedAt: time.Date(2026, 11, 2, 13, 0, 0, 0, time.UTC), Locators: bindings, Provenance: provenance,
		Symbols:       []DocumentationFactoryNativeSymbolIdentity{{NativeSymbolID: "source", GraphObjectID: uuid.NewString(), SymbolID: uuid.NewString(), SectionPath: "/api/source", GraphAddress: "api://source"}, {NativeSymbolID: "target", GraphObjectID: uuid.NewString(), SymbolID: uuid.NewString(), SectionPath: "/api/target", GraphAddress: "api://target"}},
		Relationships: []DocumentationFactoryNativeRelationshipIdentity{{NativeRelationshipID: "relationship", GraphEdgeID: uuid.NewString()}},
		Documentation: []DocumentationFactoryNativeDocumentationIdentity{{NativeSymbolID: "source", DocGraphObjectID: uuid.NewString(), DocGraphAddress: "docs://source", DocumentsGraphEdgeID: uuid.NewString()}, {NativeSymbolID: "target", DocGraphObjectID: uuid.NewString(), DocGraphAddress: "docs://target", DocumentsGraphEdgeID: uuid.NewString()}},
	}
	graph, err := BuildDocumentationFactorySourcePackageOODNativeGraphRows(context.Background(), p, ctx)
	if err != nil {
		t.Fatal(err)
	}
	positive, err := BuildDocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows(context.Background(), p, ctx, graph)
	if err != nil {
		t.Fatal(err)
	}
	if len(positive.Objects) != 2 || len(positive.Edges) != 2 || len(positive.RelationshipEvidence) != 2 {
		t.Fatalf("documents physical rows = %+v", positive)
	}
	missing := ctx
	missing.Documentation = append([]DocumentationFactoryNativeDocumentationIdentity(nil), ctx.Documentation[:1]...)
	if _, err := BuildDocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows(context.Background(), p, missing, graph); err == nil || !strings.Contains(err.Error(), "roster count") {
		t.Fatalf("missing documentation roster error=%v", err)
	}
	foreign := ctx
	foreign.Documentation = append(append([]DocumentationFactoryNativeDocumentationIdentity(nil), ctx.Documentation...), DocumentationFactoryNativeDocumentationIdentity{NativeSymbolID: "foreign", DocGraphObjectID: uuid.NewString(), DocGraphAddress: "docs://foreign", DocumentsGraphEdgeID: uuid.NewString()})
	if _, err := BuildDocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows(context.Background(), p, foreign, graph); err == nil || !strings.Contains(err.Error(), "roster count") {
		t.Fatalf("foreign documentation roster error=%v", err)
	}
	conflict := ctx
	conflict.Documentation = append([]DocumentationFactoryNativeDocumentationIdentity(nil), ctx.Documentation...)
	conflict.Documentation[1].DocGraphObjectID = conflict.Documentation[0].DocGraphObjectID
	if _, err := BuildDocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows(context.Background(), p, conflict, graph); err == nil || !strings.Contains(err.Error(), "conflicting bytes") {
		t.Fatalf("conflicting document reuse error=%v", err)
	}
}
