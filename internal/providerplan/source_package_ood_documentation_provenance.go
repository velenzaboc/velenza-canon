package providerplan

// Physical materialization of the OOD10 documentation-provenance rule.  This
// is intentionally separate from API relationship materialization: a provider
// document documents an API symbol; it is never itself an api_relationship or
// evidence for a symbol's API role.

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

// DocumentationFactoryNativeDocumentationProvenance is the boot/admitted
// document fact binding for one native API-symbol claim. It contains only
// source-derived facts selected by the source-fact authority. Coordinates are
// deliberately excluded: object/address/edge identity belongs to the
// coordinate issuer. DocumentObjectClass is a closed OOD10 choice:
// external_reference_doc or reference_page. Relationship selections must
// leave this value zero.
type DocumentationFactoryNativeDocumentationProvenance struct {
	DocumentObjectClass, DocSectionPath, DocumentsAuthoringSourcePath string
}

func (d DocumentationFactoryNativeDocumentationProvenance) zero() bool {
	return d.DocumentObjectClass == "" && d.DocSectionPath == "" && d.DocumentsAuthoringSourcePath == ""
}

func (d DocumentationFactoryNativeDocumentationProvenance) validate() error {
	if d.DocumentObjectClass != "external_reference_doc" && d.DocumentObjectClass != "reference_page" {
		return fmt.Errorf("documentation object class is not closed")
	}
	if d.DocSectionPath == "" || d.DocumentsAuthoringSourcePath == "" {
		return fmt.Errorf("documentation binding is incomplete")
	}
	return nil
}

type documentationFactoryResolvedDocumentationBinding struct {
	DocumentationFactoryNativeDocumentationProvenance
	DocumentationFactoryNativeDocumentationIdentity
}

func (d documentationFactoryResolvedDocumentationBinding) validate() error {
	if err := d.DocumentationFactoryNativeDocumentationProvenance.validate(); err != nil {
		return err
	}
	if d.NativeSymbolID == "" || d.DocGraphObjectID == "" || d.DocGraphAddress == "" || d.DocumentsGraphEdgeID == "" {
		return fmt.Errorf("documentation coordinate identity is incomplete")
	}
	return nil
}

// DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows are
// auxiliary physical rows to append to the native graph result.  The caller
// owns closure assembly; this builder owns only the closed documents lane.
type DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows struct {
	Objects, Edges, RelationshipEvidence []oodpublication.SpannerRow
	Members                              []oodpublication.ManifestMemberV8
	LocatorManifestRows                  []oodpublication.SpannerRow
	LocatorManifestNodes                 []oodpublication.ManifestNodeV8
	LocatorManifestMembers               []oodpublication.ManifestMemberV8
}

// BuildDocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows
// emits the document object, documents edge, and external-document evidence
// required for every native API symbol.  A documentation claim has exactly
// one admitted primary locator: unlike role classification, its manifest does
// not silently widen to every locator attached to the symbol.
func BuildDocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows(ctx context.Context, p DocumentationFactorySourcePackageOODNativeProjection, in DocumentationFactorySourcePackageOODNativeGraphRowsContext, graph DocumentationFactorySourcePackageOODNativeGraphRows) (DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows, error) {
	if ctx == nil || in.OrganizationID == "" || in.CreatedAt.IsZero() || in.CreatedAt.Location() == nil || in.CreatedAt.Location().String() != "UTC" || in.CreatedAt.Nanosecond()%1000 != 0 {
		return DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows{}, fmt.Errorf("documentation provenance requires organization and boot-issued UTC microsecond time")
	}
	if len(p.Symbols) == 0 || len(graph.Objects) != len(p.Symbols) || !isLowerSHA256(p.APIGraphSHA256) || !isLowerSHA256(p.SourceMappingSHA256) {
		return DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows{}, fmt.Errorf("documentation provenance graph is incomplete")
	}
	locators, projectionLocators, err := documentationQualifiedLocators(p, in)
	if err != nil {
		return DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows{}, err
	}
	identities := map[string]DocumentationFactoryNativeSymbolIdentity{}
	for _, x := range in.Symbols {
		if x.NativeSymbolID == "" || x.GraphObjectID == "" || identities[x.NativeSymbolID].NativeSymbolID != "" {
			return DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows{}, fmt.Errorf("documentation provenance symbol identities are incomplete or duplicated")
		}
		identities[x.NativeSymbolID] = x
	}
	documentationIDs := map[string]DocumentationFactoryNativeDocumentationIdentity{}
	for _, x := range in.Documentation {
		if x.NativeSymbolID == "" || x.DocGraphObjectID == "" || x.DocGraphAddress == "" || x.DocumentsGraphEdgeID == "" || documentationIDs[x.NativeSymbolID].NativeSymbolID != "" {
			return DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows{}, fmt.Errorf("documentation provenance coordinate identities are incomplete or duplicated")
		}
		documentationIDs[x.NativeSymbolID] = x
	}
	if len(documentationIDs) != len(p.Symbols) {
		return DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows{}, fmt.Errorf("documentation provenance coordinate roster count does not equal sealed symbol roster")
	}
	objects := map[string]oodpublication.SpannerRow{}
	for _, row := range graph.Objects {
		if row.Table != "OODGraphObjects" || row.Columns["organization_id"] != in.OrganizationID || row.Columns["object_class"] != "api_symbol" {
			return DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows{}, fmt.Errorf("documentation provenance received a non-native API object")
		}
		id, _ := row.Columns["graph_object_id"].(string)
		if id == "" || objects[id].Table != "" {
			return DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows{}, fmt.Errorf("documentation provenance graph object roster is malformed")
		}
		objects[id] = row
	}

	out := DocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows{}
	documentRows := map[string]oodpublication.SpannerRow{}
	edgeRows := map[string]oodpublication.SpannerRow{}
	for _, s := range p.Symbols {
		identity, ok := identities[s.ID]
		if !ok || objects[identity.GraphObjectID].Table == "" {
			return out, fmt.Errorf("symbol %q has no matching API object identity", s.ID)
		}
		selection, ok := in.Provenance.selections[nativeProvenanceClaimKey{"symbol", s.ID}]
		if !ok {
			return out, fmt.Errorf("symbol %q has no admitted documentation provenance", s.ID)
		}
		binding := documentationFactoryResolvedDocumentationBinding{DocumentationFactoryNativeDocumentationProvenance: selection.Documentation, DocumentationFactoryNativeDocumentationIdentity: documentationIDs[s.ID]}
		if err := binding.validate(); err != nil {
			return out, fmt.Errorf("symbol %q: %w", s.ID, err)
		}
		primary, err := in.Provenance.primary(in.OrganizationID, p, "symbol", s.ID)
		if err != nil {
			return out, fmt.Errorf("symbol %q documentation primary: %w", s.ID, err)
		}
		if primary != selection.NativeLocatorID {
			return out, fmt.Errorf("symbol %q documentation primary disagrees with admitted selection", s.ID)
		}
		q, root, manifest, err := nativeClaimLocator([]string{primary}, primary, projectionLocators, locators, in.OrganizationID, in.CreatedAt)
		if err != nil {
			return out, fmt.Errorf("symbol %q documentation locator: %w", s.ID, err)
		}
		out.LocatorManifestRows = append(out.LocatorManifestRows, manifest.ImmutableRows...)
		out.LocatorManifestNodes = append(out.LocatorManifestNodes, manifest.Nodes...)
		out.LocatorManifestMembers = append(out.LocatorManifestMembers, manifest.Members...)

		doc, err := documentationObjectRow(in.OrganizationID, binding, q)
		if err != nil {
			return out, fmt.Errorf("symbol %q document: %w", s.ID, err)
		}
		if prior := documentRows[binding.DocGraphObjectID]; prior.Table != "" {
			if !documentationSameRow(prior, doc) {
				return out, fmt.Errorf("document object %q is reused with conflicting bytes", binding.DocGraphObjectID)
			}
		} else {
			documentRows[binding.DocGraphObjectID] = doc
			out.Objects = append(out.Objects, doc)
			out.Members = append(out.Members, nativeMember("object", "object", binding.DocGraphObjectID, doc))
		}
		target := objects[identity.GraphObjectID]
		evidence, err := documentationRelationshipEvidenceRow(in.OrganizationID, in.CreatedAt, binding, doc, target, q, root)
		if err != nil {
			return out, fmt.Errorf("symbol %q documents evidence: %w", s.ID, err)
		}
		edge, err := documentationEdgeRow(in.OrganizationID, binding, doc, target, q)
		if err != nil {
			return out, fmt.Errorf("symbol %q documents edge: %w", s.ID, err)
		}
		if prior := edgeRows[binding.DocumentsGraphEdgeID]; prior.Table != "" {
			if !documentationSameRow(prior, edge) {
				return out, fmt.Errorf("documents edge %q is reused with conflicting bytes", binding.DocumentsGraphEdgeID)
			}
		} else {
			edgeRows[binding.DocumentsGraphEdgeID] = edge
			out.Edges = append(out.Edges, edge)
			out.Members = append(out.Members, nativeMember("edge", "edge", binding.DocumentsGraphEdgeID, edge))
		}
		out.RelationshipEvidence = append(out.RelationshipEvidence, evidence)
		out.Members = append(out.Members, nativeMember("source", "relationship_evidence", evidence.Columns["relationship_evidence_hash"].(string), evidence))
	}
	for _, r := range p.Relationships {
		selection, ok := in.Provenance.selections[nativeProvenanceClaimKey{"relationship", r.ID}]
		if !ok || !selection.Documentation.zero() {
			return out, fmt.Errorf("relationship %q must not carry documentation object provenance", r.ID)
		}
	}
	sort.Slice(out.Members, func(i, j int) bool {
		return out.Members[i].ManifestKind+out.Members[i].MemberID < out.Members[j].ManifestKind+out.Members[j].MemberID
	})
	return out, nil
}

func documentationQualifiedLocators(p DocumentationFactorySourcePackageOODNativeProjection, in DocumentationFactorySourcePackageOODNativeGraphRowsContext) (map[string]nativeQualifiedLocator, map[string]DocumentationFactoryNativeEvidenceLocator, error) {
	q := map[string]nativeQualifiedLocator{}
	for _, x := range in.Locators {
		if x.NativeLocatorID == "" || q[x.NativeLocatorID].binding.NativeLocatorID != "" || !isLowerSHA256(x.SourceArtifactHash) {
			return nil, nil, fmt.Errorf("documentation provenance locator binding is incomplete or duplicated")
		}
		r, err := oodpublication.ReceiptV8FromPhysicalRow(x.Receipt)
		if err != nil {
			return nil, nil, fmt.Errorf("documentation locator %q receipt: %w", x.NativeLocatorID, err)
		}
		b, err := oodpublication.BatchV8FromPhysicalRow(x.Batch)
		if err != nil {
			return nil, nil, fmt.Errorf("documentation locator %q batch: %w", x.NativeLocatorID, err)
		}
		artifact, err := oodpublication.SourceArtifactExternalEvidenceDigest([]oodpublication.SpannerRow{x.Receipt, x.Batch})
		if err != nil || r.OrganizationID != in.OrganizationID || b.OrganizationID != in.OrganizationID || r.FetchBatchID != b.FetchBatchID || artifact != x.SourceArtifactHash {
			return nil, nil, fmt.Errorf("documentation locator %q source artifact or ownership mismatch", x.NativeLocatorID)
		}
		if _, err := oodpublication.BuildImmutableRow(x.LocatorRow.Table, x.LocatorRow.Columns); err != nil || x.LocatorRow.Table != "OODGraphGraphFactEvidenceLocators" || x.LocatorRow.Columns["graph_fact_locator_hash"] != x.Locator.LocatorHash {
			return nil, nil, fmt.Errorf("documentation locator %q physical locator mismatch", x.NativeLocatorID)
		}
		q[x.NativeLocatorID] = nativeQualifiedLocator{binding: x, receipt: r, batch: b, sourceArtifactHash: artifact}
	}
	pl := map[string]DocumentationFactoryNativeEvidenceLocator{}
	for _, x := range p.Locators {
		if x.ID == "" || q[x.ID].binding.NativeLocatorID == "" || pl[x.ID].ID != "" {
			return nil, nil, fmt.Errorf("documentation sealed locator roster is malformed")
		}
		pl[x.ID] = x
	}
	return q, pl, nil
}

func documentationObjectRow(org string, d documentationFactoryResolvedDocumentationBinding, q nativeQualifiedLocator) (oodpublication.SpannerRow, error) {
	sourceIndex, err := oodcanon.SourceStableReferenceIndexHashV1("object", org, q.receipt.SourceStableReference)
	if err != nil {
		return oodpublication.SpannerRow{}, err
	}
	addressIndex, err := oodcanon.GraphAddressIndexHashV1("object", org, d.DocGraphAddress)
	if err != nil {
		return oodpublication.SpannerRow{}, err
	}
	identityIndex, err := oodcanon.ObjectIdentityTupleIndexHashV1(org, d.DocumentObjectClass, q.receipt.SourceAuthorityID, q.receipt.SourceRefKind, q.receipt.SourceStableReference, q.receipt.VersionCoordinate, d.DocSectionPath)
	if err != nil {
		return oodpublication.SpannerRow{}, err
	}
	row := oodpublication.SpannerRow{Table: "OODGraphObjects", KeyColumns: []string{"organization_id", "graph_object_id"}, Columns: map[string]interface{}{
		"organization_id": org, "graph_object_id": d.DocGraphObjectID, "object_class": d.DocumentObjectClass, "api_element_role": nil, "api_element_role_locator_manifest_hash": nil, "source_authority_id": q.receipt.SourceAuthorityID, "source_artifact_class": "external_document_evidence", "source_ref_kind": q.receipt.SourceRefKind, "source_stable_reference": q.receipt.SourceStableReference, "version_coordinate": q.receipt.VersionCoordinate, "section_path": d.DocSectionPath, "graph_address": d.DocGraphAddress, "source_content_hash_algorithm": q.receipt.SourceContentHashAlgorithm, "source_content_hash_profile": q.receipt.SourceContentHashProfile, "source_content_hash": q.receipt.SourceContentHash, "source_stable_reference_index_hash": sourceIndex, "graph_address_index_hash": addressIndex, "identity_tuple_index_hash": identityIndex, "graph_row_hash": zeroDigest(),
	}}
	if err := verifyNativeObjectIndexes(row); err != nil {
		return row, err
	}
	return nativeHashedRow(row, "graph_row_hash")
}

func documentationRelationshipEvidenceRow(org string, createdAt time.Time, d documentationFactoryResolvedDocumentationBinding, doc, target oodpublication.SpannerRow, q nativeQualifiedLocator, root string) (oodpublication.SpannerRow, error) {
	dv, tv := doc.Columns, target.Columns
	index, err := oodcanon.SourceStableReferenceIndexHashV1("relationship_evidence", org, dv["source_stable_reference"].(string))
	if err != nil {
		return oodpublication.SpannerRow{}, err
	}
	row := oodpublication.SpannerRow{Table: "OODGraphRelationshipEvidence", KeyColumns: []string{"organization_id", "relationship_evidence_hash"}, Columns: map[string]interface{}{
		"organization_id": org, "relationship_evidence_hash": zeroDigest(), "evidence_source_kind": "external_document_evidence", "patch_action": "add", "source_object_class": d.DocumentObjectClass, "source_authority_id": dv["source_authority_id"], "source_ref_kind": dv["source_ref_kind"], "source_stable_reference": dv["source_stable_reference"], "source_version_coordinate": dv["version_coordinate"], "source_section_path": dv["section_path"], "target_object_class": "api_symbol", "target_authority_id": tv["source_authority_id"], "target_ref_kind": tv["source_ref_kind"], "target_stable_reference": tv["source_stable_reference"], "target_version_coordinate": tv["version_coordinate"], "target_section_path": tv["section_path"], "edge_label": "documents", "authoring_source_path": d.DocumentsAuthoringSourcePath, "evidence_authority_id": q.receipt.SourceAuthorityID, "evidence_stable_reference": q.receipt.SourceStableReference, "evidence_version_coordinate": q.receipt.VersionCoordinate, "evidence_content_hash_algorithm": q.receipt.SourceContentHashAlgorithm, "evidence_content_hash_profile": q.receipt.SourceContentHashProfile, "evidence_content_hash": q.receipt.SourceContentHash, "evidence_identity_hash": q.receipt.EvidenceIdentityHash, "eligible_receipt_id": q.receipt.ReceiptID, "eligible_receipt_digest": q.receipt.RedactedTransportEvidenceDigest, "sealed_completeness_certificate_hash": q.batch.CompletenessEvidenceDigest, "evidence_archive_authority_id": q.receipt.EvidenceArchiveAuthorityID, "evidence_archive_record_id": q.receipt.EvidenceArchiveRecordID, "evidence_archive_record_digest": q.receipt.EvidenceArchiveRecordDigest, "graph_fact_locator_manifest_hash": root, "extractor_profile_id": nil, "extractor_profile_version": nil, "extractor_profile_digest": nil, "evidence_authority_class": nil, "parent_graph_snapshot_id": nil, "source_stable_reference_index_hash": index, "created_at": createdAt,
	}}
	return nativeHashedRow(row, "relationship_evidence_hash")
}

func documentationEdgeRow(org string, d documentationFactoryResolvedDocumentationBinding, doc, target oodpublication.SpannerRow, q nativeQualifiedLocator) (oodpublication.SpannerRow, error) {
	dv, tv := doc.Columns, target.Columns
	index, err := oodcanon.EdgeIdentityTupleIndexHashV1(org, "graph_object", d.DocGraphObjectID, "graph_object", tv["graph_object_id"].(string), "documents", dv["version_coordinate"].(string), tv["version_coordinate"].(string), d.DocumentsAuthoringSourcePath, q.receipt.SourceAuthorityID, q.receipt.SourceStableReference)
	if err != nil {
		return oodpublication.SpannerRow{}, err
	}
	row := oodpublication.SpannerRow{Table: "OODGraphEdges", KeyColumns: []string{"organization_id", "graph_edge_id"}, Columns: map[string]interface{}{
		"organization_id": org, "graph_edge_id": d.DocumentsGraphEdgeID, "source_endpoint_kind": "graph_object", "source_endpoint_id": d.DocGraphObjectID, "source_endpoint_class": d.DocumentObjectClass, "target_endpoint_kind": "graph_object", "target_endpoint_id": tv["graph_object_id"], "target_endpoint_class": "api_symbol", "edge_label": "documents", "edge_family": "external_reference", "source_version_coordinate": dv["version_coordinate"], "target_version_coordinate": tv["version_coordinate"], "authoring_source_path": d.DocumentsAuthoringSourcePath, "source_authority_id": q.receipt.SourceAuthorityID, "source_stable_reference": q.receipt.SourceStableReference, "source_content_hash_algorithm": q.receipt.SourceContentHashAlgorithm, "source_content_hash_profile": q.receipt.SourceContentHashProfile, "source_content_hash": q.receipt.SourceContentHash, "valid_from": nil, "valid_until": nil, "diagnostic_only": false, "identity_tuple_index_hash": index, "graph_row_hash": zeroDigest(),
	}}
	return nativeHashedRow(row, "graph_row_hash")
}

func documentationSameRow(a, b oodpublication.SpannerRow) bool {
	da, ea := oodpublication.CanonicalMemberDigestFromPhysicalRow(a)
	db, eb := oodpublication.CanonicalMemberDigestFromPhysicalRow(b)
	return ea == nil && eb == nil && da == db
}
