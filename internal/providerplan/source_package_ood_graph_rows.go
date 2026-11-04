package providerplan

// Concrete physical-row construction for the sealed native API projection.
// This deliberately accepts only boot-issued identities and qualified physical
// receipt/batch rows: it is not a generic graph-row mapper.

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

type DocumentationFactorySourcePackageOODNativeGraphRowsContext struct {
	OrganizationID string
	CreatedAt      time.Time // boot-issued, UTC microsecond time
	Locators       []DocumentationFactorySourcePackageOODLocatorBinding
	Symbols        []DocumentationFactoryNativeSymbolIdentity
	Documentation  []DocumentationFactoryNativeDocumentationIdentity
	Relationships  []DocumentationFactoryNativeRelationshipIdentity
	Provenance     DocumentationFactoryVerifiedNativeProvenance
}

// Identities and addresses are selected by the non-fact coordinate allocator.
// Primary provenance is verified separately by the admitted source-fact owner.
// Secondary indexes are derived locally with the owner's canonical profiles.
type DocumentationFactoryNativeSymbolIdentity struct {
	NativeSymbolID, GraphObjectID, SymbolID string
	SectionPath, GraphAddress               string
}
type DocumentationFactoryNativeRelationshipIdentity struct {
	NativeRelationshipID, GraphEdgeID string
}

type DocumentationFactorySourcePackageOODNativeGraphRows struct {
	Objects, Symbols, Edges, RelationshipEvidence []oodpublication.SpannerRow
	Members                                       []oodpublication.ManifestMemberV8
	Relationships                                 []oodevidence.RelationshipV8
	LocatorManifestRows                           []oodpublication.SpannerRow
	LocatorManifestNodes                          []oodpublication.ManifestNodeV8
	LocatorManifestMembers                        []oodpublication.ManifestMemberV8
}

func BuildDocumentationFactorySourcePackageOODNativeGraphRows(ctx context.Context, p DocumentationFactorySourcePackageOODNativeProjection, in DocumentationFactorySourcePackageOODNativeGraphRowsContext) (DocumentationFactorySourcePackageOODNativeGraphRows, error) {
	if ctx == nil || in.OrganizationID == "" || in.CreatedAt.IsZero() || in.CreatedAt.Location() != time.UTC || in.CreatedAt.Nanosecond()%1000 != 0 {
		return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("native graph rows require organization and boot-issued UTC microsecond time")
	}
	if !isLowerSHA256(p.SourceMappingSHA256) || len(p.Symbols) == 0 || len(p.Relationships) == 0 {
		return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("native graph projection is incomplete")
	}
	locators := make(map[string]nativeQualifiedLocator, len(in.Locators))
	for _, x := range in.Locators {
		if _, exists := locators[x.NativeLocatorID]; exists || x.NativeLocatorID == "" || !isLowerSHA256(x.SourceArtifactHash) {
			return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("native locator binding is incomplete or duplicated")
		}
		r, err := oodpublication.ReceiptV8FromPhysicalRow(x.Receipt)
		if err != nil {
			return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("locator %q receipt: %w", x.NativeLocatorID, err)
		}
		b, err := oodpublication.BatchV8FromPhysicalRow(x.Batch)
		if err != nil {
			return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("locator %q batch: %w", x.NativeLocatorID, err)
		}
		if r.OrganizationID != in.OrganizationID || b.OrganizationID != in.OrganizationID || r.FetchBatchID != b.FetchBatchID {
			return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("locator %q receipt/batch organization or batch mismatch", x.NativeLocatorID)
		}
		artifact, err := oodpublication.SourceArtifactExternalEvidenceDigest([]oodpublication.SpannerRow{x.Receipt, x.Batch})
		if err != nil {
			return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("locator %q source artifact: %w", x.NativeLocatorID, err)
		}
		if artifact != x.SourceArtifactHash || x.LocatorRow.Table != "OODGraphGraphFactEvidenceLocators" {
			return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("locator %q source artifact/row mismatch", x.NativeLocatorID)
		}
		if _, err := oodpublication.BuildImmutableRow(x.LocatorRow.Table, x.LocatorRow.Columns); err != nil || x.LocatorRow.Columns["graph_fact_locator_hash"] != x.Locator.LocatorHash {
			return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("locator %q strict locator row mismatch", x.NativeLocatorID)
		}
		locators[x.NativeLocatorID] = nativeQualifiedLocator{binding: x, receipt: r, batch: b, sourceArtifactHash: artifact}
	}
	projectionLocators := map[string]DocumentationFactoryNativeEvidenceLocator{}
	for _, x := range p.Locators {
		if _, ok := locators[x.ID]; !ok {
			return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("sealed locator %q has no qualified binding", x.ID)
		}
		projectionLocators[x.ID] = x
	}
	symbolIDs := map[string]DocumentationFactoryNativeSymbolIdentity{}
	for _, x := range in.Symbols {
		if _, ok := symbolIDs[x.NativeSymbolID]; ok || x.NativeSymbolID == "" || x.GraphObjectID == "" || x.SymbolID == "" || x.SectionPath == "" || x.GraphAddress == "" {
			return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("native symbol identity is incomplete or duplicated")
		}
		symbolIDs[x.NativeSymbolID] = x
	}
	relIDs := map[string]DocumentationFactoryNativeRelationshipIdentity{}
	for _, x := range in.Relationships {
		if _, ok := relIDs[x.NativeRelationshipID]; ok || x.NativeRelationshipID == "" || x.GraphEdgeID == "" {
			return DocumentationFactorySourcePackageOODNativeGraphRows{}, fmt.Errorf("native relationship identity is incomplete or duplicated")
		}
		relIDs[x.NativeRelationshipID] = x
	}

	out := DocumentationFactorySourcePackageOODNativeGraphRows{}
	objects := map[string]oodpublication.SpannerRow{}
	for _, s := range p.Symbols {
		id, ok := symbolIDs[s.ID]
		if !ok {
			return out, fmt.Errorf("symbol %q has no boot identity", s.ID)
		}
		primary, err := in.Provenance.primary(in.OrganizationID, p, "symbol", s.ID)
		if err != nil {
			return out, err
		}
		q, root, manifest, err := nativeClaimLocator(s.LocatorIDs, primary, projectionLocators, locators, in.OrganizationID, in.CreatedAt)
		if err != nil {
			return out, fmt.Errorf("symbol %q: %w", s.ID, err)
		}
		out.LocatorManifestRows = append(out.LocatorManifestRows, manifest.ImmutableRows...)
		out.LocatorManifestNodes = append(out.LocatorManifestNodes, manifest.Nodes...)
		out.LocatorManifestMembers = append(out.LocatorManifestMembers, manifest.Members...)
		if q.receipt.SourceStableReference == "" {
			return out, fmt.Errorf("symbol %q empty qualified reference", s.ID)
		}
		sourceIndex, e := oodcanon.SourceStableReferenceIndexHashV1("object", in.OrganizationID, q.receipt.SourceStableReference)
		if e != nil {
			return out, e
		}
		objectAddress, e := oodcanon.GraphAddressIndexHashV1("object", in.OrganizationID, id.GraphAddress)
		if e != nil {
			return out, e
		}
		objectIdentity, e := oodcanon.ObjectIdentityTupleIndexHashV1(in.OrganizationID, "api_symbol", q.receipt.SourceAuthorityID, q.receipt.SourceRefKind, q.receipt.SourceStableReference, q.receipt.VersionCoordinate, id.SectionPath)
		if e != nil {
			return out, e
		}
		obj := oodpublication.SpannerRow{Table: "OODGraphObjects", KeyColumns: []string{"organization_id", "graph_object_id"}, Columns: map[string]interface{}{
			"organization_id": in.OrganizationID, "graph_object_id": id.GraphObjectID, "object_class": "api_symbol", "api_element_role": s.Role, "api_element_role_locator_manifest_hash": root, "source_authority_id": q.receipt.SourceAuthorityID, "source_artifact_class": "external_document_evidence", "source_ref_kind": q.receipt.SourceRefKind, "source_stable_reference": q.receipt.SourceStableReference, "version_coordinate": q.receipt.VersionCoordinate, "section_path": id.SectionPath, "graph_address": id.GraphAddress, "source_content_hash_algorithm": q.receipt.SourceContentHashAlgorithm, "source_content_hash_profile": q.receipt.SourceContentHashProfile, "source_content_hash": q.receipt.SourceContentHash, "source_stable_reference_index_hash": sourceIndex, "graph_address_index_hash": objectAddress, "identity_tuple_index_hash": objectIdentity, "graph_row_hash": zeroDigest(),
		}}
		if err := verifyNativeObjectIndexes(obj); err != nil {
			return out, err
		}
		obj, err = nativeHashedRow(obj, "graph_row_hash")
		if err != nil {
			return out, err
		}
		sym := oodpublication.SpannerRow{Table: "OODGraphSymbols", KeyColumns: []string{"organization_id", "symbol_id"}, Columns: map[string]interface{}{
			"organization_id": in.OrganizationID, "symbol_id": id.SymbolID, "graph_object_id": id.GraphObjectID, "object_class": "api_symbol", "symbol_kind": s.Role, "symbol_name": s.DisplayName, "source_authority_id": q.receipt.SourceAuthorityID, "source_stable_reference": q.receipt.SourceStableReference, "version_coordinate": q.receipt.VersionCoordinate, "section_path": id.SectionPath, "graph_address": id.GraphAddress, "graph_address_index_hash": objectAddress, "identity_tuple_index_hash": objectIdentity, "graph_row_hash": zeroDigest(),
		}}
		sym.Columns["graph_address_index_hash"], _ = oodcanon.GraphAddressIndexHashV1("symbol", in.OrganizationID, id.GraphAddress)
		sym.Columns["identity_tuple_index_hash"], _ = oodcanon.SymbolIdentityTupleIndexHashV1(in.OrganizationID, "api_symbol", q.receipt.SourceAuthorityID, q.receipt.SourceStableReference, q.receipt.VersionCoordinate, id.SectionPath, s.Role, s.DisplayName)
		if err := verifyNativeSymbolIndexes(sym); err != nil {
			return out, err
		}
		sym, err = nativeHashedRow(sym, "graph_row_hash")
		if err != nil {
			return out, err
		}
		objects[s.ID] = obj
		out.Objects = append(out.Objects, obj)
		out.Symbols = append(out.Symbols, sym)
		out.Members = append(out.Members, nativeMember("object", "object", id.GraphObjectID, obj), nativeMember("symbol", "symbol", id.SymbolID, sym))
	}
	for _, r := range p.Relationships {
		identity, ok := relIDs[r.ID]
		if !ok {
			return out, fmt.Errorf("relationship %q has no boot identity", r.ID)
		}
		source, ok := symbolIDs[r.SourceID]
		if !ok {
			return out, fmt.Errorf("relationship %q source has no identity", r.ID)
		}
		target, ok := symbolIDs[r.TargetID]
		if !ok {
			return out, fmt.Errorf("relationship %q target has no identity", r.ID)
		}
		primary, err := in.Provenance.primary(in.OrganizationID, p, "relationship", r.ID)
		if err != nil {
			return out, err
		}
		q, root, manifest, err := nativeClaimLocator(r.LocatorIDs, primary, projectionLocators, locators, in.OrganizationID, in.CreatedAt)
		if err != nil {
			return out, fmt.Errorf("relationship %q: %w", r.ID, err)
		}
		out.LocatorManifestRows = append(out.LocatorManifestRows, manifest.ImmutableRows...)
		out.LocatorManifestNodes = append(out.LocatorManifestNodes, manifest.Nodes...)
		out.LocatorManifestMembers = append(out.LocatorManifestMembers, manifest.Members...)
		sourcePrimary, err := in.Provenance.primary(in.OrganizationID, p, "symbol", r.SourceID)
		if err != nil {
			return out, err
		}
		targetPrimary, err := in.Provenance.primary(in.OrganizationID, p, "symbol", r.TargetID)
		if err != nil {
			return out, err
		}
		sq, _, _, err := nativeClaimLocator(p.Symbols[nativeSymbolOffset(p.Symbols, r.SourceID)].LocatorIDs, sourcePrimary, projectionLocators, locators, in.OrganizationID, in.CreatedAt)
		if err != nil {
			return out, err
		}
		tq, _, _, err := nativeClaimLocator(p.Symbols[nativeSymbolOffset(p.Symbols, r.TargetID)].LocatorIDs, targetPrimary, projectionLocators, locators, in.OrganizationID, in.CreatedAt)
		if err != nil {
			return out, err
		}
		evidence := oodpublication.SpannerRow{Table: "OODGraphRelationshipEvidence", KeyColumns: []string{"organization_id", "relationship_evidence_hash"}, Columns: map[string]interface{}{
			"organization_id": in.OrganizationID, "relationship_evidence_hash": zeroDigest(), "evidence_source_kind": "external_document_evidence", "patch_action": "add", "source_object_class": "api_symbol", "source_authority_id": sq.receipt.SourceAuthorityID, "source_ref_kind": sq.receipt.SourceRefKind, "source_stable_reference": sq.receipt.SourceStableReference, "source_version_coordinate": sq.receipt.VersionCoordinate, "source_section_path": source.SectionPath, "target_object_class": "api_symbol", "target_authority_id": tq.receipt.SourceAuthorityID, "target_ref_kind": tq.receipt.SourceRefKind, "target_stable_reference": tq.receipt.SourceStableReference, "target_version_coordinate": tq.receipt.VersionCoordinate, "target_section_path": target.SectionPath, "edge_label": r.Label, "authoring_source_path": r.ID, "evidence_authority_id": q.receipt.SourceAuthorityID, "evidence_stable_reference": q.receipt.SourceStableReference, "evidence_version_coordinate": q.receipt.VersionCoordinate, "evidence_content_hash_algorithm": q.receipt.SourceContentHashAlgorithm, "evidence_content_hash_profile": q.receipt.SourceContentHashProfile, "evidence_content_hash": q.receipt.SourceContentHash, "evidence_identity_hash": q.receipt.EvidenceIdentityHash, "eligible_receipt_id": q.receipt.ReceiptID, "eligible_receipt_digest": q.receipt.RedactedTransportEvidenceDigest, "sealed_completeness_certificate_hash": q.batch.CompletenessEvidenceDigest, "evidence_archive_authority_id": q.receipt.EvidenceArchiveAuthorityID, "evidence_archive_record_id": q.receipt.EvidenceArchiveRecordID, "evidence_archive_record_digest": q.receipt.EvidenceArchiveRecordDigest, "graph_fact_locator_manifest_hash": root, "extractor_profile_id": nil, "extractor_profile_version": nil, "extractor_profile_digest": nil, "evidence_authority_class": nil, "parent_graph_snapshot_id": nil, "source_stable_reference_index_hash": zeroDigest(), "created_at": in.CreatedAt,
		}}
		evidence.Columns["source_stable_reference_index_hash"], _ = oodcanon.SourceStableReferenceIndexHashV1("relationship_evidence", in.OrganizationID, sq.receipt.SourceStableReference)
		if want, e := oodcanon.SourceStableReferenceIndexHashV1("relationship_evidence", in.OrganizationID, sq.receipt.SourceStableReference); e != nil || want != evidence.Columns["source_stable_reference_index_hash"] {
			return out, fmt.Errorf("relationship %q source reference index hash mismatch", r.ID)
		}
		evidence, err = nativeHashedRow(evidence, "relationship_evidence_hash")
		if err != nil {
			return out, err
		}
		edge := oodpublication.SpannerRow{Table: "OODGraphEdges", KeyColumns: []string{"organization_id", "graph_edge_id"}, Columns: map[string]interface{}{
			"organization_id": in.OrganizationID, "graph_edge_id": identity.GraphEdgeID, "source_endpoint_kind": "graph_object", "source_endpoint_id": source.GraphObjectID, "source_endpoint_class": "api_symbol", "target_endpoint_kind": "graph_object", "target_endpoint_id": target.GraphObjectID, "target_endpoint_class": "api_symbol", "edge_label": r.Label, "edge_family": "api_relationship", "source_version_coordinate": sq.receipt.VersionCoordinate, "target_version_coordinate": tq.receipt.VersionCoordinate, "authoring_source_path": r.ID, "source_authority_id": q.receipt.SourceAuthorityID, "source_stable_reference": q.receipt.SourceStableReference, "source_content_hash_algorithm": q.receipt.SourceContentHashAlgorithm, "source_content_hash_profile": q.receipt.SourceContentHashProfile, "source_content_hash": q.receipt.SourceContentHash, "valid_from": nil, "valid_until": nil, "diagnostic_only": false, "identity_tuple_index_hash": zeroDigest(), "graph_row_hash": zeroDigest(),
		}}
		edge.Columns["identity_tuple_index_hash"], _ = oodcanon.EdgeIdentityTupleIndexHashV1(in.OrganizationID, "graph_object", source.GraphObjectID, "graph_object", target.GraphObjectID, r.Label, sq.receipt.VersionCoordinate, tq.receipt.VersionCoordinate, r.ID, q.receipt.SourceAuthorityID, q.receipt.SourceStableReference)
		if want, e := oodcanon.EdgeIdentityTupleIndexHashV1(in.OrganizationID, "graph_object", source.GraphObjectID, "graph_object", target.GraphObjectID, r.Label, sq.receipt.VersionCoordinate, tq.receipt.VersionCoordinate, r.ID, q.receipt.SourceAuthorityID, q.receipt.SourceStableReference); e != nil || want != edge.Columns["identity_tuple_index_hash"] {
			return out, fmt.Errorf("relationship %q edge identity index hash mismatch", r.ID)
		}
		edge, err = nativeHashedRow(edge, "graph_row_hash")
		if err != nil {
			return out, err
		}
		out.RelationshipEvidence = append(out.RelationshipEvidence, evidence)
		out.Edges = append(out.Edges, edge)
		out.Members = append(out.Members, nativeMember("source", "relationship_evidence", evidence.Columns["relationship_evidence_hash"].(string), evidence), nativeMember("edge", "edge", identity.GraphEdgeID, edge))
		out.Relationships = append(out.Relationships, oodevidence.RelationshipV8{OrganizationID: in.OrganizationID, RelationshipEvidenceHash: evidence.Columns["relationship_evidence_hash"].(string), EvidenceSourceKind: "external_document_evidence", PatchAction: "add", SourceObjectClass: "api_symbol", SourceAuthorityID: sq.receipt.SourceAuthorityID, SourceRefKind: sq.receipt.SourceRefKind, SourceStableReference: sq.receipt.SourceStableReference, SourceVersionCoordinate: sq.receipt.VersionCoordinate, SourceSectionPath: source.SectionPath, TargetObjectClass: "api_symbol", TargetAuthorityID: tq.receipt.SourceAuthorityID, TargetRefKind: tq.receipt.SourceRefKind, TargetStableReference: tq.receipt.SourceStableReference, TargetVersionCoordinate: tq.receipt.VersionCoordinate, TargetSectionPath: target.SectionPath, EdgeLabel: r.Label, AuthoringSourcePath: r.ID, EvidenceAuthorityID: q.receipt.SourceAuthorityID, EvidenceStableReference: q.receipt.SourceStableReference, EvidenceVersionCoordinate: q.receipt.VersionCoordinate, EvidenceContentHashAlgorithm: q.receipt.SourceContentHashAlgorithm, EvidenceContentHashProfile: q.receipt.SourceContentHashProfile, EvidenceContentHash: q.receipt.SourceContentHash, EvidenceIdentityHash: stringPointer(q.receipt.EvidenceIdentityHash), EligibleReceiptID: stringPointer(q.receipt.ReceiptID), EligibleReceiptDigest: stringPointer(q.receipt.RedactedTransportEvidenceDigest), SealedCompletenessCertificateHash: stringPointer(q.batch.CompletenessEvidenceDigest), EvidenceArchiveAuthorityID: stringPointer(q.receipt.EvidenceArchiveAuthorityID), EvidenceArchiveRecordID: stringPointer(q.receipt.EvidenceArchiveRecordID), EvidenceArchiveRecordDigest: stringPointer(q.receipt.EvidenceArchiveRecordDigest), GraphFactLocatorManifestHash: stringPointer(root)})
	}
	sort.Slice(out.Members, func(i, j int) bool {
		return out.Members[i].ManifestKind+out.Members[i].MemberID < out.Members[j].ManifestKind+out.Members[j].MemberID
	})
	return out, nil
}

type nativeQualifiedLocator struct {
	binding            DocumentationFactorySourcePackageOODLocatorBinding
	receipt            oodevidence.ReceiptV8
	batch              oodevidence.BatchV8
	sourceArtifactHash string
}

func nativeClaimLocator(ids []string, primary string, p map[string]DocumentationFactoryNativeEvidenceLocator, q map[string]nativeQualifiedLocator, org string, createdAt time.Time) (nativeQualifiedLocator, string, oodpublication.NativeLocatorManifestOutput, error) {
	if len(ids) == 0 || primary == "" {
		return nativeQualifiedLocator{}, "", oodpublication.NativeLocatorManifestOutput{}, fmt.Errorf("claim has no locator")
	}
	var first nativeQualifiedLocator
	rows := make([]oodpublication.SpannerRow, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return nativeQualifiedLocator{}, "", oodpublication.NativeLocatorManifestOutput{}, fmt.Errorf("duplicate claim locator")
		}
		seen[id] = true
		x, ok := p[id]
		if !ok {
			return nativeQualifiedLocator{}, "", oodpublication.NativeLocatorManifestOutput{}, fmt.Errorf("unknown locator %q", id)
		}
		b := q[id]
		if id == primary {
			first = b
		}
		if !nativeReceiptRefMatches(x, b.receipt) {
			return nativeQualifiedLocator{}, "", oodpublication.NativeLocatorManifestOutput{}, fmt.Errorf("locator %q does not bind its qualified receipt", id)
		}
		l := b.binding.Locator
		d, e := l.ComputedHash()
		if e != nil || d != l.LocatorHash || l.OrganizationID != b.receipt.OrganizationID || l.EvidenceIdentityHash != b.receipt.EvidenceIdentityHash || l.SourceArtifactMemberHash != b.sourceArtifactHash || l.EligibleReceiptID != b.receipt.ReceiptID || l.EligibleReceiptDigest != b.receipt.RedactedTransportEvidenceDigest || l.SealedCompletenessCertificateHash != b.batch.CompletenessEvidenceDigest || l.SourceContentHash != x.SourceContentSHA256 || l.ByteStartOffset != x.ByteStartOffset || l.ByteEndOffsetExclusive != x.ByteEndOffsetExclusive || l.SelectedRangeContentHash != x.SelectedRangeSHA256 || l.SelectedRangeByteCount != x.SelectedRangeByteCount {
			return nativeQualifiedLocator{}, "", oodpublication.NativeLocatorManifestOutput{}, fmt.Errorf("locator %q canonical hash mismatch", id)
		}
		rows = append(rows, b.binding.LocatorRow)
	}
	if first.binding.NativeLocatorID == "" {
		return nativeQualifiedLocator{}, "", oodpublication.NativeLocatorManifestOutput{}, fmt.Errorf("claim primary locator is not a claim member")
	}
	manifest, e := oodpublication.BuildNativeLocatorManifest(oodpublication.NativeLocatorManifestInput{OrganizationID: org, Locators: rows, CreatedAt: createdAt})
	if e != nil {
		return nativeQualifiedLocator{}, "", oodpublication.NativeLocatorManifestOutput{}, e
	}
	return first, manifest.RootHash, manifest, nil
}
func nativeReceiptRefMatches(x DocumentationFactoryNativeEvidenceLocator, r oodevidence.ReceiptV8) bool {
	if x.SourceContentSHA256 != r.SourceContentHash {
		return false
	}
	for _, s := range x.SourceRefs {
		if s == r.SourceStableReference {
			return true
		}
	}
	return false
}
func nativeSymbolOffset(xs []DocumentationFactoryNativeAPISymbol, id string) int {
	for i, x := range xs {
		if x.ID == id {
			return i
		}
	}
	return -1
}
func nativeHashedRow(row oodpublication.SpannerRow, column string) (oodpublication.SpannerRow, error) {
	if _, e := oodpublication.BuildImmutableRow(row.Table, row.Columns); e != nil {
		return row, e
	}
	d, e := oodpublication.CanonicalMemberDigestFromPhysicalRow(row)
	if e != nil {
		return row, e
	}
	row.Columns[column] = d
	immutable, e := oodpublication.BuildImmutableRow(row.Table, row.Columns)
	if e != nil {
		return row, e
	}
	return immutable.Row(), nil
}
func nativeMember(kind, entry, id string, row oodpublication.SpannerRow) oodpublication.ManifestMemberV8 {
	hash := ""
	if entry == "relationship_evidence" {
		hash = row.Columns["relationship_evidence_hash"].(string)
	} else {
		hash = row.Columns["graph_row_hash"].(string)
	}
	return oodpublication.ManifestMemberV8{ManifestKind: kind, EntryKind: entry, MemberID: id, ClaimedHash: hash, Row: &row}
}
func verifyNativeObjectIndexes(row oodpublication.SpannerRow) error {
	v := row.Columns
	a, e := oodcanon.GraphAddressIndexHashV1("object", v["organization_id"].(string), v["graph_address"].(string))
	if e != nil || a != v["graph_address_index_hash"] {
		return fmt.Errorf("object graph address index hash mismatch")
	}
	r, e := oodcanon.SourceStableReferenceIndexHashV1("object", v["organization_id"].(string), v["source_stable_reference"].(string))
	if e != nil || r != v["source_stable_reference_index_hash"] {
		return fmt.Errorf("object source reference index hash mismatch")
	}
	i, e := oodcanon.ObjectIdentityTupleIndexHashV1(v["organization_id"].(string), v["object_class"].(string), v["source_authority_id"].(string), v["source_ref_kind"].(string), v["source_stable_reference"].(string), v["version_coordinate"].(string), v["section_path"].(string))
	if e != nil || i != v["identity_tuple_index_hash"] {
		return fmt.Errorf("object identity index hash mismatch")
	}
	return nil
}
func verifyNativeSymbolIndexes(row oodpublication.SpannerRow) error {
	v := row.Columns
	a, e := oodcanon.GraphAddressIndexHashV1("symbol", v["organization_id"].(string), v["graph_address"].(string))
	if e != nil || a != v["graph_address_index_hash"] {
		return fmt.Errorf("symbol graph address index hash mismatch")
	}
	i, e := oodcanon.SymbolIdentityTupleIndexHashV1(v["organization_id"].(string), v["object_class"].(string), v["source_authority_id"].(string), v["source_stable_reference"].(string), v["version_coordinate"].(string), v["section_path"].(string), v["symbol_kind"].(string), v["symbol_name"].(string))
	if e != nil || i != v["identity_tuple_index_hash"] {
		return fmt.Errorf("symbol identity index hash mismatch")
	}
	return nil
}
func zeroDigest() string             { return "0000000000000000000000000000000000000000000000000000000000000000" }
func stringPointer(v string) *string { return &v }
