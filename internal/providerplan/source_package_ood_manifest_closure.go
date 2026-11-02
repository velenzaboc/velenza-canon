package providerplan

// Concrete, same-transaction hydration of the nine-root OOD publication
// closure.  It deliberately reads physical rows before the evidence verifier
// is invoked: manifest hashes are claims until the reconciler binds every
// node, entry and owner row to the immutable roster.

import (
	"context"
	"encoding/binary"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodproof"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"google.golang.org/api/iterator"
	spannerv1 "google.golang.org/genproto/googleapis/spanner/v1"
)

// DocumentationFactoryOODManifestClosure is intentionally the only native
// loader result exposed to production composition.  Callers cannot supply a
// ManifestClosureInput or select a closure verifier.
type DocumentationFactoryOODManifestClosure struct {
	Input      oodpublication.ManifestClosureInput
	Reconciler oodpublication.ManifestClosureReconciler
}

func readDocumentationFactoryOODManifestClosure(ctx context.Context, tx *spanner.ReadOnlyTransaction, certificate oodevidence.ClosureCertificateV8) (DocumentationFactoryOODManifestClosure, error) {
	if err := oodReadInputs(ctx, tx, certificate.OrganizationID, certificate.VerificationCertificateID); err != nil {
		return DocumentationFactoryOODManifestClosure{}, err
	}
	in := oodpublication.ManifestClosureInput{OrganizationID: certificate.OrganizationID}
	cert, err := readDocumentationFactoryOODImmutableRow(ctx, tx, "OODGraphClosureVerificationCertificates", certificate.OrganizationID, certificate.VerificationCertificateID)
	if err != nil {
		return DocumentationFactoryOODManifestClosure{}, fmt.Errorf("closure certificate physical row: %w", err)
	}
	in.CertificateRow = &cert
	in.ImmutableRows = append(in.ImmutableRows, cert)
	seen := map[string]bool{}
	for _, root := range []string{"source", "object", "symbol", "edge", "api_property", "graph_fact_locator", "receipt", "structural_projection", "violation"} {
		x, ok := certificate.Roots[root]
		if !ok || x.Hash == "" {
			return DocumentationFactoryOODManifestClosure{}, fmt.Errorf("missing %s root", root)
		}
		if err := readDocumentationFactoryOODManifestNodeClosure(ctx, tx, certificate.OrganizationID, x.Hash, root, seen, &in, certificate); err != nil {
			return DocumentationFactoryOODManifestClosure{}, err
		}
	}
	// API roles and structural facts do not point at a raw locator digest. They
	// point at a separately sealed graph_fact_locator tree.  Those trees are
	// claims made by already-rooted physical members, so load their exact nodes,
	// entries and locator rows in this same transaction without manufacturing a
	// second set of global graph_fact_locator members.
	if err := readDocumentationFactoryOODClaimManifestClosures(ctx, tx, certificate.OrganizationID, seen, &in, certificate); err != nil {
		return DocumentationFactoryOODManifestClosure{}, err
	}
	in.ImmutableRows = uniqueDocumentationFactoryOODImmutableRows(in.ImmutableRows)
	// A reconciler owns only deterministic closure reconciliation. The narrow
	// attestor is attached at the proof boundary below.
	return DocumentationFactoryOODManifestClosure{Input: in, Reconciler: oodpublication.ManifestClosureReconciler{Input: in}}, nil
}

// readDocumentationFactoryOODClaimManifestClosures loads the distinct
// graph-fact locator manifests referenced by closure-owned facts.  The
// ordinary root traversal establishes the global locator membership first;
// a claim tree may only select from that set.  This preserves the one global
// member roster while making every claim's manifest topology part of the
// physical closure roster.
func readDocumentationFactoryOODClaimManifestClosures(ctx context.Context, tx *spanner.ReadOnlyTransaction, org string, rootedNodes map[string]bool, in *oodpublication.ManifestClosureInput, certificate oodevidence.ClosureCertificateV8) error {
	globalLocators := map[string]bool{}
	roots := map[string]bool{}
	for _, m := range in.Members {
		if m.ManifestKind == "graph_fact_locator" && m.Row != nil && m.Row.Table == "OODGraphGraphFactEvidenceLocators" {
			globalLocators[documentationFactoryOODString(*m.Row, "graph_fact_locator_hash")] = true
		}
		if m.Row == nil {
			continue
		}
		var root string
		switch m.Row.Table {
		case "OODGraphObjects":
			root = documentationFactoryOODString(*m.Row, "api_element_role_locator_manifest_hash")
		case "OODGraphRelationshipEvidence", "OODGraphAPIPropertyFacts":
			root = documentationFactoryOODString(*m.Row, "graph_fact_locator_manifest_hash")
		case "OODGraphViolations":
			evidence, ok := m.Row.Columns["evidence"].(oodpublication.CanonicalJSON)
			if !ok {
				return fmt.Errorf("violation claim locator references are not canonical evidence")
			}
			claimRoots, err := oodpublication.ViolationGraphFactLocatorManifestRoots(evidence)
			if err != nil {
				return fmt.Errorf("violation claim locator references: %w", err)
			}
			for _, claimRoot := range claimRoots {
				roots[claimRoot] = true
			}
		}
		if root != "" {
			roots[root] = true
		}
	}
	if len(roots) == 0 {
		return nil
	}
	if len(globalLocators) == 0 {
		return fmt.Errorf("claim locator manifest has no global locator members")
	}
	// Claim roots can be shared by many facts. A root already traversed as a
	// certificate root is already in the input, but it still must resolve from
	// the exact roster below.
	orderedRoots := make([]string, 0, len(roots))
	for root := range roots {
		orderedRoots = append(orderedRoots, root)
	}
	sort.Strings(orderedRoots)
	for _, root := range orderedRoots {
		if rootedNodes[root] {
			if err := verifyDocumentationFactoryOODClaimMembers(in.ImmutableRows, org, root, globalLocators); err != nil {
				return err
			}
			continue
		}
		claim := oodpublication.ManifestClosureInput{OrganizationID: org}
		claimSeen := map[string]bool{}
		if err := readDocumentationFactoryOODManifestNodeClosure(ctx, tx, org, root, "graph_fact_locator", claimSeen, &claim, certificate); err != nil {
			return fmt.Errorf("claim locator manifest %q: %w", root, err)
		}
		// A claim tree is a tree, not a way to graft a second path into a
		// certificate-rooted manifest. Reject both foreign/shared subtrees and
		// foreign locator leaves before they become closure roster rows.
		for _, n := range claim.Nodes {
			if rootedNodes[n.Hash] {
				return fmt.Errorf("claim locator manifest %q reuses rooted node %q", root, n.Hash)
			}
			rootedNodes[n.Hash] = true
		}
		for _, m := range claim.Members {
			if m.Row == nil || m.Row.Table != "OODGraphGraphFactEvidenceLocators" || !globalLocators[m.MemberID] {
				return fmt.Errorf("claim locator manifest %q has foreign locator member", root)
			}
		}
		in.Nodes = append(in.Nodes, claim.Nodes...)
		in.ImmutableRows = append(in.ImmutableRows, claim.ImmutableRows...)
		if err := verifyDocumentationFactoryOODClaimMembers(in.ImmutableRows, org, root, globalLocators); err != nil {
			return err
		}
	}
	return nil
}

func documentationFactoryOODString(row oodpublication.SpannerRow, column string) string {
	v, _ := row.Columns[column].(string)
	return v
}

func verifyDocumentationFactoryOODClaimMembers(rows []oodpublication.SpannerRow, org, root string, globalLocators map[string]bool) error {
	members, err := oodpublication.ResolveGraphFactLocatorManifestMembers(rows, org, root)
	if err != nil {
		return fmt.Errorf("claim locator manifest %q: %w", root, err)
	}
	for _, member := range members {
		if !globalLocators[member] {
			return fmt.Errorf("claim locator manifest %q has foreign locator member %q", root, member)
		}
	}
	return nil
}

func readDocumentationFactoryOODManifestNodeClosure(ctx context.Context, tx *spanner.ReadOnlyTransaction, org, hash, wantKind string, seen map[string]bool, in *oodpublication.ManifestClosureInput, certificate oodevidence.ClosureCertificateV8) error {
	if seen[hash] {
		return fmt.Errorf("manifest node cycle or shared child %q", hash)
	}
	seen[hash] = true
	row, err := readDocumentationFactoryOODImmutableRow(ctx, tx, "OODGraphManifestNodes", org, hash)
	if err != nil {
		return err
	}
	n := oodpublication.ManifestNodeV8{Hash: hash, OrganizationID: org, Row: &row}
	if err := manifestNodeFromRow(row, &n); err != nil {
		return err
	}
	if n.Kind != wantKind {
		return fmt.Errorf("manifest kind %q is not %q", n.Kind, wantKind)
	}
	in.ImmutableRows = append(in.ImmutableRows, row)
	_, entryColumns, err := oodpublication.ImmutablePhysicalColumnNames("OODGraphManifestEntries")
	if err != nil {
		return err
	}
	it := tx.Query(ctx, spanner.Statement{SQL: `SELECT ` + strings.Join(entryColumns, ",") + ` FROM OODGraphManifestEntries WHERE organization_id=@org AND manifest_node_hash=@hash ORDER BY entry_ordinal`, Params: map[string]interface{}{"org": org, "hash": hash}})
	defer it.Stop()
	for ordinal := int64(0); ; ordinal++ {
		r, e := it.Next()
		if e == iterator.Done {
			break
		}
		if e != nil {
			return e
		}
		erow, e := immutableRowFromSpanner("OODGraphManifestEntries", r)
		if e != nil {
			return e
		}
		ent, e := manifestEntryFromRow(erow)
		if e != nil || ent.Ordinal != ordinal {
			return fmt.Errorf("manifest entry: %w", e)
		}
		ent.Row = &erow
		n.Entries = append(n.Entries, ent)
		in.ImmutableRows = append(in.ImmutableRows, erow)
		if ent.EntryKind == "child_manifest" {
			if e := readDocumentationFactoryOODManifestNodeClosure(ctx, tx, org, ent.ChildHash, wantKind, seen, in, certificate); e != nil {
				return e
			}
			continue
		}
		member, e := readDocumentationFactoryOODManifestMember(ctx, tx, org, wantKind, ent, certificate)
		if e != nil {
			return e
		}
		in.Members = append(in.Members, member)
		if member.Row != nil {
			in.ImmutableRows = append(in.ImmutableRows, *member.Row)
		} else {
			in.ImmutableRows = append(in.ImmutableRows, member.EvidenceRows...)
		}
	}
	if int64(len(n.Entries)) != n.EntryCount {
		return fmt.Errorf("manifest entry count mismatch")
	}
	in.Nodes = append(in.Nodes, n)
	return nil
}

func uniqueDocumentationFactoryOODImmutableRows(rows []oodpublication.SpannerRow) []oodpublication.SpannerRow {
	seen := make(map[string]struct{}, len(rows))
	unique := make([]oodpublication.SpannerRow, 0, len(rows))
	for _, row := range rows {
		key := row.Table
		for _, column := range row.KeyColumns {
			key += "\x00" + fmt.Sprint(row.Columns[column])
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, row)
	}
	return unique
}

func manifestNodeFromRow(r oodpublication.SpannerRow, n *oodpublication.ManifestNodeV8) error {
	c := r.Columns
	var ok bool
	if n.Kind, ok = c["manifest_kind"].(string); !ok {
		return fmt.Errorf("manifest kind")
	}
	n.NodeKind, _ = c["node_kind"].(string)
	n.HashAlgorithm, _ = c["hash_algorithm"].(string)
	n.CanonicalizationProfile, _ = c["canonicalization_profile"].(string)
	n.Level, _ = c["node_level"].(int64)
	n.EntryCount, _ = c["entry_count"].(int64)
	n.TransitiveMemberCount, _ = c["transitive_member_count"].(int64)
	n.CanonicalByteCount, _ = c["canonical_byte_count"].(int64)
	n.Sealed, _ = c["sealed"].(bool)
	if x, ok := c["route_prefix_bytes"].([]byte); ok {
		n.RoutePrefix = append([]byte(nil), x...)
	}
	if x, ok := c["route_prefix_nibble_length"].(int64); ok {
		n.RoutePrefixNibbles = x
	}
	return nil
}
func manifestEntryFromRow(r oodpublication.SpannerRow) (oodpublication.ManifestEntryV8, error) {
	c := r.Columns
	e := oodpublication.ManifestEntryV8{}
	var ok bool
	e.Ordinal, ok = c["entry_ordinal"].(int64)
	if !ok {
		return e, fmt.Errorf("ordinal")
	}
	e.EntryKind, _ = c["entry_kind"].(string)
	e.CanonicalByteCount, _ = c["canonical_entry_byte_count"].(int64)
	if x, ok := c["branch_nibble"].(int64); ok {
		e.BranchNibble = x
	}
	if x, ok := c["member_id"].(string); ok {
		e.MemberID = x
	}
	if x, ok := c["member_hash"].(string); ok {
		e.MemberHash = x
	}
	if x, ok := c["child_manifest_node_hash"].(string); ok {
		e.ChildHash = x
	}
	return e, nil
}

// Only owner profiles already pinned in oodcanon are admitted.  A new OOD
// entry/table cannot quietly become source proof merely because it has a hash.
func readDocumentationFactoryOODManifestMember(ctx context.Context, tx *spanner.ReadOnlyTransaction, org, kind string, e oodpublication.ManifestEntryV8, certificate oodevidence.ClosureCertificateV8) (oodpublication.ManifestMemberV8, error) {
	if kind == "source" && e.EntryKind == "source_artifact" {
		return readDocumentationFactoryOODExternalSourceArtifact(ctx, tx, org, e, certificate)
	}
	table, key, profile, err := documentationFactoryOODMemberHome(kind, e.EntryKind, e.MemberID)
	if err != nil {
		return oodpublication.ManifestMemberV8{}, err
	}
	row, err := readDocumentationFactoryOODImmutableRow(ctx, tx, table, org, key)
	if err != nil {
		return oodpublication.ManifestMemberV8{}, err
	}
	m := oodpublication.ManifestMemberV8{ManifestKind: kind, EntryKind: e.EntryKind, MemberID: e.MemberID, ClaimedHash: e.MemberHash, Row: &row, OwnerProfile: profile}
	// Receipt leaves are reconciled from their complete typed physical receipt
	// codec (including receipt_roles), rather than through the scalar owner
	// profile projection used by ordinary members.
	if table == "OODGraphExternalFetchReceipts" {
		return m, nil
	}
	if table == "OODGraphGraphFactEvidenceLocators" {
		got, er := documentationFactoryOODLocatorHash(row)
		if er != nil || got != e.MemberHash {
			return m, fmt.Errorf("graph fact locator physical hash: %w", er)
		}
		// The reconciler's physical codec performs this same closed derivation.
		return m, nil
	}
	if _, err := oodcanon.GraphFactProfileForPhysicalTable(table); err == nil {
		return m, nil
	}
	p, err := oodcanon.ProfileFor(profile)
	if err != nil {
		return m, err
	}
	record, err := documentationFactoryOODRecordFromRow(p, row)
	if err != nil {
		return m, err
	}
	m.OwnerRecord = record
	return m, nil
}
func documentationFactoryOODMemberHome(kind, entry, id string) (string, string, string, error) {
	switch kind {
	case "object":
		return "OODGraphObjects", id, "", nil
	case "symbol":
		return "OODGraphSymbols", id, "", nil
	case "edge":
		return "OODGraphEdges", id, "", nil
	case "receipt":
		if entry == "receipt" {
			return "OODGraphExternalFetchReceipts", id, "external_fetch_receipt_v1", nil
		}
		if entry == "fetch_batch_certificate" {
			return "OODGraphExternalFetchBatches", id, "external_fetch_completeness_evidence_v3", nil
		}
	case "source":
		if entry == "relationship_evidence" {
			return "OODGraphRelationshipEvidence", id, "ood_graph_relationship_evidence_v1", nil
		}
	case "api_property":
		return "OODGraphAPIPropertyFacts", id, "ood_graph_api_property_fact_v1", nil
	case "graph_fact_locator":
		if entry == "graph_fact_locator" {
			return "OODGraphGraphFactEvidenceLocators", id, "", nil
		}
	case "structural_projection":
		return "OODGraphProjectionArtifacts", id, "ood_graph_structural_projection_artifact_v1", nil
	}
	return "", "", "", fmt.Errorf("unadmitted manifest member %s/%s", kind, entry)
}

// External source artifacts are manifest-only identities.  Their only
// admissible backing is a receipt plus its sealed batch; this derives the v2
// tuple from those protected rows and selects it by the manifest hash.
func readDocumentationFactoryOODExternalSourceArtifact(ctx context.Context, tx *spanner.ReadOnlyTransaction, org string, e oodpublication.ManifestEntryV8, cert oodevidence.ClosureCertificateV8) (oodpublication.ManifestMemberV8, error) {
	if e.MemberID != e.MemberHash {
		return oodpublication.ManifestMemberV8{}, fmt.Errorf("source artifact id/hash mismatch")
	}
	it := tx.Query(ctx, spanner.Statement{SQL: "SELECT receipt_id FROM OODGraphExternalFetchReceipts WHERE organization_id=@org", Params: map[string]interface{}{"org": org}})
	defer it.Stop()
	var match *oodpublication.ManifestMemberV8
	for {
		row, er := it.Next()
		if er == iterator.Done {
			break
		}
		if er != nil {
			return oodpublication.ManifestMemberV8{}, er
		}
		var id string
		if er = row.Columns(&id); er != nil {
			return oodpublication.ManifestMemberV8{}, er
		}
		receipt, er := readDocumentationFactoryOODReceipt(ctx, tx, org, id)
		if er != nil {
			return oodpublication.ManifestMemberV8{}, er
		}
		batch, er := readDocumentationFactoryOODBatch(ctx, tx, org, receipt.FetchBatchID)
		if er != nil {
			return oodpublication.ManifestMemberV8{}, er
		}
		p := oodcanon.SourceArtifactExternalEvidenceV2()
		rec := oodcanon.RecordValue{}
		set := func(k string, v oodcanon.Value) { rec[k] = v }
		uuidv := func(s string) (oodcanon.Value, error) { return oodcanon.UUIDText(s) }
		au, er := uuidv(receipt.SourceAuthorityID)
		if er != nil {
			return oodpublication.ManifestMemberV8{}, er
		}
		set("organization_id", oodcanon.String(org))
		set("source_authority_id", au)
		set("source_ref_kind", oodcanon.String(receipt.SourceRefKind))
		set("canonical_source_stable_reference", oodcanon.String(receipt.SourceStableReference))
		set("selected_version_coordinate", oodcanon.String(receipt.VersionCoordinate))
		set("content_hash_algorithm", oodcanon.String(receipt.SourceContentHashAlgorithm))
		set("content_hash_profile", oodcanon.String(receipt.SourceContentHashProfile))
		for _, x := range []struct{ k, v string }{{"authoritative_content_digest", receipt.SourceContentHash}, {"evidence_identity_hash", receipt.EvidenceIdentityHash}, {"source_declared_completeness_relationship_hash", batch.VerifiedCompletenessClaimDigest}} {
			v, ee := oodcanon.DigestHex(x.v)
			if ee != nil {
				return oodpublication.ManifestMemberV8{}, ee
			}
			set(x.k, v)
		}
		set("canonical_content_byte_length", oodcanon.I64(receipt.EvidenceArchiveByteCount))
		d, er := oodcanon.DigestHexOf(p, rec)
		if er != nil {
			return oodpublication.ManifestMemberV8{}, er
		}
		if d != e.MemberHash {
			continue
		}
		// A source artifact has no physical source-artifact row.  Its closed
		// owner tuple is derived from the actual sealed receipt and batch rows;
		// retain both immutable rows as virtual-member evidence so the closure
		// roster cannot be substituted after that derivation.
		receiptRow, er := readDocumentationFactoryOODImmutableRow(ctx, tx, "OODGraphExternalFetchReceipts", org, id)
		if er != nil {
			return oodpublication.ManifestMemberV8{}, er
		}
		batchRow, er := readDocumentationFactoryOODImmutableRow(ctx, tx, "OODGraphExternalFetchBatches", org, receipt.FetchBatchID)
		if er != nil {
			return oodpublication.ManifestMemberV8{}, er
		}
		physicalReceipt, er := oodpublication.ReceiptV8FromPhysicalRow(receiptRow)
		if er != nil {
			return oodpublication.ManifestMemberV8{}, fmt.Errorf("source artifact receipt physical binding: %w", er)
		}
		physicalBatch, er := oodpublication.BatchV8FromPhysicalRow(batchRow)
		if er != nil {
			return oodpublication.ManifestMemberV8{}, fmt.Errorf("source artifact batch physical binding: %w", er)
		}
		if !reflect.DeepEqual(physicalReceipt, receipt) || !reflect.DeepEqual(physicalBatch, batch) {
			return oodpublication.ManifestMemberV8{}, fmt.Errorf("source artifact typed evidence differs from immutable physical rows")
		}
		m := oodpublication.ManifestMemberV8{ManifestKind: "source", EntryKind: "source_artifact", MemberID: e.MemberID, ClaimedHash: e.MemberHash, OwnerProfile: "ood_graph_canonical_source_artifact_identity_v2_external_evidence", OwnerRecord: rec, Receipt: &physicalReceipt, Batch: &physicalBatch, EvidenceRows: []oodpublication.SpannerRow{receiptRow, batchRow}}
		if match != nil {
			return m, fmt.Errorf("ambiguous external source artifact")
		}
		match = &m
	}
	if match == nil {
		return oodpublication.ManifestMemberV8{}, fmt.Errorf("external source artifact absent from protected receipts/cert %s", cert.VerificationCertificateID)
	}
	return *match, nil
}

func immutableRowFromSpanner(table string, row *spanner.Row) (oodpublication.SpannerRow, error) {
	cols := map[string]interface{}{}
	for i, n := range row.ColumnNames() {
		v, e := decodeOODSpannerColumn(row, i)
		if e != nil {
			return oodpublication.SpannerRow{}, e
		}
		cols[n] = v
	}
	x, e := oodpublication.BuildImmutableRow(table, cols)
	if e != nil {
		return oodpublication.SpannerRow{}, e
	}
	return x.Row(), nil
}
func readDocumentationFactoryOODImmutableRow(ctx context.Context, tx *spanner.ReadOnlyTransaction, table, org, id string) (oodpublication.SpannerRow, error) {
	_, columns, err := oodpublication.ImmutablePhysicalColumnNames(table)
	if err != nil {
		return oodpublication.SpannerRow{}, err
	}
	key := "receipt_id"
	switch table {
	case "OODGraphClosureVerificationCertificates":
		key = "verification_certificate_id"
	case "OODGraphManifestNodes":
		key = "manifest_node_hash"
	case "OODGraphObjects":
		key = "graph_object_id"
	case "OODGraphSymbols":
		key = "symbol_id"
	case "OODGraphEdges":
		key = "graph_edge_id"
	case "OODGraphExternalFetchBatches":
		key = "fetch_batch_id"
	case "OODGraphRelationshipEvidence":
		key = "relationship_evidence_hash"
	case "OODGraphAPIPropertyFacts":
		key = "api_property_fact_hash"
	case "OODGraphGraphFactEvidenceLocators":
		key = "graph_fact_locator_hash"
	case "OODGraphProjectionArtifacts":
		key = "projection_artifact_id"
	}
	it := tx.Query(ctx, spanner.Statement{SQL: "SELECT " + strings.Join(columns, ",") + " FROM " + table + " WHERE organization_id=@org AND " + key + "=@id", Params: map[string]interface{}{"org": org, "id": id}})
	defer it.Stop()
	r, e := it.Next()
	if e != nil {
		return oodpublication.SpannerRow{}, e
	}
	if _, e = it.Next(); e != iterator.Done {
		return oodpublication.SpannerRow{}, fmt.Errorf("row not unique")
	}
	return immutableRowFromSpanner(table, r)
}

func documentationFactoryOODLocatorHash(r oodpublication.SpannerRow) (string, error) {
	c := r.Columns
	s := func(k string) string { v, _ := c[k].(string); return v }
	i := func(k string) int64 { v, _ := c[k].(int64); return v }
	l := oodproof.GraphFactLocator{LocatorHash: s("graph_fact_locator_hash"), OrganizationID: s("organization_id"), EvidenceIdentityHash: s("evidence_identity_hash"), SourceArtifactMemberHash: s("source_artifact_member_hash"), EligibleReceiptID: s("eligible_receipt_id"), EligibleReceiptDigest: s("eligible_receipt_digest"), SealedCompletenessCertificateHash: s("sealed_completeness_certificate_hash"), EvidenceArchiveAuthorityID: s("evidence_archive_authority_id"), EvidenceArchiveRecordID: s("evidence_archive_record_id"), EvidenceArchiveRecordDigest: s("evidence_archive_record_digest"), SourceContentHashAlgorithm: s("source_content_hash_algorithm"), SourceContentHashProfile: s("source_content_hash_profile"), SourceContentHash: s("source_content_hash"), SourceContentByteLength: i("source_content_byte_length"), CanonicalRepresentationProfileRef: s("canonical_representation_profile_ref"), CanonicalRepresentationProfileDigest: s("canonical_representation_profile_digest"), ByteStartOffset: i("byte_start_offset"), ByteEndOffsetExclusive: i("byte_end_offset_exclusive"), SelectedRangeContentHash: s("selected_range_content_hash"), SelectedRangeByteCount: i("selected_range_byte_count"), EvidenceArchiveDeletionDomainID: s("evidence_archive_deletion_domain_id"), EvidenceArchiveCryptoShredDomainID: s("evidence_archive_crypto_shred_domain_id")}
	return l.ComputedHash()
}
func decodeOODSpannerColumn(r *spanner.Row, i int) (interface{}, error) {
	g := spanner.GenericColumnValue{}
	if e := r.Column(i, &g); e != nil {
		return nil, e
	}
	switch g.Type.Code {
	case spannerv1.TypeCode_STRING:
		var v spanner.NullString
		if e := g.Decode(&v); e != nil {
			return nil, e
		}
		if !v.Valid {
			return nil, nil
		}
		return v.StringVal, nil
	case spannerv1.TypeCode_INT64:
		var v spanner.NullInt64
		if e := g.Decode(&v); e != nil {
			return nil, e
		}
		if !v.Valid {
			return nil, nil
		}
		return v.Int64, nil
	case spannerv1.TypeCode_BOOL:
		var v spanner.NullBool
		if e := g.Decode(&v); e != nil {
			return nil, e
		}
		if !v.Valid {
			return nil, nil
		}
		return v.Bool, nil
	case spannerv1.TypeCode_BYTES:
		var v []byte
		if e := g.Decode(&v); e != nil {
			return nil, e
		}
		return v, nil
	case spannerv1.TypeCode_TIMESTAMP:
		var v spanner.NullTime
		if e := g.Decode(&v); e != nil {
			return nil, e
		}
		if !v.Valid {
			return nil, nil
		}
		// Preserve the physical Spanner scalar exactly. BuildImmutableRow owns
		// the canonical UTC/microsecond admission check; normalizing here would
		// silently bind bytes that were not actually stored.
		return v.Time, nil
	case spannerv1.TypeCode_ARRAY:
		var v []string
		if e := g.Decode(&v); e != nil {
			return nil, e
		}
		return v, nil
	case spannerv1.TypeCode_JSON:
		var v spanner.NullJSON
		if e := g.Decode(&v); e != nil {
			return nil, e
		}
		if !v.Valid {
			return nil, nil
		}
		return oodpublication.CanonicalJSON([]byte(v.String())), nil
	}
	return nil, fmt.Errorf("unsupported type")
}
func documentationFactoryOODRecordFromRow(p oodcanon.Profile, row oodpublication.SpannerRow) (oodcanon.RecordValue, error) {
	out := oodcanon.RecordValue{}
	for _, f := range p.Fields {
		if f.Literal != nil {
			continue
		}
		x, ok := row.Columns[f.Name]
		if !ok {
			return nil, fmt.Errorf("missing %s", f.Name)
		}
		if x == nil {
			if f.Policy != oodcanon.Nullable {
				return nil, fmt.Errorf("null %s", f.Name)
			}
			out[f.Name] = oodcanon.NullValue(f.Type)
			continue
		}
		switch f.Type {
		case oodcanon.UTF8:
			out[f.Name] = oodcanon.String(x.(string))
		case oodcanon.SHA256:
			v, e := oodcanon.DigestHex(x.(string))
			if e != nil {
				return nil, e
			}
			out[f.Name] = v
		case oodcanon.UUID:
			v, e := oodcanon.UUIDText(x.(string))
			if e != nil {
				return nil, e
			}
			out[f.Name] = v
		case oodcanon.Int64:
			out[f.Name] = oodcanon.I64(x.(int64))
		case oodcanon.TimestampMicroseconds:
			b := make([]byte, 8)
			binary.BigEndian.PutUint64(b, uint64(x.(time.Time).UnixMicro()))
			out[f.Name] = oodcanon.Value{Type: oodcanon.TimestampMicroseconds, Presence: oodcanon.Present, Bytes: b}
		default:
			return nil, fmt.Errorf("unsupported %s", f.Name)
		}
	}
	return out, nil
}
