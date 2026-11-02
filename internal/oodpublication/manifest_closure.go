package oodpublication

// Deterministic OOD8 closure reconciliation.  Strong-read acquisition and
// cryptographic attestation remain separate authority boundaries.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
)

// ManifestClosureInput carries the complete, typed strong-read closure.
// OwnerRecord is mandatory: a stored graph_row_hash is only a claim, never
// evidence. Row is the strict physical immutable row when this member has one.
type ManifestClosureInput struct {
	OrganizationID string
	Nodes          []ManifestNodeV8
	Members        []ManifestMemberV8
	ImmutableRows  []SpannerRow
	CertificateRow *SpannerRow
	MemberVerifier *ManifestMemberVerifier
}
type ManifestNodeV8 struct {
	Hash, OrganizationID, Kind, NodeKind, HashAlgorithm, CanonicalizationProfile     string
	Level, RoutePrefixNibbles, EntryCount, TransitiveMemberCount, CanonicalByteCount int64
	RoutePrefix                                                                      []byte
	Sealed                                                                           bool
	Row                                                                              *SpannerRow
	Entries                                                                          []ManifestEntryV8
}
type ManifestEntryV8 struct {
	Ordinal, BranchNibble, CanonicalByteCount  int64
	EntryKind, MemberID, MemberHash, ChildHash string
	Row                                        *SpannerRow
}
type ManifestMemberV8 struct {
	ManifestKind, EntryKind, MemberID, ClaimedHash, OwnerProfile string
	OwnerRecord                                                  oodcanon.RecordValue
	Row                                                          *SpannerRow
	EvidenceRows                                                 []SpannerRow
	Receipt                                                      *oodevidence.ReceiptV8
	Batch                                                        *oodevidence.BatchV8
}

// ManifestClosureReconciler implements the deterministic portions of both
// legacy evidence callbacks.  Attestation is intentionally not implemented
// here; it remains a narrow external cryptographic capability.
type ManifestClosureReconciler struct{ Input ManifestClosureInput }

// ClosureAttestor is deliberately narrower than ManifestClosureAuthority: it
// cannot bless a caller-supplied traversal, only attest a closure already
// reconciled by ManifestClosureReconciler.
type ClosureAttestor interface {
	VerifyClosureAttestation(context.Context, oodevidence.ClosureCertificateV8) error
}
type AttestedManifestClosureAuthority struct {
	ManifestClosureReconciler
	Attestor ClosureAttestor
}

func (a AttestedManifestClosureAuthority) VerifyClosureAttestation(ctx context.Context, c oodevidence.ClosureCertificateV8) error {
	if a.Attestor == nil {
		return errors.New("closure attestor unavailable")
	}
	return a.Attestor.VerifyClosureAttestation(ctx, c)
}

func VerifyManifestClosureV8(c oodevidence.ClosureCertificateV8, in ManifestClosureInput) error {
	return verifyManifestClosureV8(context.Background(), c, in)
}
func verifyManifestClosureV8(ctx context.Context, c oodevidence.ClosureCertificateV8, in ManifestClosureInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in.OrganizationID == "" || in.OrganizationID != c.OrganizationID {
		return errors.New("manifest closure organization mismatch")
	}
	if len(in.Nodes) == 0 || len(in.Members) == 0 || len(in.ImmutableRows) == 0 {
		return errors.New("manifest closure incomplete")
	}
	physical, err := immutableClosureRows(in.ImmutableRows)
	if err != nil {
		return err
	}
	used := map[string]bool{}
	nodes := map[string]ManifestNodeV8{}
	for _, n := range in.Nodes {
		if n.Hash == "" || n.OrganizationID != in.OrganizationID || !n.Sealed || n.HashAlgorithm != "SHA-256" || n.EntryCount < 0 || n.TransitiveMemberCount < 0 || n.CanonicalByteCount < 0 {
			return errors.New("invalid sealed manifest node")
		}
		if _, ok := nodes[n.Hash]; ok {
			return errors.New("duplicate manifest node")
		}
		if err := bindNodePhysical(n, physical, used); err != nil {
			return err
		}
		nodes[n.Hash] = n
	}
	members := map[string]ManifestMemberV8{}
	for _, m := range in.Members {
		if m.ManifestKind == "" || m.EntryKind == "" || m.MemberID == "" || (m.Row == nil && len(m.EvidenceRows) == 0) {
			return errors.New("incomplete manifest member")
		}
		if m.Row != nil && stringColumn(*m.Row, "organization_id") != in.OrganizationID {
			return fmt.Errorf("member %s/%s organization mismatch", m.ManifestKind, m.MemberID)
		}
		for _, evidence := range m.EvidenceRows {
			if stringColumn(evidence, "organization_id") != in.OrganizationID {
				return fmt.Errorf("member %s/%s evidence organization mismatch", m.ManifestKind, m.MemberID)
			}
		}
		var d string
		var e error
		graphTuple := false
		var actual SpannerRow
		var rowFound bool
		var key string
		if m.Row == nil {
			if m.ManifestKind != "source" || m.EntryKind != "source_artifact" {
				return errors.New("virtual member is only eligible for source artifact")
			}
			if e := verifyVirtualSourceEvidence(m.EvidenceRows); e != nil {
				return e
			}
			d, e = SourceArtifactExternalEvidenceDigest(m.EvidenceRows)
			if e != nil {
				return e
			}
		} else if m.Row.Table == "OODGraphExternalFetchReceipts" {
			receipt, de := ReceiptV8FromPhysicalRow(*m.Row)
			if de != nil {
				return fmt.Errorf("derive physical receipt member: %w", de)
			}
			d, e = oodevidence.ReceiptDigestV8(receipt)
			if e != nil {
				return fmt.Errorf("derive physical receipt member: %w", e)
			}
			graphTuple = true
		} else if m.Row.Table == "OODGraphProjectionArtifacts" || m.Row.Table == "OODGraphAPIPropertyFacts" || m.Row.Table == "OODGraphGraphFactEvidenceLocators" || m.Row.Table == "OODGraphViolations" {
			if m.Row.Table == "OODGraphAPIPropertyFacts" {
				if in.MemberVerifier == nil {
					return errors.New("API property member verifier absent")
				}
				d, e = in.MemberVerifier.CanonicalMemberDigestFromPhysicalRow(ctx, *m.Row)
			} else {
				d, e = CanonicalMemberDigestFromPhysicalRow(*m.Row)
			}
			if e != nil {
				return fmt.Errorf("derive physical %s member: %w", m.Row.Table, e)
			}
			graphTuple = true
		} else if m.Row.Table == "OODGraphExternalFetchReceipts" {
			r, re := ReceiptV8FromPhysicalRow(*m.Row)
			if re != nil {
				return re
			}
			d, e = oodevidence.ReceiptDigestV8(r)
			if e != nil {
				return e
			}
			graphTuple = true
		} else if m.Row.Table == "OODGraphRelationshipEvidence" {
			derived, de := recordFromPhysical(oodcanon.RelationshipEvidenceV1(), *m.Row)
			if de != nil {
				return de
			}
			d, e = oodcanon.DigestHexOf(oodcanon.RelationshipEvidenceV1(), derived)
			if e != nil {
				return e
			}
			graphTuple = true
		} else if profile, pe := oodcanon.GraphFactProfileForPhysicalTable(m.Row.Table); pe == nil {
			graphTuple = true
			derived, de := recordFromPhysical(profile, *m.Row)
			if de != nil {
				return de
			}
			d, e = oodcanon.DigestHexOf(profile, derived)
			if e != nil {
				return e
			}
		} else {
			if m.OwnerProfile == "" || m.OwnerRecord == nil {
				return fmt.Errorf("member %s/%s owner preimage absent", m.ManifestKind, m.MemberID)
			}
			d, e = CanonicalMemberDigest(m.OwnerProfile, m.OwnerRecord)
			if e != nil {
				return fmt.Errorf("recompute %s/%s: %w", m.ManifestKind, m.MemberID, e)
			}
		}
		if d != m.ClaimedHash {
			return fmt.Errorf("member %s/%s physical owner digest mismatch", m.ManifestKind, m.MemberID)
		}
		if m.Row == nil {
			for _, evidence := range m.EvidenceRows {
				key, e := physicalRowKey(evidence)
				if e != nil {
					return e
				}
				actual, rowFound = physical[key]
				if !rowFound || !samePhysicalRow(actual, evidence) {
					return errors.New("virtual member evidence roster bytes differ")
				}
				used[key] = true
			}
			goto memberBound
		}
		key, e = physicalRowKey(*m.Row)
		if e != nil {
			return fmt.Errorf("member physical row: %w", e)
		}
		actual, rowFound = physical[key]
		if !rowFound {
			return fmt.Errorf("member %s/%s physical row not in closure roster", m.ManifestKind, m.MemberID)
		}
		if !samePhysicalRow(actual, *m.Row) {
			return fmt.Errorf("member %s/%s physical roster bytes differ", m.ManifestKind, m.MemberID)
		}
		used[key] = true
	memberBound:
		if !graphTuple && m.Row != nil {
			if e := compareOwnerRecordToRow(m.OwnerProfile, m.OwnerRecord, *m.Row); e != nil {
				return fmt.Errorf("member %s/%s owner row binding: %w", m.ManifestKind, m.MemberID, e)
			}
		}
		if m.Row != nil {
			if col := memberHashColumn(m.ManifestKind); col != "" {
				if x, ok := m.Row.Columns[col]; ok && x != d {
					return fmt.Errorf("member %s/%s claimed row hash mismatch", m.ManifestKind, m.MemberID)
				}
			}
		}
		if !allowedManifestMember(m.ManifestKind, m.EntryKind) {
			return fmt.Errorf("invalid %s entry kind %s", m.ManifestKind, m.EntryKind)
		}
		k := m.ManifestKind + "\x00" + m.EntryKind + "\x00" + m.MemberID
		if _, ok := members[k]; ok {
			return errors.New("duplicate manifest member")
		}
		members[k] = m
	}
	if err := verifyClosureCrossReferences(members, nodes); err != nil {
		return err
	}
	roots := map[string]string{"source": "source", "object": "object", "symbol": "symbol", "edge": "edge", "api_property": "api_property", "graph_fact_locator": "graph_fact_locator", "receipt": "receipt", "structural_projection": "structural_projection", "violation": "violation"}
	seen := map[string]bool{}
	for root, kind := range roots {
		x, ok := c.Roots[root]
		if !ok {
			return fmt.Errorf("missing %s root", root)
		}
		n, ok := nodes[x.Hash]
		if !ok || n.Kind != kind {
			return fmt.Errorf("%s root mismatch", root)
		}
		count, e := walkManifestV8(n.Hash, kind, nodes, members, seen, map[string]bool{})
		if e != nil {
			return fmt.Errorf("%s manifest: %w", root, e)
		}
		if count != x.Count || count != n.TransitiveMemberCount {
			return fmt.Errorf("%s count mismatch", root)
		}
	}
	if len(seen) != len(members) {
		return errors.New("extra member outside nine-root closure")
	}
	if err := verifyManifestNodeReachability(c, members, nodes); err != nil {
		return err
	}
	if in.CertificateRow == nil {
		return errors.New("closure certificate physical row absent")
	}
	if in.CertificateRow.Table != "OODGraphClosureVerificationCertificates" || in.CertificateRow.Columns["organization_id"] != c.OrganizationID || in.CertificateRow.Columns["verification_certificate_id"] != c.VerificationCertificateID || in.CertificateRow.Columns["verification_certificate_hash"] != c.VerificationCertificateHash {
		return errors.New("closure certificate physical binding mismatch")
	}
	key, e := physicalRowKey(*in.CertificateRow)
	if e != nil {
		return e
	}
	actual, ok := physical[key]
	if !ok || !samePhysicalRow(actual, *in.CertificateRow) {
		return errors.New("closure certificate physical roster bytes differ")
	}
	if err := verifyCertificateHash(actual.Columns); err != nil {
		return fmt.Errorf("recompute physical closure certificate: %w", err)
	}
	used[key] = true
	if len(used) != len(physical) {
		return errors.New("immutable closure roster has unbound extra row")
	}
	return nil
}
func (r ManifestClosureReconciler) VerifyCompleteManifestClosure(ctx context.Context, c oodevidence.ClosureCertificateV8) error {
	return verifyManifestClosureV8(ctx, c, r.Input)
}
func (r ManifestClosureReconciler) VerifyCompletePublicationRoster(_ context.Context, closure oodevidence.VerifiedClosureV8, got [][]byte) error {
	if e := oodevidence.ValidateVerifiedClosureV8(closure); e != nil {
		return e
	}
	if closure.OrganizationID() != r.Input.OrganizationID {
		return errors.New("roster organization mismatch")
	}
	want, e := CanonicalImmutableRosterBytes(r.Input.ImmutableRows)
	if e != nil {
		return e
	}
	return equalCanonicalRoster(want, got)
}
func equalCanonicalRoster(want, got [][]byte) error {
	if len(want) != len(got) {
		return errors.New("publication roster count mismatch")
	}
	sortRows := func(in [][]byte) ([][]byte, error) {
		o := make([][]byte, len(in))
		seen := map[string]bool{}
		for i := range in {
			if len(in[i]) == 0 {
				return nil, errors.New("empty publication roster row")
			}
			o[i] = append([]byte(nil), in[i]...)
			if seen[string(o[i])] {
				return nil, errors.New("duplicate publication roster row")
			}
			seen[string(o[i])] = true
		}
		sort.Slice(o, func(i, j int) bool { return bytes.Compare(o[i], o[j]) < 0 })
		return o, nil
	}
	a, e := sortRows(want)
	if e != nil {
		return e
	}
	b, e := sortRows(got)
	if e != nil {
		return e
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return errors.New("publication roster bytes differ from reconciled closure")
		}
	}
	return nil
}

// immutableClosureRows establishes the only row identity used by the
// reconciler: the strict codec's physical primary-key identity.  Supplied
// auxiliary structs never select a similarly named but different row.
func immutableClosureRows(rows []SpannerRow) (map[string]SpannerRow, error) {
	if len(rows) == 0 {
		return nil, errors.New("immutable closure roster empty")
	}
	out := make(map[string]SpannerRow, len(rows))
	for _, row := range rows {
		k, e := physicalRowKey(row)
		if e != nil {
			return nil, e
		}
		if _, ok := out[k]; ok {
			return nil, fmt.Errorf("duplicate immutable closure row %s", k)
		}
		out[k] = row
	}
	return out, nil
}
func physicalRowKey(row SpannerRow) (string, error) {
	x, e := BuildImmutableRow(row.Table, row.Columns)
	if e != nil {
		return "", e
	}
	if !sameStrings(row.KeyColumns, x.Row().KeyColumns) {
		return "", errors.New("immutable closure key roster mismatch")
	}
	return x.Key(), nil
}
func samePhysicalRow(a, b SpannerRow) bool {
	ab, e := CanonicalImmutableRowBytes(a)
	if e != nil {
		return false
	}
	bb, e := CanonicalImmutableRowBytes(b)
	return e == nil && bytes.Equal(ab, bb)
}

// verifyClosureCrossReferences closes the evidence path which cannot be
// proven by independently hashing leaves: a graph-fact locator must cite an
// actual virtual external-evidence source member in this same closure, and
// its eligible receipt coordinate/digest must be one of that member's exact
// receipt/batch evidence rows.
func verifyClosureCrossReferences(members map[string]ManifestMemberV8, nodes map[string]ManifestNodeV8) error {
	type source struct{ hash, receiptID, receiptDigest, batchID, completenessDigest string }
	type receipt struct {
		digest, batchID string
		row             SpannerRow
	}
	sources := map[string]source{}
	receipts := map[string]receipt{}
	receiptRoot := map[string]receipt{}
	locators := map[string]SpannerRow{}
	objects := map[string]SpannerRow{}
	edges := map[string]SpannerRow{}
	semanticRows := false
	claimLocators := func(root string) (map[string]SpannerRow, error) {
		out, seen := map[string]SpannerRow{}, map[string]bool{}
		var walk func(string) error
		walk = func(hash string) error {
			if seen[hash] {
				return errors.New("claim locator manifest cycle")
			}
			seen[hash] = true
			n, ok := nodes[hash]
			if !ok || n.Kind != "graph_fact_locator" || !n.Sealed || len(n.Entries) == 0 {
				return errors.New("claim locator manifest root absent or invalid")
			}
			for _, e := range n.Entries {
				if n.NodeKind == "internal" {
					if e.EntryKind != "child_manifest" || e.ChildHash == "" {
						return errors.New("claim locator manifest child invalid")
					}
					if err := walk(e.ChildHash); err != nil {
						return err
					}
					continue
				}
				if n.NodeKind != "leaf" || e.EntryKind != "graph_fact_locator" || e.MemberID == "" || e.MemberHash != e.MemberID {
					return errors.New("claim locator manifest leaf invalid")
				}
				row, ok := locators[e.MemberID]
				if !ok {
					return errors.New("claim locator is not global closure locator")
				}
				if _, dup := out[e.MemberID]; dup {
					return errors.New("claim locator duplicate")
				}
				out[e.MemberID] = row
			}
			return nil
		}
		if root == "" {
			return nil, errors.New("claim locator manifest root absent")
		}
		if err := walk(root); err != nil {
			return nil, err
		}
		if len(out) == 0 {
			return nil, errors.New("claim locator manifest empty")
		}
		return out, nil
	}
	for _, m := range members {
		if m.Row != nil && (m.Row.Table == "OODGraphObjects" || m.Row.Table == "OODGraphSymbols" || m.Row.Table == "OODGraphEdges" || m.Row.Table == "OODGraphRelationshipEvidence" || m.Row.Table == "OODGraphGraphFactEvidenceLocators" || m.Row.Table == "OODGraphAPIPropertyFacts") {
			semanticRows = true
			break
		}
	}
	// The manifest codec unit fixture intentionally contains no graph facts.
	// Every real publication closure has typed semantic rows and is reconciled
	// below against their exact physical cross-member references.
	if !semanticRows {
		return nil
	}
	// Receipt-root membership is not implied by use as virtual source evidence.
	// It is a distinct manifest root, so retain the exact physical member row
	// and require the virtual source path to select that very row below.
	for _, m := range members {
		if m.ManifestKind != "receipt" || m.EntryKind != "receipt" || m.Row == nil || m.Row.Table != "OODGraphExternalFetchReceipts" {
			continue
		}
		id, digest := stringColumn(*m.Row, "receipt_id"), stringColumn(*m.Row, "redacted_transport_evidence_digest")
		if id == "" || digest == "" || m.MemberID != id || m.ClaimedHash != digest {
			return errors.New("receipt manifest member identity mismatch")
		}
		if _, exists := receiptRoot[id]; exists {
			return errors.New("duplicate receipt-root member")
		}
		receiptRoot[id] = receipt{digest: digest, batchID: stringColumn(*m.Row, "fetch_batch_id"), row: *m.Row}
	}
	for _, m := range members {
		if m.ManifestKind != "source" || m.EntryKind != "source_artifact" || m.Row != nil {
			continue
		}
		var receiptRow, batchRow SpannerRow
		for _, r := range m.EvidenceRows {
			if r.Table == "OODGraphExternalFetchReceipts" {
				receiptRow = r
			}
			if r.Table == "OODGraphExternalFetchBatches" {
				batchRow = r
			}
		}
		if receiptRow.Table == "" || batchRow.Table == "" {
			return errors.New("source artifact receipt or batch absent")
		}
		receiptID, receiptDigest := stringColumn(receiptRow, "receipt_id"), stringColumn(receiptRow, "redacted_transport_evidence_digest")
		batchID := stringColumn(batchRow, "fetch_batch_id")
		if receiptID == "" || receiptDigest == "" || batchID == "" || stringColumn(receiptRow, "fetch_batch_id") != batchID || stringColumn(receiptRow, "organization_id") != stringColumn(batchRow, "organization_id") {
			return errors.New("source artifact receipt/batch typed binding mismatch")
		}
		if _, exists := sources[m.ClaimedHash]; exists {
			return errors.New("duplicate source artifact member hash")
		}
		sources[m.ClaimedHash] = source{m.ClaimedHash, receiptID, receiptDigest, batchID, stringColumn(batchRow, "completeness_evidence_digest")}
		if old, exists := receipts[receiptID]; exists && old.digest != receiptDigest {
			return errors.New("receipt id has conflicting digest")
		}
		receipts[receiptID] = receipt{digest: receiptDigest, batchID: batchID, row: receiptRow}
		root, exists := receiptRoot[receiptID]
		if !exists || root.digest != receiptDigest || root.batchID != batchID || !samePhysicalRow(root.row, receiptRow) {
			return errors.New("source artifact receipt is absent from exact receipt-root closure")
		}
	}
	for _, m := range members {
		if m.Row == nil {
			continue
		}
		switch m.ManifestKind {
		case "graph_fact_locator":
			h := stringColumn(*m.Row, "graph_fact_locator_hash")
			s, ok := sources[stringColumn(*m.Row, "source_artifact_member_hash")]
			r, receiptOK := receipts[stringColumn(*m.Row, "eligible_receipt_id")]
			if h == "" || !ok || !receiptOK || s.receiptID != stringColumn(*m.Row, "eligible_receipt_id") || s.receiptDigest != stringColumn(*m.Row, "eligible_receipt_digest") || r.digest != stringColumn(*m.Row, "eligible_receipt_digest") || r.batchID != s.batchID || (s.completenessDigest != "" && s.completenessDigest != stringColumn(*m.Row, "sealed_completeness_certificate_hash")) {
				return errors.New("graph fact locator does not bind closure source artifact, receipt, and batch")
			}
			// Each locator evidence field is selected from this exact archived
			// receipt; receipt ID/digest equality alone is not a proof of that.
			if stringColumn(*m.Row, "evidence_identity_hash") != stringColumn(r.row, "evidence_identity_hash") ||
				stringColumn(*m.Row, "evidence_archive_authority_id") != stringColumn(r.row, "evidence_archive_authority_id") ||
				stringColumn(*m.Row, "evidence_archive_record_id") != stringColumn(r.row, "evidence_archive_record_id") ||
				stringColumn(*m.Row, "evidence_archive_record_digest") != stringColumn(r.row, "evidence_archive_record_digest") ||
				stringColumn(*m.Row, "source_content_hash_algorithm") != stringColumn(r.row, "source_content_hash_algorithm") ||
				stringColumn(*m.Row, "source_content_hash_profile") != stringColumn(r.row, "source_content_hash_profile") ||
				stringColumn(*m.Row, "source_content_hash") != stringColumn(r.row, "source_content_hash") ||
				int64Column(*m.Row, "source_content_byte_length") != int64Column(r.row, "evidence_archive_byte_count") ||
				stringColumn(*m.Row, "evidence_archive_deletion_domain_id") != stringColumn(r.row, "evidence_archive_deletion_domain_id") ||
				stringColumn(*m.Row, "evidence_archive_crypto_shred_domain_id") != stringColumn(r.row, "evidence_archive_crypto_shred_domain_id") {
				return errors.New("graph fact locator evidence tuple differs from selected receipt")
			}
			if _, duplicate := locators[h]; duplicate {
				return errors.New("duplicate graph fact locator hash")
			}
			locators[h] = *m.Row
		case "object":
			id, h := stringColumn(*m.Row, "graph_object_id"), stringColumn(*m.Row, "graph_row_hash")
			if id == "" || h == "" {
				return errors.New("object identity absent")
			}
			if _, duplicate := objects[id]; duplicate {
				return errors.New("duplicate closure object")
			}
			objects[id] = *m.Row
		case "edge":
			id := stringColumn(*m.Row, "graph_edge_id")
			if id == "" {
				return errors.New("edge identity absent")
			}
			if _, duplicate := edges[id]; duplicate {
				return errors.New("duplicate closure edge")
			}
			edges[id] = *m.Row
		}
	}
	for _, m := range members {
		if m.Row == nil {
			continue
		}
		r := *m.Row
		switch m.ManifestKind {
		case "source":
			if m.EntryKind != "relationship_evidence" {
				continue
			}
			claim, err := claimLocators(stringColumn(r, "graph_fact_locator_manifest_hash"))
			if err != nil {
				return fmt.Errorf("relationship evidence claim locator manifest: %w", err)
			}
			var locator SpannerRow
			for _, candidate := range claim {
				if stringColumn(candidate, "eligible_receipt_id") == stringColumn(r, "eligible_receipt_id") && stringColumn(candidate, "eligible_receipt_digest") == stringColumn(r, "eligible_receipt_digest") {
					locator = candidate
					break
				}
			}
			receiptID, receiptDigest := stringColumn(r, "eligible_receipt_id"), stringColumn(r, "eligible_receipt_digest")
			locatorOK := locator.Table != ""
			receipt, receiptOK := receipts[receiptID]
			if r.Table != "OODGraphRelationshipEvidence" || !locatorOK || !receiptOK || receipt.digest != receiptDigest || stringColumn(locator, "eligible_receipt_id") != receiptID || stringColumn(locator, "eligible_receipt_digest") != receiptDigest ||
				stringColumn(r, "sealed_completeness_certificate_hash") != stringColumn(locator, "sealed_completeness_certificate_hash") ||
				stringColumn(r, "evidence_archive_authority_id") != stringColumn(locator, "evidence_archive_authority_id") ||
				stringColumn(r, "evidence_archive_record_id") != stringColumn(locator, "evidence_archive_record_id") ||
				stringColumn(r, "evidence_archive_record_digest") != stringColumn(locator, "evidence_archive_record_digest") ||
				stringColumn(r, "evidence_identity_hash") != stringColumn(locator, "evidence_identity_hash") ||
				stringColumn(r, "evidence_content_hash_algorithm") != stringColumn(locator, "source_content_hash_algorithm") ||
				stringColumn(r, "evidence_content_hash_profile") != stringColumn(locator, "source_content_hash_profile") ||
				stringColumn(r, "evidence_content_hash") != stringColumn(locator, "source_content_hash") {
				return errors.New("relationship evidence does not bind closure locator and receipt")
			}
		case "object":
			if stringColumn(r, "object_class") == "api_symbol" {
				if _, err := claimLocators(stringColumn(r, "api_element_role_locator_manifest_hash")); err != nil {
					return fmt.Errorf("API object classification locator manifest: %w", err)
				}
			}
		case "violation":
			roots, err := ViolationGraphFactLocatorManifestRoots(r.Columns["evidence"].(CanonicalJSON))
			if err != nil {
				return err
			}
			for _, root := range roots {
				if _, err := claimLocators(root); err != nil {
					return fmt.Errorf("violation locator claim: %w", err)
				}
			}
		case "api_property":
			if _, err := claimLocators(stringColumn(r, "graph_fact_locator_manifest_hash")); err != nil {
				return fmt.Errorf("API property claim locator manifest: %w", err)
			}
			kind, objectID, edgeID, subjectHash := stringColumn(r, "subject_kind"), stringColumn(r, "graph_object_id"), stringColumn(r, "graph_edge_id"), stringColumn(r, "subject_graph_row_hash")
			if kind == "object" {
				o, ok := objects[objectID]
				if !ok || edgeID != "" || stringColumn(o, "graph_row_hash") != subjectHash {
					return errors.New("API property object subject is not in closure")
				}
			} else if kind == "edge" {
				e, ok := edges[edgeID]
				if !ok || objectID != "" || stringColumn(e, "graph_row_hash") != subjectHash {
					return errors.New("API property edge subject is not in closure")
				}
			} else {
				return errors.New("API property has invalid subject union")
			}
		case "symbol":
			o, ok := objects[stringColumn(r, "graph_object_id")]
			if !ok || stringColumn(o, "object_class") != stringColumn(r, "object_class") {
				return errors.New("symbol owner object is not in closure")
			}
		case "edge":
			source, sourceOK := objects[stringColumn(r, "source_endpoint_id")]
			target, targetOK := objects[stringColumn(r, "target_endpoint_id")]
			if !sourceOK || !targetOK || stringColumn(source, "object_class") != stringColumn(r, "source_endpoint_class") || stringColumn(target, "object_class") != stringColumn(r, "target_endpoint_class") {
				return errors.New("edge endpoints are not closure objects")
			}
		}
	}
	return nil
}
func stringColumn(row SpannerRow, name string) string { v, _ := row.Columns[name].(string); return v }
func int64Column(row SpannerRow, name string) int64   { v, _ := row.Columns[name].(int64); return v }

// ResolveGraphFactLocatorManifestMembers verifies a claim locator root from
// exact physical rows; callers cannot turn a digest into a membership claim.
func ResolveGraphFactLocatorManifestMembers(rows []SpannerRow, org, root string) ([]string, error) {
	if org == "" || root == "" {
		return nil, errors.New("locator manifest coordinate incomplete")
	}
	nodes := map[string]ManifestNodeV8{}
	entries := map[string][]ManifestEntryV8{}
	locators := map[string]bool{}
	for _, r := range rows {
		if stringColumn(r, "organization_id") != org {
			continue
		}
		switch r.Table {
		case "OODGraphGraphFactEvidenceLocators":
			locators[stringColumn(r, "graph_fact_locator_hash")] = true
		case "OODGraphManifestNodes":
			h := stringColumn(r, "manifest_node_hash")
			n := ManifestNodeV8{Hash: h, OrganizationID: org, Kind: stringColumn(r, "manifest_kind"), NodeKind: stringColumn(r, "node_kind"), HashAlgorithm: stringColumn(r, "hash_algorithm"), CanonicalizationProfile: stringColumn(r, "canonicalization_profile"), Sealed: r.Columns["sealed"] == true}
			n.Level, _ = r.Columns["node_level"].(int64)
			n.EntryCount, _ = r.Columns["entry_count"].(int64)
			n.TransitiveMemberCount, _ = r.Columns["transitive_member_count"].(int64)
			n.CanonicalByteCount, _ = r.Columns["canonical_byte_count"].(int64)
			nodes[h] = n
		case "OODGraphManifestEntries":
			h := stringColumn(r, "manifest_node_hash")
			e := ManifestEntryV8{EntryKind: stringColumn(r, "entry_kind"), MemberID: stringColumn(r, "member_id"), MemberHash: stringColumn(r, "member_hash"), ChildHash: stringColumn(r, "child_manifest_node_hash")}
			e.Ordinal, _ = r.Columns["entry_ordinal"].(int64)
			e.CanonicalByteCount, _ = r.Columns["canonical_entry_byte_count"].(int64)
			entries[h] = append(entries[h], e)
		}
	}
	for h, n := range nodes {
		n.Entries = entries[h]
		nodes[h] = n
	}
	seen := map[string]bool{}
	out := []string{}
	var walk func(string) error
	walk = func(h string) error {
		if seen[h] {
			return errors.New("locator manifest cycle")
		}
		seen[h] = true
		n, ok := nodes[h]
		if !ok || n.Kind != "graph_fact_locator" || !n.Sealed {
			return errors.New("locator manifest node absent")
		}
		if err := verifyNodeHash(n, nodes); err != nil {
			return err
		}
		if int64(len(n.Entries)) != n.EntryCount {
			return errors.New("locator manifest entry count")
		}
		for i, e := range n.Entries {
			if e.Ordinal != int64(i) {
				return errors.New("locator manifest ordinal")
			}
			if n.NodeKind == "internal" {
				if e.EntryKind != "child_manifest" {
					return errors.New("locator manifest child")
				}
				if err := walk(e.ChildHash); err != nil {
					return err
				}
				continue
			}
			if n.NodeKind != "leaf" || e.EntryKind != "graph_fact_locator" || e.MemberID == "" || e.MemberHash != e.MemberID || !locators[e.MemberID] {
				return errors.New("locator manifest member absent")
			}
			out = append(out, e.MemberID)
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("locator manifest empty")
	}
	return out, nil
}

func closurePhysical(rows map[string]SpannerRow, table string, cols map[string]interface{}) (string, SpannerRow, error) {
	contract, ok := immutablePhysicalContracts[table]
	if !ok {
		return "", SpannerRow{}, fmt.Errorf("unknown physical %s table", table)
	}
	k := table
	for _, name := range contract.keys {
		v, ok := cols[name]
		if !ok {
			return "", SpannerRow{}, fmt.Errorf("physical %s identity lacks %s", table, name)
		}
		k += "\x00" + physicalKeyString(v)
	}
	r, ok := rows[k]
	if !ok {
		return "", SpannerRow{}, fmt.Errorf("missing physical %s row", table)
	}
	return k, r, nil
}
func bindNodePhysical(n ManifestNodeV8, rows map[string]SpannerRow, used map[string]bool) error {
	nodeCols := map[string]interface{}{"organization_id": n.OrganizationID, "manifest_node_hash": n.Hash}
	key, row, e := closurePhysical(rows, "OODGraphManifestNodes", nodeCols)
	if e != nil {
		return e
	}
	used[key] = true
	if n.Row == nil || !samePhysicalRow(row, *n.Row) {
		return errors.New("manifest node physical roster bytes differ")
	}
	for col, want := range map[string]interface{}{"organization_id": n.OrganizationID, "manifest_node_hash": n.Hash, "manifest_kind": n.Kind, "node_kind": n.NodeKind, "node_level": n.Level, "route_prefix_bytes": nullableBytes(n.RoutePrefix, n.CanonicalizationProfile), "route_prefix_nibble_length": nullableI64(n.RoutePrefixNibbles, n.CanonicalizationProfile), "entry_count": n.EntryCount, "transitive_member_count": n.TransitiveMemberCount, "canonical_byte_count": n.CanonicalByteCount, "hash_algorithm": n.HashAlgorithm, "canonicalization_profile": n.CanonicalizationProfile, "sealed": n.Sealed} {
		if !reflect.DeepEqual(row.Columns[col], want) {
			return fmt.Errorf("manifest node physical binding differs at %s", col)
		}
	}
	for _, entry := range n.Entries {
		cols := map[string]interface{}{"organization_id": n.OrganizationID, "manifest_node_hash": n.Hash, "entry_ordinal": entry.Ordinal}
		ek, erow, e := closurePhysical(rows, "OODGraphManifestEntries", cols)
		if e != nil {
			return e
		}
		used[ek] = true
		if entry.Row == nil || !samePhysicalRow(erow, *entry.Row) {
			return errors.New("manifest entry physical roster bytes differ")
		}
		branch := interface{}(nil)
		if n.CanonicalizationProfile == "ood_graph_sparse_patricia_membership_node_v1" {
			branch = entry.BranchNibble
		}
		memberID := interface{}(nil)
		memberHash := interface{}(nil)
		child := interface{}(nil)
		if entry.EntryKind == "child_manifest" {
			child = entry.ChildHash
		} else {
			memberID = entry.MemberID
			memberHash = entry.MemberHash
		}
		for col, want := range map[string]interface{}{"organization_id": n.OrganizationID, "manifest_node_hash": n.Hash, "entry_ordinal": entry.Ordinal, "branch_nibble": branch, "entry_kind": entry.EntryKind, "member_id": memberID, "member_hash": memberHash, "child_manifest_node_hash": child, "canonical_entry_byte_count": entry.CanonicalByteCount} {
			if !reflect.DeepEqual(erow.Columns[col], want) {
				return fmt.Errorf("manifest entry physical binding differs at %s", col)
			}
		}
	}
	return nil
}
func nullableBytes(x []byte, profile string) interface{} {
	if profile == "ood_graph_sparse_patricia_membership_node_v1" {
		return x
	}
	return nil
}
func nullableI64(x int64, profile string) interface{} {
	if profile == "ood_graph_sparse_patricia_membership_node_v1" {
		return x
	}
	return nil
}

func compareOwnerRecordToRow(profile string, record oodcanon.RecordValue, row SpannerRow) error {
	p, e := oodcanon.ProfileFor(profile)
	if e != nil {
		return e
	}
	for _, f := range p.Fields {
		if f.Literal != nil {
			continue
		}
		v, ok := record[f.Name]
		if !ok {
			return fmt.Errorf("owner record lacks %s", f.Name)
		}
		raw, present := row.Columns[f.Name]
		if !present { // nested and array canonical containers have no scalar physical column.
			if f.Type == oodcanon.Array || f.Type == oodcanon.Record || f.Type == oodcanon.Map {
				continue
			}
			return fmt.Errorf("physical row lacks owner field %s", f.Name)
		}
		if !ownerValueMatches(f, v, raw) {
			return fmt.Errorf("physical row differs at %s", f.Name)
		}
	}
	return nil
}
func ownerValueMatches(f oodcanon.Field, v oodcanon.Value, raw interface{}) bool {
	if v.Presence == oodcanon.Null {
		return raw == nil
	}
	if v.Presence != oodcanon.Present {
		return false
	}
	switch f.Type {
	case oodcanon.UTF8:
		return reflect.DeepEqual(raw, string(v.Bytes))
	case oodcanon.SHA256:
		return reflect.DeepEqual(raw, hex.EncodeToString(v.Bytes))
	case oodcanon.UUID:
		u, e := uuid.FromBytes(v.Bytes)
		return e == nil && reflect.DeepEqual(raw, u.String())
	case oodcanon.Int64:
		return len(v.Bytes) == 8 && reflect.DeepEqual(raw, int64(binary.BigEndian.Uint64(v.Bytes)))
	case oodcanon.Bool:
		b, ok := raw.(bool)
		return ok && len(v.Bytes) == 1 && b == (v.Bytes[0] == 1)
	case oodcanon.TimestampMicroseconds:
		t, ok := raw.(time.Time)
		return ok && len(v.Bytes) == 8 && t.Location() == time.UTC && t.Nanosecond()%1000 == 0 && t.UnixMicro() == int64(binary.BigEndian.Uint64(v.Bytes))
	case oodcanon.RawBytes:
		return reflect.DeepEqual(raw, v.Bytes)
	case oodcanon.Array:
		if a, ok := raw.([]string); ok && len(a) == len(v.Elements) {
			for i := range a {
				if v.Elements[i].Presence != oodcanon.Present || a[i] != string(v.Elements[i].Bytes) {
					return false
				}
			}
			return true
		}
		return false
	case oodcanon.Map, oodcanon.Record:
		if x, ok := raw.(CanonicalJSON); ok {
			return bytes.Equal(x, v.Bytes)
		}
		if x, ok := raw.([]byte); ok {
			return bytes.Equal(x, v.Bytes)
		}
		return false
	}
	return false
}

func recordFromPhysical(p oodcanon.Profile, row SpannerRow) (oodcanon.RecordValue, error) {
	r := oodcanon.RecordValue{}
	for _, f := range p.Fields {
		if f.Literal != nil {
			continue
		}
		x, ok := row.Columns[f.Name]
		if !ok {
			return nil, fmt.Errorf("physical row lacks %s", f.Name)
		}
		v, e := physicalOwnerValue(f, x)
		if e != nil {
			return nil, fmt.Errorf("physical %s: %w", f.Name, e)
		}
		r[f.Name] = v
	}
	return r, nil
}
func physicalOwnerValue(f oodcanon.Field, x interface{}) (oodcanon.Value, error) {
	if x == nil {
		if f.Policy == oodcanon.Nullable {
			return oodcanon.NullValue(f.Type), nil
		}
		return oodcanon.Value{}, errors.New("required value null")
	}
	switch f.Type {
	case oodcanon.UTF8:
		s, ok := x.(string)
		if !ok {
			return oodcanon.Value{}, errors.New("not string")
		}
		return oodcanon.String(s), nil
	case oodcanon.SHA256:
		s, ok := x.(string)
		if !ok {
			return oodcanon.Value{}, errors.New("not digest")
		}
		return oodcanon.DigestHex(s)
	case oodcanon.UUID:
		s, ok := x.(string)
		if !ok {
			return oodcanon.Value{}, errors.New("not uuid")
		}
		return oodcanon.UUIDText(s)
	case oodcanon.Int64:
		n, ok := x.(int64)
		if !ok {
			return oodcanon.Value{}, errors.New("not int64")
		}
		return oodcanon.I64(n), nil
	case oodcanon.Bool:
		b, ok := x.(bool)
		if !ok {
			return oodcanon.Value{}, errors.New("not bool")
		}
		if b {
			return oodcanon.Value{Type: oodcanon.Bool, Presence: oodcanon.Present, Bytes: []byte{1}}, nil
		}
		return oodcanon.Value{Type: oodcanon.Bool, Presence: oodcanon.Present, Bytes: []byte{0}}, nil
	case oodcanon.TimestampMicroseconds:
		t, ok := x.(time.Time)
		if !ok || t.Location() != time.UTC || t.Nanosecond()%1000 != 0 {
			return oodcanon.Value{}, errors.New("not UTC microsecond timestamp")
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(t.UnixMicro()))
		return oodcanon.Value{Type: oodcanon.TimestampMicroseconds, Presence: oodcanon.Present, Bytes: b}, nil
	}
	return oodcanon.Value{}, errors.New("unsupported physical owner field")
}

func walkManifestV8(hash, kind string, nodes map[string]ManifestNodeV8, members map[string]ManifestMemberV8, seen, stack map[string]bool) (int64, error) {
	if stack[hash] {
		return 0, errors.New("manifest cycle")
	}
	stack[hash] = true
	defer delete(stack, hash)
	n, ok := nodes[hash]
	if !ok || n.Kind != kind {
		return 0, errors.New("missing or wrong-kind manifest node")
	}
	if e := verifyNodeHash(n, nodes); e != nil {
		return 0, e
	}
	if int64(len(n.Entries)) != n.EntryCount {
		return 0, errors.New("manifest entry count mismatch")
	}
	var total int64
	children := 0
	branches := map[int64]bool{}
	for i, e := range n.Entries {
		if e.CanonicalByteCount < 0 {
			return 0, errors.New("negative canonical entry byte count")
		}
		if e.Ordinal != int64(i) {
			return 0, errors.New("noncontiguous manifest ordinal")
		}
		sparse := n.CanonicalizationProfile == "ood_graph_sparse_patricia_membership_node_v1"
		if sparse {
			if e.BranchNibble < 0 || e.BranchNibble > 15 || e.Ordinal != e.BranchNibble || branches[e.BranchNibble] {
				return 0, errors.New("invalid sparse Patricia slot")
			}
			branches[e.BranchNibble] = true
		} else if e.BranchNibble != 0 {
			return 0, errors.New("ordinary manifest branch nibble present")
		}
		switch e.EntryKind {
		case "child_manifest":
			if e.MemberID != "" || e.MemberHash != "" || e.ChildHash == "" {
				return 0, errors.New("invalid child entry union")
			}
			child, ok := nodes[e.ChildHash]
			if !ok || child.Level <= n.Level || (!sparse && child.Level != n.Level-1) {
				return 0, errors.New("invalid child level")
			}
			if sparse && (!hasPrefixNibbles(child.RoutePrefix, n.RoutePrefix, n.RoutePrefixNibbles) || child.RoutePrefixNibbles <= n.RoutePrefixNibbles || nibbleAt(child.RoutePrefix, n.RoutePrefixNibbles) != byte(e.BranchNibble)) {
				return 0, errors.New("invalid sparse child route")
			}
			x, er := walkManifestV8(e.ChildHash, kind, nodes, members, seen, stack)
			if er != nil {
				return 0, er
			}
			total += x
			children++
		default:
			if e.ChildHash != "" || e.MemberID == "" || e.MemberHash == "" {
				return 0, errors.New("invalid member entry union")
			}
			if !allowedManifestMember(kind, e.EntryKind) {
				return 0, errors.New("invalid manifest member entry kind")
			}
			k := kind + "\x00" + e.EntryKind + "\x00" + e.MemberID
			m, ok := members[k]
			if !ok || m.ClaimedHash != e.MemberHash {
				return 0, errors.New("manifest member reconciliation mismatch")
			}
			if seen[k] {
				return 0, errors.New("duplicate closure member")
			}
			if sparse {
				b, er := memberHashBytes(e.MemberHash)
				if er != nil || !hasPrefixNibbles(b, n.RoutePrefix, n.RoutePrefixNibbles) || nibbleAt(b, n.RoutePrefixNibbles) != byte(e.BranchNibble) {
					return 0, errors.New("invalid sparse member route")
				}
			}
			seen[k] = true
			total++
		}
	}
	if n.NodeKind == "internal" && children < 2 {
		return 0, errors.New("one-child internal manifest")
	}
	if n.TransitiveMemberCount != total {
		return 0, errors.New("manifest transitive count mismatch")
	}
	return total, nil
}
func verifyNodeHash(n ManifestNodeV8, nodes map[string]ManifestNodeV8) error {
	var p oodcanon.Profile
	var r oodcanon.RecordValue
	switch n.CanonicalizationProfile {
	case "ood_graph_manifest_node_v1":
		if n.NodeKind == "leaf" {
			p = oodcanon.ManifestLeafV1()
		} else if n.NodeKind == "internal" {
			p = oodcanon.ManifestInternalV1()
		} else {
			return errors.New("invalid ordinary node kind")
		}
		r = ordinaryNodeRecord(n, nodes)
	case "ood_graph_sparse_patricia_membership_node_v1":
		if n.NodeKind != "sparse_empty" && n.NodeKind != "sparse_branch" {
			return errors.New("invalid sparse node kind")
		}
		if err := validateSparseRoute(n); err != nil {
			return err
		}
		p = oodcanon.SparsePatriciaMembershipNodeV1()
		r = sparseNodeRecord(n)
	default:
		return errors.New("unknown manifest canonicalization profile")
	}
	d, e := oodcanon.DigestHexOf(p, r)
	if e != nil {
		return e
	}
	if d != n.Hash {
		return errors.New("manifest node hash mismatch")
	}
	if n.CanonicalizationProfile == "ood_graph_manifest_node_v1" {
		if err := verifyOrdinaryManifestByteCounts(n, nodes, p, r); err != nil {
			return err
		}
	} else if err := verifySparseManifestByteCounts(n, p, r); err != nil {
		return err
	}
	return nil
}

func validateSparseRoute(n ManifestNodeV8) error {
	if n.RoutePrefixNibbles < 0 || n.RoutePrefixNibbles > 64 || n.Level != n.RoutePrefixNibbles {
		return errors.New("invalid sparse route level")
	}
	want := int((n.RoutePrefixNibbles + 1) / 2)
	if len(n.RoutePrefix) != want || (n.RoutePrefixNibbles%2 == 1 && want > 0 && n.RoutePrefix[want-1]&0x0f != 0) {
		return errors.New("noncanonical sparse route prefix")
	}
	if n.NodeKind == "sparse_empty" && (n.EntryCount != 0 || n.TransitiveMemberCount != 0) {
		return errors.New("nonempty sparse empty node")
	}
	return nil
}

func nibbleAt(b []byte, pos int64) byte {
	x := b[pos/2]
	if pos%2 == 0 {
		return x >> 4
	}
	return x & 0x0f
}
func hasPrefixNibbles(value, prefix []byte, n int64) bool {
	if n == 0 {
		return true
	}
	if int64(len(value))*2 < n || int64(len(prefix))*2 < n {
		return false
	}
	for i := int64(0); i < n; i++ {
		if nibbleAt(value, i) != nibbleAt(prefix, i) {
			return false
		}
	}
	return true
}
func ordinaryNodeRecord(n ManifestNodeV8, nodes map[string]ManifestNodeV8) oodcanon.RecordValue {
	r := oodcanon.RecordValue{"manifest_kind": oodcanon.String(n.Kind), "entry_count": oodcanon.I64(n.EntryCount), "transitive_member_count": oodcanon.I64(n.TransitiveMemberCount), "canonical_byte_count": oodcanon.I64(n.CanonicalByteCount)}
	if n.NodeKind == "leaf" {
		a := make([]oodcanon.Value, 0, len(n.Entries))
		for _, e := range n.Entries {
			h, _ := oodcanon.DigestHex(e.MemberHash)
			a = append(a, oodcanon.Value{Type: oodcanon.Record, Presence: oodcanon.Present, Fields: []oodcanon.NamedValue{{Name: "entry_ordinal", Value: oodcanon.I64(e.Ordinal)}, {Name: "entry_kind", Value: oodcanon.String(e.EntryKind)}, {Name: "member_id", Value: oodcanon.String(e.MemberID)}, {Name: "member_hash", Value: h}, {Name: "child_manifest_node_hash", Value: oodcanon.NullValue(oodcanon.SHA256)}, {Name: "canonical_entry_byte_count", Value: oodcanon.I64(e.CanonicalByteCount)}}})
		}
		r["ordered_entry_tuples"] = oodcanon.Value{Type: oodcanon.Array, Presence: oodcanon.Present, Elements: a}
		return r
	}
	r["node_level"] = oodcanon.I64(n.Level)
	a := make([]oodcanon.Value, 0, len(n.Entries))
	for _, e := range n.Entries {
		h, _ := oodcanon.DigestHex(e.ChildHash)
		child := nodes[e.ChildHash]
		a = append(a, oodcanon.Value{Type: oodcanon.Record, Presence: oodcanon.Present, Fields: []oodcanon.NamedValue{{Name: "entry_ordinal", Value: oodcanon.I64(e.Ordinal)}, {Name: "entry_kind", Value: oodcanon.String(e.EntryKind)}, {Name: "member_id", Value: oodcanon.NullValue(oodcanon.UTF8)}, {Name: "member_hash", Value: oodcanon.NullValue(oodcanon.SHA256)}, {Name: "child_manifest_node_hash", Value: h}, {Name: "child_transitive_member_count", Value: oodcanon.I64(child.TransitiveMemberCount)}, {Name: "child_canonical_byte_count", Value: oodcanon.I64(child.CanonicalByteCount)}, {Name: "canonical_entry_byte_count", Value: oodcanon.I64(e.CanonicalByteCount)}}})
	}
	r["ordered_child_tuples"] = oodcanon.Value{Type: oodcanon.Array, Presence: oodcanon.Present, Elements: a}
	return r
}
func sparseNodeRecord(n ManifestNodeV8) oodcanon.RecordValue {
	a := make([]oodcanon.Value, 0, len(n.Entries))
	for _, e := range n.Entries {
		id := oodcanon.NullValue(oodcanon.UTF8)
		h := oodcanon.NullValue(oodcanon.SHA256)
		c := oodcanon.NullValue(oodcanon.SHA256)
		if e.EntryKind == "child_manifest" {
			c, _ = oodcanon.DigestHex(e.ChildHash)
		} else {
			id = oodcanon.String(e.MemberID)
			h, _ = oodcanon.DigestHex(e.MemberHash)
		}
		a = append(a, oodcanon.Value{Type: oodcanon.Record, Presence: oodcanon.Present, Fields: []oodcanon.NamedValue{{Name: "branch_nibble", Value: oodcanon.I64(e.BranchNibble)}, {Name: "entry_kind", Value: oodcanon.String(e.EntryKind)}, {Name: "member_id", Value: id}, {Name: "member_hash", Value: h}, {Name: "child_manifest_node_hash", Value: c}, {Name: "canonical_entry_byte_count", Value: oodcanon.I64(e.CanonicalByteCount)}}})
	}
	return oodcanon.RecordValue{"manifest_kind": oodcanon.String(n.Kind), "node_kind": oodcanon.String(n.NodeKind), "node_level": oodcanon.I64(n.Level), "route_prefix_nibble_length": oodcanon.I64(n.RoutePrefixNibbles), "route_prefix_bytes": oodcanon.Bytes(n.RoutePrefix), "entry_count": oodcanon.I64(n.EntryCount), "transitive_member_count": oodcanon.I64(n.TransitiveMemberCount), "canonical_byte_count": oodcanon.I64(n.CanonicalByteCount), "ordered_present_slot_tuples": oodcanon.Value{Type: oodcanon.Array, Presence: oodcanon.Present, Elements: a}}
}
func memberHashColumn(kind string) string {
	switch kind {
	case "object", "symbol", "edge":
		return "graph_row_hash"
	case "receipt":
		return "redacted_transport_evidence_digest"
	case "source":
		return "relationship_evidence_hash"
	case "api_property":
		return "api_property_fact_hash"
	case "graph_fact_locator":
		return "graph_fact_locator_hash"
	case "structural_projection":
		return "projection_hash"
	}
	return ""
}
func allowedManifestMember(kind, entry string) bool {
	switch kind {
	case "source":
		return entry == "source_artifact" || entry == "relationship_evidence"
	case "object":
		return entry == "object"
	case "symbol":
		return entry == "symbol"
	case "edge":
		return entry == "edge"
	case "api_property":
		return entry == "api_property"
	case "graph_fact_locator":
		return entry == "graph_fact_locator"
	case "receipt":
		return entry == "receipt" || entry == "fetch_batch_certificate"
	case "structural_projection":
		return entry == "structural_projection"
	case "violation":
		return entry == "violation"
	}
	return false
}

// memberHashBytes is intentionally retained here for narrow mapper validation:
// every entry hash is lowercase 32-byte SHA-256 text before it can be used as a
// sparse route coordinate.
func memberHashBytes(s string) ([]byte, error) {
	if len(s) != 64 || strings.ToLower(s) != s {
		return nil, errors.New("noncanonical member hash")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("noncanonical member hash")
	}
	return b, nil
}
