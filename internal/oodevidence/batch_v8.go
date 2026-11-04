package oodevidence

import (
	"context"
	"errors"
	"fmt"
)

// ManifestNodeAuthority owns exact OOD manifest-node hash verification and
// strong reads. The evidence package does the bounded typed traversal and
// never treats a raw hash as proof. A nil authority fails closed.
type ManifestNodeAuthority interface {
	VerifySealedManifestNode(context.Context, ReceiptManifestNode) error
	AdmittedNoncomponentRoleCounts(context.Context, BatchV8) (map[string]int64, error)
	ResolveCanonicalComponentManifest(context.Context, BatchV8) ([]ComponentManifestTuple, error)
}

// VerifiedBatchV8 is emitted only after complete roster/tree verification.
// Its state is opaque so a consumer cannot replace it with a partial roster.
type VerifiedBatchV8 struct {
	organizationID, fetchBatchID, completenessEvidenceDigest string
	receipts                                                 map[string]ReceiptV8
	batch                                                    BatchV8
	verified                                                 bool
}

func (v VerifiedBatchV8) OrganizationID() string             { return v.organizationID }
func (v VerifiedBatchV8) FetchBatchID() string               { return v.fetchBatchID }
func (v VerifiedBatchV8) CompletenessEvidenceDigest() string { return v.completenessEvidenceDigest }
func (v VerifiedBatchV8) Receipt(id string) (ReceiptV8, bool) {
	x, ok := v.receipts[id]
	return CloneReceiptV8(x), ok
}
func ValidateVerifiedBatchV8(v VerifiedBatchV8) error {
	if !v.verified || len(v.receipts) == 0 || v.organizationID == "" || v.fetchBatchID == "" {
		return errors.New("verified OOD8 batch proof absent")
	}
	return nil
}

// VerifyBatchV8 verifies the complete receipt roster, role overlap counts,
// receipt member hashes, and each sealed node in the bounded manifest tree.
func VerifyBatchV8(ctx context.Context, batch BatchV8, receipts []ReceiptV8, root ReceiptManifestNode, nodes ManifestNodeAuthority) (VerifiedBatchV8, error) {
	if nodes == nil {
		return VerifiedBatchV8{}, errors.New("manifest node authority unavailable")
	}
	if batch.TotalReceiptCount < 1 || int64(len(receipts)) != batch.TotalReceiptCount {
		return VerifiedBatchV8{}, errors.New("incomplete receipt roster")
	}
	if batch.CompletenessEvidenceReceiptCount != 1 {
		return VerifiedBatchV8{}, errors.New("OOD8 requires one completeness evidence receipt")
	}
	if err := validateBatchBasis(batch); err != nil {
		return VerifiedBatchV8{}, err
	}
	if batch.BatchReceiptManifestRootHash != root.NodeHash || root.OrganizationID != batch.OrganizationID || root.ManifestKind != "fetch_batch_receipt" {
		return VerifiedBatchV8{}, errors.New("batch root mismatch")
	}
	admittedRoles, err := nodes.AdmittedNoncomponentRoleCounts(ctx, batch)
	if err != nil {
		return VerifiedBatchV8{}, fmt.Errorf("resolve admitted profile role counts: %w", err)
	}
	all := map[string]ReceiptManifestMember{}
	if _, err := walkReceiptManifest(ctx, root, nodes, all, map[string]struct{}{}); err != nil {
		return VerifiedBatchV8{}, err
	}
	if int64(len(all)) != batch.TotalReceiptCount || root.TransitiveMemberCount != batch.TotalReceiptCount {
		return VerifiedBatchV8{}, errors.New("manifest receipt cardinality mismatch")
	}
	byID := make(map[string]ReceiptV8, len(receipts))
	component, complete, noncomponent := int64(0), int64(0), int64(0)
	for _, r := range receipts {
		if r.OrganizationID != batch.OrganizationID || r.FetchBatchID != batch.FetchBatchID {
			return VerifiedBatchV8{}, errors.New("receipt outside batch")
		}
		if r.SourceAuthorityBindingID != batch.SourceAuthorityBindingID || r.SourceAuthorityBindingDigest != batch.SourceAuthorityBindingDigest || r.RepresentationDeclarationID != batch.RepresentationDeclarationID || r.RepresentationDeclarationDigest != batch.RepresentationDeclarationDigest {
			return VerifiedBatchV8{}, errors.New("receipt authority/representation binding mismatch")
		}
		if _, ok := byID[r.ReceiptID]; ok {
			return VerifiedBatchV8{}, errors.New("duplicate receipt roster identity")
		}
		byID[r.ReceiptID] = CloneReceiptV8(r)
		m, ok := all[r.ReceiptID]
		if !ok {
			return VerifiedBatchV8{}, errors.New("roster receipt absent from manifest")
		}
		d, err := receiptDigestV8(r, admittedRoles)
		if err != nil {
			return VerifiedBatchV8{}, fmt.Errorf("receipt %s: %w", r.ReceiptID, err)
		}
		if d != m.MemberHash || d != r.RedactedTransportEvidenceDigest {
			return VerifiedBatchV8{}, errors.New("receipt member digest mismatch")
		}
		roles := roleClasses(r.ReceiptRoles)
		if roles.component {
			component++
		}
		if roles.complete {
			complete++
		}
		if roles.noncomponent {
			noncomponent++
		}
	}
	if err := validateComponentOrdinals(batch, receipts); err != nil {
		return VerifiedBatchV8{}, err
	}
	if batch.CompletenessBasisKind == "source_declared_component_manifest" {
		tuples, err := nodes.ResolveCanonicalComponentManifest(ctx, batch)
		if err != nil {
			return VerifiedBatchV8{}, fmt.Errorf("resolve canonical component manifest: %w", err)
		}
		if err := verifyComponentManifestBijection(tuples, receipts, batch.ComponentReceiptCount); err != nil {
			return VerifiedBatchV8{}, err
		}
	}
	if component != batch.ComponentReceiptCount || complete != batch.CompletenessEvidenceReceiptCount || noncomponent != batch.NoncomponentReceiptCount {
		return VerifiedBatchV8{}, errors.New("role overlap counts mismatch")
	}
	ce, ok := byID[batch.CompletenessEvidenceReceiptID]
	if !ok || !roleClasses(ce.ReceiptRoles).complete {
		return VerifiedBatchV8{}, errors.New("completeness receipt absent or role mismatch")
	}
	if ce.EvidenceIdentityHash != batch.CompletenessEvidenceIdentityHash || ce.SourceContentHashAlgorithm != batch.CompletenessEvidenceContentHashAlgorithm || ce.SourceContentHashProfile != batch.CompletenessEvidenceContentHashProfile || ce.SourceContentHash != batch.CompletenessEvidenceContentHash || ce.EvidenceArchiveAuthorityID != batch.CompletenessEvidenceArchiveAuthorityID || ce.EvidenceArchiveRecordID != batch.CompletenessEvidenceArchiveRecordID || ce.EvidenceArchiveRecordDigest != batch.CompletenessEvidenceArchiveRecordDigest {
		return VerifiedBatchV8{}, errors.New("completeness receipt/batch evidence binding mismatch")
	}
	d, err := CompletenessEvidenceDigestV8(batch)
	if err != nil {
		return VerifiedBatchV8{}, err
	}
	if d != batch.CompletenessEvidenceDigest {
		return VerifiedBatchV8{}, errors.New("completeness evidence digest mismatch")
	}
	return VerifiedBatchV8{organizationID: batch.OrganizationID, fetchBatchID: batch.FetchBatchID, completenessEvidenceDigest: d, receipts: byID, batch: CloneBatchV8(batch), verified: true}, nil
}

func verifyComponentManifestBijection(tuples []ComponentManifestTuple, receipts []ReceiptV8, expected int64) error {
	if int64(len(tuples)) != expected {
		return errors.New("component manifest tuple count mismatch")
	}
	byOrdinal := make(map[int64]ReceiptV8)
	for _, r := range receipts {
		if roleClasses(r.ReceiptRoles).component {
			byOrdinal[*r.FetchComponentOrdinal] = r
		}
	}
	seen := map[int64]struct{}{}
	for _, tuple := range tuples {
		if tuple.Ordinal < 0 || tuple.Ordinal >= expected {
			return errors.New("component manifest ordinal out of range")
		}
		if _, exists := seen[tuple.Ordinal]; exists {
			return errors.New("duplicate component manifest ordinal")
		}
		seen[tuple.Ordinal] = struct{}{}
		r, ok := byOrdinal[tuple.Ordinal]
		if !ok {
			return errors.New("component manifest tuple missing receipt")
		}
		if tuple.StableReference != r.SourceStableReference || tuple.EvidenceIdentityHash != r.EvidenceIdentityHash || tuple.ContentHashAlgorithm != r.SourceContentHashAlgorithm || tuple.ContentHashProfile != r.SourceContentHashProfile || tuple.ContentHash != r.SourceContentHash || tuple.CanonicalContentByteCount != r.EvidenceArchiveByteCount {
			return errors.New("component manifest tuple/receipt binding mismatch")
		}
	}
	return nil
}

func validateBatchBasis(batch BatchV8) error {
	if batch.ExpectedComponentCount != nil && *batch.ExpectedComponentCount < 0 {
		return errors.New("negative expected component count")
	}
	switch batch.CompletenessBasisKind {
	case "single_representation":
		if batch.ExpectedComponentCount == nil || *batch.ExpectedComponentCount != 1 || batch.ComponentReceiptCount != 0 || batch.CompletenessEvidenceReceiptCount != 1 || batch.NoncomponentReceiptCount != 0 || batch.TotalReceiptCount != 1 {
			return errors.New("single representation role/count closure invalid")
		}
	case "source_declared_total", "source_declared_component_manifest":
		if batch.ExpectedComponentCount == nil || *batch.ExpectedComponentCount != batch.ComponentReceiptCount {
			return errors.New("declared component count mismatch")
		}
	case "terminal_continuation":
		// The protected completeness-profile owner verifies the terminal claim.
	default:
		return errors.New("unknown completeness basis")
	}
	return nil
}
func validateComponentOrdinals(batch BatchV8, receipts []ReceiptV8) error {
	if batch.CompletenessBasisKind == "single_representation" {
		return nil
	}
	seen := map[int64]struct{}{}
	for _, r := range receipts {
		c := roleClasses(r.ReceiptRoles)
		if c.component {
			if r.FetchComponentOrdinal == nil || *r.FetchComponentOrdinal < 0 {
				return errors.New("component role has null/negative ordinal")
			}
			if _, ok := seen[*r.FetchComponentOrdinal]; ok {
				return errors.New("duplicate component ordinal")
			}
			seen[*r.FetchComponentOrdinal] = struct{}{}
		} else if r.FetchComponentOrdinal != nil {
			return errors.New("noncomponent receipt has ordinal")
		}
	}
	if int64(len(seen)) != batch.ComponentReceiptCount {
		return errors.New("component ordinal/cardinality mismatch")
	}
	for n := int64(0); n < batch.ComponentReceiptCount; n++ {
		if _, ok := seen[n]; !ok {
			return errors.New("sparse component ordinal")
		}
	}
	return nil
}

type roleClass struct{ component, complete, noncomponent bool }

func roleClasses(roles []string) roleClass {
	var c roleClass
	for _, r := range roles {
		switch r {
		case "component":
			c.component = true
		case "completeness_evidence":
			c.complete = true
		default:
			c.noncomponent = true
		}
	}
	return c
}

func walkReceiptManifest(ctx context.Context, node ReceiptManifestNode, authority ManifestNodeAuthority, out map[string]ReceiptManifestMember, visited map[string]struct{}) (int64, error) {
	if _, exists := visited[node.NodeHash]; exists {
		return 0, errors.New("manifest node cycle or duplicate child")
	}
	visited[node.NodeHash] = struct{}{}
	if node.ManifestKind != "fetch_batch_receipt" || !node.Sealed || node.EntryCount < 0 || node.TransitiveMemberCount < 0 {
		return 0, errors.New("unsealed or wrong manifest node")
	}
	if (node.NodeKind == "leaf" && node.NodeLevel != 0) || (node.NodeKind == "internal" && node.NodeLevel < 1) || (node.NodeKind != "leaf" && node.NodeKind != "internal") {
		return 0, errors.New("noncanonical manifest node level/kind")
	}
	if err := authority.VerifySealedManifestNode(ctx, node); err != nil {
		return 0, fmt.Errorf("verify manifest node %s: %w", node.NodeHash, err)
	}
	entries := node.Entries
	if len(entries) == 0 {
		entries = make([]ReceiptManifestEntry, 0, len(node.Members)+len(node.Children))
		for i := range node.Members {
			m := node.Members[i]
			entries = append(entries, ReceiptManifestEntry{EntryOrdinal: int64(i), Member: &m})
		}
		for i := range node.Children {
			c := node.Children[i]
			entries = append(entries, ReceiptManifestEntry{EntryOrdinal: int64(len(entries)), Child: &c})
		}
	}
	if int64(len(entries)) != node.EntryCount {
		return 0, errors.New("manifest entry count mismatch")
	}
	var subtreeCount int64
	childCount := 0
	for i, e := range entries {
		if e.EntryOrdinal != int64(i) || (e.Member == nil) == (e.Child == nil) {
			return 0, errors.New("invalid manifest entry union or ordinal")
		}
		if e.Member != nil {
			if node.NodeKind != "leaf" {
				return 0, errors.New("internal manifest has member entry")
			}
			if e.Member.ReceiptID == "" || e.Member.MemberHash == "" {
				return 0, errors.New("invalid manifest member")
			}
			if _, ok := out[e.Member.ReceiptID]; ok {
				return 0, errors.New("duplicate manifest receipt")
			}
			out[e.Member.ReceiptID] = *e.Member
			subtreeCount++
		} else if node.NodeKind != "internal" || e.Child.OrganizationID != node.OrganizationID || e.Child.ManifestKind != node.ManifestKind || e.Child.NodeHash == "" || e.Child.NodeLevel != node.NodeLevel-1 || e.Child.TransitiveMemberCount < 1 {
			return 0, errors.New("child manifest binding mismatch")
		} else if count, err := walkReceiptManifest(ctx, *e.Child, authority, out, visited); err != nil {
			return 0, err
		} else {
			if count != e.Child.TransitiveMemberCount {
				return 0, errors.New("child transitive member count mismatch")
			}
			subtreeCount += count
			childCount++
		}
	}
	if node.NodeKind == "internal" && childCount < 2 {
		return 0, errors.New("noncanonical one-child internal manifest")
	}
	if node.TransitiveMemberCount != subtreeCount {
		return 0, errors.New("manifest transitive member count mismatch")
	}
	return subtreeCount, nil
}
