package oodpublication

// Deterministic construction of the physical OOD publication plan.  This is
// deliberately a construction boundary, not an evidence mint: source,
// archive, schema and attestation facts are supplied as already-admitted typed
// rows/coordinates by boot composition.  The builder only derives the
// manifest topology, closure/certificate hashes and physical write roster.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
)

type NativePlanBuildInput struct {
	OrganizationID, SnapshotKind, SnapshotID, RunID string
	// Certificate supplies only boot-owned external coordinates (attestation,
	// profile/currentness policy). Roots and hashes are always overwritten.
	Certificate oodevidence.ClosureCertificateV8
	Members     []ManifestMemberV8
	// Rows are the exact physical backing rows for Members. Virtual source
	// members must carry their receipt/batch evidence in Members instead.
	ImmutableRows []SpannerRow
	// AuxiliaryNodes are content-addressed claim submanifests (for example a
	// per-property locator root). Their physical rows remain in ImmutableRows.
	AuxiliaryNodes []ManifestNodeV8
	MemberVerifier *ManifestMemberVerifier
	Attestor       ClosureAttestor
	CreatedAt      time.Time
}

type NativePlanBuildOutput struct {
	Plan            SpannerWritePlan
	Certificate     oodevidence.ClosureCertificateV8
	Closure         ManifestClosureInput
	VerifiedClosure oodevidence.VerifiedClosureV8
	VerifiedRoster  oodevidence.VerifiedPublicationRosterV8
}

// NativePlanDraft is an unverified deterministic successor content phase. It
// has exact new roots and a pre-certificate immutable roster for the narrow
// boot issuer to attest, but carries no publication proof.
type NativePlanDraft struct {
	Certificate                  oodevidence.ClosureCertificateV8
	ImmutableRoster              [][]byte
	members                      []ManifestMemberV8
	immutableRows                []SpannerRow
	memberVerifier               *ManifestMemberVerifier
	auxiliaryNodes               []ManifestNodeV8
	organizationID, snapshotKind string
	createdAt                    time.Time
}

type NativePlanDraftInput struct {
	OrganizationID, SnapshotKind string
	Certificate                  oodevidence.ClosureCertificateV8
	Members                      []ManifestMemberV8
	ImmutableRows                []SpannerRow
	AuxiliaryNodes               []ManifestNodeV8
	MemberVerifier               *ManifestMemberVerifier
	CreatedAt                    time.Time
}

type NativeLocatorManifestInput struct {
	OrganizationID string
	Locators       []SpannerRow
	CreatedAt      time.Time
}
type NativeLocatorManifestOutput struct {
	RootHash      string
	Nodes         []ManifestNodeV8
	ImmutableRows []SpannerRow
	Members       []ManifestMemberV8
}

func BuildNativeLocatorManifest(in NativeLocatorManifestInput) (NativeLocatorManifestOutput, error) {
	if in.OrganizationID == "" || len(in.Locators) == 0 || in.CreatedAt.IsZero() || in.CreatedAt.Location() != time.UTC || in.CreatedAt.Nanosecond()%1000 != 0 {
		return NativeLocatorManifestOutput{}, errors.New("locator manifest requires qualified locators and UTC microsecond time")
	}
	members := make([]ManifestMemberV8, 0, len(in.Locators))
	seen := map[string]bool{}
	for _, row := range in.Locators {
		if row.Table != "OODGraphGraphFactEvidenceLocators" || row.Columns["organization_id"] != in.OrganizationID {
			return NativeLocatorManifestOutput{}, errors.New("locator manifest row is not a qualified organization locator")
		}
		digest, err := CanonicalMemberDigestFromPhysicalRow(row)
		if err != nil {
			return NativeLocatorManifestOutput{}, err
		}
		id, ok := row.Columns["graph_fact_locator_hash"].(string)
		if !ok || id == "" || id != digest || seen[id] {
			return NativeLocatorManifestOutput{}, errors.New("locator manifest has duplicate or unhashed locator")
		}
		seen[id] = true
		r := row
		members = append(members, ManifestMemberV8{ManifestKind: "graph_fact_locator", EntryKind: "graph_fact_locator", MemberID: id, ClaimedHash: digest, Row: &r})
	}
	nodes, root, rows, err := nativePlanManifest(in.OrganizationID, "graph_fact_locator", members, in.CreatedAt)
	if err != nil {
		return NativeLocatorManifestOutput{}, err
	}
	return NativeLocatorManifestOutput{RootHash: root.Hash, Nodes: nodes, ImmutableRows: rows, Members: members}, nil
}

var nativePlanRootKinds = []string{"source", "object", "symbol", "edge", "api_property", "graph_fact_locator", "receipt", "structural_projection", "violation"}

func buildNativePlanContent(ctx context.Context, org string, cert oodevidence.ClosureCertificateV8, members []ManifestMemberV8, immutableRows []SpannerRow, verifier *ManifestMemberVerifier, auxiliary []ManifestNodeV8, now time.Time) (oodEvidenceCertificate oodevidence.ClosureCertificateV8, closure ManifestClosureInput, closureRows []SpannerRow, err error) {
	rows, err := normalizeNativeRows(immutableRows)
	if err != nil {
		return cert, closure, nil, err
	}
	byKind := map[string][]ManifestMemberV8{}
	for _, m := range members {
		if m.ManifestKind == "" || m.EntryKind == "" || m.MemberID == "" || !containsNativeKind(m.ManifestKind) {
			return cert, closure, nil, errors.New("native plan member incomplete or unadmitted")
		}
		if m.Row != nil {
			if _, ok := rows[rowIdentity(*m.Row)]; !ok {
				return cert, closure, nil, fmt.Errorf("member %s lacks physical row", m.MemberID)
			}
			var d string
			if m.Row.Table == "OODGraphAPIPropertyFacts" {
				if verifier == nil {
					return cert, closure, nil, errors.New("native API property requires admitted schema verifier")
				}
				d, err = verifier.CanonicalMemberDigestFromPhysicalRow(ctx, *m.Row)
			} else {
				d, err = CanonicalMemberDigestFromPhysicalRow(*m.Row)
			}
			if err != nil || d != m.ClaimedHash {
				return cert, closure, nil, fmt.Errorf("native member %s digest mismatch: %w", m.MemberID, err)
			}
		} else {
			if m.ManifestKind != "source" || m.EntryKind != "source_artifact" {
				return cert, closure, nil, errors.New("only source artifact may be virtual")
			}
			d, e := SourceArtifactExternalEvidenceDigest(m.EvidenceRows)
			if e != nil || d != m.ClaimedHash {
				return cert, closure, nil, fmt.Errorf("source artifact member digest: %w", e)
			}
			for _, r := range m.EvidenceRows {
				rows[rowIdentity(r)] = r
			}
		}
		byKind[m.ManifestKind] = append(byKind[m.ManifestKind], m)
	}
	closure = ManifestClosureInput{OrganizationID: org, MemberVerifier: verifier}
	cert.Roots = map[string]oodevidence.ClosureRoot{}
	for _, kind := range nativePlanRootKinds {
		nodes, root, manifestRows, e := nativePlanManifest(org, kind, byKind[kind], now)
		if e != nil {
			return cert, closure, nil, e
		}
		closure.Nodes = append(closure.Nodes, nodes...)
		closure.Members = append(closure.Members, byKind[kind]...)
		for _, r := range manifestRows {
			rows[rowIdentity(r)] = r
		}
		cert.Roots[kind] = oodevidence.ClosureRoot{Hash: root.Hash, Count: root.TransitiveMemberCount}
	}
	knownNodes := map[string]bool{}
	for _, n := range closure.Nodes {
		knownNodes[n.Hash] = true
	}
	for _, n := range auxiliary {
		if n.OrganizationID != org || n.Hash == "" {
			return cert, closure, nil, errors.New("auxiliary manifest node is incomplete")
		}
		if knownNodes[n.Hash] {
			continue
		}
		knownNodes[n.Hash] = true
		closure.Nodes = append(closure.Nodes, n)
	}
	cert.SourceArtifactCount, cert.RelationshipEvidenceCount = sourceCounts(byKind["source"])
	if cert.SourceArtifactCount+cert.RelationshipEvidenceCount != cert.Roots["source"].Count {
		return cert, closure, nil, errors.New("source members are not closed")
	}
	closureRows = sortedNativeRows(rows)
	cert.ClosureHash, err = oodEvidenceClosureHash(cert)
	if err != nil {
		return cert, closure, nil, err
	}
	closure.ImmutableRows = closureRows
	return cert, closure, closureRows, nil
}

// Alias keeps the content phase visibly distinct from certificate finalization.
func oodEvidenceClosureHash(c oodevidence.ClosureCertificateV8) (string, error) {
	return oodevidence.ClosureHashV8(c)
}

func BuildNativePlanDraft(ctx context.Context, in NativePlanDraftInput) (NativePlanDraft, error) {
	if ctx == nil || in.OrganizationID == "" || in.SnapshotKind == "" || in.CreatedAt.IsZero() || in.CreatedAt.Location() != time.UTC || in.CreatedAt.Nanosecond()%1000 != 0 || in.Certificate.OrganizationID != in.OrganizationID || in.Certificate.SnapshotKind != in.SnapshotKind {
		return NativePlanDraft{}, errors.New("native plan draft binding incomplete")
	}
	cert, _, rows, err := buildNativePlanContent(ctx, in.OrganizationID, in.Certificate, in.Members, in.ImmutableRows, in.MemberVerifier, in.AuxiliaryNodes, in.CreatedAt)
	if err != nil {
		return NativePlanDraft{}, err
	}
	roster, err := CanonicalImmutableRosterBytes(rows)
	if err != nil {
		return NativePlanDraft{}, err
	}
	cloned := CloneManifestClosureInput(ManifestClosureInput{Members: in.Members, ImmutableRows: in.ImmutableRows, MemberVerifier: in.MemberVerifier, Nodes: in.AuxiliaryNodes})
	return NativePlanDraft{Certificate: cert, ImmutableRoster: roster, members: cloned.Members, immutableRows: cloned.ImmutableRows, memberVerifier: cloned.MemberVerifier, auxiliaryNodes: cloned.Nodes, organizationID: in.OrganizationID, snapshotKind: in.SnapshotKind, createdAt: in.CreatedAt}, nil
}

func FinalizeNativePlan(ctx context.Context, draft NativePlanDraft, in NativePlanBuildInput) (NativePlanBuildOutput, error) {
	if draft.organizationID == "" || in.OrganizationID != draft.organizationID || in.SnapshotKind != draft.snapshotKind || !in.CreatedAt.Equal(draft.createdAt) {
		return NativePlanBuildOutput{}, errors.New("native plan finalization does not bind draft")
	}
	issued := draft.Certificate
	issued.MaterializationRunID = in.RunID
	issued.VerificationCertificateID = in.Certificate.VerificationCertificateID
	issued.AttestationAuthorityID = in.Certificate.AttestationAuthorityID
	issued.AttestationRef = in.Certificate.AttestationRef
	issued.AttestationDigest = in.Certificate.AttestationDigest
	issued.AttestationProfile = in.Certificate.AttestationProfile
	issued.VerificationCertificateHash = ""
	if issued.MaterializationRunID == "" || issued.VerificationCertificateID == "" || issued.AttestationAuthorityID == "" || issued.AttestationRef == "" || issued.AttestationDigest == "" || issued.AttestationProfile == "" {
		return NativePlanBuildOutput{}, errors.New("issued successor certificate incomplete")
	}
	content, _, rows, err := buildNativePlanContent(ctx, draft.organizationID, issued, draft.members, draft.immutableRows, draft.memberVerifier, draft.auxiliaryNodes, draft.createdAt)
	if err != nil {
		return NativePlanBuildOutput{}, err
	}
	roster, err := CanonicalImmutableRosterBytes(rows)
	if err != nil || !reflect.DeepEqual(content.Roots, draft.Certificate.Roots) || content.ClosureHash != draft.Certificate.ClosureHash || !reflect.DeepEqual(roster, draft.ImmutableRoster) {
		return NativePlanBuildOutput{}, errors.New("issuer does not bind exact draft content")
	}
	in.Certificate = issued
	in.Members = draft.members
	in.ImmutableRows = draft.immutableRows
	in.MemberVerifier = draft.memberVerifier
	in.AuxiliaryNodes = draft.auxiliaryNodes
	return BuildNativePlan(ctx, in)
}

// BuildNativePlan requires a closed, typed set of source facts and a
// boot-owned attestor. It returns opaque closure and roster proofs but never
// performs a Spanner mutation.
func BuildNativePlan(ctx context.Context, in NativePlanBuildInput) (NativePlanBuildOutput, error) {
	if ctx == nil || in.OrganizationID == "" || in.SnapshotKind == "" || in.SnapshotID == "" || in.RunID == "" {
		return NativePlanBuildOutput{}, errors.New("native plan requires organization, snapshot and run coordinates")
	}
	if in.CreatedAt.IsZero() || in.CreatedAt.Location() != time.UTC || in.CreatedAt.Nanosecond()%1000 != 0 {
		return NativePlanBuildOutput{}, errors.New("native plan requires UTC microsecond creation time")
	}
	if in.Certificate.OrganizationID != in.OrganizationID || in.Certificate.MaterializationRunID != in.RunID || in.Certificate.SnapshotKind != in.SnapshotKind {
		return NativePlanBuildOutput{}, errors.New("certificate does not bind native plan coordinates")
	}
	if in.Certificate.VerificationCertificateID == "" || in.Certificate.AttestationAuthorityID == "" || in.Certificate.AttestationRef == "" || in.Certificate.AttestationDigest == "" || in.Certificate.AttestationProfile == "" {
		return NativePlanBuildOutput{}, errors.New("native plan requires boot-owned certificate attestation coordinates")
	}
	if in.Attestor == nil {
		return NativePlanBuildOutput{}, errors.New("native plan requires boot-owned closure attestor")
	}
	rows, err := normalizeNativeRows(in.ImmutableRows)
	if err != nil {
		return NativePlanBuildOutput{}, err
	}
	byKind := map[string][]ManifestMemberV8{}
	for _, m := range in.Members {
		if m.ManifestKind == "" || m.EntryKind == "" || m.MemberID == "" {
			return NativePlanBuildOutput{}, errors.New("native plan member incomplete")
		}
		if !containsNativeKind(m.ManifestKind) {
			return NativePlanBuildOutput{}, fmt.Errorf("unadmitted manifest kind %q", m.ManifestKind)
		}
		if m.Row != nil {
			if _, ok := rows[rowIdentity(*m.Row)]; !ok {
				return NativePlanBuildOutput{}, fmt.Errorf("member %s lacks physical row", m.MemberID)
			}
		}
		if m.Row == nil && (m.ManifestKind != "source" || m.EntryKind != "source_artifact") {
			return NativePlanBuildOutput{}, errors.New("only source artifact may be virtual")
		}
		if m.Row != nil && m.Row.Table == "OODGraphAPIPropertyFacts" {
			if in.MemberVerifier == nil {
				return NativePlanBuildOutput{}, errors.New("native API property requires admitted schema verifier")
			}
			d, e := in.MemberVerifier.CanonicalMemberDigestFromPhysicalRow(ctx, *m.Row)
			if e != nil || d != m.ClaimedHash {
				return NativePlanBuildOutput{}, fmt.Errorf("API property member digest: %w", e)
			}
		} else if m.Row != nil {
			d, e := CanonicalMemberDigestFromPhysicalRow(*m.Row)
			if e != nil {
				return NativePlanBuildOutput{}, e
			}
			if d != m.ClaimedHash {
				return NativePlanBuildOutput{}, fmt.Errorf("member %s digest mismatch", m.MemberID)
			}
		} else {
			d, e := SourceArtifactExternalEvidenceDigest(m.EvidenceRows)
			if e != nil || d != m.ClaimedHash {
				return NativePlanBuildOutput{}, fmt.Errorf("source artifact member digest: %w", e)
			}
			for _, r := range m.EvidenceRows {
				rows[rowIdentity(r)] = r
			}
		}
		byKind[m.ManifestKind] = append(byKind[m.ManifestKind], m)
	}
	// Every root is present even when its member set is empty. In particular a
	// clean projection carries an empty sealed violation manifest; construction
	// must never invent a violation simply to satisfy topology.

	closure := ManifestClosureInput{OrganizationID: in.OrganizationID, MemberVerifier: in.MemberVerifier}
	cert := in.Certificate
	cert.Roots = map[string]oodevidence.ClosureRoot{}
	for _, kind := range nativePlanRootKinds {
		nodes, n, manifestRows, err := nativePlanManifest(in.OrganizationID, kind, byKind[kind], in.CreatedAt)
		if err != nil {
			return NativePlanBuildOutput{}, err
		}
		closure.Nodes = append(closure.Nodes, nodes...)
		closure.Members = append(closure.Members, byKind[kind]...)
		for _, r := range manifestRows {
			rows[rowIdentity(r)] = r
		}
		cert.Roots[kind] = oodevidence.ClosureRoot{Hash: n.Hash, Count: n.TransitiveMemberCount}
	}
	knownNodes := map[string]bool{}
	for _, n := range closure.Nodes {
		knownNodes[n.Hash] = true
	}
	for _, n := range in.AuxiliaryNodes {
		if n.OrganizationID != in.OrganizationID || n.Hash == "" {
			return NativePlanBuildOutput{}, errors.New("auxiliary manifest node is incomplete")
		}
		if !knownNodes[n.Hash] {
			knownNodes[n.Hash] = true
			closure.Nodes = append(closure.Nodes, n)
		}
	}
	cert.SourceArtifactCount, cert.RelationshipEvidenceCount = sourceCounts(byKind["source"])
	if cert.SourceArtifactCount+cert.RelationshipEvidenceCount != cert.Roots["source"].Count {
		return NativePlanBuildOutput{}, errors.New("source members are not closed source artifacts/relationship evidence")
	}
	closureRows := sortedNativeRows(rows)
	cert.ClosureHash, err = oodevidence.ClosureHashV8(cert)
	if err != nil {
		return NativePlanBuildOutput{}, err
	}
	cert.VerificationCertificateHash, err = oodevidence.CertificateHashV8(cert)
	if err != nil {
		return NativePlanBuildOutput{}, err
	}
	cr, err := nativeCertificateRow(cert, in.CreatedAt)
	if err != nil {
		return NativePlanBuildOutput{}, err
	}
	closure.CertificateRow = &cr
	closureRows = append(closureRows, cr)
	closure.ImmutableRows = closureRows
	reconciler := ManifestClosureReconciler{Input: closure}
	if err := reconciler.VerifyCompleteManifestClosure(ctx, cert); err != nil {
		return NativePlanBuildOutput{}, fmt.Errorf("constructed native closure: %w", err)
	}
	p := nativeMutablePlan(in, cert, closureRows)
	if err := validateSpannerWritePlan(p); err != nil {
		return NativePlanBuildOutput{}, fmt.Errorf("constructed native write plan: %w", err)
	}
	proof, err := oodevidence.VerifyClosureV8(ctx, cert, AttestedManifestClosureAuthority{ManifestClosureReconciler: reconciler, Attestor: in.Attestor})
	if err != nil {
		return NativePlanBuildOutput{}, fmt.Errorf("verify constructed native closure: %w", err)
	}
	canonicalRows, err := CanonicalImmutableRosterBytes(p.ImmutableRows)
	if err != nil {
		return NativePlanBuildOutput{}, err
	}
	roster, err := oodevidence.VerifyPublicationRosterV8(ctx, proof, canonicalRows, reconciler)
	if err != nil {
		return NativePlanBuildOutput{}, fmt.Errorf("verify constructed native roster: %w", err)
	}
	return NativePlanBuildOutput{Plan: p, Certificate: cert, Closure: closure, VerifiedClosure: proof, VerifiedRoster: roster}, nil
}

func containsNativeKind(x string) bool {
	for _, k := range nativePlanRootKinds {
		if x == k {
			return true
		}
	}
	return false
}
func rowIdentity(r SpannerRow) string {
	x, e := BuildImmutableRow(r.Table, r.Columns)
	if e != nil {
		return "!" + r.Table
	}
	return x.Key()
}
func normalizeNativeRows(in []SpannerRow) (map[string]SpannerRow, error) {
	out := map[string]SpannerRow{}
	for _, r := range in {
		x, e := BuildImmutableRow(r.Table, r.Columns)
		if e != nil {
			return nil, e
		}
		rr := x.Row()
		k := x.Key()
		if _, ok := out[k]; ok {
			return nil, errors.New("duplicate native immutable row")
		}
		out[k] = rr
	}
	return out, nil
}
func sortedNativeRows(m map[string]SpannerRow) []SpannerRow {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]SpannerRow, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}
func sourceCounts(ms []ManifestMemberV8) (int64, int64) {
	var a, b int64
	for _, m := range ms {
		if m.EntryKind == "source_artifact" {
			a++
		}
		if m.EntryKind == "relationship_evidence" {
			b++
		}
	}
	return a, b
}

const nativeManifestMaxEntries = 1024

// nativePlanManifest constructs the ordinary bounded tree bottom-up.  Ordinary
// manifests are not sparse membership tries: leaves and internal nodes use the
// owner-pinned v1 profiles, each node has at most 1024 entries, and a parent
// references only its children's independently measured preimages.
func nativePlanManifest(org, kind string, members []ManifestMemberV8, now time.Time) ([]ManifestNodeV8, ManifestNodeV8, []SpannerRow, error) {
	sort.Slice(members, func(i, j int) bool {
		if members[i].EntryKind != members[j].EntryKind {
			return members[i].EntryKind < members[j].EntryKind
		}
		return members[i].MemberID < members[j].MemberID
	})
	leaves := make([]ManifestNodeV8, 0, (len(members)+nativeManifestMaxEntries-1)/nativeManifestMaxEntries)
	for start := 0; start < len(members) || (len(members) == 0 && start == 0); start += nativeManifestMaxEntries {
		end := start + nativeManifestMaxEntries
		if end > len(members) {
			end = len(members)
		}
		n, err := nativeLeafNode(org, kind, members[start:end])
		if err != nil {
			return nil, ManifestNodeV8{}, nil, err
		}
		leaves = append(leaves, n)
		if len(members) == 0 {
			break
		}
	}
	nodes := append([]ManifestNodeV8(nil), leaves...)
	level := int64(1)
	current := leaves
	for len(current) > 1 {
		next := make([]ManifestNodeV8, 0, (len(current)+nativeManifestMaxEntries-1)/nativeManifestMaxEntries)
		for start := 0; start < len(current); start += nativeManifestMaxEntries {
			end := start + nativeManifestMaxEntries
			if end > len(current) {
				end = len(current)
			}
			n, err := nativeInternalNode(org, kind, level, current[start:end])
			if err != nil {
				return nil, ManifestNodeV8{}, nil, err
			}
			next = append(next, n)
		}
		nodes = append(nodes, next...)
		current = next
		level++
	}
	rows := make([]SpannerRow, 0, len(nodes)*2)
	for i := range nodes {
		nr, entries, err := nativeManifestPhysicalRows(nodes[i], now)
		if err != nil {
			return nil, ManifestNodeV8{}, nil, err
		}
		nodes[i].Row = &nr
		for j := range entries {
			nodes[i].Entries[j].Row = &entries[j]
		}
		rows = append(rows, nr)
		rows = append(rows, entries...)
	}
	return nodes, nodes[len(nodes)-1], rows, nil
}

func nativeLeafNode(org, kind string, members []ManifestMemberV8) (ManifestNodeV8, error) {
	entries := make([]ManifestEntryV8, len(members))
	for i, m := range members {
		entries[i] = ManifestEntryV8{Ordinal: int64(i), EntryKind: m.EntryKind, MemberID: m.MemberID, MemberHash: m.ClaimedHash}
	}
	n := ManifestNodeV8{OrganizationID: org, Kind: kind, NodeKind: "leaf", HashAlgorithm: "SHA-256", CanonicalizationProfile: "ood_graph_manifest_node_v1", EntryCount: int64(len(entries)), TransitiveMemberCount: int64(len(entries)), Sealed: true, Entries: entries}
	return nativeFinalizeOrdinaryNode(n, nil)
}

func nativeInternalNode(org, kind string, level int64, children []ManifestNodeV8) (ManifestNodeV8, error) {
	if len(children) < 2 {
		return ManifestNodeV8{}, errors.New("one-child internal manifest")
	}
	entries := make([]ManifestEntryV8, len(children))
	var total int64
	for i, child := range children {
		entries[i] = ManifestEntryV8{Ordinal: int64(i), EntryKind: "child_manifest", ChildHash: child.Hash}
		total += child.TransitiveMemberCount
	}
	n := ManifestNodeV8{OrganizationID: org, Kind: kind, NodeKind: "internal", Level: level, HashAlgorithm: "SHA-256", CanonicalizationProfile: "ood_graph_manifest_node_v1", EntryCount: int64(len(entries)), TransitiveMemberCount: total, Sealed: true, Entries: entries}
	byHash := make(map[string]ManifestNodeV8, len(children))
	for _, child := range children {
		byHash[child.Hash] = child
	}
	return nativeFinalizeOrdinaryNode(n, byHash)
}

func nativeFinalizeOrdinaryNode(n ManifestNodeV8, children map[string]ManifestNodeV8) (ManifestNodeV8, error) {
	for i := range n.Entries {
		b, err := oodcanon.EncodeNestedRecord(nativeOrdinaryEntryFields(n.NodeKind), nativeOrdinaryEntryValues(n.Entries[i], children))
		if err != nil {
			return ManifestNodeV8{}, err
		}
		n.Entries[i].CanonicalByteCount = int64(len(b))
	}
	// INT64 self-count has a fixed eight-byte encoding, so measuring the
	// provisional zero count then replacing it is exactly the owner's rule.
	n.CanonicalByteCount = 0
	b, err := oodcanon.Encode(nativeOrdinaryProfile(n.NodeKind), ordinaryNodeRecord(n, children))
	if err != nil {
		return ManifestNodeV8{}, err
	}
	n.CanonicalByteCount = int64(len(b))
	n.Hash, err = oodcanon.DigestHexOf(nativeOrdinaryProfile(n.NodeKind), ordinaryNodeRecord(n, children))
	if err != nil {
		return ManifestNodeV8{}, err
	}
	return n, nil
}

func nativeOrdinaryProfile(kind string) oodcanon.Profile {
	if kind == "leaf" {
		return oodcanon.ManifestLeafV1()
	}
	return oodcanon.ManifestInternalV1()
}
func nativeOrdinaryEntryFields(kind string) []oodcanon.Field {
	p := nativeOrdinaryProfile(kind)
	return p.Fields[len(p.Fields)-1].Element.Nested
}
func nativeOrdinaryEntryValues(e ManifestEntryV8, children map[string]ManifestNodeV8) []oodcanon.NamedValue {
	if e.EntryKind != "child_manifest" {
		return []oodcanon.NamedValue{{Name: "entry_ordinal", Value: oodcanon.I64(e.Ordinal)}, {Name: "entry_kind", Value: oodcanon.String(e.EntryKind)}, {Name: "member_id", Value: oodcanon.String(e.MemberID)}, {Name: "member_hash", Value: mustNativeDigest(e.MemberHash)}, {Name: "child_manifest_node_hash", Value: oodcanon.NullValue(oodcanon.SHA256)}, {Name: "canonical_entry_byte_count", Value: oodcanon.I64(0)}}
	}
	c := children[e.ChildHash]
	return []oodcanon.NamedValue{{Name: "entry_ordinal", Value: oodcanon.I64(e.Ordinal)}, {Name: "entry_kind", Value: oodcanon.String("child_manifest")}, {Name: "member_id", Value: oodcanon.NullValue(oodcanon.UTF8)}, {Name: "member_hash", Value: oodcanon.NullValue(oodcanon.SHA256)}, {Name: "child_manifest_node_hash", Value: mustNativeDigest(e.ChildHash)}, {Name: "child_transitive_member_count", Value: oodcanon.I64(c.TransitiveMemberCount)}, {Name: "child_canonical_byte_count", Value: oodcanon.I64(c.CanonicalByteCount)}, {Name: "canonical_entry_byte_count", Value: oodcanon.I64(0)}}
}

func nativeManifestPhysicalRows(n ManifestNodeV8, now time.Time) (SpannerRow, []SpannerRow, error) {
	nr, err := fullNativeRow("OODGraphManifestNodes", map[string]interface{}{"organization_id": n.OrganizationID, "manifest_node_hash": n.Hash, "manifest_kind": n.Kind, "node_kind": n.NodeKind, "node_level": n.Level, "route_prefix_bytes": nil, "route_prefix_nibble_length": nil, "entry_count": n.EntryCount, "transitive_member_count": n.TransitiveMemberCount, "canonical_byte_count": n.CanonicalByteCount, "hash_algorithm": n.HashAlgorithm, "canonicalization_profile": n.CanonicalizationProfile, "sealed": true, "created_at": now})
	if err != nil {
		return SpannerRow{}, nil, err
	}
	rows := make([]SpannerRow, 0, len(n.Entries))
	for _, e := range n.Entries {
		memberID, memberHash, child := interface{}(nil), interface{}(nil), interface{}(nil)
		if e.EntryKind == "child_manifest" {
			child = e.ChildHash
		} else {
			memberID = e.MemberID
			memberHash = e.MemberHash
		}
		r, err := fullNativeRow("OODGraphManifestEntries", map[string]interface{}{"organization_id": n.OrganizationID, "manifest_node_hash": n.Hash, "entry_ordinal": e.Ordinal, "branch_nibble": nil, "entry_kind": e.EntryKind, "member_id": memberID, "member_hash": memberHash, "child_manifest_node_hash": child, "canonical_entry_byte_count": e.CanonicalByteCount, "created_at": now})
		if err != nil {
			return SpannerRow{}, nil, err
		}
		rows = append(rows, r)
	}
	return nr, rows, nil
}
func mustNativeDigest(s string) oodcanon.Value {
	v, e := oodcanon.DigestHex(s)
	if e != nil {
		panic(e)
	}
	return v
}
func fullNativeRow(table string, values map[string]interface{}) (SpannerRow, error) {
	_, cols, e := ImmutablePhysicalColumnNames(table)
	if e != nil {
		return SpannerRow{}, e
	}
	if len(values) != len(cols) {
		return SpannerRow{}, errors.New("native row incomplete")
	}
	x, e := BuildImmutableRow(table, values)
	if e != nil {
		return SpannerRow{}, e
	}
	return x.Row(), nil
}

func nativeCertificateRow(c oodevidence.ClosureCertificateV8, now time.Time) (SpannerRow, error) {
	_, cols, e := ImmutablePhysicalColumnNames("OODGraphClosureVerificationCertificates")
	if e != nil {
		return SpannerRow{}, e
	}
	m := map[string]interface{}{}
	for _, k := range cols {
		m[k] = ""
	}
	m["organization_id"] = c.OrganizationID
	m["verification_certificate_id"] = c.VerificationCertificateID
	m["verification_certificate_hash"] = c.VerificationCertificateHash
	m["materialization_run_id"] = c.MaterializationRunID
	m["snapshot_kind"] = c.SnapshotKind
	m["source_set_hash"] = c.SourceSetHash
	m["closure_hash"] = c.ClosureHash
	m["verification_attestation_authority_id"] = c.AttestationAuthorityID
	m["verification_attestation_ref"] = c.AttestationRef
	m["verification_attestation_digest"] = c.AttestationDigest
	m["verification_attestation_profile"] = c.AttestationProfile
	m["created_at"] = now
	for _, k := range nativePlanRootKinds {
		r := c.Roots[k]
		if k == "source" {
			m["source_manifest_root_hash"] = r.Hash
			m["source_artifact_count"] = c.SourceArtifactCount
			m["relationship_evidence_count"] = c.RelationshipEvidenceCount
		} else {
			m[k+"_manifest_root_hash"] = r.Hash
			m[k+"_count"] = r.Count
		}
	}
	for _, x := range []struct {
		k string
		v interface{}
	}{{"relationship_identity_set_hash", c.RelationshipIdentitySetHash}, {"source_authority_identity_set_hash", c.SourceAuthorityIdentitySetHash}, {"source_authority_identity_count", c.SourceAuthorityIdentityCount}, {"completeness_identity_set_hash", c.CompletenessIdentitySetHash}, {"completeness_identity_count", c.CompletenessIdentityCount}, {"permission_policy_identity_set_hash", c.PermissionPolicyIdentitySetHash}, {"permission_policy_identity_count", c.PermissionPolicyIdentityCount}, {"archive_binding_identity_set_hash", c.ArchiveBindingIdentitySetHash}, {"archive_binding_identity_count", c.ArchiveBindingIdentityCount}, {"profile_identity_set_hash", c.ProfileIdentitySetHash}, {"profile_identity_count", c.ProfileIdentityCount}, {"external_source_receipt_eligibility_set_hash", c.ExternalSourceReceiptEligibilitySetHash}, {"external_source_receipt_eligibility_count", c.ExternalSourceReceiptEligibilityCount}, {"materialization_profile_id", c.MaterializationProfileID}, {"materialization_profile_version", c.MaterializationProfileVersion}, {"materialization_profile_digest", c.MaterializationProfileDigest}, {"publication_budget_profile_ref", c.PublicationBudgetProfileRef}, {"publication_budget_profile_digest", c.PublicationBudgetProfileDigest}, {"manifest_hash_algorithm", c.ManifestHashAlgorithm}, {"manifest_hash_profile", c.ManifestHashProfile}, {"manifest_hash_contract_digest", c.ManifestHashContractDigest}, {"closure_hash_algorithm", c.ClosureHashAlgorithm}, {"closure_hash_profile", c.ClosureHashProfile}, {"closure_hash_contract_digest", c.ClosureHashContractDigest}, {"verifier_capability_name", c.VerifierCapabilityName}, {"verifier_capability_version", c.VerifierCapabilityVersion}, {"verifier_capability_digest", c.VerifierCapabilityDigest}, {"verification_policy_ref", c.VerificationPolicyRef}, {"verification_policy_digest", c.VerificationPolicyDigest}, {"verification_result", "verified"}} {
		m[x.k] = x.v
	}
	return fullNativeRow("OODGraphClosureVerificationCertificates", m)
}

func nativeMutablePlan(in NativePlanBuildInput, c oodevidence.ClosureCertificateV8, rows []SpannerRow) SpannerWritePlan {
	p := SpannerWritePlan{OrganizationID: in.OrganizationID, SnapshotKind: in.SnapshotKind, SnapshotID: in.SnapshotID, RunID: in.RunID, ClosureHash: c.ClosureHash, ImmutableRows: rows}
	p.Snapshot = nativeMutable(TableSnapshots, []string{"organization_id", "graph_snapshot_id"}, SnapshotColumns())
	p.Run = nativeMutable(TableRuns, []string{"organization_id", "materialization_run_id"}, MaterializationRunColumns())
	p.Head = nativeMutable(TableSnapshotHeads, []string{"organization_id", "snapshot_kind"}, SnapshotHeadColumns())
	p.Publication = nativeMutable(TablePublicationState, []string{"organization_id"}, PublicationStateColumns())
	for _, r := range []*SpannerRow{&p.Snapshot, &p.Run, &p.Head, &p.Publication} {
		r.Columns["organization_id"] = in.OrganizationID
	}
	roots := c.Roots
	set := func(m map[string]interface{}) {
		m["source_set_hash"] = c.SourceSetHash
		m["source_manifest_root_hash"] = roots["source"].Hash
		m["source_artifact_count"] = c.SourceArtifactCount
		m["relationship_evidence_count"] = c.RelationshipEvidenceCount
		m["materialization_profile_id"] = c.MaterializationProfileID
		m["materialization_profile_version"] = c.MaterializationProfileVersion
		m["materialization_profile_digest"] = c.MaterializationProfileDigest
		for _, k := range nativePlanRootKinds {
			if k != "source" {
				m[k+"_manifest_root_hash"] = roots[k].Hash
				m[k+"_count"] = roots[k].Count
			}
		}
	}
	set(p.Snapshot.Columns)
	p.Head.Columns["source_set_hash"] = c.SourceSetHash
	p.Head.Columns["source_manifest_root_hash"] = roots["source"].Hash
	p.Head.Columns["source_artifact_count"] = c.SourceArtifactCount
	p.Head.Columns["relationship_evidence_count"] = c.RelationshipEvidenceCount
	p.Head.Columns["materialization_profile_id"] = c.MaterializationProfileID
	p.Head.Columns["materialization_profile_version"] = c.MaterializationProfileVersion
	p.Head.Columns["materialization_profile_digest"] = c.MaterializationProfileDigest
	p.Head.Columns["receipt_manifest_root_hash"] = roots["receipt"].Hash
	p.Run.Columns["input_source_set_hash"] = c.SourceSetHash
	p.Run.Columns["input_source_manifest_root_hash"] = roots["source"].Hash
	p.Run.Columns["input_source_count"] = c.SourceArtifactCount
	p.Run.Columns["input_relationship_evidence_count"] = c.RelationshipEvidenceCount
	p.Run.Columns["materialization_profile_id"] = c.MaterializationProfileID
	p.Run.Columns["materialization_profile_version"] = c.MaterializationProfileVersion
	p.Run.Columns["materialization_profile_digest"] = c.MaterializationProfileDigest
	p.Run.Columns["publication_budget_profile_ref"] = c.PublicationBudgetProfileRef
	p.Run.Columns["publication_budget_profile_digest"] = c.PublicationBudgetProfileDigest
	p.Snapshot.Columns["graph_snapshot_id"] = in.SnapshotID
	p.Snapshot.Columns["snapshot_kind"] = in.SnapshotKind
	p.Snapshot.Columns["materialization_run_id"] = in.RunID
	p.Snapshot.Columns["closure_hash"] = c.ClosureHash
	p.Snapshot.Columns["verification_certificate_id"] = c.VerificationCertificateID
	p.Snapshot.Columns["verification_certificate_hash"] = c.VerificationCertificateHash
	p.Run.Columns["materialization_run_id"] = in.RunID
	p.Run.Columns["target_graph_snapshot_id"] = in.SnapshotID
	p.Run.Columns["candidate_closure_hash"] = c.ClosureHash
	p.Run.Columns["candidate_verification_certificate_id"] = c.VerificationCertificateID
	p.Run.Columns["candidate_verification_certificate_hash"] = c.VerificationCertificateHash
	p.Head.Columns["snapshot_kind"] = in.SnapshotKind
	p.Head.Columns["graph_snapshot_id"] = in.SnapshotID
	p.Head.Columns["closure_hash"] = c.ClosureHash
	p.Head.Columns["verification_certificate_id"] = c.VerificationCertificateID
	p.Head.Columns["verification_certificate_hash"] = c.VerificationCertificateHash
	p.Publication.Columns["last_graph_snapshot_id"] = in.SnapshotID
	p.Publication.Columns["last_snapshot_kind"] = in.SnapshotKind
	return p
}
func nativeMutable(table string, keys, cols []string) SpannerRow {
	m := map[string]interface{}{}
	for _, k := range cols {
		m[k] = "native"
		if k == "graph_version" || k == "head_generation" || k == "current_graph_version" || k == "publication_generation" || k == "published_head_generation" || k == "published_org_publication_generation" || k == "input_source_count" || k == "input_relationship_evidence_count" || k == "object_count" || k == "symbol_count" || k == "edge_count" || k == "violation_count" || k == "source_artifact_count" || k == "relationship_evidence_count" || len(k) > 6 && k[len(k)-6:] == "_count" {
			m[k] = int64(1)
		}
		if k == "predecessor_graph_snapshot_id" || k == "predecessor_snapshot_envelope_hash" || k == "predecessor_org_publication_state_hash" || k == "compared_predecessor_graph_snapshot_id" || k == "compared_predecessor_closure_hash" {
			m[k] = nil
		}
	}
	return SpannerRow{Table: table, KeyColumns: keys, Columns: m}
}
