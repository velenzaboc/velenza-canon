package providerplan

import (
	"context"
	"fmt"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

// DocumentationFactorySourcePackageOODPlan is the sealed physical successor
// plan and the locator-byte proofs consumed by the materializer.
type DocumentationFactorySourcePackageOODPlan struct {
	Native                oodpublication.NativePlanBuildOutput
	VerifiedClosure       oodevidence.VerifiedClosureV8
	VerifiedRoster        oodevidence.VerifiedPublicationRosterV8
	LocatorProofs         []oodevidence.VerifiedLocatorV8
	EvidenceLocatorProofs []oodevidence.VerifiedGraphFactLocatorV8
	RoleProofs            []oodevidence.VerifiedAPIElementRoleV8
}

type DocumentationFactoryOODArchivedCanonicalBytes interface {
	ReadArchivedCanonicalBytes(context.Context, oodevidence.ReceiptV8) ([]byte, error)
}

// BuildDocumentationFactoryProductionSourceOODPlan is intentionally limited
// to the opaque same-read qualified compiler result.  The concrete fact mapper
// is kept beside this entrypoint so no caller can supply rows or authority.
func BuildDocumentationFactoryProductionSourceOODPlan(ctx context.Context, q DocumentationFactoryProductionSourceQualifiedCompilation) (DocumentationFactorySourcePackageOODPlan, error) {
	if ctx == nil || q.preparation == nil || q.preparation.issuer == nil {
		return DocumentationFactorySourcePackageOODPlan{}, fmt.Errorf("qualified OOD successor preparation is absent")
	}
	if err := validateDocumentationFactoryProductionSourceOODCurrentEvidenceRows(q.expected, q.request, q.current); err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, fmt.Errorf("qualified OOD successor current evidence: %w", err)
	}
	if q.current.preparation != q.preparation || q.preparation.certificate.OrganizationID != q.expected.OrganizationID || q.current.Snapshot.OrganizationID != q.expected.OrganizationID {
		return DocumentationFactorySourcePackageOODPlan{}, fmt.Errorf("qualified OOD successor preparation is not the exact validated current closure")
	}
	p, err := ProjectDocumentationFactorySourcePackageOODNative(ctx, q.compiled)
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	in := q.preparation.closure.Input
	coordinateIssuer, ok := q.preparation.attestation.(DocumentationFactoryOODSuccessorCoordinateIssuer)
	if !ok {
		return DocumentationFactorySourcePackageOODPlan{}, fmt.Errorf("qualified OOD successor has no coordinate issuer")
	}
	coordinates, err := coordinateIssuer.IssueSuccessorCoordinates(ctx, successorCoordinateRequest(q.expected.OrganizationID, p))
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, fmt.Errorf("issue successor coordinates: %w", err)
	}
	if err := verifySuccessorCoordinateRoster(p, coordinates); err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	if coordinates.SnapshotID == "" || coordinates.RunID == "" || coordinates.VerificationCertificateID == "" || coordinates.CreatedAt.IsZero() || coordinates.CreatedAt.Location() != time.UTC || coordinates.CreatedAt.Nanosecond()%1000 != 0 {
		return DocumentationFactorySourcePackageOODPlan{}, fmt.Errorf("successor coordinate allocation lacks snapshot/run/certificate/time")
	}
	base := q.preparation.certificate
	// Locator rows are physical successor facts, derived from archived bytes
	// under boot-selected profile authority; never reuse predecessor locators.
	locators, locatorMembers, err := buildDocumentationFactorySourcePackageOODLocatorBindings(ctx, p, in.ImmutableRows, q.preparation.attestation, coordinates.CreatedAt)
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	evidenceProofs, err := verifySuccessorLocatorProofs(ctx, locators, q.current.VerifiedBatches, q.preparation.attestation)
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	locatorRows := make([]oodpublication.SpannerRow, len(locators))
	for i, x := range locators {
		locatorRows[i] = x.LocatorRow
	}
	provenanceAuthority, ok := q.preparation.attestation.(DocumentationFactoryOODNativeProvenanceAuthority)
	if !ok {
		return DocumentationFactorySourcePackageOODPlan{}, fmt.Errorf("admitted native source-fact provenance authority absent")
	}
	provenance, err := verifyDocumentationFactoryNativeProvenance(ctx, q.expected.OrganizationID, p, locators, provenanceAuthority)
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	graphContext := DocumentationFactorySourcePackageOODNativeGraphRowsContext{OrganizationID: q.expected.OrganizationID, CreatedAt: coordinates.CreatedAt, Locators: locators, Symbols: coordinates.Symbols, Documentation: coordinates.Documentation, Relationships: coordinates.Relationships, Provenance: provenance}
	graph, err := BuildDocumentationFactorySourcePackageOODNativeGraphRows(ctx, p, graphContext)
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	documentation, err := BuildDocumentationFactorySourcePackageOODNativeDocumentationProvenanceRows(ctx, p, graphContext, graph)
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	relationshipProofs, err := verifySuccessorRelationshipProofs(ctx, p, graph, locators, provenance, q.current.VerifiedBatches, q.preparation.attestation)
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	roleProofs, err := verifySuccessorRoleProofs(ctx, p, graph, locators, provenance, q.current.VerifiedBatches, q.preparation.attestation)
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	property, err := BuildDocumentationFactorySourcePackageOODNativePropertyRows(ctx, p, graph, DocumentationFactorySourcePackageOODNativePropertyRowsContext{OrganizationID: q.expected.OrganizationID, SnapshotID: coordinates.SnapshotID, RunID: coordinates.RunID, CreatedAt: coordinates.CreatedAt, LocatorBindings: locators, Properties: coordinates.Properties, Gaps: coordinates.Gaps, PropertySchemas: q.preparation.attestation})
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	newRows := append([]oodpublication.SpannerRow{}, locatorRows...)
	newRows = append(newRows, graph.LocatorManifestRows...)
	newRows = append(newRows, graph.Objects...)
	newRows = append(newRows, graph.Symbols...)
	newRows = append(newRows, graph.Edges...)
	newRows = append(newRows, graph.RelationshipEvidence...)
	newRows = append(newRows, documentation.Objects...)
	newRows = append(newRows, documentation.Edges...)
	newRows = append(newRows, documentation.RelationshipEvidence...)
	newRows = append(newRows, documentation.LocatorManifestRows...)
	newRows = append(newRows, property.Properties...)
	newRows = append(newRows, property.Violations...)
	newRows = append(newRows, property.LocatorManifestRows...)
	newMembers := append([]oodpublication.ManifestMemberV8{}, locatorMembers...)
	newMembers = append(newMembers, graph.Members...)
	newMembers = append(newMembers, documentation.Members...)
	newMembers = append(newMembers, property.Members...)
	// Source and receipt members retain the exact qualified receipt/batch rows,
	// not any predecessor graph facts.
	for _, x := range locators {
		pair := []oodpublication.SpannerRow{x.Receipt, x.Batch}
		newRows = append(newRows, pair...)
		newMembers = append(newMembers, oodpublication.ManifestMemberV8{ManifestKind: "source", EntryKind: "source_artifact", MemberID: x.Receipt.Columns["receipt_id"].(string), ClaimedHash: x.SourceArtifactHash, EvidenceRows: pair})
		h, e := oodpublication.CanonicalMemberDigestFromPhysicalRow(x.Receipt)
		if e != nil {
			return DocumentationFactorySourcePackageOODPlan{}, e
		}
		r := x.Receipt
		newMembers = append(newMembers, oodpublication.ManifestMemberV8{ManifestKind: "receipt", EntryKind: "receipt", MemberID: r.Columns["receipt_id"].(string), ClaimedHash: h, Row: &r})
	}
	verifier := oodpublication.ManifestMemberVerifier{PropertyPayloadSchemas: q.preparation.attestation}
	newRows, err = dedupeSuccessorImmutableRows(newRows)
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	newMembers, err = dedupeSuccessorMembers(newMembers)
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	auxNodes := append([]oodpublication.ManifestNodeV8{}, graph.LocatorManifestNodes...)
	auxNodes = append(auxNodes, documentation.LocatorManifestNodes...)
	auxNodes = append(auxNodes, property.LocatorManifestNodes...)
	draft, err := oodpublication.BuildNativePlanDraft(ctx, oodpublication.NativePlanDraftInput{OrganizationID: base.OrganizationID, SnapshotKind: base.SnapshotKind, Certificate: base, Members: newMembers, ImmutableRows: newRows, AuxiliaryNodes: auxNodes, MemberVerifier: &verifier, CreatedAt: coordinates.CreatedAt})
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, fmt.Errorf("draft native successor: %w", err)
	}
	issuance, err := q.preparation.issuer.IssueSuccessorCertificate(ctx, DocumentationFactoryOODSuccessorCertificateRequest{Certificate: draft.Certificate, ImmutableRoster: draft.ImmutableRoster})
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, fmt.Errorf("attest native successor draft: %w", err)
	}
	if err = issuance.validate(); err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, err
	}
	if issuance.SnapshotID != coordinates.SnapshotID || issuance.RunID != coordinates.RunID || issuance.VerificationCertificateID != coordinates.VerificationCertificateID || !issuance.CreatedAt.Equal(coordinates.CreatedAt) {
		return DocumentationFactorySourcePackageOODPlan{}, fmt.Errorf("certificate issuance does not equal allocated successor coordinates")
	}
	native, err := oodpublication.FinalizeNativePlan(ctx, draft, oodpublication.NativePlanBuildInput{OrganizationID: base.OrganizationID, SnapshotKind: base.SnapshotKind, SnapshotID: issuance.SnapshotID, RunID: issuance.RunID, Certificate: oodevidence.ClosureCertificateV8{VerificationCertificateID: issuance.VerificationCertificateID, AttestationAuthorityID: issuance.AttestationAuthorityID, AttestationRef: issuance.AttestationRef, AttestationDigest: issuance.AttestationDigest, AttestationProfile: issuance.AttestationProfile}, Attestor: issuance.Attestor, CreatedAt: issuance.CreatedAt})
	if err != nil {
		return DocumentationFactorySourcePackageOODPlan{}, fmt.Errorf("construct native successor: %w", err)
	}
	return DocumentationFactorySourcePackageOODPlan{Native: native, VerifiedClosure: native.VerifiedClosure, VerifiedRoster: native.VerifiedRoster, LocatorProofs: relationshipProofs, EvidenceLocatorProofs: evidenceProofs, RoleProofs: roleProofs}, nil
}

func verifySuccessorRelationshipProofs(ctx context.Context, p DocumentationFactorySourcePackageOODNativeProjection, graph DocumentationFactorySourcePackageOODNativeGraphRows, locators []DocumentationFactorySourcePackageOODLocatorBinding, provenance DocumentationFactoryVerifiedNativeProvenance, batches []oodevidence.VerifiedBatchV8, authority interface{}) ([]oodevidence.VerifiedLocatorV8, error) {
	roles, ok := authority.(oodevidence.APIElementRoleManifestDerivationAuthority)
	if !ok {
		return nil, fmt.Errorf("API role-manifest authority absent")
	}
	eligibility, ok := authority.(oodevidence.ProfileEligibilityAuthority)
	if !ok {
		return nil, fmt.Errorf("relationship eligibility authority absent")
	}
	archive, ok := authority.(DocumentationFactoryOODArchivedCanonicalBytes)
	if !ok {
		return nil, fmt.Errorf("archive authority absent")
	}
	loc := map[string]DocumentationFactorySourcePackageOODLocatorBinding{}
	for _, x := range locators {
		loc[x.NativeLocatorID] = x
	}
	batch := map[string]oodevidence.VerifiedBatchV8{}
	for _, x := range batches {
		batch[x.FetchBatchID()] = x
	}
	objects := map[string]oodpublication.SpannerRow{}
	for i, s := range p.Symbols {
		if i < len(graph.Objects) {
			objects[s.ID] = graph.Objects[i]
		}
	}
	rels := map[string]oodevidence.RelationshipV8{}
	for _, x := range graph.Relationships {
		rels[x.AuthoringSourcePath] = x
	}
	out := make([]oodevidence.VerifiedLocatorV8, 0, len(p.Relationships))
	for _, x := range p.Relationships {
		r, ok := rels[x.ID]
		if !ok || len(x.LocatorIDs) == 0 {
			return nil, fmt.Errorf("relationship %q proof input absent", x.ID)
		}
		primaryID, primaryErr := provenance.primary(provenance.organizationID, p, "relationship", x.ID)
		if primaryErr != nil {
			return nil, primaryErr
		}
		l, present := loc[primaryID]
		if !present || !nativeLocatorRef(x.LocatorIDs, primaryID) {
			return nil, fmt.Errorf("relationship %q declared primary locator is absent from its claim", x.ID)
		}
		b, ok := batch[l.Receipt.Columns["fetch_batch_id"].(string)]
		if !ok {
			return nil, fmt.Errorf("relationship %q verified batch absent", x.ID)
		}
		receipt, e := oodpublication.ReceiptV8FromPhysicalRow(l.Receipt)
		if e != nil {
			return nil, e
		}
		body, e := archive.ReadArchivedCanonicalBytes(ctx, receipt)
		if e != nil {
			return nil, e
		}
		source, target := objects[x.SourceID], objects[x.TargetID]
		if source.Table == "" || target.Table == "" {
			return nil, fmt.Errorf("relationship %q endpoint objects absent", x.ID)
		}
		sb := oodevidence.APIElementRoleBinding{Role: source.Columns["api_element_role"].(string), LocatorManifestHash: source.Columns["api_element_role_locator_manifest_hash"].(string)}
		tb := oodevidence.APIElementRoleBinding{Role: target.Columns["api_element_role"].(string), LocatorManifestHash: target.Columns["api_element_role_locator_manifest_hash"].(string)}
		v, e := oodevidence.VerifyRelationshipLocatorWithAPIRoleManifestsV8(ctx, r, b, l.Locator, body, sb, tb, roles, eligibility)
		if e != nil {
			return nil, fmt.Errorf("relationship %q: %w", x.ID, e)
		}
		out = append(out, v)
	}
	return out, nil
}

func verifySuccessorLocatorProofs(ctx context.Context, locators []DocumentationFactorySourcePackageOODLocatorBinding, batches []oodevidence.VerifiedBatchV8, authority interface{}) ([]oodevidence.VerifiedGraphFactLocatorV8, error) {
	archive, ok := authority.(DocumentationFactoryOODArchivedCanonicalBytes)
	if !ok {
		return nil, fmt.Errorf("archive resolver absent")
	}
	byID := map[string]oodevidence.VerifiedBatchV8{}
	for _, b := range batches {
		byID[b.FetchBatchID()] = b
	}
	out := make([]oodevidence.VerifiedGraphFactLocatorV8, 0, len(locators))
	for _, x := range locators {
		b, ok := byID[x.Receipt.Columns["fetch_batch_id"].(string)]
		if !ok {
			return nil, fmt.Errorf("locator %q lacks verified batch", x.NativeLocatorID)
		}
		r, e := oodpublication.ReceiptV8FromPhysicalRow(x.Receipt)
		if e != nil {
			return nil, e
		}
		body, e := archive.ReadArchivedCanonicalBytes(ctx, r)
		if e != nil {
			return nil, e
		}
		v, e := oodevidence.VerifyGraphFactLocatorV8(ctx, b, x.Locator, body)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}

func dedupeSuccessorImmutableRows(rows []oodpublication.SpannerRow) ([]oodpublication.SpannerRow, error) {
	m := map[string]oodpublication.SpannerRow{}
	b := map[string]string{}
	for _, r := range rows {
		x, e := oodpublication.BuildImmutableRow(r.Table, r.Columns)
		if e != nil {
			return nil, e
		}
		k := x.Key()
		raw := string(x.Bytes())
		if old, ok := b[k]; ok && old != raw {
			return nil, fmt.Errorf("successor immutable row key %q has conflicting bytes", k)
		}
		b[k] = raw
		m[k] = x.Row()
	}
	out := make([]oodpublication.SpannerRow, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	return out, nil
}

// rowIdentity is the strict physical key used by the local claim-manifest
// deduplicator; it never derives an identity from a mutable map.
func rowIdentity(row oodpublication.SpannerRow) string {
	x, e := oodpublication.BuildImmutableRow(row.Table, row.Columns)
	if e != nil {
		return "!" + row.Table
	}
	return x.Key()
}
func dedupeSuccessorMembers(in []oodpublication.ManifestMemberV8) ([]oodpublication.ManifestMemberV8, error) {
	m := map[string]oodpublication.ManifestMemberV8{}
	for _, x := range in {
		k := x.ManifestKind + "\x00" + x.EntryKind + "\x00" + x.MemberID
		if old, ok := m[k]; ok {
			if old.ClaimedHash != x.ClaimedHash {
				return nil, fmt.Errorf("successor member %q conflicts", k)
			}
			continue
		}
		m[k] = x
	}
	out := make([]oodpublication.ManifestMemberV8, 0, len(m))
	for _, x := range m {
		out = append(out, x)
	}
	return out, nil
}

func successorCoordinateRequest(org string, p DocumentationFactorySourcePackageOODNativeProjection) DocumentationFactoryOODSuccessorCoordinateRequest {
	r := DocumentationFactoryOODSuccessorCoordinateRequest{OrganizationID: org, APIGraphSHA256: p.APIGraphSHA256, SourceMappingSHA256: p.SourceMappingSHA256}
	for _, x := range p.Symbols {
		r.SymbolIDs = append(r.SymbolIDs, x.ID)
		r.DocumentationSymbolIDs = append(r.DocumentationSymbolIDs, x.ID)
	}
	for _, x := range p.Relationships {
		r.RelationshipIDs = append(r.RelationshipIDs, x.ID)
	}
	for _, x := range p.Properties {
		r.PropertyIDs = append(r.PropertyIDs, x.ID)
	}
	for _, x := range p.Gaps {
		r.GapIDs = append(r.GapIDs, x.ID)
	}
	return r
}

// verifySuccessorCoordinateRoster closes the boot allocation response over
// the retained sealed identifiers. A valid UUID for a substituted candidate is
// not an allocation for this compiler result.
func verifySuccessorCoordinateRoster(p DocumentationFactorySourcePackageOODNativeProjection, got DocumentationFactoryOODSuccessorCoordinates) error {
	check := func(kind string, want []string, actual []string) error {
		seen := map[string]bool{}
		for _, id := range actual {
			if id == "" || seen[id] {
				return fmt.Errorf("successor %s coordinate roster has empty/duplicate id", kind)
			}
			seen[id] = true
		}
		if len(want) != len(seen) {
			return fmt.Errorf("successor %s coordinate roster count mismatch", kind)
		}
		for _, id := range want {
			if !seen[id] {
				return fmt.Errorf("successor %s coordinate roster substitutes %q", kind, id)
			}
		}
		return nil
	}
	s := make([]string, len(got.Symbols))
	for i, x := range got.Symbols {
		s[i] = x.NativeSymbolID
	}
	if e := check("symbol", nativeSymbolIDs(p), s); e != nil {
		return e
	}
	d := make([]string, len(got.Documentation))
	for i, x := range got.Documentation {
		d[i] = x.NativeSymbolID
	}
	if e := check("documentation", nativeSymbolIDs(p), d); e != nil {
		return e
	}
	r := make([]string, len(got.Relationships))
	for i, x := range got.Relationships {
		r[i] = x.NativeRelationshipID
	}
	if e := check("relationship", nativeRelationshipIDs(p), r); e != nil {
		return e
	}
	q := make([]string, len(got.Properties))
	for i, x := range got.Properties {
		q[i] = x.NativePropertyID
	}
	if e := check("property", nativePropertyIDs(p), q); e != nil {
		return e
	}
	g := make([]string, len(got.Gaps))
	for i, x := range got.Gaps {
		g[i] = x.NativeGapID
	}
	return check("gap", nativeGapIDs(p), g)
}
func nativeSymbolIDs(p DocumentationFactorySourcePackageOODNativeProjection) []string {
	x := make([]string, len(p.Symbols))
	for i, v := range p.Symbols {
		x[i] = v.ID
	}
	return x
}
func nativeRelationshipIDs(p DocumentationFactorySourcePackageOODNativeProjection) []string {
	x := make([]string, len(p.Relationships))
	for i, v := range p.Relationships {
		x[i] = v.ID
	}
	return x
}
func nativePropertyIDs(p DocumentationFactorySourcePackageOODNativeProjection) []string {
	x := make([]string, len(p.Properties))
	for i, v := range p.Properties {
		x[i] = v.ID
	}
	return x
}
func nativeGapIDs(p DocumentationFactorySourcePackageOODNativeProjection) []string {
	x := make([]string, len(p.Gaps))
	for i, v := range p.Gaps {
		x[i] = v.ID
	}
	return x
}
