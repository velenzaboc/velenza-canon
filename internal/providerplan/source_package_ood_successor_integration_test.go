package providerplan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/oodapi"
	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodproof"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

// successorIntegrationAuthority is deliberately a narrow boot fixture. It
// embeds the real proof-fixture attestation, then supplies only the separate
// archive/profile/identity/certificate capabilities the successor asks for.
// It never receives candidate graph facts or constructs a plan.
type successorIntegrationAuthority struct {
	sourceProofFixtureAuthority
	archives   map[string][]byte
	manifests  map[string]map[string]bool
	projection DocumentationFactorySourcePackageOODNativeProjection
}

func (a successorIntegrationAuthority) AttestCurrentProviderDocumentationEvidence(_ context.Context, c oodpublication.CurrentSealedClosure, r DocumentationFactoryProductionSourceOODReadRequest, _ oodevidence.VerifiedClosureV8, _ []oodevidence.VerifiedBatchV8, members []DocumentationFactoryProductionSourceOODSpannerMembershipRow) (DocumentationFactoryProductionSourceOODProofAttestation, error) {
	if len(members) != len(r.Request.EvidenceIdentities) {
		return DocumentationFactoryProductionSourceOODProofAttestation{}, fmt.Errorf("fixture membership roster mismatch")
	}
	g := productionSourceOwnerObservation(r.Request)
	g.OrganizationID = r.Expected.OrganizationID
	bindings := make([]DocumentationFactoryProductionSourceOODEvidenceBindingRow, len(members))
	for i, m := range members {
		bindings[i] = DocumentationFactoryProductionSourceOODEvidenceBindingRow{Identity: r.Request.EvidenceIdentities[i], EvidenceIdentitySHA256: m.EvidenceIdentitySHA256, ReceiptID: m.ReceiptID, ReceiptSHA256: m.ReceiptSHA256, FetchBatchID: m.FetchBatchID, FetchBatchCertificateID: c.CertificateID, FetchBatchCertificateSHA256: c.CertificateHash, ArchiveBindingSHA256: m.ArchiveBindingSHA256, RelationshipEvidenceSHA256: sha256Hex([]byte("fixture-relationship/" + m.ReceiptID)), LocatorManifestSHA256: sha256Hex([]byte("fixture-locator/" + m.ReceiptID)), ExternalCurrentValidityReference: "fixture-current", ExternalCurrentValiditySHA256: sha256Hex([]byte("fixture-current"))}
	}
	return DocumentationFactoryProductionSourceOODProofAttestation{CurrentGeneration: g, ExternalCurrentValidityReference: "fixture-current", ExternalCurrentValiditySHA256: sha256Hex([]byte("fixture-current")), Bindings: bindings}, nil
}

func successorFixtureRows(t *testing.T, f oodtestfixture.Fixture) []oodpublication.SpannerRow {
	t.Helper()
	rows := append([]oodpublication.SpannerRow(nil), f.ImmutableRows...)
	var nodeTemplate, entryTemplate oodpublication.SpannerRow
	type receiptMember struct{ id, digest string }
	byBatch := map[string]receiptMember{}
	for _, row := range f.ImmutableRows {
		switch row.Table {
		case "OODGraphManifestNodes":
			if nodeTemplate.Table == "" {
				nodeTemplate = row
			}
		case "OODGraphManifestEntries":
			if entryTemplate.Table == "" {
				entryTemplate = row
			}
		case "OODGraphExternalFetchReceipts":
			byBatch[row.Columns["fetch_batch_id"].(string)] = receiptMember{id: row.Columns["receipt_id"].(string), digest: row.Columns["redacted_transport_evidence_digest"].(string)}
		}
	}
	if nodeTemplate.Table == "" || entryTemplate.Table == "" {
		t.Fatal("fixture lacks manifest templates")
	}
	clone := func(row oodpublication.SpannerRow) oodpublication.SpannerRow {
		out := row
		out.Columns = make(map[string]interface{}, len(row.Columns))
		for k, v := range row.Columns {
			out.Columns[k] = v
		}
		return out
	}
	for _, row := range f.ImmutableRows {
		if row.Table != "OODGraphExternalFetchBatches" {
			continue
		}
		batch, err := oodpublication.BatchV8FromPhysicalRow(row)
		if err != nil {
			t.Fatal(err)
		}
		member := byBatch[batch.FetchBatchID]
		receiptRow := oodpublication.SpannerRow{}
		for _, candidate := range f.ImmutableRows {
			if candidate.Table == "OODGraphExternalFetchReceipts" && candidate.Columns["receipt_id"] == member.id {
				receiptRow = candidate
				break
			}
		}
		receipt, err := oodpublication.ReceiptV8FromPhysicalRow(receiptRow)
		if err != nil {
			t.Fatal(err)
		}
		manifest := successorReceiptManifest(t, receipt)
		root := manifest.NodeHash
		if root != batch.BatchReceiptManifestRootHash {
			t.Fatalf("fixture batch manifest root %q != reconstructed %q", batch.BatchReceiptManifestRootHash, root)
		}
		node, entry := clone(nodeTemplate), clone(entryTemplate)
		node.Columns["manifest_node_hash"], node.Columns["manifest_kind"], node.Columns["node_kind"], node.Columns["node_level"], node.Columns["entry_count"], node.Columns["transitive_member_count"], node.Columns["canonical_byte_count"] = root, "fetch_batch_receipt", "leaf", int64(0), int64(1), int64(1), manifest.CanonicalByteCount
		entry.Columns["manifest_node_hash"], entry.Columns["entry_ordinal"], entry.Columns["entry_kind"], entry.Columns["member_id"], entry.Columns["member_hash"], entry.Columns["child_manifest_node_hash"], entry.Columns["canonical_entry_byte_count"] = root, int64(0), "receipt", member.id, member.digest, nil, manifest.Entries[0].CanonicalEntryByteCount
		rows = append(rows, node, entry)
	}
	return rows
}

func successorFixtureArchives(t *testing.T, f oodtestfixture.Fixture, bodies [][]byte) map[string][]byte {
	t.Helper()
	byHash := make(map[string][]byte, len(bodies))
	for _, body := range bodies {
		byHash[sha256Hex(body)] = body
	}
	out := map[string][]byte{}
	for _, row := range f.ImmutableRows {
		if row.Table != "OODGraphExternalFetchReceipts" {
			continue
		}
		id, _ := row.Columns["receipt_id"].(string)
		hash, _ := row.Columns["source_content_hash"].(string)
		body, ok := byHash[hash]
		if !ok {
			t.Fatalf("fixture receipt %q has no exact compiler body", id)
		}
		out[id] = append([]byte(nil), body...)
	}
	if len(out) != len(bodies) {
		t.Fatalf("fixture archive roster=%d, want compiler bodies=%d", len(out), len(bodies))
	}
	return out
}

func successorFixtureManifestBindings(t *testing.T, f oodtestfixture.Fixture, p DocumentationFactorySourcePackageOODNativeProjection, archives map[string][]byte) map[string]map[string]bool {
	t.Helper()
	byHash := map[string]string{}
	for _, row := range f.ImmutableRows {
		if row.Table == "OODGraphExternalFetchReceipts" {
			byHash[row.Columns["source_content_hash"].(string)] = row.Columns["receipt_id"].(string)
		}
	}
	out := map[string]map[string]bool{}
	for _, l := range p.Locators {
		receiptID := byHash[l.SourceContentSHA256]
		if receiptID == "" || archives[receiptID] == nil || !isLowerSHA256(l.EvidenceManifestSHA256) {
			t.Fatalf("sealed locator %q has no exact receipt/manifest binding", l.ID)
		}
		if out[receiptID] == nil {
			out[receiptID] = map[string]bool{}
		}
		out[receiptID][l.EvidenceManifestSHA256] = true
	}
	return out
}

func successorReceiptManifest(t *testing.T, receipt oodevidence.ReceiptV8) oodevidence.ReceiptManifestNode {
	t.Helper()
	member := &oodevidence.ReceiptManifestMember{EntryOrdinal: 0, ReceiptID: receipt.ReceiptID, MemberHash: receipt.RedactedTransportEvidenceDigest}
	digest, err := oodcanon.DigestHex(member.MemberHash)
	if err != nil {
		t.Fatal(err)
	}
	fields := []oodcanon.NamedValue{{Name: "entry_ordinal", Value: oodcanon.I64(0)}, {Name: "entry_kind", Value: oodcanon.String("receipt")}, {Name: "member_id", Value: oodcanon.String(member.ReceiptID)}, {Name: "member_hash", Value: digest}, {Name: "child_manifest_node_hash", Value: oodcanon.NullValue(oodcanon.SHA256)}, {Name: "canonical_entry_byte_count", Value: oodcanon.I64(0)}}
	encoded, err := oodcanon.EncodeNestedRecord(oodcanon.ManifestLeafV1().Fields[7].Element.Nested, fields)
	if err != nil {
		t.Fatal(err)
	}
	entry := oodevidence.ReceiptManifestEntry{EntryOrdinal: 0, CanonicalEntryByteCount: int64(len(encoded)), Member: member}
	fields[len(fields)-1].Value = oodcanon.I64(entry.CanonicalEntryByteCount)
	value := oodcanon.Value{Type: oodcanon.Record, Presence: oodcanon.Present, Fields: fields}
	record := oodcanon.RecordValue{"manifest_kind": oodcanon.String("fetch_batch_receipt"), "entry_count": oodcanon.I64(1), "transitive_member_count": oodcanon.I64(1), "canonical_byte_count": oodcanon.I64(0), "ordered_entry_tuples": oodcanon.Value{Type: oodcanon.Array, Presence: oodcanon.Present, Elements: []oodcanon.Value{value}}}
	encoded, err = oodcanon.Encode(oodcanon.ManifestLeafV1(), record)
	if err != nil {
		t.Fatal(err)
	}
	node := oodevidence.ReceiptManifestNode{OrganizationID: receipt.OrganizationID, ManifestKind: "fetch_batch_receipt", NodeKind: "leaf", NodeLevel: 0, Sealed: true, EntryCount: 1, TransitiveMemberCount: 1, CanonicalByteCount: int64(len(encoded)), Entries: []oodevidence.ReceiptManifestEntry{entry}}
	node.NodeHash, err = oodevidence.ReceiptManifestNodeHashV8(node)
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func (a successorIntegrationAuthority) ReadArchivedCanonicalBytes(_ context.Context, r oodevidence.ReceiptV8) ([]byte, error) {
	body, ok := a.archives[r.ReceiptID]
	if !ok || oodevidence.VerifyArchivedCanonicalBytes(r, body) != nil {
		return nil, fmt.Errorf("fixture archive receipt substitution")
	}
	return append([]byte(nil), body...), nil
}

func (a successorIntegrationAuthority) ResolveCanonicalRepresentationProfile(_ context.Context, r oodevidence.ReceiptV8) (string, string, error) {
	if _, ok := a.archives[r.ReceiptID]; !ok {
		return "", "", fmt.Errorf("fixture representation receipt substitution")
	}
	return a.fixture.Locator.CanonicalRepresentationProfileRef, a.fixture.Locator.CanonicalRepresentationProfileDigest, nil
}

func (a successorIntegrationAuthority) VerifyEvidenceManifestBinding(_ context.Context, r oodevidence.ReceiptV8, manifestSHA string) error {
	allowed, ok := a.manifests[r.ReceiptID]
	if _, archived := a.archives[r.ReceiptID]; !ok || !archived || !allowed[manifestSHA] {
		return fmt.Errorf("fixture evidence-manifest binding substitution")
	}
	return nil
}

func (a successorIntegrationAuthority) VerifyNativeAPIElementRoleManifests(_ context.Context, r oodevidence.RelationshipV8, _ oodevidence.VerifiedBatchV8, locator oodproof.GraphFactLocator, source, target oodevidence.APIElementRoleBinding) error {
	contract, ok := oodapi.RelationshipContractFor(r.EdgeLabel)
	if !ok || source.Role != contract.SourceRole || target.Role != contract.TargetRole || source.LocatorManifestHash == "" || target.LocatorManifestHash == "" || r.GraphFactLocatorManifestHash == nil || locator.LocatorHash == "" {
		return fmt.Errorf("fixture API role/claim-manifest binding substitution")
	}
	return nil
}

func (a successorIntegrationAuthority) VerifyNativeAPIElementRole(_ context.Context, _ oodevidence.VerifiedBatchV8, locator oodproof.GraphFactLocator, coordinate oodevidence.APIElementSourceCoordinate, binding oodevidence.APIElementRoleBinding) error {
	if binding.Role == "" || binding.LocatorManifestHash == "" || locator.LocatorHash == "" {
		return fmt.Errorf("fixture standalone role binding is incomplete")
	}
	for _, symbol := range a.projection.Symbols {
		if symbol.Role != binding.Role {
			continue
		}
		for _, locatorID := range symbol.LocatorIDs {
			native := a.projection.Locators
			for _, candidate := range native {
				if candidate.ID == locatorID && candidate.SourceContentSHA256 == locator.SourceContentHash && coordinate.StableReference == candidate.SourceRefs[0] {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("fixture standalone role is outside sealed symbol roster")
}

func (a successorIntegrationAuthority) VerifyCurrentAPIElementRoleEligibility(_ context.Context, coordinate oodevidence.APIElementSourceCoordinate, binding oodevidence.APIElementRoleBinding, receipt oodevidence.ReceiptV8, batch oodevidence.BatchV8) error {
	if receipt.FetchBatchID != batch.FetchBatchID || receipt.SourceAuthorityID != coordinate.AuthorityID || receipt.SourceRefKind != coordinate.RefKind || receipt.SourceStableReference != coordinate.StableReference || receipt.VersionCoordinate != coordinate.VersionCoordinate {
		return fmt.Errorf("fixture standalone role currentness is outside selected receipt/batch")
	}
	for _, symbol := range a.projection.Symbols {
		if symbol.Role != binding.Role {
			continue
		}
		for _, locatorID := range symbol.LocatorIDs {
			for _, locator := range a.projection.Locators {
				if locator.ID == locatorID && locator.SourceContentSHA256 == receipt.SourceContentHash && len(locator.SourceRefs) != 0 && locator.SourceRefs[0] == coordinate.StableReference {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("fixture standalone role currentness is outside sealed symbol roster")
}

// ResolveAndVerifyNativePrimaryProvenance is the test-owned admitted source
// fact facet. It binds selections to the exact sealed graph/mapping hashes
// and independently chooses the lexicographically smallest sealed locator ID
// for each claim; coordinates never select factual provenance.
func (a successorIntegrationAuthority) ResolveAndVerifyNativePrimaryProvenance(_ context.Context, r DocumentationFactoryOODNativeProvenanceRequest) ([]DocumentationFactoryNativePrimaryProvenance, error) {
	if r.OrganizationID != a.fixture.Certificate.OrganizationID || r.APIGraphSHA256 != a.projection.APIGraphSHA256 || r.SourceMappingSHA256 != a.projection.SourceMappingSHA256 {
		return nil, fmt.Errorf("fixture primary provenance request is outside sealed graph binding")
	}
	wantClaims := map[string][]string{}
	for _, symbol := range a.projection.Symbols {
		wantClaims["symbol\x00"+symbol.ID] = append([]string(nil), symbol.LocatorIDs...)
	}
	for _, relationship := range a.projection.Relationships {
		wantClaims["relationship\x00"+relationship.ID] = append([]string(nil), relationship.LocatorIDs...)
	}
	if len(r.Claims) != len(wantClaims) {
		return nil, fmt.Errorf("fixture primary provenance claim roster is not the sealed roster")
	}
	projectionLocators := map[string]DocumentationFactoryNativeEvidenceLocator{}
	for _, locator := range a.projection.Locators {
		projectionLocators[locator.ID] = locator
	}
	receiptsByContent := map[string]oodevidence.ReceiptV8{}
	for _, row := range a.fixture.ImmutableRows {
		if row.Table != "OODGraphExternalFetchReceipts" {
			continue
		}
		receipt, err := oodpublication.ReceiptV8FromPhysicalRow(row)
		if err != nil {
			return nil, fmt.Errorf("fixture primary provenance receipt: %w", err)
		}
		receiptsByContent[receipt.SourceContentHash] = receipt
	}
	qualified := map[string]DocumentationFactoryNativeProvenanceLocator{}
	for _, x := range r.Locators {
		locator, exists := projectionLocators[x.NativeLocatorID]
		receipt, receiptOK := receiptsByContent[locator.SourceContentSHA256]
		if x.NativeLocatorID == "" || qualified[x.NativeLocatorID].NativeLocatorID != "" || !exists || !receiptOK || x.ReceiptID != receipt.ReceiptID || x.ReceiptDigest != receipt.RedactedTransportEvidenceDigest || x.EvidenceIdentityHash != receipt.EvidenceIdentityHash || x.GraphFactLocatorHash == "" {
			return nil, fmt.Errorf("fixture primary provenance locator roster is malformed")
		}
		qualified[x.NativeLocatorID] = x
	}
	if len(qualified) != len(projectionLocators) {
		return nil, fmt.Errorf("fixture primary provenance locator roster is not the sealed roster")
	}
	out := make([]DocumentationFactoryNativePrimaryProvenance, 0, len(r.Claims))
	for _, claim := range r.Claims {
		ids := append([]string(nil), claim.LocatorIDs...)
		claimKey := claim.Kind + "\x00" + claim.NativeClaimID
		wantIDs, exists := wantClaims[claimKey]
		if (claim.Kind != "symbol" && claim.Kind != "relationship") || claim.NativeClaimID == "" || len(ids) == 0 || !exists {
			return nil, fmt.Errorf("fixture primary provenance claim is malformed")
		}
		sort.Strings(ids)
		sortedWant := append([]string(nil), wantIDs...)
		sort.Strings(sortedWant)
		if len(ids) != len(sortedWant) {
			return nil, fmt.Errorf("fixture primary provenance claim locator count is substituted")
		}
		for i := range ids {
			if ids[i] != sortedWant[i] {
				return nil, fmt.Errorf("fixture primary provenance claim locator is substituted")
			}
		}
		selected, ok := qualified[ids[0]]
		if !ok {
			return nil, fmt.Errorf("fixture primary provenance selection is unqualified")
		}
		selection := DocumentationFactoryNativePrimaryProvenance{Kind: claim.Kind, NativeClaimID: claim.NativeClaimID, DocumentationFactoryNativeProvenanceLocator: selected}
		if claim.Kind == "symbol" {
			selection.Documentation = DocumentationFactoryNativeDocumentationProvenance{
				DocumentObjectClass:          "external_reference_doc",
				DocSectionPath:               "/documentation/" + claim.NativeClaimID,
				DocumentsAuthoringSourcePath: "documentation/" + claim.NativeClaimID,
			}
		}
		out = append(out, selection)
	}
	return out, nil
}

func (a successorIntegrationAuthority) VerifyCurrentRelationshipEligibility(_ context.Context, r oodevidence.RelationshipV8, receipt oodevidence.ReceiptV8, batch oodevidence.BatchV8) error {
	if r.OrganizationID != receipt.OrganizationID || receipt.FetchBatchID != batch.FetchBatchID {
		return fmt.Errorf("fixture relationship is outside selected receipt/batch")
	}
	return nil
}

func (a successorIntegrationAuthority) IssueSuccessorCoordinates(_ context.Context, r DocumentationFactoryOODSuccessorCoordinateRequest) (DocumentationFactoryOODSuccessorCoordinates, error) {
	if r.OrganizationID == "" || r.APIGraphSHA256 == "" || r.SourceMappingSHA256 == "" {
		return DocumentationFactoryOODSuccessorCoordinates{}, fmt.Errorf("fixture successor coordinate request incomplete")
	}
	id := func(kind, native string) string {
		return uuid.NewSHA1(uuid.NameSpaceURL, []byte("successor-integration/"+kind+"/"+native)).String()
	}
	digest := func(kind, native string) string {
		return sha256Hex([]byte("successor-integration/" + kind + "/" + native))
	}
	out := DocumentationFactoryOODSuccessorCoordinates{
		SnapshotID: id("snapshot", "allocated"), RunID: id("run", "allocated"), VerificationCertificateID: id("certificate", "allocated"),
		CreatedAt: time.Date(2026, time.November, 2, 13, 0, 0, 123000000, time.UTC),
	}
	symbols := map[string]DocumentationFactoryNativeAPISymbol{}
	for _, x := range a.projection.Symbols {
		symbols[x.ID] = x
	}
	for _, native := range r.SymbolIDs {
		s := symbols[native]
		if s.ID == "" || len(s.LocatorIDs) == 0 {
			return DocumentationFactoryOODSuccessorCoordinates{}, fmt.Errorf("fixture symbol allocation %q is outside sealed projection", native)
		}
		section, address := "/"+native, "api://successor/"+native
		out.Symbols = append(out.Symbols, DocumentationFactoryNativeSymbolIdentity{NativeSymbolID: native, GraphObjectID: id("object", native), SymbolID: id("symbol", native), SectionPath: section, GraphAddress: address})
	}
	for _, native := range r.DocumentationSymbolIDs {
		if symbols[native].ID == "" {
			return DocumentationFactoryOODSuccessorCoordinates{}, fmt.Errorf("fixture documentation allocation %q is outside sealed projection", native)
		}
		out.Documentation = append(out.Documentation, DocumentationFactoryNativeDocumentationIdentity{NativeSymbolID: native, DocGraphObjectID: id("documentation-object", native), DocGraphAddress: "documentation://successor/" + native, DocumentsGraphEdgeID: id("documentation-edge", native)})
	}
	for _, native := range r.RelationshipIDs {
		var relation DocumentationFactoryNativeAPIRelationship
		for _, x := range a.projection.Relationships {
			if x.ID == native {
				relation = x
				break
			}
		}
		if relation.ID == "" || len(relation.LocatorIDs) == 0 {
			return DocumentationFactoryOODSuccessorCoordinates{}, fmt.Errorf("fixture relationship allocation %q is outside sealed projection", native)
		}
		out.Relationships = append(out.Relationships, DocumentationFactoryNativeRelationshipIdentity{NativeRelationshipID: native, GraphEdgeID: id("edge", native)})
	}
	for _, x := range a.projection.Properties {
		object := id("object", x.SubjectID)
		out.Properties = append(out.Properties, DocumentationFactoryNativePropertyIdentity{NativePropertyID: x.ID, SubjectKind: x.SubjectKind, NativeSubjectID: x.SubjectID, GraphObjectID: object, PropertyFamily: x.Family, PropertySchemaArtifactID: a.fixture.PropertySchema.ArtifactID, PropertySchemaVersion: a.fixture.PropertySchema.Version, PropertySchemaDigest: a.fixture.PropertySchema.Digest, PropertyPayloadProfile: a.fixture.PropertySchema.Profile, ExtractorProfileID: id("extractor", x.ID), ExtractorProfileVersion: "v1", ExtractorProfileDigest: digest("extractor", x.ID), EvidenceAuthorityClass: "documentation", DeletionDomainID: a.fixture.Receipt.EvidenceArchiveDeletionDomainID})
	}
	for _, x := range a.projection.Gaps {
		out.Gaps = append(out.Gaps, DocumentationFactoryNativeGapIdentity{NativeGapID: x.ID, ViolationID: id("violation", x.ID), ViolationCode: "native_gap_unsupported", Severity: "warning", Status: "active", VisibilityScope: "organization", NativeSubjectID: x.BlockedSubjectID, GraphObjectID: id("object", x.BlockedSubjectID), GapClass: x.GapClass, BlockedSubjectKind: x.BlockedSubjectKind, BlockedSubjectID: x.BlockedSubjectID, BlockedClaimKind: x.BlockedClaimKind, BlockedClaimID: x.BlockedClaimID, Disposition: x.Disposition})
	}
	return out, nil
}

func (a successorIntegrationAuthority) IssueSuccessorCertificate(_ context.Context, r DocumentationFactoryOODSuccessorCertificateRequest) (DocumentationFactoryOODSuccessorCertificateIssuance, error) {
	if err := r.validate(); err != nil {
		return DocumentationFactoryOODSuccessorCertificateIssuance{}, err
	}
	key := r.Certificate.ClosureHash
	return DocumentationFactoryOODSuccessorCertificateIssuance{SnapshotID: uuid.NewSHA1(uuid.NameSpaceURL, []byte("successor-integration/snapshot/allocated")).String(), RunID: uuid.NewSHA1(uuid.NameSpaceURL, []byte("successor-integration/run/allocated")).String(), VerificationCertificateID: uuid.NewSHA1(uuid.NameSpaceURL, []byte("successor-integration/certificate/allocated")).String(), AttestationAuthorityID: uuid.NewSHA1(uuid.NameSpaceURL, []byte("successor-attestor")).String(), AttestationRef: "fixture/successor", AttestationDigest: sha256Hex([]byte("successor-attestation/" + key)), AttestationProfile: "fixture/v1", Attestor: a.fixture.Attestor, CreatedAt: time.Date(2026, time.November, 2, 13, 0, 0, 123000000, time.UTC)}, nil
}

// This test begins at the actual four-stage source-package compiler.  It is
// intentionally not a hand-built DocumentationFactorySourceCompileResult: the
// native graph projection must come from bytes retained by the sealed compiler
// result before a protected OOD current read may attach successor evidence.
func TestSourcePackageSuccessorUsesCompilerRetainedNativeProjection(t *testing.T) {
	fixture := newSourcePackageCompilerTestFixture(t, "successor_fixture")
	bundle := testCloudCandidateBundle(t, fixture.manifestPath)
	sealCloudCandidateBundleIntoTestScaffold(t, fixture.manifestPath, bundle)

	compiled, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		sourcePackageCompilerTestDependencies(t),
	)
	if err != nil {
		t.Fatalf("compile sealed native source package: %v", err)
	}
	projection, err := ProjectDocumentationFactorySourcePackageOODNative(context.Background(), compiled)
	if err != nil {
		t.Fatalf("project compiler-retained native graph: %v", err)
	}
	if projection.APIGraphSHA256 == "" || projection.SourceMappingSHA256 == "" || len(projection.Symbols) == 0 || len(projection.Relationships) == 0 || len(projection.Locators) == 0 {
		t.Fatalf("compiler retained incomplete native projection: %#v", projection)
	}
}

// This is the qualification half of the successor path.  It invokes the
// protected launcher composition (real strong Spanner reader, current-reader
// validation, per-call capture, and production compiler flow) while using the
// deterministic factory runner only for the four source-package stages.
func TestSourcePackageSuccessorCapturesQualifiedCompilationFromProtectedSameRead(t *testing.T) {
	fixture := newSourcePackageCompilerTestFixture(t, "fixture_provider")
	bundle := testCloudCandidateBundle(t, fixture.manifestPath)
	sealCloudCandidateBundleIntoTestScaffold(t, fixture.manifestPath, bundle)
	prepared, err := prepareDocumentationFactorySourceCompilation(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	identities, _, err := deriveDocumentationFactoryProviderEvidenceIdentities(prepared)
	if err != nil || len(identities) != len(prepared.evidenceBodies) {
		t.Fatalf("derive compiler evidence roster: identities=%d bodies=%d err=%v", len(identities), len(prepared.evidenceBodies), err)
	}
	bodies, identityHashes := make([][]byte, len(prepared.evidenceBodies)), make([]string, len(identities))
	references := make([]string, len(prepared.evidenceBodies))
	projection, err := decodeSealedNativeAPIJSONL(bundle.Documents[sourcePackageOutputRoleAPIGraphArtifact], sha256Hex(bundle.Documents[sourcePackageOutputRoleAPIGraphArtifact]), sha256Hex(bundle.Documents[sourcePackageOutputRoleSourceMapping]))
	if err != nil {
		t.Fatalf("decode retained candidate locators: %v", err)
	}
	for i := range bodies {
		bodies[i] = prepared.evidenceBodies[i].Raw
		identityHashes[i] = sha256Hex([]byte(documentationFactoryProviderEvidenceIdentityKey(identities[i])))
		for _, locator := range projection.Locators {
			if locator.SourceContentSHA256 == identities[i].SourceContentSHA256 && len(locator.SourceRefs) != 0 {
				references[i] = locator.SourceRefs[0]
				break
			}
		}
		if references[i] == "" {
			t.Fatalf("sealed native graph has no locator for evidence body %d", i)
		}
	}
	f := oodtestfixture.BuildForEvidenceSetWithReferences(context.Background(), t, bodies, identityHashes, references)
	expected := productionSourceOwnerBindingExpectation()
	expected.OrganizationID = f.Certificate.OrganizationID
	expected.Provider = "fixture_provider"
	receipt := filepath.Join(t.TempDir(), "source-owner-receipt.json")
	if err := os.WriteFile(receipt, []byte("{\"receipt_kind\":\"opaque_source_owner_verification\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, done := newSourceProofIntegrationClient(t, sourceProofIntegrationSpanner{serveCurrentHead: true, rows: successorFixtureRows(t, f), fixture: &f})
	defer done()
	archives := successorFixtureArchives(t, f, bodies)
	authority := successorIntegrationAuthority{sourceProofFixtureAuthority: sourceProofFixtureAuthority{fixture: f}, archives: archives, manifests: successorFixtureManifestBindings(t, f, projection, archives), projection: projection}
	launcher, err := NewDocumentationFactoryProductionSourceProtectedLauncher(client, expected, authority)
	if err != nil {
		t.Fatal(err)
	}
	q, err := launcher.compileDocumentationFactoryProductionSourcePackageForPreparationWithDependencies(context.Background(), DocumentationFactoryProductionSourceCompileOptions{
		SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot, VerificationReceiptPath: receipt, ExpectedProvider: expected.Provider,
	}, documentationFactoryProductionSourceCompilerDependencies{SourceCompiler: sourcePackageCompilerTestDependencies(t), Now: func() time.Time {
		return time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)
	}})
	if err != nil {
		t.Fatalf("protected compiler did not capture exact multi-receipt current evidence: %v", err)
	}
	if q.preparation == nil || q.compiled.oodProjection == nil {
		t.Fatal("protected compilation did not retain one sealed qualified preparation")
	}
	if err := validateDocumentationFactoryProductionSourceOODCurrentEvidenceRows(q.expected, q.request, q.current); err != nil {
		t.Fatalf("captured same-read current evidence is not locally revalidatable: %v", err)
	}
	plan, err := BuildDocumentationFactoryProductionSourceOODPlan(context.Background(), q)
	if err != nil {
		t.Fatalf("qualified sealed compiler result did not construct physical successor: %v", err)
	}
	if len(plan.Native.Closure.ImmutableRows) == 0 || len(plan.LocatorProofs) == 0 || len(plan.EvidenceLocatorProofs) == 0 {
		t.Fatalf("successor plan omitted physical rows or locator proof products: %#v", plan)
	}
	if len(plan.RoleProofs) != len(projection.Symbols) {
		t.Fatalf("successor plan role-proof roster=%d, want one proof for each sealed symbol=%d", len(plan.RoleProofs), len(projection.Symbols))
	}
	if plan.VerifiedClosure.ClosureHash() == f.Certificate.ClosureHash || plan.VerifiedClosure.CertificateID() != uuid.NewSHA1(uuid.NameSpaceURL, []byte("successor-integration/certificate/allocated")).String() {
		t.Fatalf("successor reused predecessor closure or did not retain allocated certificate: successor=%q predecessor=%q certificate=%q", plan.VerifiedClosure.ClosureHash(), f.Certificate.ClosureHash, plan.VerifiedClosure.CertificateID())
	}
	assertSuccessorFixtureProjectionMaterialized(t, projection, plan.Native.Plan.ImmutableRows)
	if err := oodapi.ValidateMaterialization(plan.VerifiedClosure, plan.VerifiedRoster, oodapi.FactoryOutput{Plan: plan.Native.Plan, LocatorProofs: plan.LocatorProofs, RoleProofs: plan.RoleProofs, EvidenceLocatorProofs: plan.EvidenceLocatorProofs}); err != nil {
		missing := []string{}
		incidents := map[string]int{}
		for _, row := range plan.Native.Plan.ImmutableRows {
			if row.Table == "OODGraphEdges" && row.Columns["edge_family"] == "api_relationship" {
				incidents[row.Columns["source_endpoint_id"].(string)]++
				incidents[row.Columns["target_endpoint_id"].(string)]++
			}
		}
		for _, row := range plan.Native.Plan.ImmutableRows {
			if row.Table != "OODGraphObjects" || row.Columns["object_class"] != "api_symbol" {
				continue
			}
			coord := oodevidence.APIElementSourceCoordinate{ObjectClass: row.Columns["object_class"].(string), AuthorityID: row.Columns["source_authority_id"].(string), RefKind: row.Columns["source_ref_kind"].(string), StableReference: row.Columns["source_stable_reference"].(string), VersionCoordinate: row.Columns["version_coordinate"].(string), SectionPath: row.Columns["section_path"].(string)}
			binding := oodevidence.APIElementRoleBinding{Role: row.Columns["api_element_role"].(string), LocatorManifestHash: row.Columns["api_element_role_locator_manifest_hash"].(string)}
			found := false
			for _, proof := range plan.LocatorProofs {
				found = found || (proof.SourceCoordinate() == coord && proof.SourceRoleBinding() == binding) || (proof.TargetCoordinate() == coord && proof.TargetRoleBinding() == binding)
			}
			if !found {
				objectID := row.Columns["graph_object_id"].(string)
				missing = append(missing, fmt.Sprintf("%s/%s/incidents=%d", binding.Role, objectID, incidents[objectID]))
			}
		}
		t.Fatalf("actual successor plan failed shared final API materialization verifier: %v (unproved roles=%v)", err, missing)
	}
}

// assertSuccessorFixtureProjectionMaterialized proves that the successful
// protected compile did not merely produce a nonempty plan: every sealed
// candidate fact family has a corresponding physical successor family, and
// every relationship retained its native authoring anchor.
func assertSuccessorFixtureProjectionMaterialized(t *testing.T, projection DocumentationFactorySourcePackageOODNativeProjection, rows []oodpublication.SpannerRow) {
	t.Helper()
	objects, symbols, locators, properties, violations, documentationEdges, documentationEvidence := 0, 0, 0, 0, 0, 0, 0
	relationships := map[string]bool{}
	for _, row := range rows {
		switch row.Table {
		case "OODGraphObjects":
			if row.Columns["object_class"] == "api_symbol" {
				objects++
			}
		case "OODGraphSymbols":
			if row.Columns["object_class"] == "api_symbol" {
				symbols++
			}
		case "OODGraphGraphFactEvidenceLocators":
			locators++
		case "OODGraphEdges":
			if row.Columns["edge_family"] == "api_relationship" {
				anchor, _ := row.Columns["authoring_source_path"].(string)
				if anchor == "" || relationships[anchor] {
					t.Fatalf("successor relationship physical anchor is empty or duplicated: %q", anchor)
				}
				relationships[anchor] = true
			}
			if row.Columns["edge_family"] == "external_reference" && row.Columns["edge_label"] == "documents" {
				documentationEdges++
			}
		case "OODGraphRelationshipEvidence":
			if row.Columns["evidence_source_kind"] == "external_document_evidence" && row.Columns["edge_label"] == "documents" {
				documentationEvidence++
			}
		case "OODGraphAPIPropertyFacts":
			properties++
		case "OODGraphViolations":
			violations++
		}
	}
	if objects != len(projection.Symbols) || symbols != len(projection.Symbols) || locators != len(projection.Locators) || properties != len(projection.Properties) || violations != len(projection.Gaps) || len(relationships) != len(projection.Relationships) || documentationEdges != len(projection.Symbols) || documentationEvidence != len(projection.Symbols) {
		t.Fatalf("sealed native projection was not completely physicalized: objects=%d/%d symbols=%d/%d locators=%d/%d relationships=%d/%d documentation_edges=%d/%d documentation_evidence=%d/%d properties=%d/%d gaps=%d/%d", objects, len(projection.Symbols), symbols, len(projection.Symbols), locators, len(projection.Locators), len(relationships), len(projection.Relationships), documentationEdges, len(projection.Symbols), documentationEvidence, len(projection.Symbols), properties, len(projection.Properties), violations, len(projection.Gaps))
	}
	for _, relationship := range projection.Relationships {
		if !relationships[relationship.ID] {
			t.Fatalf("sealed relationship %q lacks its physical authoring anchor", relationship.ID)
		}
	}
}
