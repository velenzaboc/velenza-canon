package providerplan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/oodproof"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

func TestBuildDocumentationFactorySourcePackageOODNativeGraphRows(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	var receipt, batch, locatorRow oodpublication.SpannerRow
	for _, row := range f.ImmutableRows {
		if row.Table == "OODGraphExternalFetchReceipts" {
			receipt = row
		}
		if row.Table == "OODGraphExternalFetchBatches" {
			batch = row
		}
		if row.Table == "OODGraphGraphFactEvidenceLocators" {
			locatorRow = row
		}
	}
	if receipt.Table == "" || batch.Table == "" {
		t.Fatal("fixture physical evidence absent")
	}
	artifact, err := oodpublication.SourceArtifactExternalEvidenceDigest([]oodpublication.SpannerRow{receipt, batch})
	if err != nil {
		t.Fatal(err)
	}
	// The source mapping digest is the owner-pinned representation profile used
	// by this mapper, so the locator is recomputed from its exact physical pair.
	mapping := sha256Hex([]byte("sealed-source-mapping"))
	l := oodproof.GraphFactLocator{OrganizationID: f.Receipt.OrganizationID, EvidenceIdentityHash: f.Receipt.EvidenceIdentityHash, SourceArtifactMemberHash: artifact, EligibleReceiptID: f.Receipt.ReceiptID, EligibleReceiptDigest: f.Receipt.RedactedTransportEvidenceDigest, SealedCompletenessCertificateHash: f.Batch.CompletenessEvidenceDigest(), EvidenceArchiveAuthorityID: f.Receipt.EvidenceArchiveAuthorityID, EvidenceArchiveRecordID: f.Receipt.EvidenceArchiveRecordID, EvidenceArchiveRecordDigest: f.Receipt.EvidenceArchiveRecordDigest, SourceContentHashAlgorithm: f.Receipt.SourceContentHashAlgorithm, SourceContentHashProfile: f.Receipt.SourceContentHashProfile, SourceContentHash: f.Receipt.SourceContentHash, SourceContentByteLength: f.Receipt.EvidenceArchiveByteCount, CanonicalRepresentationProfileRef: "native_source_mapping_v1", CanonicalRepresentationProfileDigest: mapping, ByteStartOffset: f.Locator.ByteStartOffset, ByteEndOffsetExclusive: f.Locator.ByteEndOffsetExclusive, SelectedRangeContentHash: f.Locator.SelectedRangeContentHash, SelectedRangeByteCount: f.Locator.SelectedRangeByteCount, EvidenceArchiveDeletionDomainID: f.Receipt.EvidenceArchiveDeletionDomainID, EvidenceArchiveCryptoShredDomainID: f.Receipt.EvidenceArchiveCryptoShredDomainID}
	l.LocatorHash, err = l.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	cols := map[string]interface{}{}
	for k, v := range locatorRow.Columns {
		cols[k] = v
	}
	cols["graph_fact_locator_hash"], cols["evidence_identity_hash"], cols["source_artifact_member_hash"], cols["eligible_receipt_id"], cols["eligible_receipt_digest"] = l.LocatorHash, l.EvidenceIdentityHash, l.SourceArtifactMemberHash, l.EligibleReceiptID, l.EligibleReceiptDigest
	cols["sealed_completeness_certificate_hash"], cols["evidence_archive_authority_id"], cols["evidence_archive_record_id"], cols["evidence_archive_record_digest"] = l.SealedCompletenessCertificateHash, l.EvidenceArchiveAuthorityID, l.EvidenceArchiveRecordID, l.EvidenceArchiveRecordDigest
	cols["source_content_hash_algorithm"], cols["source_content_hash_profile"], cols["source_content_hash"], cols["source_content_byte_length"] = l.SourceContentHashAlgorithm, l.SourceContentHashProfile, l.SourceContentHash, l.SourceContentByteLength
	cols["canonical_representation_profile_ref"], cols["canonical_representation_profile_digest"], cols["byte_start_offset"], cols["byte_end_offset_exclusive"], cols["selected_range_content_hash"], cols["selected_range_byte_count"], cols["evidence_archive_deletion_domain_id"], cols["evidence_archive_crypto_shred_domain_id"] = l.CanonicalRepresentationProfileRef, l.CanonicalRepresentationProfileDigest, l.ByteStartOffset, l.ByteEndOffsetExclusive, l.SelectedRangeContentHash, l.SelectedRangeByteCount, l.EvidenceArchiveDeletionDomainID, l.EvidenceArchiveCryptoShredDomainID
	locatorRow.Columns = cols
	digest := func(s string) string { return sha256Hex([]byte(s)) }
	id := func(s string) string { return uuid.NewSHA1(uuid.NameSpaceURL, []byte("native-rows/"+s)).String() }
	p := DocumentationFactorySourcePackageOODNativeProjection{APIGraphSHA256: digest("sealed-api-graph"), SourceMappingSHA256: mapping, Locators: []DocumentationFactoryNativeEvidenceLocator{{ID: "l", SourceContentSHA256: f.Receipt.SourceContentHash, SelectedRangeSHA256: f.Locator.SelectedRangeContentHash, ByteStartOffset: f.Locator.ByteStartOffset, ByteEndOffsetExclusive: f.Locator.ByteEndOffsetExclusive, SelectedRangeByteCount: f.Locator.SelectedRangeByteCount, SourceRefs: []string{f.Receipt.SourceStableReference}}}, Symbols: []DocumentationFactoryNativeAPISymbol{{ID: "source", Role: "operation", SemanticKey: "source", DisplayName: "source", LocatorIDs: []string{"l"}}, {ID: "target", Role: "resource", SemanticKey: "target", DisplayName: "target", LocatorIDs: []string{"l"}}}, Relationships: []DocumentationFactoryNativeAPIRelationship{{ID: "r", Label: "operation_reads_resource", SourceID: "source", TargetID: "target", LocatorIDs: []string{"l"}}}}
	bindings := []DocumentationFactorySourcePackageOODLocatorBinding{{NativeLocatorID: "l", SourceArtifactHash: artifact, Locator: l, LocatorRow: locatorRow, Receipt: receipt, Batch: batch}}
	provenance := provenanceTestVerified(t, f.Receipt.OrganizationID, p, bindings)
	ctx := DocumentationFactorySourcePackageOODNativeGraphRowsContext{
		OrganizationID: f.Receipt.OrganizationID,
		CreatedAt:      time.Date(2026, 11, 2, 13, 0, 0, 0, time.UTC),
		Locators:       bindings,
		Symbols: []DocumentationFactoryNativeSymbolIdentity{
			{NativeSymbolID: "source", GraphObjectID: id("source-object"), SymbolID: id("source-symbol"), SectionPath: "/source", GraphAddress: "api://source"},
			{NativeSymbolID: "target", GraphObjectID: id("target-object"), SymbolID: id("target-symbol"), SectionPath: "/target", GraphAddress: "api://target"},
		},
		Relationships: []DocumentationFactoryNativeRelationshipIdentity{{NativeRelationshipID: "r", GraphEdgeID: id("edge")}},
		Provenance:    provenance,
	}
	got, err := BuildDocumentationFactorySourcePackageOODNativeGraphRows(context.Background(), p, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Objects) != 2 || len(got.Symbols) != 2 || len(got.Edges) != 1 || len(got.RelationshipEvidence) != 1 || len(got.Members) != 6 {
		t.Fatalf("unexpected physical rows: %+v", got)
	}
	for _, r := range append(append(append(got.Objects, got.Symbols...), got.Edges...), got.RelationshipEvidence...) {
		if _, err := oodpublication.BuildImmutableRow(r.Table, r.Columns); err != nil {
			t.Fatalf("strict row %s: %v", r.Table, err)
		}
		if _, err := oodpublication.CanonicalMemberDigestFromPhysicalRow(r); err != nil {
			t.Fatalf("owner digest %s: %v", r.Table, err)
		}
	}

	ctx.Locators[0].Locator.LocatorHash = digest("substituted")
	if _, err := BuildDocumentationFactorySourcePackageOODNativeGraphRows(context.Background(), p, ctx); err == nil {
		t.Fatal("accepted substituted locator hash")
	}
}

func TestNativeClaimLocatorRejectsForeignPrimary(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	var receiptRow, batchRow, locatorRow oodpublication.SpannerRow
	for _, r := range f.ImmutableRows {
		switch r.Table {
		case "OODGraphExternalFetchReceipts":
			receiptRow = r
		case "OODGraphExternalFetchBatches":
			batchRow = r
		case "OODGraphGraphFactEvidenceLocators":
			locatorRow = r
		}
	}
	batch, err := oodpublication.BatchV8FromPhysicalRow(batchRow)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := oodpublication.SourceArtifactExternalEvidenceDigest([]oodpublication.SpannerRow{receiptRow, batchRow})
	if err != nil {
		t.Fatal(err)
	}
	l := f.Locator
	l.SourceArtifactMemberHash = artifact
	l.SealedCompletenessCertificateHash = batch.CompletenessEvidenceDigest
	l.LocatorHash, err = l.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	base := nativeQualifiedLocator{binding: DocumentationFactorySourcePackageOODLocatorBinding{NativeLocatorID: "a", Locator: l, LocatorRow: locatorRow}, receipt: f.Receipt, batch: batch, sourceArtifactHash: artifact}
	// Verify a valid claim first, then test that a primary outside the claim
	// cannot supply its source identity.
	other := base
	other.binding.NativeLocatorID = "b"
	other.receipt.SourceStableReference = "https://different.example/document"
	p := map[string]DocumentationFactoryNativeEvidenceLocator{
		"a": {ID: "a", SourceContentSHA256: f.Receipt.SourceContentHash, SelectedRangeSHA256: l.SelectedRangeContentHash, ByteStartOffset: l.ByteStartOffset, ByteEndOffsetExclusive: l.ByteEndOffsetExclusive, SelectedRangeByteCount: l.SelectedRangeByteCount, SourceRefs: []string{f.Receipt.SourceStableReference}},
		"b": {ID: "b", SourceContentSHA256: f.Receipt.SourceContentHash, SelectedRangeSHA256: l.SelectedRangeContentHash, ByteStartOffset: l.ByteStartOffset, ByteEndOffsetExclusive: l.ByteEndOffsetExclusive, SelectedRangeByteCount: l.SelectedRangeByteCount, SourceRefs: []string{other.receipt.SourceStableReference}},
	}
	if _, _, _, err := nativeClaimLocator([]string{"a"}, "a", p, map[string]nativeQualifiedLocator{"a": base}, f.Receipt.OrganizationID, time.Date(2026, 11, 2, 13, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("valid baseline refused: %v", err)
	}
	if _, _, _, err := nativeClaimLocator([]string{"a", "b"}, "foreign", p, map[string]nativeQualifiedLocator{"a": base, "b": other}, f.Receipt.OrganizationID, time.Date(2026, 11, 2, 13, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "primary locator is not a claim member") {
		t.Fatalf("foreign claim primary error=%v", err)
	}
}

func TestSuccessorLocatorBuilderRefusesAmbiguousReceiptMatch(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	rows := append([]oodpublication.SpannerRow(nil), f.ImmutableRows...)
	for _, r := range f.ImmutableRows {
		if r.Table != "OODGraphExternalFetchReceipts" {
			continue
		}
		copy := r
		copy.Columns = map[string]interface{}{}
		for k, v := range r.Columns {
			copy.Columns[k] = v
		}
		copy.Columns["receipt_id"] = uuid.NewString()
		// It only reaches the candidate-count fence; no forged row becomes evidence.
		rows = append(rows, copy)
		break
	}
	p := DocumentationFactorySourcePackageOODNativeProjection{Locators: []DocumentationFactoryNativeEvidenceLocator{{ID: "ambiguous", EvidenceManifestSHA256: sha256Hex([]byte("manifest")), SourceContentSHA256: f.Receipt.SourceContentHash, SelectedRangeSHA256: f.Locator.SelectedRangeContentHash, ByteStartOffset: f.Locator.ByteStartOffset, ByteEndOffsetExclusive: f.Locator.ByteEndOffsetExclusive, SelectedRangeByteCount: f.Locator.SelectedRangeByteCount, SourceRefs: []string{f.Receipt.SourceStableReference}}}}
	a := successorIntegrationAuthority{sourceProofFixtureAuthority: sourceProofFixtureAuthority{fixture: f}}
	if _, _, err := buildDocumentationFactorySourcePackageOODLocatorBindings(context.Background(), p, rows, a, time.Date(2026, 11, 2, 13, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "ambiguous qualified receipts") {
		t.Fatalf("ambiguous receipt match error = %v", err)
	}
}
