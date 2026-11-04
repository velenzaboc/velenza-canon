package providerplan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodproof"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

var errPrimaryTestManifestSubstitution = errors.New("evidence-manifest substitution")

// primaryTestAuthority deliberately refuses exactly the substituted manifest
// after the locator selector has found its one qualified receipt.
type primaryTestAuthority struct{ successorIntegrationAuthority }

func (primaryTestAuthority) VerifyEvidenceManifestBinding(context.Context, oodevidence.ReceiptV8, string) error {
	return errPrimaryTestManifestSubstitution
}

func TestNativeClaimLocatorDeclaredPrimaryIsOrderStableAcrossSources(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	base := primaryTestQualifiedLocator(t, f)
	secondary := primaryTestAlternateQualifiedLocator(t, base)
	when := time.Date(2026, 11, 2, 13, 0, 0, 0, time.UTC)
	locators := map[string]DocumentationFactoryNativeEvidenceLocator{
		"primary":   primaryTestNativeLocator("primary", base),
		"secondary": primaryTestNativeLocator("secondary", secondary),
	}
	qualified := map[string]nativeQualifiedLocator{"primary": base, "secondary": secondary}

	first, firstRoot, _, err := nativeClaimLocator([]string{"primary", "secondary"}, "secondary", locators, qualified, f.Receipt.OrganizationID, when)
	if err != nil {
		t.Fatalf("valid heterogeneous claim refused: %v", err)
	}
	second, secondRoot, _, err := nativeClaimLocator([]string{"secondary", "primary"}, "secondary", locators, qualified, f.Receipt.OrganizationID, when)
	if err != nil {
		t.Fatalf("reordered valid heterogeneous claim refused: %v", err)
	}
	if firstRoot != secondRoot {
		t.Fatalf("claim manifest root changed with locator order: %q != %q", firstRoot, secondRoot)
	}
	if first.receipt.SourceStableReference != secondary.receipt.SourceStableReference || second.receipt.SourceStableReference != secondary.receipt.SourceStableReference {
		t.Fatalf("declared primary source tuple was not retained: first=%q second=%q want=%q", first.receipt.SourceStableReference, second.receipt.SourceStableReference, secondary.receipt.SourceStableReference)
	}

	if _, _, _, err := nativeClaimLocator([]string{"primary", "secondary"}, "foreign", locators, qualified, f.Receipt.OrganizationID, when); err == nil || !strings.Contains(err.Error(), "primary locator is not a claim member") {
		t.Fatalf("foreign primary error = %v", err)
	}
	if _, _, _, err := nativeClaimLocator([]string{"primary", "secondary"}, "", locators, qualified, f.Receipt.OrganizationID, when); err == nil || !strings.Contains(err.Error(), "claim has no locator") {
		t.Fatalf("missing primary error = %v", err)
	}
}

func TestSuccessorLocatorBuilderRefusesEvidenceManifestSubstitution(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	p := DocumentationFactorySourcePackageOODNativeProjection{Locators: []DocumentationFactoryNativeEvidenceLocator{{
		ID: "manifest-substitution", EvidenceManifestSHA256: sha256Hex([]byte("substituted-manifest")),
		SourceContentSHA256: f.Receipt.SourceContentHash, SelectedRangeSHA256: f.Locator.SelectedRangeContentHash,
		ByteStartOffset: f.Locator.ByteStartOffset, ByteEndOffsetExclusive: f.Locator.ByteEndOffsetExclusive,
		SelectedRangeByteCount: f.Locator.SelectedRangeByteCount, SourceRefs: []string{f.Receipt.SourceStableReference},
	}}}
	a := primaryTestAuthority{successorIntegrationAuthority{sourceProofFixtureAuthority: sourceProofFixtureAuthority{fixture: f}}}
	_, _, err := buildDocumentationFactorySourcePackageOODLocatorBindings(context.Background(), p, f.ImmutableRows, a, time.Date(2026, 11, 2, 13, 0, 0, 0, time.UTC))
	if !errors.Is(err, errPrimaryTestManifestSubstitution) {
		t.Fatalf("manifest substitution error = %v, want wrapped %v", err, errPrimaryTestManifestSubstitution)
	}
}

func primaryTestQualifiedLocator(t *testing.T, f oodtestfixture.Fixture) nativeQualifiedLocator {
	t.Helper()
	var receiptRow, batchRow, locatorRow oodpublication.SpannerRow
	for _, row := range f.ImmutableRows {
		switch row.Table {
		case "OODGraphExternalFetchReceipts":
			receiptRow = row
		case "OODGraphExternalFetchBatches":
			batchRow = row
		case "OODGraphGraphFactEvidenceLocators":
			locatorRow = row
		}
	}
	receipt, err := oodpublication.ReceiptV8FromPhysicalRow(receiptRow)
	if err != nil {
		t.Fatal(err)
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
	return nativeQualifiedLocator{binding: DocumentationFactorySourcePackageOODLocatorBinding{NativeLocatorID: "primary", Locator: l, LocatorRow: primaryTestLocatorRow(t, locatorRow, l)}, receipt: receipt, batch: batch, sourceArtifactHash: artifact}
}

func primaryTestAlternateQualifiedLocator(t *testing.T, base nativeQualifiedLocator) nativeQualifiedLocator {
	t.Helper()
	receipt := base.receipt
	receipt.ReceiptID = uuid.NewString()
	receipt.SourceStableReference = "https://example.invalid/independent-source"
	receipt.VersionCoordinate = "independent-version"
	receipt.EvidenceIdentityHash = sha256Hex([]byte("independent-evidence-identity"))
	l := base.binding.Locator
	l.EvidenceIdentityHash = receipt.EvidenceIdentityHash
	l.SourceArtifactMemberHash = sha256Hex([]byte("independent-source-artifact"))
	l.EligibleReceiptID = receipt.ReceiptID
	l.LocatorHash = ""
	var err error
	l.LocatorHash, err = l.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	return nativeQualifiedLocator{binding: DocumentationFactorySourcePackageOODLocatorBinding{NativeLocatorID: "secondary", Locator: l, LocatorRow: primaryTestLocatorRow(t, base.binding.LocatorRow, l)}, receipt: receipt, batch: base.batch, sourceArtifactHash: l.SourceArtifactMemberHash}
}

func primaryTestNativeLocator(id string, q nativeQualifiedLocator) DocumentationFactoryNativeEvidenceLocator {
	l := q.binding.Locator
	return DocumentationFactoryNativeEvidenceLocator{ID: id, SourceContentSHA256: l.SourceContentHash, SelectedRangeSHA256: l.SelectedRangeContentHash, ByteStartOffset: l.ByteStartOffset, ByteEndOffsetExclusive: l.ByteEndOffsetExclusive, SelectedRangeByteCount: l.SelectedRangeByteCount, SourceRefs: []string{q.receipt.SourceStableReference}}
}

func primaryTestLocatorRow(t *testing.T, template oodpublication.SpannerRow, l oodproof.GraphFactLocator) oodpublication.SpannerRow {
	t.Helper()
	columns := make(map[string]interface{}, len(template.Columns))
	for k, v := range template.Columns {
		columns[k] = v
	}
	values := map[string]interface{}{
		"graph_fact_locator_hash": l.LocatorHash, "evidence_identity_hash": l.EvidenceIdentityHash, "source_artifact_member_hash": l.SourceArtifactMemberHash,
		"eligible_receipt_id": l.EligibleReceiptID, "eligible_receipt_digest": l.EligibleReceiptDigest, "sealed_completeness_certificate_hash": l.SealedCompletenessCertificateHash,
		"evidence_archive_authority_id": l.EvidenceArchiveAuthorityID, "evidence_archive_record_id": l.EvidenceArchiveRecordID, "evidence_archive_record_digest": l.EvidenceArchiveRecordDigest,
		"source_content_hash_algorithm": l.SourceContentHashAlgorithm, "source_content_hash_profile": l.SourceContentHashProfile, "source_content_hash": l.SourceContentHash, "source_content_byte_length": l.SourceContentByteLength,
		"canonical_representation_profile_ref": l.CanonicalRepresentationProfileRef, "canonical_representation_profile_digest": l.CanonicalRepresentationProfileDigest,
		"byte_start_offset": l.ByteStartOffset, "byte_end_offset_exclusive": l.ByteEndOffsetExclusive, "selected_range_content_hash": l.SelectedRangeContentHash, "selected_range_byte_count": l.SelectedRangeByteCount,
		"evidence_archive_deletion_domain_id": l.EvidenceArchiveDeletionDomainID, "evidence_archive_crypto_shred_domain_id": l.EvidenceArchiveCryptoShredDomainID,
	}
	for k, v := range values {
		columns[k] = v
	}
	immutable, err := oodpublication.BuildImmutableRow("OODGraphGraphFactEvidenceLocators", columns)
	if err != nil {
		t.Fatalf("strict locator row: %v", err)
	}
	return immutable.Row()
}
