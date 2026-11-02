package oodevidence

import (
	"context"
	"errors"

	"github.com/velenzaboc/velenza-canon/internal/oodproof"
)

// VerifiedGraphFactLocatorV8 proves one exact archived range against its
// opaque complete batch. Claim-manifest membership and interpretation are
// separate obligations of the consuming closure and derivation verifier.
type VerifiedGraphFactLocatorV8 struct {
	organizationID, locatorHash string
	verified                    bool
}

func (v VerifiedGraphFactLocatorV8) OrganizationID() string { return v.organizationID }
func (v VerifiedGraphFactLocatorV8) LocatorHash() string    { return v.locatorHash }
func ValidateVerifiedGraphFactLocatorV8(v VerifiedGraphFactLocatorV8) error {
	if !v.verified || v.organizationID == "" || v.locatorHash == "" {
		return errors.New("verified graph-fact locator absent")
	}
	return nil
}

func VerifyGraphFactLocatorV8(ctx context.Context, batch VerifiedBatchV8, locator oodproof.GraphFactLocator, archivedBody []byte) (VerifiedGraphFactLocatorV8, error) {
	if _, err := verifyGraphFactLocatorReceipt(ctx, batch, locator, archivedBody); err != nil {
		return VerifiedGraphFactLocatorV8{}, err
	}
	return VerifiedGraphFactLocatorV8{organizationID: locator.OrganizationID, locatorHash: locator.LocatorHash, verified: true}, nil
}

func verifyGraphFactLocatorReceipt(ctx context.Context, batch VerifiedBatchV8, locator oodproof.GraphFactLocator, archivedBody []byte) (ReceiptV8, error) {
	if ctx == nil {
		return ReceiptV8{}, errors.New("graph-fact locator context absent")
	}
	if err := ctx.Err(); err != nil {
		return ReceiptV8{}, err
	}
	if err := ValidateVerifiedBatchV8(batch); err != nil {
		return ReceiptV8{}, err
	}
	receipt, ok := batch.Receipt(locator.EligibleReceiptID)
	if !ok {
		return ReceiptV8{}, errors.New("locator receipt not selected by verified complete batch")
	}
	if err := VerifyArchivedCanonicalBytes(receipt, archivedBody); err != nil {
		return ReceiptV8{}, err
	}
	if locator.OrganizationID != receipt.OrganizationID || locator.EvidenceIdentityHash != receipt.EvidenceIdentityHash || locator.EligibleReceiptDigest != receipt.RedactedTransportEvidenceDigest || locator.SealedCompletenessCertificateHash != batch.CompletenessEvidenceDigest() || locator.EvidenceArchiveAuthorityID != receipt.EvidenceArchiveAuthorityID || locator.EvidenceArchiveRecordID != receipt.EvidenceArchiveRecordID || locator.EvidenceArchiveRecordDigest != receipt.EvidenceArchiveRecordDigest || locator.SourceContentHashAlgorithm != receipt.SourceContentHashAlgorithm || locator.SourceContentHashProfile != receipt.SourceContentHashProfile || locator.SourceContentHash != receipt.SourceContentHash || locator.SourceContentByteLength != receipt.EvidenceArchiveByteCount || locator.EvidenceArchiveDeletionDomainID != receipt.EvidenceArchiveDeletionDomainID || locator.EvidenceArchiveCryptoShredDomainID != receipt.EvidenceArchiveCryptoShredDomainID {
		return ReceiptV8{}, errors.New("locator receipt/archive/content cross-binding mismatch")
	}
	if _, err := oodproof.VerifyGraphFactLocator(ctx, locator, archivedBody); err != nil {
		return ReceiptV8{}, err
	}
	return receipt, nil
}
