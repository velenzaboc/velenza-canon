package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// externalEvidenceArchive is the protected source-carrier seam used by
// external-document ingestion. A production implementation must create an
// immutable AGFS file version plus external_carrier_hold through the
// SOURCE RECORD custody boundary, and hydrate it only through AGFS's
// kernel-internal external_source_evidence_carrier_resolution. Ordinary
// fs.file.write, fs.file.read, caller-visible file coordinates, and ordinary
// read claims are intentionally not implementations of this interface.
type externalEvidenceArchive interface {
	Archive(context.Context, externalEvidenceArchiveRequest) (externalEvidenceArchiveReceipt, error)
	Hydrate(context.Context, externalEvidenceHydrationRequest) (externalEvidenceHydrationResult, error)
}

// archiveExternalEvidence detaches the canonical source bytes before they
// cross the adapter boundary. Interface arguments copy slice headers, not the
// backing array; without this copy an adapter could mutate or retain an alias
// to the same bytes the locator parser consumes after Archive returns.
func archiveExternalEvidence(ctx context.Context, archive externalEvidenceArchive, request externalEvidenceArchiveRequest) (externalEvidenceArchiveReceipt, error) {
	request.SourceBytes = append([]byte(nil), request.SourceBytes...)
	return archive.Archive(ctx, request)
}

// externalEvidenceArchiveRequest contains no credential, bearer token,
// principal assertion, ordinary AGFS namespace coordinate, or caller-chosen
// organization. The adapter resolves CallerContext and the current PIA/Gate/
// source-currentness closure inside the protected kernel boundary.
type externalEvidenceArchiveRequest struct {
	OrganizationID                    string
	SourceBytes                       []byte
	SourceContentHashAlgorithm        string
	SourceContentHashProfile          string
	SourceContentHash                 string
	BodyStorageAuthorizationReference string
	BodyRetentionHoldReference        string
	DeletionDomainID                  string
	CryptoShredDomainID               string
}

type externalEvidenceArchiveReceipt struct {
	OrganizationID                    string `json:"organization_id"`
	ArchiveAuthorityID                string `json:"archive_authority_id"`
	FileID                            string `json:"file_id"`
	ExplicitVersion                   int64  `json:"explicit_version"`
	AGFSContentHash                   string `json:"agfs_content_hash"`
	AGFSBodyReferenceHash             string `json:"agfs_body_reference_hash"`
	SourceByteLength                  int64  `json:"source_byte_length"`
	SourceContentHashAlgorithm        string `json:"source_content_hash_algorithm"`
	SourceContentHashProfile          string `json:"source_content_hash_profile"`
	SourceContentHash                 string `json:"source_content_hash"`
	BodyStorageAuthorizationReference string `json:"body_storage_authorization_reference"`
	BodyRetentionHoldReference        string `json:"body_retention_hold_reference"`
	DeletionDomainID                  string `json:"deletion_domain_id"`
	CryptoShredDomainID               string `json:"crypto_shred_domain_id"`
	ArchiveRecordDigest               string `json:"archive_record_digest"`
}

type externalEvidenceHydrationRequest struct {
	Archive externalEvidenceArchiveReceipt
	Start   int64
	End     int64
}

type externalEvidenceHydrationResult struct {
	Bytes               []byte
	SelectedRangeSHA256 string
	SourceContentHash   string
	ArchiveRecordDigest string
	FileID              string
	ExplicitVersion     int64
}

// hydrateExternalEvidenceByteRange is the internal exact-field hydration
// seam. Candidate discovery supplies only a durable receipt and one
// zero-based half-open range. The adapter must re-evaluate the current
// CallerContext, PIA grants, Gate proceed evidence, hard hold, and SOURCE
// RECORD currentness at mint and redemption; no ordinary AGFS handle can be
// substituted. No graph row, embedding, caller value, or provider network
// response can supply the returned bytes.
func hydrateExternalEvidenceByteRange(ctx context.Context, env *Env, receipt *stagedExternalVerificationReceipt, start, end int64) (externalEvidenceHydrationResult, error) {
	if env == nil || env.ExternalArchive == nil {
		return externalEvidenceHydrationResult{}, fmt.Errorf("trusted protected external evidence archive adapter required for exact hydration")
	}
	if err := requireArchivedExternalEvidence(receipt); err != nil {
		return externalEvidenceHydrationResult{}, err
	}
	if start < 0 || end <= start || end > receipt.Archive.SourceByteLength {
		return externalEvidenceHydrationResult{}, fmt.Errorf("external evidence byte range [%d,%d) must be nonempty and inside [0,%d)", start, end, receipt.Archive.SourceByteLength)
	}
	result, err := env.ExternalArchive.Hydrate(ctx, externalEvidenceHydrationRequest{Archive: *receipt.Archive, Start: start, End: end})
	if err != nil {
		return externalEvidenceHydrationResult{}, err
	}
	// Hydration results cross the same adapter boundary. Detach the selected
	// bytes before verification and return so an adapter-retained buffer cannot
	// change an already-verified exact field after this function returns.
	result.Bytes = append([]byte(nil), result.Bytes...)
	if result.SourceContentHash != receipt.DecodedSHA256 || result.ArchiveRecordDigest != receipt.Archive.ArchiveRecordDigest || result.FileID != receipt.Archive.FileID || result.ExplicitVersion != receipt.Archive.ExplicitVersion {
		return externalEvidenceHydrationResult{}, fmt.Errorf("hydrated external evidence provenance does not match the durable graph receipt")
	}
	selectedSum := sha256.Sum256(result.Bytes)
	if result.SelectedRangeSHA256 != hex.EncodeToString(selectedSum[:]) || int64(len(result.Bytes)) != end-start {
		return externalEvidenceHydrationResult{}, fmt.Errorf("hydrated external evidence bytes do not match the requested exact range receipt")
	}
	return result, nil
}

func validateExternalEvidenceArchiveRequest(in externalEvidenceArchiveRequest, maxBytes int64) error {
	if in.OrganizationID == "" || strings.TrimSpace(in.OrganizationID) != in.OrganizationID {
		return fmt.Errorf("external evidence archive requires a canonical organization coordinate")
	}
	if len(in.SourceBytes) == 0 {
		return fmt.Errorf("external evidence archive refuses an empty source representation")
	}
	if maxBytes <= 0 || int64(len(in.SourceBytes)) > maxBytes {
		return fmt.Errorf("external evidence body exceeds the configured %d-byte archive ceiling", maxBytes)
	}
	if in.SourceContentHashAlgorithm != "sha256" || in.SourceContentHashProfile != externalEvidenceHashProfile {
		return fmt.Errorf("external evidence archive requires the SHA-256 algorithm and exact transport-decoded source hash profile")
	}
	sum := sha256.Sum256(in.SourceBytes)
	if hex.EncodeToString(sum[:]) != in.SourceContentHash {
		return fmt.Errorf("external evidence source digest does not match the bytes submitted for archive")
	}
	for name, value := range map[string]string{
		"body_storage_authorization_reference": in.BodyStorageAuthorizationReference,
		"body_retention_hold_reference":        in.BodyRetentionHoldReference,
		"deletion_domain_id":                   in.DeletionDomainID,
		"crypto_shred_domain_id":               in.CryptoShredDomainID,
	} {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("external evidence archive requires %s", name)
		}
	}
	for name, value := range map[string]string{
		"deletion_domain_id":     in.DeletionDomainID,
		"crypto_shred_domain_id": in.CryptoShredDomainID,
	} {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed.String() != value {
			return fmt.Errorf("external evidence archive %s must be one canonical lowercase UUID", name)
		}
	}
	return nil
}

func validateExternalEvidenceArchiveReceiptForRequest(request externalEvidenceArchiveRequest, receipt externalEvidenceArchiveReceipt) error {
	if err := validateExternalEvidenceArchiveReceipt(receipt); err != nil {
		return err
	}
	if receipt.OrganizationID != request.OrganizationID ||
		receipt.SourceByteLength != int64(len(request.SourceBytes)) ||
		receipt.SourceContentHashAlgorithm != request.SourceContentHashAlgorithm ||
		receipt.SourceContentHashProfile != request.SourceContentHashProfile ||
		receipt.SourceContentHash != request.SourceContentHash ||
		receipt.BodyStorageAuthorizationReference != request.BodyStorageAuthorizationReference ||
		receipt.BodyRetentionHoldReference != request.BodyRetentionHoldReference ||
		receipt.DeletionDomainID != request.DeletionDomainID ||
		receipt.CryptoShredDomainID != request.CryptoShredDomainID {
		return fmt.Errorf("external evidence archive receipt does not bind the exact authorized request")
	}
	return nil
}

func validateExternalEvidenceArchiveReceipt(receipt externalEvidenceArchiveReceipt) error {
	if receipt.OrganizationID == "" || receipt.ArchiveAuthorityID == "" || receipt.FileID == "" || receipt.ExplicitVersion < 1 || receipt.AGFSContentHash == "" || receipt.AGFSBodyReferenceHash == "" || receipt.SourceByteLength <= 0 || receipt.ArchiveRecordDigest == "" {
		return fmt.Errorf("external evidence archive receipt is incomplete")
	}
	if receipt.SourceContentHashAlgorithm != "sha256" || receipt.SourceContentHashProfile != externalEvidenceHashProfile {
		return fmt.Errorf("external evidence archive receipt lacks the canonical source hash contract")
	}
	for name, value := range map[string]string{
		"agfs_content_hash":        receipt.AGFSContentHash,
		"agfs_body_reference_hash": receipt.AGFSBodyReferenceHash,
		"source_content_hash":      receipt.SourceContentHash,
		"archive_record_digest":    receipt.ArchiveRecordDigest,
	} {
		if err := validateExternalContentHash("sha256", value); err != nil {
			return fmt.Errorf("external evidence archive receipt %s: %w", name, err)
		}
	}
	for name, value := range map[string]string{
		"body_storage_authorization_reference": receipt.BodyStorageAuthorizationReference,
		"body_retention_hold_reference":        receipt.BodyRetentionHoldReference,
		"deletion_domain_id":                   receipt.DeletionDomainID,
		"crypto_shred_domain_id":               receipt.CryptoShredDomainID,
	} {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("external evidence archive receipt requires %s", name)
		}
	}
	bodyReferenceHash, err := externalAGFSBodyReferenceHash(receipt)
	if err != nil {
		return err
	}
	if bodyReferenceHash != receipt.AGFSBodyReferenceHash {
		return fmt.Errorf("external evidence AGFS body reference hash mismatch")
	}
	digest, err := externalEvidenceArchiveRecordDigest(receipt)
	if err != nil {
		return err
	}
	if digest != receipt.ArchiveRecordDigest {
		return fmt.Errorf("external evidence archive receipt digest mismatch")
	}
	return nil
}

func externalEvidenceArchiveRecordDigest(receipt externalEvidenceArchiveReceipt) (string, error) {
	if receipt.SourceByteLength < 0 {
		return "", fmt.Errorf("external archive byte count must be nonnegative")
	}
	var preimage bytes.Buffer
	preimage.WriteString("OODGCFE1")
	if err := binary.Write(&preimage, binary.BigEndian, uint32(10)); err != nil {
		return "", err
	}
	fields := []struct {
		name    string
		typeTag byte
		value   []byte
	}{
		{"canonicalization_profile", 0x01, []byte("external_evidence_archive_binding_v1")},
		{"organization_id", 0x01, []byte(receipt.OrganizationID)},
		{"evidence_archive_authority_id", 0x09, nil},
		{"evidence_archive_record_id", 0x09, nil},
		{"source_content_hash_algorithm", 0x01, []byte(receipt.SourceContentHashAlgorithm)},
		{"source_content_hash_profile", 0x01, []byte(receipt.SourceContentHashProfile)},
		{"source_content_hash", 0x08, nil},
		{"evidence_archive_byte_count", 0x03, make([]byte, 8)},
		{"evidence_archive_deletion_domain_id", 0x09, nil},
		{"evidence_archive_crypto_shred_domain_id", 0x09, nil},
	}
	for index, raw := range []string{receipt.ArchiveAuthorityID, receipt.FileID, receipt.DeletionDomainID, receipt.CryptoShredDomainID} {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("external archive UUID field %q is not canonical: %w", raw, err)
		}
		if parsed.String() != raw {
			return "", fmt.Errorf("external archive UUID field %q is not canonical lowercase text", raw)
		}
		fieldIndex := []int{2, 3, 8, 9}[index]
		fields[fieldIndex].value = append([]byte(nil), parsed[:]...)
	}
	digestBytes, err := hex.DecodeString(receipt.SourceContentHash)
	if err != nil {
		return "", fmt.Errorf("decode external archive source digest: %w", err)
	}
	if len(digestBytes) != sha256.Size {
		return "", fmt.Errorf("external archive source digest decodes to %d bytes, want %d", len(digestBytes), sha256.Size)
	}
	fields[6].value = digestBytes
	binary.BigEndian.PutUint64(fields[7].value, uint64(receipt.SourceByteLength))
	for _, field := range fields {
		if err := writeExternalArchiveHashField(&preimage, field.name, field.typeTag, field.value); err != nil {
			return "", err
		}
	}
	sum := sha256.Sum256(preimage.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

func writeExternalArchiveHashField(dst *bytes.Buffer, name string, typeTag byte, value []byte) error {
	if err := binary.Write(dst, binary.BigEndian, uint32(len(name))); err != nil {
		return err
	}
	dst.WriteString(name)
	dst.WriteByte(typeTag)
	dst.WriteByte(0x01)
	if err := binary.Write(dst, binary.BigEndian, uint64(len(value))); err != nil {
		return err
	}
	_, err := dst.Write(value)
	return err
}

func externalAGFSBodyReferenceHash(receipt externalEvidenceArchiveReceipt) (string, error) {
	preimage := struct {
		OrganizationID                    string `json:"organization_id"`
		FileID                            string `json:"file_id"`
		ExplicitVersion                   int64  `json:"explicit_version"`
		ContentHash                       string `json:"content_hash"`
		BodyStorageAuthorizationReference string `json:"body_storage_authorization_reference"`
		BodyRetentionHoldReference        string `json:"body_retention_hold_reference"`
	}{
		OrganizationID: receipt.OrganizationID, FileID: receipt.FileID, ExplicitVersion: receipt.ExplicitVersion,
		ContentHash: receipt.AGFSContentHash, BodyStorageAuthorizationReference: receipt.BodyStorageAuthorizationReference,
		BodyRetentionHoldReference: receipt.BodyRetentionHoldReference,
	}
	canonical, err := canonicalJSON(preimage)
	if err != nil {
		return "", fmt.Errorf("canonicalize AGFS body reference: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
