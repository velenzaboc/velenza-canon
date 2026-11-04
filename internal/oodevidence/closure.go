package oodevidence

import (
	"context"
	"errors"
	"fmt"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
)

// ClosureRoot is one of OOD8's fixed nine roots. The exact name set is
// intentionally closed by closureRecord below.
type ClosureRoot struct {
	Hash  string
	Count int64
}
type ClosureCertificateV8 struct {
	OrganizationID, MaterializationRunID, SnapshotKind, SourceSetHash                                        string
	Roots                                                                                                    map[string]ClosureRoot
	SourceArtifactCount, RelationshipEvidenceCount                                                           int64
	RelationshipIdentitySetHash, SourceAuthorityIdentitySetHash                                              string
	SourceAuthorityIdentityCount                                                                             int64
	CompletenessIdentitySetHash                                                                              string
	CompletenessIdentityCount                                                                                int64
	PermissionPolicyIdentitySetHash                                                                          string
	PermissionPolicyIdentityCount                                                                            int64
	ArchiveBindingIdentitySetHash                                                                            string
	ArchiveBindingIdentityCount                                                                              int64
	ProfileIdentitySetHash                                                                                   string
	ProfileIdentityCount                                                                                     int64
	ExternalSourceReceiptEligibilitySetHash                                                                  string
	ExternalSourceReceiptEligibilityCount                                                                    int64
	MaterializationProfileID, MaterializationProfileVersion, MaterializationProfileDigest                    string
	PublicationBudgetProfileRef, PublicationBudgetProfileDigest                                              string
	ManifestHashAlgorithm, ManifestHashProfile, ManifestHashContractDigest                                   string
	ClosureHashAlgorithm, ClosureHashProfile, ClosureHashContractDigest                                      string
	VerifierCapabilityName, VerifierCapabilityVersion, VerifierCapabilityDigest                              string
	VerificationPolicyRef, VerificationPolicyDigest                                                          string
	ClosureHash, VerificationCertificateHash                                                                 string
	VerificationCertificateID, AttestationAuthorityID, AttestationRef, AttestationDigest, AttestationProfile string
}

var closureRootFields = []string{"source", "object", "symbol", "edge", "api_property", "graph_fact_locator", "receipt", "structural_projection", "violation"}

// ManifestClosureAuthority is the protected OOD owner that performs the
// bounded strong-read traversal outside the final publication RWT. It cannot
// be replaced with caller strings or a boolean assertion.
type ManifestClosureAuthority interface {
	VerifyCompleteManifestClosure(context.Context, ClosureCertificateV8) error
	VerifyClosureAttestation(context.Context, ClosureCertificateV8) error
}
type VerifiedClosureV8 struct {
	organizationID, certificateID, certificateHash, closureHash string
	verified                                                    bool
}

func (v VerifiedClosureV8) OrganizationID() string  { return v.organizationID }
func (v VerifiedClosureV8) CertificateID() string   { return v.certificateID }
func (v VerifiedClosureV8) CertificateHash() string { return v.certificateHash }

// ClosureHash is retained from the verified certificate.  It is deliberately
// an accessor rather than caller supplied publication material.
func (v VerifiedClosureV8) ClosureHash() string { return v.closureHash }
func ValidateVerifiedClosureV8(v VerifiedClosureV8) error {
	if !v.verified || v.organizationID == "" || v.certificateID == "" || v.certificateHash == "" || v.closureHash == "" {
		return errors.New("verified OOD8 closure proof absent")
	}
	return nil
}

func ClosureHashV8(c ClosureCertificateV8) (string, error) {
	p, e := oodcanon.ProfileFor("ood_graph_content_closure_v1")
	if e != nil {
		return "", e
	}
	r, e := closureRecord(c)
	if e != nil {
		return "", e
	}
	return oodcanon.DigestHexOf(p, r)
}
func CertificateHashV8(c ClosureCertificateV8) (string, error) {
	p, e := oodcanon.ProfileFor("ood_graph_closure_verification_certificate_v1")
	if e != nil {
		return "", e
	}
	r, e := certificateRecord(c)
	if e != nil {
		return "", e
	}
	return oodcanon.DigestHexOf(p, r)
}
func VerifyClosureV8(ctx context.Context, c ClosureCertificateV8, authority ManifestClosureAuthority) (VerifiedClosureV8, error) {
	c = CloneClosureCertificateV8(c)
	if authority == nil {
		return VerifiedClosureV8{}, errors.New("closure authority unavailable")
	}
	if len(c.Roots) != len(closureRootFields) || c.VerificationCertificateID == "" || c.AttestationAuthorityID == "" || c.AttestationRef == "" || c.AttestationDigest == "" || c.AttestationProfile == "" {
		return VerifiedClosureV8{}, errors.New("closure certificate attestation or root set incomplete")
	}
	h, e := ClosureHashV8(c)
	if e != nil {
		return VerifiedClosureV8{}, e
	}
	if h != c.ClosureHash {
		return VerifiedClosureV8{}, errors.New("closure hash mismatch")
	}
	ch, e := CertificateHashV8(c)
	if e != nil {
		return VerifiedClosureV8{}, e
	}
	if ch != c.VerificationCertificateHash {
		return VerifiedClosureV8{}, errors.New("certificate hash mismatch")
	}
	if e = authority.VerifyCompleteManifestClosure(ctx, CloneClosureCertificateV8(c)); e != nil {
		return VerifiedClosureV8{}, fmt.Errorf("strong closure traversal: %w", e)
	}
	// The attestor is an external capability. It must not receive aliases to
	// the certificate retained by this verifier or its caller.
	if e = authority.VerifyClosureAttestation(ctx, CloneClosureCertificateV8(c)); e != nil {
		return VerifiedClosureV8{}, fmt.Errorf("closure attestation: %w", e)
	}
	return VerifiedClosureV8{organizationID: c.OrganizationID, certificateID: c.VerificationCertificateID, certificateHash: ch, closureHash: c.ClosureHash, verified: true}, nil
}

func closureRecord(c ClosureCertificateV8) (oodcanon.RecordValue, error) {
	v := oodcanon.RecordValue{}
	if e := addStrings(v, map[string]string{"organization_id": c.OrganizationID, "publication_budget_profile_ref": c.PublicationBudgetProfileRef, "materialization_profile_version": c.MaterializationProfileVersion}); e != nil {
		return nil, e
	}
	if e := addUUIDs(v, map[string]string{"materialization_profile_id": c.MaterializationProfileID}); e != nil {
		return nil, e
	}
	if e := addDigests(v, map[string]string{"source_set_hash": c.SourceSetHash, "materialization_profile_digest": c.MaterializationProfileDigest, "publication_budget_profile_digest": c.PublicationBudgetProfileDigest}); e != nil {
		return nil, e
	}
	for _, n := range closureRootFields {
		x, ok := c.Roots[n]
		if !ok || x.Count < 0 {
			return nil, fmt.Errorf("missing closure root %s", n)
		}
		d, e := oodcanon.DigestHex(x.Hash)
		if e != nil {
			return nil, e
		}
		if n == "source" {
			if x.Count != c.SourceArtifactCount+c.RelationshipEvidenceCount || c.SourceArtifactCount < 0 || c.RelationshipEvidenceCount < 0 {
				return nil, errors.New("source root count mismatch")
			}
			v["source_manifest_root_hash"], v["source_artifact_count"], v["relationship_evidence_count"] = d, oodcanon.I64(c.SourceArtifactCount), oodcanon.I64(c.RelationshipEvidenceCount)
		} else {
			v[n+"_manifest_root_hash"], v[n+"_count"] = d, oodcanon.I64(x.Count)
		}
	}
	return v, nil
}
func certificateRecord(c ClosureCertificateV8) (oodcanon.RecordValue, error) {
	v, e := closureRecord(c)
	if e != nil {
		return nil, e
	}
	delete(v, "publication_budget_profile_ref")
	delete(v, "publication_budget_profile_digest")
	v["materialization_run_id"], e = oodcanon.UUIDText(c.MaterializationRunID)
	if e != nil {
		return nil, e
	}
	v["snapshot_kind"] = oodcanon.String(c.SnapshotKind)
	for k, s := range map[string]string{"relationship_identity_set_hash": c.RelationshipIdentitySetHash, "source_authority_identity_set_hash": c.SourceAuthorityIdentitySetHash, "completeness_identity_set_hash": c.CompletenessIdentitySetHash, "permission_policy_identity_set_hash": c.PermissionPolicyIdentitySetHash, "archive_binding_identity_set_hash": c.ArchiveBindingIdentitySetHash, "profile_identity_set_hash": c.ProfileIdentitySetHash, "external_source_receipt_eligibility_set_hash": c.ExternalSourceReceiptEligibilitySetHash, "manifest_hash_contract_digest": c.ManifestHashContractDigest, "closure_hash_contract_digest": c.ClosureHashContractDigest, "verifier_capability_digest": c.VerifierCapabilityDigest, "verification_policy_digest": c.VerificationPolicyDigest, "closure_hash": c.ClosureHash} {
		x, er := oodcanon.DigestHex(s)
		if er != nil {
			return nil, er
		}
		v[k] = x
	}
	for k, n := range map[string]int64{"source_authority_identity_count": c.SourceAuthorityIdentityCount, "completeness_identity_count": c.CompletenessIdentityCount, "permission_policy_identity_count": c.PermissionPolicyIdentityCount, "archive_binding_identity_count": c.ArchiveBindingIdentityCount, "profile_identity_count": c.ProfileIdentityCount, "external_source_receipt_eligibility_count": c.ExternalSourceReceiptEligibilityCount} {
		v[k] = oodcanon.I64(n)
	}
	for k, s := range map[string]string{"manifest_hash_algorithm": c.ManifestHashAlgorithm, "manifest_hash_profile": c.ManifestHashProfile, "closure_hash_algorithm": c.ClosureHashAlgorithm, "closure_hash_profile": c.ClosureHashProfile, "verifier_capability_name": c.VerifierCapabilityName, "verifier_capability_version": c.VerifierCapabilityVersion, "verification_policy_ref": c.VerificationPolicyRef} {
		v[k] = oodcanon.String(s)
	}
	v["publication_budget_profile_ref"] = oodcanon.String(c.PublicationBudgetProfileRef)
	publicationBudgetDigest, er := oodcanon.DigestHex(c.PublicationBudgetProfileDigest)
	if er != nil {
		return nil, er
	}
	v["publication_budget_profile_digest"] = publicationBudgetDigest
	return v, nil
}
