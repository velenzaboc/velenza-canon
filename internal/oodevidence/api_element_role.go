package oodevidence

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/velenzaboc/velenza-canon/internal/oodproof"
)

// APIElementRoleEvidenceAuthority is the narrow admitted authority for one
// independently classified API symbol. It verifies the exact native
// classification manifest/proof and its current eligibility; it does not
// receive graph rows, publication authority, or a caller-selected coordinate.
type APIElementRoleEvidenceAuthority interface {
	VerifyNativeAPIElementRole(context.Context, VerifiedBatchV8, oodproof.GraphFactLocator, APIElementSourceCoordinate, APIElementRoleBinding) error
	VerifyCurrentAPIElementRoleEligibility(context.Context, APIElementSourceCoordinate, APIElementRoleBinding, ReceiptV8, BatchV8) error
}

// VerifiedAPIElementRoleV8 is an opaque proof for a single API-symbol role.
// Relationship proofs cannot be substituted for it: this proof has exactly
// one source coordinate, role binding, primary graph-fact locator and receipt.
type VerifiedAPIElementRoleV8 struct {
	organizationID, locatorHash, evidenceLocatorHash                        string
	sourceContentHashAlgorithm, sourceContentHashProfile, sourceContentHash string
	coordinate                                                              APIElementSourceCoordinate
	binding                                                                 APIElementRoleBinding
	verified                                                                bool
}

func (v VerifiedAPIElementRoleV8) OrganizationID() string      { return v.organizationID }
func (v VerifiedAPIElementRoleV8) LocatorHash() string         { return v.locatorHash }
func (v VerifiedAPIElementRoleV8) EvidenceLocatorHash() string { return v.evidenceLocatorHash }
func (v VerifiedAPIElementRoleV8) SourceContentHashAlgorithm() string {
	return v.sourceContentHashAlgorithm
}
func (v VerifiedAPIElementRoleV8) SourceContentHashProfile() string {
	return v.sourceContentHashProfile
}
func (v VerifiedAPIElementRoleV8) SourceContentHash() string                    { return v.sourceContentHash }
func (v VerifiedAPIElementRoleV8) SourceCoordinate() APIElementSourceCoordinate { return v.coordinate }
func (v VerifiedAPIElementRoleV8) RoleBinding() APIElementRoleBinding           { return v.binding }

func ValidateVerifiedAPIElementRoleV8(v VerifiedAPIElementRoleV8) error {
	if !v.verified || v.organizationID == "" || v.locatorHash == "" || v.evidenceLocatorHash == "" || v.sourceContentHashAlgorithm == "" || v.sourceContentHashProfile == "" || !lowerSHA256.MatchString(v.sourceContentHash) || !validAPIElementCoordinate(v.coordinate) || v.binding.Role == "" || !lowerSHA256.MatchString(v.binding.LocatorManifestHash) {
		return errors.New("verified OOD8 API element role proof absent")
	}
	return nil
}

var lowerSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validAPIElementCoordinate(c APIElementSourceCoordinate) bool {
	return c.ObjectClass == "api_symbol" && c.AuthorityID != "" && c.RefKind != "" && c.StableReference != "" && c.VersionCoordinate != "" && c.SectionPath != ""
}

// VerifyAPIElementRoleV8 proves an independently classified API symbol from
// exact archived bytes. It first re-verifies the batch/receipt/archive/range
// binding and then asks only the admitted role authority to verify the native
// classification and currentness of that same tuple.
func VerifyAPIElementRoleV8(ctx context.Context, batch VerifiedBatchV8, locator oodproof.GraphFactLocator, archivedBody []byte, coordinate APIElementSourceCoordinate, binding APIElementRoleBinding, authority APIElementRoleEvidenceAuthority) (VerifiedAPIElementRoleV8, error) {
	if authority == nil || !validAPIElementCoordinate(coordinate) || binding.Role == "" || !lowerSHA256.MatchString(binding.LocatorManifestHash) {
		return VerifiedAPIElementRoleV8{}, errors.New("native API element role authority, coordinate, or binding absent")
	}
	receipt, err := verifyGraphFactLocatorReceipt(ctx, batch, locator, archivedBody)
	if err != nil {
		return VerifiedAPIElementRoleV8{}, err
	}
	if coordinate.AuthorityID != receipt.SourceAuthorityID || coordinate.RefKind != receipt.SourceRefKind || coordinate.StableReference != receipt.SourceStableReference || coordinate.VersionCoordinate != receipt.VersionCoordinate {
		return VerifiedAPIElementRoleV8{}, errors.New("API element role source coordinate does not equal qualified receipt")
	}
	if err := authority.VerifyNativeAPIElementRole(ctx, batch, locator, coordinate, binding); err != nil {
		return VerifiedAPIElementRoleV8{}, fmt.Errorf("native API element role classification: %w", err)
	}
	if err := authority.VerifyCurrentAPIElementRoleEligibility(ctx, coordinate, binding, receipt, batch.batch); err != nil {
		return VerifiedAPIElementRoleV8{}, fmt.Errorf("current API element role eligibility: %w", err)
	}
	return VerifiedAPIElementRoleV8{organizationID: receipt.OrganizationID, locatorHash: binding.LocatorManifestHash, evidenceLocatorHash: locator.LocatorHash, sourceContentHashAlgorithm: receipt.SourceContentHashAlgorithm, sourceContentHashProfile: receipt.SourceContentHashProfile, sourceContentHash: receipt.SourceContentHash, coordinate: coordinate, binding: binding, verified: true}, nil
}
