package oodevidence

import (
	"context"
	"errors"
	"fmt"

	"github.com/velenzaboc/velenza-canon/internal/oodproof"
)

// VerifiedLocatorV8 is minted only after VerifyRelationshipLocator has
// checked the complete batch, archived bytes, locator and eligibility.
type VerifiedLocatorV8 struct {
	organizationID, relationshipHash, locatorHash, sourceStableReference, targetStableReference string
	sourceAPIElementRole, targetAPIElementRole                                                  string
	evidenceLocatorHash, edgeLabel                                                              string
	sourceCoordinate, targetCoordinate                                                          APIElementSourceCoordinate
	sourceRoleManifest, targetRoleManifest                                                      string
	verified                                                                                    bool
	roleManifestsVerified                                                                       bool
}

// APIElementSourceCoordinate is the exact source-owned identity of an endpoint.
// A stable document reference alone cannot distinguish two symbols in that document.
type APIElementSourceCoordinate struct {
	ObjectClass, AuthorityID, RefKind, StableReference, VersionCoordinate, SectionPath string
}

// APIElementRoleBinding separates classification evidence from the evidence
// establishing a relationship between two classified symbols.
type APIElementRoleBinding struct{ Role, LocatorManifestHash string }

func (v VerifiedLocatorV8) EvidenceLocatorHash() string                  { return v.evidenceLocatorHash }
func (v VerifiedLocatorV8) EdgeLabel() string                            { return v.edgeLabel }
func (v VerifiedLocatorV8) SourceCoordinate() APIElementSourceCoordinate { return v.sourceCoordinate }
func (v VerifiedLocatorV8) TargetCoordinate() APIElementSourceCoordinate { return v.targetCoordinate }
func (v VerifiedLocatorV8) SourceRoleBinding() APIElementRoleBinding {
	return APIElementRoleBinding{v.sourceAPIElementRole, v.sourceRoleManifest}
}
func (v VerifiedLocatorV8) TargetRoleBinding() APIElementRoleBinding {
	return APIElementRoleBinding{v.targetAPIElementRole, v.targetRoleManifest}
}

func (v VerifiedLocatorV8) OrganizationID() string        { return v.organizationID }
func (v VerifiedLocatorV8) RelationshipHash() string      { return v.relationshipHash }
func (v VerifiedLocatorV8) LocatorHash() string           { return v.locatorHash }
func (v VerifiedLocatorV8) SourceStableReference() string { return v.sourceStableReference }
func (v VerifiedLocatorV8) TargetStableReference() string { return v.targetStableReference }
func (v VerifiedLocatorV8) SourceAPIElementRole() string  { return v.sourceAPIElementRole }
func (v VerifiedLocatorV8) TargetAPIElementRole() string  { return v.targetAPIElementRole }
func ValidateVerifiedLocatorV8(v VerifiedLocatorV8) error {
	if !v.verified || v.organizationID == "" || v.relationshipHash == "" || v.locatorHash == "" {
		return errors.New("verified OOD8 locator proof absent")
	}
	return nil
}

// ValidateVerifiedAPIRoleLocatorV8 is stricter than the generic relationship
// locator proof: API materialization must have exact native endpoint roles.
func ValidateVerifiedAPIRoleLocatorV8(v VerifiedLocatorV8) error {
	if err := ValidateVerifiedLocatorV8(v); err != nil {
		return err
	}
	if !v.roleManifestsVerified || v.sourceAPIElementRole == "" || v.targetAPIElementRole == "" || v.sourceRoleManifest == "" || v.targetRoleManifest == "" || v.evidenceLocatorHash == "" {
		return errors.New("verified OOD8 API role derivation absent")
	}
	return nil
}

// APIElementRoleDerivationAuthority verifies the native classified output
// which assigned a source-neutral role to each relationship endpoint.  This
// is intentionally not a caller-owned boolean: implementations must bind the
// exact role/profile/locator to the protected native derivation artifact.
type APIElementRoleDerivationAuthority interface {
	VerifyNativeAPIElementRoles(context.Context, RelationshipV8, VerifiedBatchV8, oodproof.GraphFactLocator, string, string) error
}

func VerifyRelationshipLocatorV8(ctx context.Context, r RelationshipV8, batch VerifiedBatchV8, locator oodproof.GraphFactLocator, archivedBody []byte, eligibility ProfileEligibilityAuthority) (VerifiedLocatorV8, error) {
	if err := VerifyRelationshipLocator(ctx, r, batch, locator, archivedBody, eligibility); err != nil {
		return VerifiedLocatorV8{}, err
	}
	if r.GraphFactLocatorManifestHash == nil {
		return VerifiedLocatorV8{}, errors.New("relationship locator manifest hash absent")
	}
	return VerifiedLocatorV8{organizationID: r.OrganizationID, relationshipHash: r.RelationshipEvidenceHash, locatorHash: *r.GraphFactLocatorManifestHash, evidenceLocatorHash: locator.LocatorHash, edgeLabel: r.EdgeLabel, sourceStableReference: r.SourceStableReference, targetStableReference: r.TargetStableReference,
		sourceCoordinate: APIElementSourceCoordinate{r.SourceObjectClass, r.SourceAuthorityID, r.SourceRefKind, r.SourceStableReference, r.SourceVersionCoordinate, r.SourceSectionPath},
		targetCoordinate: APIElementSourceCoordinate{r.TargetObjectClass, r.TargetAuthorityID, r.TargetRefKind, r.TargetStableReference, r.TargetVersionCoordinate, r.TargetSectionPath}, verified: true}, nil
}

// VerifyRelationshipLocatorWithAPIRolesV8 retains legacy role diagnostics.
// Its output is ineligible for API materialization because this older authority
// does not independently bind each endpoint's classification manifest.
func VerifyRelationshipLocatorWithAPIRolesV8(ctx context.Context, r RelationshipV8, batch VerifiedBatchV8, locator oodproof.GraphFactLocator, archivedBody []byte, sourceRole, targetRole string, roles APIElementRoleDerivationAuthority, eligibility ProfileEligibilityAuthority) (VerifiedLocatorV8, error) {
	if roles == nil {
		return VerifiedLocatorV8{}, errors.New("native API role derivation authority unavailable")
	}
	v, err := VerifyRelationshipLocatorV8(ctx, r, batch, locator, archivedBody, eligibility)
	if err != nil {
		return VerifiedLocatorV8{}, err
	}
	if sourceRole == "" || targetRole == "" {
		return VerifiedLocatorV8{}, errors.New("native API role derivation is incomplete")
	}
	if err := roles.VerifyNativeAPIElementRoles(ctx, r, batch, locator, sourceRole, targetRole); err != nil {
		return VerifiedLocatorV8{}, fmt.Errorf("native API role derivation: %w", err)
	}
	v.sourceAPIElementRole, v.targetAPIElementRole = sourceRole, targetRole
	return v, nil
}

// APIElementRoleManifestDerivationAuthority verifies the exact admitted native
// classification bindings, including the distinct evidence roots for each role.
type APIElementRoleManifestDerivationAuthority interface {
	VerifyNativeAPIElementRoleManifests(context.Context, RelationshipV8, VerifiedBatchV8, oodproof.GraphFactLocator, APIElementRoleBinding, APIElementRoleBinding) error
}

func VerifyRelationshipLocatorWithAPIRoleManifestsV8(ctx context.Context, r RelationshipV8, batch VerifiedBatchV8, locator oodproof.GraphFactLocator, archivedBody []byte, source, target APIElementRoleBinding, roles APIElementRoleManifestDerivationAuthority, eligibility ProfileEligibilityAuthority) (VerifiedLocatorV8, error) {
	if roles == nil || source.Role == "" || target.Role == "" || source.LocatorManifestHash == "" || target.LocatorManifestHash == "" {
		return VerifiedLocatorV8{}, errors.New("native API role manifest authority or binding absent")
	}
	v, err := VerifyRelationshipLocatorV8(ctx, r, batch, locator, archivedBody, eligibility)
	if err != nil {
		return VerifiedLocatorV8{}, err
	}
	if err := roles.VerifyNativeAPIElementRoleManifests(ctx, r, batch, locator, source, target); err != nil {
		return VerifiedLocatorV8{}, fmt.Errorf("native API role manifest derivation: %w", err)
	}
	v.sourceAPIElementRole, v.targetAPIElementRole = source.Role, target.Role
	v.sourceRoleManifest, v.targetRoleManifest = source.LocatorManifestHash, target.LocatorManifestHash
	v.roleManifestsVerified = true
	return v, nil
}
