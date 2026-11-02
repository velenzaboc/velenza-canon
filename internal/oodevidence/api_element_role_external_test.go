package oodevidence_test

import (
	"context"
	"errors"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodproof"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

type apiElementRoleAuthority struct {
	coordinate oodevidence.APIElementSourceCoordinate
	binding    oodevidence.APIElementRoleBinding
}

func (a apiElementRoleAuthority) VerifyNativeAPIElementRole(_ context.Context, _ oodevidence.VerifiedBatchV8, _ oodproof.GraphFactLocator, coordinate oodevidence.APIElementSourceCoordinate, binding oodevidence.APIElementRoleBinding) error {
	if coordinate != a.coordinate || binding != a.binding {
		return errors.New("unexpected classified API role")
	}
	return nil
}
func (a apiElementRoleAuthority) VerifyCurrentAPIElementRoleEligibility(_ context.Context, coordinate oodevidence.APIElementSourceCoordinate, binding oodevidence.APIElementRoleBinding, receipt oodevidence.ReceiptV8, batch oodevidence.BatchV8) error {
	if coordinate != a.coordinate || binding != a.binding || receipt.OrganizationID == "" || receipt.FetchBatchID != batch.FetchBatchID {
		return errors.New("unexpected current API role eligibility tuple")
	}
	return nil
}

func TestAPIElementRoleProofBindsExactQualifiedLocatorAndClassification(t *testing.T) {
	ctx := context.Background()
	f := oodtestfixture.Build(ctx, t)
	body := []byte("canonical archived API evidence")
	coordinate := oodevidence.APIElementSourceCoordinate{ObjectClass: "api_symbol", AuthorityID: f.Receipt.SourceAuthorityID, RefKind: f.Receipt.SourceRefKind, StableReference: f.Receipt.SourceStableReference, VersionCoordinate: f.Receipt.VersionCoordinate, SectionPath: "/fixture/api"}
	binding := oodevidence.APIElementRoleBinding{Role: "operation", LocatorManifestHash: f.Locator.LocatorHash}
	authority := apiElementRoleAuthority{coordinate: coordinate, binding: binding}
	proof, err := oodevidence.VerifyAPIElementRoleV8(ctx, f.Batch, f.Locator, body, coordinate, binding, authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := oodevidence.ValidateVerifiedAPIElementRoleV8(proof); err != nil || proof.OrganizationID() != f.Receipt.OrganizationID || proof.EvidenceLocatorHash() != f.Locator.LocatorHash || proof.SourceCoordinate() != coordinate || proof.RoleBinding() != binding || proof.SourceContentHashAlgorithm() != f.Receipt.SourceContentHashAlgorithm || proof.SourceContentHashProfile() != f.Receipt.SourceContentHashProfile || proof.SourceContentHash() != f.Receipt.SourceContentHash {
		t.Fatalf("exact API element proof lost: %v", err)
	}
	if err := oodevidence.ValidateVerifiedAPIElementRoleV8(oodevidence.VerifiedAPIElementRoleV8{}); err == nil {
		t.Fatal("zero API element proof accepted")
	}
	for name, mutate := range map[string]func(*oodevidence.APIElementSourceCoordinate, *oodevidence.APIElementRoleBinding, *[]byte){
		"wrong source": func(c *oodevidence.APIElementSourceCoordinate, _ *oodevidence.APIElementRoleBinding, _ *[]byte) {
			c.AuthorityID = "11111111-1111-4111-8111-111111111111"
		},
		"wrong manifest": func(_ *oodevidence.APIElementSourceCoordinate, b *oodevidence.APIElementRoleBinding, _ *[]byte) {
			b.LocatorManifestHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"wrong role": func(_ *oodevidence.APIElementSourceCoordinate, b *oodevidence.APIElementRoleBinding, _ *[]byte) {
			b.Role = "resource"
		},
		"altered body": func(_ *oodevidence.APIElementSourceCoordinate, _ *oodevidence.APIElementRoleBinding, body *[]byte) {
			*body = []byte("altered archive")
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, b, archived := coordinate, binding, append([]byte(nil), body...)
			mutate(&c, &b, &archived)
			if _, err := oodevidence.VerifyAPIElementRoleV8(ctx, f.Batch, f.Locator, archived, c, b, authority); err == nil {
				t.Fatal("substituted API element role proof accepted")
			}
		})
	}
	foreign := f.Locator
	foreign.OrganizationID = "11111111-1111-4111-8111-111111111111"
	var errHash error
	foreign.LocatorHash, errHash = foreign.ComputedHash()
	if errHash != nil {
		t.Fatal(errHash)
	}
	if _, err := oodevidence.VerifyAPIElementRoleV8(ctx, f.Batch, foreign, body, coordinate, binding, authority); err == nil {
		t.Fatal("foreign-tenant locator accepted as an API element role proof")
	}
}
