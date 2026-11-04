package oodevidence_test

import (
	"context"
	"errors"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodproof"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

type testRoleAuthority struct {
	source, target oodevidence.APIElementRoleBinding
}

func (a testRoleAuthority) VerifyNativeAPIElementRoles(context.Context, oodevidence.RelationshipV8, oodevidence.VerifiedBatchV8, oodproof.GraphFactLocator, string, string) error {
	return nil
}
func (a testRoleAuthority) VerifyCurrentRelationshipEligibility(context.Context, oodevidence.RelationshipV8, oodevidence.ReceiptV8, oodevidence.BatchV8) error {
	return nil
}
func (a testRoleAuthority) VerifyNativeAPIElementRoleManifests(_ context.Context, _ oodevidence.RelationshipV8, _ oodevidence.VerifiedBatchV8, _ oodproof.GraphFactLocator, source, target oodevidence.APIElementRoleBinding) error {
	if source != a.source || target != a.target {
		return errors.New("test-owned role manifest mismatch")
	}
	return nil
}

func TestAPIRoleProofRequiresIndependentManifestAuthority(t *testing.T) {
	ctx := context.Background()
	f := oodtestfixture.Build(ctx, t)
	body := []byte("canonical archived API evidence")
	a := testRoleAuthority{source: oodevidence.APIElementRoleBinding{Role: "operation", LocatorManifestHash: *f.Relationship.GraphFactLocatorManifestHash}, target: oodevidence.APIElementRoleBinding{Role: "resource", LocatorManifestHash: *f.Relationship.GraphFactLocatorManifestHash}}
	legacy, err := oodevidence.VerifyRelationshipLocatorWithAPIRolesV8(ctx, f.Relationship, f.Batch, f.Locator, body, "operation", "resource", a, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := oodevidence.ValidateVerifiedAPIRoleLocatorV8(legacy); err == nil {
		t.Fatal("legacy role proof manufactured classification manifest authority")
	}
	proof, err := oodevidence.VerifyRelationshipLocatorWithAPIRoleManifestsV8(ctx, f.Relationship, f.Batch, f.Locator, body, a.source, a.target, a, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := oodevidence.ValidateVerifiedAPIRoleLocatorV8(proof); err != nil {
		t.Fatal(err)
	}
	changed := a.source
	changed.LocatorManifestHash = f.Locator.SourceContentHash
	if _, err := oodevidence.VerifyRelationshipLocatorWithAPIRoleManifestsV8(ctx, f.Relationship, f.Batch, f.Locator, body, changed, a.target, a, a); err == nil {
		t.Fatal("substituted classification manifest inherited authority")
	}
}

func TestGraphFactLocatorProofBindsArchiveAndCompleteBatch(t *testing.T) {
	ctx := context.Background()
	f := oodtestfixture.Build(ctx, t)
	body := []byte("canonical archived API evidence")
	p, err := oodevidence.VerifyGraphFactLocatorV8(ctx, f.Batch, f.Locator, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := oodevidence.ValidateVerifiedGraphFactLocatorV8(p); err != nil || p.OrganizationID() != f.Receipt.OrganizationID || p.LocatorHash() != f.Locator.LocatorHash {
		t.Fatalf("exact proof lost: %v", err)
	}
	for name, mutate := range map[string]func(*oodproof.GraphFactLocator){
		"foreign receipt":           func(l *oodproof.GraphFactLocator) { l.EligibleReceiptID = "11111111-1111-4111-8111-111111111111" },
		"archive substitution":      func(l *oodproof.GraphFactLocator) { l.EvidenceArchiveRecordDigest = l.SourceContentHash },
		"range substitution":        func(l *oodproof.GraphFactLocator) { l.ByteEndOffsetExclusive-- },
		"completeness substitution": func(l *oodproof.GraphFactLocator) { l.SealedCompletenessCertificateHash = l.SourceContentHash },
	} {
		t.Run(name, func(t *testing.T) {
			l := f.Locator
			mutate(&l)
			l.LocatorHash, err = l.ComputedHash()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := oodevidence.VerifyGraphFactLocatorV8(ctx, f.Batch, l, body); err == nil {
				t.Fatal("correlated locator substitution accepted")
			}
		})
	}
	if _, err := oodevidence.VerifyGraphFactLocatorV8(ctx, f.Batch, f.Locator, []byte("altered archive")); err == nil {
		t.Fatal("changed archive accepted")
	}
	if _, err := oodevidence.VerifyGraphFactLocatorV8(ctx, oodevidence.VerifiedBatchV8{}, f.Locator, body); err == nil {
		t.Fatal("unverified batch accepted")
	}
}
