package oodevidence_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

type mutatingClosureAuthority struct {
	expected       oodevidence.ClosureCertificateV8
	original       *oodevidence.ClosureCertificateV8
	mutateOriginal bool
}

func (a mutatingClosureAuthority) VerifyCompleteManifestClosure(_ context.Context, c oodevidence.ClosureCertificateV8) error {
	c.Roots["object"] = oodevidence.ClosureRoot{Hash: "mutated", Count: -1}
	if a.mutateOriginal {
		a.original.Roots["object"] = oodevidence.ClosureRoot{Hash: "caller-mutated", Count: -1}
	}
	return nil
}
func (a mutatingClosureAuthority) VerifyClosureAttestation(_ context.Context, c oodevidence.ClosureCertificateV8) error {
	if c.Roots["object"] != a.expected.Roots["object"] {
		return fmt.Errorf("traversal callback altered attestation input")
	}
	c.Roots["object"] = oodevidence.ClosureRoot{Hash: "attestor-mutated", Count: -1}
	return nil
}

func TestClosureCallbacksCannotRewriteVerifiedCertificate(t *testing.T) {
	for _, mutateOriginal := range []bool{false, true} {
		f := oodtestfixture.Build(context.Background(), t)
		expected := oodevidence.CloneClosureCertificateV8(f.Certificate)
		a := mutatingClosureAuthority{expected: expected, original: &f.Certificate, mutateOriginal: mutateOriginal}
		p, err := oodevidence.VerifyClosureV8(context.Background(), f.Certificate, a)
		if err != nil {
			t.Fatal(err)
		}
		if p.ClosureHash() != expected.ClosureHash || p.CertificateHash() != expected.VerificationCertificateHash {
			t.Fatal("callback changed retained proof binding")
		}
		if !mutateOriginal && f.Certificate.Roots["object"] != expected.Roots["object"] {
			t.Fatal("callback changed caller certificate map")
		}
	}
}
