package main

import (
	"context"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
	"testing"
)

func buildOOD8AllRootsManifestFixture(t *testing.T) (OOD8APIClosureMaterializationInput, oodevidence.VerifiedClosureV8) {
	t.Helper()
	f := oodtestfixture.Build(context.Background(), t)
	return OOD8APIClosureMaterializationInput{Certificate: f.Certificate, Closure: f.Closure, Attestor: f.Attestor, Factory: OOD8APIFactoryOutput{LocatorProofs: f.LocatorProofs, EvidenceLocatorProofs: f.EvidenceLocatorProofs, Plan: f.Plan}}, f.Proof
}

func TestOOD8AllRootsManifestFixtureBuildsVerifiedClosure(t *testing.T) {
	_, proof := buildOOD8AllRootsManifestFixture(t)
	if err := oodevidence.ValidateVerifiedClosureV8(proof); err != nil {
		t.Fatal(err)
	}
}
