package main

import (
	"context"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

func TestDocumentationFactoryOODPreparationRefusesBeforeAuthorityWhenProtectedCompilerIsUnavailable(t *testing.T) {
	boot, err := NewDocumentationFactoryOODPreparationBoot(providerplan.DocumentationFactoryProductionSourceProtectedLauncher{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = boot.PrepareDocumentationFactoryOOD(context.Background(), providerplan.DocumentationFactoryProductionSourceCompileOptions{})
	if err == nil {
		t.Fatal("unconfigured protected compiler was accepted")
	}
}

func TestDocumentationFactoryOODPreparationRejectsNilContextBeforeProtectedCompilation(t *testing.T) {
	boot, err := NewDocumentationFactoryOODPreparationBoot(providerplan.DocumentationFactoryProductionSourceProtectedLauncher{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = boot.PrepareDocumentationFactoryOOD(nil, providerplan.DocumentationFactoryProductionSourceCompileOptions{})
	if err == nil {
		t.Fatal("nil context was accepted")
	}
}

// This is the final no-write boundary used by the boot pipeline after the
// protected compiler and concrete successor builder return their opaque proof
// values. It deliberately uses the real nine-root fixture rather than a
// manually asserted closure/roster.
func TestDocumentationFactoryOODPreparationAcceptsCompleteOpaqueSuccessorPlan(t *testing.T) {
	fixture, roster := factoryOODPreparationFixture(t)
	materialization, err := BuildVerifiedOOD8APIMaterialization(context.Background(), OOD8APINativeMaterializationOutput{
		Closure: fixture.Proof,
		Roster:  roster,
		Factory: OOD8APIFactoryOutput{Plan: fixture.Plan, LocatorProofs: fixture.LocatorProofs, EvidenceLocatorProofs: fixture.EvidenceLocatorProofs},
	})
	if err != nil {
		t.Fatalf("complete protected successor plan was refused: %v", err)
	}
	if materialization.plan.ClosureHash != fixture.Proof.ClosureHash() {
		t.Fatal("opaque preparation lost the verified closure binding")
	}
}

func TestOOD8MaterializationRejectsLocatorFieldSubstitution(t *testing.T) {
	fixture, roster := factoryOODPreparationFixture(t)
	plan := fixture.Plan
	for i := range plan.ImmutableRows {
		if plan.ImmutableRows[i].Table == "OODGraphObjects" {
			plan.ImmutableRows[i].Columns["api_element_role_locator_manifest_hash"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			break
		}
	}
	if _, err := BuildVerifiedOOD8APIMaterialization(context.Background(), OOD8APINativeMaterializationOutput{Closure: fixture.Proof, Roster: roster, Factory: OOD8APIFactoryOutput{Plan: plan, LocatorProofs: fixture.LocatorProofs, EvidenceLocatorProofs: fixture.EvidenceLocatorProofs}}); err == nil {
		t.Fatal("correlated locator substitution was accepted")
	}
}

func factoryOODPreparationFixture(t *testing.T) (oodtestfixture.Fixture, oodevidence.VerifiedPublicationRosterV8) {
	t.Helper()
	fixture := oodtestfixture.Build(context.Background(), t)
	rows, err := oodpublication.CanonicalImmutableRosterBytes(fixture.Plan.ImmutableRows)
	if err != nil {
		t.Fatal(err)
	}
	roster, err := oodevidence.VerifyPublicationRosterV8(context.Background(), fixture.Proof, rows, oodpublication.ManifestClosureReconciler{Input: fixture.Closure})
	if err != nil {
		t.Fatal(err)
	}
	return fixture, roster
}
