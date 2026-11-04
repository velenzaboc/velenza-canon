package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

// DocumentationFactoryOODPreparationBoot is a composable service boot
// boundary. The launcher owns source qualification and its private qualified
// result owns the same-read OOD facts. Neither is selected by source package
// input.
type DocumentationFactoryOODPreparationBoot struct {
	launcher providerplan.DocumentationFactoryProductionSourceProtectedLauncher
}

func NewDocumentationFactoryOODPreparationBoot(launcher providerplan.DocumentationFactoryProductionSourceProtectedLauncher) (DocumentationFactoryOODPreparationBoot, error) {
	return DocumentationFactoryOODPreparationBoot{launcher: launcher}, nil
}

// PreparedDocumentationFactoryOODOutput is preparation-only. Materialization
// stays opaque and the closure is supplied only for the separately owned
// protected publication boundary. This API deliberately has no Publish method.
type PreparedDocumentationFactoryOODOutput struct {
	Materialization OOD8APIMaterialization
	Closure         oodevidence.VerifiedClosureV8
}

// PrepareDocumentationFactoryOOD is the production compile-to-preparation
// caller. It makes no Spanner write: it invokes the real protected compiler,
// projects the compiler-retained sealed native document, constructs the
// complete OOD plan under boot-owned authority, and validates that plan through
// the existing opaque OOD8 API materializer.
func (b DocumentationFactoryOODPreparationBoot) PrepareDocumentationFactoryOOD(ctx context.Context, options providerplan.DocumentationFactoryProductionSourceCompileOptions) (PreparedDocumentationFactoryOODOutput, error) {
	if ctx == nil {
		return PreparedDocumentationFactoryOODOutput{}, errors.New("factory OOD preparation requires context")
	}
	qualified, err := b.launcher.CompileDocumentationFactoryProductionSourcePackageForPreparation(ctx, options)
	if err != nil {
		return PreparedDocumentationFactoryOODOutput{}, fmt.Errorf("compile protected factory source package: %w", err)
	}
	plan, err := providerplan.BuildDocumentationFactoryProductionSourceOODPlan(ctx, qualified)
	if err != nil {
		return PreparedDocumentationFactoryOODOutput{}, fmt.Errorf("build sealed native OOD plan: %w", err)
	}
	materialization, err := BuildVerifiedOOD8APIMaterialization(ctx, OOD8APINativeMaterializationOutput{
		Closure: plan.VerifiedClosure,
		Roster:  plan.VerifiedRoster,
		Factory: OOD8APIFactoryOutput{Plan: plan.Native.Plan, LocatorProofs: plan.LocatorProofs, EvidenceLocatorProofs: plan.EvidenceLocatorProofs, RoleProofs: plan.RoleProofs},
	})
	if err != nil {
		return PreparedDocumentationFactoryOODOutput{}, fmt.Errorf("prepare verified OOD8 API materialization: %w", err)
	}
	return PreparedDocumentationFactoryOODOutput{Materialization: materialization, Closure: plan.Native.VerifiedClosure}, nil
}
