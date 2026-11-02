package providerplan

import (
	"context"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

func TestPreparationCaptureDetachesCertificateAndPhysicalReadBuffers(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	in := DocumentationFactoryProductionSourceOODCurrentEvidenceRows{preparation: &documentationFactoryProductionSourceOODPreparationEvidence{certificate: f.Certificate, closure: DocumentationFactoryOODManifestClosure{Input: f.Closure}}}
	in.CurrentGeneration.EvidenceIdentities = []DocumentationFactoryProviderEvidenceIdentity{{SourceContentSHA256: "original"}}
	out := cloneDocumentationFactoryProductionSourceOODCurrentEvidenceRows(in)
	in.CurrentGeneration.EvidenceIdentities[0].SourceContentSHA256 = "changed"
	delete(in.preparation.certificate.Roots, "source")
	in.preparation.closure.Input.ImmutableRows[0].Columns["organization_id"] = "foreign"
	if out.CurrentGeneration.EvidenceIdentities[0].SourceContentSHA256 != "original" {
		t.Fatal("owner observation alias survived capture")
	}
	if err := oodpublication.VerifyManifestClosureV8(out.preparation.certificate, out.preparation.closure.Input); err != nil {
		t.Fatalf("capture lost immutable proof after producer mutation: %v", err)
	}
	if err := out.preparation.closure.Reconciler.VerifyCompleteManifestClosure(context.Background(), out.preparation.certificate); err != nil {
		t.Fatalf("capture reconciler retained stale read-buffer aliases: %v", err)
	}
}
