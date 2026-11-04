package providerplan

import (
	"context"
	"strings"
	"testing"

	"cloud.google.com/go/spanner"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

type productionSourceProtectedLauncherAuthority struct {
	productionSourceOODFixtureAuthority
}

func (productionSourceProtectedLauncherAuthority) ResolveAPIPropertyPayloadSchema(_ context.Context, id, version, digest, profile string) (oodpublication.AdmittedAPIPropertyPayloadSchema, error) {
	return oodpublication.AdmittedAPIPropertyPayloadSchema{ArtifactID: id, Version: version, Digest: digest, Profile: profile, Fields: []oodpublication.APIPropertyPayloadField{{Name: "fixture", Type: 1}}}, nil
}

func (productionSourceProtectedLauncherAuthority) AttestCurrentProviderDocumentationEvidence(context.Context, oodpublication.CurrentSealedClosure, DocumentationFactoryProductionSourceOODReadRequest, oodevidence.VerifiedClosureV8, []oodevidence.VerifiedBatchV8, []DocumentationFactoryProductionSourceOODSpannerMembershipRow) (DocumentationFactoryProductionSourceOODProofAttestation, error) {
	return DocumentationFactoryProductionSourceOODProofAttestation{}, nil
}

func TestProtectedSourceLauncherRejectsMissingBootDependencies(t *testing.T) {
	binding := productionSourceOwnerBindingExpectation()
	authority := productionSourceProtectedLauncherAuthority{}
	for _, tc := range []struct {
		name      string
		client    *spanner.Client
		expected  DocumentationFactoryProductionSourceOwnerBindingExpectation
		authority DocumentationFactoryProductionSourceOODProofAttestationAuthority
		want      string
	}{
		{"client", nil, binding, authority, "selected Spanner client"},
		{"binding", &spanner.Client{}, DocumentationFactoryProductionSourceOwnerBindingExpectation{}, authority, "binding expectation"},
		{"authority", &spanner.Client{}, binding, nil, "attestation authority"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewDocumentationFactoryProductionSourceProtectedLauncher(tc.client, tc.expected, tc.authority)
			if err == nil || got.client != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("launcher=%#v err=%v", got, err)
			}
		})
	}
}

func TestProtectedSourceLauncherIsABootResolver(t *testing.T) {
	launcher, err := NewDocumentationFactoryProductionSourceProtectedLauncher(&spanner.Client{}, productionSourceOwnerBindingExpectation(), productionSourceProtectedLauncherAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := launcher.ResolveDocumentationFactoryProductionSourceVerifier(context.Background())
	if err != nil || verifier == nil {
		t.Fatalf("verifier=%T err=%v", verifier, err)
	}
}
