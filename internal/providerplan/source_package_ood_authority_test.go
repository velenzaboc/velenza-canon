package providerplan

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

type productionSourceOODAuthorityStub struct {
	observation DocumentationFactoryProductionSourceOODReadObservation
	request     DocumentationFactoryProductionSourceOODReadRequest
	err         error
	calls       int
}

func (s *productionSourceOODAuthorityStub) ReadCurrentEligibleProviderEvidence(_ context.Context, request DocumentationFactoryProductionSourceOODReadRequest) (DocumentationFactoryProductionSourceOODReadObservation, error) {
	s.calls++
	s.request = request
	return s.observation, s.err
}

func productionSourceOODEligibilityProof() DocumentationFactoryProductionSourceOODEligibilityProof {
	return DocumentationFactoryProductionSourceOODEligibilityProof{
		OrganizationID: "123e4567-e89b-12d3-a456-426614174000", Provider: "provider",
		SnapshotID: "123e4567-e89b-12d3-a456-426614174001", SnapshotKind: "provider_documentation", SnapshotHeadGeneration: 7, SnapshotState: "sealed", SnapshotStatus: "active",
		SourceSetSHA256: strings.Repeat("1", 64), ClosureSHA256: strings.Repeat("2", 64),
		VerificationCertificateID: "123e4567-e89b-12d3-a456-426614174002", VerificationCertificateSHA256: strings.Repeat("3", 64),
		MaterializationProfileID: "123e4567-e89b-12d3-a456-426614174003", MaterializationProfileVersion: "v1", MaterializationProfileSHA256: strings.Repeat("4", 64),
		ExternalReceiptManifestRootSHA256: strings.Repeat("5", 64), FetchBatchManifestRootSHA256: strings.Repeat("6", 64), FetchBatchCount: 1,
		ArchiveBindingManifestRootSHA256: strings.Repeat("7", 64), ExternalCurrentValidityResultReference: "ood_current_validity", ExternalCurrentValidityResultSHA256: strings.Repeat("8", 64),
	}
}

func productionSourceOODObservation(request DocumentationFactoryProductionSourceVerificationRequest) DocumentationFactoryProductionSourceOODReadObservation {
	return DocumentationFactoryProductionSourceOODReadObservation{
		CurrentGeneration: productionSourceOwnerObservation(request),
		Eligibility:       productionSourceOODEligibilityProof(),
	}
}

func TestProductionSourceOODAuthorityReaderClosesCurrentEligibleObservation(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	authority := &productionSourceOODAuthorityStub{observation: productionSourceOODObservation(request)}
	reader, err := NewDocumentationFactoryProductionSourceOODAuthorityReader(productionSourceOwnerBindingExpectation(), authority)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.ReadCurrentAuthenticatedProviderEvidence(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if authority.calls != 1 || !reflect.DeepEqual(got, authority.observation.CurrentGeneration) || !reflect.DeepEqual(authority.request.Expected, productionSourceOwnerBindingExpectation()) || !reflect.DeepEqual(authority.request.Request, request) {
		t.Fatalf("OOD reader did not bind the exact boot/request/observation coordinates: calls=%d request=%+v got=%+v", authority.calls, authority.request, got)
	}
	verifier, err := NewDocumentationFactoryProductionSourceOODVerifier(productionSourceOwnerBindingExpectation(), authority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), request); err != nil {
		t.Fatalf("OOD-composed production verifier refused exact observation: %v", err)
	}
}

func TestProductionSourceOODAuthorityReaderRefusesNonEligibleAndSubstitutedProofs(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	for _, testCase := range []struct {
		name   string
		mutate func(*DocumentationFactoryProductionSourceOODReadObservation)
		want   string
	}{
		{"foreign organization", func(v *DocumentationFactoryProductionSourceOODReadObservation) {
			v.Eligibility.OrganizationID = "123e4567-e89b-12d3-a456-426614174099"
		}, "organization and provider"},
		{"foreign provider", func(v *DocumentationFactoryProductionSourceOODReadObservation) {
			v.Eligibility.Provider = "another_provider"
		}, "organization and provider"},
		{"unsealed snapshot", func(v *DocumentationFactoryProductionSourceOODReadObservation) {
			v.Eligibility.SnapshotState = "candidate"
		}, "not sealed"},
		{"zero head generation", func(v *DocumentationFactoryProductionSourceOODReadObservation) {
			v.Eligibility.SnapshotHeadGeneration = 0
		}, "head generation"},
		{"noncanonical snapshot", func(v *DocumentationFactoryProductionSourceOODReadObservation) {
			v.Eligibility.SnapshotID = "not-a-uuid"
		}, "snapshot_id"},
		{"invalid certificate digest", func(v *DocumentationFactoryProductionSourceOODReadObservation) {
			v.Eligibility.VerificationCertificateSHA256 = "not-a-digest"
		}, "verification_certificate_sha256"},
		{"missing batch manifest", func(v *DocumentationFactoryProductionSourceOODReadObservation) {
			v.Eligibility.FetchBatchManifestRootSHA256 = ""
		}, "fetch_batch_manifest_root_sha256"},
		{"missing archive closure", func(v *DocumentationFactoryProductionSourceOODReadObservation) {
			v.Eligibility.ArchiveBindingManifestRootSHA256 = ""
		}, "archive_binding_manifest_root_sha256"},
		{"missing current validity", func(v *DocumentationFactoryProductionSourceOODReadObservation) {
			v.Eligibility.ExternalCurrentValidityResultSHA256 = ""
		}, "external_current_validity_result_sha256"},
		{"stale source observation", func(v *DocumentationFactoryProductionSourceOODReadObservation) {
			v.CurrentGeneration.VerifiedAt = "2026-10-30T14:59:59Z"
		}, "does not bind"},
		{"partial source identities", func(v *DocumentationFactoryProductionSourceOODReadObservation) {
			v.CurrentGeneration.EvidenceIdentities = nil
		}, "complete exact evidence"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			observation := productionSourceOODObservation(request)
			observation.CurrentGeneration.EvidenceIdentities = cloneDocumentationFactoryProviderEvidenceIdentities(observation.CurrentGeneration.EvidenceIdentities)
			testCase.mutate(&observation)
			authority := &productionSourceOODAuthorityStub{observation: observation}
			reader, err := NewDocumentationFactoryProductionSourceOODAuthorityReader(productionSourceOwnerBindingExpectation(), authority)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.ReadCurrentAuthenticatedProviderEvidence(context.Background(), request); err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("OOD observation refusal = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestProductionSourceOODAuthorityReaderRefusesBeforeAuthorityForWrongBootOrRequest(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	authority := &productionSourceOODAuthorityStub{observation: productionSourceOODObservation(request)}
	if reader, err := NewDocumentationFactoryProductionSourceOODAuthorityReader(productionSourceOwnerBindingExpectation(), nil); err == nil || reader != nil {
		t.Fatalf("nil OOD authority reader=%v err=%v", reader, err)
	}
	reader, err := NewDocumentationFactoryProductionSourceOODAuthorityReader(productionSourceOwnerBindingExpectation(), authority)
	if err != nil {
		t.Fatal(err)
	}
	request.ExpectedProvider = "other_provider"
	if _, err := reader.ReadCurrentAuthenticatedProviderEvidence(context.Background(), request); err == nil || !strings.Contains(err.Error(), "boot-selected provider") {
		t.Fatalf("wrong provider error = %v", err)
	}
	if authority.calls != 0 {
		t.Fatalf("authority was called for a wrong boot provider: %d", authority.calls)
	}
}
