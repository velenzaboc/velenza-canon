package providerplan

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

type productionSourceOwnerReaderStub struct {
	observed DocumentationFactoryProductionSourceOwnerCurrentGeneration
	request  DocumentationFactoryProductionSourceVerificationRequest
	err      error
	calls    int
}

func (s *productionSourceOwnerReaderStub) ReadCurrentAuthenticatedProviderEvidence(_ context.Context, request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceOwnerCurrentGeneration, error) {
	s.calls++
	s.request = request
	return s.observed, s.err
}

func productionSourceOwnerRequestFixture(t *testing.T) DocumentationFactoryProductionSourceVerificationRequest {
	t.Helper()
	identity := DocumentationFactoryProviderEvidenceIdentity{
		ManifestRole: "evidence_manifest", ManifestID: "manifest.a", ManifestVersion: "v1", ManifestRawSHA256: strings.Repeat("a", 64), ManifestByteCount: 10,
		ComponentOrdinal: 0, SourceContentSHA256: strings.Repeat("b", 64), SourceContentByteCount: 5,
		CarrierRole: "evidence_carrier", CarrierID: "carrier.a", CarrierVersion: "v1", CarrierRawSHA256: strings.Repeat("c", 64), CarrierByteCount: 5,
	}
	root, err := documentationFactoryProviderEvidenceIdentitySetRoot([]DocumentationFactoryProviderEvidenceIdentity{identity})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("opaque owner-authenticated receipt")
	return DocumentationFactoryProductionSourceVerificationRequest{
		ExpectedProvider: "provider", SourcePackageSHA256: strings.Repeat("d", 64), SourcePackageByteCount: 123,
		EvidenceIdentities: []DocumentationFactoryProviderEvidenceIdentity{identity}, EvidenceIdentitySetRootSHA256: root,
		VerificationReceiptRaw: raw, VerificationReceiptSHA256: sha256Hex(raw), VerificationReceiptByteCount: int64(len(raw)),
		ObservedAt: time.Date(2026, time.October, 30, 15, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
}

func productionSourceOwnerObservation(request DocumentationFactoryProductionSourceVerificationRequest) DocumentationFactoryProductionSourceOwnerCurrentGeneration {
	return DocumentationFactoryProductionSourceOwnerCurrentGeneration{
		Provider: request.ExpectedProvider, OrganizationID: "123e4567-e89b-12d3-a456-426614174000", SourceOwnerID: "provider_documentation_owner", AuthenticatedProducerID: "provider_documentation_producer", ProducerAuthenticationBindingRef: "provider_producer_binding",
		ProducerAuthenticationBindingSHA256: strings.Repeat("e", 64), CurrentGeneration: 1, CurrentGenerationBindingSHA256: strings.Repeat("f", 64),
		SourcePackageSHA256: request.SourcePackageSHA256, SourcePackageByteCount: request.SourcePackageByteCount,
		VerificationReceiptSHA256: request.VerificationReceiptSHA256, VerificationReceiptByteCount: request.VerificationReceiptByteCount,
		EvidenceIdentities: cloneDocumentationFactoryProviderEvidenceIdentities(request.EvidenceIdentities), EvidenceIdentitySetRootSHA256: request.EvidenceIdentitySetRootSHA256,
		VerifiedAt: request.ObservedAt,
	}
}

func productionSourceOwnerBindingExpectation() DocumentationFactoryProductionSourceOwnerBindingExpectation {
	return DocumentationFactoryProductionSourceOwnerBindingExpectation{
		Provider: "provider", OrganizationID: "123e4567-e89b-12d3-a456-426614174000", SourceOwnerID: "provider_documentation_owner", AuthenticatedProducerID: "provider_documentation_producer", ProducerAuthenticationBindingRef: "provider_producer_binding", ProducerAuthenticationBindingSHA256: strings.Repeat("e", 64),
	}
}

func TestProductionSourceOwnerVerifierRequiresBootOwnedReader(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	_, err := BootSelectedDocumentationFactoryProductionSourceVerifier().VerifyDocumentationFactoryProductionSourcePackage(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "not boot configured") {
		t.Fatalf("unconfigured boot authority = %v", err)
	}
}

func TestProductionSourceBootResolverRequiresConcreteProtectedComposition(t *testing.T) {
	if verifier, err := ResolveDocumentationFactoryProductionSourceVerifier(context.Background(), nil); err == nil || verifier != nil || !strings.Contains(err.Error(), "boot resolver") {
		t.Fatalf("nil resolver verifier=%v err=%v", verifier, err)
	}
	composition := DocumentationFactoryProductionSourceBootComposition{
		Expected: productionSourceOwnerBindingExpectation(),
		Reader:   &productionSourceOODStrongReaderStub{rows: productionSourceOODCurrentRows(productionSourceOwnerRequestFixture(t))},
	}
	verifier, err := ResolveDocumentationFactoryProductionSourceVerifier(context.Background(), composition)
	if err != nil || verifier == nil {
		t.Fatalf("concrete boot composition verifier=%v err=%v", verifier, err)
	}
}

func TestProductionSourceOwnerVerifierRefusesBeforeReaderForWrongProviderOrCancellation(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	reader := &productionSourceOwnerReaderStub{observed: productionSourceOwnerObservation(request)}
	verifier, err := NewDocumentationFactoryProductionSourceOwnerVerifier(productionSourceOwnerBindingExpectation(), reader)
	if err != nil {
		t.Fatal(err)
	}
	request.ExpectedProvider = "another_provider"
	if _, err := verifier.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), request); err == nil {
		t.Fatal("wrong provider accepted")
	}
	request = productionSourceOwnerRequestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.VerifyDocumentationFactoryProductionSourcePackage(ctx, request); err == nil {
		t.Fatal("cancelled verification accepted")
	}
	if reader.calls != 0 {
		t.Fatal("reader invoked outside selected provider or after cancellation")
	}
}

func TestProductionSourceOwnerVerifierAcceptsOnlyExactCurrentOwnerObservation(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	reader := &productionSourceOwnerReaderStub{observed: productionSourceOwnerObservation(request)}
	verifier, err := NewDocumentationFactoryProductionSourceOwnerVerifier(productionSourceOwnerBindingExpectation(), reader)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := verifier.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if reader.calls != 1 || !reflect.DeepEqual(reader.request, request) || !answer.ProducerAuthenticated || !answer.CurrentGenerationVerified || !answer.CompleteEvidenceIdentitySetVerified || answer.TestOwned {
		t.Fatalf("owner observation was not closed into verifier answer: calls=%d request=%+v answer=%+v", reader.calls, reader.request, answer)
	}
}

func TestProductionSourceOwnerVerifierRefusesSubstitutedOrIncompleteAuthorityObservation(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	for _, testCase := range []struct {
		name   string
		mutate func(*DocumentationFactoryProductionSourceOwnerCurrentGeneration)
		want   string
	}{
		{"test owned", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) { v.TestOwned = true }, "test-owned"},
		{"missing owner", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) { v.SourceOwnerID = "" }, "source_owner_id"},
		{"wrong valid owner", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) { v.SourceOwnerID = "other_owner" }, "boot-selected owner binding"},
		{"wrong valid producer", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) {
			v.AuthenticatedProducerID = "other_producer"
		}, "boot-selected owner binding"},
		{"wrong valid producer binding", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) {
			v.ProducerAuthenticationBindingSHA256 = strings.Repeat("1", 64)
		}, "boot-selected owner binding"},
		{"zero generation", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) { v.CurrentGeneration = 0 }, "current generation"},
		{"bad producer binding", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) {
			v.ProducerAuthenticationBindingSHA256 = "bad"
		}, "producer_authentication"},
		{"package substitution", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) {
			v.SourcePackageSHA256 = strings.Repeat("0", 64)
		}, "does not bind"},
		{"receipt replay", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) {
			v.VerificationReceiptSHA256 = strings.Repeat("1", 64)
		}, "does not bind"},
		{"stale observation", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) {
			v.VerifiedAt = time.Date(2026, time.October, 30, 14, 59, 59, 0, time.UTC).Format(time.RFC3339Nano)
		}, "does not bind"},
		{"dropped identity", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) { v.EvidenceIdentities = nil }, "complete exact evidence"},
		{"identity substitution", func(v *DocumentationFactoryProductionSourceOwnerCurrentGeneration) {
			v.EvidenceIdentities[0].CarrierRawSHA256 = strings.Repeat("9", 64)
		}, "complete exact evidence"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			observed := productionSourceOwnerObservation(request)
			observed.EvidenceIdentities = cloneDocumentationFactoryProviderEvidenceIdentities(observed.EvidenceIdentities)
			testCase.mutate(&observed)
			reader := &productionSourceOwnerReaderStub{observed: observed}
			verifier, err := NewDocumentationFactoryProductionSourceOwnerVerifier(productionSourceOwnerBindingExpectation(), reader)
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), request)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("authority refusal = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestProductionSourceOwnerVerifierRefusesIncompleteBootBinding(t *testing.T) {
	reader := &productionSourceOwnerReaderStub{}
	for _, binding := range []DocumentationFactoryProductionSourceOwnerBindingExpectation{
		{},
		{Provider: "provider", OrganizationID: "not-a-uuid", SourceOwnerID: "owner", AuthenticatedProducerID: "producer", ProducerAuthenticationBindingRef: "binding", ProducerAuthenticationBindingSHA256: strings.Repeat("a", 64)},
		{Provider: "provider", OrganizationID: "123e4567-e89b-12d3-a456-426614174000", SourceOwnerID: "owner", AuthenticatedProducerID: "producer", ProducerAuthenticationBindingRef: "binding", ProducerAuthenticationBindingSHA256: "bad"},
	} {
		if verifier, err := NewDocumentationFactoryProductionSourceOwnerVerifier(binding, reader); err == nil || verifier != nil {
			t.Fatalf("incomplete boot binding verifier=%v err=%v", verifier, err)
		}
	}
}
