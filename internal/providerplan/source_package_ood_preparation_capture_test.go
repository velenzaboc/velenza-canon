package providerplan

import (
	"context"
	"testing"
)

func TestPreparationCapturePromotesOnlyAfterCurrentEvidenceValidation(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	rows := productionSourceOODCurrentRows(request)
	rows.preparation = &documentationFactoryProductionSourceOODPreparationEvidence{}
	capture := &documentationFactoryProductionSourcePreparationCapture{reader: &productionSourceOODStrongReaderStub{rows: rows}}
	readRequest := DocumentationFactoryProductionSourceOODReadRequest{Expected: productionSourceOwnerBindingExpectation(), Request: request}
	if _, err := capture.ReadCurrentEligibleProviderEvidenceRows(context.Background(), readRequest); err != nil {
		t.Fatal(err)
	}
	if capture.rows != nil || capture.pending == nil {
		t.Fatal("raw protected read promoted preparation before validation")
	}
	if err := capture.observeValidatedPreparation(readRequest.Expected, request, rows); err != nil {
		t.Fatalf("promote validated protected read: %v", err)
	}
	if capture.rows == nil || capture.pending != nil {
		t.Fatal("validated protected read did not promote capture")
	}
}

func TestPreparationCaptureRefusesRequestSubstitutionAtPromotion(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	rows := productionSourceOODCurrentRows(request)
	rows.preparation = &documentationFactoryProductionSourceOODPreparationEvidence{}
	capture := &documentationFactoryProductionSourcePreparationCapture{reader: &productionSourceOODStrongReaderStub{rows: rows}}
	readRequest := DocumentationFactoryProductionSourceOODReadRequest{Expected: productionSourceOwnerBindingExpectation(), Request: request}
	if _, err := capture.ReadCurrentEligibleProviderEvidenceRows(context.Background(), readRequest); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DocumentationFactoryProductionSourceVerificationRequest){
		"observation time": func(r *DocumentationFactoryProductionSourceVerificationRequest) {
			r.ObservedAt = "2026-08-28T21:30:01Z"
		},
		"package length": func(r *DocumentationFactoryProductionSourceVerificationRequest) { r.SourcePackageByteCount++ },
		"receipt length": func(r *DocumentationFactoryProductionSourceVerificationRequest) { r.VerificationReceiptByteCount++ },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := request
			mutate(&mutated)
			if err := capture.observeValidatedPreparation(readRequest.Expected, mutated, rows); err == nil {
				t.Fatal("substituted request promoted preparation capture")
			}
		})
	}
}
