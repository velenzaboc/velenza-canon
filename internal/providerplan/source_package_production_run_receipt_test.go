package providerplan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDocumentationFactoryProductionSourceRunReceiptClosesReleaseRelay(t *testing.T) {
	t.Parallel()
	result := acceptedProductionSourceCompileResult(t, "quickbooks")
	receipt, err := SealDocumentationFactoryProductionSourceRunReceipt(result)
	if err != nil {
		t.Fatalf("seal production source run receipt: %v", err)
	}
	if err := ValidateDocumentationFactoryProductionSourceRunReceipt(receipt); err != nil {
		t.Fatalf("validate production source run receipt: %v", err)
	}
	if receipt.SourceReceipt.ProductionSourceVerification == nil {
		t.Fatal("production source run receipt dropped the source-owner verification binding")
	}
	if receipt.SourceReceipt.FactoryReceiptSHA256 != receipt.FactoryReceipt.ReceiptSHA256 || receipt.SourceReceipt.FactoryPortableReceiptSHA256 != receipt.FactoryReceipt.PortableReceiptSHA256 {
		t.Fatal("production source run receipt does not cross-bind its source and factory receipts")
	}
	if !receipt.BodyFree || receipt.AuthoritySelected || receipt.AdmissionAuthorized || receipt.FactoryComplete {
		t.Fatalf("production source run receipt overclaims completion: %+v", receipt)
	}
}

func TestDocumentationFactoryProductionSourceRunReceiptRejectsIncompleteOrSubstitutedInputs(t *testing.T) {
	t.Parallel()
	accepted := acceptedProductionSourceCompileResult(t, "quickbooks")
	other := acceptedProductionSourceCompileResult(t, "xero")

	tests := []struct {
		name        string
		mutate      func(DocumentationFactorySourceCompileResult) DocumentationFactorySourceCompileResult
		wantMessage string
	}{
		{
			name: "candidate source receipt",
			mutate: func(result DocumentationFactorySourceCompileResult) DocumentationFactorySourceCompileResult {
				result.SourceReceipt.ProductionSourceVerification = nil
				recloseDocumentationFactorySourceReceiptForTest(t, &result.SourceReceipt)
				return result
			},
			wantMessage: "production source verification",
		},
		{
			name: "cross-pair substituted factory receipt",
			mutate: func(result DocumentationFactorySourceCompileResult) DocumentationFactorySourceCompileResult {
				result.FactoryReceipt = other.FactoryReceipt
				return result
			},
			wantMessage: "factory receipt",
		},
		{
			name: "test-owned source verification",
			mutate: func(result DocumentationFactorySourceCompileResult) DocumentationFactorySourceCompileResult {
				verification := *result.SourceReceipt.ProductionSourceVerification
				verification.TestOwned = true
				recloseDocumentationFactoryProductionSourceVerificationForTest(t, &verification)
				result.SourceReceipt.ProductionSourceVerification = &verification
				recloseDocumentationFactorySourceReceiptForTest(t, &result.SourceReceipt)
				return result
			},
			wantMessage: "production-eligible",
		},
		{
			name: "provider substitution",
			mutate: func(result DocumentationFactorySourceCompileResult) DocumentationFactorySourceCompileResult {
				verification := *result.SourceReceipt.ProductionSourceVerification
				verification.Provider = "different_provider"
				recloseDocumentationFactoryProductionSourceVerificationForTest(t, &verification)
				result.SourceReceipt.ProductionSourceVerification = &verification
				recloseDocumentationFactorySourceReceiptForTest(t, &result.SourceReceipt)
				return result
			},
			wantMessage: "provider",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := SealDocumentationFactoryProductionSourceRunReceipt(testCase.mutate(accepted)); err == nil || !strings.Contains(err.Error(), testCase.wantMessage) {
				t.Fatalf("seal error = %v, want %q", err, testCase.wantMessage)
			}
		})
	}
}

func TestDocumentationFactoryProductionSourceRunReceiptRejectsEnvelopeDigestMutation(t *testing.T) {
	t.Parallel()
	receipt, err := SealDocumentationFactoryProductionSourceRunReceipt(acceptedProductionSourceCompileResult(t, "quickbooks"))
	if err != nil {
		t.Fatal(err)
	}
	receipt.ReceiptSHA256 = strings.Repeat("f", 64)
	if err := ValidateDocumentationFactoryProductionSourceRunReceipt(receipt); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("mutated envelope digest error = %v", err)
	}
}

func acceptedProductionSourceCompileResult(t *testing.T, provider string) DocumentationFactorySourceCompileResult {
	t.Helper()
	fixture := newSourcePackageCompilerTestFixture(t, provider)
	verificationReceiptPath := filepath.Join(t.TempDir(), "source-owner-verification.receipt")
	if err := os.WriteFile(verificationReceiptPath, []byte("{\"receipt_kind\":\"opaque_authenticated_source_owner_verification\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	verifier := productionSourcePackageVerifierFunc(func(_ context.Context, request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
		return acceptedProductionSourcePackageVerification(request), nil
	})
	result, err := compileDocumentationFactoryProductionSourcePackageWithDependencies(
		context.Background(),
		DocumentationFactoryProductionSourceCompileOptions{
			SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot,
			VerificationReceiptPath: verificationReceiptPath, ExpectedProvider: "fixture_provider",
		},
		verifier,
		documentationFactoryProductionSourceCompilerDependencies{
			SourceCompiler: sourcePackageCompilerTestDependencies(t),
			Now: func() time.Time {
				return time.Date(2026, time.August, 28, 22, 0, 0, 0, time.UTC)
			},
		},
	)
	if err != nil {
		t.Fatalf("compile accepted production source fixture: %v", err)
	}
	return result
}

func recloseDocumentationFactoryProductionSourceVerificationForTest(t *testing.T, receipt *DocumentationFactoryProductionSourceVerificationReceipt) {
	t.Helper()
	receipt.BindingSHA256 = ""
	raw, err := canonicalFactoryJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.BindingSHA256 = sha256Hex(raw)
}

func recloseDocumentationFactorySourceReceiptForTest(t *testing.T, receipt *DocumentationFactorySourceCompileReceipt) {
	t.Helper()
	receipt.ReceiptSHA256 = ""
	raw, err := canonicalFactoryJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ReceiptSHA256 = sha256Hex(raw)
}
