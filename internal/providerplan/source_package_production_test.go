package providerplan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type productionSourcePackageVerifierFunc func(context.Context, DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error)

func (verify productionSourcePackageVerifierFunc) VerifyDocumentationFactoryProductionSourcePackage(ctx context.Context, request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
	return verify(ctx, request)
}

func TestDocumentationFactoryProductionSourceCompilerRefusesUntrustedEvidenceBeforeFactory(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 28, 21, 30, 0, 0, time.UTC)
	tests := []struct {
		name        string
		verifier    func(DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error)
		wantMessage string
	}{
		{name: "missing verifier", wantMessage: "production source-package verifier is required"},
		{
			name: "test owned",
			verifier: func(request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
				result := acceptedProductionSourcePackageVerification(request)
				result.TestOwned = true
				return result, nil
			},
			wantMessage: "test-owned",
		},
		{
			name: "unauthenticated",
			verifier: func(request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
				result := acceptedProductionSourcePackageVerification(request)
				result.ProducerAuthenticated = false
				return result, nil
			},
			wantMessage: "authenticated producer",
		},
		{
			name: "stale",
			verifier: func(request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
				result := acceptedProductionSourcePackageVerification(request)
				result.CurrentGenerationVerified = false
				return result, nil
			},
			wantMessage: "current generation",
		},
		{
			name: "mismatched provider",
			verifier: func(request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
				result := acceptedProductionSourcePackageVerification(request)
				result.Provider = "different_provider"
				return result, nil
			},
			wantMessage: "provider",
		},
		{
			name: "fabricated receipt",
			verifier: func(request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
				result := acceptedProductionSourcePackageVerification(request)
				result.VerificationReceiptSHA256 = strings.Repeat("f", 64)
				return result, nil
			},
			wantMessage: "verification receipt",
		},
		{
			name: "mismatched source package",
			verifier: func(request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
				result := acceptedProductionSourcePackageVerification(request)
				result.SourcePackageSHA256 = strings.Repeat("e", 64)
				return result, nil
			},
			wantMessage: "source package",
		},
		{
			name: "incomplete evidence identity roster",
			verifier: func(request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
				result := acceptedProductionSourcePackageVerification(request)
				result.CompleteEvidenceIdentitySetVerified = false
				return result, nil
			},
			wantMessage: "complete evidence identity set",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
			verificationReceiptPath := filepath.Join(t.TempDir(), "source-owner-verification.receipt")
			if err := os.WriteFile(verificationReceiptPath, []byte("{\"receipt_kind\":\"opaque_source_owner_verification\"}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			dependencies := sourcePackageCompilerTestDependencies(t)
			factoryRuns := 0
			underlying := dependencies.RunFactory
			dependencies.RunFactory = func(options FactoryRunOptions) (FactoryRunReceipt, error) {
				factoryRuns++
				return underlying(options)
			}
			var verifier DocumentationFactoryProductionSourceVerifier
			if testCase.verifier != nil {
				verifier = productionSourcePackageVerifierFunc(func(_ context.Context, request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
					return testCase.verifier(request)
				})
			}
			_, err := compileDocumentationFactoryProductionSourcePackageWithDependencies(
				context.Background(),
				DocumentationFactoryProductionSourceCompileOptions{
					SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot,
					VerificationReceiptPath: verificationReceiptPath, ExpectedProvider: "fixture_provider",
				},
				verifier,
				documentationFactoryProductionSourceCompilerDependencies{SourceCompiler: dependencies, Now: func() time.Time { return now }},
			)
			if err == nil || !strings.Contains(err.Error(), testCase.wantMessage) {
				t.Fatalf("production source verification error = %v, want %q", err, testCase.wantMessage)
			}
			if factoryRuns != 0 {
				t.Fatalf("untrusted production source package ran the factory %d times", factoryRuns)
			}
			if _, statErr := os.Lstat(fixture.outputRoot); !os.IsNotExist(statErr) {
				t.Fatalf("untrusted production source package published output: %v", statErr)
			}
		})
	}
}

func TestDocumentationFactoryProductionSourceCompilerRunsVerifiedPackageThroughIdenticalFactory(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	verificationReceiptPath := filepath.Join(t.TempDir(), "source-owner-verification.receipt")
	verificationReceiptRaw := []byte("{\"receipt_kind\":\"opaque_authenticated_source_owner_verification\"}\n")
	if err := os.WriteFile(verificationReceiptPath, verificationReceiptRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 28, 21, 30, 0, 0, time.UTC)
	dependencies := sourcePackageCompilerTestDependencies(t)
	factoryRuns := 0
	underlying := dependencies.RunFactory
	dependencies.RunFactory = func(options FactoryRunOptions) (FactoryRunReceipt, error) {
		factoryRuns++
		return underlying(options)
	}
	verifierCalls := 0
	verifier := productionSourcePackageVerifierFunc(func(_ context.Context, request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
		verifierCalls++
		if request.ExpectedProvider != "fixture_provider" || request.SourcePackageSHA256 == "" || request.SourcePackageByteCount <= 0 || request.VerificationReceiptSHA256 != sha256Hex(verificationReceiptRaw) {
			return DocumentationFactoryProductionSourceVerification{}, fmt.Errorf("incomplete exact verification request: %+v", request)
		}
		if len(request.EvidenceIdentities) == 0 || request.EvidenceIdentitySetRootSHA256 == "" {
			return DocumentationFactoryProductionSourceVerification{}, fmt.Errorf("missing exact provider evidence identity roster")
		}
		return acceptedProductionSourcePackageVerification(request), nil
	})

	result, err := compileDocumentationFactoryProductionSourcePackageWithDependencies(
		context.Background(),
		DocumentationFactoryProductionSourceCompileOptions{
			SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot,
			VerificationReceiptPath: verificationReceiptPath, ExpectedProvider: "fixture_provider",
		},
		verifier,
		documentationFactoryProductionSourceCompilerDependencies{SourceCompiler: dependencies, Now: func() time.Time { return now }},
	)
	if err != nil {
		t.Fatal(err)
	}
	if verifierCalls != 1 || factoryRuns != 1 {
		t.Fatalf("production source calls = verifier %d/factory %d, want 1/1", verifierCalls, factoryRuns)
	}
	if result.FactoryReceipt.PreflightReceipt.Provider != "fixture_provider" {
		t.Fatalf("compiled provider = %q", result.FactoryReceipt.PreflightReceipt.Provider)
	}
	if err := validateDocumentationFactorySourceReceipt(result.SourceReceipt); err != nil {
		t.Fatalf("production-shaped source receipt: %v", err)
	}
	verification := result.SourceReceipt.ProductionSourceVerification
	if verification == nil {
		t.Fatal("production-shaped source receipt lacks its verified provider-evidence binding")
	}
	if result.SourceReceipt.AuthoritySelected || result.SourceReceipt.AdmissionAuthorized || result.SourceReceipt.FactoryComplete || !result.SourceReceipt.BodyFree {
		t.Fatalf("production-shaped source receipt overclaims completion: %+v", result.SourceReceipt)
	}
	receiptRaw, err := os.ReadFile(filepath.Join(fixture.outputRoot, filepath.FromSlash(sourcePackageCompileReceiptPath)))
	if err != nil {
		t.Fatalf("read published production-shaped source receipt: %v", err)
	}
	if !strings.Contains(string(receiptRaw), `"production_source_verification"`) {
		t.Fatal("published source receipt omits its production provider-evidence binding")
	}
}

func TestDocumentationFactoryProductionSourceCompilerRejectsCompiledProviderMismatchWithoutPublishing(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	verificationReceiptPath := filepath.Join(t.TempDir(), "source-owner-verification.receipt")
	if err := os.WriteFile(verificationReceiptPath, []byte("{\"receipt_kind\":\"opaque_source_owner_verification\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencies := sourcePackageCompilerTestDependencies(t)
	factoryRuns := 0
	underlying := dependencies.RunFactory
	dependencies.RunFactory = func(options FactoryRunOptions) (FactoryRunReceipt, error) {
		factoryRuns++
		return underlying(options)
	}
	verifier := productionSourcePackageVerifierFunc(func(_ context.Context, request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
		return acceptedProductionSourcePackageVerification(request), nil
	})
	_, err := compileDocumentationFactoryProductionSourcePackageWithDependencies(
		context.Background(),
		DocumentationFactoryProductionSourceCompileOptions{
			SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot,
			VerificationReceiptPath: verificationReceiptPath, ExpectedProvider: "different_provider",
		},
		verifier,
		documentationFactoryProductionSourceCompilerDependencies{SourceCompiler: dependencies, Now: func() time.Time { return time.Date(2026, time.August, 28, 21, 30, 0, 0, time.UTC) }},
	)
	if err == nil || !strings.Contains(err.Error(), "does not match compiled provider") {
		t.Fatalf("compiled-provider mismatch error = %v", err)
	}
	if factoryRuns != 1 {
		t.Fatalf("compiled-provider mismatch factory runs = %d, want 1", factoryRuns)
	}
	if _, statErr := os.Lstat(fixture.outputRoot); !os.IsNotExist(statErr) {
		t.Fatalf("compiled-provider mismatch published output: %v", statErr)
	}
}

func TestDocumentationFactoryProductionSourceCompilerRejectsVerificationReceiptMutationBeforePublication(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	verificationReceiptPath := filepath.Join(t.TempDir(), "source-owner-verification.receipt")
	if err := os.WriteFile(verificationReceiptPath, []byte("{\"receipt_kind\":\"opaque_source_owner_verification\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencies := sourcePackageCompilerTestDependencies(t)
	underlying := dependencies.RunFactory
	dependencies.RunFactory = func(options FactoryRunOptions) (FactoryRunReceipt, error) {
		receipt, err := underlying(options)
		if err != nil {
			return receipt, err
		}
		if writeErr := os.WriteFile(verificationReceiptPath, []byte("{\"receipt_kind\":\"mutated_source_owner_verification\"}\n"), 0o600); writeErr != nil {
			return FactoryRunReceipt{}, writeErr
		}
		return receipt, nil
	}
	verifier := productionSourcePackageVerifierFunc(func(_ context.Context, request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
		return acceptedProductionSourcePackageVerification(request), nil
	})
	_, err := compileDocumentationFactoryProductionSourcePackageWithDependencies(
		context.Background(),
		DocumentationFactoryProductionSourceCompileOptions{
			SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot,
			VerificationReceiptPath: verificationReceiptPath, ExpectedProvider: "fixture_provider",
		},
		verifier,
		documentationFactoryProductionSourceCompilerDependencies{SourceCompiler: dependencies, Now: func() time.Time { return time.Date(2026, time.August, 28, 21, 30, 0, 0, time.UTC) }},
	)
	if err == nil || !strings.Contains(err.Error(), "revalidate production source-package verification receipt") {
		t.Fatalf("verification-receipt mutation error = %v", err)
	}
	if _, statErr := os.Lstat(fixture.outputRoot); !os.IsNotExist(statErr) {
		t.Fatalf("verification-receipt mutation published output: %v", statErr)
	}
}

func TestDocumentationFactoryProductionSourceReceiptRejectsTrustMutation(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	verificationReceiptPath := filepath.Join(t.TempDir(), "source-owner-verification.receipt")
	if err := os.WriteFile(verificationReceiptPath, []byte("{\"receipt_kind\":\"opaque_source_owner_verification\"}\n"), 0o600); err != nil {
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
		documentationFactoryProductionSourceCompilerDependencies{SourceCompiler: sourcePackageCompilerTestDependencies(t), Now: func() time.Time { return time.Date(2026, time.August, 28, 21, 30, 0, 0, time.UTC) }},
	)
	if err != nil {
		t.Fatal(err)
	}
	mutated := result.SourceReceipt
	verification := *mutated.ProductionSourceVerification
	verification.TestOwned = true
	verification.BindingSHA256 = ""
	raw, err := canonicalFactoryJSON(verification)
	if err != nil {
		t.Fatal(err)
	}
	verification.BindingSHA256 = sha256Hex(raw)
	mutated.ProductionSourceVerification = &verification
	mutated.ReceiptSHA256 = ""
	raw, err = canonicalFactoryJSON(mutated)
	if err != nil {
		t.Fatal(err)
	}
	mutated.ReceiptSHA256 = sha256Hex(raw)
	if err := validateDocumentationFactorySourceReceipt(mutated); err == nil || !strings.Contains(err.Error(), "not production-eligible") {
		t.Fatalf("mutated production trust receipt error = %v", err)
	}
}

func acceptedProductionSourcePackageVerification(request DocumentationFactoryProductionSourceVerificationRequest) DocumentationFactoryProductionSourceVerification {
	return DocumentationFactoryProductionSourceVerification{
		Provider:                            request.ExpectedProvider,
		SourcePackageSHA256:                 request.SourcePackageSHA256,
		EvidenceIdentitySetRootSHA256:       request.EvidenceIdentitySetRootSHA256,
		VerificationReceiptSHA256:           request.VerificationReceiptSHA256,
		VerifiedAt:                          request.ObservedAt,
		ProducerAuthenticated:               true,
		CurrentGenerationVerified:           true,
		CompleteEvidenceIdentitySetVerified: true,
	}
}
