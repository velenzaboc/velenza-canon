package providerplan

import (
	"context"
	"strings"
	"testing"
	"time"
)

func productionVerificationRequestFixture() DocumentationFactoryProductionSourceVerificationRequest {
	return DocumentationFactoryProductionSourceVerificationRequest{
		ExpectedProvider:              "quickbooks",
		SourcePackageSHA256:           sha256Hex([]byte("package")),
		SourcePackageByteCount:        128,
		EvidenceIdentitySetRootSHA256: sha256Hex([]byte("identity set")),
		VerificationReceiptSHA256:     sha256Hex([]byte("verification receipt")),
		VerificationReceiptByteCount:  64,
		ObservedAt:                    time.Unix(1_700_000_000, 0).UTC().Format(time.RFC3339Nano),
	}
}

func productionVerificationAnswerFixture(request DocumentationFactoryProductionSourceVerificationRequest) DocumentationFactoryProductionSourceVerification {
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

// The verifier is the only production trust seam, so every coordinate it
// returns is re-checked against the request that was actually measured. A
// verdict that does not bind the exact package, identity set, receipt and
// instant must not become a factory receipt.
func TestSealDocumentationFactoryProductionSourceVerificationRefusesUnboundVerdicts(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*DocumentationFactoryProductionSourceVerification)
		want   string
	}{
		{
			name:   "test-owned evidence",
			mutate: func(a *DocumentationFactoryProductionSourceVerification) { a.TestOwned = true },
			want:   "returned test-owned evidence",
		},
		{
			name:   "producer is not authenticated",
			mutate: func(a *DocumentationFactoryProductionSourceVerification) { a.ProducerAuthenticated = false },
			want:   "lacks an authenticated producer",
		},
		{
			name:   "generation is not current",
			mutate: func(a *DocumentationFactoryProductionSourceVerification) { a.CurrentGenerationVerified = false },
			want:   "does not establish the current generation",
		},
		{
			name: "evidence identity set is incomplete",
			mutate: func(a *DocumentationFactoryProductionSourceVerification) {
				a.CompleteEvidenceIdentitySetVerified = false
			},
			want: "does not establish the complete evidence identity set",
		},
		{
			name:   "provider differs from the expected provider",
			mutate: func(a *DocumentationFactoryProductionSourceVerification) { a.Provider = "another_provider" },
			want:   "does not match expected provider",
		},
		{
			name: "package digest differs",
			mutate: func(a *DocumentationFactoryProductionSourceVerification) {
				a.SourcePackageSHA256 = sha256Hex([]byte("a different package"))
			},
			want: "does not bind the exact source package",
		},
		{
			name: "evidence identity root differs",
			mutate: func(a *DocumentationFactoryProductionSourceVerification) {
				a.EvidenceIdentitySetRootSHA256 = sha256Hex([]byte("a different identity set"))
			},
			want: "does not bind the exact provider evidence identity set",
		},
		{
			name: "verification receipt digest differs",
			mutate: func(a *DocumentationFactoryProductionSourceVerification) {
				a.VerificationReceiptSHA256 = sha256Hex([]byte("a different receipt"))
			},
			want: "does not bind the exact verification receipt",
		},
		{
			name: "verified instant differs from the observed instant",
			mutate: func(a *DocumentationFactoryProductionSourceVerification) {
				a.VerifiedAt = time.Unix(1_800_000_000, 0).UTC().Format(time.RFC3339Nano)
			},
			want: "stale or bound to a different observation instant",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := productionVerificationRequestFixture()
			answer := productionVerificationAnswerFixture(request)
			test.mutate(&answer)
			receipt, err := sealDocumentationFactoryProductionSourceVerification(request, answer)
			if err == nil {
				t.Fatalf("an unbound verification verdict was sealed")
			}
			if receipt.BindingSHA256 != "" {
				t.Fatalf("a refused verdict produced a binding digest %q", receipt.BindingSHA256)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestValidateDocumentationFactoryProductionSourceVerificationReceiptRefusesIneligibleReceipts(t *testing.T) {
	eligible := func() DocumentationFactoryProductionSourceVerificationReceipt {
		return DocumentationFactoryProductionSourceVerificationReceipt{
			VerificationKind:                    documentationFactoryProductionSourceVerificationKind,
			VerificationVersion:                 documentationFactoryProductionSourceVerificationVersion,
			Result:                              documentationFactoryProductionSourceVerificationResult,
			Provider:                            "quickbooks",
			ObservedAt:                          time.Unix(1_700_000_000, 0).UTC().Format(time.RFC3339Nano),
			SourcePackageSHA256:                 sha256Hex([]byte("package")),
			SourcePackageByteCount:              128,
			EvidenceIdentitySetRootSHA256:       sha256Hex([]byte("identity set")),
			VerificationReceiptSHA256:           sha256Hex([]byte("verification receipt")),
			VerificationReceiptByteCount:        64,
			ProducerAuthenticated:               true,
			CurrentGenerationVerified:           true,
			CompleteEvidenceIdentitySetVerified: true,
			BindingSHA256:                       sha256Hex([]byte("binding")),
		}
	}

	for _, test := range []struct {
		name   string
		mutate func(*DocumentationFactoryProductionSourceVerificationReceipt)
		want   string
	}{
		{
			name:   "wrong verification kind",
			mutate: func(r *DocumentationFactoryProductionSourceVerificationReceipt) { r.VerificationKind = "other" },
			want:   "kind/version/result is invalid",
		},
		{
			name:   "wrong result",
			mutate: func(r *DocumentationFactoryProductionSourceVerificationReceipt) { r.Result = "other" },
			want:   "kind/version/result is invalid",
		},
		{
			name:   "noncanonical provider",
			mutate: func(r *DocumentationFactoryProductionSourceVerificationReceipt) { r.Provider = "Not A Provider" },
			want:   "provider is invalid",
		},
		{
			name:   "observed_at is not canonical UTC",
			mutate: func(r *DocumentationFactoryProductionSourceVerificationReceipt) { r.ObservedAt = "2026-09-15 12:00:00" },
			want:   "observed_at is not canonical UTC RFC3339",
		},
		{
			name:   "source package byte count is not positive",
			mutate: func(r *DocumentationFactoryProductionSourceVerificationReceipt) { r.SourcePackageByteCount = 0 },
			want:   "byte counts are invalid",
		},
		{
			name: "verification receipt byte count is not positive",
			mutate: func(r *DocumentationFactoryProductionSourceVerificationReceipt) {
				r.VerificationReceiptByteCount = -1
			},
			want: "byte counts are invalid",
		},
		{
			name:   "malformed binding digest",
			mutate: func(r *DocumentationFactoryProductionSourceVerificationReceipt) { r.BindingSHA256 = "not-a-sha256" },
			want:   "is invalid",
		},
		{
			name:   "receipt claims test ownership",
			mutate: func(r *DocumentationFactoryProductionSourceVerificationReceipt) { r.TestOwned = true },
			want:   "trust verdict is not production-eligible",
		},
		{
			name: "receipt drops producer authentication",
			mutate: func(r *DocumentationFactoryProductionSourceVerificationReceipt) {
				r.ProducerAuthenticated = false
			},
			want: "trust verdict is not production-eligible",
		},
		{
			name: "receipt carries no evidence identities",
			mutate: func(r *DocumentationFactoryProductionSourceVerificationReceipt) {
				r.EvidenceIdentities = nil
			},
			want: "evidence identity set is empty",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			receipt := eligible()
			test.mutate(&receipt)
			if err := validateDocumentationFactoryProductionSourceVerificationReceipt(receipt); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestProviderEvidenceIdentitySetRootRefusesEmptyAndInvalidIdentities(t *testing.T) {
	if _, err := documentationFactoryProviderEvidenceIdentitySetRoot(nil); err == nil ||
		!strings.Contains(err.Error(), "evidence identity set is empty") {
		t.Fatalf("empty identity set error = %v, want an empty-set refusal", err)
	}
	invalid := []DocumentationFactoryProviderEvidenceIdentity{{}}
	if _, err := documentationFactoryProviderEvidenceIdentitySetRoot(invalid); err == nil ||
		!strings.Contains(err.Error(), "evidence identity[0]") {
		t.Fatalf("invalid identity error = %v, want the offending index named", err)
	}
	if err := validateDocumentationFactoryProviderEvidenceIdentity(DocumentationFactoryProviderEvidenceIdentity{}); err == nil {
		t.Fatal("an empty provider evidence identity was accepted")
	}
}

func TestCompileProductionSourcePackageRefusesMissingTrustSeamInputs(t *testing.T) {
	options := DocumentationFactoryProductionSourceCompileOptions{
		SourcePackagePath:       "package.json",
		VerificationReceiptPath: "receipt.json",
		ExpectedProvider:        "quickbooks",
		OutputRoot:              "out",
	}
	dependencies := documentationFactoryProductionSourceCompilerDependencies{Now: time.Now}

	if _, err := compileDocumentationFactoryProductionSourcePackageWithDependencies(nil, options, nil, dependencies); err == nil ||
		!strings.Contains(err.Error(), "context is required") {
		t.Fatalf("nil context error = %v, want a required-context refusal", err)
	}
	// A nil verifier must refuse before the factory runs rather than defaulting
	// to some permissive implementation.
	if _, err := compileDocumentationFactoryProductionSourcePackageWithDependencies(context.Background(), options, nil, dependencies); err == nil ||
		!strings.Contains(err.Error(), "verifier is required") {
		t.Fatalf("nil verifier error = %v, want a required-verifier refusal", err)
	}
}
