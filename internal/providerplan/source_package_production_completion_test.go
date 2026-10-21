package providerplan

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestProductionSourceCompilerPublicBoundaryRejectsNilContext(t *testing.T) {
	_, err := CompileDocumentationFactoryProductionSourcePackage(nil, DocumentationFactoryProductionSourceCompileOptions{}, productionSourcePackageVerifierFunc(func(context.Context, DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
		return DocumentationFactoryProductionSourceVerification{}, nil
	}))
	if err == nil || !strings.Contains(err.Error(), "context is required") {
		t.Fatalf("nil-context error = %v", err)
	}
}

func TestProductionSourceCompilerDependencyAndCoordinateBoundariesFailClosed(t *testing.T) {
	verifier := productionSourcePackageVerifierFunc(func(context.Context, DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
		return DocumentationFactoryProductionSourceVerification{}, nil
	})
	tests := []struct {
		name         string
		options      DocumentationFactoryProductionSourceCompileOptions
		dependencies documentationFactoryProductionSourceCompilerDependencies
		want         string
	}{
		{
			name:         "missing clock",
			dependencies: documentationFactoryProductionSourceCompilerDependencies{},
			want:         "clock is required",
		},
		{
			name:    "empty verification receipt path",
			options: DocumentationFactoryProductionSourceCompileOptions{SourcePackagePath: "source.json", OutputRoot: "out", ExpectedProvider: "provider"},
			dependencies: documentationFactoryProductionSourceCompilerDependencies{
				SourceCompiler: defaultDocumentationFactorySourceCompilerDependencies(),
				Now:            func() time.Time { return time.Now() },
			},
			want: "verification receipt path",
		},
		{
			name:    "noncanonical provider",
			options: DocumentationFactoryProductionSourceCompileOptions{SourcePackagePath: "source.json", OutputRoot: "out", VerificationReceiptPath: "receipt.json", ExpectedProvider: "Bad Provider"},
			dependencies: documentationFactoryProductionSourceCompilerDependencies{
				SourceCompiler: defaultDocumentationFactorySourceCompilerDependencies(),
				Now:            func() time.Time { return time.Now() },
			},
			want: "expected provider",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := compileDocumentationFactoryProductionSourcePackageWithDependencies(context.Background(), testCase.options, verifier, testCase.dependencies)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("boundary error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestProductionVerificationReceiptValidationRejectsEveryTrustBoundary(t *testing.T) {
	valid := productionVerificationReceiptForCompletionTest(t)
	tests := []struct {
		name   string
		mutate func(*DocumentationFactoryProductionSourceVerificationReceipt)
		want   string
	}{
		{name: "envelope identity", mutate: func(receipt *DocumentationFactoryProductionSourceVerificationReceipt) {
			receipt.VerificationKind = "wrong"
		}, want: "kind/version/result"},
		{name: "provider", mutate: func(receipt *DocumentationFactoryProductionSourceVerificationReceipt) {
			receipt.Provider = "Bad Provider"
		}, want: "provider is invalid"},
		{name: "observation instant", mutate: func(receipt *DocumentationFactoryProductionSourceVerificationReceipt) {
			receipt.ObservedAt = "not-a-time"
		}, want: "observed_at"},
		{name: "byte count", mutate: func(receipt *DocumentationFactoryProductionSourceVerificationReceipt) {
			receipt.SourcePackageByteCount = 0
		}, want: "byte counts"},
		{name: "digest", mutate: func(receipt *DocumentationFactoryProductionSourceVerificationReceipt) {
			receipt.BindingSHA256 = "uppercase"
		}, want: "is invalid"},
		{name: "trust verdict", mutate: func(receipt *DocumentationFactoryProductionSourceVerificationReceipt) {
			receipt.ProducerAuthenticated = false
		}, want: "not production-eligible"},
		{name: "identity", mutate: func(receipt *DocumentationFactoryProductionSourceVerificationReceipt) {
			receipt.EvidenceIdentities[0].ManifestRole = "Bad Role"
		}, want: "manifest coordinate"},
		{name: "binding", mutate: func(receipt *DocumentationFactoryProductionSourceVerificationReceipt) {
			receipt.BindingSHA256 = strings.Repeat("f", 64)
		}, want: "binding hash mismatch"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			receipt := valid
			receipt.EvidenceIdentities = cloneDocumentationFactoryProviderEvidenceIdentities(valid.EvidenceIdentities)
			testCase.mutate(&receipt)
			if err := validateDocumentationFactoryProductionSourceVerificationReceipt(receipt); err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("receipt validation error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestProductionEvidenceIdentitySetRejectsEmptyDuplicateAndMalformedRows(t *testing.T) {
	valid := productionVerificationReceiptForCompletionTest(t).EvidenceIdentities[0]
	if _, err := documentationFactoryProviderEvidenceIdentitySetRoot(nil); err == nil || !strings.Contains(err.Error(), "set is empty") {
		t.Fatalf("empty identity-set error = %v", err)
	}
	if _, err := documentationFactoryProviderEvidenceIdentitySetRoot([]DocumentationFactoryProviderEvidenceIdentity{valid, valid}); err == nil || !strings.Contains(err.Error(), "unsorted or duplicated") {
		t.Fatalf("duplicate identity-set error = %v", err)
	}
	malformed := valid
	malformed.CarrierRawSHA256 = "not-a-digest"
	if _, err := documentationFactoryProviderEvidenceIdentitySetRoot([]DocumentationFactoryProviderEvidenceIdentity{malformed}); err == nil || !strings.Contains(err.Error(), "carrier_raw_sha256 is invalid") {
		t.Fatalf("malformed identity-set error = %v", err)
	}
	malformed = valid
	malformed.SourceContentByteCount = 0
	if err := validateDocumentationFactoryProviderEvidenceIdentity(malformed); err == nil || !strings.Contains(err.Error(), "byte count is invalid") {
		t.Fatalf("invalid identity byte-count error = %v", err)
	}
}

func productionVerificationReceiptForCompletionTest(t *testing.T) DocumentationFactoryProductionSourceVerificationReceipt {
	t.Helper()
	digest := strings.Repeat("a", 64)
	identity := DocumentationFactoryProviderEvidenceIdentity{
		ManifestRole: "evidence_manifest", ManifestID: "manifest.a", ManifestVersion: "v1", ManifestRawSHA256: digest, ManifestByteCount: 10,
		ComponentOrdinal: 0, SourceContentSHA256: strings.Repeat("b", 64), SourceContentByteCount: 5,
		CarrierRole: "evidence_carrier", CarrierID: "carrier.a", CarrierVersion: "v1", CarrierRawSHA256: strings.Repeat("c", 64), CarrierByteCount: 5,
	}
	root, err := documentationFactoryProviderEvidenceIdentitySetRoot([]DocumentationFactoryProviderEvidenceIdentity{identity})
	if err != nil {
		t.Fatalf("build identity root: %v", err)
	}
	request := DocumentationFactoryProductionSourceVerificationRequest{
		ExpectedProvider: "provider", SourcePackageSHA256: digest, SourcePackageByteCount: 20,
		EvidenceIdentities: []DocumentationFactoryProviderEvidenceIdentity{identity}, EvidenceIdentitySetRootSHA256: root,
		VerificationReceiptSHA256: strings.Repeat("d", 64), VerificationReceiptByteCount: 14, ObservedAt: "2026-09-09T00:00:00Z",
	}
	receipt, err := sealDocumentationFactoryProductionSourceVerification(request, acceptedProductionSourcePackageVerification(request))
	if err != nil {
		t.Fatalf("seal valid production verification receipt: %v", err)
	}
	return receipt
}
