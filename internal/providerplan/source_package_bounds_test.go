package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSourcePackageTemplateResolutionCoordinatesAndUseAreExact(t *testing.T) {
	coordinate := sourcePackageCoordinate{Role: "source_contract", ID: "source.contract", Version: "v1"}
	materials := map[sourcePackageCoordinate]sourcePackageMaterial{
		coordinate: {coordinate: coordinate, raw: []byte(`{"amount":12.30,"nested":{"a/b~c":"value"}}`), authorityClass: "canonical"},
	}
	used := map[sourcePackageCoordinate]struct{}{}
	projection := func(kind, pointer string) map[string]interface{} {
		return map[string]interface{}{"$resource_projection": map[string]interface{}{"resource": coordinate, "projection": kind, "json_pointer": pointer}}
	}
	resolved, err := resolveSourcePackageTemplateValue(map[string]interface{}{"digest": projection(sourcePackageProjectionSHA256, ""), "bytes": projection(sourcePackageProjectionByteCount, ""), "value": projection(sourcePackageProjectionJSONValue, "/nested/a~1b~0c")}, materials, used, 0)
	if err != nil {
		t.Fatalf("resolve exact projections: %v", err)
	}
	value := resolved.(map[string]interface{})
	if value["value"] != "value" || value["digest"] != sha256Hex(materials[coordinate].raw) || value["bytes"] != json.Number("43") {
		t.Fatalf("resolved projection=%#v", value)
	}
	if _, exists := used[coordinate]; !exists || sourcePackageCoordinateLabel(coordinate) != "source_contract/source.contract/v1" {
		t.Fatalf("resource use/label was not exact: %v", used)
	}
	if _, err := resolveSourcePackageTemplateValue(projection(sourcePackageProjectionSHA256, "/amount"), materials, map[sourcePackageCoordinate]struct{}{}, 0); err == nil || !strings.Contains(err.Error(), "forbids") {
		t.Fatalf("digest projection pointer error=%v", err)
	}
	if _, err := resolveSourcePackageJSONPointer(map[string]interface{}{"rows": []interface{}{1}}, "/rows/01"); err == nil || !strings.Contains(err.Error(), "non-canonical") {
		t.Fatalf("noncanonical pointer error=%v", err)
	}
	if _, err := sourcePackageMaterialForReference(materials, sourcePackageCoordinate{Role: "missing", ID: "missing.id", Version: "v1"}, map[sourcePackageCoordinate]struct{}{}); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("missing material error=%v", err)
	}
	if err := validateSourcePackageDeclaredPath(" ../unsafe", "fixture"); err == nil {
		t.Fatal("padded traversal path accepted")
	}
	if err := validateSourcePackageBundlePath(".hidden/file.json", "fixture"); err == nil {
		t.Fatal("hidden bundle path accepted")
	}
}

func TestSourcePackageCompilerInputDependenciesAndOutputOrderFailClosed(t *testing.T) {
	dependencies := defaultDocumentationFactorySourceCompilerDependencies()
	options := DocumentationFactorySourceCompileOptions{SourcePackagePath: "fixture.json", OutputRoot: "out"}
	if err := validateDocumentationFactorySourceCompilerInputs(options, dependencies); err != nil {
		t.Fatalf("default dependencies and inputs: %v", err)
	}
	dependencies.Publish = nil
	if err := validateDocumentationFactorySourceCompilerInputs(options, dependencies); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("nil dependency error=%v", err)
	}
	if err := validateDocumentationFactorySourceCompilerInputs(DocumentationFactorySourceCompileOptions{SourcePackagePath: " fixture.json", OutputRoot: "out"}, defaultDocumentationFactorySourceCompilerDependencies()); err == nil || !strings.Contains(err.Error(), "padded") {
		t.Fatalf("padded input path error=%v", err)
	}
	files := sourcePackageOutputFiles(map[string][]byte{"b.json": []byte("b"), "a.json": []byte("a")})
	if len(files) != 2 || files[0].RelativePath != "a.json" || files[1].RelativePath != "b.json" {
		t.Fatalf("source output order=%#v", files)
	}
	files[0].Raw[0] = 'x'
	if string(sourcePackageOutputFiles(map[string][]byte{"a.json": []byte("a")})[0].Raw) != "a" {
		t.Fatal("source output files did not clone retained bytes")
	}
}

func TestProductionSourceVerificationReceiptBindsExactIdentitySet(t *testing.T) {
	digest := strings.Repeat("a", 64)
	identity := DocumentationFactoryProviderEvidenceIdentity{
		ManifestRole: "evidence_manifest", ManifestID: "manifest.a", ManifestVersion: "v1", ManifestRawSHA256: digest, ManifestByteCount: 10,
		ComponentOrdinal: 0, SourceContentSHA256: strings.Repeat("b", 64), SourceContentByteCount: 5,
		CarrierRole: "evidence_carrier", CarrierID: "carrier.a", CarrierVersion: "v1", CarrierRawSHA256: strings.Repeat("c", 64), CarrierByteCount: 5,
	}
	root, err := documentationFactoryProviderEvidenceIdentitySetRoot([]DocumentationFactoryProviderEvidenceIdentity{identity})
	if err != nil {
		t.Fatal(err)
	}
	request := DocumentationFactoryProductionSourceVerificationRequest{ExpectedProvider: "provider", SourcePackageSHA256: digest, SourcePackageByteCount: 20, EvidenceIdentities: []DocumentationFactoryProviderEvidenceIdentity{identity}, EvidenceIdentitySetRootSHA256: root, VerificationReceiptRaw: []byte("opaque receipt"), VerificationReceiptSHA256: strings.Repeat("d", 64), VerificationReceiptByteCount: 14, ObservedAt: "2026-09-09T00:00:00Z"}
	answer := DocumentationFactoryProductionSourceVerification{Provider: request.ExpectedProvider, SourcePackageSHA256: request.SourcePackageSHA256, EvidenceIdentitySetRootSHA256: root, VerificationReceiptSHA256: request.VerificationReceiptSHA256, VerifiedAt: request.ObservedAt, ProducerAuthenticated: true, CurrentGenerationVerified: true, CompleteEvidenceIdentitySetVerified: true}
	receipt, err := sealDocumentationFactoryProductionSourceVerification(request, answer)
	if err != nil {
		t.Fatalf("seal production receipt: %v", err)
	}
	if err := validateDocumentationFactoryProductionSourceVerificationReceipt(receipt); err != nil {
		t.Fatalf("validate sealed receipt: %v", err)
	}
	tampered := receipt
	tampered.EvidenceIdentities[0].CarrierID = "carrier.other"
	if err := validateDocumentationFactoryProductionSourceVerificationReceipt(tampered); err == nil || !strings.Contains(err.Error(), "root mismatch") {
		t.Fatalf("identity tamper error=%v", err)
	}
	answer.TestOwned = true
	if _, err := sealDocumentationFactoryProductionSourceVerification(request, answer); err == nil || !strings.Contains(err.Error(), "test-owned") {
		t.Fatalf("test-owned verification error=%v", err)
	}
}
