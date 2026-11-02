package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildCloudMappingPackageClosesSelectedActualMappings(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	first, err := BuildCloudMappingPackage(request, scope)
	if err != nil {
		t.Fatalf("build four-service mapping package: %v", err)
	}
	second, err := BuildCloudMappingPackage(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	if !EqualCloudMappingPackages(first, second) {
		t.Fatal("four-service mapping package is not deterministic")
	}
	if first.Status != cloudMappingPackageStatus || first.Version != cloudMappingPackageVersion || first.DispositionTotals != (CloudMappingDispositionTotals{Mapped: 31, Private: 24, Unsupported: 200}) {
		t.Fatalf("mapping package status/closure = %q/%q/%+v", first.Status, first.Version, first.DispositionTotals)
	}
	if !isLowerSHA256(first.ScopeSHA256) {
		t.Fatalf("mapping package omitted canonical scope binding: %q", first.ScopeSHA256)
	}
	if len(first.ProviderPackages) != 2 || len(first.Documents) != 3 {
		t.Fatalf("provider/document count = %d/%d, want 2/3", len(first.ProviderPackages), len(first.Documents))
	}
	if first.DispositionTotals.total() != 255 {
		t.Fatalf("disposition total = %d, want 255", first.DispositionTotals.total())
	}

	providers := map[string]CloudProviderMappingPackage{}
	for _, provider := range first.ProviderPackages {
		providers[provider.ProviderID] = provider
		body, ok := first.Documents[provider.DocumentRole]
		if !ok || !bytes.HasSuffix(body, []byte{'\n'}) || provider.DocumentSHA256 != sha256Hex(body) {
			t.Fatalf("provider %s document does not bind exact canonical bytes", provider.ProviderID)
		}
		if len(provider.CatalogSourceIDs) != 2 {
			t.Fatalf("provider %s catalog closure = %v, want two retained models", provider.ProviderID, provider.CatalogSourceIDs)
		}
	}
	if providers["aws"].DispositionTotals != (CloudMappingDispositionTotals{Mapped: 16, Private: 10, Unsupported: 81}) || providers["gcp"].DispositionTotals != (CloudMappingDispositionTotals{Mapped: 15, Private: 14, Unsupported: 119}) {
		t.Fatalf("provider mapping closures = aws:%+v gcp:%+v", providers["aws"].DispositionTotals, providers["gcp"].DispositionTotals)
	}

	parent := first.Documents[cloudMappingParentRole]
	if !bytes.HasSuffix(parent, []byte{'\n'}) || bytes.Contains(parent, []byte(`"authoritative_graph_materialization":true`)) || bytes.Contains(parent, []byte(`"source_qualification_status":"qualified"`)) {
		t.Fatal("parent manifest promoted an unqualified candidate package")
	}
	var decoded map[string]any
	if err := json.Unmarshal(parent, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["status"] != cloudMappingPackageStatus || decoded["authoritative_graph_materialization"] != false || decoded["selected_scope_sha256"] != first.ScopeSHA256 {
		t.Fatalf("parent manifest status = %#v", decoded)
	}
}

func TestBuildCloudMappingPackageRefusesPartialOrChangedClosure(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*CloudSourceCandidateRequest){
		"partial target roster":     func(value *CloudSourceCandidateRequest) { value.Targets = value.Targets[:len(value.Targets)-1] },
		"unpinned catalog identity": func(value *CloudSourceCandidateRequest) { value.Catalogs[0].Source.ID = "substituted-model" },
		"mutated parsed catalog":    func(value *CloudSourceCandidateRequest) { value.Catalogs[0].ModelSHA256 = strings.Repeat("0", 64) },
		"disposition closure changed": func(value *CloudSourceCandidateRequest) {
			value.Targets[0].MappingContract.Fields[0].Disposition = CloudSourcePrivateOnly
		},
	} {
		t.Run(name, func(t *testing.T) {
			copyRequest := cloneCloudMappingPackageRequest(t, request)
			mutate(&copyRequest)
			scope, loadErr := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if _, err := BuildCloudMappingPackage(copyRequest, scope); err == nil {
				t.Fatal("incomplete or substituted mapping closure was accepted")
			}
		})
	}
}

func TestCloudMappingDispositionTotalsAccountsForEveryAllowedDisposition(t *testing.T) {
	target := CloudSourceObjectTarget{ProviderID: "test", ServiceID: "service", APISurfaceID: "surface", OperationID: "read", SourceObjectType: "Thing", RecordClassSymbol: "thing", SourceSchemaVersion: "1", SourceMappingVersion: "1", MappingContract: &CloudMappingContract{Fields: []CloudMappingContractField{
		{SourcePointer: "/mapped", Disposition: CloudSourceMapsExactSourceFact},
		{SourcePointer: "/not-observed", Disposition: CloudSourceNotObserved},
		{SourcePointer: "/private", Disposition: CloudSourcePrivateOnly},
		{SourcePointer: "/unknown", Disposition: CloudSourceUnknown},
		{SourcePointer: "/unsupported", Disposition: CloudSourceUnsupported},
	}}}
	totals, err := cloudMappingDispositionTotals([]CloudSourceObjectTarget{target})
	if err != nil || totals != (CloudMappingDispositionTotals{Mapped: 1, NotObserved: 1, Private: 1, Unknown: 1, Unsupported: 1}) || totals.total() != 5 {
		t.Fatalf("allowed disposition accounting = %+v / %v", totals, err)
	}
	target.MappingContract.Fields[0].Disposition = CloudSourceFieldDisposition("unrecognized")
	if _, err := cloudMappingDispositionTotals([]CloudSourceObjectTarget{target}); err == nil {
		t.Fatal("unrecognized disposition was silently omitted")
	}
}

func cloneCloudMappingPackageRequest(t *testing.T, request CloudSourceCandidateRequest) CloudSourceCandidateRequest {
	t.Helper()
	// The builder receives parsed catalogs and contracts. A JSON round-trip is
	// unsuitable because catalogs intentionally contain raw JSON bytes, so copy
	// the mutable target contract slice explicitly and leave immutable catalog
	// model evidence intact.
	copyRequest := CloudSourceCandidateRequest{Catalogs: append([]CloudCatalog(nil), request.Catalogs...), Targets: append([]CloudSourceObjectTarget(nil), request.Targets...), retainedModels: append([]PinnedCloudModel(nil), request.retainedModels...)}
	for i := range copyRequest.Targets {
		original := request.Targets[i]
		if original.MappingContract == nil {
			continue
		}
		contract := *original.MappingContract
		contract.Fields = append([]CloudMappingContractField(nil), original.MappingContract.Fields...)
		contract.Nested = append([]CloudNestedDecomposition(nil), original.MappingContract.Nested...)
		for nested := range contract.Nested {
			contract.Nested[nested].Fields = append([]CloudMappingContractField(nil), original.MappingContract.Nested[nested].Fields...)
		}
		copyRequest.Targets[i].MappingContract = &contract
	}
	return copyRequest
}

func TestCloudMappingPackageDoesNotDescribeCandidateAsQualification(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := BuildCloudMappingPackage(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	for role, body := range pkg.Documents {
		if strings.Contains(string(body), `"admission_authorized":true`) || strings.Contains(string(body), `"authoritative_graph_materialization":true`) {
			t.Fatalf("%s asserts unavailable authority", role)
		}
	}
}

func TestWriteCloudMappingPackageExclusiveBindsOnlyDeclaredDocuments(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := BuildCloudMappingPackage(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "mapping-package")
	if err := WriteCloudMappingPackageExclusive(root, pkg); err != nil {
		t.Fatal(err)
	}
	for role, want := range pkg.Documents {
		got, err := os.ReadFile(filepath.Join(root, role+".json"))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("written %s does not equal declared package bytes: %v", role, err)
		}
	}
	if err := WriteCloudMappingPackageExclusive(root, pkg); err == nil {
		t.Fatal("existing mapping package root was replaced")
	}
}

func TestWriteCloudMappingPackageExclusiveRefusesTamperedManifestOrProviderClosure(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	base, err := BuildCloudMappingPackage(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*CloudMappingPackage){
		"parent count": func(pkg *CloudMappingPackage) {
			rewriteCloudMappingPackageDocument(t, pkg, cloudMappingParentRole, func(body map[string]any) { body["selected_catalog_count"] = float64(99) })
		},
		"provider catalog lineage": func(pkg *CloudMappingPackage) {
			provider := &pkg.ProviderPackages[0]
			rewriteCloudMappingPackageDocument(t, pkg, provider.DocumentRole, func(body map[string]any) {
				catalogs := body["catalogs"].([]any)
				catalogs[0].(map[string]any)["model_sha256"] = strings.Repeat("0", 64)
			})
			provider.DocumentSHA256 = sha256Hex(pkg.Documents[provider.DocumentRole])
		},
		"provider target totals": func(pkg *CloudMappingPackage) {
			provider := &pkg.ProviderPackages[0]
			rewriteCloudMappingPackageDocument(t, pkg, provider.DocumentRole, func(body map[string]any) {
				body["disposition_totals"].(map[string]any)["unsupported"] = float64(0)
			})
			provider.DocumentSHA256 = sha256Hex(pkg.Documents[provider.DocumentRole])
		},
	} {
		t.Run(name, func(t *testing.T) {
			pkg := cloneCloudMappingPackage(t, base)
			mutate(&pkg)
			root := filepath.Join(t.TempDir(), "must-not-publish")
			if err := WriteCloudMappingPackageExclusive(root, pkg); err == nil {
				t.Fatal("tampered package was published")
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatalf("refused package created output root: %v", err)
			}
		})
	}
}

func cloneCloudMappingPackage(t *testing.T, pkg CloudMappingPackage) CloudMappingPackage {
	t.Helper()
	clone := pkg
	clone.ProviderPackages = append([]CloudProviderMappingPackage(nil), pkg.ProviderPackages...)
	for index := range clone.ProviderPackages {
		clone.ProviderPackages[index].Catalogs = append([]CloudMappingCatalogReference(nil), pkg.ProviderPackages[index].Catalogs...)
		clone.ProviderPackages[index].CatalogSourceIDs = append([]string(nil), pkg.ProviderPackages[index].CatalogSourceIDs...)
		clone.ProviderPackages[index].TargetKeys = append([]string(nil), pkg.ProviderPackages[index].TargetKeys...)
	}
	clone.Documents = make(map[string][]byte, len(pkg.Documents))
	for role, raw := range pkg.Documents {
		clone.Documents[role] = append([]byte(nil), raw...)
	}
	return clone
}

func rewriteCloudMappingPackageDocument(t *testing.T, pkg *CloudMappingPackage, role string, mutate func(map[string]any)) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(pkg.Documents[role], &body); err != nil {
		t.Fatal(err)
	}
	mutate(body)
	raw, err := canonicalFactoryJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	pkg.Documents[role] = append(raw, '\n')
}
