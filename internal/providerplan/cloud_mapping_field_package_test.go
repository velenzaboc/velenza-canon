package providerplan

import "testing"

func TestCloudMappingFieldPackageClosesAllSelectedOccurrences(t *testing.T) {
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
	targets, programs, gaps := 0, 0, 0
	for _, provider := range pkg.ProviderPackages {
		var doc cloudMappingProviderDocument
		if err := strictUnmarshal(pkg.Documents[provider.DocumentRole], &doc); err != nil {
			t.Fatal(err)
		}
		if err := validateCloudMappingFieldPackages(doc); err != nil {
			t.Fatal(err)
		}
		targets += len(doc.FieldDerivations)
		for _, field := range doc.FieldDerivations {
			programs += len(field.Programs)
			gaps += len(field.Gaps)
		}
		// Tamper the native package member itself, without relying on the
		// surrounding document hash to reject a missing field or wrong model.
		for _, mutate := range []func(*cloudMappingProviderDocument){
			func(d *cloudMappingProviderDocument) {
				d.FieldDerivations = d.FieldDerivations[:len(d.FieldDerivations)-1]
			},
			func(d *cloudMappingProviderDocument) {
				d.FieldDerivations[0].Programs = d.FieldDerivations[0].Programs[1:]
			},
			func(d *cloudMappingProviderDocument) {
				d.FieldDerivations[0].ModelSHA256 = sha256Hex([]byte("other model"))
			},
			func(d *cloudMappingProviderDocument) {
				d.FieldDerivations[0].SourceSchemaOwnerLocator.JSONPointer = "/invented"
			},
			func(d *cloudMappingProviderDocument) {
				d.FieldDerivations[0].Programs[0].ProgramSHA256 = sha256Hex([]byte("other program"))
			},
			func(d *cloudMappingProviderDocument) { d.FieldDerivations[0].Programs[0].FieldPointer = "/invented" },
		} {
			var changed cloudMappingProviderDocument
			if err := strictUnmarshal(pkg.Documents[provider.DocumentRole], &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := validateCloudMappingFieldPackages(changed); err == nil {
				t.Fatal("changed field package accepted")
			}
		}
	}
	if targets != 9 || programs != 255 || gaps != 0 {
		t.Fatalf("field closure targets=%d programs=%d exact-span gaps=%d", targets, programs, gaps)
	}
}
