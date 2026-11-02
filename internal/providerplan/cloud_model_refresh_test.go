package providerplan

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func cloudRefreshFixture(t *testing.T) (CloudSourceCandidateInput, CloudAPIProfileDocument, []byte, []byte, CloudModelRefreshOptions) {
	t.Helper()
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join("../../testdata/cloudapi", name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	var input CloudSourceCandidateInput
	if err := strictUnmarshal(read("candidate-input.json"), &input); err != nil {
		t.Fatal(err)
	}
	profiles, err := LoadCloudAPIProfileDocument("../../testdata/cloudapi/provider-profiles-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	old := read("official/gcp/compute-v1.discovery.json")
	fresh := read("refresh-20261102/compute-v1.discovery.json")
	options := CloudModelRefreshOptions{ModelID: "gcp-compute-model", ModelPath: "refresh-20261102/compute-v1.discovery.json", ExpectedSHA256: "ce740f987255bec9ed06e051e6df52797ddbe216bc8644b3433ccc16b0ebfe37", MappingVersion: "candidate-20261026", ServiceProfileVersion: "2", Retrieved: "2026-11-02", Source: CloudCatalogSourceIdentity{ID: "gcp-compute-model", URI: "https://www.googleapis.com/discovery/v1/apis/compute/v1/rest", StableCoordinate: "gcp/compute/v1@sha256:ce740f987255bec9ed06e051e6df52797ddbe216bc8644b3433ccc16b0ebfe37", FormatRevision: "discovery-20261026"}}
	return input, profiles, old, fresh, options
}

func TestCloudModelRefreshRebuildsCompletePreparation(t *testing.T) {
	input, profiles, old, fresh, options := cloudRefreshFixture(t)
	before, _ := canonicalFactoryJSON(input)
	next, nextProfiles, audit, err := RefreshCloudModelCandidates(input, profiles, old, fresh, options)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := canonicalFactoryJSON(input)
	if !bytes.Equal(before, after) {
		t.Fatal("mutated historical input")
	}
	if len(audit.Changes) != 6 {
		t.Fatalf("changes = %d", len(audit.Changes))
	}
	root := t.TempDir()
	paths := map[string]bool{next.NeutralSchemaExportPath: true}
	for _, model := range next.Models {
		paths[model.ModelPath] = true
		for _, path := range model.SupplementalEvidencePaths {
			paths[path] = true
		}
	}
	for _, target := range next.Targets {
		for _, binding := range target.MappingContract.EvidenceBindings {
			paths[binding.SourcePath] = true
		}
	}
	add := func(evidence []CloudProfileEvidence) {
		for _, item := range evidence {
			paths[item.LocalPath] = true
		}
	}
	for _, p := range nextProfiles.Providers {
		add(p.Evidence)
		for _, s := range p.Services {
			add(s.Evidence)
			for _, operation := range s.Operations {
				add(operation.Evidence)
			}
		}
	}
	for name := range paths {
		raw, err := os.ReadFile(filepath.Join("../../testdata/cloudapi", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range map[string]any{"candidate-input.json": next, "profiles.json": nextProfiles} {
		raw, err := canonicalFactoryJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	request, err := LoadCloudSourceCandidateInput(filepath.Join(root, "candidate-input.json"), NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	loadedProfiles, err := LoadCloudAPIProfileDocument(filepath.Join(root, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadCloudIngestionHandoffPolicy("../../testdata/cloudapi/ingestion-handoff-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := BuildCloudFactoryPreparation(request, scope, loadedProfiles, policy)
	if err != nil {
		t.Fatal(err)
	}
	var manifest CloudPreparationManifest
	if err := strictUnmarshal(prepared.ManifestJSON(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.DispositionTotals != (CloudMappingDispositionTotals{Mapped: 31, Private: 24, Unsupported: 200}) || manifest.Resources != 6 || manifest.OperationTargets != 9 {
		t.Fatalf("refreshed closure: %+v", manifest)
	}
	output := filepath.Join(root, "prepared")
	if err := prepared.PublishExclusive(output); err != nil {
		t.Fatal(err)
	}
	if err := prepared.VerifyDirectory(output); err != nil {
		t.Fatal(err)
	}
	bundle, err := BuildCloudModelRefreshBundle("../../testdata/cloudapi/candidate-input.json", "../../testdata/cloudapi/provider-profiles-v1.json", scope, policy, options)
	if err != nil {
		t.Fatalf("complete refresh bundle: %v", err)
	}
	bundleRoot := filepath.Join(root, "bundle")
	if err := bundle.PublishExclusive(bundleRoot); err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyDirectory(bundleRoot); err != nil {
		t.Fatal(err)
	}
}

func TestCloudModelRefreshRefusesUnjustifiedCarryForward(t *testing.T) {
	input, profiles, old, fresh, options := cloudRefreshFixture(t)
	for name, mutate := range map[string]func(*CloudSourceCandidateInput, *CloudAPIProfileDocument, *CloudModelRefreshOptions){
		"wrong new pin": func(_ *CloudSourceCandidateInput, _ *CloudAPIProfileDocument, o *CloudModelRefreshOptions) {
			o.ExpectedSHA256 = sha256Hex([]byte("wrong"))
		},
		"changed origin": func(_ *CloudSourceCandidateInput, _ *CloudAPIProfileDocument, o *CloudModelRefreshOptions) {
			o.Source.URI = "https://example.invalid/model"
		},
		"same generation": func(_ *CloudSourceCandidateInput, _ *CloudAPIProfileDocument, o *CloudModelRefreshOptions) {
			o.MappingVersion = "candidate-1"
		},
		"path escape": func(_ *CloudSourceCandidateInput, _ *CloudAPIProfileDocument, o *CloudModelRefreshOptions) {
			o.ModelPath = "../model.json"
		},
		"forged old locator": func(in *CloudSourceCandidateInput, _ *CloudAPIProfileDocument, _ *CloudModelRefreshOptions) {
			for i := range in.Targets {
				if in.Targets[i].ServiceID == "compute" {
					in.Targets[i].StableIdentityEvidence[0].Locator.StartByte++
					return
				}
			}
		},
		"forged semantic evidence": func(in *CloudSourceCandidateInput, _ *CloudAPIProfileDocument, _ *CloudModelRefreshOptions) {
			for i := range in.Targets {
				if in.Targets[i].ServiceID == "compute" && len(in.Targets[i].MappingContract.EvidenceBindings) > 0 {
					in.Targets[i].MappingContract.EvidenceBindings[0].SliceSHA256 = sha256Hex([]byte("wrong"))
					return
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := canonicalFactoryJSON(input)
			var candidate CloudSourceCandidateInput
			if err := strictUnmarshal(raw, &candidate); err != nil {
				t.Fatal(err)
			}
			p := profiles
			o := options
			mutate(&candidate, &p, &o)
			if _, _, _, err := RefreshCloudModelCandidates(candidate, p, old, fresh, o); err == nil {
				t.Fatal("accepted unjustified refresh")
			}
		})
	}
}

func TestCloudModelRefreshRejectsOperationSubstitution(t *testing.T) {
	input, profiles, old, fresh, options := cloudRefreshFixture(t)
	var locator CloudCatalogEvidenceLocator
	for _, p := range profiles.Providers {
		for _, s := range p.Services {
			if s.ServiceID == "compute" {
				locator = s.Operations[0].ModelEvidence.Locator
			}
		}
	}
	spans, err := cloudCatalogJSONPointerSpans(fresh)
	if err != nil {
		t.Fatal(err)
	}
	span := spans[locator.JSONPointer]
	changed := append([]byte(nil), fresh...)
	slice := changed[span.start:span.end]
	index := bytes.Index(slice, []byte(`"GET"`))
	if index < 0 {
		t.Fatal("fixture lacks HTTP method")
	}
	copy(slice[index:index+5], []byte(`"PUT"`))
	options.ExpectedSHA256 = sha256Hex(changed)
	if _, _, _, err := RefreshCloudModelCandidates(input, profiles, old, changed, options); err == nil {
		t.Fatal("accepted operation semantics substitution")
	}
	profileRaw, _ := canonicalFactoryJSON(profiles)
	var other CloudAPIProfileDocument
	if err := strictUnmarshal(profileRaw, &other); err != nil {
		t.Fatal(err)
	}
	for i := range other.Providers {
		for j := range other.Providers[i].Services {
			service := &other.Providers[i].Services[j]
			if service.ServiceID == "compute" {
				service.Operations[0].ModelEvidence.Locator.EvidenceID = "foreign"
			}
		}
	}
	options.ExpectedSHA256 = sha256Hex(fresh)
	if _, _, _, err := RefreshCloudModelCandidates(input, other, old, fresh, options); err == nil {
		t.Fatal("rebound foreign locator to model bytes")
	}
}
