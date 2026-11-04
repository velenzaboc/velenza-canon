package main

import (
	"bytes"
	"github.com/velenzaboc/velenza-canon/internal/providerplan"
	"os"
	"path/filepath"
	"testing"
)

func TestModelRefreshCommandCreatesReverifiableSuccessor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "refreshed")
	args := []string{"--input", "../../testdata/cloudapi/candidate-input.json", "--profiles", "../../testdata/cloudapi/provider-profiles-v1.json", "--scope", "../../testdata/cloudapi/mapping-package-scope.json", "--ingestion-policy", "../../testdata/cloudapi/ingestion-handoff-policy.json", "--refresh", "../../testdata/cloudapi/refresh-20261102/refresh-request.json", "--output-root", root}
	var out, errout bytes.Buffer
	if code := run(args, &out, &errout); code != 0 {
		t.Fatalf("create %d: %s", code, errout.String())
	}
	first := append([]byte(nil), out.Bytes()...)
	out.Reset()
	errout.Reset()
	if code := run(append(args, "--verify"), &out, &errout); code != 0 || !bytes.Equal(first, out.Bytes()) {
		t.Fatalf("verify %d: %s", code, errout.String())
	}
	request, err := providerplan.LoadCloudSourceCandidateInput(filepath.Join(root, "candidate-input.json"), providerplan.NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := providerplan.LoadCloudAPIProfileDocument(filepath.Join(root, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	scope, err := providerplan.LoadCloudMappingPackageScope(filepath.Join(root, "scope.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := providerplan.LoadCloudIngestionHandoffPolicy(filepath.Join(root, "ingestion-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := providerplan.ValidateCloudFactoryPreparation(filepath.Join(root, "prepared"), request, scope, profiles, policy); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "revision-audit.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errout.Reset()
	if run(append(args, "--verify"), &out, &errout) == 0 {
		t.Fatal("accepted changed revision audit")
	}
}
