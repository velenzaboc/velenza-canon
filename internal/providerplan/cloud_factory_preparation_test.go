package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCloudFactoryPreparationReconcilesAndReverifies(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := LoadCloudAPIProfileDocument("../../testdata/cloudapi/provider-profiles-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadCloudIngestionHandoffPolicy("../../testdata/cloudapi/ingestion-handoff-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := BuildCloudFactoryPreparation(request, scope, profiles, policy)
	if err != nil {
		t.Fatal(err)
	}
	var manifest CloudPreparationManifest
	if err := json.Unmarshal(prepared.ManifestJSON(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "candidate_prepared_unqualified" || manifest.Providers != 2 || manifest.Services != 4 || manifest.Resources != 6 || manifest.OperationTargets != 9 || manifest.DispositionTotals != (CloudMappingDispositionTotals{Mapped: 31, Private: 24, Unsupported: 200}) {
		t.Fatalf("unexpected closure: %+v", manifest)
	}
	if len(manifest.Documents) != 7 {
		t.Fatalf("document count = %d", len(manifest.Documents))
	}
	root := filepath.Join(t.TempDir(), "prepared")
	if err := prepared.PublishExclusive(root); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCloudFactoryPreparation(root, request, scope, profiles, policy); err != nil {
		t.Fatal(err)
	}
	// Copy-only access prevents post-construction caller mutation.
	copyManifest := prepared.ManifestJSON()
	copyManifest[0] = '!'
	if bytes.Equal(copyManifest, prepared.ManifestJSON()) {
		t.Fatal("manifest aliases sealed preparation")
	}
	if err := prepared.PublishExclusive(root); err == nil {
		t.Fatal("replaced an existing output tree")
	}
	if err := prepared.VerifyDirectory(root); err != nil {
		t.Fatal(err)
	}
	t.Run("changed payload", func(t *testing.T) {
		path := filepath.Join(root, "coverage.json")
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := prepared.VerifyDirectory(root); err == nil {
			t.Fatal("accepted substituted coverage")
		}
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("extra member", func(t *testing.T) {
		path := filepath.Join(root, "unexpected.json")
		if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := prepared.VerifyDirectory(root); err == nil {
			t.Fatal("accepted extra member")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("extra empty directory", func(t *testing.T) {
		path := filepath.Join(root, "unexpected")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := prepared.VerifyDirectory(root); err == nil {
			t.Fatal("accepted extra directory")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing member", func(t *testing.T) {
		path := filepath.Join(root, "profiles.json")
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := prepared.VerifyDirectory(root); err == nil {
			t.Fatal("accepted missing profile")
		}
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("wrong profile pin", func(t *testing.T) {
		var other CloudAPIProfileDocument
		raw, err := json.Marshal(profiles)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &other); err != nil {
			t.Fatal(err)
		}
		other.Providers[0].Services[0].CatalogModelSHA256 = sha256Hex([]byte("wrong"))
		if _, err := BuildCloudFactoryPreparation(request, scope, other, policy); err == nil {
			t.Fatal("accepted substituted model/profile binding")
		}
	})
	if err := prepared.VerifyDirectory(root); err != nil {
		t.Fatal(err)
	}
}

func TestCloudFactoryPreparationRejectsUnconstructed(t *testing.T) {
	var empty CloudFactoryPreparation
	root := filepath.Join(t.TempDir(), "absent")
	if err := empty.PublishExclusive(root); err == nil {
		t.Fatal("published unconstructed preparation")
	}
	if err := empty.VerifyDirectory(root); err == nil {
		t.Fatal("verified unconstructed preparation")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("unconstructed publication had filesystem effects")
	}
}
