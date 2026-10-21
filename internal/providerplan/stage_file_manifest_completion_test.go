package providerplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStageCompileFileManifestRefusesANilAccumulatorAndPaddedPath(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeStageInputManifestFixture(t, dir,
		`{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)

	if _, _, _, err := loadStageCompileFileManifestWithAdmission(manifestPath, nil); err == nil ||
		!strings.Contains(err.Error(), "accumulator is nil") {
		t.Fatalf("nil accumulator error = %v, want an explicit nil refusal", err)
	}

	for _, test := range []struct {
		name string
		path string
	}{
		{name: "padded", path: " " + manifestPath},
		{name: "empty", path: "   "},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := loadStageCompileFileManifestWithAdmission(test.path, newCanonicalProviderInputAdmissionAccumulator())
			if err == nil || !strings.Contains(err.Error(), "empty or padded") {
				t.Fatalf("error = %v, want an empty-or-padded manifest path refusal", err)
			}
		})
	}
}

func TestLoadStageCompileFileManifestRefusesUnusableDeclaredPaths(t *testing.T) {
	for _, test := range []struct {
		name    string
		declare string
		prepare func(t *testing.T, dir string)
		want    string
	}{
		{
			name:    "escapes the manifest directory",
			declare: "../escape.json",
			want:    "empty, padded, or non-relative",
		},
		{
			name:    "is empty",
			declare: "",
			want:    "empty, padded, or non-relative",
		},
		{
			name:    "is padded",
			declare: " request.json",
			want:    "empty, padded, or non-relative",
		},
		{
			name:    "names a directory rather than a file",
			declare: "a-directory",
			prepare: func(t *testing.T, dir string) {
				if err := os.Mkdir(filepath.Join(dir, "a-directory"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			want: "is not a regular file",
		},
		{
			name:    "names an absent file",
			declare: "absent.json",
			want:    "",
		},
		{
			name:    "names an empty file",
			declare: "request.json",
			prepare: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "request.json"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "is empty",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if test.prepare != nil {
				test.prepare(t, dir)
			}
			manifestPath := writeStageInputManifestFixture(t, dir,
				`{"request_path":`+quoteStageManifestJSONString(test.declare)+`,"predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
			_, _, err := LoadStageCompileFileManifest(manifestPath)
			if err == nil {
				t.Fatalf("declared path %q was accepted", test.declare)
			}
			if test.want != "" && !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestStageCompileManifestPreflightRefusesIncompleteCoordinates(t *testing.T) {
	for _, test := range []struct {
		name     string
		manifest string
		want     string
	}{
		{
			name:     "material without a role",
			manifest: `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[{"role":"  ","id":"artifact","version":"1","path":"material.json"}],"evidence_bodies":[]}`,
			want:     "materials[0] has an empty role, id, or version",
		},
		{
			name:     "material without a version",
			manifest: `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[{"role":"material","id":"artifact","version":"","path":"material.json"}],"evidence_bodies":[]}`,
			want:     "materials[0] has an empty role, id, or version",
		},
		{
			name:     "evidence body without a manifest role",
			manifest: `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[{"manifest_role":"","manifest_id":"artifact","manifest_version":"1","component_ordinal":0,"path":"body.json"}]}`,
			want:     "evidence_bodies[0] has an empty manifest role, id, or version",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "request.json"), []byte(`{"value":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
			manifestPath := writeStageInputManifestFixture(t, dir, test.manifest)
			// The preflight runs before any declared file is opened, so an
			// incomplete coordinate is refused without touching the filesystem.
			if _, _, err := LoadStageCompileFileManifest(manifestPath); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestReadExactStageManifestFileSealsItsOwnAdmission(t *testing.T) {
	dir := t.TempDir()
	want := []byte("exact material bytes\n")
	if err := os.WriteFile(filepath.Join(dir, "material.json"), want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readExactStageManifestFile(dir, "material.json", "materials[0].path")
	if err != nil {
		t.Fatalf("read exact stage manifest file: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("bytes = %q, want %q", got, want)
	}

	if _, err := readExactStageManifestFile(dir, "../escape.json", "materials[0].path"); err == nil {
		t.Fatal("a declared path escaping the manifest directory was accepted")
	}
}

func TestStageCompileInputAdmissionBindingRefusesEmptyAndMutatedBindings(t *testing.T) {
	if err := bindAndValidateStageCompileInputAdmission(nil, providerInputAdmissionProof{}, nil); err == nil ||
		!strings.Contains(err.Error(), "binding is empty") {
		t.Fatalf("nil binding error = %v, want an empty-binding refusal", err)
	}
	empty := stageCompileInputAdmissionBinding{}
	if err := bindAndValidateStageCompileInputAdmission(&empty, providerInputAdmissionProof{}, nil); err == nil ||
		!strings.Contains(err.Error(), "binding is empty") {
		t.Fatalf("empty binding error = %v, want an empty-binding refusal", err)
	}
	if err := compactStageCompileInputAdmissionBinding(nil); err == nil ||
		!strings.Contains(err.Error(), "binding is empty") {
		t.Fatalf("nil compaction error = %v, want an empty-binding refusal", err)
	}
}

func TestStageCompileInputAdmissionCompactionReleasesExactlyBoundBytes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "request.json"), []byte("exact request bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := writeStageInputManifestFixture(t, dir,
		`{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	_, _, binding, err := loadStageCompileFileManifestWithAdmission(manifestPath, accumulator)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := accumulator.seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := bindAndValidateStageCompileInputAdmission(&binding, proof, accumulator.resources); err != nil {
		t.Fatal(err)
	}

	if err := compactStageCompileInputAdmissionBinding(&binding); err != nil {
		t.Fatalf("compaction of an exactly bound binding failed: %v", err)
	}
	for index, item := range binding.Items {
		if item.Raw != nil {
			t.Fatalf("item %d retained its bytes after compaction", index)
		}
		if !item.ContentValidated {
			t.Fatalf("item %d was released without recording that it was validated", index)
		}
	}
	// A compacted binding still satisfies the admission check, because the
	// content proof survives the release of the bytes themselves.
	if err := bindAndValidateStageCompileInputAdmission(&binding, proof, accumulator.resources); err != nil {
		t.Fatalf("compacted binding no longer validates: %v", err)
	}
}

func TestStageCompileInputAdmissionCompactionRefusesMutatedBytes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "request.json"), []byte("exact request bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := writeStageInputManifestFixture(t, dir,
		`{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	_, _, binding, err := loadStageCompileFileManifestWithAdmission(manifestPath, accumulator)
	if err != nil {
		t.Fatal(err)
	}
	binding.Items[len(binding.Items)-1].Raw = append([]byte(nil), []byte("mutated in memory")...)
	if err := compactStageCompileInputAdmissionBinding(&binding); err == nil ||
		!strings.Contains(err.Error(), "not exactly bound before release") {
		t.Fatalf("mutated compaction error = %v, want an exact-binding refusal", err)
	}
}

func quoteStageManifestJSONString(value string) string {
	return `"` + strings.ReplaceAll(value, `\`, `\\`) + `"`
}
