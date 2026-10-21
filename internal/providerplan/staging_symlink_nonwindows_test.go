//go:build !windows

package providerplan

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeProviderInputSymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Fatal(err)
	}
}

func TestResolveRelativeEvidenceStagingPathRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	manifestDirectory := filepath.Join(root, "manifest")
	if err := os.Mkdir(manifestDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(manifestDirectory, "evidence.jsonl")
	if err := os.WriteFile(manifestPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside.b64")
	if err := os.WriteFile(outside, []byte("ZXhhY3Q="), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(manifestDirectory, "linked.b64")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	_, err := resolveRelativeEvidenceStagingPath(manifestPath, filepath.Base(link))
	if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
		t.Fatalf("got %v, want symlink escape refusal", err)
	}
}

func TestProviderInputAdmissionRejectsDirectSymlinksAndLinkedParents(t *testing.T) {
	t.Run("dependency or authority file", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "authority-target.md")
		raw := []byte("exact authority bytes")
		if err := os.WriteFile(target, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "authority.md")
		makeProviderInputSymlink(t, target, link)
		_, err := readVerificationAuthorityWithAdmission(link, verificationAuthorityRoleGrandVision, newCanonicalProviderInputAdmissionAccumulator())
		if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
			t.Fatalf("error = %v, want direct authority/dependency symlink refusal", err)
		}
	})

	t.Run("evidence manifest", func(t *testing.T) {
		fixture := newTestFixture(t)
		link := filepath.Join(t.TempDir(), "evidence.jsonl")
		makeProviderInputSymlink(t, fixture.evidencePath, link)
		_, err := loadEvidenceBodiesWithAdmission([]string{link}, map[string]struct{}{supportedEvidenceRepresentationKind: {}}, newCanonicalProviderInputAdmissionAccumulator())
		if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
			t.Fatalf("error = %v, want direct evidence-manifest symlink refusal", err)
		}
	})

	t.Run("linked parent", func(t *testing.T) {
		root := t.TempDir()
		realDir := filepath.Join(root, "real")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(realDir, "authority.md"), []byte("exact authority bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		linkedDir := filepath.Join(root, "linked")
		makeProviderInputSymlink(t, realDir, linkedDir)
		_, err := readArtifactInputWithAdmission(filepath.Join(linkedDir, "authority.md"), newCanonicalProviderInputAdmissionAccumulator())
		if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
			t.Fatalf("error = %v, want linked parent refusal", err)
		}
	})
}

func TestProviderInputAdmissionRejectsInRootStagingBodySymlink(t *testing.T) {
	body := []byte("exact staged evidence body")
	encoded := []byte(base64.StdEncoding.EncodeToString(body))
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.jsonl")
	if err := os.WriteFile(manifestPath, []byte("manifest placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "body-target.b64")
	if err := os.WriteFile(target, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "body.b64")
	makeProviderInputSymlink(t, target, link)
	_, _, err := decodeBoundedRelativeEvidenceStagingFile(
		manifestPath,
		strings.Repeat("f", 64),
		filepath.Base(link),
		evidenceSourceCoordinate{Ref: "fixture", URL: "https://example.com/fixture"},
		int64(len(body)),
		sha256Hex(body),
		newCanonicalProviderInputAdmissionAccumulator(),
	)
	if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
		t.Fatalf("error = %v, want in-root staging-body link refusal", err)
	}
}

func TestStageCompileInputAdmissionRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	manifestDir := filepath.Join(root, "manifest")
	if err := os.Mkdir(manifestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside.json")
	if err := os.WriteFile(outside, []byte("outside exact bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(manifestDir, "request.json")
	makeProviderInputSymlink(t, outside, link)
	manifestPath := writeStageInputManifestFixture(t, manifestDir, `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
	_, _, err := LoadStageCompileFileManifest(manifestPath)
	if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
		t.Fatalf("error = %v, want stage input symlink-escape refusal", err)
	}
}

func TestStageCompileInputAdmissionRejectsInRootSymlinkAndLinkedParent(t *testing.T) {
	t.Run("direct manifest link", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "request.json"), []byte("exact request bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		target := writeStageInputManifestFixture(t, dir, `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
		link := filepath.Join(dir, "linked-inputs.json")
		makeProviderInputSymlink(t, target, link)
		_, _, err := LoadStageCompileFileManifest(link)
		if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
			t.Fatalf("error = %v, want direct stage-manifest link refusal", err)
		}
	})

	t.Run("in-root input link", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, []byte("exact request bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		makeProviderInputSymlink(t, target, filepath.Join(dir, "request.json"))
		manifestPath := writeStageInputManifestFixture(t, dir, `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
		_, _, err := LoadStageCompileFileManifest(manifestPath)
		if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
			t.Fatalf("error = %v, want in-root stage input link refusal", err)
		}
	})

	t.Run("linked parent", func(t *testing.T) {
		root := t.TempDir()
		realDir := filepath.Join(root, "real")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(realDir, "request.json"), []byte("exact request bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		manifestPath := writeStageInputManifestFixture(t, realDir, `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
		linkedDir := filepath.Join(root, "linked")
		makeProviderInputSymlink(t, realDir, linkedDir)
		_, _, err := LoadStageCompileFileManifest(filepath.Join(linkedDir, filepath.Base(manifestPath)))
		if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
			t.Fatalf("error = %v, want linked parent refusal", err)
		}
	})
}
