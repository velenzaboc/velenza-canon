//go:build windows

package providerplan

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type reparsePointFileInfo struct {
	attributes uint32
}

func (info reparsePointFileInfo) Name() string       { return "fixture" }
func (info reparsePointFileInfo) Size() int64        { return 1 }
func (info reparsePointFileInfo) Mode() os.FileMode  { return 0o600 }
func (info reparsePointFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (info reparsePointFileInfo) IsDir() bool        { return false }
func (info reparsePointFileInfo) Sys() any {
	return &syscall.Win32FileAttributeData{FileAttributes: info.attributes}
}

func makeWindowsJunction(t *testing.T, target, junction string) {
	t.Helper()
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, target).CombinedOutput()
	if err != nil {
		t.Fatalf("create Windows junction fixture: %v (%s)", err, strings.TrimSpace(string(output)))
	}
	t.Cleanup(func() {
		if err := os.Remove(junction); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove junction fixture: %v", err)
		}
	})
}

func TestWindowsReparseAttributeDetection(t *testing.T) {
	if !fileInfoHasReparsePoint(reparsePointFileInfo{attributes: syscall.FILE_ATTRIBUTE_REPARSE_POINT}) {
		t.Fatal("reparse-point attribute was not detected")
	}
	if fileInfoHasReparsePoint(reparsePointFileInfo{attributes: syscall.FILE_ATTRIBUTE_NORMAL}) {
		t.Fatal("normal-file attribute was classified as a reparse point")
	}
}

func TestWindowsStableIdentityDistinguishesEqualLegacyLow64FileIDs(t *testing.T) {
	low64 := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	leftID := [16]byte{8: 9}
	rightID := [16]byte{8: 10}
	copy(leftID[:8], low64[:])
	copy(rightID[:8], low64[:])
	left := providerInputStableFileIdentity{volume: 7, fileID: leftID}
	right := providerInputStableFileIdentity{volume: 7, fileID: rightID}
	if left == right {
		t.Fatal("128-bit Windows identity collapsed distinct high-64 file ID bytes")
	}
	if string(left.fileID[:8]) != string(right.fileID[:8]) {
		t.Fatal("fixture does not preserve all eight legacy low-64 file ID bytes")
	}
}

func TestWindowsStableIdentityUsesFileIDInfoAndFailsClosed(t *testing.T) {
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "identity-probe"), os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	want := providerWindowsFileIDInfo{VolumeSerialNumber: 19, FileID: [16]byte{0: 1, 8: 2, 15: 3}}
	identity, err := stableProviderInputFileIdentityWithQuery(file, func(_ windows.Handle, class uint32, buffer *byte, size uint32) error {
		if class != windows.FileIdInfo {
			t.Fatalf("identity query class = %d, want FileIdInfo", class)
		}
		if size != uint32(unsafe.Sizeof(providerWindowsFileIDInfo{})) || size != 24 {
			t.Fatalf("identity query buffer size = %d, want exact 24-byte FILE_ID_INFO ABI", size)
		}
		*(*providerWindowsFileIDInfo)(unsafe.Pointer(buffer)) = want
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if identity != (providerInputStableFileIdentity{volume: want.VolumeSerialNumber, fileID: want.FileID}) {
		t.Fatalf("queried stable identity = %+v, want exact FILE_ID_INFO %+v", identity, want)
	}
	if _, err := stableProviderInputFileIdentityWithQuery(file, func(windows.Handle, uint32, *byte, uint32) error {
		return windows.ERROR_NOT_SUPPORTED
	}); err == nil {
		t.Fatal("unsupported 128-bit file identity query fell back instead of failing closed")
	}
}

func TestProviderInputAdmissionRejectsWindowsAlternateDataStreams(t *testing.T) {
	for _, path := range []string{
		`C:\provider\authority.json:shadow`,
		`C:\provider\authority.json::$DATA`,
		`\\server\share\manifest.json:stream`,
		`relative.json:stream`,
		`C:\provider:stream\manifest.json`,
	} {
		if err := validateProviderInputPathSyntax(path, "provider input"); err == nil || !strings.Contains(err.Error(), "alternate-data-stream") {
			t.Fatalf("ADS path %q error = %v, want syntax refusal", path, err)
		}
	}
	for _, path := range []string{
		`C:\provider\authority.json`,
		`C:provider\authority.json`,
		`\\server\share\manifest.json`,
		`\\?\C:\provider\authority.json`,
		`\\?\UNC\server\share\manifest.json`,
	} {
		if err := validateProviderInputPathSyntax(path, "provider input"); err != nil {
			t.Fatalf("ordinary Windows path %q rejected: %v", path, err)
		}
	}

	for _, resourceKind := range []string{
		providerInputAdmissionResourceKindStageManifest,
		providerInputAdmissionResourceKindAuthority,
		providerInputAdmissionResourceKindManifest,
		providerInputAdmissionResourceKindArtifact,
	} {
		_, err := readBoundedProviderInputFile(
			`C:\provider\top-level-input.json:shadow`,
			resourceKind,
			resourceKind,
			"",
			newCanonicalProviderInputAdmissionAccumulator(),
		)
		if err == nil || !strings.Contains(err.Error(), "alternate-data-stream") {
			t.Fatalf("top-level %s ADS error = %v, want refusal before file read", resourceKind, err)
		}
	}
}

func TestProviderInputAdmissionRejectsWindowsReparsePoints(t *testing.T) {
	t.Run("direct dependency or authority parent", func(t *testing.T) {
		root := t.TempDir()
		realDir := filepath.Join(root, "real")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		raw := []byte("exact authority bytes")
		if err := os.WriteFile(filepath.Join(realDir, "authority.md"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		junction := filepath.Join(root, "junction")
		makeWindowsJunction(t, realDir, junction)
		_, err := readVerificationAuthorityWithAdmission(filepath.Join(junction, "authority.md"), verificationAuthorityRoleGrandVision, newCanonicalProviderInputAdmissionAccumulator())
		if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
			t.Fatalf("error = %v, want Windows dependency/authority junction-parent refusal", err)
		}
	})

	t.Run("direct evidence manifest parent", func(t *testing.T) {
		root := t.TempDir()
		realDir := filepath.Join(root, "real")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(realDir, "evidence.jsonl"), []byte("manifest bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		junction := filepath.Join(root, "junction")
		makeWindowsJunction(t, realDir, junction)
		_, err := readBoundedProviderInputFile(filepath.Join(junction, "evidence.jsonl"), "evidence manifest", providerInputAdmissionResourceKindManifest, "", newCanonicalProviderInputAdmissionAccumulator())
		if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
			t.Fatalf("error = %v, want Windows evidence-manifest junction-parent refusal", err)
		}
	})

	t.Run("direct stage manifest parent", func(t *testing.T) {
		root := t.TempDir()
		realDir := filepath.Join(root, "real")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(realDir, "request.json"), []byte("exact request bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		manifestPath := writeStageInputManifestFixture(t, realDir, `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
		junction := filepath.Join(root, "junction")
		makeWindowsJunction(t, realDir, junction)
		_, _, err := LoadStageCompileFileManifest(filepath.Join(junction, filepath.Base(manifestPath)))
		if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
			t.Fatalf("error = %v, want Windows stage-manifest junction-parent refusal", err)
		}
	})

	t.Run("in-root stage input component", func(t *testing.T) {
		root := t.TempDir()
		manifestDir := filepath.Join(root, "manifest")
		realInputDir := filepath.Join(root, "real-input")
		if err := os.Mkdir(manifestDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(realInputDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(realInputDir, "request.json"), []byte("exact request bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		junction := filepath.Join(manifestDir, "linked")
		makeWindowsJunction(t, realInputDir, junction)
		manifestPath := writeStageInputManifestFixture(t, manifestDir, `{"request_path":"linked/request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
		_, _, err := LoadStageCompileFileManifest(manifestPath)
		if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
			t.Fatalf("error = %v, want Windows in-root stage-input reparse refusal", err)
		}
	})

	t.Run("in-root evidence staging component", func(t *testing.T) {
		body := []byte("exact staged evidence body")
		encoded := []byte(base64.StdEncoding.EncodeToString(body))
		root := t.TempDir()
		manifestDir := filepath.Join(root, "manifest")
		realCarrierDir := filepath.Join(root, "real-carrier")
		if err := os.Mkdir(manifestDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(realCarrierDir, 0o700); err != nil {
			t.Fatal(err)
		}
		manifestPath := filepath.Join(manifestDir, "manifest.jsonl")
		if err := os.WriteFile(manifestPath, []byte("manifest placeholder"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(realCarrierDir, "body.b64"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		junction := filepath.Join(manifestDir, "linked")
		makeWindowsJunction(t, realCarrierDir, junction)
		_, _, err := decodeBoundedRelativeEvidenceStagingFile(
			manifestPath,
			strings.Repeat("f", 64),
			"linked/body.b64",
			evidenceSourceCoordinate{Ref: "fixture", URL: "https://example.com/fixture"},
			int64(len(body)),
			sha256Hex(body),
			newCanonicalProviderInputAdmissionAccumulator(),
		)
		if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
			t.Fatalf("error = %v, want Windows in-root evidence-staging reparse refusal", err)
		}
	})
}
