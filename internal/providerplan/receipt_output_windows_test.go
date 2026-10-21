//go:build windows

package providerplan

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func installFactoryOutputRedirect(path string, target string) error {
	output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", path, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("create Windows junction fixture: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func TestWindowsFactoryOutputNativeStructContracts(t *testing.T) {
	if windowsFileDispositionInformationSize != 1 {
		t.Fatalf("FileDispositionInformation payload size = %d, want one-byte BOOLEAN", windowsFileDispositionInformationSize)
	}
	var layout windowsFileRenameInformation
	handleSize := unsafe.Sizeof(layout.rootDirectory)
	wantRootOffset := uintptr(4)
	if handleSize == 8 {
		wantRootOffset = 8
	}
	wantLengthOffset := wantRootOffset + handleSize
	wantNameOffset := wantLengthOffset + unsafe.Sizeof(layout.fileNameLength)
	if got := unsafe.Offsetof(layout.rootDirectory); got != wantRootOffset {
		t.Fatalf("FILE_RENAME_INFORMATION RootDirectory offset = %d, want %d", got, wantRootOffset)
	}
	if got := unsafe.Offsetof(layout.fileNameLength); got != wantLengthOffset {
		t.Fatalf("FILE_RENAME_INFORMATION FileNameLength offset = %d, want %d", got, wantLengthOffset)
	}
	if got := unsafe.Offsetof(layout.fileName); got != wantNameOffset {
		t.Fatalf("FILE_RENAME_INFORMATION FileName offset = %d, want %d", got, wantNameOffset)
	}
}

func TestWindowsFactoryOutputCreateOptionsRequireWriteThrough(t *testing.T) {
	want := uint32(windows.FILE_NON_DIRECTORY_FILE |
		windows.FILE_OPEN_REPARSE_POINT |
		windows.FILE_SYNCHRONOUS_IO_NONALERT |
		windows.FILE_WRITE_THROUGH)
	if got := uint32(windowsFactoryFileCreateOptions); got != want {
		t.Fatalf("NtCreateFile stage options = %#x, want exact no-follow synchronous write-through mask %#x", got, want)
	}
}

func TestWindowsFactoryOutputAbortDeletesExactStagedHandle(t *testing.T) {
	parent := t.TempDir()
	resolved, err := resolveFactoryOutputPath(filepath.Join(parent, "factory-receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	staged, _, err := createFactoryOutputExclusive(resolved, factoryOutputTestHooks{})
	if err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join(parent, staged.stagedName())
	if _, err := os.Lstat(stagePath); err != nil {
		t.Fatalf("private stage absent before abort: %v", err)
	}
	if err := staged.abort(); err != nil {
		_ = staged.release()
		t.Fatalf("handle-based stage disposition: %v", err)
	}
	if err := staged.release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stagePath); !os.IsNotExist(err) {
		t.Fatalf("handle-disposed private stage still exists: %v", err)
	}
}

func TestWindowsFactoryOutputPostRenameDurabilityFailureCannotSucceed(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "factory-receipt.json")
	barrierCalled := false
	injected := fmt.Errorf("injected post-rename durability failure")
	err := writeFactoryReceiptExclusiveWithHooks(path, []byte("receipt"), factoryOutputTestHooks{
		windowsPostRenameDurability: func() error {
			barrierCalled = true
			return injected
		},
	})
	if err == nil {
		t.Fatal("post-rename durability failure was reported as success")
	}
	if !strings.Contains(err.Error(), injected.Error()) {
		t.Fatalf("write error %q does not preserve injected durability failure", err)
	}
	if !barrierCalled {
		t.Fatal("post-rename durability barrier was not called")
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatalf("failed publication left final name behind: %v", statErr)
	}
}

func TestWriteFactoryReceiptExclusiveRejectsJunctionParent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "junction-parent")
	output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", junction, target).CombinedOutput()
	if err != nil {
		t.Fatalf("create Windows junction fixture: %v (%s)", err, strings.TrimSpace(string(output)))
	}
	if err := writeFactoryReceiptExclusive(filepath.Join(junction, "receipt.json"), []byte("receipt")); err == nil {
		t.Fatal("junction output parent was accepted")
	}
	if _, err := os.Lstat(filepath.Join(target, "receipt.json")); !os.IsNotExist(err) {
		t.Fatalf("junction refusal wrote into target directory: %v", err)
	}
}

func TestWriteFactoryReceiptExclusiveRejectsWindowsNormalizedAndDeviceComponents(t *testing.T) {
	for _, relative := range []string{
		"NUL", "con.txt", "PrN.json", "AUX", "COM1.log", "lPt9.txt",
		"COM¹", "com².log", "LPT³.json", "CONIN$", "conout$.json",
		"receipt.", "receipt ", filepath.Join("parent.", "receipt.json"), filepath.Join("parent ", "receipt.json"),
	} {
		t.Run(relative, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, relative)
			if err := WriteReceiptExclusive(path, []byte("must not be published")); err == nil {
				t.Fatalf("Windows-normalized or device output path %q was accepted", relative)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("refused output path %q left filesystem entries: %v", relative, entries)
			}
		})
	}
}

func TestWriteFactoryReceiptExclusiveRejectsExistingWindowsShortNameParentAlias(t *testing.T) {
	shortParent := `C:\PROGRA~1`
	if _, err := os.Stat(shortParent); err != nil {
		t.Fatalf("required Windows short-name positive-control parent %q is unavailable: %v", shortParent, err)
	}
	path := filepath.Join(shortParent, "velenza-factory-alias-refusal.json")
	if err := WriteReceiptExclusive(path, []byte("must not be published")); err == nil || !strings.Contains(err.Error(), "resolves through an alias") {
		t.Fatalf("short-name parent alias error = %v, want exact alias refusal", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("short-name alias refusal reached the final object: %v", err)
	}
}
