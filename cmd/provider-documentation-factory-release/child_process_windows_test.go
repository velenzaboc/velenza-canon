//go:build windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

const (
	retainedChildWindowsHelperEnvironment = "VELENZA_RETAINED_CHILD_WINDOWS_HELPER"
	retainedChildWindowsHelperOutput      = "retained-child-windows-helper-ok"
	retainedChildWindowsMoveReplace       = 0x00000001
)

var retainedChildWindowsMoveFileEx = releaseKernel32.NewProc("MoveFileExW")

func TestRetainedChildWindowsUnchangedExecutionAndIdentity(t *testing.T) {
	_, _, executable := createRetainedChildWindowsFixture(t)
	child, err := openRetainedChildExecutable(executable)
	if err != nil {
		t.Fatalf("open retained child: %v", err)
	}
	defer child.close()
	originalIdentity := child.identity
	originalMeasurement := child.measurement

	command, err := child.command([]string{"-test.run=^TestRetainedChildWindowsHelperProcess$"})
	if err != nil {
		t.Fatalf("construct retained child command: %v", err)
	}
	command.Env = append(os.Environ(), retainedChildWindowsHelperEnvironment+"=1")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("execute retained child: %v\nstderr: %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), retainedChildWindowsHelperOutput) {
		t.Fatalf("retained child output %q does not contain helper sentinel", stdout.String())
	}
	if err := child.verify(); err != nil {
		t.Fatalf("verify unchanged retained child: %v", err)
	}
	if child.identity != originalIdentity || child.measurement != originalMeasurement {
		t.Fatal("retained child identity or measurement changed after execution")
	}
	visibleIdentity, err := releaseWindowsPathIdentity(executable)
	if err != nil {
		t.Fatalf("derive visible child identity: %v", err)
	}
	if visibleIdentity != originalIdentity {
		t.Fatal("visible child path does not preserve the complete FILE_ID_128 identity")
	}
}

func TestRetainedChildWindowsRefusesLeafReplacement(t *testing.T) {
	root, _, executable := createRetainedChildWindowsFixture(t)
	replacement := filepath.Join(root, "replacement.exe")
	copyRetainedChildWindowsTestExecutable(t, replacement)

	child, err := openRetainedChildExecutable(executable)
	if err != nil {
		t.Fatalf("open retained child: %v", err)
	}
	originalIdentity := child.identity
	if err := moveRetainedChildWindowsPath(replacement, executable, retainedChildWindowsMoveReplace); err == nil {
		child.close()
		t.Fatal("leaf replacement succeeded while the executable identity was retained")
	}
	if err := child.verify(); err != nil {
		child.close()
		t.Fatalf("verify retained child after refused leaf replacement: %v", err)
	}
	visibleIdentity, err := releaseWindowsPathIdentity(executable)
	if err != nil || visibleIdentity != originalIdentity {
		child.close()
		t.Fatal("refused leaf replacement changed the complete visible FILE_ID_128 identity")
	}
	child.close()

	if err := moveRetainedChildWindowsPath(replacement, executable, retainedChildWindowsMoveReplace); err != nil {
		t.Fatalf("leaf replacement remained blocked after releasing retained handles: %v", err)
	}
}

func TestRetainedChildWindowsRefusesAncestorReplacement(t *testing.T) {
	root, ancestor, executable := createRetainedChildWindowsFixture(t)
	movedAncestor := filepath.Join(root, "locked-moved")

	child, err := openRetainedChildExecutable(executable)
	if err != nil {
		t.Fatalf("open retained child: %v", err)
	}
	if err := moveRetainedChildWindowsPath(ancestor, movedAncestor, 0); err == nil {
		child.close()
		t.Fatal("ancestor replacement succeeded while the executable path chain was retained")
	}
	if err := child.verify(); err != nil {
		child.close()
		t.Fatalf("verify retained child after refused ancestor replacement: %v", err)
	}
	child.close()

	if err := moveRetainedChildWindowsPath(ancestor, movedAncestor, 0); err != nil {
		t.Fatalf("ancestor rename remained blocked after releasing retained handles: %v", err)
	}
	if err := moveRetainedChildWindowsPath(movedAncestor, ancestor, 0); err != nil {
		t.Fatalf("restore ancestor after unlocked control rename: %v", err)
	}
}

func TestRetainedChildWindowsHelperProcess(t *testing.T) {
	if os.Getenv(retainedChildWindowsHelperEnvironment) != "1" {
		return
	}
	if _, err := fmt.Fprint(os.Stdout, retainedChildWindowsHelperOutput); err != nil {
		t.Fatalf("write helper sentinel: %v", err)
	}
}

func createRetainedChildWindowsFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	ancestor := filepath.Join(root, "locked")
	output := filepath.Join(ancestor, "output")
	if err := os.MkdirAll(output, 0o700); err != nil {
		t.Fatalf("create retained child fixture directories: %v", err)
	}
	executable := filepath.Join(output, "provider-documentation-factory-run.exe")
	copyRetainedChildWindowsTestExecutable(t, executable)
	return root, ancestor, executable
}

func copyRetainedChildWindowsTestExecutable(t *testing.T, destination string) {
	t.Helper()
	sourcePath, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve current test executable: %v", err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open current test executable: %v", err)
	}
	defer source.Close()
	destinationFile, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatalf("create retained child test executable: %v", err)
	}
	if _, err := io.Copy(destinationFile, source); err != nil {
		_ = destinationFile.Close()
		t.Fatalf("copy retained child test executable: %v", err)
	}
	if err := destinationFile.Sync(); err != nil {
		_ = destinationFile.Close()
		t.Fatalf("sync retained child test executable: %v", err)
	}
	if err := destinationFile.Close(); err != nil {
		t.Fatalf("close retained child test executable: %v", err)
	}
}

func moveRetainedChildWindowsPath(source, destination string, flags uint32) error {
	sourcePointer, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPointer, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	result, _, callErr := retainedChildWindowsMoveFileEx.Call(
		uintptr(unsafe.Pointer(sourcePointer)),
		uintptr(unsafe.Pointer(destinationPointer)),
		uintptr(flags),
	)
	if result == 0 {
		return fmt.Errorf("MoveFileExW %q to %q: %w", source, destination, callErr)
	}
	return nil
}
