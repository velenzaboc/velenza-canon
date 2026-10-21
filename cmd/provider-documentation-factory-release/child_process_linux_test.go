//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const retainedLinuxChildMarker = "VELENZA_RETAINED_LINUX_CHILD_TEST"

func TestLinuxRetainedChildExecutesProcDescriptor(t *testing.T) {
	path := copyLinuxTestExecutable(t)
	child, err := openRetainedChildExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	command, err := child.command([]string{"-test.run", "^TestLinuxRetainedChildHelper$"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Path != "/proc/self/fd/3" || len(command.ExtraFiles) != 1 || command.ExtraFiles[0] != child.file {
		t.Fatalf("Linux child command path=%q extra_files=%d, want /proc/self/fd/3 and the retained executable", command.Path, len(command.ExtraFiles))
	}
	command.Env = append(os.Environ(), retainedLinuxChildMarker+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("execute retained Linux child: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("retained-linux-child-ok")) {
		t.Fatalf("retained Linux child omitted marker: %s", output)
	}
	if err := child.verify(); err != nil {
		t.Fatalf("reverify executed Linux child: %v", err)
	}
}

func TestLinuxRetainedChildHelper(t *testing.T) {
	marker := os.Getenv(retainedLinuxChildMarker)
	if marker == "" {
		return
	}
	if marker != "1" {
		t.Fatalf("unexpected retained Linux child marker %q", marker)
	}
	fmt.Fprintln(os.Stdout, "retained-linux-child-ok")
}

func copyLinuxTestExecutable(t *testing.T) string {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "provider-release-linux-test")
	if err := os.WriteFile(path, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
