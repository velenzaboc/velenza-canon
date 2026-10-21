//go:build darwin

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const retainedDarwinChildMarker = "VELENZA_RETAINED_DARWIN_CHILD_TEST"

func TestDarwinRetainedChildExecutesCanonicalSelectedPath(t *testing.T) {
	path := copyDarwinTestExecutable(t)
	child, err := openRetainedChildExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	command, err := child.command([]string{"-test.run", "^TestDarwinRetainedChildHelper$"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Path != path || len(command.ExtraFiles) != 0 {
		t.Fatalf("Darwin child command path=%q extra_files=%d, want canonical path %q and no descriptor launch", command.Path, len(command.ExtraFiles), path)
	}
	command.Env = append(os.Environ(), retainedDarwinChildMarker+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("execute retained Darwin child: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("retained-darwin-child-ok")) {
		t.Fatalf("retained Darwin child omitted marker: %s", output)
	}
	if err := child.verify(); err != nil {
		t.Fatalf("reverify executed Darwin child: %v", err)
	}
}

func TestDarwinRetainedChildRejectsSameBytePathReplacementBeforeCommand(t *testing.T) {
	path := copyDarwinTestExecutable(t)
	child, err := openRetainedChildExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := child.command(nil); err == nil {
		t.Fatal("same-byte Darwin child path replacement was accepted")
	}
}

func TestDarwinRetainedChildRejectsAncestorSymlinkSubstitution(t *testing.T) {
	path := copyDarwinTestExecutable(t)
	child, err := openRetainedChildExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	parent := filepath.Dir(path)
	movedParent := parent + ".retained"
	if err := os.Rename(parent, movedParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(movedParent), parent); err != nil {
		_ = os.Rename(movedParent, parent)
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove(parent)
		_ = os.Rename(movedParent, parent)
	}()
	if _, err := child.command(nil); err == nil {
		t.Fatal("Darwin child ancestor symlink substitution was accepted")
	}
}

func TestDarwinRetainedChildRejectsSameSizeByteMutationWithRestoredMtime(t *testing.T) {
	path := copyDarwinTestExecutable(t)
	child, err := openRetainedChildExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), raw...)
	mutated[len(mutated)-1] ^= 0xff
	if err := os.WriteFile(path, mutated, before.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("test mutation did not restore size and mtime: before=%+v after=%+v err=%v", before, after, err)
	}
	if _, err := child.command(nil); err == nil {
		t.Fatal("same-size Darwin child byte mutation with restored mtime was accepted")
	}
}

func TestDarwinRetainedChildRejectsPathDriftDuringExecution(t *testing.T) {
	path := copyDarwinTestExecutable(t)
	child, err := openRetainedChildExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	coordination := t.TempDir()
	ready := filepath.Join(coordination, "ready")
	proceed := filepath.Join(coordination, "proceed")
	command, err := child.command([]string{"-test.run", "^TestDarwinRetainedChildHelper$"})
	if err != nil {
		t.Fatal(err)
	}
	command.Env = append(os.Environ(),
		retainedDarwinChildMarker+"=1",
		retainedDarwinChildMarker+"_READY="+ready,
		retainedDarwinChildMarker+"_PROCEED="+proceed,
	)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.WriteFile(proceed, []byte("continue"), 0o600)
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	waitForDarwinTestPath(t, ready)
	if err := os.Rename(path, path+".running"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proceed, []byte("continue"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("retained Darwin helper failed after path drift: %v\n%s", err, output.Bytes())
	}
	if err := child.verify(); err == nil {
		t.Fatal("Darwin child path drift during execution was accepted")
	}
}

func TestDarwinRetainedChildHelper(t *testing.T) {
	if os.Getenv(retainedDarwinChildMarker) == "1" {
		if ready := os.Getenv(retainedDarwinChildMarker + "_READY"); ready != "" {
			if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
				t.Fatal(err)
			}
			proceed := os.Getenv(retainedDarwinChildMarker + "_PROCEED")
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, err := os.Lstat(proceed); err == nil {
					break
				} else if !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if time.Now().After(deadline) {
					t.Fatal("timed out waiting for parent continuation")
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		fmt.Fprintln(os.Stdout, "retained-darwin-child-ok")
	}
}

func waitForDarwinTestPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Lstat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for Darwin helper readiness")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func copyDarwinTestExecutable(t *testing.T) string {
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
	path := filepath.Join(t.TempDir(), "provider-release-darwin-test")
	if err := os.WriteFile(path, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
