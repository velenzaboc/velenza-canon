//go:build windows

package providerplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFactoryCleanSourceRejectsWindowsJunctionParent(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	externalRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(externalRoot, "escape.go"), []byte("package escape\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	makeWindowsJunction(t, externalRoot, filepath.Join(sourceRoot, "candidate-junction"))
	assertFactoryCleanSourceCopyFails(t, sourceRoot, "symbolic link or reparse point")
}

func TestFactoryCleanSourceRejectsCanonicalPathJunction(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "escape.go"), []byte("package escape\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	canonicalParent := filepath.Join(sourceRoot, "_canonical")
	if err := os.MkdirAll(canonicalParent, 0o700); err != nil {
		t.Fatal(err)
	}
	makeWindowsJunction(t, outside, filepath.Join(canonicalParent, "specs-repo"))
	assertFactoryCleanSourceCopyFails(t, sourceRoot, "symbolic link or reparse point")
}

func TestFactoryCleanSourceRejectsWindowsTrackedFileThroughJunctionParent(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	trackedRoot := filepath.Join(sourceRoot, "tracked-parent")
	if err := os.MkdirAll(trackedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	trackedPath := filepath.Join(trackedRoot, "tracked.go")
	if err := os.WriteFile(trackedPath, []byte("package tracked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"add", "tracked-parent/tracked.go"}})
	if err := os.Remove(trackedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(trackedRoot); err != nil {
		t.Fatal(err)
	}
	externalRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(externalRoot, "tracked.go"), []byte("package external\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	makeWindowsJunction(t, externalRoot, trackedRoot)
	assertFactoryCleanSourceCopyFails(t, sourceRoot, "symbolic link or reparse point")
}

func TestFactoryCleanSourceRejectsWindowsCaseCollidingGitPaths(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	candidatePath := filepath.Join(sourceRoot, "candidate.go")
	if err := os.WriteFile(candidatePath, []byte("package candidate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	objectID := strings.TrimSpace(string(runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: []string{"hash-object", "-w", "--", "candidate.go"},
	})))
	for _, relative := range []string{"candidate.go", "CANDIDATE.go"} {
		runFactoryCommand(t, sourceRoot, factoryCommandOptions{
			name: "git", args: []string{"-c", "core.ignorecase=false", "update-index", "--add", "--cacheinfo", "100644," + objectID + "," + relative},
		})
	}
	assertFactoryCleanSourceCopyFails(t, sourceRoot, "collapse to one native path")
}

func TestFactoryCleanSourceRejectsWindowsTrailingDotAndSpaceAliases(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	candidatePath := filepath.Join(sourceRoot, "candidate")
	if err := os.WriteFile(candidatePath, []byte("exact candidate bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	objectID := strings.TrimSpace(string(runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: []string{"hash-object", "-w", "--", "candidate"},
	})))
	for _, relative := range []string{"candidate", "candidate.", "candidate "} {
		runFactoryCommand(t, sourceRoot, factoryCommandOptions{
			name: "git", args: []string{"-c", "core.protectNTFS=false", "update-index", "--add", "--cacheinfo", "100644," + objectID + "," + relative},
		})
	}
	assertFactoryCleanSourceCopyFails(t, sourceRoot, "resolve to one physical file")
}

func TestFactoryCleanTargetWriterRejectsWindowsLeafAliases(t *testing.T) {
	targetRoot := filepath.Join(t.TempDir(), "clean-source")
	writer, err := newFactoryCleanTargetWriter(targetRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.release() }()
	if err := writer.writeFile("candidate", []byte("first bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"candidate.", "candidate "} {
		if err := writer.writeFile(alias, []byte("replacement bytes\n"), 0o600); err == nil || !strings.Contains(err.Error(), "create exclusive clean target file") {
			t.Fatalf("Windows target leaf alias %q error = %v, want exclusive-create refusal", alias, err)
		}
	}
}

func TestFactoryCleanTargetWriterRejectsWindowsDirectoryAliases(t *testing.T) {
	for _, alias := range []string{"candidate.", "candidate "} {
		t.Run(alias, func(t *testing.T) {
			targetRoot := filepath.Join(t.TempDir(), "clean-source")
			writer, err := newFactoryCleanTargetWriter(targetRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = writer.release() }()
			if err := writer.writeFile(filepath.Join("candidate", "first.go"), []byte("package first\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := writer.writeFile(filepath.Join(alias, "second.go"), []byte("package second\n"), 0o600); err == nil || !strings.Contains(err.Error(), "create exclusive clean target directory") {
				t.Fatalf("Windows target directory alias %q error = %v, want exclusive-create refusal", alias, err)
			}
		})
	}
}

func TestFactoryCleanTargetWriterRejectsWindowsDeviceNames(t *testing.T) {
	for _, deviceName := range []string{
		"CON", "con.txt", "PRN", "AUX.log", "NUL",
		"COM1", "com9.json", "LPT1", "lpt9.txt",
		"COM¹", "com².log", "COM³", "LPT¹", "lpt².log", "LPT³",
		"CONIN$", "conin$.txt", "CONOUT$", "conout$.json",
	} {
		for _, relative := range []string{deviceName, filepath.Join(deviceName, "candidate.go")} {
			t.Run(relative, func(t *testing.T) {
				targetRoot := filepath.Join(t.TempDir(), "clean-source")
				writer, err := newFactoryCleanTargetWriter(targetRoot)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = writer.release() }()
				if err := writer.writeFile(relative, []byte("must not be created\n"), 0o600); err == nil || !strings.Contains(err.Error(), "reserved Windows device name") {
					t.Fatalf("Windows device path %q error = %v, want reserved-device refusal", relative, err)
				}
			})
		}
	}
}

func TestFactoryCleanTargetWriterAcceptsNeighboringWindowsNondeviceNames(t *testing.T) {
	for _, name := range []string{"COM0", "COM10", "LPT0", "LPT10", "CONIN", "CONOUT"} {
		for _, relative := range []string{name, filepath.Join(name, "candidate.go")} {
			t.Run(relative, func(t *testing.T) {
				targetRoot := filepath.Join(t.TempDir(), "clean-source")
				writer, err := newFactoryCleanTargetWriter(targetRoot)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = writer.release() }()
				if err := writer.writeFile(relative, []byte("accepted neighboring name\n"), 0o600); err != nil {
					t.Fatalf("neighboring Windows nondevice path %q was rejected: %v", relative, err)
				}
			})
		}
	}
}
