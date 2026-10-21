package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func successfulStageOperations(t *testing.T) stageCompileOperations {
	t.Helper()
	return stageCompileOperations{
		load: func(path string) ([]byte, providerplan.StageCompileInputs, error) {
			if path != "inputs.json" {
				t.Fatalf("load path = %q, want inputs.json", path)
			}
			return []byte("request"), providerplan.StageCompileInputs{}, nil
		},
		compile: func(raw []byte, _ providerplan.StageCompileInputs) ([]byte, error) {
			if string(raw) != "request" {
				t.Fatalf("compile request = %q, want request", raw)
			}
			return []byte("receipt\n"), nil
		},
		write: func(string, []byte) error { return nil },
	}
}

func TestRunWithOperationsRequiresInputs(t *testing.T) {
	var stderr bytes.Buffer
	if code := runWithOperations(nil, &bytes.Buffer{}, &stderr, successfulStageOperations(t)); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if got := stderr.String(); got != "provider-documentation-stage-compile: --inputs is required\n" {
		t.Fatalf("stderr = %q", got)
	}
}

func TestRunWithOperationsHandlesLoadAndCompileFailures(t *testing.T) {
	tests := []struct {
		name string
		edit func(*stageCompileOperations)
	}{
		{name: "load", edit: func(operations *stageCompileOperations) {
			operations.load = func(string) ([]byte, providerplan.StageCompileInputs, error) {
				return nil, providerplan.StageCompileInputs{}, errors.New("private load failure")
			}
		}},
		{name: "compile", edit: func(operations *stageCompileOperations) {
			operations.compile = func([]byte, providerplan.StageCompileInputs) ([]byte, error) {
				return nil, errors.New("private compile failure")
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := successfulStageOperations(t)
			test.edit(&operations)
			var stdout, stderr bytes.Buffer
			if code := runWithOperations([]string{"--inputs", "inputs.json"}, &stdout, &stderr, operations); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if stdout.Len() != 0 || strings.Contains(stderr.String(), "private") {
				t.Fatalf("private failure crossed boundary: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunWithOperationsPublishesReceipt(t *testing.T) {
	operations := successfulStageOperations(t)
	var stdout, stderr bytes.Buffer
	if code := runWithOperations([]string{"--inputs", "inputs.json"}, &stdout, &stderr, operations); code != 0 {
		t.Fatalf("exit = %d stderr=%q", code, stderr.String())
	}
	if got := stdout.String(); got != "receipt\n" {
		t.Fatalf("stdout = %q", got)
	}

	operations = successfulStageOperations(t)
	operations.write = func(path string, raw []byte) error {
		if path != "receipt.json" || string(raw) != "receipt\n" {
			t.Fatalf("write path/raw = %q/%q", path, raw)
		}
		return nil
	}
	stdout.Reset()
	stderr.Reset()
	if code := runWithOperations([]string{"--inputs", "inputs.json", "--out", "receipt.json"}, &stdout, &stderr, operations); code != 0 {
		t.Fatalf("file exit = %d stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("file publication also wrote stdout: %q", stdout.String())
	}
}

func TestRunWithOperationsRefusesPublicationFailures(t *testing.T) {
	publicationError := errors.New("private publication failure")
	t.Run("stdout", func(t *testing.T) {
		var stderr bytes.Buffer
		if code := runWithOperations([]string{"--inputs", "inputs.json"}, failingWriter{err: publicationError}, &stderr, successfulStageOperations(t)); code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if strings.Contains(stderr.String(), publicationError.Error()) {
			t.Fatalf("private error crossed boundary: %q", stderr.String())
		}
	})
	t.Run("file", func(t *testing.T) {
		operations := successfulStageOperations(t)
		operations.write = func(string, []byte) error { return publicationError }
		var stderr bytes.Buffer
		if code := runWithOperations([]string{"--inputs", "inputs.json", "--out", "receipt.json"}, &bytes.Buffer{}, &stderr, operations); code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if strings.Contains(stderr.String(), publicationError.Error()) {
			t.Fatalf("private error crossed boundary: %q", stderr.String())
		}
	})
}

func TestUnknownFlagDiagnosticIsStableAndPathFree(t *testing.T) {
	var first, second bytes.Buffer
	if code := run([]string{"--not-a-real-flag"}, &bytes.Buffer{}, &first); code != 2 {
		t.Fatalf("first exit = %d, want 2", code)
	}
	if code := run([]string{"--not-a-real-flag"}, &bytes.Buffer{}, &second); code != 2 {
		t.Fatalf("second exit = %d, want 2", code)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatalf("unknown-flag diagnostics differ:\nfirst=%s\nsecond=%s", first.Bytes(), second.Bytes())
	}
	if strings.Contains(strings.ToLower(first.String()), "go-build") || strings.Contains(first.String(), `:\`) {
		t.Fatalf("unknown-flag diagnostic exposes a local launch path: %s", first.Bytes())
	}
}

func TestCommandRejectsPositionalArgumentsWithoutEcho(t *testing.T) {
	secret := "ActualOpaqueCredentialValue123456"
	var stdout, stderr bytes.Buffer
	if code := run([]string{secret}, &stdout, &stderr); code == 0 {
		t.Fatal("positional argument was accepted")
	}
	if strings.Contains(stdout.String()+stderr.String(), secret) {
		t.Fatal("positional argument was reflected across the public diagnostic boundary")
	}
}

func TestPublicCLIHasContentNeutralDiagnosticsAcrossExecutablePaths(t *testing.T) {
	secret := "ActualOpaqueCredentialValue123456"
	first, second := buildCommandAtTwoPaths(t)
	firstUnknown := runCommandFailure(t, first, "--"+secret)
	secondUnknown := runCommandFailure(t, second, "--"+secret)
	if !bytes.Equal(firstUnknown, secondUnknown) {
		t.Fatalf("unknown-flag diagnostics differ by executable path:\nfirst=%s\nsecond=%s", firstUnknown, secondUnknown)
	}
	if bytes.Contains(firstUnknown, []byte(secret)) {
		t.Fatal("invalid flag secret crossed the public diagnostic boundary")
	}

	manifest := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(manifest, []byte(`{"kind":"`+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	malformed := runCommandFailure(t, first, "--inputs", manifest)
	if bytes.Contains(malformed, []byte(secret)) || bytes.Contains(malformed, []byte(manifest)) {
		t.Fatalf("malformed-content diagnostic exposed caller bytes or path: %s", malformed)
	}
}

func buildCommandAtTwoPaths(t *testing.T) (string, string) {
	t.Helper()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	directory := t.TempDir()
	first := filepath.Join(directory, "first", "provider-documentation-stage-compile"+suffix)
	second := filepath.Join(directory, "second", "renamed-stage-command"+suffix)
	if err := os.MkdirAll(filepath.Dir(first), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-trimpath", "-tags=factory_release", "-o", first, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build public command: %v\n%s", err, output)
	}
	if err := os.MkdirAll(filepath.Dir(second), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	return first, second
}

func runCommandFailure(t *testing.T, path string, args ...string) []byte {
	t.Helper()
	command := exec.Command(path, args...)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("command unexpectedly succeeded: %s", output)
	}
	return output
}
