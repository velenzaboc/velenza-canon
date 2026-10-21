package main

import (
	"bytes"
	"errors"
	"io"
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

func completeArguments() []string {
	return []string{
		"--ood", "ood.json", "--expected-ood-sha256", strings.Repeat("1", 64),
		"--grand-vision", "vision.md", "--expected-grand-vision-sha256", strings.Repeat("2", 64),
		"--source-record", "source.json", "--expected-source-record-sha256", strings.Repeat("3", 64),
		"--graph-compile-inputs", "graph.json",
		"--evidence-manifest", "one.jsonl", "--evidence-manifest", "two.jsonl",
		"--dependency-artifact", "dependency.json",
	}
}

func successfulVerifyOperations(t *testing.T) verifyOperations {
	t.Helper()
	return verifyOperations{
		verify: func(options providerplan.Options) (providerplan.Receipt, error) {
			if options.OODSpecPath != "ood.json" || options.GrandVisionPath != "vision.md" || options.SourceRecordSpecPath != "source.json" || options.GraphCompileInputManifestPath != "graph.json" {
				t.Fatalf("unexpected verify paths: %#v", options)
			}
			if len(options.EvidenceManifestPath) != 2 || len(options.DependencyArtifactPath) != 1 {
				t.Fatalf("repeated flags not preserved: %#v", options)
			}
			return providerplan.Receipt{}, nil
		},
		marshal: func(any) ([]byte, error) { return []byte("receipt"), nil },
		write:   func(string, []byte) error { return nil },
	}
}

func TestRepeatedFlagStringAndSet(t *testing.T) {
	var values repeatedFlag
	if got := values.String(); got != "[]" {
		t.Fatalf("empty string = %q", got)
	}
	if err := values.Set("one"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := values.String(); got != "[one]" {
		t.Fatalf("string = %q", got)
	}
}

func TestRunWithOperationsRequiresEveryAuthorityInput(t *testing.T) {
	requirements := []string{
		"--ood", "--expected-ood-sha256", "--grand-vision", "--expected-grand-vision-sha256",
		"--source-record", "--expected-source-record-sha256", "--graph-compile-inputs",
	}
	full := completeArguments()
	for _, missing := range requirements {
		t.Run(missing, func(t *testing.T) {
			args := append([]string(nil), full...)
			for index := 0; index < len(args)-1; index++ {
				if args[index] == missing {
					args[index+1] = "   "
					break
				}
			}
			var stderr bytes.Buffer
			if code := runWithOperations(args, &bytes.Buffer{}, &stderr, successfulVerifyOperations(t)); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), missing+" is required") {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestRunWithOperationsHandlesPrivateFailures(t *testing.T) {
	privateError := errors.New("private opaque failure")
	tests := []struct {
		name string
		edit func(*verifyOperations)
		args func() []string
	}{
		{name: "verify", edit: func(operations *verifyOperations) {
			operations.verify = func(providerplan.Options) (providerplan.Receipt, error) { return providerplan.Receipt{}, privateError }
		}, args: completeArguments},
		{name: "marshal", edit: func(operations *verifyOperations) {
			operations.marshal = func(any) ([]byte, error) { return nil, privateError }
		}, args: completeArguments},
		{name: "stdout", edit: func(*verifyOperations) {}, args: completeArguments},
		{name: "file", edit: func(operations *verifyOperations) {
			operations.write = func(string, []byte) error { return privateError }
		}, args: func() []string { return append(completeArguments(), "--out", "receipt.json") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := successfulVerifyOperations(t)
			test.edit(&operations)
			var stdout io.Writer = &bytes.Buffer{}
			if test.name == "stdout" {
				stdout = failingWriter{err: privateError}
			}
			var stderr bytes.Buffer
			if code := runWithOperations(test.args(), stdout, &stderr, operations); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if strings.Contains(stderr.String(), privateError.Error()) {
				t.Fatalf("private failure crossed boundary: %q", stderr.String())
			}
		})
	}
}

func TestRunWithOperationsPublishesReceipt(t *testing.T) {
	operations := successfulVerifyOperations(t)
	var stdout, stderr bytes.Buffer
	if code := runWithOperations(completeArguments(), &stdout, &stderr, operations); code != 0 {
		t.Fatalf("stdout exit = %d stderr=%q", code, stderr.String())
	}
	if got := stdout.String(); got != "receipt\n" {
		t.Fatalf("stdout = %q", got)
	}

	operations = successfulVerifyOperations(t)
	operations.write = func(path string, raw []byte) error {
		if path != "receipt.json" || string(raw) != "receipt\n" {
			t.Fatalf("write path/raw = %q/%q", path, raw)
		}
		return nil
	}
	stdout.Reset()
	stderr.Reset()
	if code := runWithOperations(append(completeArguments(), "--out", "receipt.json"), &stdout, &stderr, operations); code != 0 {
		t.Fatalf("file exit = %d stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("file publication also wrote stdout: %q", stdout.String())
	}
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

	malformedPath := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(malformedPath, []byte(`{"kind":"`+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"--ood", malformedPath, "--expected-ood-sha256", strings.Repeat("0", 64),
		"--grand-vision", malformedPath, "--expected-grand-vision-sha256", strings.Repeat("0", 64),
		"--source-record", malformedPath, "--expected-source-record-sha256", strings.Repeat("0", 64),
		"--graph-compile-inputs", malformedPath,
	}
	malformed := runCommandFailure(t, first, args...)
	if bytes.Contains(malformed, []byte(secret)) || bytes.Contains(malformed, []byte(malformedPath)) {
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
	first := filepath.Join(directory, "first", "provider-plan-verify"+suffix)
	second := filepath.Join(directory, "second", "renamed-provider-verifier"+suffix)
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
