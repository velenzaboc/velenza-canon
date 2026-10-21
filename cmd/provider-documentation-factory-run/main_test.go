package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

type factoryFailWriter struct{ err error }

func (w factoryFailWriter) Write([]byte) (int, error) { return 0, w.err }

func completePreparedArguments() []string {
	return []string{
		"--evidence-intake-inputs", "intake.json",
		"--semantic-extraction-inputs", "semantic.json",
		"--graph-compile-inputs", "graph.json",
		"--full-factory-inputs", "factory.json",
		"--ood", "ood.json", "--expected-ood-sha256", strings.Repeat("A", 64),
		"--grand-vision", "vision.md", "--expected-grand-vision-sha256", strings.Repeat("B", 64),
		"--source-record", "source.json", "--expected-source-record-sha256", strings.Repeat("C", 64),
		"--evidence-manifest", "evidence-one.jsonl", "--evidence-manifest", "evidence-two.jsonl",
		"--dependency-artifact", "dependency.json",
	}
}

func successfulFactoryOperations(t *testing.T) factoryCommandOperations {
	t.Helper()
	return factoryCommandOperations{
		runPrepared: func(options providerplan.FactoryRunOptions) (providerplan.FactoryRunReceipt, error) {
			if options.EvidenceIntakeInputManifestPath != "intake.json" || options.SemanticExtractionInputManifestPath != "semantic.json" || options.GraphCompileInputManifestPath != "graph.json" || options.FullFactoryInputManifestPath != "factory.json" {
				t.Fatalf("unexpected stage inputs: %#v", options)
			}
			if options.Preflight.ExpectedOODSpecSHA256 != strings.Repeat("a", 64) || options.Preflight.ExpectedGrandVisionSHA256 != strings.Repeat("b", 64) || options.Preflight.ExpectedSourceRecordSHA256 != strings.Repeat("c", 64) {
				t.Fatalf("authority digests were not normalized: %#v", options.Preflight)
			}
			if len(options.Preflight.EvidenceManifestPath) != 2 || len(options.Preflight.DependencyArtifactPath) != 1 {
				t.Fatalf("repeated inputs were not preserved: %#v", options.Preflight)
			}
			return providerplan.FactoryRunReceipt{ReceiptKind: "fixture"}, nil
		},
		runSource: func(providerplan.DocumentationFactorySourceCompileOptions) (providerplan.DocumentationFactorySourceCompileResult, error) {
			return providerplan.DocumentationFactorySourceCompileResult{FactoryReceipt: providerplan.FactoryRunReceipt{ReceiptKind: "source"}}, nil
		},
		runProductionSource: func(context.Context, providerplan.DocumentationFactoryProductionSourceCompileOptions) (providerplan.DocumentationFactoryProductionSourceRunReceipt, error) {
			return providerplan.DocumentationFactoryProductionSourceRunReceipt{ReceiptKind: "production"}, nil
		},
		write: func(string, []byte) error { return nil },
	}
}

func TestRepeatedFlagRoundTrip(t *testing.T) {
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

func TestCommandDependenciesAreRequired(t *testing.T) {
	operations := successfulFactoryOperations(t)
	tests := []struct {
		name string
		edit func(*factoryCommandOperations)
	}{
		{name: "prepared", edit: func(value *factoryCommandOperations) { value.runPrepared = nil }},
		{name: "source", edit: func(value *factoryCommandOperations) { value.runSource = nil }},
		{name: "writer", edit: func(value *factoryCommandOperations) { value.write = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := operations
			test.edit(&candidate)
			var stderr bytes.Buffer
			if code := runWithOperations(nil, &bytes.Buffer{}, &stderr, candidate); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), "command dependency is unavailable") {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestPreparedModeRequiresAllInputsAndEvidence(t *testing.T) {
	full := completePreparedArguments()
	requirements := []string{
		"--evidence-intake-inputs", "--semantic-extraction-inputs", "--graph-compile-inputs", "--full-factory-inputs",
		"--ood", "--expected-ood-sha256", "--grand-vision", "--expected-grand-vision-sha256",
		"--source-record", "--expected-source-record-sha256",
	}
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
			if code := runWithOperations(args, &bytes.Buffer{}, &stderr, successfulFactoryOperations(t)); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), missing+" is required") {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}

	withoutEvidence := completePreparedArguments()
	filtered := make([]string, 0, len(withoutEvidence))
	for index := 0; index < len(withoutEvidence); index++ {
		if withoutEvidence[index] == "--evidence-manifest" {
			index++
			continue
		}
		filtered = append(filtered, withoutEvidence[index])
	}
	var stderr bytes.Buffer
	if code := runWithOperations(filtered, &bytes.Buffer{}, &stderr, successfulFactoryOperations(t)); code != 1 || !strings.Contains(stderr.String(), "at least one --evidence-manifest") {
		t.Fatalf("missing evidence exit/stderr = %d/%q", code, stderr.String())
	}
}

func TestOperationFailuresStayPrivate(t *testing.T) {
	privateError := errors.New("opaque private failure")
	tests := []struct {
		name string
		args []string
		edit func(*factoryCommandOperations)
	}{
		{name: "prepared", args: completePreparedArguments(), edit: func(value *factoryCommandOperations) {
			value.runPrepared = func(providerplan.FactoryRunOptions) (providerplan.FactoryRunReceipt, error) {
				return providerplan.FactoryRunReceipt{}, privateError
			}
		}},
		{name: "source", args: []string{"--source-package", "source.json", "--output-root", "output"}, edit: func(value *factoryCommandOperations) {
			value.runSource = func(providerplan.DocumentationFactorySourceCompileOptions) (providerplan.DocumentationFactorySourceCompileResult, error) {
				return providerplan.DocumentationFactorySourceCompileResult{}, privateError
			}
		}},
		{name: "production unavailable", args: []string{"--source-package", "source.json", "--output-root", "output", "--source-verification-receipt", "verify.json", "--expected-provider", "provider"}, edit: func(value *factoryCommandOperations) {
			value.runProductionSource = nil
		}},
		{name: "production", args: []string{"--source-package", "source.json", "--output-root", "output", "--source-verification-receipt", "verify.json", "--expected-provider", "provider"}, edit: func(value *factoryCommandOperations) {
			value.runProductionSource = func(context.Context, providerplan.DocumentationFactoryProductionSourceCompileOptions) (providerplan.DocumentationFactoryProductionSourceRunReceipt, error) {
				return providerplan.DocumentationFactoryProductionSourceRunReceipt{}, privateError
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := successfulFactoryOperations(t)
			test.edit(&operations)
			var stdout, stderr bytes.Buffer
			if code := runWithOperations(test.args, &stdout, &stderr, operations); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if stdout.Len() != 0 || strings.Contains(stderr.String(), privateError.Error()) {
				t.Fatalf("private failure crossed boundary: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestPreparedReceiptPublicationPaths(t *testing.T) {
	operations := successfulFactoryOperations(t)
	var stdout, stderr bytes.Buffer
	if code := runWithOperations(completePreparedArguments(), &stdout, &stderr, operations); code != 0 {
		t.Fatalf("stdout exit = %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"receipt_kind": "fixture"`) {
		t.Fatalf("stdout receipt = %q", stdout.String())
	}

	operations = successfulFactoryOperations(t)
	operations.write = func(path string, raw []byte) error {
		if path != "receipt.json" || !bytes.Contains(raw, []byte(`"receipt_kind": "fixture"`)) {
			t.Fatalf("write path/raw = %q/%q", path, raw)
		}
		return nil
	}
	if code := runWithOperations(append(completePreparedArguments(), "--out", "receipt.json"), &bytes.Buffer{}, &stderr, operations); code != 0 {
		t.Fatalf("file exit = %d stderr=%q", code, stderr.String())
	}
}

func TestReceiptPublicationFailures(t *testing.T) {
	privateError := errors.New("private publication failure")
	fail := func(message string) int {
		if message == "" {
			t.Fatal("empty public failure")
		}
		return 7
	}
	if code := publishFactoryCommandValue(make(chan int), "", &bytes.Buffer{}, fail, func(string, []byte) error { return nil }); code != 7 {
		t.Fatalf("marshal exit = %d, want 7", code)
	}
	if code := publishFactoryCommandValue(providerplan.FactoryRunReceipt{}, "", factoryFailWriter{err: privateError}, fail, func(string, []byte) error { return nil }); code != 7 {
		t.Fatalf("stdout exit = %d, want 7", code)
	}
	if code := publishFactoryCommandReceipt(providerplan.FactoryRunReceipt{}, "receipt.json", &bytes.Buffer{}, fail, func(string, []byte) error { return privateError }); code != 7 {
		t.Fatalf("file exit = %d, want 7", code)
	}
}

func TestSourceModeInvokesWholeRunCompilerWithoutPreparedInputs(t *testing.T) {
	var captured providerplan.DocumentationFactorySourceCompileOptions
	preparedRuns := 0
	operations := factoryCommandOperations{
		runPrepared: func(providerplan.FactoryRunOptions) (providerplan.FactoryRunReceipt, error) {
			preparedRuns++
			return providerplan.FactoryRunReceipt{}, fmt.Errorf("prepared mode must not run")
		},
		runSource: func(options providerplan.DocumentationFactorySourceCompileOptions) (providerplan.DocumentationFactorySourceCompileResult, error) {
			captured = options
			return providerplan.DocumentationFactorySourceCompileResult{FactoryReceipt: providerplan.FactoryRunReceipt{ReceiptKind: "fixture_factory_receipt"}}, nil
		},
		write: func(string, []byte) error { return fmt.Errorf("unexpected file receipt publication") },
	}
	var stdout, stderr bytes.Buffer
	code := runWithOperations([]string{"--source-package", "sealed-source.json", "--output-root", "candidate-output"}, &stdout, &stderr, operations)
	if code != 0 {
		t.Fatalf("source mode exit = %d stderr=%s", code, stderr.String())
	}
	if preparedRuns != 0 || captured.SourcePackagePath != "sealed-source.json" || captured.OutputRoot != "candidate-output" {
		t.Fatalf("source invocation = %+v prepared_runs=%d", captured, preparedRuns)
	}
	if !strings.Contains(stdout.String(), `"receipt_kind": "fixture_factory_receipt"`) {
		t.Fatalf("source mode did not publish the nested factory receipt: %s", stdout.String())
	}
}

func TestProductionSourceModeInvokesOnlyVerifiedWholeRunCompiler(t *testing.T) {
	var captured providerplan.DocumentationFactoryProductionSourceCompileOptions
	preparedRuns := 0
	candidateRuns := 0
	operations := factoryCommandOperations{
		runPrepared: func(providerplan.FactoryRunOptions) (providerplan.FactoryRunReceipt, error) {
			preparedRuns++
			return providerplan.FactoryRunReceipt{}, fmt.Errorf("prepared mode must not run")
		},
		runSource: func(providerplan.DocumentationFactorySourceCompileOptions) (providerplan.DocumentationFactorySourceCompileResult, error) {
			candidateRuns++
			return providerplan.DocumentationFactorySourceCompileResult{}, fmt.Errorf("candidate source mode must not run")
		},
		runProductionSource: func(_ context.Context, options providerplan.DocumentationFactoryProductionSourceCompileOptions) (providerplan.DocumentationFactoryProductionSourceRunReceipt, error) {
			captured = options
			return providerplan.DocumentationFactoryProductionSourceRunReceipt{
				ReceiptKind:    "fixture_production_source_run_receipt",
				FactoryReceipt: providerplan.FactoryRunReceipt{ReceiptKind: "fixture_production_factory_receipt"},
			}, nil
		},
		write: func(string, []byte) error { return fmt.Errorf("unexpected file receipt publication") },
	}
	var stdout, stderr bytes.Buffer
	code := runWithOperations([]string{
		"--source-package", "sealed-source.json",
		"--source-verification-receipt", "source-owner.receipt.json",
		"--expected-provider", "quickbooks_online",
		"--output-root", "candidate-output",
	}, &stdout, &stderr, operations)
	if code != 0 {
		t.Fatalf("production source mode exit = %d stderr=%s", code, stderr.String())
	}
	if preparedRuns != 0 || candidateRuns != 0 || captured.SourcePackagePath != "sealed-source.json" || captured.VerificationReceiptPath != "source-owner.receipt.json" || captured.ExpectedProvider != "quickbooks_online" || captured.OutputRoot != "candidate-output" {
		t.Fatalf("production source invocation = %+v prepared_runs=%d candidate_runs=%d", captured, preparedRuns, candidateRuns)
	}
	if !strings.Contains(stdout.String(), `"receipt_kind": "fixture_production_source_run_receipt"`) || !strings.Contains(stdout.String(), `"factory_receipt"`) {
		t.Fatalf("production source mode did not publish the production source receipt relay: %s", stdout.String())
	}
}

func TestSourceModeIsCompleteAndMutuallyExclusive(t *testing.T) {
	runs := 0
	operations := factoryCommandOperations{
		runPrepared: func(providerplan.FactoryRunOptions) (providerplan.FactoryRunReceipt, error) {
			runs++
			return providerplan.FactoryRunReceipt{}, nil
		},
		runSource: func(providerplan.DocumentationFactorySourceCompileOptions) (providerplan.DocumentationFactorySourceCompileResult, error) {
			runs++
			return providerplan.DocumentationFactorySourceCompileResult{}, nil
		},
		write: func(string, []byte) error { return nil },
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing output", args: []string{"--source-package", "sealed-source.json"}, want: "--output-root is required"},
		{name: "missing package", args: []string{"--output-root", "candidate-output"}, want: "--source-package is required"},
		{name: "mixed prepared stage", args: []string{"--source-package", "sealed-source.json", "--output-root", "candidate-output", "--graph-compile-inputs", "prepared.json"}, want: "cannot be combined"},
		{name: "mixed evidence", args: []string{"--source-package", "sealed-source.json", "--output-root", "candidate-output", "--evidence-manifest", "evidence.jsonl"}, want: "cannot be combined"},
		{name: "production missing receipt", args: []string{"--source-package", "sealed-source.json", "--output-root", "candidate-output", "--expected-provider", "quickbooks_online"}, want: "--source-verification-receipt is required"},
		{name: "production missing provider", args: []string{"--source-package", "sealed-source.json", "--output-root", "candidate-output", "--source-verification-receipt", "source-owner.receipt.json"}, want: "--expected-provider is required"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runWithOperations(testCase.args, &stdout, &stderr, operations); code == 0 || !strings.Contains(stderr.String(), testCase.want) {
				t.Fatalf("exit/diagnostic = %d/%q, want failure containing %q", code, stderr.String(), testCase.want)
			}
		})
	}
	if runs != 0 {
		t.Fatalf("invalid source-mode commands executed %d operations", runs)
	}
}

func TestProductionSourceModeFailsClosedWithoutSelectedOwnerVerifier(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--source-package", "sealed-source.json",
		"--source-verification-receipt", "source-owner.receipt.json",
		"--expected-provider", "quickbooks_online",
		"--output-root", "candidate-output",
	}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "production source verification failed") {
		t.Fatalf("unwired production verifier exit/diagnostic = %d/%q", code, stderr.String())
	}
	if stdout.Len() != 0 || strings.Contains(stderr.String(), "sealed-source.json") || strings.Contains(stderr.String(), "source-owner.receipt.json") {
		t.Fatalf("unwired production verifier exposed caller paths: stdout=%q stderr=%q", stdout.String(), stderr.String())
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
		"--evidence-intake-inputs", malformedPath,
		"--semantic-extraction-inputs", malformedPath,
		"--graph-compile-inputs", malformedPath,
		"--full-factory-inputs", malformedPath,
		"--ood", malformedPath, "--expected-ood-sha256", strings.Repeat("0", 64),
		"--grand-vision", malformedPath, "--expected-grand-vision-sha256", strings.Repeat("0", 64),
		"--source-record", malformedPath, "--expected-source-record-sha256", strings.Repeat("0", 64),
		"--evidence-manifest", malformedPath,
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
	first := filepath.Join(directory, "first", "provider-documentation-factory-run"+suffix)
	second := filepath.Join(directory, "second", "renamed-factory-command"+suffix)
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
