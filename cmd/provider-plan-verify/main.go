package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

type repeatedFlag []string

func (v *repeatedFlag) String() string         { return fmt.Sprint([]string(*v)) }
func (v *repeatedFlag) Set(value string) error { *v = append(*v, value); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithOperations(args, stdout, stderr, verifyOperations{
		verify: providerplan.Verify,
		marshal: func(value any) ([]byte, error) {
			return json.MarshalIndent(value, "", "  ")
		},
		write: providerplan.WriteReceiptExclusive,
	})
}

type verifyOperations struct {
	verify  func(providerplan.Options) (providerplan.Receipt, error)
	marshal func(any) ([]byte, error)
	write   func(string, []byte) error
}

func runWithOperations(args []string, stdout, stderr io.Writer, operations verifyOperations) int {
	var evidence repeatedFlag
	var dependencies repeatedFlag
	flags := flag.NewFlagSet("provider-plan-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	oodPath := flags.String("ood", "", "path to the authoritative OOD_GRAPH_PROTOCOL_v1.ood.json bytes")
	oodSHA := flags.String("expected-ood-sha256", "", "independently selected current-origin SHA-256 for the OOD authority bytes")
	grandVisionPath := flags.String("grand-vision", "", "path to the authoritative VELENZA_GRAND_VISION_v1.md bytes")
	grandVisionSHA := flags.String("expected-grand-vision-sha256", "", "independently selected current-origin SHA-256 for the Grand Vision authority bytes")
	sourceRecordPath := flags.String("source-record", "", "path to the authoritative SOURCE_RECORD_AND_SEMANTIC_PROJECTION_v1.ood.json bytes")
	sourceRecordSHA := flags.String("expected-source-record-sha256", "", "independently selected current-origin SHA-256 for the Source Record authority bytes")
	graphCompileInputsPath := flags.String("graph-compile-inputs", "", "path to the strict graph-compile stage input manifest")
	outPath := flags.String("out", "", "optional body-free receipt path; stdout when omitted")
	flags.Var(&evidence, "evidence-manifest", "exact evidence-body manifest JSONL; repeat for each corpus")
	flags.Var(&dependencies, "dependency-artifact", "exact structured candidate artifact declared by the plan; repeat for the complete dependency closure")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(stderr, "provider-plan-verify: invalid command-line arguments")
		return 2
	}
	fail := func(message string) int {
		fmt.Fprintln(stderr, "provider-plan-verify: "+message)
		return 1
	}

	if flags.NArg() != 0 {
		return fail("positional arguments are not accepted")
	}
	for _, requirement := range []struct {
		name  string
		value string
	}{
		{name: "--ood", value: *oodPath},
		{name: "--expected-ood-sha256", value: *oodSHA},
		{name: "--grand-vision", value: *grandVisionPath},
		{name: "--expected-grand-vision-sha256", value: *grandVisionSHA},
		{name: "--source-record", value: *sourceRecordPath},
		{name: "--expected-source-record-sha256", value: *sourceRecordSHA},
		{name: "--graph-compile-inputs", value: *graphCompileInputsPath},
	} {
		if strings.TrimSpace(requirement.value) == "" {
			return fail(requirement.name + " is required")
		}
	}
	receipt, err := operations.verify(providerplan.Options{OODSpecPath: *oodPath, ExpectedOODSpecSHA256: *oodSHA, GrandVisionPath: *grandVisionPath, ExpectedGrandVisionSHA256: *grandVisionSHA, SourceRecordSpecPath: *sourceRecordPath, ExpectedSourceRecordSHA256: *sourceRecordSHA, GraphCompileInputManifestPath: *graphCompileInputsPath, EvidenceManifestPath: evidence, DependencyArtifactPath: dependencies})
	if err != nil {
		return fail("provider validation failed")
	}
	raw, err := operations.marshal(receipt)
	if err != nil {
		return fail("receipt serialization failed")
	}
	raw = append(raw, '\n')
	if *outPath == "" {
		if _, err := stdout.Write(raw); err != nil {
			return fail("receipt publication failed")
		}
		return 0
	}
	if err := operations.write(*outPath, raw); err != nil {
		return fail("receipt publication failed")
	}
	return 0
}
