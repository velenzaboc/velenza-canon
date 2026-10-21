package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

type repeatedFlag []string

func (values *repeatedFlag) String() string { return fmt.Sprint([]string(*values)) }
func (values *repeatedFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type factoryCommandOperations struct {
	runPrepared         func(providerplan.FactoryRunOptions) (providerplan.FactoryRunReceipt, error)
	runSource           func(providerplan.DocumentationFactorySourceCompileOptions) (providerplan.DocumentationFactorySourceCompileResult, error)
	runProductionSource func(context.Context, providerplan.DocumentationFactoryProductionSourceCompileOptions) (providerplan.DocumentationFactoryProductionSourceRunReceipt, error)
	write               func(string, []byte) error
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithOperations(args, stdout, stderr, factoryCommandOperations{
		runPrepared: providerplan.RunDocumentationFactory,
		runSource:   providerplan.CompileDocumentationFactorySourcePackage,
		runProductionSource: func(ctx context.Context, options providerplan.DocumentationFactoryProductionSourceCompileOptions) (providerplan.DocumentationFactoryProductionSourceRunReceipt, error) {
			result, err := providerplan.CompileDocumentationFactoryProductionSourcePackage(ctx, options, nil)
			if err != nil {
				return providerplan.DocumentationFactoryProductionSourceRunReceipt{}, err
			}
			return providerplan.SealDocumentationFactoryProductionSourceRunReceipt(result)
		},
		write: providerplan.WriteReceiptExclusive,
	})
}

func runWithOperations(args []string, stdout, stderr io.Writer, operations factoryCommandOperations) int {
	if operations.runPrepared == nil || operations.runSource == nil || operations.write == nil {
		fmt.Fprintln(stderr, "provider-documentation-factory-run: command dependency is unavailable")
		return 1
	}
	var evidence repeatedFlag
	var dependencies repeatedFlag
	flags := flag.NewFlagSet("provider-documentation-factory-run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	evidenceIntake := flags.String("evidence-intake-inputs", "", "strict evidence_intake stage input manifest")
	semanticExtraction := flags.String("semantic-extraction-inputs", "", "strict semantic_extraction stage input manifest")
	graphCompile := flags.String("graph-compile-inputs", "", "strict graph_compile stage input manifest")
	fullFactory := flags.String("full-factory-inputs", "", "strict full_factory stage input manifest")
	oodPath := flags.String("ood", "", "path to the exact OOD Graph authority bytes already declared as a stage material")
	oodSHA := flags.String("expected-ood-sha256", "", "independently selected OOD Graph SHA-256")
	grandVisionPath := flags.String("grand-vision", "", "path to the exact Grand Vision authority bytes already declared as a stage material")
	grandVisionSHA := flags.String("expected-grand-vision-sha256", "", "independently selected Grand Vision SHA-256")
	sourceRecordPath := flags.String("source-record", "", "path to the exact Source Record authority bytes already declared as a stage material")
	sourceRecordSHA := flags.String("expected-source-record-sha256", "", "independently selected Source Record SHA-256")
	sourcePackagePath := flags.String("source-package", "", "strict sealed source-package manifest for whole-run candidate materialization")
	sourceVerificationReceipt := flags.String("source-verification-receipt", "", "opaque body-free source-owner receipt for production-shaped provider evidence verification")
	expectedProvider := flags.String("expected-provider", "", "provider identity the source-owner receipt must authenticate")
	outputRoot := flags.String("output-root", "", "absent directory to atomically publish the complete source-compiler candidate tree")
	outPath := flags.String("out", "", "optional body-free factory receipt path; stdout when omitted")
	flags.Var(&evidence, "evidence-manifest", "exact evidence manifest already declared as an intake-stage material; repeat for the corpus")
	flags.Var(&dependencies, "dependency-artifact", "exact plan-bound or transitive dependency; repeat for the complete verifier closure")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(stderr, "provider-documentation-factory-run: invalid command-line arguments")
		return 2
	}

	fail := func(message string) int {
		fmt.Fprintln(stderr, "provider-documentation-factory-run: "+message)
		return 1
	}
	if flags.NArg() != 0 {
		return fail("positional arguments are not accepted")
	}
	productionSourceMode := strings.TrimSpace(*sourceVerificationReceipt) != "" || strings.TrimSpace(*expectedProvider) != ""
	sourceMode := strings.TrimSpace(*sourcePackagePath) != "" || strings.TrimSpace(*outputRoot) != "" || productionSourceMode
	preparedModeProvided := strings.TrimSpace(*evidenceIntake) != "" || strings.TrimSpace(*semanticExtraction) != "" || strings.TrimSpace(*graphCompile) != "" || strings.TrimSpace(*fullFactory) != "" || strings.TrimSpace(*oodPath) != "" || strings.TrimSpace(*oodSHA) != "" || strings.TrimSpace(*grandVisionPath) != "" || strings.TrimSpace(*grandVisionSHA) != "" || strings.TrimSpace(*sourceRecordPath) != "" || strings.TrimSpace(*sourceRecordSHA) != "" || len(evidence) != 0 || len(dependencies) != 0
	if sourceMode {
		if strings.TrimSpace(*sourcePackagePath) == "" {
			return fail("--source-package is required in source mode")
		}
		if strings.TrimSpace(*outputRoot) == "" {
			return fail("--output-root is required in source mode")
		}
		if preparedModeProvided {
			return fail("source mode cannot be combined with prepared-stage or preflight flags")
		}
		if productionSourceMode {
			if strings.TrimSpace(*sourceVerificationReceipt) == "" {
				return fail("--source-verification-receipt is required in production source mode")
			}
			if strings.TrimSpace(*expectedProvider) == "" {
				return fail("--expected-provider is required in production source mode")
			}
			if operations.runProductionSource == nil {
				return fail("production source verification is unavailable")
			}
			result, err := operations.runProductionSource(context.Background(), providerplan.DocumentationFactoryProductionSourceCompileOptions{
				SourcePackagePath: *sourcePackagePath, VerificationReceiptPath: *sourceVerificationReceipt,
				ExpectedProvider: *expectedProvider, OutputRoot: *outputRoot,
			})
			if err != nil {
				return fail("production source verification failed")
			}
			return publishFactoryCommandValue(result, *outPath, stdout, fail, operations.write)
		}
		result, err := operations.runSource(providerplan.DocumentationFactorySourceCompileOptions{SourcePackagePath: *sourcePackagePath, OutputRoot: *outputRoot})
		if err != nil {
			return fail("source compilation failed")
		}
		return publishFactoryCommandReceipt(result.FactoryReceipt, *outPath, stdout, fail, operations.write)
	}
	required := []struct {
		name  string
		value string
	}{
		{name: "--evidence-intake-inputs", value: *evidenceIntake},
		{name: "--semantic-extraction-inputs", value: *semanticExtraction},
		{name: "--graph-compile-inputs", value: *graphCompile},
		{name: "--full-factory-inputs", value: *fullFactory},
		{name: "--ood", value: *oodPath},
		{name: "--expected-ood-sha256", value: *oodSHA},
		{name: "--grand-vision", value: *grandVisionPath},
		{name: "--expected-grand-vision-sha256", value: *grandVisionSHA},
		{name: "--source-record", value: *sourceRecordPath},
		{name: "--expected-source-record-sha256", value: *sourceRecordSHA},
	}
	for _, requirement := range required {
		if strings.TrimSpace(requirement.value) == "" {
			return fail(requirement.name + " is required")
		}
	}
	if len(evidence) == 0 {
		return fail("at least one --evidence-manifest is required")
	}

	receipt, err := operations.runPrepared(providerplan.FactoryRunOptions{
		EvidenceIntakeInputManifestPath:     *evidenceIntake,
		SemanticExtractionInputManifestPath: *semanticExtraction,
		GraphCompileInputManifestPath:       *graphCompile,
		FullFactoryInputManifestPath:        *fullFactory,
		Preflight: providerplan.Options{
			OODSpecPath: *oodPath, ExpectedOODSpecSHA256: strings.ToLower(*oodSHA),
			GrandVisionPath: *grandVisionPath, ExpectedGrandVisionSHA256: strings.ToLower(*grandVisionSHA),
			SourceRecordSpecPath: *sourceRecordPath, ExpectedSourceRecordSHA256: strings.ToLower(*sourceRecordSHA),
			EvidenceManifestPath: evidence, DependencyArtifactPath: dependencies,
		},
	})
	if err != nil {
		return fail("factory validation failed")
	}
	return publishFactoryCommandReceipt(receipt, *outPath, stdout, fail, operations.write)
}

func publishFactoryCommandReceipt(receipt providerplan.FactoryRunReceipt, outPath string, stdout io.Writer, fail func(string) int, write func(string, []byte) error) int {
	return publishFactoryCommandValue(receipt, outPath, stdout, fail, write)
}

func publishFactoryCommandValue(receipt any, outPath string, stdout io.Writer, fail func(string) int, write func(string, []byte) error) int {
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fail("receipt serialization failed")
	}
	raw = append(raw, '\n')
	if outPath == "" {
		if _, err := stdout.Write(raw); err != nil {
			return fail("receipt publication failed")
		}
		return 0
	}
	if err := write(outPath, raw); err != nil {
		return fail("receipt publication failed")
	}
	return 0
}
