package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithOperations(args, stdout, stderr, stageCompileOperations{
		load:    providerplan.LoadStageCompileFileManifest,
		compile: providerplan.CompileStageReceipt,
		write:   providerplan.WriteReceiptExclusive,
	})
}

type stageCompileOperations struct {
	load    func(string) ([]byte, providerplan.StageCompileInputs, error)
	compile func([]byte, providerplan.StageCompileInputs) ([]byte, error)
	write   func(string, []byte) error
}

func runWithOperations(args []string, stdout, stderr io.Writer, operations stageCompileOperations) int {
	flags := flag.NewFlagSet("provider-documentation-stage-compile", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("inputs", "", "path to the strict body-free stage input manifest")
	outPath := flags.String("out", "", "optional stage receipt path; stdout when omitted")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(stderr, "provider-documentation-stage-compile: invalid command-line arguments")
		return 2
	}
	fail := func(message string) int {
		fmt.Fprintln(stderr, "provider-documentation-stage-compile: "+message)
		return 1
	}

	if flags.NArg() != 0 {
		return fail("positional arguments are not accepted")
	}
	if strings.TrimSpace(*manifestPath) == "" {
		return fail("--inputs is required")
	}
	requestRaw, inputs, err := operations.load(*manifestPath)
	if err != nil {
		return fail("stage input validation failed")
	}
	receipt, err := operations.compile(requestRaw, inputs)
	if err != nil {
		return fail(providerplan.PublicStageCompileDiagnostic(err))
	}
	if *outPath == "" {
		if _, err := stdout.Write(receipt); err != nil {
			return fail("receipt publication failed")
		}
		return 0
	}
	if err := operations.write(*outPath, receipt); err != nil {
		return fail("receipt publication failed")
	}
	return 0
}
