// cloud-coverage-audit publishes an exhaustive candidate-only field coverage
// ledger. It does not qualify evidence, execute provider calls, or admit work.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("cloud-coverage-audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "pinned model and mapping input")
	scope := flags.String("scope", "", "exact selected catalog and operation target roster")
	output := flags.String("output-root", "", "new absolute coverage output directory")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(stderr, "cloud-coverage-audit: invalid arguments")
		return 2
	}
	fail := func(message string) int { fmt.Fprintln(stderr, "cloud-coverage-audit: "+message); return 1 }
	if flags.NArg() != 0 || *input == "" || *scope == "" || *output == "" {
		return fail("--input, --scope and --output-root are required; positional arguments are not accepted")
	}
	request, err := providerplan.LoadCloudSourceCandidateInput(*input, providerplan.NewCloudCatalogParser())
	if err != nil {
		return fail("pinned input refused")
	}
	selection, err := providerplan.LoadCloudMappingPackageScope(*scope)
	if err != nil {
		return fail("selected scope refused")
	}
	backlog, err := providerplan.BuildCloudCoverageBacklog(request, selection)
	if err != nil {
		return fail("coverage closure refused")
	}
	if err := providerplan.ValidateCloudCoverageBacklog(backlog.Document, request, selection); err != nil {
		return fail("coverage self-validation refused")
	}
	if err := providerplan.WriteCloudCoverageBacklogExclusive(*output, backlog); err != nil {
		return fail("exclusive coverage publication refused")
	}
	if err := json.NewEncoder(stdout).Encode(backlog); err != nil {
		return fail("coverage summary output failed")
	}
	return 0
}
