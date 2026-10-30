// cloud-api-factory generates reviewable, candidate-only cloud API documents.
// It has no network, credential, grant, admission, deployment, or live-cloud
// mode. Full compilation is permitted only with a caller-supplied scaffold
// whose five rendered documents exactly equal the generated candidates.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("cloud-api-factory", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "candidate input JSON with pinned model paths and target contract")
	output := flags.String("output-root", "", "new absolute candidate output directory")
	scaffold := flags.String("source-package", "", "optional supplied sealed source-package scaffold")
	compiled := flags.String("compiled-output-root", "", "new absolute compiler output directory; requires --source-package")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(stderr, "cloud-api-factory: invalid command-line arguments")
		return 2
	}
	fail := func(v string) int { fmt.Fprintln(stderr, "cloud-api-factory: "+v); return 1 }
	if flags.NArg() != 0 || strings.TrimSpace(*input) == "" || strings.TrimSpace(*output) == "" {
		return fail("--input and --output-root are required; positional arguments are not accepted")
	}
	if (*scaffold == "") != (*compiled == "") {
		return fail("--source-package and --compiled-output-root must be supplied together")
	}
	request, err := providerplan.LoadCloudSourceCandidateInput(*input, providerplan.NewCloudCatalogParser())
	if err != nil {
		return fail("candidate input refused")
	}
	bundle, err := providerplan.BuildCloudSourceCandidateBundle(request)
	if err != nil {
		return fail("candidate generation refused")
	}
	if err := providerplan.WriteCloudSourceCandidateBundleExclusive(*output, bundle); err != nil {
		return fail("candidate publication refused")
	}
	if *scaffold != "" {
		if _, err := providerplan.CompileCloudSourceCandidateWithScaffold(bundle, *scaffold, *compiled); err != nil {
			return fail("supplied scaffold compilation refused")
		}
	}
	compilerStatus := "not_requested"
	if *scaffold != "" {
		compilerStatus = "compiled_candidate_not_verified"
	}
	_, _ = fmt.Fprintf(stdout, "status=%s candidate_output=%s compiler=%s\n", bundle.Status, filepath.Clean(*output), compilerStatus)
	return 0
}
