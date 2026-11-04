// cloud-mapping-package composes a declared scope of checked offline mappings.
// Its output is candidate input, never a factory verification or admission.
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
	flags := flag.NewFlagSet("cloud-mapping-package", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "pinned model and mapping input")
	scope := flags.String("scope", "", "exact selected catalog and operation target roster")
	output := flags.String("output-root", "", "new absolute candidate package directory")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(stderr, "cloud-mapping-package: invalid arguments")
		return 2
	}
	fail := func(message string) int { fmt.Fprintln(stderr, "cloud-mapping-package: "+message); return 1 }
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
	pkg, err := providerplan.BuildCloudMappingPackage(request, selection)
	if err != nil {
		return fail("mapping closure refused")
	}
	if err := providerplan.WriteCloudMappingPackageExclusive(*output, pkg); err != nil {
		return fail("exclusive candidate package publication refused")
	}
	if err := json.NewEncoder(stdout).Encode(pkg); err != nil {
		return fail("package summary output failed")
	}
	return 0
}
