// cloud-factory-prepare reproducibly composes checked cloud candidate data.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("cloud-factory-prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "pinned cloud model and neutral mapping input")
	scopePath := flags.String("scope", "", "exact catalog and operation selection")
	profilesPath := flags.String("profiles", "", "shared provider and service API profiles")
	policyPath := flags.String("ingestion-policy", "", "owner-pinned source identity and reconciliation handoff policy")
	output := flags.String("output-root", "", "candidate output directory")
	verify := flags.Bool("verify", false, "rebuild from inputs and verify an existing output tree")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(stderr, "cloud-factory-prepare: invalid arguments")
		return 2
	}
	fail := func(message string) int { fmt.Fprintln(stderr, "cloud-factory-prepare: "+message); return 1 }
	if flags.NArg() != 0 || *input == "" || *scopePath == "" || *profilesPath == "" || *policyPath == "" || *output == "" {
		return fail("--input, --scope, --profiles, --ingestion-policy and --output-root are required")
	}
	root, err := filepath.Abs(*output)
	if err != nil {
		return fail("output coordinate refused")
	}
	request, err := providerplan.LoadCloudSourceCandidateInput(*input, providerplan.NewCloudCatalogParser())
	if err != nil {
		return fail("pinned model and mapping inputs refused")
	}
	scope, err := providerplan.LoadCloudMappingPackageScope(*scopePath)
	if err != nil {
		return fail("scope refused")
	}
	profiles, err := providerplan.LoadCloudAPIProfileDocument(*profilesPath)
	if err != nil {
		return fail("profiles refused")
	}
	policy, err := providerplan.LoadCloudIngestionHandoffPolicy(*policyPath)
	if err != nil {
		return fail("ingestion handoff policy refused")
	}
	prepared, err := providerplan.BuildCloudFactoryPreparation(request, scope, profiles, policy)
	if err != nil {
		return fail("candidate composition refused")
	}
	if !*verify {
		if err := prepared.PublishExclusive(root); err != nil {
			return fail("exclusive candidate publication refused")
		}
	}
	if err := prepared.VerifyDirectory(root); err != nil {
		return fail("candidate output verification refused")
	}
	if _, err := stdout.Write(prepared.ManifestJSON()); err != nil {
		return fail("manifest output failed")
	}
	return 0
}
