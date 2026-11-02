// cloud-model-refresh prepares an exclusively published, unqualified successor.
package main

import (
	"flag"
	"fmt"
	"github.com/velenzaboc/velenza-canon/internal/providerplan"
	"io"
	"os"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, out, errout io.Writer) int {
	f := flag.NewFlagSet("cloud-model-refresh", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	input := f.String("input", "", "previous pinned candidate input")
	profiles := f.String("profiles", "", "previous pinned profile document")
	scopePath := f.String("scope", "", "selected mapping scope")
	policyPath := f.String("ingestion-policy", "", "owner-pinned ingestion policy")
	optionsPath := f.String("refresh", "", "exact successor model coordinates and versions")
	output := f.String("output-root", "", "absent output root")
	verify := f.Bool("verify", false, "reconstruct and compare existing output")
	fail := func(message string) int { fmt.Fprintln(errout, "cloud-model-refresh: "+message); return 1 }
	if f.Parse(args) != nil || f.NArg() != 0 || *input == "" || *profiles == "" || *scopePath == "" || *policyPath == "" || *optionsPath == "" || *output == "" {
		return fail("--input, --profiles, --scope, --ingestion-policy, --refresh and --output-root are required")
	}
	scope, err := providerplan.LoadCloudMappingPackageScope(*scopePath)
	if err != nil {
		return fail("scope refused")
	}
	policy, err := providerplan.LoadCloudIngestionHandoffPolicy(*policyPath)
	if err != nil {
		return fail("ingestion policy refused")
	}
	options, err := providerplan.LoadCloudModelRefreshOptions(*optionsPath)
	if err != nil {
		return fail("successor coordinates refused")
	}
	bundle, err := providerplan.BuildCloudModelRefreshBundle(*input, *profiles, scope, policy, options)
	if err != nil {
		return fail("successor composition refused")
	}
	if !*verify {
		if err := bundle.PublishExclusive(*output); err != nil {
			return fail("exclusive publication refused")
		}
	}
	if err := bundle.VerifyDirectory(*output); err != nil {
		return fail("exact successor tree verification refused")
	}
	if _, err := out.Write(bundle.ManifestJSON()); err != nil {
		return fail("manifest output failed")
	}
	return 0
}
