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
func run(args []string, out, errout io.Writer) int {
	f := flag.NewFlagSet("cloud-model-audit", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	old := f.String("old", "", "pinned old model")
	fresh := f.String("new", "", "candidate new model")
	model := f.String("model", "", "retained model for exact byte selections")
	selections := f.String("select", "", "pinned source coordinate and named JSON pointers")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	if *model != "" || *selections != "" {
		if *model == "" || *selections == "" || *old != "" || *fresh != "" {
			fmt.Fprintln(errout, "cloud-model-audit: --model and --select must be supplied together")
			return 2
		}
		raw, err := readModel(*model)
		if err != nil {
			return 1
		}
		request, err := readModel(*selections)
		if err != nil {
			return 1
		}
		bindings, err := providerplan.MeasureCloudModelEvidence(raw, request)
		if err != nil {
			fmt.Fprintln(errout, "cloud-model-audit:", err)
			return 1
		}
		if err := json.NewEncoder(out).Encode(bindings); err != nil {
			return 1
		}
		return 0
	}
	if *old == "" || *fresh == "" {
		fmt.Fprintln(errout, "cloud-model-audit: --old and --new are required")
		return 2
	}
	a, e := readModel(*old)
	if e != nil {
		fmt.Fprintln(errout, "cloud-model-audit: old input refused")
		return 1
	}
	b, e := readModel(*fresh)
	if e != nil {
		fmt.Fprintln(errout, "cloud-model-audit: new input refused")
		return 1
	}
	r, e := providerplan.AuditCloudModelRevision(a, b)
	if e != nil {
		fmt.Fprintln(errout, "cloud-model-audit: audit refused")
		return 1
	}
	if json.NewEncoder(out).Encode(r) != nil {
		return 1
	}
	return 0
}

func readModel(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const maxBytes = 64 << 20
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, fmt.Errorf("model exceeds audit bound")
	}
	return raw, nil
}
