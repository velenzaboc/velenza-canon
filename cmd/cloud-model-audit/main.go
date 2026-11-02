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
	if f.Parse(args) != nil || f.NArg() != 0 || *old == "" || *fresh == "" {
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
