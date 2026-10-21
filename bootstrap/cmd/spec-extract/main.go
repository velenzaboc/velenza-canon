package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

var exit = os.Exit

// spec-extract applies an extraction recipe to a source `.ood.json`
// spec file and emits flat ConceptRecords as JSON. Output goes to
// stdout by default, or to --output <path>.
//
// Usage:
//
//	spec-extract --recipe <path> --source <path> [--output <path>]
//
// Exit codes:
//
//	0  success
//	2  invocation error (bad flag, missing file, parse failure)
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "spec-extract:", err)
		exit(2)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("spec-extract", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	recipePath := flags.String("recipe", "", "path to the extraction recipe JSON (required)")
	sourcePath := flags.String("source", "", "path to the source .ood.json spec file (required)")
	outputPath := flags.String("output", "", "path to write extracted records JSON (default: stdout)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *recipePath == "" || *sourcePath == "" {
		return fmt.Errorf("--recipe and --source are required")
	}

	recipe, err := LoadRecipe(*recipePath)
	if err != nil {
		return err
	}
	source, err := LoadSource(*sourcePath)
	if err != nil {
		return err
	}

	records, err := Extract(recipe, source, *sourcePath)
	if err != nil {
		return err
	}

	out, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if *outputPath != "" {
		if err := os.WriteFile(*outputPath, out, 0o644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	} else {
		_, err = fmt.Fprintln(stdout, string(out))
		return err
	}
	return nil
}
