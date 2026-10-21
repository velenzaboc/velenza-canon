package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

var exit = os.Exit

// spec-admit transforms a validated concept table into a directory of
// submission JSON files in the shape spec_graph_import accepts. The
// caller then runs `spec_graph_import file_path=<dir>` to actually
// admit the concepts.
//
// Usage:
//
//	spec-admit --table <path> --output-dir <path> --org-id <id>
//
// Exit codes:
//
//	0  success
//	2  invocation error (bad flag, missing file, parse failure)
func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "spec-admit:", err)
		exit(2)
	}
}

func run(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("spec-admit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	tablePath := flags.String("table", "", "path to the validated concept table JSON (required)")
	outputDir := flags.String("output-dir", "", "directory to write submission files into (required)")
	orgID := flags.String("org-id", "", "organization_id stamped on every submission (required)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *tablePath == "" || *outputDir == "" || *orgID == "" {
		return fmt.Errorf("--table, --output-dir, --org-id are required")
	}

	table, err := LoadConceptTable(*tablePath)
	if err != nil {
		return err
	}
	subs, err := ToSubmissions(table, *orgID)
	if err != nil {
		return err
	}
	if err := WriteSubmissionDir(subs, *outputDir); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "spec-admit: wrote %d submissions to %s\n", len(subs), *outputDir)
	fmt.Fprintln(stderr, "spec-admit: next step → spec_graph_import file_path="+*outputDir)
	return nil
}
