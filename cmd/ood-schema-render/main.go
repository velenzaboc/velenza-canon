package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/velenzaboc/velenza-canon/internal/oodschema"
)

var exit = os.Exit

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ood-schema-render", flag.ContinueOnError)
	flags.SetOutput(stderr)
	oodPath := flags.String("ood", "", "path to canonical OOD_GRAPH_PROTOCOL_v1.ood.json bytes")
	outPath := flags.String("out", "", "path for rendered Spanner DDL")
	receiptPath := flags.String("receipt", "", "optional path for the body-free render receipt")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *oodPath == "" || *outPath == "" {
		return fmt.Errorf("-ood and -out are required")
	}
	oodBytes, err := os.ReadFile(*oodPath)
	if err != nil {
		return fmt.Errorf("read OOD spec: %w", err)
	}
	ddl, receipt, err := oodschema.Render(oodBytes)
	if err != nil {
		return fmt.Errorf("render OOD schema: %w", err)
	}
	if err := writeFile(*outPath, ddl); err != nil {
		return fmt.Errorf("write rendered DDL: %w", err)
	}
	receiptBytes, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("encode receipt: %w", err)
	}
	receiptBytes = append(receiptBytes, '\n')
	if *receiptPath != "" {
		if err := writeFile(*receiptPath, receiptBytes); err != nil {
			return fmt.Errorf("write receipt: %w", err)
		}
		return nil
	}
	_, err = stdout.Write(receiptBytes)
	return err
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
