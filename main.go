// spec-graph is the Node Identity & Admission MCP server.
//
// Subcommands:
//   spec-graph mcp                       run as MCP stdio subprocess
//   spec-graph init                      apply bootstrap/schema_v1.sql to the experimental DB
//   spec-graph reset --confirm           drop + recreate the experimental DB
//
// See README.md and REQUIREMENTS.md for the three-tier framing, the
// experimental-bootstrap operating mode, and the cutover discipline.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "mcp":
		err = cmdMCP(ctx, os.Args[2:])
	case "init":
		err = cmdInit(ctx, os.Args[2:])
	case "reset":
		err = cmdReset(ctx, os.Args[2:])
	case "trace-code":
		err = cmdTraceCode(ctx, os.Args[2:])
	case "arbor-info":
		err = runArborInfoCLI(os.Args[2:], os.Stdout)
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "spec-graph:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `velenza-canon (spec-graph) — Normative Root Canon & Node Identity MCP server

usage:
  spec-graph mcp                       run as MCP Streamable HTTP server
  spec-graph init                      apply bootstrap/schema_v1.sql to the experimental DB
  spec-graph reset --confirm           drop + recreate the experimental DB
  spec-graph trace-code --spec-dir <dir> --code-dir <dir> [--fail-on-dangling] [--fail-on-uncovered]
                                       audit cross-layer //spec: and //volt: coverage
  spec-graph arbor-info                emit the Layer 2 Velenza Arbor Stack JSON descriptor

For live-graph R-rule audits, see bootstrap/audit/README.md — the audit
recipes run entirely in Spanner via ML.PREDICT against a registered Vertex
AI remote model, not as a spec-graph subcommand.

Config file: $VELENZA_CANON_CONFIG or $SPEC_GRAPH_CONFIG (default ./spec-graph.config.json).
Canon example:      velenza-canon.config.example.json
Bootstrap example:  spec-graph.config.bootstrap.example.json
Production example: spec-graph.config.production.example.json`)
}
