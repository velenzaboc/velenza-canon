package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

const validOOD = `{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263","title":"OOD Graph Protocol","version":"1","sections":{"s6_spanner_storage_model":{"table_surfaces":{"example":{"physical_table_name":"OODGraphExample","primary_key":["organization_id","example_id"],"columns":{"organization_id":"STRING(36) NOT NULL","example_id":"STRING(36) NOT NULL","value":"STRING(64) NOT NULL"}}},"spanner_ddl_model":{"ddl_is_normative_schema_shape":true,"ddl_apply_instruction":false,"table_surface_column_order_parity":{"required":true},"statements":["CREATE TABLE OODGraphExample (organization_id STRING(36) NOT NULL, example_id STRING(36) NOT NULL, value STRING(64) NOT NULL) PRIMARY KEY (organization_id, example_id)"]}},"s7_spanner_property_graph_schema":{"create_property_graph_model":{"ddl_is_normative_schema_shape":true,"ddl_apply_instruction":false,"property_graph_name":"OODGraph","node_tables":"OODGraphExample KEY (organization_id, example_id) LABEL ood_graph_node PROPERTIES (organization_id, example_id, value) DYNAMIC LABEL (value)","edge_tables_generation":"OODGraphExample KEY (organization_id, example_id) SOURCE KEY (organization_id, example_id) REFERENCES OODGraphExample (organization_id, example_id) DESTINATION KEY (organization_id, example_id) REFERENCES OODGraphExample (organization_id, example_id) LABEL ood_graph_edge PROPERTIES (organization_id, example_id, value) DYNAMIC LABEL (value)"}}}}`

func TestRunRendersDDLAndReceipt(t *testing.T) {
	dir := t.TempDir()
	ood := filepath.Join(dir, "ood.json")
	if err := os.WriteFile(ood, []byte(validOOD), 0o600); err != nil {
		t.Fatal(err)
	}
	out, receipt := filepath.Join(dir, "schema.sql"), filepath.Join(dir, "receipt.json")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-ood", ood, "-out", out, "-receipt", receipt}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(out); err != nil || len(data) == 0 {
		t.Fatalf("DDL: %q %v", data, err)
	}
	if data, err := os.ReadFile(receipt); err != nil || !strings.Contains(string(data), "ood_spec_sha256") {
		t.Fatalf("receipt: %q %v", data, err)
	}
}

func TestRunRejectsMissingArgumentsAndWritesReceiptToStdout(t *testing.T) {
	if err := run(nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected required argument error")
	}
	dir := t.TempDir()
	ood, out := filepath.Join(dir, "ood.json"), filepath.Join(dir, "schema.sql")
	if err := os.WriteFile(ood, []byte(validOOD), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-ood", ood, "-out", out}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "ood_spec_sha256") {
		t.Fatalf("stdout %q", stdout.String())
	}
}

func TestWriteFileCreatesParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "output")
	if err := writeFile(path, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "ok" {
		t.Fatalf("got %q, %v", data, err)
	}
}

func TestRunClosesInvalidInputsAndOutputBoundaries(t *testing.T) {
	dir := t.TempDir()
	bad, out := filepath.Join(dir, "bad.json"), filepath.Join(dir, "schema.sql")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-ood", bad, "-out", out}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted malformed OOD")
	}
	if err := run([]string{"-ood", filepath.Join(dir, "missing"), "-out", out}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted missing OOD")
	}
	ood := filepath.Join(dir, "ood.json")
	if err := os.WriteFile(ood, []byte(validOOD), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-ood", ood, "-out", filepath.Join(dir, "missing-parent", "schema")}, failingWriter{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected stdout error")
	}
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(blocker, "child"), []byte("x")); err == nil {
		t.Fatal("expected mkdir error")
	}
}

func TestMainUsesNonzeroExitForRunFailure(t *testing.T) {
	oldArgs, oldExit := os.Args, exit
	t.Cleanup(func() { os.Args, exit = oldArgs, oldExit })
	os.Args = []string{"ood-schema-render"}
	code := -1
	exit = func(got int) { code = got; panic("exit") }
	defer func() {
		if recover() == nil || code != 1 {
			t.Fatalf("exit code %d", code)
		}
	}()
	main()
}
