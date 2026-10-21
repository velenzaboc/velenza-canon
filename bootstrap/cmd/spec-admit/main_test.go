package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWritesSortedSubmissions(t *testing.T) {
	dir := t.TempDir()
	table, output := filepath.Join(dir, "table.json"), filepath.Join(dir, "out")
	data := `{"concepts":[{"canonical_name":"zeta","node_kind":"axiom","contract":{},"payload":{}},{"canonical_name":"alpha","node_kind":"section","contract":{},"payload":{}}],"edges":[{"edge_label":"references","source_name":"zeta","target_name":"alpha"}]}`
	if err := os.WriteFile(table, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := run([]string{"--table", table, "--output-dir", output, "--org-id", "org"}, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "wrote 3 submissions") {
		t.Fatalf("stderr %q", stderr.String())
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 3 {
		t.Fatalf("entries %d, %v", len(entries), err)
	}
	if !strings.Contains(entries[0].Name(), "alpha") {
		t.Fatalf("not canonical sort: %q", entries[0].Name())
	}
}

func TestRunAndMainRejectInvalidInvocation(t *testing.T) {
	if err := run(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted missing flags")
	}
	oldArgs, oldExit := os.Args, exit
	t.Cleanup(func() { os.Args, exit = oldArgs, oldExit })
	os.Args = []string{"spec-admit"}
	code := -1
	exit = func(got int) { code = got; panic("exit") }
	defer func() {
		if recover() == nil || code != 2 {
			t.Fatalf("exit %d", code)
		}
	}()
	main()
}

func TestTransformClosesMalformedInputsAndUnknownKinds(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadConceptTable(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("accepted missing table")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConceptTable(bad); err == nil {
		t.Fatal("accepted malformed table")
	}
	if _, err := ToSubmissions(&ConceptTable{Concepts: []Concept{{CanonicalName: "unknown", NodeKind: "not_registered"}}}, "org"); err == nil {
		t.Fatal("accepted unknown kind")
	}
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteSubmissionDir(nil, filepath.Join(blocker, "child")); err == nil {
		t.Fatal("accepted non-directory output parent")
	}
}
