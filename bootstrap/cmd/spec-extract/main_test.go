package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunExtractsToStdoutAndFile(t *testing.T) {
	dir := t.TempDir()
	recipe := filepath.Join(dir, "recipe.json")
	source := filepath.Join(dir, "source.json")
	if err := os.WriteFile(recipe, []byte(`{"source_spec_id":"id","source_spec_name":"name","concept_domain":"domain","node_kind":"axiom","extractions":[{"path":"items[*]","id_field":"id","leaf_fields":{"title":"title"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(`{"items":[{"id":"one","title":"first"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := run([]string{"--recipe", recipe, "--source", source}, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "first") {
		t.Fatalf("stdout %q", stdout.String())
	}
	out := filepath.Join(dir, "nested", "out.json")
	if err := os.Mkdir(filepath.Dir(out), 0o700); err != nil { t.Fatal(err) }
	if err := run([]string{"--recipe", recipe, "--source", source, "--output", out}, &stdout); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(out); err != nil || !strings.Contains(string(data), "first") {
		t.Fatalf("file %q: %v", data, err)
	}
}

func TestRunRejectsBadInputs(t *testing.T) {
	if err := run(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted missing flags")
	}
	if err := run([]string{"--recipe", "missing", "--source", "missing"}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted missing inputs")
	}
}

func TestMainExitsForInvalidArguments(t *testing.T) {
	oldArgs, oldExit := os.Args, exit
	t.Cleanup(func() { os.Args, exit = oldArgs, oldExit })
	os.Args = []string{"spec-extract"}
	code := -1
	exit = func(got int) { code = got; panic("exit") }
	defer func() {
		if recover() == nil || code != 2 {
			t.Fatalf("exit code %d", code)
		}
	}()
	main()
}
