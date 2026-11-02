package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageCommandWritesSelectedClosureAndRefusesOverwrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "package")
	args := []string{"--input", "../../testdata/cloudapi/candidate-input.json", "--scope", "../../testdata/cloudapi/mapping-package-scope.json", "--output-root", root}
	var out, diagnostic bytes.Buffer
	if code := run(args, &out, &diagnostic); code != 0 {
		t.Fatalf("code=%d diagnostic=%s", code, &diagnostic)
	}
	if !strings.Contains(out.String(), `"mapped":31`) || !strings.Contains(out.String(), `"status":"candidate_complete_unqualified"`) {
		t.Fatalf("wrong summary: %s", &out)
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 3 {
		t.Fatalf("package roster=%v %v", files, err)
	}
	parent := filepath.Join(root, "cloud_mapping_parent_manifest.json")
	before, err := os.ReadFile(parent)
	if err != nil {
		t.Fatal(err)
	}
	if run(args, &out, &diagnostic) == 0 {
		t.Fatal("overwrote existing package")
	}
	after, err := os.ReadFile(parent)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing package changed")
	}
}

func TestPackageCommandRefusesMissingScopeAndUnknownAuthorityFlag(t *testing.T) {
	for _, args := range [][]string{{}, {"--input", "unread"}, {"--admit", "true"}, {"--source-owner", "caller"}} {
		var out, diagnostic bytes.Buffer
		if run(args, &out, &diagnostic) == 0 || out.Len() != 0 {
			t.Fatal("invalid invocation produced output")
		}
	}
}
