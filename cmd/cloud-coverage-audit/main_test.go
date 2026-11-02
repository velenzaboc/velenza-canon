package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoverageCommandPublishesCandidateOnlyExactLedger(t *testing.T) {
	root := filepath.Join(t.TempDir(), "coverage")
	args := []string{"--input", "../../testdata/cloudapi/candidate-input.json", "--scope", "../../testdata/cloudapi/mapping-package-scope.json", "--output-root", root}
	var out, diagnostic bytes.Buffer
	if code := run(args, &out, &diagnostic); code != 0 {
		t.Fatalf("code=%d diagnostic=%s", code, &diagnostic)
	}
	if !strings.Contains(out.String(), `"unsupported":200`) || !strings.Contains(out.String(), `"status":"candidate_coverage_backlog"`) {
		t.Fatalf("wrong summary: %s", &out)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 1 || entries[0].Name() != "cloud_mapping_coverage_backlog.json" {
		t.Fatalf("output=%v %v", entries, err)
	}
	if run(args, &out, &diagnostic) == 0 {
		t.Fatal("coverage command overwrote output")
	}
}

func TestCoverageCommandRefusesAuthorityAndIncompleteFlags(t *testing.T) {
	for _, args := range [][]string{{}, {"--input", "missing"}, {"--admit", "true"}, {"--source-owner", "caller"}} {
		var out, diagnostic bytes.Buffer
		if run(args, &out, &diagnostic) == 0 || out.Len() != 0 {
			t.Fatal("invalid coverage invocation produced output")
		}
	}
}
