package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPreparationCommandRoundTripAndTamper(t *testing.T) {
	root := filepath.Join(t.TempDir(), "prepared")
	args := []string{"--input", "../../testdata/cloudapi/candidate-input.json", "--scope", "../../testdata/cloudapi/mapping-package-scope.json", "--profiles", "../../testdata/cloudapi/provider-profiles-v1.json", "--ingestion-policy", "../../testdata/cloudapi/ingestion-handoff-policy.json", "--output-root", root}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("prepare exit=%d: %s", code, stderr.String())
	}
	var manifest map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["status"] != "candidate_prepared_unqualified" {
		t.Fatal("unexpected authority promotion")
	}
	first := append([]byte(nil), stdout.Bytes()...)
	stdout.Reset()
	stderr.Reset()
	verify := append(append([]string(nil), args...), "--verify")
	if code := run(verify, &stdout, &stderr); code != 0 {
		t.Fatalf("verify exit=%d: %s", code, stderr.String())
	}
	if !bytes.Equal(first, stdout.Bytes()) {
		t.Fatal("reconstruction changed candidate manifest")
	}
	if err := os.WriteFile(filepath.Join(root, "scope.json"), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(verify, &stdout, &stderr); code == 0 || stdout.Len() != 0 {
		t.Fatal("tampered package reported success")
	}
}

func TestPreparationCommandRefusesIncompleteArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"--bad"}, {"--input", "unused", "unexpected"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code == 0 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("accepted arguments %q", args)
		}
	}
}
