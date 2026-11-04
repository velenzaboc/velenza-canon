package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFeatureGraphReadFileUsesActualCapBoundary(t *testing.T) {
	name := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(name, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := featureGraphReadFile(name, 3)
	if err != nil {
		t.Fatalf("featureGraphReadFile() at cap: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("featureGraphReadFile() = %q, want abc", got)
	}
	if _, err := featureGraphReadFile(name, 2); err == nil {
		t.Fatal("featureGraphReadFile() below cap succeeded, want refusal")
	}
}

func TestFeatureGraphReadFileAppliesAbsoluteCapBeforeReading(t *testing.T) {
	name := filepath.Join(t.TempDir(), "oversize.json")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(featureGraphInputByteCap) + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := featureGraphReadFile(name, int(^uint(0)>>1)); err == nil {
		t.Fatal("featureGraphReadFile() accepted a file over the absolute cap")
	}
}

func TestFeatureGraphCommandRejectsHiddenCredentialConfigBeforeClient(t *testing.T) {
	name := filepath.Join(t.TempDir(), "operator.json")
	if err := os.WriteFile(name, []byte(`{"credentials_file":"not-a-real-carrier"}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := cmdFeatureGraphPublish(context.Background(), []string{"--config", name, "--selection", "unused", "--manifest", "unused"})
	if err == nil || !strings.Contains(err.Error(), "only allowed inside google_credentials") {
		t.Fatalf("hidden credential config did not refuse before client construction: %v", err)
	}
}
