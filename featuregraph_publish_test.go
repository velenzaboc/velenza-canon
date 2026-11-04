package main

import (
	"os"
	"path/filepath"
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
