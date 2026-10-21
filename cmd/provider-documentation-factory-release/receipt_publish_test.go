package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishValidatedReceiptCreatesExactlyOnceWithExactBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "validated-receipt.json")
	raw := []byte("{\"body_free\":true,\"receipt_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n")
	if err := publishValidatedReceipt(path, raw); err != nil {
		t.Fatalf("publish validated receipt: %v", err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read published validated receipt: %v", err)
	}
	if !bytes.Equal(persisted, raw) {
		t.Fatalf("published receipt bytes = %q, want %q", persisted, raw)
	}
	if err := publishValidatedReceipt(path, []byte("replacement")); err == nil {
		t.Fatal("second validated receipt publication unexpectedly replaced the existing target")
	}
	persisted, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("reread published validated receipt: %v", err)
	}
	if !bytes.Equal(persisted, raw) {
		t.Fatalf("existing validated receipt changed after second publication: %q", persisted)
	}
}

func TestPublishValidatedReceiptRejectsNonCanonicalAndEmptyInputs(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name string
		path string
		raw  []byte
	}{
		{name: "empty bytes", path: filepath.Join(root, "empty.json"), raw: nil},
		{name: "relative path", path: "validated-receipt.json", raw: []byte("receipt")},
		{name: "traversal component", path: root + string(filepath.Separator) + "missing" + string(filepath.Separator) + ".." + string(filepath.Separator) + "traversal.json", raw: []byte("receipt")},
		{name: "padded path", path: filepath.Join(root, "padded.json") + " ", raw: []byte("receipt")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := publishValidatedReceipt(test.path, test.raw); err == nil {
				t.Fatalf("publishValidatedReceipt(%q) unexpectedly succeeded", test.path)
			}
		})
	}
}
