package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

func TestModelAuditCommand(t *testing.T) {
	dir := t.TempDir()
	oldPath, newPath := filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json")
	for path, body := range map[string]string{oldPath: `{"revision":"1","n":9007199254740992}`, newPath: `{"revision":"2","n":9007199254740993}`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var out, errout bytes.Buffer
	if code := run([]string{"--old", oldPath, "--new", newPath}, &out, &errout); code != 0 {
		t.Fatalf("code=%d err=%s", code, errout.String())
	}
	var audit providerplan.CloudModelRevisionAudit
	if err := json.Unmarshal(out.Bytes(), &audit); err != nil || len(audit.Changes) != 2 || audit.OldSHA256 == audit.NewSHA256 {
		t.Fatalf("audit=%+v err=%v", audit, err)
	}
	if err := os.WriteFile(newPath, []byte(`{"n":1,"n":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"--old", oldPath, "--new", newPath}, &out, &errout); code == 0 || out.Len() != 0 {
		t.Fatal("duplicate-key model published an audit")
	}
	if code := run([]string{"--old", oldPath}, &out, &errout); code != 2 {
		t.Fatal("missing required input accepted")
	}
}

func TestModelAuditReadBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate((64 << 20) + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readModel(path); err == nil {
		t.Fatal("oversized model accepted")
	}
}
