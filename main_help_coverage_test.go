package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestMainHelpPathReturnsWithoutExit(t *testing.T) {
	original := os.Args
	os.Args = []string{"spec-graph", "--help"}
	t.Cleanup(func() { os.Args = original })
	originalStderr := os.Stderr
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("capture help output: %v", err)
	}
	os.Stderr = writeEnd
	t.Cleanup(func() {
		os.Stderr = originalStderr
		_ = readEnd.Close()
		_ = writeEnd.Close()
	})
	main()
	if err := writeEnd.Close(); err != nil {
		t.Fatalf("close help-output writer: %v", err)
	}
	raw, err := io.ReadAll(readEnd)
	if err != nil {
		t.Fatalf("read help output: %v", err)
	}
	if help := string(raw); !strings.Contains(help, "usage:") || !strings.Contains(help, "spec-graph mcp") {
		t.Fatalf("main help output = %q", help)
	}
}
