//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	physical, err := physicalTestTempDirectory()
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve physical test temporary directory:", err)
		os.Exit(2)
	}
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		if err := os.Setenv(key, physical); err != nil {
			fmt.Fprintln(os.Stderr, "set physical test temporary directory:", err)
			os.Exit(2)
		}
	}
	os.Exit(m.Run())
}

func physicalTestTempDirectory() (string, error) {
	root := os.TempDir()
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("temporary directory is not absolute")
	}
	physical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	physical = filepath.Clean(physical)
	info, err := os.Lstat(physical)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("temporary directory is not physical")
	}
	return physical, nil
}

// physicalTestPath resolves every symbolic link in an existing path. The
// Windows sibling reads the final path from an opened handle instead, because
// filepath.EvalSymlinks fails beneath a directory junction there.
func physicalTestPath(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}
