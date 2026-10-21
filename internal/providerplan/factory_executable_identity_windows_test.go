//go:build windows

package providerplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFactoryExecutableIdentityNoFollowRejectsReparseReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "factory-runner.exe")
	target := filepath.Join(root, "replacement-target.exe")
	if err := os.WriteFile(path, []byte("initial executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("replacement target"), 0o700); err != nil {
		t.Fatal(err)
	}

	_, _, err := factoryExecutableIdentityWithOperations(factoryExecutableIdentityOperations{
		executable:   func() (string, error) { return path, nil },
		initialLstat: os.Lstat,
		initialOpen:  openProviderInputPathNoFollow,
		open: func(openPath string) (*os.File, error) {
			if err := os.Remove(openPath); err != nil {
				return nil, err
			}
			if err := os.Symlink(target, openPath); err != nil {
				t.Fatalf("create executable reparse fixture: %v", err)
			}
			return openProviderInputPathNoFollow(openPath)
		},
		finalLstat: os.Lstat,
		finalOpen:  openProviderInputPathNoFollow,
	})
	if err == nil || !strings.Contains(err.Error(), "open factory runner executable") {
		t.Fatalf("reparse executable-path substitution error = %v, want no-follow refusal", err)
	}
}
