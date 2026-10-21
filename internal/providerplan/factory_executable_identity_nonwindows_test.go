//go:build !windows

package providerplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFactoryExecutableIdentityNoFollowRejectsFIFOReplacementPromptly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "factory-runner")
	if err := os.WriteFile(path, []byte("initial executable"), 0o700); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, _, err := factoryExecutableIdentityWithOperations(factoryExecutableIdentityOperations{
			executable:   func() (string, error) { return path, nil },
			initialLstat: os.Lstat,
			initialOpen:  openProviderInputPathNoFollow,
			open: func(openPath string) (*os.File, error) {
				if err := os.Remove(openPath); err != nil {
					return nil, err
				}
				if err := unix.Mkfifo(openPath, 0o600); err != nil {
					return nil, err
				}
				return openProviderInputPathNoFollow(openPath)
			},
			finalLstat: os.Lstat,
			finalOpen:  openProviderInputPathNoFollow,
		})
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil || (!strings.Contains(err.Error(), "not a regular file") && !strings.Contains(err.Error(), "open factory runner executable")) {
			t.Fatalf("FIFO executable-path substitution error = %v, want prompt fail-closed refusal", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO executable-path substitution blocked instead of failing closed")
	}
}
