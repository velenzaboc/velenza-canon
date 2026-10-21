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

func TestProviderInputAdmissionNoFollowOpenRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dependency.json")
	if err := os.WriteFile(path, []byte("initial regular bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	hookCalled := false
	accumulator.beforeStableOpen = func(resourceKind, hookPath string) error {
		if resourceKind != providerInputAdmissionResourceKindArtifact || hookPath != path {
			return nil
		}
		if err := os.Remove(hookPath); err != nil {
			return err
		}
		if err := unix.Mkfifo(hookPath, 0o600); err != nil {
			return err
		}
		hookCalled = true
		return nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := readArtifactInputWithAdmission(path, accumulator)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO replacement error = %v, want prompt nonregular refusal", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO replacement blocked the bounded no-follow input open")
	}
	if !hookCalled {
		t.Fatal("FIFO replacement hook did not run after path inspection")
	}
	if len(accumulator.resources) != 0 || len(accumulator.physicalSnapshots) != 0 || accumulator.residentInputBytes != 0 {
		t.Fatalf("FIFO refusal changed provider input admission state: resources=%d snapshots=%d resident=%d", len(accumulator.resources), len(accumulator.physicalSnapshots), accumulator.residentInputBytes)
	}
}
