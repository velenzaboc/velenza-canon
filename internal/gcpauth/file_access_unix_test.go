//go:build unix

package gcpauth

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

// fakeStatInfo reports a real credential fixture's genuine permission bits
// (via the embedded os.FileInfo) but a substituted *syscall.Stat_t, so the
// owner-mismatch branch of validateCredentialFileAccess can be exercised
// deterministically without needing root to os.Chown a real file to another
// uid — chown to an arbitrary uid is refused for a non-root test process, and
// a root test process would need the reverse (a file NOT already owned by
// its own effective uid), so neither ambient privilege level can reach this
// branch by construction alone.
type fakeStatInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (f fakeStatInfo) Sys() any { return &f.stat }

func TestValidateCredentialFileAccessUnixRejectsOwnerMismatch(t *testing.T) {
	path := writeCredentialFile(t, `{"type":"authorized_user"}`, 0o600)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	realInfo, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	realStat, ok := realInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("file.Stat().Sys() = %T, want *syscall.Stat_t", realInfo.Sys())
	}
	mismatched := *realStat
	mismatched.Uid = realStat.Uid + 1
	info := fakeStatInfo{FileInfo: realInfo, stat: mismatched}

	if err := validateCredentialFileAccess(file, info); err == nil || !strings.Contains(err.Error(), "owned by the effective user") {
		t.Fatalf("validateCredentialFileAccess(uid mismatch) = %v, want owner refusal", err)
	}
}
