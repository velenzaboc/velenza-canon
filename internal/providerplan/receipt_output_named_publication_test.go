//go:build !windows

package providerplan

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The no-replace rename flag and the full-sync command are darwin-only
// constants, so this selected-on-linux test names sentinels and asserts the
// configured value is passed through unchanged.
const (
	testNoReplaceRenameFlag = uint32(0x4)
	testFullSyncCommand     = 0x33
)

func TestNamedFactoryPublicationRefusesAnEmptyStageName(t *testing.T) {
	renamed := false
	publication := namedFactoryPublication{
		rename: func(int, string, int, string, uint32) error { renamed = true; return nil },
	}
	err := publication.publish(7, 9, -1, "", "receipt.json")
	if err == nil || !strings.Contains(err.Error(), "requires a named private stage for atomic publication") {
		t.Fatalf("empty stage name error = %v, want a named-stage refusal", err)
	}
	if renamed {
		t.Fatal("an empty stage name still attempted a rename")
	}
}

func TestNamedFactoryPublicationRenamesStageToFinalWithTheNoReplaceFlag(t *testing.T) {
	var gotFromFD, gotToFD int
	var gotFrom, gotTo string
	var gotFlag uint32
	publication := namedFactoryPublication{
		rename: func(fromFD int, from string, toFD int, to string, flag uint32) error {
			gotFromFD, gotFrom, gotToFD, gotTo, gotFlag = fromFD, from, toFD, to, flag
			return nil
		},
		renameFlag: testNoReplaceRenameFlag,
	}
	if err := publication.publish(7, 9, -1, "receipt", "receipt.json"); err != nil {
		t.Fatalf("publish = %v, want success", err)
	}
	if gotFromFD != 9 || gotFrom != "receipt" || gotToFD != 7 || gotTo != "receipt.json" {
		t.Fatalf("rename moved (%d,%q) to (%d,%q), want the stage directory to the retained parent", gotFromFD, gotFrom, gotToFD, gotTo)
	}
	if gotFlag != testNoReplaceRenameFlag {
		t.Fatalf("rename flag = %#x, want the configured no-replace flag %#x", gotFlag, testNoReplaceRenameFlag)
	}
}

func TestNamedFactoryPublicationPreservesACollisionRefusal(t *testing.T) {
	publication := namedFactoryPublication{
		rename:     func(int, string, int, string, uint32) error { return unix.EEXIST },
		renameFlag: testNoReplaceRenameFlag,
	}
	err := publication.publish(7, 9, -1, "receipt", "receipt.json")
	if err == nil {
		t.Fatal("a refused no-replace rename reported a successful publication")
	}
	if !errors.Is(err, unix.EEXIST) {
		t.Fatalf("publication error = %v, want the EEXIST collision cause preserved", err)
	}
	if !strings.Contains(err.Error(), "rename private stage to final leaf with RENAME_EXCL: ") {
		t.Fatalf("publication error = %v, want the no-replace publication context", err)
	}
}

func TestNamedFactoryPublicationFullSyncPrefersTheStrongestBarrier(t *testing.T) {
	var gotFD, gotCmd, gotArg int
	fsyncCalled := false
	publication := namedFactoryPublication{
		fcntl: func(fd uintptr, cmd, arg int) (int, error) {
			gotFD, gotCmd, gotArg = int(fd), cmd, arg
			return 0, nil
		},
		fullSyncCmd: testFullSyncCommand,
		fsync:       func(int) error { fsyncCalled = true; return nil },
	}
	if err := publication.syncFile(11); err != nil {
		t.Fatalf("syncFile = %v, want success", err)
	}
	if gotFD != 11 || gotCmd != testFullSyncCommand || gotArg != 0 {
		t.Fatalf("full sync called fd=%d cmd=%#x arg=%d, want fd=11 cmd=%#x arg=0", gotFD, gotCmd, gotArg, testFullSyncCommand)
	}
	if fsyncCalled {
		t.Fatal("a successful full sync still weakened to fsync")
	}
}

func TestNamedFactoryPublicationFullSyncNamesItsSubject(t *testing.T) {
	for _, test := range []struct {
		name string
		call func(namedFactoryPublication) error
		want string
	}{
		{name: "file", call: func(p namedFactoryPublication) error { return p.syncFile(3) }, want: "F_FULLFSYNC staged file: "},
		{name: "directory", call: func(p namedFactoryPublication) error { return p.syncDirectory(3) }, want: "F_FULLFSYNC parent directory: "},
	} {
		t.Run(test.name, func(t *testing.T) {
			publication := namedFactoryPublication{
				fcntl: func(uintptr, int, int) (int, error) { return -1, unix.EIO },
				fsync: func(int) error { return nil },
			}
			err := test.call(publication)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to name %q", err, test.want)
			}
		})
	}
}

func TestNamedFactoryPublicationFullSyncNeverWeakensOnANonFallbackError(t *testing.T) {
	fsyncCalled := false
	publication := namedFactoryPublication{
		fcntl: func(uintptr, int, int) (int, error) { return -1, unix.EIO },
		fsync: func(int) error { fsyncCalled = true; return nil },
	}
	err := publication.syncFile(5)
	if err == nil {
		t.Fatal("a failed durability barrier reported success")
	}
	if fsyncCalled {
		t.Fatal("a non-fallback errno still weakened to fsync")
	}
	if !errors.Is(err, unix.EIO) {
		t.Fatalf("error = %v, want the original errno preserved", err)
	}
	if strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("error = %v, want no unsupported-fallback wording for a real failure", err)
	}
}

func TestNamedFactoryPublicationFullSyncFallsBackOnlyForUnimplementedBarriers(t *testing.T) {
	for _, test := range []struct {
		name  string
		errno unix.Errno
	}{
		{name: "EINVAL", errno: unix.EINVAL},
		{name: "ENOTSUP", errno: unix.ENOTSUP},
		{name: "EOPNOTSUPP", errno: unix.EOPNOTSUPP},
		{name: "ENOTTY", errno: unix.ENOTTY},
		{name: "ENOSYS", errno: unix.ENOSYS},
	} {
		t.Run(test.name, func(t *testing.T) {
			fsyncFD := 0
			fsyncCalled := false
			publication := namedFactoryPublication{
				fcntl: func(uintptr, int, int) (int, error) { return -1, test.errno },
				fsync: func(fd int) error { fsyncCalled, fsyncFD = true, fd; return nil },
			}
			if err := publication.syncFile(13); err != nil {
				t.Fatalf("syncFile = %v, want the fsync fallback to succeed", err)
			}
			if !fsyncCalled {
				t.Fatal("an unimplemented barrier did not fall back to fsync")
			}
			if fsyncFD != 13 {
				t.Fatalf("fallback fsync used fd %d, want the same descriptor 13", fsyncFD)
			}
		})
	}
}

func TestNamedFactoryPublicationReportsBothCausesWhenTheFallbackAlsoFails(t *testing.T) {
	fallbackFailure := errors.New("injected fsync failure")
	publication := namedFactoryPublication{
		fcntl: func(uintptr, int, int) (int, error) { return -1, unix.ENOTSUP },
		fsync: func(int) error { return fallbackFailure },
	}
	err := publication.syncFile(3)
	if err == nil {
		t.Fatal("a failed fallback fsync reported durability success")
	}
	if !errors.Is(err, unix.ENOTSUP) || !errors.Is(err, fallbackFailure) {
		t.Fatalf("error = %v, want both the barrier and the fallback causes", err)
	}
	if !strings.Contains(err.Error(), "F_FULLFSYNC staged file unsupported: ") ||
		!strings.Contains(err.Error(), "fsync staged file fallback: ") {
		t.Fatalf("error = %v, want both causes named with their subject", err)
	}
}

func TestUnnamedStageUnsupportedReportsNoSupportWithoutAnError(t *testing.T) {
	fd, supported, err := unnamedStageUnsupported(7)
	if err != nil {
		t.Fatalf("unnamed stage probe = %v, want a clean unsupported answer that routes to a named stage", err)
	}
	if supported {
		t.Fatal("a platform with no unnamed-stage primitive reported support")
	}
	if fd != -1 {
		t.Fatalf("unnamed stage descriptor = %d, want -1 so no caller can use it", fd)
	}
}

func TestUnsupportedPlatformPublicationFailsClosedNamingThePlatform(t *testing.T) {
	err := unsupportedPlatformPublication(1, 2, 3, "receipt", "receipt.json")
	if err == nil {
		t.Fatal("a platform with no atomic no-replace primitive reported a successful publication")
	}
	if !strings.Contains(err.Error(), runtime.GOOS) {
		t.Fatalf("refusal = %v, want it to name the platform %q", err, runtime.GOOS)
	}
	if !strings.Contains(err.Error(), "no configured atomic no-replace publication primitive; refusing") {
		t.Fatalf("refusal = %v, want an explicit fail-closed refusal", err)
	}
}
