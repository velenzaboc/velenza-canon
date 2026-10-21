//go:build !windows

package providerplan

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// namedFactoryPublication holds the platform primitives that publish a named
// private stage under strict no-replace semantics and force the result to
// stable storage. The primitives are values rather than direct calls because
// the constants and syscalls they name (for example macOS RENAME_EXCL and
// F_FULLFSYNC) exist only in that platform's headers, so naming them here
// would not compile elsewhere. Holding them as fields keeps the per-platform
// file free of executable statements while this behaviour stays on a build the
// coverage gate measures.
type namedFactoryPublication struct {
	rename      func(int, string, int, string, uint32) error
	renameFlag  uint32
	fcntl       func(uintptr, int, int) (int, error)
	fullSyncCmd int
	fsync       func(int) error
}

func (publication namedFactoryPublication) publish(parentFD int, stageDirFD int, _ int, stagedName string, finalName string) error {
	if stagedName == "" {
		return fmt.Errorf("macOS requires a named private stage for atomic publication")
	}
	if err := publication.rename(stageDirFD, stagedName, parentFD, finalName, publication.renameFlag); err != nil {
		return fmt.Errorf("rename private stage to final leaf with RENAME_EXCL: %w", err)
	}
	return nil
}

func (publication namedFactoryPublication) syncFile(fd int) error {
	return publication.fullSync(fd, "staged file")
}

func (publication namedFactoryPublication) syncDirectory(fd int) error {
	return publication.fullSync(fd, "parent directory")
}

// fullSync prefers the platform's strongest durability barrier and falls back
// to fsync only when the filesystem reports that barrier unimplemented. A
// fallback that itself fails reports both causes rather than the weaker one.
func (publication namedFactoryPublication) fullSync(fd int, subject string) error {
	if _, err := publication.fcntl(uintptr(fd), publication.fullSyncCmd, 0); err == nil {
		return nil
	} else if !fullSyncFallbackAllowed(err) {
		return fmt.Errorf("F_FULLFSYNC %s: %w", subject, err)
	} else if fallbackErr := publication.fsync(fd); fallbackErr != nil {
		return errors.Join(
			fmt.Errorf("F_FULLFSYNC %s unsupported: %w", subject, err),
			fmt.Errorf("fsync %s fallback: %w", subject, fallbackErr),
		)
	}
	return nil
}

func fullSyncFallbackAllowed(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.ENOSYS)
}

// unnamedStageUnsupported reports that a platform has no unnamed-stage
// primitive, which routes the caller to the named private stage instead.
func unnamedStageUnsupported(int) (int, bool, error) {
	return -1, false, nil
}

// unsupportedPlatformPublication fails closed on a platform with no atomic
// no-replace primitive rather than degrading to a replacing rename.
func unsupportedPlatformPublication(int, int, int, string, string) error {
	return fmt.Errorf("%s has no configured atomic no-replace publication primitive; refusing", runtime.GOOS)
}
