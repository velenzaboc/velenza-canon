//go:build linux

package providerplan

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func createUnnamedNonWindowsFactoryFile(parentFD int) (int, bool, error) {
	fd, err := unix.Openat(parentFD, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err == nil {
		return fd, true, nil
	}
	if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENOSYS) {
		return -1, false, nil
	}
	return -1, false, fmt.Errorf("create private unnamed --out stage relative to retained parent: %w", err)
}

func publishNonWindowsFactoryOutput(parentFD int, stageDirFD int, stagedFD int, stagedName string, finalName string) error {
	if stagedName == "" {
		if err := unix.Linkat(stagedFD, "", parentFD, finalName, unix.AT_EMPTY_PATH); err == nil {
			return nil
		} else if !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("link private unnamed stage to final leaf with AT_EMPTY_PATH: %w", err)
		} else {
			// AT_EMPTY_PATH may require CAP_DAC_READ_SEARCH. procfs exposes this
			// process's still-open descriptor as an unforgeable source identity;
			// the destination remains relative to the retained parent handle.
			procPath := fmt.Sprintf("/proc/self/fd/%d", stagedFD)
			if fallbackErr := unix.Linkat(unix.AT_FDCWD, procPath, parentFD, finalName, unix.AT_SYMLINK_FOLLOW); fallbackErr != nil {
				return errors.Join(
					fmt.Errorf("link private unnamed stage with AT_EMPTY_PATH: %w", err),
					fmt.Errorf("link private unnamed stage through procfs descriptor fallback: %w", fallbackErr),
				)
			}
		}
		return nil
	}
	if err := unix.Renameat2(stageDirFD, stagedName, parentFD, finalName, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("rename private stage to final leaf with RENAME_NOREPLACE: %w", err)
	}
	return nil
}

func syncNonWindowsFactoryFile(fd int) error {
	return unix.Fsync(fd)
}

func syncNonWindowsFactoryDirectory(fd int) error {
	return unix.Fsync(fd)
}
