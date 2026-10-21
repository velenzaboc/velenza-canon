//go:build linux || darwin

package providerplan

import (
	"os"

	"golang.org/x/sys/unix"
)

type providerInputMutationToken struct {
	seconds     int64
	nanoseconds int64
}

// currentProviderInputMutationToken reads the POSIX change time, which moves on
// both content and metadata mutation and therefore witnesses changes that mtime
// alone hides. Linux and macOS disagree on the syscall.Stat_t field name (Ctim
// versus Ctimespec), so this reads unix.Stat_t, which names it Ctim on both and
// lets one selected file serve every POSIX target.
//
// The descriptor comes from SyscallConn rather than File.Fd: Fd permanently
// returns the descriptor to blocking mode and detaches it from the runtime
// poller, which is a lasting side effect on a handle the caller still owns.
func currentProviderInputMutationToken(file *os.File) (providerInputMutationToken, error) {
	connection, err := file.SyscallConn()
	if err != nil {
		return providerInputMutationToken{}, err
	}
	var stat unix.Stat_t
	var statErr error
	if controlErr := connection.Control(func(fd uintptr) {
		statErr = unix.Fstat(int(fd), &stat)
	}); controlErr != nil {
		return providerInputMutationToken{}, controlErr
	}
	if statErr != nil {
		return providerInputMutationToken{}, statErr
	}
	return providerInputMutationToken{seconds: int64(stat.Ctim.Sec), nanoseconds: int64(stat.Ctim.Nsec)}, nil
}
