//go:build darwin

package providerplan

import "golang.org/x/sys/unix"

// darwinFactoryPublication binds the macOS primitives: renameatx_np with
// RENAME_EXCL for atomic no-replace publication and F_FULLFSYNC for a real
// platter-level flush, with fsync only as the documented fallback.
var darwinFactoryPublication = namedFactoryPublication{
	rename:      unix.RenameatxNp,
	renameFlag:  unix.RENAME_EXCL,
	fcntl:       unix.FcntlInt,
	fullSyncCmd: unix.F_FULLFSYNC,
	fsync:       unix.Fsync,
}

var createUnnamedNonWindowsFactoryFile = unnamedStageUnsupported

var publishNonWindowsFactoryOutput = darwinFactoryPublication.publish

var syncNonWindowsFactoryFile = darwinFactoryPublication.syncFile

var syncNonWindowsFactoryDirectory = darwinFactoryPublication.syncDirectory
