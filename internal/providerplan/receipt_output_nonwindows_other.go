//go:build !windows && !linux && !darwin

package providerplan

import "golang.org/x/sys/unix"

var createUnnamedNonWindowsFactoryFile = unnamedStageUnsupported

var publishNonWindowsFactoryOutput = unsupportedPlatformPublication

var syncNonWindowsFactoryFile = unix.Fsync

var syncNonWindowsFactoryDirectory = unix.Fsync
