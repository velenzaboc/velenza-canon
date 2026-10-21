//go:build linux

package providerplan

import "golang.org/x/sys/unix"

func publishNonWindowsFactoryCleanTargetDirectory(parentFD int, stagedName, finalName string) error {
	return unix.Renameat2(parentFD, stagedName, parentFD, finalName, unix.RENAME_NOREPLACE)
}
