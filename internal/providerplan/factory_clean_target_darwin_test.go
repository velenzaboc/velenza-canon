//go:build darwin

package providerplan

import "golang.org/x/sys/unix"

func publishNonWindowsFactoryCleanTargetDirectory(parentFD int, stagedName, finalName string) error {
	return unix.RenameatxNp(parentFD, stagedName, parentFD, finalName, unix.RENAME_EXCL)
}
