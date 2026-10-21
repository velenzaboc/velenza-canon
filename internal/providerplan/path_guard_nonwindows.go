//go:build !windows

package providerplan

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type providerInputStableFileIdentity struct {
	device uint64
	inode  uint64
}

func stableProviderInputFileIdentity(file *os.File) (providerInputStableFileIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return providerInputStableFileIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("filesystem metadata does not expose device/inode identity")
	}
	return providerInputStableFileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func validateProviderInputPathSyntax(string, string) error { return nil }

func fileInfoHasReparsePoint(os.FileInfo) bool {
	return false
}

func canonicalProviderInputPathKey(path string) string {
	return filepath.Clean(path)
}
