//go:build !windows

package providerplan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func validateFactoryOutputRawPath(string) error { return nil }

func openFactoryOutputDirectoryPathNoFollow(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolute = filepath.Clean(absolute)
	root := string(filepath.Separator)
	remainder := strings.TrimPrefix(absolute, root)
	if remainder == absolute {
		return nil, fmt.Errorf("--out directory %q has no filesystem root", path)
	}
	currentFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if remainder != "" {
		for _, component := range strings.Split(remainder, string(filepath.Separator)) {
			if component == "" || component == "." || component == ".." {
				_ = unix.Close(currentFD)
				return nil, fmt.Errorf("--out directory %q contains an invalid component", path)
			}
			nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			_ = unix.Close(currentFD)
			if openErr != nil {
				return nil, openErr
			}
			currentFD = nextFD
		}
	}
	file := os.NewFile(uintptr(currentFD), absolute)
	if file == nil {
		_ = unix.Close(currentFD)
		return nil, fmt.Errorf("retain --out directory identity handle for %q", absolute)
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("--out directory %q is not a stable directory", absolute)
	}
	return file, nil
}
