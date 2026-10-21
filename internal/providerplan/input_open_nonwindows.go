//go:build !windows

package providerplan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openProviderInputPathNoFollow(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolute = filepath.Clean(absolute)
	root := string(filepath.Separator)
	remainder := strings.TrimPrefix(absolute, root)
	if remainder == absolute || remainder == "" {
		return nil, fmt.Errorf("input path %q does not name a file below the filesystem root", path)
	}
	components := strings.Split(remainder, string(filepath.Separator))
	currentFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(currentFD)
			return nil, fmt.Errorf("input path %q contains an invalid component", path)
		}
		last := index == len(components)-1
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if !last {
			flags |= unix.O_DIRECTORY
		}
		nextFD, openErr := unix.Openat(currentFD, component, flags, 0)
		_ = unix.Close(currentFD)
		if openErr != nil {
			return nil, openErr
		}
		if !last {
			currentFD = nextFD
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstat(nextFD, &stat); err != nil {
			_ = unix.Close(nextFD)
			return nil, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			_ = unix.Close(nextFD)
			return nil, fmt.Errorf("input path %q is not a regular file", path)
		}
		if err := unix.SetNonblock(nextFD, false); err != nil {
			_ = unix.Close(nextFD)
			return nil, err
		}
		file := os.NewFile(uintptr(nextFD), absolute)
		if file == nil {
			_ = unix.Close(nextFD)
			return nil, fmt.Errorf("retain input file handle for %q", path)
		}
		return file, nil
	}
	return nil, fmt.Errorf("input path %q did not resolve to a leaf", path)
}
