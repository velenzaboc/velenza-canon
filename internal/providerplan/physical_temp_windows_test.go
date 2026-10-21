//go:build windows

package providerplan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestMain is the Windows sibling of physical_temp_nonwindows_test.go.
//
// Fixtures in this package live under os.TempDir, and the production path
// guards refuse any path that reaches its object through an alias: an 8.3
// short-name component, or a directory junction or symbolic link. Those guards
// are correct and stay unchanged; the fixture root is what must be physical.
// GitHub-hosted Windows runners set TEMP to C:\Users\RUNNER~1\AppData\Local\Temp,
// so without this every fixture path carried a short-name alias.
//
// filepath.EvalSymlinks cannot produce the physical path on Windows: it expands
// short names, but for any path beneath a directory junction it returns a bare
// ERROR_PATH_NOT_FOUND. The final path is therefore read from an opened handle.
func TestMain(m *testing.M) {
	physical, err := physicalTestTempDirectory()
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve physical test temporary directory:", err)
		os.Exit(2)
	}
	for _, key := range []string{"TMP", "TEMP"} {
		if err := os.Setenv(key, physical); err != nil {
			fmt.Fprintln(os.Stderr, "set physical test temporary directory:", err)
			os.Exit(2)
		}
	}
	os.Exit(m.Run())
}

func physicalTestTempDirectory() (string, error) {
	root := os.TempDir()
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("temporary directory is not absolute")
	}
	physical, err := physicalTestPath(root)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(physical)
	if err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.IsDir() {
		return "", fmt.Errorf("temporary directory is not physical")
	}
	return physical, nil
}

// physicalTestPath returns the normalized final path of an existing file or
// directory: every short-name component expanded and every junction or
// symbolic link resolved, as reported by GetFinalPathNameByHandle.
func physicalTestPath(path string) (string, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, windows.MAX_PATH)
	for {
		// Flags 0 = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS: long names, drive letter.
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", fmt.Errorf("resolve final path of %q: %w", path, err)
		}
		if length < uint32(len(buffer)) {
			resolved := windows.UTF16ToString(buffer[:length])
			if strings.HasPrefix(resolved, `\\?\UNC\`) {
				resolved = `\\` + strings.TrimPrefix(resolved, `\\?\UNC\`)
			} else {
				resolved = strings.TrimPrefix(resolved, `\\?\`)
			}
			return filepath.Clean(resolved), nil
		}
		buffer = make([]uint16, int(length)+1)
	}
}
