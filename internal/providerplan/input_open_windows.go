//go:build windows

package providerplan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openProviderInputPathNoFollow(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolute = filepath.Clean(absolute)
	parent := filepath.Dir(absolute)
	leaf := filepath.Base(absolute)
	volume := filepath.VolumeName(parent)
	root := volume + string(filepath.Separator)
	if volume == "" {
		return nil, fmt.Errorf("input path %q has no absolute Windows volume", path)
	}
	remainder := strings.TrimPrefix(parent, root)
	if remainder == parent || leaf == "" || leaf == "." || leaf == ".." {
		return nil, fmt.Errorf("input path %q does not resolve below its Windows volume root", path)
	}
	components := []string{}
	if remainder != "" {
		components = strings.Split(remainder, string(filepath.Separator))
	}
	for _, component := range append(append([]string(nil), components...), leaf) {
		if err := validateFactoryWindowsPathComponent(component); err != nil {
			return nil, err
		}
	}
	rootName, err := windowsNTPath(root)
	if err != nil {
		return nil, err
	}
	parentHandle, err := openWindowsFactoryDirectory(0, rootName)
	if err != nil {
		return nil, err
	}
	current := root
	for _, component := range components {
		handle, openErr := openWindowsFactoryDirectory(parentHandle, component)
		_ = windows.CloseHandle(parentHandle)
		if openErr != nil {
			return nil, openErr
		}
		current = filepath.Join(current, component)
		if err := validateWindowsFactoryOpenedPath(handle, current); err != nil {
			_ = windows.CloseHandle(handle)
			return nil, err
		}
		parentHandle = handle
	}
	handle, err := openWindowsProviderInputFile(parentHandle, leaf)
	_ = windows.CloseHandle(parentHandle)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), absolute)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("retain input file handle for %q", path)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || fileInfoHasReparsePoint(info) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("input path %q is not a stable regular file", path)
	}
	return file, nil
}

func openWindowsProviderInputFile(parent windows.Handle, leaf string) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(leaf)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_GENERIC_READ|windows.SYNCHRONIZE,
		attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return handle, nil
}
