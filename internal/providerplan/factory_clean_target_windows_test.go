//go:build windows

package providerplan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsFactoryCleanTargetDirectory struct {
	file      *os.File
	handle    windows.Handle
	path      string
	identity  providerInputStableFileIdentity
	ancestors []*os.File
	closed    bool
}

func createFactoryCleanTargetRoot(absolute string) (factoryCleanTargetDirectoryHandle, providerInputStableFileIdentity, error) {
	resolved, err := resolveFactoryOutputPath(absolute)
	if err != nil {
		return nil, providerInputStableFileIdentity{}, err
	}
	for _, component := range append(append([]string(nil), resolved.components...), resolved.leaf) {
		if err := validateFactoryCleanTargetComponent(component); err != nil {
			return nil, providerInputStableFileIdentity{}, err
		}
	}
	rootName, err := windowsNTPath(resolved.root)
	if err != nil {
		return nil, providerInputStableFileIdentity{}, err
	}
	rootHandle, err := openWindowsFactoryDirectory(0, rootName)
	if err != nil {
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("open clean target filesystem root %q without following reparse points: %w", resolved.root, err)
	}
	rootFile := os.NewFile(uintptr(rootHandle), resolved.root)
	if rootFile == nil {
		_ = windows.CloseHandle(rootHandle)
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("retain clean target filesystem root %q", resolved.root)
	}
	ancestors := []*os.File{rootFile}
	closeAncestors := func() {
		for index := len(ancestors) - 1; index >= 0; index-- {
			_ = ancestors[index].Close()
		}
	}
	parentHandle := rootHandle
	current := resolved.root
	for _, component := range resolved.components {
		handle, openErr := openWindowsFactoryDirectory(parentHandle, component)
		if openErr != nil {
			closeAncestors()
			return nil, providerInputStableFileIdentity{}, fmt.Errorf("open clean target parent component %q without following reparse points: %w", component, openErr)
		}
		current = filepath.Join(current, component)
		directory := os.NewFile(uintptr(handle), current)
		if directory == nil {
			_ = windows.CloseHandle(handle)
			closeAncestors()
			return nil, providerInputStableFileIdentity{}, fmt.Errorf("retain clean target parent component %q", current)
		}
		info, statErr := directory.Stat()
		if statErr != nil || !info.IsDir() || fileInfoHasReparsePoint(info) {
			_ = directory.Close()
			closeAncestors()
			if statErr != nil {
				return nil, providerInputStableFileIdentity{}, fmt.Errorf("inspect clean target parent %q: %w", current, statErr)
			}
			return nil, providerInputStableFileIdentity{}, fmt.Errorf("clean target parent %q is not a stable directory", current)
		}
		ancestors = append(ancestors, directory)
		parentHandle = handle
	}

	handle, err := createWindowsFactoryCleanTargetDirectory(parentHandle, resolved.leaf)
	if err != nil {
		closeAncestors()
		return nil, providerInputStableFileIdentity{}, err
	}
	directory := os.NewFile(uintptr(handle), absolute)
	if directory == nil {
		_ = windows.CloseHandle(handle)
		closeAncestors()
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("retain clean target root %q", absolute)
	}
	created, err := directory.Stat()
	if err != nil || !created.IsDir() || fileInfoHasReparsePoint(created) {
		_ = directory.Close()
		closeAncestors()
		if err != nil {
			return nil, providerInputStableFileIdentity{}, fmt.Errorf("inspect new clean target root %q: %w", absolute, err)
		}
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("new clean target root %q is not a stable directory", absolute)
	}
	identity, err := stableProviderInputFileIdentity(directory)
	if err != nil {
		_ = directory.Close()
		closeAncestors()
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("derive clean target root identity for %q: %w", absolute, err)
	}
	result := &windowsFactoryCleanTargetDirectory{
		file: directory, handle: handle, path: absolute, identity: identity, ancestors: ancestors,
	}
	if err := result.validate(); err != nil {
		_ = result.close()
		return nil, providerInputStableFileIdentity{}, err
	}
	return result, identity, nil
}

func (directory *windowsFactoryCleanTargetDirectory) createDirectory(component, displayPath string) (factoryCleanTargetDirectoryHandle, providerInputStableFileIdentity, error) {
	if directory == nil || directory.closed {
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("clean target parent handle is closed")
	}
	if err := validateFactoryCleanTargetComponent(component); err != nil {
		return nil, providerInputStableFileIdentity{}, err
	}
	handle, err := createWindowsFactoryCleanTargetDirectory(directory.handle, component)
	if err != nil {
		return nil, providerInputStableFileIdentity{}, err
	}
	file := os.NewFile(uintptr(handle), displayPath)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("retain new clean target directory %q", displayPath)
	}
	created, err := file.Stat()
	if err != nil || !created.IsDir() || fileInfoHasReparsePoint(created) {
		_ = file.Close()
		if err != nil {
			return nil, providerInputStableFileIdentity{}, fmt.Errorf("inspect new clean target directory %q: %w", displayPath, err)
		}
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("new clean target directory %q is not stable", displayPath)
	}
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		_ = file.Close()
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("derive new clean target directory identity for %q: %w", displayPath, err)
	}
	result := &windowsFactoryCleanTargetDirectory{file: file, handle: handle, path: displayPath, identity: identity}
	if err := result.validate(); err != nil {
		_ = result.close()
		return nil, providerInputStableFileIdentity{}, err
	}
	return result, identity, nil
}

func (directory *windowsFactoryCleanTargetDirectory) createFile(component, displayPath string, raw []byte, mode os.FileMode) (providerInputStableFileIdentity, error) {
	if directory == nil || directory.closed {
		return providerInputStableFileIdentity{}, fmt.Errorf("clean target parent handle is closed")
	}
	if err := validateFactoryCleanTargetComponent(component); err != nil {
		return providerInputStableFileIdentity{}, err
	}
	handle, err := createWindowsFactoryFile(directory.handle, component)
	if err != nil {
		return providerInputStableFileIdentity{}, err
	}
	file := os.NewFile(uintptr(handle), displayPath)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return providerInputStableFileIdentity{}, fmt.Errorf("retain new clean target file %q", displayPath)
	}
	return writeExactFactoryCleanTargetFile(file, displayPath, raw, mode)
}

func (directory *windowsFactoryCleanTargetDirectory) validate() error {
	if directory == nil || directory.closed {
		return fmt.Errorf("clean target directory handle is closed")
	}
	return validateFactoryCleanTargetDirectoryHandle(directory.path, directory.file, directory.identity)
}

func (directory *windowsFactoryCleanTargetDirectory) close() error {
	if directory == nil || directory.closed {
		return nil
	}
	directory.closed = true
	var closeErrors []error
	if err := directory.file.Close(); err != nil {
		closeErrors = append(closeErrors, err)
	}
	for index := len(directory.ancestors) - 1; index >= 0; index-- {
		if err := directory.ancestors[index].Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	return errors.Join(closeErrors...)
}

func createWindowsFactoryCleanTargetDirectory(parent windows.Handle, component string) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(component)
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
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE,
		attributes,
		&status,
		nil,
		windows.FILE_ATTRIBUTE_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_CREATE,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_WRITE_THROUGH,
		0,
		0,
	)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return handle, nil
}

func validateFactoryCleanTargetComponent(component string) error {
	if err := validateFactoryWindowsPathComponent(component); err != nil {
		return fmt.Errorf("clean target component: %w", err)
	}
	return nil
}
