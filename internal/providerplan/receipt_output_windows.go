//go:build windows

package providerplan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsFactoryOutput struct {
	file                 *os.File
	fileHandle           windows.Handle
	cleanupHandle        windows.Handle
	parents              []*os.File
	parentHandle         windows.Handle
	stageName            string
	finalName            string
	postRenameDurability func() error
	dataClosed           bool
	removed              bool
	released             bool
}

type windowsFileRenameInformation struct {
	replaceIfExists uint32
	rootDirectory   windows.Handle
	fileNameLength  uint32
	fileName        [1]uint16
}

const (
	windowsFileDispositionInformationSize = 1
	windowsFactoryFileCreateOptions       = windows.FILE_NON_DIRECTORY_FILE |
		windows.FILE_OPEN_REPARSE_POINT |
		windows.FILE_SYNCHRONOUS_IO_NONALERT |
		windows.FILE_WRITE_THROUGH
)

func createFactoryOutputExclusive(path factoryOutputPath, hooks factoryOutputTestHooks) (factoryOutputObject, []factoryOutputPathIdentity, error) {
	for _, component := range append(append([]string(nil), path.components...), path.leaf) {
		if err := validateFactoryWindowsPathComponent(component); err != nil {
			return nil, nil, fmt.Errorf("--out path %q: %w", path.absolute, err)
		}
	}

	rootName, err := windowsNTPath(path.root)
	if err != nil {
		return nil, nil, err
	}
	rootHandle, err := openWindowsFactoryDirectory(0, rootName)
	if err != nil {
		return nil, nil, fmt.Errorf("open --out filesystem root %q without following reparse points: %w", path.root, err)
	}
	rootFile := os.NewFile(uintptr(rootHandle), path.root)
	if rootFile == nil {
		_ = windows.CloseHandle(rootHandle)
		return nil, nil, fmt.Errorf("retain --out filesystem root %q", path.root)
	}
	rootInfo, err := rootFile.Stat()
	if err != nil || !rootInfo.IsDir() || factoryOutputFileInfoHasReparsePoint(rootInfo) {
		_ = rootFile.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("inspect --out filesystem root %q: %w", path.root, err)
		}
		return nil, nil, fmt.Errorf("--out filesystem root %q is not a stable directory", path.root)
	}
	rootIdentity, err := stableProviderInputFileIdentity(rootFile)
	if err != nil {
		_ = rootFile.Close()
		return nil, nil, fmt.Errorf("derive --out filesystem root identity %q: %w", path.root, err)
	}

	parents := []*os.File{rootFile}
	parentHandle := rootHandle
	current := path.root
	identities := []factoryOutputPathIdentity{{path: path.root, identity: rootIdentity}}
	closeParents := func() {
		for index := len(parents) - 1; index >= 0; index-- {
			_ = parents[index].Close()
		}
	}
	for _, component := range path.components {
		handle, openErr := openWindowsFactoryDirectory(parentHandle, component)
		if openErr != nil {
			closeParents()
			return nil, nil, fmt.Errorf("open --out parent component %q without following reparse points: %w", component, openErr)
		}
		current = filepath.Join(current, component)
		directory := os.NewFile(uintptr(handle), current)
		if directory == nil {
			_ = windows.CloseHandle(handle)
			closeParents()
			return nil, nil, fmt.Errorf("retain --out parent component %q", current)
		}
		info, statErr := directory.Stat()
		if statErr != nil || !info.IsDir() || factoryOutputFileInfoHasReparsePoint(info) {
			_ = directory.Close()
			closeParents()
			if statErr != nil {
				return nil, nil, fmt.Errorf("inspect retained --out parent %q: %w", current, statErr)
			}
			return nil, nil, fmt.Errorf("--out path %q has a non-directory or reparse parent %q", path.absolute, current)
		}
		if err := validateWindowsFactoryOpenedPath(handle, current); err != nil {
			_ = directory.Close()
			closeParents()
			return nil, nil, err
		}
		identity, identityErr := stableProviderInputFileIdentity(directory)
		if identityErr != nil {
			_ = directory.Close()
			closeParents()
			return nil, nil, fmt.Errorf("derive retained --out parent identity %q: %w", current, identityErr)
		}
		parents = append(parents, directory)
		identities = append(identities, factoryOutputPathIdentity{path: current, identity: identity})
		parentHandle = handle
	}

	if hooks.afterParentOpen != nil {
		if err := hooks.afterParentOpen(); err != nil {
			closeParents()
			return nil, nil, fmt.Errorf("after --out parent open test hook: %w", err)
		}
	}
	stageName, err := newFactoryOutputStagedName()
	if err != nil {
		closeParents()
		return nil, nil, err
	}
	createdHandle, err := createWindowsFactoryFile(parentHandle, stageName)
	if err != nil {
		closeParents()
		return nil, nil, err
	}
	cleanupHandle := windows.InvalidHandle
	if err := windows.DuplicateHandle(
		windows.CurrentProcess(),
		createdHandle,
		windows.CurrentProcess(),
		&cleanupHandle,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		_ = removeWindowsFactoryOutput(createdHandle)
		_ = windows.CloseHandle(createdHandle)
		closeParents()
		return nil, nil, fmt.Errorf("retain cleanup handle for staged --out target: %w", err)
	}
	file := os.NewFile(uintptr(createdHandle), filepath.Join(filepath.Dir(path.absolute), stageName))
	if file == nil {
		_ = removeWindowsFactoryOutput(cleanupHandle)
		_ = windows.CloseHandle(cleanupHandle)
		_ = windows.CloseHandle(createdHandle)
		closeParents()
		return nil, nil, fmt.Errorf("retain staged --out target handle")
	}
	createdInfo, statErr := file.Stat()
	if statErr != nil || !createdInfo.Mode().IsRegular() || factoryOutputFileInfoHasReparsePoint(createdInfo) {
		_ = removeWindowsFactoryOutput(cleanupHandle)
		_ = file.Close()
		_ = windows.CloseHandle(cleanupHandle)
		closeParents()
		if statErr != nil {
			return nil, nil, fmt.Errorf("inspect staged --out target handle: %w", statErr)
		}
		return nil, nil, fmt.Errorf("staged --out target is not a stable regular file")
	}
	postRenameDurability := func() error {
		return flushWindowsFactoryOutputAfterRename(createdHandle)
	}
	if hooks.windowsPostRenameDurability != nil {
		postRenameDurability = hooks.windowsPostRenameDurability
	}
	return &windowsFactoryOutput{
		file:                 file,
		fileHandle:           createdHandle,
		cleanupHandle:        cleanupHandle,
		parents:              parents,
		parentHandle:         parentHandle,
		stageName:            stageName,
		finalName:            path.leaf,
		postRenameDurability: postRenameDurability,
	}, identities, nil
}

func openWindowsFactoryDirectory(root windows.Handle, name string) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: root,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return handle, nil
}

func createWindowsFactoryFile(parent windows.Handle, leaf string) (windows.Handle, error) {
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
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE,
		attributes,
		&status,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ,
		windows.FILE_CREATE,
		windowsFactoryFileCreateOptions,
		0,
		0,
	)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return handle, nil
}

func renameWindowsFactoryOutput(handle windows.Handle, parent windows.Handle, finalName string) error {
	name, err := windows.UTF16FromString(finalName)
	if err != nil {
		return err
	}
	nameBytes := (len(name) - 1) * 2
	var layout windowsFileRenameInformation
	buffer := make([]byte, int(unsafe.Offsetof(layout.fileName))+nameBytes)
	info := (*windowsFileRenameInformation)(unsafe.Pointer(&buffer[0]))
	info.replaceIfExists = 0
	info.rootDirectory = parent
	info.fileNameLength = uint32(nameBytes)
	copy((*[windows.MAX_LONG_PATH]uint16)(unsafe.Pointer(&info.fileName[0]))[:nameBytes/2:nameBytes/2], name)
	var status windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(handle, &status, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation)
}

func windowsNTPath(path string) (string, error) {
	if strings.IndexByte(path, 0) >= 0 {
		return "", fmt.Errorf("--out filesystem root contains NUL")
	}
	if len(path) >= len(`\\?\UNC\`) && strings.EqualFold(path[:len(`\\?\UNC\`)], `\\?\UNC\`) {
		return `\??\UNC\` + path[len(`\\?\UNC\`):], nil
	}
	if strings.HasPrefix(path, `\\?\`) {
		return `\??\` + path[len(`\\?\`):], nil
	}
	if strings.HasPrefix(path, `\\`) {
		return `\??\UNC\` + strings.TrimPrefix(path, `\\`), nil
	}
	if filepath.VolumeName(path) == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("--out filesystem root %q is not an absolute Windows volume", path)
	}
	return `\??\` + path, nil
}

func (output *windowsFactoryOutput) dataFile() *os.File { return output.file }

func (output *windowsFactoryOutput) stagedName() string { return output.stageName }

func (output *windowsFactoryOutput) syncData() error { return output.file.Sync() }

func (output *windowsFactoryOutput) publish() error {
	if err := renameWindowsFactoryOutput(output.fileHandle, output.parentHandle, output.finalName); err != nil {
		return err
	}
	if err := output.postRenameDurability(); err != nil {
		return fmt.Errorf("flush renamed --out file and metadata: %w", err)
	}
	return nil
}

func flushWindowsFactoryOutputAfterRename(handle windows.Handle) error {
	return windows.FlushFileBuffers(handle)
}

func (output *windowsFactoryOutput) closeData() error {
	if output.dataClosed {
		return nil
	}
	output.dataClosed = true
	return output.file.Close()
}

func (output *windowsFactoryOutput) abort() error {
	if output.removed {
		return nil
	}
	if err := removeWindowsFactoryOutput(output.cleanupHandle); err != nil {
		return err
	}
	output.removed = true
	return nil
}

func removeWindowsFactoryOutput(handle windows.Handle) error {
	// NtSetInformationFile's FileDispositionInformation payload is exactly the
	// one-byte BOOLEAN ABI. A four-byte Win32 BOOL belongs to a different API.
	deleteFile := byte(1)
	var status windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(handle, &status, &deleteFile, windowsFileDispositionInformationSize, windows.FileDispositionInformation)
}

func (output *windowsFactoryOutput) release() error {
	if output.released {
		return nil
	}
	output.released = true
	var releaseErrors []error
	if err := output.closeData(); err != nil {
		releaseErrors = append(releaseErrors, err)
	}
	if output.cleanupHandle != windows.InvalidHandle {
		if err := windows.CloseHandle(output.cleanupHandle); err != nil {
			releaseErrors = append(releaseErrors, err)
		}
		output.cleanupHandle = windows.InvalidHandle
	}
	for index := len(output.parents) - 1; index >= 0; index-- {
		if err := output.parents[index].Close(); err != nil {
			releaseErrors = append(releaseErrors, err)
		}
	}
	return errors.Join(releaseErrors...)
}

func factoryOutputFileInfoHasReparsePoint(info os.FileInfo) bool {
	switch data := info.Sys().(type) {
	case *syscall.Win32FileAttributeData:
		return data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
	case *syscall.ByHandleFileInformation:
		return data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
	default:
		return false
	}
}
