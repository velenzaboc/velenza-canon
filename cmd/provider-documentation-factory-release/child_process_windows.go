//go:build windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	releaseWindowsGenericRead          = 0x80000000
	releaseWindowsGenericExecute       = 0x20000000
	releaseWindowsFileShareRead        = 0x00000001
	releaseWindowsOpenExisting         = 3
	releaseWindowsFileAttributeNormal  = 0x00000080
	releaseWindowsFileFlagOpenReparse  = 0x00200000
	releaseWindowsFileFlagSequential   = 0x08000000
	releaseWindowsFileAttributeDir     = 0x00000010
	releaseWindowsFileAttributeReparse = 0x00000400
	releaseWindowsFileIdInfo           = 18
	releaseWindowsFileAttributeTagInfo = 9
)

var (
	releaseKernel32                     = syscall.NewLazyDLL("kernel32.dll")
	releaseCreateFileW                  = releaseKernel32.NewProc("CreateFileW")
	releaseGetFileInformationByHandleEx = releaseKernel32.NewProc("GetFileInformationByHandleEx")
)

type releaseWindowsFileIdentity struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type releaseWindowsAttributeTag struct {
	FileAttributes uint32
	ReparseTag     uint32
}

type retainedChildWindowsPath struct {
	absolute   string
	root       string
	components []string
	leaf       string
}

type retainedChildWindowsDirectory struct {
	file     *os.File
	identity releaseWindowsFileIdentity
	expected string
}

type retainedChildExecutable struct {
	file        *os.File
	measurement measuredExecutable
	identity    releaseWindowsFileIdentity
	path        retainedChildWindowsPath
	parents     []retainedChildWindowsDirectory
}

func openRetainedChildExecutable(path string) (*retainedChildExecutable, error) {
	resolved, err := resolveRetainedChildWindowsPath(path)
	if err != nil {
		return nil, err
	}
	parents, err := retainChildWindowsParents(resolved)
	if err != nil {
		return nil, err
	}
	closeOnError := func(err error) (*retainedChildExecutable, error) {
		closeRetainedChildWindowsParents(parents)
		return nil, err
	}

	parent := parents[len(parents)-1].file
	handle, err := releaseReceiptNtOpenRelative(
		syscall.Handle(parent.Fd()),
		resolved.leaf,
		releaseWindowsGenericRead|releaseWindowsGenericExecute|releaseReceiptWindowsSynchronize,
		releaseWindowsFileShareRead,
		releaseReceiptWindowsFileOpen,
		releaseReceiptWindowsNonDirectoryFile|releaseWindowsFileFlagOpenReparse|releaseReceiptWindowsSynchronousIONA,
	)
	if err != nil {
		return closeOnError(fmt.Errorf("open retained factory child leaf without following reparse points: %w", err))
	}
	file := os.NewFile(uintptr(handle), resolved.absolute)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return closeOnError(fmt.Errorf("retain factory child handle"))
	}
	closeFileOnError := func(err error) (*retainedChildExecutable, error) {
		_ = file.Close()
		return closeOnError(err)
	}
	attributes, err := releaseWindowsAttributes(handle)
	if err != nil || attributes.FileAttributes&(releaseWindowsFileAttributeDir|releaseWindowsFileAttributeReparse) != 0 {
		return closeFileOnError(fmt.Errorf("built factory child is a directory or reparse point"))
	}
	if err := validateReleaseReceiptWindowsOpenedPath(handle, resolved.absolute); err != nil {
		return closeFileOnError(fmt.Errorf("built factory child path is not canonical: %w", err))
	}
	identity, err := releaseWindowsIdentity(handle)
	if err != nil {
		return closeFileOnError(err)
	}
	measurement, err := measureOpenExecutable(file, resolved.absolute)
	if err != nil {
		return closeFileOnError(err)
	}
	return &retainedChildExecutable{
		file:        file,
		measurement: measurement,
		identity:    identity,
		path:        resolved,
		parents:     parents,
	}, nil
}

func (child *retainedChildExecutable) command(args []string) (*exec.Cmd, error) {
	if err := child.verify(); err != nil {
		return nil, err
	}
	return exec.Command(child.measurement.path, args...), nil
}

func (child *retainedChildExecutable) verify() error {
	if child == nil || child.file == nil || len(child.parents) == 0 {
		return fmt.Errorf("retained factory child is closed")
	}
	for _, parent := range child.parents {
		identity, err := validateRetainedChildWindowsDirectory(parent.file, parent.expected)
		if err != nil || identity != parent.identity {
			return fmt.Errorf("retained factory child ancestor %q changed during execution", parent.expected)
		}
	}
	identity, err := releaseWindowsIdentity(syscall.Handle(child.file.Fd()))
	if err != nil || identity != child.identity {
		return fmt.Errorf("retained factory child identity changed during execution")
	}
	attributes, err := releaseWindowsAttributes(syscall.Handle(child.file.Fd()))
	if err != nil || attributes.FileAttributes&(releaseWindowsFileAttributeDir|releaseWindowsFileAttributeReparse) != 0 {
		return fmt.Errorf("retained factory child became a directory or reparse point")
	}
	if err := validateReleaseReceiptWindowsOpenedPath(syscall.Handle(child.file.Fd()), child.path.absolute); err != nil {
		return fmt.Errorf("retained factory child path changed during execution: %w", err)
	}
	actual, err := measureOpenExecutable(child.file, child.measurement.path)
	if err != nil || actual != child.measurement {
		return fmt.Errorf("retained factory child bytes changed during execution")
	}
	if err := child.verifyRelativeLeaf(); err != nil {
		return err
	}
	return nil
}

func (child *retainedChildExecutable) verifyRelativeLeaf() error {
	parent := child.parents[len(child.parents)-1].file
	handle, err := releaseReceiptNtOpenRelative(
		syscall.Handle(parent.Fd()),
		child.path.leaf,
		releaseWindowsGenericRead|releaseWindowsGenericExecute|releaseReceiptWindowsSynchronize,
		releaseWindowsFileShareRead,
		releaseReceiptWindowsFileOpen,
		releaseReceiptWindowsNonDirectoryFile|releaseWindowsFileFlagOpenReparse|releaseReceiptWindowsSynchronousIONA,
	)
	if err != nil {
		return fmt.Errorf("reopen retained factory child leaf through stable parent: %w", err)
	}
	file := os.NewFile(uintptr(handle), child.path.absolute)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return fmt.Errorf("retain reopened factory child leaf")
	}
	defer file.Close()
	attributes, attributeErr := releaseWindowsAttributes(handle)
	identity, identityErr := releaseWindowsIdentity(handle)
	pathErr := validateReleaseReceiptWindowsOpenedPath(handle, child.path.absolute)
	measurement, measurementErr := measureOpenExecutable(file, child.path.absolute)
	if attributeErr != nil || identityErr != nil || pathErr != nil || measurementErr != nil ||
		attributes.FileAttributes&(releaseWindowsFileAttributeDir|releaseWindowsFileAttributeReparse) != 0 ||
		identity != child.identity || measurement != child.measurement {
		return fmt.Errorf("factory child leaf no longer names the retained executable through its stable parent")
	}
	return nil
}

func (child *retainedChildExecutable) close() {
	if child == nil {
		return
	}
	if child.file != nil {
		_ = child.file.Close()
		child.file = nil
	}
	closeRetainedChildWindowsParents(child.parents)
	child.parents = nil
}

func resolveRetainedChildWindowsPath(path string) (retainedChildWindowsPath, error) {
	if path == "" || path != filepath.Clean(path) || !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
		return retainedChildWindowsPath{}, fmt.Errorf("built factory child path is not absolute and canonical")
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || !isReleaseReceiptASCIIAlpha(volume[0]) {
		return retainedChildWindowsPath{}, fmt.Errorf("built factory child path does not use a canonical drive-letter volume")
	}
	root := volume + string(filepath.Separator)
	remainder := strings.TrimPrefix(path, root)
	if remainder == path || remainder == "" {
		return retainedChildWindowsPath{}, fmt.Errorf("built factory child path does not name a file below its volume root")
	}
	components := strings.Split(remainder, string(filepath.Separator))
	for _, component := range components {
		if err := validateRetainedChildWindowsComponent(component); err != nil {
			return retainedChildWindowsPath{}, fmt.Errorf("built factory child path %q: %w", path, err)
		}
	}
	return retainedChildWindowsPath{
		absolute:   path,
		root:       root,
		components: append([]string(nil), components[:len(components)-1]...),
		leaf:       components[len(components)-1],
	}, nil
}

func validateRetainedChildWindowsComponent(component string) error {
	if component == "" || component == "." || component == ".." || strings.ContainsAny(component, `<>:"/\|?*`) {
		return fmt.Errorf("path component %q is invalid or contains native alias syntax", component)
	}
	if strings.TrimRight(component, " .") != component {
		return fmt.Errorf("path component %q has a Windows-normalized trailing dot or space", component)
	}
	for _, value := range component {
		if value < 0x20 {
			return fmt.Errorf("path component %q contains a control character", component)
		}
	}
	upperBase := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
	reserved := map[string]struct{}{
		"CON": {}, "PRN": {}, "AUX": {}, "NUL": {}, "CONIN$": {}, "CONOUT$": {},
	}
	for index := 1; index <= 9; index++ {
		reserved[fmt.Sprintf("COM%d", index)] = struct{}{}
		reserved[fmt.Sprintf("LPT%d", index)] = struct{}{}
	}
	if _, forbidden := reserved[upperBase]; forbidden {
		return fmt.Errorf("path component %q is a reserved Windows device name", component)
	}
	return nil
}

func retainChildWindowsParents(path retainedChildWindowsPath) ([]retainedChildWindowsDirectory, error) {
	pointer, err := syscall.UTF16PtrFromString(path.root)
	if err != nil {
		return nil, err
	}
	handleValue, _, callErr := releaseCreateFileW.Call(
		uintptr(unsafe.Pointer(pointer)),
		uintptr(releaseReceiptWindowsFileListDirectory|releaseReceiptWindowsFileTraverse|releaseReceiptWindowsFileReadAttrs|releaseReceiptWindowsSynchronize),
		uintptr(releaseWindowsFileShareRead|releaseReceiptWindowsShareWrite),
		0,
		uintptr(releaseWindowsOpenExisting),
		uintptr(releaseReceiptWindowsBackupSemantics|releaseWindowsFileFlagOpenReparse),
		0,
	)
	if handleValue == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("open factory child volume root %q without following reparse points: %w", path.root, callErr)
	}
	rootHandle := syscall.Handle(handleValue)
	rootFile := os.NewFile(handleValue, path.root)
	if rootFile == nil {
		_ = syscall.CloseHandle(rootHandle)
		return nil, fmt.Errorf("retain factory child volume root %q", path.root)
	}
	rootIdentity, err := validateRetainedChildWindowsDirectory(rootFile, path.root)
	if err != nil {
		_ = rootFile.Close()
		return nil, err
	}
	parents := []retainedChildWindowsDirectory{{file: rootFile, identity: rootIdentity, expected: path.root}}
	currentHandle := rootHandle
	currentPath := path.root
	for _, component := range path.components {
		handle, openErr := releaseReceiptNtOpenRelative(
			currentHandle,
			component,
			releaseReceiptWindowsFileListDirectory|releaseReceiptWindowsFileTraverse|releaseReceiptWindowsFileReadAttrs|releaseReceiptWindowsSynchronize,
			releaseWindowsFileShareRead|releaseReceiptWindowsShareWrite,
			releaseReceiptWindowsFileOpen,
			releaseReceiptWindowsDirectoryFile|releaseWindowsFileFlagOpenReparse|releaseReceiptWindowsSynchronousIONA,
		)
		if openErr != nil {
			closeRetainedChildWindowsParents(parents)
			return nil, fmt.Errorf("open factory child ancestor component %q without following reparse points: %w", component, openErr)
		}
		currentPath = filepath.Join(currentPath, component)
		directory := os.NewFile(uintptr(handle), currentPath)
		if directory == nil {
			_ = syscall.CloseHandle(handle)
			closeRetainedChildWindowsParents(parents)
			return nil, fmt.Errorf("retain factory child ancestor component %q", currentPath)
		}
		identity, identityErr := validateRetainedChildWindowsDirectory(directory, currentPath)
		if identityErr != nil {
			_ = directory.Close()
			closeRetainedChildWindowsParents(parents)
			return nil, identityErr
		}
		parents = append(parents, retainedChildWindowsDirectory{file: directory, identity: identity, expected: currentPath})
		currentHandle = handle
	}
	return parents, nil
}

func validateRetainedChildWindowsDirectory(file *os.File, expected string) (releaseWindowsFileIdentity, error) {
	handle := syscall.Handle(file.Fd())
	attributes, err := releaseWindowsAttributes(handle)
	if err != nil || attributes.FileAttributes&releaseWindowsFileAttributeDir == 0 || attributes.FileAttributes&releaseWindowsFileAttributeReparse != 0 {
		return releaseWindowsFileIdentity{}, fmt.Errorf("factory child ancestor %q is not a stable non-reparse directory", expected)
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		return releaseWindowsFileIdentity{}, fmt.Errorf("factory child ancestor %q is not a directory", expected)
	}
	if err := validateReleaseReceiptWindowsOpenedPath(handle, expected); err != nil {
		return releaseWindowsFileIdentity{}, fmt.Errorf("factory child ancestor path is not canonical: %w", err)
	}
	identity, err := releaseWindowsIdentity(handle)
	if err != nil {
		return releaseWindowsFileIdentity{}, fmt.Errorf("derive factory child ancestor identity for %q: %w", expected, err)
	}
	return identity, nil
}

func closeRetainedChildWindowsParents(parents []retainedChildWindowsDirectory) {
	for index := len(parents) - 1; index >= 0; index-- {
		_ = parents[index].file.Close()
	}
}

func readPrivateChildReceipt(path string) ([]byte, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, _, callErr := releaseCreateFileW.Call(
		uintptr(unsafe.Pointer(pointer)), uintptr(releaseWindowsGenericRead), uintptr(releaseWindowsFileShareRead), 0,
		uintptr(releaseWindowsOpenExisting), uintptr(releaseWindowsFileAttributeNormal|releaseWindowsFileFlagOpenReparse|releaseWindowsFileFlagSequential), 0,
	)
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("open private child receipt: %w", callErr)
	}
	file := os.NewFile(handle, path)
	if file == nil {
		_ = syscall.CloseHandle(syscall.Handle(handle))
		return nil, fmt.Errorf("retain private child receipt handle")
	}
	defer file.Close()
	attributes, err := releaseWindowsAttributes(syscall.Handle(handle))
	if err != nil || attributes.FileAttributes&(releaseWindowsFileAttributeDir|releaseWindowsFileAttributeReparse) != 0 {
		return nil, fmt.Errorf("private child receipt is a directory or reparse point")
	}
	identity, err := releaseWindowsIdentity(syscall.Handle(handle))
	if err != nil {
		return nil, err
	}
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maximumCommandOutput {
		return nil, fmt.Errorf("private child receipt is not a bounded regular file")
	}
	var output bytes.Buffer
	count, err := io.Copy(&output, io.LimitReader(file, maximumCommandOutput+1))
	if err != nil || count > maximumCommandOutput || count != before.Size() {
		return nil, fmt.Errorf("read bounded private child receipt")
	}
	after, err := file.Stat()
	finalIdentity, identityErr := releaseWindowsIdentity(syscall.Handle(handle))
	if err != nil || identityErr != nil || finalIdentity != identity || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("private child receipt changed while read")
	}
	pathIdentity, err := releaseWindowsPathIdentity(path)
	if err != nil || pathIdentity != identity {
		return nil, fmt.Errorf("private child receipt path changed while read")
	}
	return output.Bytes(), nil
}

func releaseWindowsPathIdentity(path string) (releaseWindowsFileIdentity, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return releaseWindowsFileIdentity{}, err
	}
	handle, _, callErr := releaseCreateFileW.Call(
		uintptr(unsafe.Pointer(pointer)), uintptr(releaseWindowsGenericRead), uintptr(releaseWindowsFileShareRead), 0,
		uintptr(releaseWindowsOpenExisting), uintptr(releaseWindowsFileAttributeNormal|releaseWindowsFileFlagOpenReparse), 0,
	)
	if handle == uintptr(syscall.InvalidHandle) {
		return releaseWindowsFileIdentity{}, fmt.Errorf("reopen private receipt path: %w", callErr)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))
	attributes, err := releaseWindowsAttributes(syscall.Handle(handle))
	if err != nil || attributes.FileAttributes&(releaseWindowsFileAttributeDir|releaseWindowsFileAttributeReparse) != 0 {
		return releaseWindowsFileIdentity{}, fmt.Errorf("private receipt path became a reparse point")
	}
	return releaseWindowsIdentity(syscall.Handle(handle))
}

func releaseWindowsIdentity(handle syscall.Handle) (releaseWindowsFileIdentity, error) {
	var identity releaseWindowsFileIdentity
	result, _, callErr := releaseGetFileInformationByHandleEx.Call(
		uintptr(handle), uintptr(releaseWindowsFileIdInfo), uintptr(unsafe.Pointer(&identity)), unsafe.Sizeof(identity),
	)
	if result == 0 {
		return releaseWindowsFileIdentity{}, fmt.Errorf("query retained factory child FILE_ID_INFO: %w", callErr)
	}
	return identity, nil
}

func releaseWindowsAttributes(handle syscall.Handle) (releaseWindowsAttributeTag, error) {
	var attributes releaseWindowsAttributeTag
	result, _, callErr := releaseGetFileInformationByHandleEx.Call(
		uintptr(handle), uintptr(releaseWindowsFileAttributeTagInfo), uintptr(unsafe.Pointer(&attributes)), unsafe.Sizeof(attributes),
	)
	if result == 0 {
		return releaseWindowsAttributeTag{}, fmt.Errorf("query retained factory child attributes: %w", callErr)
	}
	return attributes, nil
}
