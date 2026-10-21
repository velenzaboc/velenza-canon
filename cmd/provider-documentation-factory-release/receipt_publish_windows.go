//go:build windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	releaseReceiptWindowsShareWrite         = 0x00000002
	releaseReceiptWindowsShareDelete        = 0x00000004
	releaseReceiptWindowsBackupSemantics    = 0x02000000
	releaseReceiptWindowsSynchronize        = 0x00100000
	releaseReceiptWindowsFileGenericRead    = 0x00120089
	releaseReceiptWindowsFileGenericWrite   = 0x00120116
	releaseReceiptWindowsFileListDirectory  = 0x00000001
	releaseReceiptWindowsFileTraverse       = 0x00000020
	releaseReceiptWindowsFileReadAttrs      = 0x00000080
	releaseReceiptWindowsFileOpen           = 1
	releaseReceiptWindowsFileCreate         = 2
	releaseReceiptWindowsDirectoryFile      = 0x00000001
	releaseReceiptWindowsWriteThrough       = 0x00000002
	releaseReceiptWindowsSynchronousIONA    = 0x00000020
	releaseReceiptWindowsNonDirectoryFile   = 0x00000040
	releaseReceiptWindowsObjCaseInsensitive = 0x00000040
	releaseReceiptWindowsObjDontReparse     = 0x00001000
)

var (
	releaseReceiptNTDLL                    = syscall.NewLazyDLL("ntdll.dll")
	releaseReceiptNtCreateFile             = releaseReceiptNTDLL.NewProc("NtCreateFile")
	releaseReceiptGetFinalPathNameByHandle = releaseKernel32.NewProc("GetFinalPathNameByHandleW")
)

type publishValidatedReceiptHooks struct {
	afterParentOpen    func() error
	beforeVisibleCheck func() error
}

type releaseReceiptWindowsPath struct {
	absolute   string
	root       string
	components []string
	leaf       string
}

type retainedReleaseReceiptWindowsDirectory struct {
	file     *os.File
	identity releaseWindowsFileIdentity
	expected string
}

type releaseReceiptUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type releaseReceiptObjectAttributes struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               *releaseReceiptUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type releaseReceiptIOStatusBlock struct {
	Status      uintptr
	Information uintptr
}

func publishValidatedReceipt(path string, raw []byte) error {
	return publishValidatedReceiptWithHooks(path, raw, publishValidatedReceiptHooks{})
}

func publishValidatedReceiptWithHooks(path string, raw []byte, hooks publishValidatedReceiptHooks) error {
	if len(raw) == 0 {
		return fmt.Errorf("validated receipt bytes are empty")
	}
	resolved, err := resolveReleaseReceiptWindowsPath(path)
	if err != nil {
		return err
	}

	parents, err := retainReleaseReceiptWindowsParents(resolved)
	if err != nil {
		return err
	}
	defer closeRetainedReleaseReceiptWindowsParents(parents)
	parent := parents[len(parents)-1].file
	if hooks.afterParentOpen != nil {
		if err := hooks.afterParentOpen(); err != nil {
			return fmt.Errorf("after validated receipt parent open: %w", err)
		}
	}

	handle, err := releaseReceiptNtOpenRelative(
		syscall.Handle(parent.Fd()),
		resolved.leaf,
		releaseReceiptWindowsFileGenericRead|releaseReceiptWindowsFileGenericWrite|releaseReceiptWindowsSynchronize,
		releaseWindowsFileShareRead|releaseReceiptWindowsShareDelete,
		releaseReceiptWindowsFileCreate,
		releaseReceiptWindowsNonDirectoryFile|releaseWindowsFileFlagOpenReparse|releaseReceiptWindowsSynchronousIONA|releaseReceiptWindowsWriteThrough,
	)
	if err != nil {
		return fmt.Errorf("create validated receipt exactly once at %q: %w", resolved.absolute, err)
	}
	file := os.NewFile(uintptr(handle), resolved.absolute)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return fmt.Errorf("retain validated receipt handle for %q", resolved.absolute)
	}
	defer file.Close()
	attributes, err := releaseWindowsAttributes(handle)
	if err != nil || attributes.FileAttributes&(releaseWindowsFileAttributeDir|releaseWindowsFileAttributeReparse) != 0 {
		return fmt.Errorf("created validated receipt %q is a directory or reparse point", resolved.absolute)
	}
	createdIdentity, err := releaseWindowsIdentity(handle)
	if err != nil {
		return fmt.Errorf("derive created validated receipt identity for %q: %w", resolved.absolute, err)
	}
	createdInfo, err := file.Stat()
	if err != nil || !createdInfo.Mode().IsRegular() {
		if err != nil {
			return fmt.Errorf("inspect created validated receipt %q: %w", resolved.absolute, err)
		}
		return fmt.Errorf("created validated receipt %q is not a regular file", resolved.absolute)
	}

	if err := writeReleaseReceiptBytes(file, raw); err != nil {
		return fmt.Errorf("write validated receipt %q: %w", resolved.absolute, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync validated receipt %q: %w", resolved.absolute, err)
	}
	if err := verifyReleaseReceiptBytes(file, raw); err != nil {
		return fmt.Errorf("read back validated receipt %q: %w", resolved.absolute, err)
	}
	if hooks.beforeVisibleCheck != nil {
		if err := hooks.beforeVisibleCheck(); err != nil {
			return fmt.Errorf("before validated receipt visible-path check: %w", err)
		}
	}

	visible, err := reopenVisibleReleaseReceiptWindowsPath(resolved, parents, createdIdentity)
	if err != nil {
		return err
	}
	defer visible.Close()
	retainedIdentity, err := releaseWindowsIdentity(handle)
	if err != nil || retainedIdentity != createdIdentity {
		return fmt.Errorf("retained validated receipt %q changed identity", resolved.absolute)
	}
	if err := verifyReleaseReceiptBytes(file, raw); err != nil {
		return fmt.Errorf("reverify retained validated receipt %q: %w", resolved.absolute, err)
	}
	if err := verifyReleaseReceiptBytes(visible, raw); err != nil {
		return fmt.Errorf("reverify caller-visible validated receipt %q: %w", resolved.absolute, err)
	}
	return nil
}

func resolveReleaseReceiptWindowsPath(path string) (releaseReceiptWindowsPath, error) {
	if path == "" || path != strings.TrimSpace(path) || strings.IndexByte(path, 0) >= 0 {
		return releaseReceiptWindowsPath{}, fmt.Errorf("validated receipt path is empty, padded, or contains NUL")
	}
	if strings.Contains(path, "/") {
		return releaseReceiptWindowsPath{}, fmt.Errorf("validated receipt path %q uses a non-canonical Windows separator", path)
	}
	for index := 0; index < len(path); index++ {
		if path[index] < 0x20 || path[index] >= 0x7f {
			return releaseReceiptWindowsPath{}, fmt.Errorf("validated receipt path %q contains a normalization-risk character", path)
		}
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return releaseReceiptWindowsPath{}, fmt.Errorf("validated receipt path %q is not an absolute canonical path", path)
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || !isReleaseReceiptASCIIAlpha(volume[0]) {
		return releaseReceiptWindowsPath{}, fmt.Errorf("validated receipt path %q does not use a canonical drive-letter volume", path)
	}
	root := volume + string(filepath.Separator)
	remainder := strings.TrimPrefix(path, root)
	if remainder == path || remainder == "" {
		return releaseReceiptWindowsPath{}, fmt.Errorf("validated receipt path %q does not name a file below its volume root", path)
	}
	components := strings.Split(remainder, string(filepath.Separator))
	for _, component := range components {
		if err := validateReleaseReceiptWindowsComponent(component); err != nil {
			return releaseReceiptWindowsPath{}, fmt.Errorf("validated receipt path %q: %w", path, err)
		}
	}
	return releaseReceiptWindowsPath{
		absolute:   path,
		root:       root,
		components: append([]string(nil), components[:len(components)-1]...),
		leaf:       components[len(components)-1],
	}, nil
}

func validateReleaseReceiptWindowsComponent(component string) error {
	if component == "" || component == "." || component == ".." || strings.ContainsAny(component, `<>:"/\|?*`) {
		return fmt.Errorf("path component %q is invalid or contains native alias syntax", component)
	}
	if strings.TrimRight(component, " .") != component {
		return fmt.Errorf("path component %q has a Windows-normalized trailing dot or space", component)
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
	for index := 0; index+1 < len(component); index++ {
		if component[index] == '~' && component[index+1] >= '0' && component[index+1] <= '9' {
			return fmt.Errorf("path component %q contains Windows short-name alias syntax", component)
		}
	}
	return nil
}

func retainReleaseReceiptWindowsParents(path releaseReceiptWindowsPath) ([]retainedReleaseReceiptWindowsDirectory, error) {
	pointer, err := syscall.UTF16PtrFromString(path.root)
	if err != nil {
		return nil, err
	}
	handleValue, _, callErr := releaseCreateFileW.Call(
		uintptr(unsafe.Pointer(pointer)),
		uintptr(releaseWindowsGenericRead),
		uintptr(releaseWindowsFileShareRead|releaseReceiptWindowsShareWrite|releaseReceiptWindowsShareDelete),
		0,
		uintptr(releaseWindowsOpenExisting),
		uintptr(releaseReceiptWindowsBackupSemantics|releaseWindowsFileFlagOpenReparse),
		0,
	)
	if handleValue == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("open validated receipt volume root %q without following reparse points: %w", path.root, callErr)
	}
	rootHandle := syscall.Handle(handleValue)
	rootFile := os.NewFile(handleValue, path.root)
	if rootFile == nil {
		_ = syscall.CloseHandle(rootHandle)
		return nil, fmt.Errorf("retain validated receipt volume root %q", path.root)
	}
	rootIdentity, err := validateReleaseReceiptWindowsDirectory(rootFile, path.root)
	if err != nil {
		_ = rootFile.Close()
		return nil, err
	}
	parents := []retainedReleaseReceiptWindowsDirectory{{file: rootFile, identity: rootIdentity, expected: path.root}}
	currentHandle := rootHandle
	currentPath := path.root
	for _, component := range path.components {
		handle, openErr := releaseReceiptNtOpenRelative(
			currentHandle,
			component,
			releaseReceiptWindowsFileListDirectory|releaseReceiptWindowsFileTraverse|releaseReceiptWindowsFileReadAttrs|releaseReceiptWindowsSynchronize,
			releaseWindowsFileShareRead|releaseReceiptWindowsShareWrite|releaseReceiptWindowsShareDelete,
			releaseReceiptWindowsFileOpen,
			releaseReceiptWindowsDirectoryFile|releaseWindowsFileFlagOpenReparse|releaseReceiptWindowsSynchronousIONA,
		)
		if openErr != nil {
			closeRetainedReleaseReceiptWindowsParents(parents)
			return nil, fmt.Errorf("open validated receipt parent component %q without following reparse points: %w", component, openErr)
		}
		currentPath = filepath.Join(currentPath, component)
		directory := os.NewFile(uintptr(handle), currentPath)
		if directory == nil {
			_ = syscall.CloseHandle(handle)
			closeRetainedReleaseReceiptWindowsParents(parents)
			return nil, fmt.Errorf("retain validated receipt parent component %q", currentPath)
		}
		identity, identityErr := validateReleaseReceiptWindowsDirectory(directory, currentPath)
		if identityErr != nil {
			_ = directory.Close()
			closeRetainedReleaseReceiptWindowsParents(parents)
			return nil, identityErr
		}
		parents = append(parents, retainedReleaseReceiptWindowsDirectory{file: directory, identity: identity, expected: currentPath})
		currentHandle = handle
	}
	return parents, nil
}

func reopenVisibleReleaseReceiptWindowsPath(path releaseReceiptWindowsPath, expected []retainedReleaseReceiptWindowsDirectory, created releaseWindowsFileIdentity) (*os.File, error) {
	actual, err := retainReleaseReceiptWindowsParents(path)
	if err != nil {
		return nil, fmt.Errorf("reopen caller-visible validated receipt parent path %q: %w", filepath.Dir(path.absolute), err)
	}
	defer closeRetainedReleaseReceiptWindowsParents(actual)
	if len(actual) != len(expected) {
		return nil, fmt.Errorf("caller-visible validated receipt parent path %q changed", filepath.Dir(path.absolute))
	}
	for index := range actual {
		if actual[index].identity != expected[index].identity {
			return nil, fmt.Errorf("caller-visible validated receipt parent path %q changed identity", filepath.Dir(path.absolute))
		}
	}
	parent := actual[len(actual)-1].file
	handle, err := releaseReceiptNtOpenRelative(
		syscall.Handle(parent.Fd()),
		path.leaf,
		releaseReceiptWindowsFileGenericRead|releaseReceiptWindowsSynchronize,
		releaseWindowsFileShareRead|releaseReceiptWindowsShareWrite|releaseReceiptWindowsShareDelete,
		releaseReceiptWindowsFileOpen,
		releaseReceiptWindowsNonDirectoryFile|releaseWindowsFileFlagOpenReparse|releaseReceiptWindowsSynchronousIONA,
	)
	if err != nil {
		return nil, fmt.Errorf("reopen caller-visible validated receipt %q without following reparse points: %w", path.absolute, err)
	}
	file := os.NewFile(uintptr(handle), path.absolute)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, fmt.Errorf("retain caller-visible validated receipt handle for %q", path.absolute)
	}
	attributes, attributeErr := releaseWindowsAttributes(handle)
	identity, identityErr := releaseWindowsIdentity(handle)
	info, statErr := file.Stat()
	aliasErr := validateReleaseReceiptWindowsOpenedPath(handle, path.absolute)
	if attributeErr != nil || identityErr != nil || statErr != nil || aliasErr != nil || attributes.FileAttributes&(releaseWindowsFileAttributeDir|releaseWindowsFileAttributeReparse) != 0 || identity != created || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("caller-visible validated receipt %q does not name the retained created identity", path.absolute)
	}
	return file, nil
}

func validateReleaseReceiptWindowsDirectory(file *os.File, expected string) (releaseWindowsFileIdentity, error) {
	handle := syscall.Handle(file.Fd())
	attributes, err := releaseWindowsAttributes(handle)
	if err != nil || attributes.FileAttributes&releaseWindowsFileAttributeDir == 0 || attributes.FileAttributes&releaseWindowsFileAttributeReparse != 0 {
		return releaseWindowsFileIdentity{}, fmt.Errorf("validated receipt parent %q is not a stable non-reparse directory", expected)
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		return releaseWindowsFileIdentity{}, fmt.Errorf("validated receipt parent %q is not a directory", expected)
	}
	if err := validateReleaseReceiptWindowsOpenedPath(handle, expected); err != nil {
		return releaseWindowsFileIdentity{}, err
	}
	identity, err := releaseWindowsIdentity(handle)
	if err != nil {
		return releaseWindowsFileIdentity{}, fmt.Errorf("derive validated receipt parent identity for %q: %w", expected, err)
	}
	return identity, nil
}

func validateReleaseReceiptWindowsOpenedPath(handle syscall.Handle, expected string) error {
	buffer := make([]uint16, 512)
	for {
		length, _, callErr := releaseReceiptGetFinalPathNameByHandle.Call(uintptr(handle), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0)
		if length == 0 {
			return fmt.Errorf("resolve retained validated receipt path %q: %w", expected, callErr)
		}
		if length < uintptr(len(buffer)) {
			resolved := syscall.UTF16ToString(buffer[:length])
			resolved = strings.TrimPrefix(resolved, `\\?\`)
			expected = strings.TrimPrefix(expected, `\\?\`)
			if !strings.EqualFold(filepath.Clean(resolved), filepath.Clean(expected)) {
				return fmt.Errorf("validated receipt path %q resolves through an alias to %q", expected, resolved)
			}
			return nil
		}
		buffer = make([]uint16, int(length)+1)
	}
}

func releaseReceiptNtOpenRelative(root syscall.Handle, name string, access, share, disposition, options uint32) (syscall.Handle, error) {
	encoded, err := syscall.UTF16FromString(name)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	nameLength := (len(encoded) - 1) * 2
	if nameLength > int(^uint16(0)) {
		return syscall.InvalidHandle, fmt.Errorf("validated receipt path component is too long")
	}
	unicode := releaseReceiptUnicodeString{
		Length:        uint16(nameLength),
		MaximumLength: uint16(len(encoded) * 2),
		Buffer:        &encoded[0],
	}
	attributes := releaseReceiptObjectAttributes{
		Length:        uint32(unsafe.Sizeof(releaseReceiptObjectAttributes{})),
		RootDirectory: root,
		ObjectName:    &unicode,
		Attributes:    releaseReceiptWindowsObjCaseInsensitive | releaseReceiptWindowsObjDontReparse,
	}
	var handle syscall.Handle
	var status releaseReceiptIOStatusBlock
	result, _, _ := releaseReceiptNtCreateFile.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(access),
		uintptr(unsafe.Pointer(&attributes)),
		uintptr(unsafe.Pointer(&status)),
		0,
		uintptr(releaseWindowsFileAttributeNormal),
		uintptr(share),
		uintptr(disposition),
		uintptr(options),
		0,
		0,
	)
	runtime.KeepAlive(encoded)
	runtime.KeepAlive(unicode)
	runtime.KeepAlive(attributes)
	runtime.KeepAlive(status)
	if uint32(result)&0x80000000 != 0 {
		return syscall.InvalidHandle, fmt.Errorf("NtCreateFile failed with status 0x%08x", uint32(result))
	}
	return handle, nil
}

func isReleaseReceiptASCIIAlpha(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func writeReleaseReceiptBytes(file *os.File, raw []byte) error {
	for written := 0; written < len(raw); {
		count, err := file.Write(raw[written:])
		if err != nil {
			return err
		}
		if count <= 0 {
			return io.ErrShortWrite
		}
		written += count
	}
	return nil
}

func verifyReleaseReceiptBytes(file *os.File, raw []byte) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	persisted, err := io.ReadAll(io.LimitReader(file, int64(len(raw))+1))
	if err != nil {
		return err
	}
	if !bytes.Equal(persisted, raw) {
		return fmt.Errorf("persisted bytes differ from the independently validated receipt")
	}
	return nil
}

func closeRetainedReleaseReceiptWindowsParents(parents []retainedReleaseReceiptWindowsDirectory) {
	for index := len(parents) - 1; index >= 0; index-- {
		_ = parents[index].file.Close()
	}
}
