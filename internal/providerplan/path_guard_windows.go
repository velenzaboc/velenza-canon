//go:build windows

package providerplan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type providerInputStableFileIdentity struct {
	volume uint64
	fileID [16]byte
}

type providerWindowsFileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type providerWindowsFileIDQuery func(windows.Handle, uint32, *byte, uint32) error

func stableProviderInputFileIdentity(file *os.File) (providerInputStableFileIdentity, error) {
	return stableProviderInputFileIdentityWithQuery(file, windows.GetFileInformationByHandleEx)
}

func stableProviderInputFileIdentityWithQuery(file *os.File, query providerWindowsFileIDQuery) (providerInputStableFileIdentity, error) {
	if file == nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("query 128-bit file identity from nil handle")
	}
	if query == nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("query 128-bit file identity without a query operation")
	}
	var data providerWindowsFileIDInfo
	if err := query(
		windows.Handle(file.Fd()),
		windows.FileIdInfo,
		(*byte)(unsafe.Pointer(&data)),
		uint32(unsafe.Sizeof(data)),
	); err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("query volume/128-bit file identity: %w", err)
	}
	return providerInputStableFileIdentity{volume: data.VolumeSerialNumber, fileID: data.FileID}, nil
}

func validateProviderInputPathSyntax(path, label string) error {
	volume := filepath.VolumeName(path)
	remainder := strings.TrimPrefix(path, volume)
	if strings.Contains(remainder, ":") {
		return fmt.Errorf("%s path %q contains Windows alternate-data-stream syntax", label, path)
	}
	return nil
}

func fileInfoHasReparsePoint(info os.FileInfo) bool {
	switch data := info.Sys().(type) {
	case *syscall.Win32FileAttributeData:
		return data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
	case *syscall.ByHandleFileInformation:
		return data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
	default:
		return false
	}
}

func canonicalProviderInputPathKey(path string) string {
	return strings.ToLower(filepath.Clean(path))
}
