//go:build windows

package providerplan

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type providerInputMutationToken struct {
	changeTime    int64
	lastWriteTime int64
}

type providerWindowsFileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

func currentProviderInputMutationToken(file *os.File) (providerInputMutationToken, error) {
	var info providerWindowsFileBasicInfo
	err := windows.GetFileInformationByHandleEx(
		windows.Handle(file.Fd()),
		windows.FileBasicInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		return providerInputMutationToken{}, err
	}
	return providerInputMutationToken{changeTime: info.ChangeTime, lastWriteTime: info.LastWriteTime}, nil
}
