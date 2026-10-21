//go:build windows

package providerplan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func validateFactoryWindowsPathComponent(component string) error {
	if component == "" || component == "." || component == ".." || strings.Contains(component, ":") {
		return fmt.Errorf("path component %q is invalid or contains alternate-data-stream syntax", component)
	}
	if strings.TrimRight(component, " .") != component {
		return fmt.Errorf("path component %q has a Windows-normalized trailing dot or space", component)
	}
	base := strings.ToUpper(strings.TrimRight(strings.SplitN(component, ".", 2)[0], " ."))
	reserved := map[string]struct{}{
		"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
		"CONIN$": {}, "CONOUT$": {},
		"COM¹": {}, "COM²": {}, "COM³": {},
		"LPT¹": {}, "LPT²": {}, "LPT³": {},
	}
	for index := 1; index <= 9; index++ {
		reserved[fmt.Sprintf("COM%d", index)] = struct{}{}
		reserved[fmt.Sprintf("LPT%d", index)] = struct{}{}
	}
	if _, forbidden := reserved[base]; forbidden {
		return fmt.Errorf("path component %q is a reserved Windows device name", component)
	}
	return nil
}

func validateFactoryOutputRawPath(path string) error {
	volume := filepath.VolumeName(path)
	remainder := strings.TrimPrefix(path, volume)
	for _, component := range strings.FieldsFunc(remainder, func(character rune) bool {
		return character == '\\' || character == '/'
	}) {
		if err := validateFactoryWindowsPathComponent(component); err != nil {
			return err
		}
	}
	return nil
}

func validateWindowsFactoryOpenedPath(handle windows.Handle, expected string) error {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return fmt.Errorf("resolve retained Windows path %q: %w", expected, err)
		}
		if length < uint32(len(buffer)) {
			resolved := windows.UTF16ToString(buffer[:length])
			resolved = strings.TrimPrefix(resolved, `\\?\`)
			expected = strings.TrimPrefix(expected, `\\?\`)
			if !strings.EqualFold(filepath.Clean(resolved), filepath.Clean(expected)) {
				return fmt.Errorf("Windows path %q resolves through an alias to %q", expected, resolved)
			}
			return nil
		}
		buffer = make([]uint16, int(length)+1)
	}
}

func openFactoryOutputDirectoryPathNoFollow(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolute = filepath.Clean(absolute)
	name, err := windowsNTPath(absolute)
	if err != nil {
		return nil, err
	}
	handle, err := openWindowsFactoryDirectory(0, name)
	if err != nil {
		return nil, err
	}
	if err := validateWindowsFactoryOpenedPath(handle, absolute); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	file := os.NewFile(uintptr(handle), absolute)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("retain --out directory identity handle for %q", absolute)
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() || factoryOutputFileInfoHasReparsePoint(info) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("--out directory %q is not a stable directory", absolute)
	}
	return file, nil
}
