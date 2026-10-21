//go:build windows

package providerplan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsSourcePackageOutputObject struct {
	file     *os.File
	handle   windows.Handle
	identity providerInputStableFileIdentity
	name     string
	parent   *windowsSourcePackageOutputDirectory
	raw      []byte
	removed  bool
	closed   bool
}

type windowsSourcePackageOutputDirectory struct {
	file     *os.File
	handle   windows.Handle
	identity providerInputStableFileIdentity
	relative string
	name     string
	parent   *windowsSourcePackageOutputDirectory
	removed  bool
	closed   bool
}

type windowsSourcePackageOutputStage struct {
	root          *windowsSourcePackageOutputDirectory
	parentHandles []*os.File
	parentHandle  windows.Handle
	stageName     string
	finalName     string
	absoluteStage string
	directories   map[string]*windowsSourcePackageOutputDirectory
	files         map[string]*windowsSourcePackageOutputObject
	published     bool
	privateMode   bool
	released      bool
}

type windowsSourcePackageValidationEntry struct {
	name      string
	relative  string
	directory bool
}

type windowsSourcePackageValidationHandle struct {
	file   *os.File
	handle windows.Handle
}

func validateSourcePackageOutputPathComponent(component string) error {
	return validateFactoryWindowsPathComponent(component)
}

func createSourcePackageOutputStage(resolved factoryOutputPath, hooks sourcePackageOutputHooks) (sourcePackageOutputStage, []factoryOutputPathIdentity, error) {
	for _, component := range append(append([]string(nil), resolved.components...), resolved.leaf) {
		if err := validateFactoryWindowsPathComponent(component); err != nil {
			return nil, nil, err
		}
	}
	rootName, err := windowsNTPath(resolved.root)
	if err != nil {
		return nil, nil, err
	}
	rootHandle, err := openWindowsSourcePackageParentDirectory(0, rootName, len(resolved.components) == 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open source-package filesystem root %q: %w", resolved.root, err)
	}
	rootFile := os.NewFile(uintptr(rootHandle), resolved.root)
	if rootFile == nil {
		_ = windows.CloseHandle(rootHandle)
		return nil, nil, fmt.Errorf("retain source-package filesystem root %q", resolved.root)
	}
	rootIdentity, err := stableProviderInputFileIdentity(rootFile)
	if err != nil {
		_ = rootFile.Close()
		return nil, nil, err
	}
	parents := []*os.File{rootFile}
	identities := []factoryOutputPathIdentity{{path: resolved.root, identity: rootIdentity}}
	parentHandle := rootHandle
	current := resolved.root
	closeParents := func() {
		for index := len(parents) - 1; index >= 0; index-- {
			_ = parents[index].Close()
		}
	}
	for index, component := range resolved.components {
		handle, openErr := openWindowsSourcePackageParentDirectory(parentHandle, component, index == len(resolved.components)-1)
		if openErr != nil {
			closeParents()
			return nil, nil, fmt.Errorf("open source-package output parent component %q: %w", component, openErr)
		}
		current = filepath.Join(current, component)
		directory := os.NewFile(uintptr(handle), current)
		if directory == nil {
			_ = windows.CloseHandle(handle)
			closeParents()
			return nil, nil, fmt.Errorf("retain source-package output parent %q", current)
		}
		info, statErr := directory.Stat()
		if statErr != nil || !info.IsDir() || fileInfoHasReparsePoint(info) {
			_ = directory.Close()
			closeParents()
			return nil, nil, fmt.Errorf("source-package output parent %q is not a stable directory", current)
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
			return nil, nil, identityErr
		}
		parents = append(parents, directory)
		identities = append(identities, factoryOutputPathIdentity{path: current, identity: identity})
		parentHandle = handle
	}
	if hooks.afterParentOpen != nil {
		if err := hooks.afterParentOpen(); err != nil {
			closeParents()
			return nil, nil, err
		}
	}
	stageName, err := newFactoryOutputStagedName()
	if err != nil {
		closeParents()
		return nil, nil, err
	}
	stageName += ".d"
	stageDirectory, err := createWindowsSourcePackageOutputDirectory(parentHandle, stageName, filepath.Join(filepath.Dir(resolved.absolute), stageName), "", nil)
	if err != nil {
		closeParents()
		return nil, nil, err
	}
	stage := &windowsSourcePackageOutputStage{
		root: stageDirectory, parentHandles: parents, parentHandle: parentHandle,
		stageName: stageName, finalName: resolved.leaf,
		absoluteStage: filepath.Join(filepath.Dir(resolved.absolute), stageName),
		directories:   map[string]*windowsSourcePackageOutputDirectory{"": stageDirectory},
		files:         make(map[string]*windowsSourcePackageOutputObject),
	}
	return stage, identities, nil
}

func openWindowsSourcePackageParentDirectory(root windows.Handle, name string, writable bool) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: root, ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	access := uint32(windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	if writable {
		access |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle, access, attributes, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0, 0,
	)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return handle, nil
}

func createWindowsSourcePackageOutputDirectory(parent windows.Handle, name, displayPath, relative string, parentDirectory *windowsSourcePackageOutputDirectory) (*windowsSourcePackageOutputDirectory, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE|windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.DELETE|windows.SYNCHRONIZE,
		attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_CREATE,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_WRITE_THROUGH,
		0, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("create exclusive source-package directory %q: %w", name, err)
	}
	file := os.NewFile(uintptr(handle), displayPath)
	if file == nil {
		_ = removeWindowsFactoryOutput(handle)
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("retain source-package directory %q", name)
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() || fileInfoHasReparsePoint(info) {
		_ = removeWindowsFactoryOutput(handle)
		_ = file.Close()
		return nil, fmt.Errorf("new source-package directory %q is not stable", name)
	}
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		_ = removeWindowsFactoryOutput(handle)
		_ = file.Close()
		return nil, err
	}
	return &windowsSourcePackageOutputDirectory{file: file, handle: handle, identity: identity, relative: relative, name: name, parent: parentDirectory}, nil
}

func (stage *windowsSourcePackageOutputStage) stagePath() string { return stage.absoluteStage }

func (stage *windowsSourcePackageOutputStage) writeFile(entry preparedSourcePackageOutputFile) error {
	parent := stage.root
	for index, component := range entry.components[:len(entry.components)-1] {
		relative := strings.Join(entry.components[:index+1], "/")
		key := strings.ToLower(relative)
		next := stage.directories[key]
		if next == nil {
			created, err := createWindowsSourcePackageOutputDirectory(parent.handle, component, filepath.Join(stage.absoluteStage, filepath.FromSlash(relative)), relative, parent)
			if err != nil {
				return err
			}
			stage.directories[key] = created
			next = created
		}
		parent = next
	}
	leaf := entry.components[len(entry.components)-1]
	handle, err := createWindowsSourcePackageOutputFile(parent.handle, leaf)
	if err != nil {
		return fmt.Errorf("create exclusive source-package file: %w", err)
	}
	file := os.NewFile(uintptr(handle), filepath.Join(stage.absoluteStage, filepath.FromSlash(entry.relative)))
	if file == nil {
		_ = removeWindowsFactoryOutput(handle)
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("retain source-package file handle")
	}
	identity, err := inspectNewSourcePackageOutputFile(file, entry.relative)
	if err != nil {
		_ = removeWindowsFactoryOutput(handle)
		_ = file.Close()
		return err
	}
	object := &windowsSourcePackageOutputObject{file: file, handle: handle, identity: identity, name: leaf, parent: parent, raw: entry.raw}
	stage.files[strings.ToLower(entry.relative)] = object
	writtenIdentity, err := writeExactSourcePackageOutputFile(file, entry.relative, entry.raw, identity, file.Sync)
	if err != nil {
		return err
	}
	object.identity = writtenIdentity
	return nil
}

func createWindowsSourcePackageOutputFile(parent windows.Handle, leaf string) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(leaf)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE,
		attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_CREATE, windowsFactoryFileCreateOptions, 0, 0,
	)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return handle, nil
}

func (stage *windowsSourcePackageOutputStage) seal(roster []preparedSourcePackageOutputFile) error {
	if len(stage.files) != len(roster) {
		return fmt.Errorf("source-package output tree has %d retained files, want %d", len(stage.files), len(roster))
	}
	for _, entry := range roster {
		object := stage.files[strings.ToLower(entry.relative)]
		if object == nil {
			return fmt.Errorf("source-package output tree omits %q", entry.relative)
		}
		if err := verifyExactSourcePackageOutputFile(object.file, entry.relative, entry.raw, object.identity); err != nil {
			return err
		}
	}
	if err := stage.validateClosedRoster(roster); err != nil {
		return err
	}
	directories := make([]*windowsSourcePackageOutputDirectory, 0, len(stage.directories))
	for _, directory := range stage.directories {
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(left, right int) bool { return len(directories[left].relative) > len(directories[right].relative) })
	for _, directory := range directories {
		identity, err := stableProviderInputFileIdentity(directory.file)
		if err != nil || identity != directory.identity {
			return fmt.Errorf("source-package directory %q changed identity", directory.relative)
		}
		if err := windows.FlushFileBuffers(directory.handle); err != nil {
			return fmt.Errorf("flush source-package directory %q: %w", directory.relative, err)
		}
	}
	return nil
}

func (stage *windowsSourcePackageOutputStage) validateClosedRoster(roster []preparedSourcePackageOutputFile) error {
	expected := make(map[string][]string, len(stage.directories))
	for _, entry := range roster {
		for index, component := range entry.components {
			parent := strings.ToLower(strings.Join(entry.components[:index], "/"))
			expected[parent] = append(expected[parent], component)
		}
	}
	for key, directory := range stage.directories {
		duplicate := windows.InvalidHandle
		if err := windows.DuplicateHandle(windows.CurrentProcess(), directory.handle, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return err
		}
		copyFile := os.NewFile(uintptr(duplicate), directory.relative)
		if copyFile == nil {
			_ = windows.CloseHandle(duplicate)
			return fmt.Errorf("retain source-package directory enumeration handle")
		}
		entries, err := copyFile.ReadDir(-1)
		_ = copyFile.Close()
		if err != nil {
			return fmt.Errorf("enumerate source-package directory %q: %w", directory.relative, err)
		}
		wantSet := make(map[string]struct{})
		for _, name := range expected[key] {
			wantSet[strings.ToLower(name)] = struct{}{}
		}
		if len(entries) != len(wantSet) {
			return fmt.Errorf("source-package directory %q contains %d entries, want %d", directory.relative, len(entries), len(wantSet))
		}
		for _, entry := range entries {
			if _, ok := wantSet[strings.ToLower(entry.Name())]; !ok {
				return fmt.Errorf("source-package directory %q contains undeclared entry %q", directory.relative, entry.Name())
			}
			if info, infoErr := entry.Info(); infoErr != nil || fileInfoHasReparsePoint(info) {
				return fmt.Errorf("source-package entry %q is unreadable or a reparse point", entry.Name())
			}
		}
	}
	return nil
}

func (stage *windowsSourcePackageOutputStage) publish() error {
	if err := renameWindowsFactoryOutput(stage.root.handle, stage.parentHandle, stage.finalName); err != nil {
		return err
	}
	stage.published = true
	if err := windows.FlushFileBuffers(stage.root.handle); err != nil {
		return fmt.Errorf("flush published source-package root: %w", err)
	}
	return nil
}

func (stage *windowsSourcePackageOutputStage) preparePublish() error {
	var closeErrors []error
	for _, object := range stage.files {
		if object.closed {
			continue
		}
		if err := object.file.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		} else {
			object.closed = true
		}
	}
	directories := make([]*windowsSourcePackageOutputDirectory, 0, len(stage.directories)-1)
	for _, directory := range stage.directories {
		if directory == stage.root {
			continue
		}
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(left, right int) bool { return len(directories[left].relative) > len(directories[right].relative) })
	for _, directory := range directories {
		if directory.closed {
			continue
		}
		if err := directory.file.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		} else {
			directory.closed = true
		}
	}
	return errors.Join(closeErrors...)
}

func (stage *windowsSourcePackageOutputStage) validatePrepared(roster []preparedSourcePackageOutputFile) error {
	return stage.validateClosedTreeFromRetainedRoot(roster)
}

func (stage *windowsSourcePackageOutputStage) validatePrivateRoot() error {
	handle, err := openWindowsFactoryDirectory(stage.parentHandle, stage.stageName)
	if err != nil {
		return fmt.Errorf("open private factory source-output root by retained name: %w", err)
	}
	file := os.NewFile(uintptr(handle), stage.stageName)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("retain private factory source-output root identity handle")
	}
	identity, identityErr := stableProviderInputFileIdentity(file)
	info, statErr := file.Stat()
	closeErr := file.Close()
	if identityErr != nil || statErr != nil || closeErr != nil || !info.IsDir() || fileInfoHasReparsePoint(info) || identity != stage.root.identity {
		return fmt.Errorf("private factory source-output root changed path identity")
	}
	return nil
}

func (stage *windowsSourcePackageOutputStage) preparePrivateCallback() error {
	type replacement struct {
		file   *os.File
		handle windows.Handle
	}
	directoryReplacements := make(map[*windowsSourcePackageOutputDirectory]replacement, len(stage.directories))
	fileReplacements := make(map[*windowsSourcePackageOutputObject]replacement, len(stage.files))
	rootHandle, err := openWindowsSourcePackagePrivateCallbackObject(stage.parentHandle, stage.stageName, true)
	if err != nil {
		return err
	}
	rootFile := os.NewFile(uintptr(rootHandle), stage.stageName)
	if rootFile == nil {
		_ = windows.CloseHandle(rootHandle)
		return fmt.Errorf("retain callback-compatible private source-output root handle")
	}
	rootIdentity, err := stableProviderInputFileIdentity(rootFile)
	if err != nil || rootIdentity != stage.root.identity {
		_ = rootFile.Close()
		return fmt.Errorf("private source-output root changed identity while preparing callback access")
	}
	directoryReplacements[stage.root] = replacement{file: rootFile, handle: rootHandle}
	directories := make([]*windowsSourcePackageOutputDirectory, 0, len(stage.directories)-1)
	for _, directory := range stage.directories {
		if directory != stage.root {
			directories = append(directories, directory)
		}
	}
	sort.Slice(directories, func(left, right int) bool {
		leftDepth := strings.Count(directories[left].relative, "/")
		rightDepth := strings.Count(directories[right].relative, "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return directories[left].relative < directories[right].relative
	})
	closeReplacements := func() {
		for _, object := range fileReplacements {
			_ = object.file.Close()
		}
		for _, directory := range directoryReplacements {
			_ = directory.file.Close()
		}
	}
	for _, directory := range directories {
		parent := directoryReplacements[directory.parent]
		handle, openErr := openWindowsSourcePackagePrivateCallbackObject(parent.handle, directory.name, true)
		if openErr != nil {
			closeReplacements()
			return openErr
		}
		file := os.NewFile(uintptr(handle), directory.relative)
		if file == nil {
			_ = windows.CloseHandle(handle)
			closeReplacements()
			return fmt.Errorf("retain callback-compatible private directory %q", directory.relative)
		}
		identity, identityErr := stableProviderInputFileIdentity(file)
		if identityErr != nil || identity != directory.identity {
			_ = file.Close()
			closeReplacements()
			return fmt.Errorf("private directory %q changed identity while preparing callback access", directory.relative)
		}
		directoryReplacements[directory] = replacement{file: file, handle: handle}
	}
	for _, object := range stage.files {
		parent := directoryReplacements[object.parent]
		handle, openErr := openWindowsSourcePackagePrivateCallbackObject(parent.handle, object.name, false)
		if openErr != nil {
			closeReplacements()
			return openErr
		}
		file := os.NewFile(uintptr(handle), object.name)
		if file == nil {
			_ = windows.CloseHandle(handle)
			closeReplacements()
			return fmt.Errorf("retain callback-compatible private file %q", object.name)
		}
		identity, identityErr := stableProviderInputFileIdentity(file)
		if identityErr != nil || identity != object.identity {
			_ = file.Close()
			closeReplacements()
			return fmt.Errorf("private file %q changed identity while preparing callback access", object.name)
		}
		fileReplacements[object] = replacement{file: file, handle: handle}
	}
	var closeErrors []error
	for object, replacement := range fileReplacements {
		if err := object.file.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
		object.file = replacement.file
		object.handle = replacement.handle
	}
	for _, directory := range append(directories, stage.root) {
		replacement := directoryReplacements[directory]
		if err := directory.file.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
		directory.file = replacement.file
		directory.handle = replacement.handle
	}
	stage.privateMode = true
	return errors.Join(closeErrors...)
}

func openWindowsSourcePackagePrivateCallbackObject(parent windows.Handle, name string, directory bool) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if directory {
		access |= windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		access |= windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, attributes, &status, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, options, 0, 0)
	return handle, err
}

func (stage *windowsSourcePackageOutputStage) validatePublished(roster []preparedSourcePackageOutputFile) error {
	identity, err := stableProviderInputFileIdentity(stage.root.file)
	if err != nil || identity != stage.root.identity {
		return fmt.Errorf("published source-package root changed retained identity: %w", err)
	}
	handle, err := openWindowsFactoryDirectory(stage.parentHandle, stage.finalName)
	if err != nil {
		return fmt.Errorf("open published source-package root by final name: %w", err)
	}
	file := os.NewFile(uintptr(handle), stage.finalName)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("retain published source-package root identity handle")
	}
	got, identityErr := stableProviderInputFileIdentity(file)
	info, statErr := file.Stat()
	closeErr := file.Close()
	if identityErr != nil || statErr != nil || closeErr != nil || !info.IsDir() || fileInfoHasReparsePoint(info) || got != stage.root.identity {
		return fmt.Errorf("published source-package root changed path identity")
	}
	return stage.validateClosedTreeFromRetainedRoot(roster)
}

func (stage *windowsSourcePackageOutputStage) validateClosedTreeFromRetainedRoot(roster []preparedSourcePackageOutputFile) error {
	rootIdentity, err := stableProviderInputFileIdentity(stage.root.file)
	if err != nil || rootIdentity != stage.root.identity {
		return fmt.Errorf("source-package root changed retained identity after descendant handles closed: %w", err)
	}
	expected := make(map[string]map[string]windowsSourcePackageValidationEntry)
	for _, rosterEntry := range roster {
		for index, component := range rosterEntry.components {
			parentRelative := strings.Join(rosterEntry.components[:index], "/")
			parentKey := strings.ToLower(parentRelative)
			children := expected[parentKey]
			if children == nil {
				children = make(map[string]windowsSourcePackageValidationEntry)
				expected[parentKey] = children
			}
			relative := strings.Join(rosterEntry.components[:index+1], "/")
			entry := windowsSourcePackageValidationEntry{name: component, relative: relative, directory: index < len(rosterEntry.components)-1}
			key := strings.ToLower(component)
			if prior, ok := children[key]; ok && prior != entry {
				return fmt.Errorf("source-package roster has inconsistent child projection %q", relative)
			}
			children[key] = entry
		}
	}
	directoryKeys := make([]string, 0, len(expected))
	for key := range expected {
		directoryKeys = append(directoryKeys, key)
	}
	sort.Slice(directoryKeys, func(left, right int) bool {
		leftDepth := strings.Count(directoryKeys[left], "/")
		rightDepth := strings.Count(directoryKeys[right], "/")
		if directoryKeys[left] == "" {
			leftDepth = -1
		}
		if directoryKeys[right] == "" {
			rightDepth = -1
		}
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return directoryKeys[left] < directoryKeys[right]
	})
	openedDirectories := map[string]windowsSourcePackageValidationHandle{
		"": {file: stage.root.file, handle: stage.root.handle},
	}
	var opened []windowsSourcePackageValidationHandle
	closeOpened := func(cause error) error {
		joined := []error{cause}
		for index := len(opened) - 1; index >= 0; index-- {
			if closeErr := opened[index].file.Close(); closeErr != nil {
				joined = append(joined, closeErr)
			}
		}
		return errors.Join(joined...)
	}
	for _, directoryKey := range directoryKeys {
		current, ok := openedDirectories[directoryKey]
		if !ok {
			return closeOpened(fmt.Errorf("source-package tree omits retained directory %q", directoryKey))
		}
		children := expected[directoryKey]
		entries, enumerateErr := readWindowsSourcePackageDirectoryEntries(current.handle, directoryKey)
		if enumerateErr != nil {
			return closeOpened(enumerateErr)
		}
		if len(entries) != len(children) {
			return closeOpened(fmt.Errorf("source-package directory %q contains %d entries after descendant handles closed, want %d", directoryKey, len(entries), len(children)))
		}
		observed := make(map[string]os.DirEntry, len(entries))
		for _, entry := range entries {
			key := strings.ToLower(entry.Name())
			declaration, declared := children[key]
			if !declared || declaration.name != entry.Name() {
				return closeOpened(fmt.Errorf("source-package directory %q contains undeclared or case-changed entry %q", directoryKey, entry.Name()))
			}
			info, infoErr := entry.Info()
			if infoErr != nil || fileInfoHasReparsePoint(info) {
				return closeOpened(fmt.Errorf("source-package entry %q is unreadable or a reparse point after descendant handles closed", declaration.relative))
			}
			observed[key] = entry
		}
		childKeys := make([]string, 0, len(children))
		for key := range children {
			childKeys = append(childKeys, key)
		}
		sort.Strings(childKeys)
		for _, childKey := range childKeys {
			declaration := children[childKey]
			entry := observed[childKey]
			if entry == nil {
				return closeOpened(fmt.Errorf("source-package directory %q omits declared entry %q", directoryKey, declaration.name))
			}
			if declaration.directory {
				record := stage.directories[strings.ToLower(declaration.relative)]
				if record == nil {
					return closeOpened(fmt.Errorf("source-package retained-directory ledger omits %q", declaration.relative))
				}
				handle, openErr := openWindowsSourcePackageValidationObject(current.handle, declaration.name, true, stage.privateMode)
				if openErr != nil {
					return closeOpened(fmt.Errorf("open source-package directory %q without following reparse points: %w", declaration.relative, openErr))
				}
				file := os.NewFile(uintptr(handle), declaration.relative)
				if file == nil {
					_ = windows.CloseHandle(handle)
					return closeOpened(fmt.Errorf("retain source-package validation directory %q", declaration.relative))
				}
				identity, identityErr := stableProviderInputFileIdentity(file)
				info, statErr := file.Stat()
				if identityErr != nil || statErr != nil || !info.IsDir() || fileInfoHasReparsePoint(info) || identity != record.identity {
					_ = file.Close()
					return closeOpened(fmt.Errorf("source-package directory %q changed identity, kind, or became a reparse point", declaration.relative))
				}
				validationHandle := windowsSourcePackageValidationHandle{file: file, handle: handle}
				openedDirectories[strings.ToLower(declaration.relative)] = validationHandle
				opened = append(opened, validationHandle)
				continue
			}
			record := stage.files[strings.ToLower(declaration.relative)]
			if record == nil {
				return closeOpened(fmt.Errorf("source-package retained-file ledger omits %q", declaration.relative))
			}
			handle, openErr := openWindowsSourcePackageValidationObject(current.handle, declaration.name, false, stage.privateMode)
			if openErr != nil {
				return closeOpened(fmt.Errorf("open source-package file %q without following reparse points: %w", declaration.relative, openErr))
			}
			file := os.NewFile(uintptr(handle), declaration.relative)
			if file == nil {
				_ = windows.CloseHandle(handle)
				return closeOpened(fmt.Errorf("retain source-package validation file %q", declaration.relative))
			}
			identity, identityErr := stableProviderInputFileIdentity(file)
			info, statErr := file.Stat()
			if identityErr != nil || statErr != nil || !info.Mode().IsRegular() || fileInfoHasReparsePoint(info) || identity != record.identity || info.Size() != int64(len(record.raw)) {
				_ = file.Close()
				return closeOpened(fmt.Errorf("source-package file %q changed identity, kind, size, or became a reparse point", declaration.relative))
			}
			persisted, readErr := io.ReadAll(io.LimitReader(file, int64(len(record.raw))+1))
			if readErr != nil || !bytes.Equal(persisted, record.raw) {
				_ = file.Close()
				return closeOpened(fmt.Errorf("source-package file %q differs from declared bytes after descendant handles closed", declaration.relative))
			}
			validationHandle := windowsSourcePackageValidationHandle{file: file, handle: handle}
			opened = append(opened, validationHandle)
		}
	}
	return closeOpened(nil)
}

func readWindowsSourcePackageDirectoryEntries(handle windows.Handle, relative string) ([]os.DirEntry, error) {
	duplicate := windows.InvalidHandle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), handle, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), relative)
	if file == nil {
		_ = windows.CloseHandle(duplicate)
		return nil, fmt.Errorf("retain source-package directory enumeration handle")
	}
	entries, err := file.ReadDir(-1)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	return entries, nil
}

func openWindowsSourcePackageValidationObject(parent windows.Handle, name string, directory bool, shareWrite bool) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if directory {
		access |= windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		access |= windows.FILE_GENERIC_READ
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_DELETE)
	if shareWrite {
		share |= windows.FILE_SHARE_WRITE
	}
	err = windows.NtCreateFile(&handle, access, attributes, &status, nil, 0, share, windows.FILE_OPEN, options, 0, 0)
	return handle, err
}

func (stage *windowsSourcePackageOutputStage) abort() error {
	if stage.privateMode {
		return stage.abortPrivateCallbackTree()
	}
	var abortErrors []error
	closedTree := false
	for _, object := range stage.files {
		if object.closed {
			closedTree = true
			continue
		}
		if object.removed {
			continue
		}
		if err := removeWindowsFactoryOutput(object.handle); err != nil {
			abortErrors = append(abortErrors, err)
		} else {
			object.removed = true
		}
		if err := object.file.Close(); err != nil {
			abortErrors = append(abortErrors, err)
		} else {
			object.closed = true
		}
	}
	if closedTree {
		if err := stage.abortClosedTree(); err != nil {
			abortErrors = append(abortErrors, err)
		}
		return errors.Join(abortErrors...)
	}
	directories := make([]*windowsSourcePackageOutputDirectory, 0, len(stage.directories))
	for _, directory := range stage.directories {
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(left, right int) bool { return len(directories[left].relative) > len(directories[right].relative) })
	for _, directory := range directories {
		if directory.removed {
			continue
		}
		if err := removeWindowsFactoryOutput(directory.handle); err != nil {
			abortErrors = append(abortErrors, err)
		} else {
			directory.removed = true
		}
		if err := directory.file.Close(); err != nil {
			abortErrors = append(abortErrors, err)
		} else {
			directory.closed = true
		}
	}
	return errors.Join(abortErrors...)
}

func (stage *windowsSourcePackageOutputStage) abortPrivateCallbackTree() error {
	var cleanupErrors []error
	for _, object := range stage.files {
		if object.closed {
			continue
		}
		if err := object.file.Truncate(0); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("erase retained private source-output file %q: %w", object.name, err))
		} else if err := object.file.Sync(); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("sync erased private source-output file %q: %w", object.name, err))
		}
		if err := object.file.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		} else {
			object.closed = true
		}
	}
	directories := make([]*windowsSourcePackageOutputDirectory, 0, len(stage.directories)-1)
	for _, directory := range stage.directories {
		if directory != stage.root {
			directories = append(directories, directory)
		}
	}
	sort.Slice(directories, func(left, right int) bool { return len(directories[left].relative) > len(directories[right].relative) })
	for _, directory := range directories {
		if directory.closed {
			continue
		}
		if err := directory.file.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		} else {
			directory.closed = true
		}
	}
	if err := stage.abortClosedTree(); err != nil {
		cleanupErrors = append(cleanupErrors, err)
	}
	return errors.Join(cleanupErrors...)
}

func (stage *windowsSourcePackageOutputStage) abortClosedTree() error {
	openedDirectories := map[string]*os.File{"": stage.root.file}
	directoryHandles := map[string]windows.Handle{"": stage.root.handle}
	directories := make([]*windowsSourcePackageOutputDirectory, 0, len(stage.directories)-1)
	for _, directory := range stage.directories {
		if directory != stage.root {
			directories = append(directories, directory)
		}
	}
	sort.Slice(directories, func(left, right int) bool {
		leftDepth := strings.Count(directories[left].relative, "/")
		rightDepth := strings.Count(directories[right].relative, "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return directories[left].relative < directories[right].relative
	})
	for _, directory := range directories {
		parentKey := ""
		if directory.parent != nil {
			parentKey = strings.ToLower(directory.parent.relative)
		}
		parentHandle, ok := directoryHandles[parentKey]
		if !ok {
			continue
		}
		handle, err := openWindowsSourcePackageCleanupDirectory(parentHandle, directory.name)
		if err != nil {
			continue
		}
		file := os.NewFile(uintptr(handle), directory.relative)
		if file == nil {
			_ = windows.CloseHandle(handle)
			continue
		}
		identity, identityErr := stableProviderInputFileIdentity(file)
		if identityErr != nil || identity != directory.identity {
			_ = file.Close()
			continue
		}
		key := strings.ToLower(directory.relative)
		openedDirectories[key] = file
		directoryHandles[key] = handle
	}
	var cleanupErrors []error
	for _, object := range stage.files {
		if !object.closed {
			continue
		}
		parentKey := strings.ToLower(object.parent.relative)
		parentHandle, ok := directoryHandles[parentKey]
		if !ok {
			continue
		}
		handle, err := openWindowsSourcePackageCleanupFile(parentHandle, object.name)
		if err != nil {
			continue
		}
		file := os.NewFile(uintptr(handle), object.name)
		if file == nil {
			_ = windows.CloseHandle(handle)
			continue
		}
		identity, identityErr := stableProviderInputFileIdentity(file)
		if identityErr == nil && identity == object.identity {
			if err := file.Truncate(0); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			}
			if err := removeWindowsFactoryOutput(handle); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			}
		}
		if err := file.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	sort.Slice(directories, func(left, right int) bool { return len(directories[left].relative) > len(directories[right].relative) })
	for _, directory := range directories {
		key := strings.ToLower(directory.relative)
		file := openedDirectories[key]
		if file == nil {
			continue
		}
		handle := directoryHandles[key]
		if err := removeWindowsFactoryOutput(handle); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
		if err := file.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
		directory.removed = true
		directory.closed = true
	}
	if stage.privateMode {
		cleanupHandle, cleanupErr := openWindowsSourcePackageCleanupDirectory(stage.parentHandle, stage.stageName)
		cleanupMatches := false
		var cleanupFile *os.File
		if cleanupErr == nil {
			cleanupFile = os.NewFile(uintptr(cleanupHandle), stage.stageName)
			if cleanupFile == nil {
				_ = windows.CloseHandle(cleanupHandle)
				cleanupErr = fmt.Errorf("retain private source-output root cleanup handle")
			} else {
				identity, identityErr := stableProviderInputFileIdentity(cleanupFile)
				cleanupMatches = identityErr == nil && identity == stage.root.identity
				if !cleanupMatches && identityErr != nil {
					cleanupErr = identityErr
				}
				if !cleanupMatches {
					_ = cleanupFile.Close()
				}
			}
		}
		if !stage.root.closed {
			if err := stage.root.file.Close(); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			} else {
				stage.root.closed = true
			}
		}
		if cleanupMatches {
			if err := removeWindowsFactoryOutput(cleanupHandle); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			}
			if err := cleanupFile.Close(); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			}
			stage.root.removed = true
		} else {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("private source-output root cleanup refused a missing or substituted path: %w", cleanupErr))
		}
	} else if err := removeWindowsFactoryOutput(stage.root.handle); err != nil {
		cleanupErrors = append(cleanupErrors, err)
	} else {
		stage.root.removed = true
	}
	return errors.Join(cleanupErrors...)
}

func openWindowsSourcePackageCleanupDirectory(parent windows.Handle, name string) (windows.Handle, error) {
	return openWindowsSourcePackageCleanupObject(parent, name, true)
}

func openWindowsSourcePackageCleanupFile(parent windows.Handle, name string) (windows.Handle, error) {
	return openWindowsSourcePackageCleanupObject(parent, name, false)
}

func openWindowsSourcePackageCleanupObject(parent windows.Handle, name string, directory bool) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.DELETE | windows.SYNCHRONIZE)
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if directory {
		access |= windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		access |= windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, attributes, &status, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, options, 0, 0)
	return handle, err
}

func (stage *windowsSourcePackageOutputStage) release() error {
	if stage.released {
		return nil
	}
	stage.released = true
	var releaseErrors []error
	for _, object := range stage.files {
		if object.closed {
			continue
		}
		if err := object.file.Close(); err != nil {
			releaseErrors = append(releaseErrors, err)
		}
	}
	directories := make([]*windowsSourcePackageOutputDirectory, 0, len(stage.directories))
	for _, directory := range stage.directories {
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(left, right int) bool { return len(directories[left].relative) > len(directories[right].relative) })
	for _, directory := range directories {
		if directory.closed {
			continue
		}
		if err := directory.file.Close(); err != nil {
			releaseErrors = append(releaseErrors, err)
		}
	}
	for index := len(stage.parentHandles) - 1; index >= 0; index-- {
		if err := stage.parentHandles[index].Close(); err != nil {
			releaseErrors = append(releaseErrors, err)
		}
	}
	return errors.Join(releaseErrors...)
}
