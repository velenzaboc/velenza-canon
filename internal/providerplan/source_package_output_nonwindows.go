//go:build !windows

package providerplan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type nonWindowsSourcePackageOutputObject struct {
	file     *os.File
	identity providerInputStableFileIdentity
	name     string
	parent   *nonWindowsSourcePackageOutputDirectory
	raw      []byte
}

type nonWindowsSourcePackageOutputDirectory struct {
	file     *os.File
	fd       int
	identity providerInputStableFileIdentity
	relative string
	name     string
	parent   *nonWindowsSourcePackageOutputDirectory
}

type nonWindowsSourcePackageOutputStage struct {
	root          *nonWindowsSourcePackageOutputDirectory
	parentHandles []*os.File
	parentFD      int
	stageName     string
	finalName     string
	absoluteStage string
	directories   map[string]*nonWindowsSourcePackageOutputDirectory
	files         map[string]*nonWindowsSourcePackageOutputObject
	hooks         sourcePackageOutputHooks
	published     bool
	released      bool
}

func validateSourcePackageOutputPathComponent(string) error { return nil }

func createSourcePackageOutputStage(resolved factoryOutputPath, hooks sourcePackageOutputHooks) (sourcePackageOutputStage, []factoryOutputPathIdentity, error) {
	rootFD, err := unix.Open(resolved.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	rootFile := os.NewFile(uintptr(rootFD), resolved.root)
	if rootFile == nil {
		_ = unix.Close(rootFD)
		return nil, nil, fmt.Errorf("retain source-package filesystem root")
	}
	rootIdentity, err := stableProviderInputFileIdentity(rootFile)
	if err != nil {
		_ = rootFile.Close()
		return nil, nil, err
	}
	parents := []*os.File{rootFile}
	identities := []factoryOutputPathIdentity{{path: resolved.root, identity: rootIdentity}}
	parentFD := rootFD
	current := resolved.root
	closeParents := func() {
		for index := len(parents) - 1; index >= 0; index-- {
			_ = parents[index].Close()
		}
	}
	for _, component := range resolved.components {
		fd, openErr := unix.Openat(parentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			closeParents()
			return nil, nil, openErr
		}
		current = filepath.Join(current, component)
		directory := os.NewFile(uintptr(fd), current)
		if directory == nil {
			_ = unix.Close(fd)
			closeParents()
			return nil, nil, fmt.Errorf("retain source-package output parent %q", current)
		}
		info, statErr := directory.Stat()
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = directory.Close()
			closeParents()
			return nil, nil, fmt.Errorf("source-package output parent %q is not a stable directory", current)
		}
		identity, identityErr := stableProviderInputFileIdentity(directory)
		if identityErr != nil {
			_ = directory.Close()
			closeParents()
			return nil, nil, identityErr
		}
		parents = append(parents, directory)
		identities = append(identities, factoryOutputPathIdentity{path: current, identity: identity})
		parentFD = fd
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
	if err := unix.Mkdirat(parentFD, stageName, 0o700); err != nil {
		closeParents()
		return nil, nil, fmt.Errorf("create exclusive source-package staging root: %w", err)
	}
	stageFD, err := unix.Openat(parentFD, stageName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		_ = unix.Unlinkat(parentFD, stageName, unix.AT_REMOVEDIR)
		closeParents()
		return nil, nil, err
	}
	stageFile := os.NewFile(uintptr(stageFD), filepath.Join(filepath.Dir(resolved.absolute), stageName))
	if stageFile == nil {
		_ = unix.Close(stageFD)
		_ = unix.Unlinkat(parentFD, stageName, unix.AT_REMOVEDIR)
		closeParents()
		return nil, nil, fmt.Errorf("retain source-package staging root")
	}
	stageIdentity, err := stableProviderInputFileIdentity(stageFile)
	if err != nil {
		_ = stageFile.Close()
		_ = unix.Unlinkat(parentFD, stageName, unix.AT_REMOVEDIR)
		closeParents()
		return nil, nil, err
	}
	root := &nonWindowsSourcePackageOutputDirectory{file: stageFile, fd: stageFD, identity: stageIdentity, name: stageName}
	stage := &nonWindowsSourcePackageOutputStage{
		root: root, parentHandles: parents, parentFD: parentFD, stageName: stageName, finalName: resolved.leaf,
		absoluteStage: filepath.Join(filepath.Dir(resolved.absolute), stageName),
		directories:   map[string]*nonWindowsSourcePackageOutputDirectory{"": root}, files: make(map[string]*nonWindowsSourcePackageOutputObject), hooks: hooks,
	}
	return stage, identities, nil
}

func (stage *nonWindowsSourcePackageOutputStage) stagePath() string { return stage.absoluteStage }

func (stage *nonWindowsSourcePackageOutputStage) writeFile(entry preparedSourcePackageOutputFile) error {
	parent := stage.root
	for index, component := range entry.components[:len(entry.components)-1] {
		relative := strings.Join(entry.components[:index+1], "/")
		next := stage.directories[relative]
		if next == nil {
			if err := unix.Mkdirat(parent.fd, component, 0o700); err != nil {
				return fmt.Errorf("create exclusive source-package directory %q: %w", relative, err)
			}
			fd, err := unix.Openat(parent.fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			file := os.NewFile(uintptr(fd), filepath.Join(stage.absoluteStage, filepath.FromSlash(relative)))
			if file == nil {
				_ = unix.Close(fd)
				return fmt.Errorf("retain source-package directory %q", relative)
			}
			identity, err := stableProviderInputFileIdentity(file)
			if err != nil {
				_ = file.Close()
				return err
			}
			next = &nonWindowsSourcePackageOutputDirectory{file: file, fd: fd, identity: identity, relative: relative, name: component, parent: parent}
			stage.directories[relative] = next
		}
		parent = next
	}
	leaf := entry.components[len(entry.components)-1]
	fd, err := unix.Openat(parent.fd, leaf, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create exclusive source-package file: %w", err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(stage.absoluteStage, filepath.FromSlash(entry.relative)))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("retain source-package file")
	}
	identity, err := inspectNewSourcePackageOutputFile(file, entry.relative)
	if err != nil {
		_ = file.Close()
		return err
	}
	object := &nonWindowsSourcePackageOutputObject{file: file, identity: identity, name: leaf, parent: parent, raw: entry.raw}
	stage.files[entry.relative] = object
	writtenIdentity, err := writeExactSourcePackageOutputFile(file, entry.relative, entry.raw, identity, func() error {
		if stage.hooks.afterFileDataWrite != nil {
			if hookErr := stage.hooks.afterFileDataWrite(entry.relative); hookErr != nil {
				return hookErr
			}
		}
		if stage.hooks.beforeFileSync != nil {
			if hookErr := stage.hooks.beforeFileSync(entry.relative); hookErr != nil {
				return hookErr
			}
		}
		if syncErr := syncNonWindowsFactoryFile(fd); syncErr != nil {
			return syncErr
		}
		if stage.hooks.afterFileSync != nil {
			return stage.hooks.afterFileSync(entry.relative)
		}
		return nil
	})
	if err != nil {
		return err
	}
	object.identity = writtenIdentity
	return nil
}

func (stage *nonWindowsSourcePackageOutputStage) seal(roster []preparedSourcePackageOutputFile) error {
	if len(stage.files) != len(roster) {
		return fmt.Errorf("source-package output tree has %d retained files, want %d", len(stage.files), len(roster))
	}
	for _, entry := range roster {
		object := stage.files[entry.relative]
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
	directories := make([]*nonWindowsSourcePackageOutputDirectory, 0, len(stage.directories))
	for _, directory := range stage.directories {
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(left, right int) bool { return len(directories[left].relative) > len(directories[right].relative) })
	for _, directory := range directories {
		identity, err := stableProviderInputFileIdentity(directory.file)
		if err != nil || identity != directory.identity {
			return fmt.Errorf("source-package directory %q changed identity", directory.relative)
		}
		if err := syncNonWindowsFactoryDirectory(directory.fd); err != nil {
			return fmt.Errorf("sync source-package directory %q: %w", directory.relative, err)
		}
	}
	return nil
}

func (stage *nonWindowsSourcePackageOutputStage) validateClosedRoster(roster []preparedSourcePackageOutputFile) error {
	expected := make(map[string][]string, len(stage.directories))
	for _, entry := range roster {
		for index, component := range entry.components {
			parent := strings.Join(entry.components[:index], "/")
			expected[parent] = append(expected[parent], component)
		}
	}
	for key, directory := range stage.directories {
		duplicateFD, err := unix.Openat(directory.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		copyFile := os.NewFile(uintptr(duplicateFD), directory.relative)
		if copyFile == nil {
			_ = unix.Close(duplicateFD)
			return fmt.Errorf("retain source-package directory enumeration handle")
		}
		entries, err := copyFile.ReadDir(-1)
		_ = copyFile.Close()
		if err != nil {
			return fmt.Errorf("enumerate source-package directory %q: %w", directory.relative, err)
		}
		wantSet := make(map[string]struct{})
		for _, name := range expected[key] {
			wantSet[name] = struct{}{}
		}
		if len(entries) != len(wantSet) {
			return fmt.Errorf("source-package directory %q contains %d entries, want %d", directory.relative, len(entries), len(wantSet))
		}
		for _, entry := range entries {
			if _, ok := wantSet[entry.Name()]; !ok {
				return fmt.Errorf("source-package directory %q contains undeclared entry %q", directory.relative, entry.Name())
			}
			relative := entry.Name()
			if key != "" {
				relative = key + "/" + entry.Name()
			}
			if retainedDirectory := stage.directories[relative]; retainedDirectory != nil {
				same, matchErr := nonWindowsSourcePackageNamedObjectMatches(directory.fd, entry.Name(), retainedDirectory.identity, true)
				if matchErr != nil {
					return fmt.Errorf("source-package directory %q changed identity or kind: %w", relative, matchErr)
				}
				if !same {
					return fmt.Errorf("source-package directory %q changed identity or kind", relative)
				}
				continue
			}
			retainedFile := stage.files[relative]
			if retainedFile == nil {
				return fmt.Errorf("source-package retained-object ledger omits %q", relative)
			}
			same, matchErr := nonWindowsSourcePackageNamedObjectMatches(directory.fd, entry.Name(), retainedFile.identity, false)
			if matchErr != nil {
				return fmt.Errorf("source-package file %q changed identity or kind: %w", relative, matchErr)
			}
			if !same {
				return fmt.Errorf("source-package file %q changed identity or kind", relative)
			}
		}
	}
	return nil
}

func (stage *nonWindowsSourcePackageOutputStage) publish() error {
	if err := publishNonWindowsFactoryOutput(stage.parentFD, stage.parentFD, -1, stage.stageName, stage.finalName); err != nil {
		return err
	}
	stage.published = true
	if err := syncNonWindowsFactoryDirectory(stage.parentFD); err != nil {
		return fmt.Errorf("sync source-package output parent after publication: %w", err)
	}
	return nil
}

func (stage *nonWindowsSourcePackageOutputStage) preparePublish() error { return nil }

func (stage *nonWindowsSourcePackageOutputStage) validatePrepared(roster []preparedSourcePackageOutputFile) error {
	if err := stage.validatePrivateRoot(); err != nil {
		return err
	}
	return stage.seal(roster)
}

func (stage *nonWindowsSourcePackageOutputStage) validatePrivateRoot() error {
	same, err := nonWindowsSourcePackageNamedObjectMatches(stage.parentFD, stage.stageName, stage.root.identity, true)
	if err != nil {
		return fmt.Errorf("open private factory source-output root by retained name: %w", err)
	}
	if !same {
		return fmt.Errorf("private factory source-output root changed path identity")
	}
	return nil
}

func (stage *nonWindowsSourcePackageOutputStage) preparePrivateCallback() error { return nil }

func (stage *nonWindowsSourcePackageOutputStage) validatePublished(roster []preparedSourcePackageOutputFile) error {
	same, err := nonWindowsSourcePackageNamedObjectMatches(stage.parentFD, stage.finalName, stage.root.identity, true)
	if err != nil || !same {
		return fmt.Errorf("published source-package root changed identity: %w", err)
	}
	return stage.seal(roster)
}

func (stage *nonWindowsSourcePackageOutputStage) abort() error {
	var abortErrors []error
	for _, object := range stage.files {
		if err := object.file.Truncate(0); err != nil {
			abortErrors = append(abortErrors, err)
			continue
		}
		if err := object.file.Sync(); err != nil {
			abortErrors = append(abortErrors, err)
		}
		if same, err := nonWindowsSourcePackageNamedObjectMatches(object.parent.fd, object.name, object.identity, false); err == nil && same {
			if err := unix.Unlinkat(object.parent.fd, object.name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				abortErrors = append(abortErrors, err)
			}
		}
	}
	directories := make([]*nonWindowsSourcePackageOutputDirectory, 0, len(stage.directories))
	for _, directory := range stage.directories {
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(left, right int) bool { return len(directories[left].relative) > len(directories[right].relative) })
	for _, directory := range directories {
		parentFD := stage.parentFD
		name := stage.stageName
		if directory.parent != nil {
			parentFD = directory.parent.fd
			name = directory.name
		} else if stage.published {
			name = stage.finalName
		}
		if same, err := nonWindowsSourcePackageNamedObjectMatches(parentFD, name, directory.identity, true); err == nil && same {
			if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
				abortErrors = append(abortErrors, err)
			}
		}
	}
	return errors.Join(abortErrors...)
}

func nonWindowsSourcePackageNamedObjectMatches(parentFD int, name string, identity providerInputStableFileIdentity, directory bool) (bool, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(parentFD, name, flags, 0)
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return false, fmt.Errorf("retain cleanup identity handle")
	}
	got, identityErr := stableProviderInputFileIdentity(file)
	_ = file.Close()
	return identityErr == nil && got == identity, identityErr
}

func (stage *nonWindowsSourcePackageOutputStage) release() error {
	if stage.released {
		return nil
	}
	stage.released = true
	var releaseErrors []error
	for _, object := range stage.files {
		if err := object.file.Close(); err != nil {
			releaseErrors = append(releaseErrors, err)
		}
	}
	directories := make([]*nonWindowsSourcePackageOutputDirectory, 0, len(stage.directories))
	for _, directory := range stage.directories {
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(left, right int) bool { return len(directories[left].relative) > len(directories[right].relative) })
	for _, directory := range directories {
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
