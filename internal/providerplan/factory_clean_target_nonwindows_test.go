//go:build !windows

package providerplan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type nonWindowsFactoryCleanTargetDirectory struct {
	file      *os.File
	fd        int
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
	rootFD, err := unix.Open(resolved.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("open clean target filesystem root %q without following links: %w", resolved.root, err)
	}
	rootFile := os.NewFile(uintptr(rootFD), resolved.root)
	if rootFile == nil {
		_ = unix.Close(rootFD)
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("retain clean target filesystem root %q", resolved.root)
	}
	ancestors := []*os.File{rootFile}
	closeAncestors := func() {
		for index := len(ancestors) - 1; index >= 0; index-- {
			_ = ancestors[index].Close()
		}
	}
	parentFD := rootFD
	current := resolved.root
	for _, component := range resolved.components {
		if err := validateFactoryCleanTargetComponent(component); err != nil {
			closeAncestors()
			return nil, providerInputStableFileIdentity{}, err
		}
		fd, openErr := unix.Openat(parentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			closeAncestors()
			return nil, providerInputStableFileIdentity{}, fmt.Errorf("open clean target parent component %q without following links: %w", component, openErr)
		}
		current = filepath.Join(current, component)
		directory := os.NewFile(uintptr(fd), current)
		if directory == nil {
			_ = unix.Close(fd)
			closeAncestors()
			return nil, providerInputStableFileIdentity{}, fmt.Errorf("retain clean target parent component %q", current)
		}
		info, statErr := directory.Stat()
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = directory.Close()
			closeAncestors()
			if statErr != nil {
				return nil, providerInputStableFileIdentity{}, fmt.Errorf("inspect clean target parent %q: %w", current, statErr)
			}
			return nil, providerInputStableFileIdentity{}, fmt.Errorf("clean target parent %q is not a stable directory", current)
		}
		ancestors = append(ancestors, directory)
		parentFD = fd
	}
	if err := validateFactoryCleanTargetComponent(resolved.leaf); err != nil {
		closeAncestors()
		return nil, providerInputStableFileIdentity{}, err
	}
	result, identity, err := createNonWindowsFactoryCleanTargetDirectory(parentFD, resolved.leaf, absolute, nonWindowsFactoryCleanTargetDirectoryTestHooks{})
	if err != nil {
		closeAncestors()
		return nil, providerInputStableFileIdentity{}, err
	}
	result.ancestors = ancestors
	return result, identity, nil
}

func (directory *nonWindowsFactoryCleanTargetDirectory) createDirectory(component, displayPath string) (factoryCleanTargetDirectoryHandle, providerInputStableFileIdentity, error) {
	if directory == nil || directory.closed {
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("clean target parent handle is closed")
	}
	if err := validateFactoryCleanTargetComponent(component); err != nil {
		return nil, providerInputStableFileIdentity{}, err
	}
	return createNonWindowsFactoryCleanTargetDirectory(directory.fd, component, displayPath, nonWindowsFactoryCleanTargetDirectoryTestHooks{})
}

type nonWindowsFactoryCleanTargetDirectoryTestHooks struct {
	afterStageOpen func(stageName string) error
	beforePublish  func(stageName string) error
}

func createNonWindowsFactoryCleanTargetDirectory(parentFD int, component, displayPath string, hooks nonWindowsFactoryCleanTargetDirectoryTestHooks) (*nonWindowsFactoryCleanTargetDirectory, providerInputStableFileIdentity, error) {
	stageName, err := newFactoryOutputStagedName()
	if err != nil {
		return nil, providerInputStableFileIdentity{}, err
	}
	stageName += ".d"
	if err := unix.Mkdirat(parentFD, stageName, 0o700); err != nil {
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("create private clean target directory stage: %w", err)
	}
	fd, err := unix.Openat(parentFD, stageName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("retain private clean target directory stage: %w", err)
	}
	file := os.NewFile(uintptr(fd), displayPath+" (private directory stage)")
	if file == nil {
		_ = unix.Close(fd)
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("retain private clean target directory stage handle")
	}
	created, err := file.Stat()
	if err != nil || !created.IsDir() || created.Mode()&os.ModeSymlink != 0 {
		_ = file.Close()
		if err != nil {
			return nil, providerInputStableFileIdentity{}, fmt.Errorf("inspect private clean target directory stage: %w", err)
		}
		return nil, providerInputStableFileIdentity{}, fmt.Errorf("private clean target directory stage is not stable")
	}
	cleanup := func(name string, cause error) (*nonWindowsFactoryCleanTargetDirectory, providerInputStableFileIdentity, error) {
		joined := []error{cause}
		if removeErr := removeNonWindowsFactoryCleanTargetDirectoryName(parentFD, name, created); removeErr != nil {
			joined = append(joined, removeErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			joined = append(joined, closeErr)
		}
		return nil, providerInputStableFileIdentity{}, errors.Join(joined...)
	}
	if hooks.afterStageOpen != nil {
		if err := hooks.afterStageOpen(stageName); err != nil {
			return cleanup(stageName, fmt.Errorf("after private clean target directory stage open test hook: %w", err))
		}
	}
	if err := validateNonWindowsFactoryCleanTargetDirectoryName(parentFD, stageName, created); err != nil {
		return cleanup(stageName, err)
	}
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return cleanup(stageName, fmt.Errorf("derive private clean target directory identity: %w", err))
	}
	if hooks.beforePublish != nil {
		if err := hooks.beforePublish(stageName); err != nil {
			return cleanup(stageName, fmt.Errorf("before private clean target directory publish test hook: %w", err))
		}
	}
	if err := validateNonWindowsFactoryCleanTargetDirectoryName(parentFD, stageName, created); err != nil {
		return cleanup(stageName, err)
	}
	if err := publishNonWindowsFactoryCleanTargetDirectory(parentFD, stageName, component); err != nil {
		return cleanup(stageName, fmt.Errorf("publish private clean target directory stage as %q: %w", component, err))
	}
	if err := validateNonWindowsFactoryCleanTargetDirectoryName(parentFD, component, created); err != nil {
		return cleanup(component, err)
	}
	result := &nonWindowsFactoryCleanTargetDirectory{file: file, fd: fd, path: displayPath, identity: identity}
	if err := result.validate(); err != nil {
		return cleanup(component, err)
	}
	return result, identity, nil
}

func validateNonWindowsFactoryCleanTargetDirectoryName(parentFD int, name string, created os.FileInfo) error {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open clean target directory name %q for identity validation: %w", name, err)
	}
	current := os.NewFile(uintptr(fd), name)
	if current == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("retain clean target directory name %q for identity validation", name)
	}
	got, statErr := current.Stat()
	closeErr := current.Close()
	if statErr != nil {
		return fmt.Errorf("inspect clean target directory name %q: %w", name, statErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close clean target directory identity handle %q: %w", name, closeErr)
	}
	if !got.IsDir() || got.Mode()&os.ModeSymlink != 0 || !os.SameFile(created, got) {
		return fmt.Errorf("clean target directory name %q changed identity", name)
	}
	return nil
}

func removeNonWindowsFactoryCleanTargetDirectoryName(parentFD int, name string, created os.FileInfo) error {
	if err := validateNonWindowsFactoryCleanTargetDirectoryName(parentFD, name, created); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("refuse cleanup of changed clean target directory name %q: %w", name, err)
	}
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove exact clean target directory name %q: %w", name, err)
	}
	return nil
}

func (directory *nonWindowsFactoryCleanTargetDirectory) createFile(component, displayPath string, raw []byte, mode os.FileMode) (providerInputStableFileIdentity, error) {
	if directory == nil || directory.closed {
		return providerInputStableFileIdentity{}, fmt.Errorf("clean target parent handle is closed")
	}
	if err := validateFactoryCleanTargetComponent(component); err != nil {
		return providerInputStableFileIdentity{}, err
	}
	fd, err := unix.Openat(directory.fd, component, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return providerInputStableFileIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), displayPath)
	if file == nil {
		_ = unix.Close(fd)
		return providerInputStableFileIdentity{}, fmt.Errorf("retain new clean target file %q", displayPath)
	}
	return writeExactFactoryCleanTargetFile(file, displayPath, raw, mode)
}

func (directory *nonWindowsFactoryCleanTargetDirectory) validate() error {
	if directory == nil || directory.closed {
		return fmt.Errorf("clean target directory handle is closed")
	}
	return validateFactoryCleanTargetDirectoryHandle(directory.path, directory.file, directory.identity)
}

func (directory *nonWindowsFactoryCleanTargetDirectory) close() error {
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

func validateFactoryCleanTargetComponent(component string) error {
	if component == "" || component == "." || component == ".." || strings.IndexByte(component, 0) >= 0 {
		return fmt.Errorf("clean target component %q is invalid", component)
	}
	return nil
}
