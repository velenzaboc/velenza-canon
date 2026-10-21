//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type publishValidatedReceiptHooks struct {
	afterParentOpen    func() error
	beforeVisibleCheck func() error
}

type releaseReceiptUnixIdentity struct {
	device uint64
	inode  uint64
}

type releaseReceiptUnixPath struct {
	absolute   string
	components []string
	leaf       string
}

type retainedReleaseReceiptDirectory struct {
	root     *os.Root
	file     *os.File
	identity releaseReceiptUnixIdentity
}

func publishValidatedReceipt(path string, raw []byte) error {
	return publishValidatedReceiptWithHooks(path, raw, publishValidatedReceiptHooks{})
}

func publishValidatedReceiptWithHooks(path string, raw []byte, hooks publishValidatedReceiptHooks) error {
	if len(raw) == 0 {
		return fmt.Errorf("validated receipt bytes are empty")
	}
	resolved, err := resolveReleaseReceiptUnixPath(path)
	if err != nil {
		return err
	}

	parents, err := retainReleaseReceiptUnixParents(resolved)
	if err != nil {
		return err
	}
	defer closeRetainedReleaseReceiptUnixParents(parents)
	parent := parents[len(parents)-1]
	if hooks.afterParentOpen != nil {
		if err := hooks.afterParentOpen(); err != nil {
			return fmt.Errorf("after validated receipt parent open: %w", err)
		}
	}

	file, err := parent.root.OpenFile(resolved.leaf, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create validated receipt exactly once at %q: %w", resolved.absolute, err)
	}
	defer file.Close()
	createdIdentity, err := releaseReceiptUnixFileIdentity(file)
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
	if err := parent.file.Sync(); err != nil {
		return fmt.Errorf("sync validated receipt parent %q: %w", filepath.Dir(resolved.absolute), err)
	}
	if hooks.beforeVisibleCheck != nil {
		if err := hooks.beforeVisibleCheck(); err != nil {
			return fmt.Errorf("before validated receipt visible-path check: %w", err)
		}
	}

	visible, err := reopenVisibleReleaseReceiptUnixPath(resolved, parents, createdIdentity)
	if err != nil {
		return err
	}
	defer visible.Close()
	retainedIdentity, err := releaseReceiptUnixFileIdentity(file)
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

func resolveReleaseReceiptUnixPath(path string) (releaseReceiptUnixPath, error) {
	if path == "" || path != strings.TrimSpace(path) || strings.IndexByte(path, 0) >= 0 {
		return releaseReceiptUnixPath{}, fmt.Errorf("validated receipt path is empty, padded, or contains NUL")
	}
	for index := 0; index < len(path); index++ {
		if path[index] < 0x20 || path[index] >= 0x7f {
			return releaseReceiptUnixPath{}, fmt.Errorf("validated receipt path %q contains a normalization-risk character", path)
		}
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return releaseReceiptUnixPath{}, fmt.Errorf("validated receipt path %q is not an absolute canonical path", path)
	}
	trimmed := strings.TrimPrefix(path, string(filepath.Separator))
	if trimmed == path || trimmed == "" {
		return releaseReceiptUnixPath{}, fmt.Errorf("validated receipt path %q does not name a file below the filesystem root", path)
	}
	components := strings.Split(trimmed, string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return releaseReceiptUnixPath{}, fmt.Errorf("validated receipt path %q contains an invalid component", path)
		}
	}
	return releaseReceiptUnixPath{
		absolute:   path,
		components: append([]string(nil), components[:len(components)-1]...),
		leaf:       components[len(components)-1],
	}, nil
}

func retainReleaseReceiptUnixParents(path releaseReceiptUnixPath) ([]retainedReleaseReceiptDirectory, error) {
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, fmt.Errorf("open validated receipt filesystem root: %w", err)
	}
	rootFile, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("retain validated receipt filesystem root handle: %w", err)
	}
	rootIdentity, err := releaseReceiptUnixFileIdentity(rootFile)
	if err != nil {
		_ = rootFile.Close()
		_ = root.Close()
		return nil, fmt.Errorf("derive validated receipt filesystem root identity: %w", err)
	}
	parents := []retainedReleaseReceiptDirectory{{root: root, file: rootFile, identity: rootIdentity}}
	current := root
	for _, component := range path.components {
		before, beforeErr := current.Lstat(component)
		if beforeErr != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			closeRetainedReleaseReceiptUnixParents(parents)
			return nil, fmt.Errorf("validated receipt parent component %q is absent, a link, or not a directory", component)
		}
		beforeIdentity, beforeIdentityErr := releaseReceiptUnixInfoIdentity(before)
		if beforeIdentityErr != nil {
			closeRetainedReleaseReceiptUnixParents(parents)
			return nil, fmt.Errorf("derive validated receipt parent path identity for %q: %w", component, beforeIdentityErr)
		}
		next, openErr := current.OpenRoot(component)
		if openErr != nil {
			closeRetainedReleaseReceiptUnixParents(parents)
			return nil, fmt.Errorf("open validated receipt parent component %q: %w", component, openErr)
		}
		directory, fileErr := next.Open(".")
		if fileErr != nil {
			_ = next.Close()
			closeRetainedReleaseReceiptUnixParents(parents)
			return nil, fmt.Errorf("retain validated receipt parent component %q: %w", component, fileErr)
		}
		identity, identityErr := releaseReceiptUnixFileIdentity(directory)
		after, afterErr := current.Lstat(component)
		afterIdentity, afterIdentityErr := releaseReceiptUnixInfoIdentity(after)
		if identityErr != nil || afterErr != nil || afterIdentityErr != nil || after.Mode()&os.ModeSymlink != 0 || !after.IsDir() || beforeIdentity != identity || afterIdentity != identity {
			_ = directory.Close()
			_ = next.Close()
			closeRetainedReleaseReceiptUnixParents(parents)
			return nil, fmt.Errorf("validated receipt parent component %q changed or resolved through a link", component)
		}
		parents = append(parents, retainedReleaseReceiptDirectory{root: next, file: directory, identity: identity})
		current = next
	}
	return parents, nil
}

func reopenVisibleReleaseReceiptUnixPath(path releaseReceiptUnixPath, expected []retainedReleaseReceiptDirectory, created releaseReceiptUnixIdentity) (*os.File, error) {
	actual, err := retainReleaseReceiptUnixParents(path)
	if err != nil {
		return nil, fmt.Errorf("reopen caller-visible validated receipt parent path %q: %w", filepath.Dir(path.absolute), err)
	}
	defer closeRetainedReleaseReceiptUnixParents(actual)
	if len(actual) != len(expected) {
		return nil, fmt.Errorf("caller-visible validated receipt parent path %q changed", filepath.Dir(path.absolute))
	}
	for index := range actual {
		if actual[index].identity != expected[index].identity {
			return nil, fmt.Errorf("caller-visible validated receipt parent path %q changed identity", filepath.Dir(path.absolute))
		}
	}
	parent := actual[len(actual)-1].root
	before, err := parent.Lstat(path.leaf)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("caller-visible validated receipt %q is absent, a link, or not regular", path.absolute)
	}
	beforeIdentity, err := releaseReceiptUnixInfoIdentity(before)
	if err != nil || beforeIdentity != created {
		return nil, fmt.Errorf("caller-visible validated receipt %q does not name the retained created identity", path.absolute)
	}
	file, err := parent.Open(path.leaf)
	if err != nil {
		return nil, fmt.Errorf("reopen caller-visible validated receipt %q: %w", path.absolute, err)
	}
	identity, identityErr := releaseReceiptUnixFileIdentity(file)
	after, afterErr := parent.Lstat(path.leaf)
	afterIdentity, afterIdentityErr := releaseReceiptUnixInfoIdentity(after)
	info, statErr := file.Stat()
	if identityErr != nil || afterErr != nil || afterIdentityErr != nil || statErr != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !info.Mode().IsRegular() || identity != created || afterIdentity != created {
		_ = file.Close()
		return nil, fmt.Errorf("caller-visible validated receipt %q changed or resolved through a link", path.absolute)
	}
	return file, nil
}

func releaseReceiptUnixFileIdentity(file *os.File) (releaseReceiptUnixIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		return releaseReceiptUnixIdentity{}, err
	}
	return releaseReceiptUnixIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func releaseReceiptUnixInfoIdentity(info os.FileInfo) (releaseReceiptUnixIdentity, error) {
	if info == nil {
		return releaseReceiptUnixIdentity{}, fmt.Errorf("file identity metadata is absent")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return releaseReceiptUnixIdentity{}, fmt.Errorf("file identity metadata has unexpected type %T", info.Sys())
	}
	return releaseReceiptUnixIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
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

func closeRetainedReleaseReceiptUnixParents(parents []retainedReleaseReceiptDirectory) {
	for index := len(parents) - 1; index >= 0; index-- {
		_ = parents[index].file.Close()
		_ = parents[index].root.Close()
	}
}
