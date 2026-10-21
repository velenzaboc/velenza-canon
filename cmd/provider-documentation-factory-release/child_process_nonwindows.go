//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

type retainedChildExecutable struct {
	file        *os.File
	measurement measuredExecutable
	identity    releaseReceiptUnixIdentity
	path        releaseReceiptUnixPath
	parents     []retainedReleaseReceiptDirectory
}

func openRetainedChildExecutable(path string) (*retainedChildExecutable, error) {
	resolved, err := resolveReleaseReceiptUnixPath(path)
	if err != nil {
		return nil, fmt.Errorf("resolve retained factory child path: %w", err)
	}
	parents, err := retainReleaseReceiptUnixParents(resolved)
	if err != nil {
		return nil, fmt.Errorf("retain factory child parent path: %w", err)
	}
	closeParentsOnError := func(err error) (*retainedChildExecutable, error) {
		closeRetainedReleaseReceiptUnixParents(parents)
		return nil, err
	}
	parent := parents[len(parents)-1].root
	pathInfo, err := parent.Lstat(resolved.leaf)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o111 == 0 {
		return closeParentsOnError(fmt.Errorf("built factory child path is not a no-follow executable regular file"))
	}
	pathIdentity, err := releaseReceiptUnixInfoIdentity(pathInfo)
	if err != nil {
		return closeParentsOnError(fmt.Errorf("derive factory child path identity: %w", err))
	}
	file, err := parent.OpenFile(resolved.leaf, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return closeParentsOnError(fmt.Errorf("open retained factory child relative to stable parent: %w", err))
	}
	closeFileOnError := func(err error) (*retainedChildExecutable, error) {
		_ = file.Close()
		return closeParentsOnError(err)
	}
	identity, err := file.Stat()
	openedIdentity, identityErr := releaseReceiptUnixFileIdentity(file)
	if err != nil || identityErr != nil || !identity.Mode().IsRegular() || identity.Mode().Perm()&0o111 == 0 || openedIdentity != pathIdentity {
		return closeFileOnError(fmt.Errorf("retained factory child differs from the selected path"))
	}
	if err := syscall.SetNonblock(int(file.Fd()), false); err != nil {
		return closeFileOnError(fmt.Errorf("clear retained factory child nonblocking mode: %w", err))
	}
	measurement, err := measureOpenExecutable(file, resolved.absolute)
	if err != nil {
		return closeFileOnError(err)
	}
	child := &retainedChildExecutable{
		file: file, measurement: measurement, identity: openedIdentity,
		path: resolved, parents: parents,
	}
	if err := child.verify(); err != nil {
		return closeFileOnError(err)
	}
	return child, nil
}

func (child *retainedChildExecutable) command(args []string) (*exec.Cmd, error) {
	if err := child.verify(); err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "linux":
		command := exec.Command("/proc/self/fd/3", args...)
		command.ExtraFiles = []*os.File{child.file}
		return command, nil
	case "darwin":
		return exec.Command(child.measurement.path, args...), nil
	default:
		return nil, fmt.Errorf("retained executable launch is unsupported on %s", runtime.GOOS)
	}
}

func (child *retainedChildExecutable) verify() error {
	if child == nil || child.file == nil || len(child.parents) == 0 {
		return fmt.Errorf("retained factory child is closed")
	}
	actual, err := measureOpenExecutable(child.file, child.measurement.path)
	if err != nil || actual != child.measurement {
		return fmt.Errorf("retained factory child changed during execution")
	}
	identity, err := releaseReceiptUnixFileIdentity(child.file)
	if err != nil || identity != child.identity {
		return fmt.Errorf("retained factory child identity changed during execution")
	}
	for _, parent := range child.parents {
		identity, err := releaseReceiptUnixFileIdentity(parent.file)
		if err != nil || identity != parent.identity {
			return fmt.Errorf("retained factory child parent changed during execution")
		}
	}
	if err := child.verifyVisiblePath(); err != nil {
		return err
	}
	return nil
}

func (child *retainedChildExecutable) verifyVisiblePath() error {
	visibleParents, err := retainReleaseReceiptUnixParents(child.path)
	if err != nil {
		return fmt.Errorf("reopen caller-visible factory child parent path: %w", err)
	}
	defer closeRetainedReleaseReceiptUnixParents(visibleParents)
	if len(visibleParents) != len(child.parents) {
		return fmt.Errorf("caller-visible factory child parent path changed")
	}
	for index := range visibleParents {
		if visibleParents[index].identity != child.parents[index].identity {
			return fmt.Errorf("caller-visible factory child parent path changed identity")
		}
	}
	parent := visibleParents[len(visibleParents)-1].root
	before, err := parent.Lstat(child.path.leaf)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("caller-visible factory child is absent, a link, or not executable")
	}
	beforeIdentity, err := releaseReceiptUnixInfoIdentity(before)
	if err != nil || beforeIdentity != child.identity {
		return fmt.Errorf("caller-visible factory child does not name the retained identity")
	}
	file, err := parent.OpenFile(child.path.leaf, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("reopen caller-visible factory child through stable parent: %w", err)
	}
	defer file.Close()
	if err := syscall.SetNonblock(int(file.Fd()), false); err != nil {
		return fmt.Errorf("clear reopened factory child nonblocking mode: %w", err)
	}
	identity, identityErr := releaseReceiptUnixFileIdentity(file)
	measurement, measurementErr := measureOpenExecutable(file, child.measurement.path)
	after, afterErr := parent.Lstat(child.path.leaf)
	afterIdentity, afterIdentityErr := releaseReceiptUnixInfoIdentity(after)
	if identityErr != nil || measurementErr != nil || afterErr != nil || afterIdentityErr != nil ||
		after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || after.Mode().Perm()&0o111 == 0 ||
		identity != child.identity || afterIdentity != child.identity || measurement != child.measurement {
		return fmt.Errorf("caller-visible factory child changed during relative reopen")
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
	closeRetainedReleaseReceiptUnixParents(child.parents)
	child.parents = nil
}

func readPrivateChildReceipt(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || pathInfo.Size() < 0 || pathInfo.Size() > maximumCommandOutput {
		return nil, fmt.Errorf("private child receipt is not a bounded no-follow regular file")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open private child receipt: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("retain private child receipt handle")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, fmt.Errorf("private child receipt changed before open")
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		return nil, fmt.Errorf("clear private receipt nonblocking mode: %w", err)
	}
	var output bytes.Buffer
	count, err := io.Copy(&output, io.LimitReader(file, maximumCommandOutput+1))
	if err != nil || count > maximumCommandOutput || count != openedInfo.Size() {
		return nil, fmt.Errorf("read bounded private child receipt")
	}
	finalInfo, err := file.Stat()
	finalPathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(openedInfo, finalInfo) || !os.SameFile(openedInfo, finalPathInfo) || openedInfo.Size() != finalInfo.Size() || !openedInfo.ModTime().Equal(finalInfo.ModTime()) {
		return nil, fmt.Errorf("private child receipt changed while read")
	}
	return output.Bytes(), nil
}
