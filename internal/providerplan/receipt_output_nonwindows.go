//go:build !windows

package providerplan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type nonWindowsFactoryOutput struct {
	file         *os.File
	cleanupFD    int
	parentFD     int
	stageDir     *os.File
	stageDirFD   int
	stageDirName string
	stageDirInfo os.FileInfo
	stageName    string
	finalName    string
	parents      []*os.File
	dataClosed   bool
	published    bool
	released     bool
}

type nonWindowsNamedStageConstruction struct {
	parentFD         int
	stageDirName     string
	stageDirFD       int
	stageDir         *os.File
	stageDirIdentity unix.Stat_t
	stageName        string
	fileFD           int
	fileIdentity     unix.Stat_t
	cleanupFD        int
}

func (construction *nonWindowsNamedStageConstruction) rollback() error {
	var rollbackErrors []error
	if construction.cleanupFD >= 0 {
		if err := unix.Close(construction.cleanupFD); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
		construction.cleanupFD = -1
	}
	if construction.fileFD >= 0 {
		currentFD, err := unix.Openat(construction.stageDirFD, construction.stageName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err == nil {
			var current unix.Stat_t
			if statErr := unix.Fstat(currentFD, &current); statErr == nil && sameNonWindowsFactoryIdentity(current, construction.fileIdentity) {
				if unlinkErr := unix.Unlinkat(construction.stageDirFD, construction.stageName, 0); unlinkErr != nil && !errors.Is(unlinkErr, unix.ENOENT) {
					rollbackErrors = append(rollbackErrors, unlinkErr)
				}
			}
			_ = unix.Close(currentFD)
		}
		if err := unix.Close(construction.fileFD); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
		construction.fileFD = -1
	}
	if construction.stageDir != nil {
		if err := construction.stageDir.Close(); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
		construction.stageDir = nil
		construction.stageDirFD = -1
	} else if construction.stageDirFD >= 0 {
		if err := unix.Close(construction.stageDirFD); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
		construction.stageDirFD = -1
	}
	currentDirFD, err := unix.Openat(construction.parentFD, construction.stageDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == nil {
		var current unix.Stat_t
		if statErr := unix.Fstat(currentDirFD, &current); statErr == nil && sameNonWindowsFactoryIdentity(current, construction.stageDirIdentity) {
			if unlinkErr := unix.Unlinkat(construction.parentFD, construction.stageDirName, unix.AT_REMOVEDIR); unlinkErr != nil && !errors.Is(unlinkErr, unix.ENOENT) {
				rollbackErrors = append(rollbackErrors, unlinkErr)
			}
		}
		_ = unix.Close(currentDirFD)
	}
	return errors.Join(rollbackErrors...)
}

func sameNonWindowsFactoryIdentity(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}

func createFactoryOutputExclusive(path factoryOutputPath, hooks factoryOutputTestHooks) (factoryOutputObject, []factoryOutputPathIdentity, error) {
	rootFD, err := unix.Open(path.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open --out filesystem root %q without following links: %w", path.root, err)
	}
	rootFile := os.NewFile(uintptr(rootFD), path.root)
	if rootFile == nil {
		_ = unix.Close(rootFD)
		return nil, nil, fmt.Errorf("retain --out filesystem root %q", path.root)
	}
	rootInfo, err := rootFile.Stat()
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		_ = rootFile.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("inspect --out filesystem root %q: %w", path.root, err)
		}
		return nil, nil, fmt.Errorf("--out filesystem root %q is not a stable directory", path.root)
	}
	rootIdentity, err := stableProviderInputFileIdentity(rootFile)
	if err != nil {
		_ = rootFile.Close()
		return nil, nil, fmt.Errorf("derive --out filesystem root identity %q: %w", path.root, err)
	}
	parents := []*os.File{rootFile}
	parentFD := rootFD
	current := path.root
	identities := []factoryOutputPathIdentity{{path: path.root, identity: rootIdentity}}
	closeParents := func() {
		for index := len(parents) - 1; index >= 0; index-- {
			_ = parents[index].Close()
		}
	}

	for _, component := range path.components {
		fd, openErr := unix.Openat(parentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			closeParents()
			return nil, nil, fmt.Errorf("open --out parent component %q without following links: %w", component, openErr)
		}
		current = filepath.Join(current, component)
		directory := os.NewFile(uintptr(fd), current)
		if directory == nil {
			_ = unix.Close(fd)
			closeParents()
			return nil, nil, fmt.Errorf("retain --out parent component %q", current)
		}
		info, statErr := directory.Stat()
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = directory.Close()
			closeParents()
			if statErr != nil {
				return nil, nil, fmt.Errorf("inspect retained --out parent %q: %w", current, statErr)
			}
			return nil, nil, fmt.Errorf("--out path %q has a non-directory or symbolic-link parent %q", path.absolute, current)
		}
		identity, identityErr := stableProviderInputFileIdentity(directory)
		if identityErr != nil {
			_ = directory.Close()
			closeParents()
			return nil, nil, fmt.Errorf("derive retained --out parent identity %q: %w", current, identityErr)
		}
		parents = append(parents, directory)
		identities = append(identities, factoryOutputPathIdentity{path: current, identity: identity})
		parentFD = fd
	}

	if hooks.afterParentOpen != nil {
		if err := hooks.afterParentOpen(); err != nil {
			closeParents()
			return nil, nil, fmt.Errorf("after --out parent open test hook: %w", err)
		}
	}

	fd := -1
	namedStage := hooks.forceNamedStage
	if !namedStage {
		var supported bool
		fd, supported, err = createUnnamedNonWindowsFactoryFile(parentFD)
		if err != nil {
			closeParents()
			return nil, nil, err
		}
		namedStage = !supported
	}
	stageName := ""
	stageDirFD := parentFD
	cleanupFD := -1
	var stageDir *os.File
	var stageDirName string
	var stageDirInfo os.FileInfo
	if namedStage {
		stageDirName, err = newFactoryOutputStagedName()
		if err != nil {
			closeParents()
			return nil, nil, err
		}
		stageDirName += ".d"
		if err = unix.Mkdirat(parentFD, stageDirName, 0o700); err != nil {
			closeParents()
			return nil, nil, fmt.Errorf("create private --out staging container: %w", err)
		}
		construction := nonWindowsNamedStageConstruction{
			parentFD: parentFD, stageDirName: stageDirName, stageDirFD: -1, stageName: "receipt", fileFD: -1, cleanupFD: -1,
		}
		if err := unix.Fstatat(parentFD, stageDirName, &construction.stageDirIdentity, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			closeParents()
			return nil, nil, fmt.Errorf("capture private --out staging container identity: %w", err)
		}
		failConstruction := func(cause error) (factoryOutputObject, []factoryOutputPathIdentity, error) {
			rollbackErr := construction.rollback()
			closeParents()
			if rollbackErr != nil {
				return nil, nil, errors.Join(cause, fmt.Errorf("rollback private --out staging construction: %w", rollbackErr))
			}
			return nil, nil, cause
		}
		if hooks.nonWindowsConstructionStep != nil {
			if hookErr := hooks.nonWindowsConstructionStep("after_stage_directory_create"); hookErr != nil {
				return failConstruction(hookErr)
			}
		}
		stageDirFD, err = unix.Openat(parentFD, stageDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return failConstruction(fmt.Errorf("retain private --out staging container: %w", err))
		}
		construction.stageDirFD = stageDirFD
		stageDir = os.NewFile(uintptr(stageDirFD), filepath.Join(filepath.Dir(path.absolute), stageDirName))
		if stageDir == nil {
			return failConstruction(fmt.Errorf("retain private --out staging container handle"))
		}
		construction.stageDir = stageDir
		if hooks.nonWindowsConstructionStep != nil {
			if hookErr := hooks.nonWindowsConstructionStep("after_stage_directory_open"); hookErr != nil {
				return failConstruction(hookErr)
			}
		}
		stageDirInfo, err = stageDir.Stat()
		if err != nil || !stageDirInfo.IsDir() {
			return failConstruction(fmt.Errorf("inspect private --out staging container: %w", err))
		}
		stageName = "receipt"
		fd, err = unix.Openat(stageDirFD, stageName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return failConstruction(fmt.Errorf("create file in private --out staging container: %w", err))
		}
		construction.fileFD = fd
		if err := unix.Fstat(fd, &construction.fileIdentity); err != nil {
			return failConstruction(fmt.Errorf("capture private --out stage identity: %w", err))
		}
		if hooks.nonWindowsConstructionStep != nil {
			if hookErr := hooks.nonWindowsConstructionStep("after_stage_file_create"); hookErr != nil {
				return failConstruction(hookErr)
			}
		}
		cleanupFD, err = unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return failConstruction(fmt.Errorf("atomically retain CLOEXEC cleanup handle for staged --out target: %w", err))
		}
		construction.cleanupFD = cleanupFD
		if hooks.nonWindowsConstructionStep != nil {
			if hookErr := hooks.nonWindowsConstructionStep("after_cleanup_handle_duplicate"); hookErr != nil {
				return failConstruction(hookErr)
			}
		}
		construction.fileFD = -1
		construction.cleanupFD = -1
	}
	if !namedStage {
		cleanupFD, err = unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			_ = unix.Close(fd)
			closeParents()
			return nil, nil, fmt.Errorf("atomically retain CLOEXEC cleanup handle for staged --out target: %w", err)
		}
	}
	displayName := path.absolute + " (private unnamed stage)"
	if namedStage {
		displayName = filepath.Join(filepath.Dir(path.absolute), stageDirName, stageName)
	}
	file := os.NewFile(uintptr(fd), displayName)
	if file == nil {
		_ = unix.Close(cleanupFD)
		_ = unix.Close(fd)
		if stageDir != nil {
			_ = stageDir.Close()
		}
		closeParents()
		return nil, nil, fmt.Errorf("retain staged --out target handle")
	}
	return &nonWindowsFactoryOutput{
		file:         file,
		cleanupFD:    cleanupFD,
		parentFD:     parentFD,
		stageDir:     stageDir,
		stageDirFD:   stageDirFD,
		stageDirName: stageDirName,
		stageDirInfo: stageDirInfo,
		stageName:    stageName,
		finalName:    path.leaf,
		parents:      parents,
	}, identities, nil
}

func (output *nonWindowsFactoryOutput) dataFile() *os.File { return output.file }

func (output *nonWindowsFactoryOutput) stagedName() string {
	if output.stageDirName == "" {
		return ""
	}
	return filepath.Join(output.stageDirName, output.stageName)
}

func (output *nonWindowsFactoryOutput) syncData() error {
	return syncNonWindowsFactoryFile(int(output.file.Fd()))
}

func (output *nonWindowsFactoryOutput) publish() error {
	if output.stageDir != nil {
		if err := output.validateNamedStageIdentity(); err != nil {
			return err
		}
		if err := syncNonWindowsFactoryDirectory(output.stageDirFD); err != nil {
			return fmt.Errorf("durably sync private --out staging container: %w", err)
		}
	}
	if err := publishNonWindowsFactoryOutput(output.parentFD, output.stageDirFD, int(output.file.Fd()), output.stageName, output.finalName); err != nil {
		return err
	}
	output.published = true
	if err := output.removeNamedStageContainer(); err != nil {
		return err
	}
	if err := syncNonWindowsFactoryDirectory(output.parentFD); err != nil {
		return fmt.Errorf("durably sync --out parent after atomic publish and stage-name removal: %w", err)
	}
	return nil
}

func (output *nonWindowsFactoryOutput) closeData() error {
	if output.dataClosed {
		return nil
	}
	output.dataClosed = true
	return output.file.Close()
}

func (output *nonWindowsFactoryOutput) abort() error {
	if output.stageDir == nil || output.published {
		return nil
	}
	// Erase the exact opened inode first. Even if an attacker moved it and put an
	// unrelated object at the mutable inner name, no receipt bytes survive.
	if err := output.file.Truncate(0); err != nil {
		return fmt.Errorf("erase aborted private --out stage through retained handle: %w", err)
	}
	if err := output.file.Sync(); err != nil {
		return fmt.Errorf("sync erased private --out stage: %w", err)
	}
	if err := output.validateNamedStageIdentity(); err != nil {
		return nil // a swapped unrelated inner object is never unlinked
	}
	if err := unix.Unlinkat(output.stageDirFD, output.stageName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove erased private --out stage: %w", err)
	}
	return output.removeNamedStageContainer()
}

func (output *nonWindowsFactoryOutput) validateNamedStageIdentity() error {
	currentFD, err := unix.Openat(output.stageDirFD, output.stageName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open private --out stage name for identity validation: %w", err)
	}
	current := os.NewFile(uintptr(currentFD), output.stageName)
	if current == nil {
		_ = unix.Close(currentFD)
		return fmt.Errorf("retain private --out stage identity handle")
	}
	defer current.Close()
	want, err := output.file.Stat()
	if err != nil {
		return err
	}
	got, err := current.Stat()
	if err != nil {
		return err
	}
	if !got.Mode().IsRegular() || !os.SameFile(want, got) {
		return fmt.Errorf("private --out stage name changed identity")
	}
	return nil
}

func (output *nonWindowsFactoryOutput) removeNamedStageContainer() error {
	if output.stageDir == nil || output.stageDirName == "" {
		return nil
	}
	currentFD, err := unix.Openat(output.parentFD, output.stageDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("open private --out staging container for cleanup: %w", err)
	}
	current := os.NewFile(uintptr(currentFD), output.stageDirName)
	if current == nil {
		_ = unix.Close(currentFD)
		return fmt.Errorf("retain private --out staging cleanup handle")
	}
	got, statErr := current.Stat()
	_ = current.Close()
	if statErr != nil || !got.IsDir() || !os.SameFile(output.stageDirInfo, got) {
		return nil // never remove an attacker-swapped unrelated container
	}
	if err := unix.Unlinkat(output.parentFD, output.stageDirName, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove private --out staging container: %w", err)
	}
	return nil
}

func (output *nonWindowsFactoryOutput) release() error {
	if output.released {
		return nil
	}
	output.released = true
	var releaseErrors []error
	if err := output.closeData(); err != nil {
		releaseErrors = append(releaseErrors, err)
	}
	if output.cleanupFD >= 0 {
		if err := unix.Close(output.cleanupFD); err != nil {
			releaseErrors = append(releaseErrors, err)
		}
		output.cleanupFD = -1
	}
	if output.stageDir != nil {
		if err := output.stageDir.Close(); err != nil {
			releaseErrors = append(releaseErrors, err)
		}
		output.stageDir = nil
	}
	for index := len(output.parents) - 1; index >= 0; index-- {
		if err := output.parents[index].Close(); err != nil {
			releaseErrors = append(releaseErrors, err)
		}
	}
	return errors.Join(releaseErrors...)
}

func factoryOutputFileInfoHasReparsePoint(os.FileInfo) bool { return false }
