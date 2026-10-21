package providerplan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// factorySourceOutputFile is one member of the closed source-package output
// roster. RelativePath is always slash-separated and Raw is copied before any
// filesystem operation, so caller mutation cannot change the published bytes.
type factorySourceOutputFile struct {
	RelativePath string
	Raw          []byte
}

// sourcePackageOutputHooks are explicit arguments rather than package globals
// so hostile-filesystem tests remain deterministic under the race detector.
type sourcePackageOutputHooks struct {
	afterParentOpen    func() error
	afterStageCreate   func(stagePath string) error
	beforeFileWrite    func(relative string) error
	afterFileDataWrite func(relative string) error
	beforeFileSync     func(relative string) error
	afterFileSync      func(relative string) error
	afterFileWrite     func(relative string) error
	beforePublish      func(stagePath string) error
	afterPrepare       func(stagePath string) error
	afterPublish       func(rootPath string) error
}

type privateFactorySourceOutputHooks struct {
	tempRoot         string
	afterStageCreate func(stagePath string) error
}

type preparedSourcePackageOutputFile struct {
	relative   string
	components []string
	raw        []byte
}

type sourcePackageOutputStage interface {
	stagePath() string
	writeFile(preparedSourcePackageOutputFile) error
	seal([]preparedSourcePackageOutputFile) error
	preparePublish() error
	validatePrepared([]preparedSourcePackageOutputFile) error
	validatePrivateRoot() error
	preparePrivateCallback() error
	publish() error
	validatePublished([]preparedSourcePackageOutputFile) error
	abort() error
	release() error
}

// publishSourcePackageOutputExclusive privately constructs a complete output
// tree and atomically exposes it at an absent final root. It never merges with
// or replaces an existing filesystem object.
func publishFactorySourceOutputDirectoryExclusive(root string, roster []factorySourceOutputFile) error {
	return publishFactorySourceOutputDirectoryExclusiveWithHooks(root, roster, sourcePackageOutputHooks{})
}

// withPrivateFactorySourceOutputDirectory constructs an exact source-output
// tree under a fresh system-temp coordinate for the duration of callback. The
// tree is never published, and every publisher-owned file identity is erased
// during cleanup on both success and failure.
func withPrivateFactorySourceOutputDirectory(files []factorySourceOutputFile, callback func(root string) error) error {
	return withPrivateFactorySourceOutputDirectoryWithHooks(files, callback, privateFactorySourceOutputHooks{})
}

func withPrivateFactorySourceOutputDirectoryWithHooks(files []factorySourceOutputFile, callback func(root string) error, hooks privateFactorySourceOutputHooks) error {
	if callback == nil {
		return fmt.Errorf("private factory source-output callback is nil")
	}
	prepared, err := prepareSourcePackageOutputRoster(files)
	if err != nil {
		return err
	}
	tempRoot := hooks.tempRoot
	if tempRoot == "" {
		tempRoot = os.TempDir()
	}
	tempRoot = filepath.Clean(tempRoot)
	coordinate, err := newPrivateFactorySourceOutputCoordinate(tempRoot)
	if err != nil {
		return err
	}
	resolved, err := resolveFactoryOutputPath(coordinate)
	if err != nil {
		return fmt.Errorf("resolve private factory source-output coordinate: %w", err)
	}
	stage, parents, err := createSourcePackageOutputStage(resolved, sourcePackageOutputHooks{})
	if err != nil {
		return fmt.Errorf("create private factory source-output tree under %q: %w", tempRoot, err)
	}
	finish := func(cause error) error {
		var joined []error
		if cause != nil {
			joined = append(joined, cause)
		}
		if abortErr := stage.abort(); abortErr != nil {
			joined = append(joined, fmt.Errorf("erase private factory source-output tree: %w", abortErr))
		}
		if releaseErr := stage.release(); releaseErr != nil {
			joined = append(joined, fmt.Errorf("release private factory source-output handles: %w", releaseErr))
		}
		return errors.Join(joined...)
	}
	if hooks.afterStageCreate != nil {
		if err := hooks.afterStageCreate(stage.stagePath()); err != nil {
			return finish(fmt.Errorf("after private factory source-output stage creation test hook: %w", err))
		}
	}
	for _, entry := range prepared {
		if err := stage.writeFile(entry); err != nil {
			return finish(fmt.Errorf("write private factory source-output file %q: %w", entry.relative, err))
		}
	}
	if err := stage.seal(prepared); err != nil {
		return finish(fmt.Errorf("seal private factory source-output tree: %w", err))
	}
	if err := stage.validatePrivateRoot(); err != nil {
		return finish(err)
	}
	if err := validateFactoryOutputParents(parents); err != nil {
		return finish(err)
	}
	if err := stage.preparePrivateCallback(); err != nil {
		return finish(fmt.Errorf("prepare retained private source-output handles for callback access: %w", err))
	}
	if err := stage.validatePrivateRoot(); err != nil {
		return finish(err)
	}
	if err := stage.validatePrepared(prepared); err != nil {
		return finish(fmt.Errorf("revalidate private source-output tree before callback: %w", err))
	}
	callbackErr := callback(stage.stagePath())
	if callbackErr != nil {
		return finish(fmt.Errorf("private factory source-output callback: %w", callbackErr))
	}
	if err := stage.validatePrivateRoot(); err != nil {
		return finish(err)
	}
	if err := stage.validatePrepared(prepared); err != nil {
		return finish(fmt.Errorf("revalidate private factory source-output tree after callback: %w", err))
	}
	if err := validateFactoryOutputParents(parents); err != nil {
		return finish(err)
	}
	return finish(nil)
}

func newPrivateFactorySourceOutputCoordinate(tempRoot string) (string, error) {
	if strings.TrimSpace(tempRoot) == "" || tempRoot != strings.TrimSpace(tempRoot) {
		return "", fmt.Errorf("private factory source-output temp root is empty or padded")
	}
	for attempt := 0; attempt < 16; attempt++ {
		name, err := newFactoryOutputStagedName()
		if err != nil {
			return "", err
		}
		coordinate := filepath.Join(tempRoot, name+".private-root")
		if _, err := os.Lstat(coordinate); os.IsNotExist(err) {
			return coordinate, nil
		} else if err != nil {
			return "", fmt.Errorf("inspect private factory source-output coordinate %q: %w", coordinate, err)
		}
	}
	return "", fmt.Errorf("allocate an absent private factory source-output coordinate under %q", tempRoot)
}

func publishFactorySourceOutputDirectoryExclusiveWithHooks(root string, roster []factorySourceOutputFile, hooks sourcePackageOutputHooks) error {
	prepared, err := prepareSourcePackageOutputRoster(roster)
	if err != nil {
		return err
	}
	if strings.TrimSpace(root) == "" || root != strings.TrimSpace(root) || filepath.Clean(root) != root {
		return fmt.Errorf("source-package output root is empty, padded, or not clean")
	}
	resolved, err := resolveFactoryOutputPath(root)
	if err != nil {
		return fmt.Errorf("resolve source-package output root: %w", err)
	}
	stage, parents, err := createSourcePackageOutputStage(resolved, hooks)
	if err != nil {
		return fmt.Errorf("create private source-package output stage for %q: %w", resolved.absolute, err)
	}
	abort := func(cause error) error {
		joined := []error{cause}
		if abortErr := stage.abort(); abortErr != nil {
			joined = append(joined, fmt.Errorf("abort private source-package output stage for %q: %w", resolved.absolute, abortErr))
		}
		if releaseErr := stage.release(); releaseErr != nil {
			joined = append(joined, fmt.Errorf("release source-package output handles for %q: %w", resolved.absolute, releaseErr))
		}
		return errors.Join(joined...)
	}

	if hooks.afterStageCreate != nil {
		if err := hooks.afterStageCreate(stage.stagePath()); err != nil {
			return abort(fmt.Errorf("after source-package stage creation test hook: %w", err))
		}
	}
	for _, entry := range prepared {
		if hooks.beforeFileWrite != nil {
			if err := hooks.beforeFileWrite(entry.relative); err != nil {
				return abort(fmt.Errorf("before source-package file %q test hook: %w", entry.relative, err))
			}
		}
		if err := stage.writeFile(entry); err != nil {
			return abort(fmt.Errorf("write source-package file %q: %w", entry.relative, err))
		}
		if hooks.afterFileWrite != nil {
			if err := hooks.afterFileWrite(entry.relative); err != nil {
				return abort(fmt.Errorf("after source-package file %q test hook: %w", entry.relative, err))
			}
		}
	}
	if err := stage.seal(prepared); err != nil {
		return abort(fmt.Errorf("seal private source-package output tree: %w", err))
	}
	if err := validateFactoryOutputParents(parents); err != nil {
		return abort(err)
	}
	if hooks.beforePublish != nil {
		if err := hooks.beforePublish(stage.stagePath()); err != nil {
			return abort(fmt.Errorf("before source-package publication test hook: %w", err))
		}
	}
	// Re-seal after the last caller-controlled hook. This is the final exact-byte
	// and closed-roster gate immediately before the atomic no-replace rename.
	if err := stage.seal(prepared); err != nil {
		return abort(fmt.Errorf("reseal private source-package output tree before publication: %w", err))
	}
	if err := validateFactoryOutputParents(parents); err != nil {
		return abort(err)
	}
	if err := stage.preparePublish(); err != nil {
		return abort(fmt.Errorf("prepare sealed source-package output tree for atomic publication: %w", err))
	}
	if hooks.afterPrepare != nil {
		if err := hooks.afterPrepare(stage.stagePath()); err != nil {
			return abort(fmt.Errorf("after source-package prepare-for-publication test hook: %w", err))
		}
	}
	if err := stage.validatePrepared(prepared); err != nil {
		return abort(fmt.Errorf("revalidate source-package output tree after descendant handles closed: %w", err))
	}
	if err := validateFactoryOutputParents(parents); err != nil {
		return abort(err)
	}
	if err := stage.publish(); err != nil {
		return abort(fmt.Errorf("publish source-package output root %q: %w", resolved.absolute, err))
	}
	if hooks.afterPublish != nil {
		if err := hooks.afterPublish(resolved.absolute); err != nil {
			return abort(fmt.Errorf("after source-package publication test hook: %w", err))
		}
	}
	if err := validateFactoryOutputParents(parents); err != nil {
		return abort(err)
	}
	if err := stage.validatePublished(prepared); err != nil {
		return abort(fmt.Errorf("verify published source-package output tree: %w", err))
	}
	if err := stage.release(); err != nil {
		return fmt.Errorf("release published source-package output handles for %q: %w", resolved.absolute, err)
	}
	return nil
}

func prepareSourcePackageOutputRoster(roster []factorySourceOutputFile) ([]preparedSourcePackageOutputFile, error) {
	if len(roster) == 0 {
		return nil, fmt.Errorf("source-package output roster is empty")
	}
	prepared := make([]preparedSourcePackageOutputFile, 0, len(roster))
	for _, entry := range roster {
		relative := entry.RelativePath
		if strings.TrimSpace(relative) == "" || relative != strings.TrimSpace(relative) || strings.IndexByte(relative, 0) >= 0 {
			return nil, fmt.Errorf("source-package output relative path %q is empty, padded, or contains NUL", relative)
		}
		if strings.Contains(relative, `\`) || path.IsAbs(relative) || path.Clean(relative) != relative || relative == "." || filepath.VolumeName(relative) != "" {
			return nil, fmt.Errorf("source-package output path %q is not a clean slash-separated relative file path", relative)
		}
		components := strings.Split(relative, "/")
		for _, component := range components {
			if component == "" || component == "." || component == ".." {
				return nil, fmt.Errorf("source-package output path %q contains an invalid component", relative)
			}
			if err := validateSourcePackageOutputPathComponent(component); err != nil {
				return nil, fmt.Errorf("source-package output path %q: %w", relative, err)
			}
		}
		prepared = append(prepared, preparedSourcePackageOutputFile{
			relative:   relative,
			components: append([]string(nil), components...),
			raw:        append([]byte(nil), entry.Raw...),
		})
	}
	sort.Slice(prepared, func(left, right int) bool { return prepared[left].relative < prepared[right].relative })
	for index := range prepared {
		for prior := 0; prior < index; prior++ {
			if strings.EqualFold(prepared[prior].relative, prepared[index].relative) {
				return nil, fmt.Errorf("source-package output roster contains duplicate or case-fold-alias paths %q and %q", prepared[prior].relative, prepared[index].relative)
			}
			if sourcePackageOutputPathIsFoldedPrefix(prepared[prior].components, prepared[index].components) {
				return nil, fmt.Errorf("source-package output path %q treats file %q as a directory", prepared[index].relative, prepared[prior].relative)
			}
			if sourcePackageOutputPathIsFoldedPrefix(prepared[index].components, prepared[prior].components) {
				return nil, fmt.Errorf("source-package output path %q treats file %q as a directory", prepared[prior].relative, prepared[index].relative)
			}
			sharedDirectories := min(len(prepared[prior].components), len(prepared[index].components)) - 1
			for component := 0; component < sharedDirectories; component++ {
				if !strings.EqualFold(prepared[prior].components[component], prepared[index].components[component]) {
					break
				}
				if prepared[prior].components[component] != prepared[index].components[component] {
					return nil, fmt.Errorf("source-package output roster contains case-fold-alias directory components %q and %q", prepared[prior].components[component], prepared[index].components[component])
				}
			}
		}
	}
	return prepared, nil
}

func sourcePackageOutputPathIsFoldedPrefix(prefix, candidate []string) bool {
	if len(prefix) >= len(candidate) {
		return false
	}
	for index := range prefix {
		if !strings.EqualFold(prefix[index], candidate[index]) {
			return false
		}
	}
	return true
}

func inspectNewSourcePackageOutputFile(file *os.File, label string) (providerInputStableFileIdentity, error) {
	if file == nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("retain source-package file %q", label)
	}
	created, err := file.Stat()
	if err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("inspect new source-package file %q: %w", label, err)
	}
	if !created.Mode().IsRegular() || fileInfoHasReparsePoint(created) {
		return providerInputStableFileIdentity{}, fmt.Errorf("source-package file %q is not a stable regular file", label)
	}
	createdIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("derive new source-package file identity %q: %w", label, err)
	}
	return createdIdentity, nil
}

func writeExactSourcePackageOutputFile(file *os.File, label string, raw []byte, createdIdentity providerInputStableFileIdentity, syncFile func() error) (providerInputStableFileIdentity, error) {
	if file == nil || syncFile == nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("retain source-package file %q and its sync operation", label)
	}
	written, err := io.Copy(file, bytes.NewReader(raw))
	if err != nil || written != int64(len(raw)) {
		if err == nil {
			err = fmt.Errorf("short write: wrote %d of %d bytes", written, len(raw))
		}
		return providerInputStableFileIdentity{}, fmt.Errorf("write source-package file %q: %w", label, err)
	}
	if err := syncFile(); err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("sync source-package file %q: %w", label, err)
	}
	after, err := file.Stat()
	if err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("reinspect source-package file %q: %w", label, err)
	}
	afterIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("rederive source-package file identity %q: %w", label, err)
	}
	if createdIdentity != afterIdentity || after.Size() != int64(len(raw)) {
		return providerInputStableFileIdentity{}, fmt.Errorf("source-package file %q changed identity or size while writing", label)
	}
	if err := verifyExactSourcePackageOutputFile(file, label, raw, afterIdentity); err != nil {
		return providerInputStableFileIdentity{}, err
	}
	return afterIdentity, nil
}

func verifyExactSourcePackageOutputFile(file *os.File, label string, raw []byte, wantIdentity providerInputStableFileIdentity) error {
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("rewind source-package file %q: %w", label, err)
	}
	persisted, err := io.ReadAll(io.LimitReader(file, int64(len(raw))+1))
	if err != nil {
		return fmt.Errorf("read back source-package file %q: %w", label, err)
	}
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return fmt.Errorf("rederive source-package file identity %q: %w", label, err)
	}
	if identity != wantIdentity || !bytes.Equal(persisted, raw) {
		return fmt.Errorf("source-package file %q changed identity or differs from declared bytes", label)
	}
	return nil
}
