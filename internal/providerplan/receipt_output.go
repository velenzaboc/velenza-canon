package providerplan

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type factoryOutputPath struct {
	absolute   string
	root       string
	leaf       string
	components []string
}

type factoryOutputPathIdentity struct {
	path     string
	identity providerInputStableFileIdentity
}

// factoryOutputObject retains the resolved parent chain and a private staged
// object. The final leaf is not created until publish atomically installs the
// fully written and synced staged object with strict no-replace semantics.
type factoryOutputObject interface {
	dataFile() *os.File
	stagedName() string
	syncData() error
	publish() error
	closeData() error
	abort() error
	release() error
}

// factoryOutputTestHooks are explicit arguments rather than mutable package
// globals so deterministic adversarial tests remain race-detector safe.
type factoryOutputTestHooks struct {
	afterParentOpen             func() error
	afterStageCreate            func(stagedName string) error
	beforePublish               func() error
	windowsPostRenameDurability func() error
	nonWindowsConstructionStep  func(step string) error
	forceNamedStage             bool
}

func writeFactoryReceiptExclusive(path string, raw []byte) error {
	return writeFactoryReceiptExclusiveWithHooks(path, raw, factoryOutputTestHooks{})
}

// WriteReceiptExclusive publishes a body-free provider receipt exactly once.
// All provider CLIs use this one crash-safe, link/reparse-safe implementation.
func WriteReceiptExclusive(path string, raw []byte) error {
	return writeFactoryReceiptExclusive(path, raw)
}

func writeFactoryReceiptExclusiveWithHooks(path string, raw []byte, hooks factoryOutputTestHooks) error {
	if len(raw) == 0 {
		return fmt.Errorf("provider receipt bytes are empty")
	}
	resolved, err := resolveFactoryOutputPath(path)
	if err != nil {
		return err
	}

	output, parents, err := createFactoryOutputExclusive(resolved, hooks)
	if err != nil {
		return fmt.Errorf("stage new --out target %q: %w", resolved.absolute, err)
	}
	abort := func(cause error) error {
		joined := []error{cause}
		if abortErr := output.abort(); abortErr != nil {
			joined = append(joined, fmt.Errorf("abort staged --out target %q: %w", resolved.absolute, abortErr))
		}
		if releaseErr := output.release(); releaseErr != nil {
			joined = append(joined, fmt.Errorf("release staged --out target handles %q: %w", resolved.absolute, releaseErr))
		}
		return errors.Join(joined...)
	}

	if hooks.afterStageCreate != nil {
		if err := hooks.afterStageCreate(output.stagedName()); err != nil {
			return abort(fmt.Errorf("after --out stage creation test hook: %w", err))
		}
	}

	file := output.dataFile()
	created, err := file.Stat()
	if err != nil {
		return abort(fmt.Errorf("inspect staged --out target %q: %w", resolved.absolute, err))
	}
	if !created.Mode().IsRegular() || factoryOutputFileInfoHasReparsePoint(created) {
		return abort(fmt.Errorf("staged --out target %q is not a stable regular file", resolved.absolute))
	}
	createdIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return abort(fmt.Errorf("derive staged --out target identity %q: %w", resolved.absolute, err))
	}
	written, err := file.Write(raw)
	if err != nil || written != len(raw) {
		if err == nil {
			err = fmt.Errorf("short write: wrote %d of %d bytes", written, len(raw))
		}
		return abort(fmt.Errorf("write staged --out target %q: %w", resolved.absolute, err))
	}
	if err := output.syncData(); err != nil {
		return abort(fmt.Errorf("sync staged --out target %q: %w", resolved.absolute, err))
	}
	afterWrite, err := file.Stat()
	if err != nil {
		return abort(fmt.Errorf("reinspect staged --out target %q: %w", resolved.absolute, err))
	}
	afterWriteIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return abort(fmt.Errorf("rederive staged --out target identity %q: %w", resolved.absolute, err))
	}
	if createdIdentity != afterWriteIdentity || afterWrite.Size() != int64(len(raw)) {
		return abort(fmt.Errorf("staged --out target %q changed identity or size while writing", resolved.absolute))
	}
	if _, err := file.Seek(0, 0); err != nil {
		return abort(fmt.Errorf("rewind staged --out target %q: %w", resolved.absolute, err))
	}
	persisted, err := io.ReadAll(io.LimitReader(file, int64(len(raw))+1))
	if err != nil {
		return abort(fmt.Errorf("read back staged --out target %q: %w", resolved.absolute, err))
	}
	if !bytes.Equal(persisted, raw) {
		return abort(fmt.Errorf("staged --out target %q differs from the sealed receipt bytes", resolved.absolute))
	}
	if err := validateFactoryOutputParents(parents); err != nil {
		return abort(err)
	}
	if hooks.beforePublish != nil {
		if err := hooks.beforePublish(); err != nil {
			return abort(fmt.Errorf("before --out publish test hook: %w", err))
		}
	}
	if err := validateFactoryOutputParents(parents); err != nil {
		return abort(err)
	}
	if err := output.publish(); err != nil {
		return abort(fmt.Errorf("publish new --out target %q: %w", resolved.absolute, err))
	}
	if err := validateFactoryOutputIdentity(resolved.absolute, parents, createdIdentity); err != nil {
		return abort(err)
	}
	if err := output.closeData(); err != nil {
		return abort(fmt.Errorf("close new --out target %q: %w", resolved.absolute, err))
	}
	if err := output.release(); err != nil {
		return fmt.Errorf("release new --out target handles %q: %w", resolved.absolute, err)
	}
	return nil
}

func newFactoryOutputStagedName() (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("generate private --out stage identity: %w", err)
	}
	return ".factory-output-stage-" + hex.EncodeToString(entropy[:]) + ".tmp", nil
}

func resolveFactoryOutputPath(path string) (factoryOutputPath, error) {
	if strings.TrimSpace(path) == "" || path != strings.TrimSpace(path) {
		return factoryOutputPath{}, fmt.Errorf("--out path is empty or padded")
	}
	if err := validateFactoryOutputRawPath(path); err != nil {
		return factoryOutputPath{}, fmt.Errorf("--out path %q: %w", path, err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return factoryOutputPath{}, fmt.Errorf("resolve --out path %q: %w", path, err)
	}
	absolute = filepath.Clean(absolute)
	parent := filepath.Dir(absolute)
	leaf := filepath.Base(absolute)
	if parent == absolute || leaf == "." || leaf == string(filepath.Separator) || leaf == "" {
		return factoryOutputPath{}, fmt.Errorf("--out path %q does not name a file", path)
	}

	volume := filepath.VolumeName(parent)
	root := volume + string(filepath.Separator)
	if volume == "" {
		root = string(filepath.Separator)
	}
	remainder := strings.TrimPrefix(parent, root)
	if remainder == parent {
		return factoryOutputPath{}, fmt.Errorf("resolve --out parent root %q", parent)
	}
	var components []string
	if remainder != "" {
		components = strings.Split(remainder, string(filepath.Separator))
		for _, component := range components {
			if component == "" || component == "." || component == ".." {
				return factoryOutputPath{}, fmt.Errorf("--out path %q has an invalid parent component", path)
			}
		}
	}
	return factoryOutputPath{
		absolute:   absolute,
		root:       root,
		leaf:       leaf,
		components: components,
	}, nil
}

func validateFactoryOutputParents(parents []factoryOutputPathIdentity) error {
	for _, parent := range parents {
		file, err := openFactoryOutputDirectoryPathNoFollow(parent.path)
		if err != nil {
			return fmt.Errorf("--out parent %q changed identity or became a link/reparse point", parent.path)
		}
		identity, identityErr := stableProviderInputFileIdentity(file)
		closeErr := file.Close()
		if identityErr != nil || closeErr != nil || identity != parent.identity {
			return fmt.Errorf("--out parent %q changed identity or its 128-bit identity could not be verified", parent.path)
		}
	}
	return nil
}

func validateFactoryOutputIdentity(path string, parents []factoryOutputPathIdentity, createdIdentity providerInputStableFileIdentity) error {
	if err := validateFactoryOutputParents(parents); err != nil {
		return err
	}
	file, err := openStableProviderInput(path, "--out target")
	if err != nil {
		return fmt.Errorf("reinspect --out target %q: %w", path, err)
	}
	defer file.Close()
	leaf, err := file.Stat()
	if err != nil {
		return fmt.Errorf("reinspect opened --out target %q: %w", path, err)
	}
	leafIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return fmt.Errorf("derive final --out target identity %q: %w", path, err)
	}
	if !leaf.Mode().IsRegular() || factoryOutputFileInfoHasReparsePoint(leaf) || leafIdentity != createdIdentity {
		return fmt.Errorf("--out target %q changed identity or became a link/reparse point", path)
	}
	return nil
}
