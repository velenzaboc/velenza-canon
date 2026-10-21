//go:build !windows

package providerplan

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func installFactoryOutputRedirect(path string, target string) error {
	return os.Symlink(target, path)
}

func TestWriteFactoryReceiptExclusiveRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked-parent")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeFactoryReceiptExclusive(filepath.Join(link, "receipt.json"), []byte("receipt")); err == nil {
		t.Fatal("symlink output parent was accepted")
	}
	if _, err := os.Lstat(filepath.Join(target, "receipt.json")); !os.IsNotExist(err) {
		t.Fatalf("symlink refusal wrote into target directory: %v", err)
	}
}

func TestWriteFactoryReceiptExclusiveAbortNeverUnlinksSwappedStageName(t *testing.T) {
	parent := t.TempDir()
	finalPath := filepath.Join(parent, "factory-receipt.json")
	quarantinedStage := filepath.Join(parent, "original-private-stage")
	wantSentinel := []byte("unrelated sentinel must survive")
	var swappedName string
	err := writeFactoryReceiptExclusiveWithHooks(
		finalPath,
		[]byte("receipt bytes"),
		factoryOutputTestHooks{
			forceNamedStage: true,
			afterStageCreate: func(stagedName string) error {
				if stagedName == "" {
					return fmt.Errorf("forced named stage has no name")
				}
				swappedName = filepath.Join(parent, stagedName)
				if err := os.Rename(swappedName, quarantinedStage); err != nil {
					return err
				}
				if err := os.WriteFile(swappedName, wantSentinel, 0o600); err != nil {
					return err
				}
				return fmt.Errorf("force abort after stage-name swap")
			},
		},
	)
	if err == nil {
		t.Fatal("forced abort unexpectedly succeeded")
	}
	got, err := os.ReadFile(swappedName)
	if err != nil {
		t.Fatalf("read unrelated sentinel after abort: %v", err)
	}
	if !bytes.Equal(got, wantSentinel) {
		t.Fatalf("unrelated sentinel = %q, want %q", got, wantSentinel)
	}
	if _, err := os.Lstat(finalPath); !os.IsNotExist(err) {
		t.Fatalf("forced pre-publish abort created final leaf: %v", err)
	}
}

func TestNonWindowsFactoryOutputCleanupDescriptorIsCLOEXEC(t *testing.T) {
	path, err := resolveFactoryOutputPath(filepath.Join(t.TempDir(), "factory-receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	staged, _, err := createFactoryOutputExclusive(path, factoryOutputTestHooks{forceNamedStage: true})
	if err != nil {
		t.Fatal(err)
	}
	output, ok := staged.(*nonWindowsFactoryOutput)
	if !ok {
		t.Fatalf("staged output type = %T", staged)
	}
	defer func() {
		_ = output.abort()
		_ = output.release()
	}()
	flags, err := unix.FcntlInt(uintptr(output.cleanupFD), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("cleanup descriptor flags = %#x, FD_CLOEXEC absent", flags)
	}
}

func TestNonWindowsFactoryOutputConstructionFailureRollsBackExactNamedStage(t *testing.T) {
	for _, step := range []string{
		"after_stage_directory_create",
		"after_stage_directory_open",
		"after_stage_file_create",
		"after_cleanup_handle_duplicate",
	} {
		t.Run(step, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "factory-receipt.json")
			injected := fmt.Errorf("injected %s failure", step)
			err := writeFactoryReceiptExclusiveWithHooks(path, []byte("receipt"), factoryOutputTestHooks{
				forceNamedStage: true,
				nonWindowsConstructionStep: func(current string) error {
					if current == step {
						return injected
					}
					return nil
				},
			})
			if err == nil || !errors.Is(err, injected) {
				t.Fatalf("construction failure = %v, want injected failure", err)
			}
			entries, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("construction failure at %s left output/stage residue: %v", step, entries)
			}
		})
	}
}
