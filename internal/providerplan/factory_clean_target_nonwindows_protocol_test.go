//go:build !windows

package providerplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNonWindowsFactoryCleanTargetDirectoryRejectsPrivateStageSwap(t *testing.T) {
	parent := t.TempDir()
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parentFD)
	finalPath := filepath.Join(parent, "clean-source")
	retainedStage := filepath.Join(parent, "retained-private-stage")
	var stageName string
	created, _, err := createNonWindowsFactoryCleanTargetDirectory(
		parentFD,
		"clean-source",
		finalPath,
		nonWindowsFactoryCleanTargetDirectoryTestHooks{
			afterStageOpen: func(name string) error {
				stageName = name
				stagePath := filepath.Join(parent, name)
				if err := os.Rename(stagePath, retainedStage); err != nil {
					return err
				}
				return os.Mkdir(stagePath, 0o700)
			},
		},
	)
	if created != nil {
		_ = created.close()
		t.Fatal("private stage substitution returned a retained directory")
	}
	if err == nil || !strings.Contains(err.Error(), "changed identity") {
		t.Fatalf("private stage substitution error = %v, want identity refusal", err)
	}
	if stageName == "" {
		t.Fatal("private stage mutation hook did not run")
	}
	if _, err := os.Lstat(finalPath); !os.IsNotExist(err) {
		t.Fatalf("private stage substitution published a final directory: %v", err)
	}
	for _, path := range []string{retainedStage, filepath.Join(parent, stageName)} {
		if info, err := os.Lstat(path); err != nil || !info.IsDir() {
			t.Fatalf("identity-safe refusal removed or changed %q: %v / %v", path, info, err)
		}
	}
}

func TestNonWindowsFactoryCleanTargetDirectoryPublishIsNoReplace(t *testing.T) {
	parent := t.TempDir()
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parentFD)
	finalPath := filepath.Join(parent, "clean-source")
	var stageName string
	created, _, err := createNonWindowsFactoryCleanTargetDirectory(
		parentFD,
		"clean-source",
		finalPath,
		nonWindowsFactoryCleanTargetDirectoryTestHooks{
			beforePublish: func(name string) error {
				stageName = name
				return os.Mkdir(finalPath, 0o700)
			},
		},
	)
	if created != nil {
		_ = created.close()
		t.Fatal("preexisting final directory was replaced")
	}
	if err == nil || !strings.Contains(err.Error(), "publish private clean target directory stage") {
		t.Fatalf("preexisting final publication error = %v, want no-replace refusal", err)
	}
	if stageName == "" {
		t.Fatal("before-publish hook did not run")
	}
	if info, err := os.Lstat(finalPath); err != nil || !info.IsDir() {
		t.Fatalf("preexisting final directory changed: %v / %v", info, err)
	}
	if _, err := os.Lstat(filepath.Join(parent, stageName)); !os.IsNotExist(err) {
		t.Fatalf("exact private stage cleanup result = %v, want absent", err)
	}
}
