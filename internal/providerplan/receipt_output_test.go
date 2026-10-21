package providerplan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteFactoryReceiptExclusiveCreatesOnceAndRefusesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "factory-receipt.json")
	want := []byte("{\"receipt\":\"candidate-only\"}\n")
	if err := writeFactoryReceiptExclusive(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("persisted receipt = %q, want %q", got, want)
	}
	if err := writeFactoryReceiptExclusive(path, []byte("replacement")); err == nil {
		t.Fatal("existing receipt was replaced")
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("replacement refusal changed the existing receipt")
	}
}

func TestWriteFactoryReceiptExclusiveRefusesInputHardLinkAlias(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "immutable-input.json")
	want := []byte("immutable input bytes")
	if err := os.WriteFile(input, want, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "receipt.json")
	if err := os.Link(input, output); err != nil {
		t.Fatalf("create hard-link alias fixture: %v", err)
	}
	if err := writeFactoryReceiptExclusive(output, []byte("receipt")); err == nil {
		t.Fatal("hard-link input alias was truncated")
	}
	got, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("hard-link alias refusal changed immutable input bytes")
	}
}

func TestWriteFactoryReceiptExclusiveParentReplacementCannotRedirectCreate(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "output-parent")
	retainedParent := filepath.Join(root, "retained-output-parent")
	redirectTarget := filepath.Join(root, "redirect-target")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(redirectTarget, 0o700); err != nil {
		t.Fatal(err)
	}

	leaf := "factory-receipt.json"
	redirectLeaf := filepath.Join(redirectTarget, leaf)
	parentReplaced := false
	stageObserved := false
	err := writeFactoryReceiptExclusiveWithHooks(
		filepath.Join(parent, leaf),
		[]byte("must never reach redirect target"),
		factoryOutputTestHooks{
			afterParentOpen: func() error {
				if err := os.Rename(parent, retainedParent); err != nil {
					return err
				}
				if err := installFactoryOutputRedirect(parent, redirectTarget); err != nil {
					return err
				}
				parentReplaced = true
				return nil
			},
			afterStageCreate: func(stagedName string) error {
				if _, err := os.Lstat(redirectLeaf); !os.IsNotExist(err) {
					return fmt.Errorf("redirect target received a final object before publish: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(retainedParent, leaf)); !os.IsNotExist(err) {
					return fmt.Errorf("retained parent received final leaf before publish: %v", err)
				}
				if stagedName != "" {
					info, err := os.Lstat(filepath.Join(retainedParent, stagedName))
					if err != nil {
						return fmt.Errorf("retained parent does not contain private handle-relative stage: %w", err)
					}
					if !info.Mode().IsRegular() || info.Size() != 0 {
						return fmt.Errorf("private stage mode/size = %v/%d, want regular/0", info.Mode(), info.Size())
					}
				}
				stageObserved = true
				return nil
			},
		},
	)
	if err == nil {
		t.Fatal("parent replacement was accepted")
	}
	if !parentReplaced || !stageObserved {
		t.Fatalf("adversarial boundary hooks ran = parent:%v stage:%v", parentReplaced, stageObserved)
	}
	if _, err := os.Lstat(redirectLeaf); !os.IsNotExist(err) {
		t.Fatalf("redirect target received output: %v", err)
	}
}

func TestWriteFactoryReceiptExclusiveCrashBeforePublishLeavesFinalAbsentAndRestartSucceeds(t *testing.T) {
	const helperMode = "FACTORY_OUTPUT_CRASH_HELPER"
	const helperPath = "FACTORY_OUTPUT_CRASH_PATH"
	if os.Getenv(helperMode) == "1" {
		path := os.Getenv(helperPath)
		err := writeFactoryReceiptExclusiveWithHooks(
			path,
			[]byte("fully staged but never published"),
			factoryOutputTestHooks{
				beforePublish: func() error {
					_, _ = fmt.Fprintln(os.Stdout, "READY-BEFORE-PUBLISH")
					select {}
				},
			},
		)
		t.Fatalf("crash helper returned before being killed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "factory-receipt.json")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWriteFactoryReceiptExclusiveCrashBeforePublishLeavesFinalAbsentAndRestartSucceeds$")
	command.Env = append(os.Environ(), helperMode+"=1", helperPath+"="+path)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "READY-BEFORE-PUBLISH" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("crash helper readiness = %q, %v; stderr=%s", strings.TrimSpace(line), err, stderr.String())
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("final leaf existed before publish: %v", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("kill staged helper: %v", err)
	}
	_ = command.Wait()

	want := []byte("restart publishes complete receipt")
	if err := writeFactoryReceiptExclusive(path, want); err != nil {
		t.Fatalf("restart after pre-publish kill: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("restart receipt = %q, want %q", got, want)
	}
}
