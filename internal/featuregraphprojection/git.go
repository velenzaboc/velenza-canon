package featuregraphprojection

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// GitReader reads one configured, immutable Git blob. It accepts only an
// object hash (never a revision expression or ref), disables replacement
// objects, and checks the exact tree entry before reading its content.
type GitReader struct{}

func (GitReader) ReadArtifact(ctx context.Context, a Artifact, r Repository, limit int) ([]byte, error) {
	if limit <= 0 || r.GitDir == "" || !filepath.IsAbs(r.GitDir) || filepath.Clean(r.GitDir) != r.GitDir {
		return nil, fmt.Errorf("invalid immutable artifact reader configuration")
	}
	if !fullObjectHash(a.Commit) {
		return nil, fmt.Errorf("artifact commit must be a lowercase 40- or 64-character object hash")
	}
	if !canonicalArtifactPath(a.Path) {
		return nil, fmt.Errorf("unsafe artifact path")
	}
	if !allowedArtifactPath(a.Path, r.PathPrefixes) {
		return nil, fmt.Errorf("artifact path outside allowed prefixes")
	}
	if !allowedRole(a.Role, r.Roles) {
		return nil, fmt.Errorf("artifact role not allowed")
	}
	objectType, err := gitOutput(ctx, r.GitDir, "cat-file", "-t", a.Commit)
	if err != nil || strings.TrimSpace(string(objectType)) != "commit" {
		return nil, fmt.Errorf("artifact commit is not an immutable commit object")
	}

	entry, err := gitOutput(ctx, r.GitDir, "ls-tree", "-z", a.Commit, "--", a.Path)
	if err != nil {
		return nil, fmt.Errorf("inspect immutable git tree: %w", err)
	}
	objectID, err := regularBlobEntry(entry, a.Path)
	if err != nil {
		return nil, err
	}
	sizeText, err := gitOutput(ctx, r.GitDir, "cat-file", "-s", objectID)
	if err != nil {
		return nil, fmt.Errorf("inspect immutable git blob size: %w", err)
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(sizeText)), 10, 64)
	if err != nil || size < 0 || size > int64(limit) {
		return nil, fmt.Errorf("artifact exceeds byte cap")
	}

	cmd := gitCommand(ctx, r.GitDir, "cat-file", "blob", objectID)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open immutable git blob: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("open immutable git blob: %w", err)
	}
	b, readErr := io.ReadAll(io.LimitReader(stdout, int64(limit)+1))
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("read immutable git blob: %w", readErr)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("read immutable git blob: %w", waitErr)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("artifact exceeds byte cap")
	}
	return b, nil
}

func gitCommand(ctx context.Context, gitDir string, args ...string) *exec.Cmd {
	args = append([]string{"--no-replace-objects", "--git-dir=" + gitDir}, args...)
	return exec.CommandContext(ctx, "git", args...)
}

func gitOutput(ctx context.Context, gitDir string, args ...string) ([]byte, error) {
	return gitCommand(ctx, gitDir, args...).Output()
}

func fullObjectHash(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func canonicalArtifactPath(value string) bool {
	return value != "" && !path.IsAbs(value) && path.Clean(value) == value &&
		!strings.HasPrefix(value, "./") && !strings.Contains(value, "\\") &&
		value != ".." && !strings.HasPrefix(value, "../") && !strings.Contains(value, "/../") &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func allowedArtifactPath(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if !canonicalArtifactPath(prefix) {
			continue
		}
		if value == prefix || strings.HasPrefix(value, prefix+"/") {
			return true
		}
	}
	return false
}

func allowedRole(role string, roles []string) bool {
	if role == "" {
		return false
	}
	for _, allowed := range roles {
		if role == allowed {
			return true
		}
	}
	return false
}

func regularBlobEntry(raw []byte, wantPath string) (string, error) {
	entries := strings.Split(string(raw), "\x00")
	if len(entries) != 2 || entries[0] == "" || entries[1] != "" {
		return "", fmt.Errorf("immutable git tree did not return exactly one artifact")
	}
	parts := strings.SplitN(entries[0], "\t", 2)
	if len(parts) != 2 || parts[1] != wantPath {
		return "", fmt.Errorf("immutable git tree returned a different artifact")
	}
	meta := strings.Fields(parts[0])
	if len(meta) != 3 || (meta[0] != "100644" && meta[0] != "100755") || meta[1] != "blob" || !fullObjectHash(meta[2]) {
		return "", fmt.Errorf("artifact must be a regular Git blob")
	}
	return meta[2], nil
}
