package providerplan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type providerInputAdmissionPathIdentity struct {
	key      string
	identity providerInputStableFileIdentity
}

func stableProviderInputPathIdentity(path, label string) (providerInputStableFileIdentity, os.FileInfo, error) {
	file, err := openStableProviderInput(path, label)
	if err != nil {
		return providerInputStableFileIdentity{}, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return providerInputStableFileIdentity{}, nil, fmt.Errorf("inspect opened %s %q for stable identity: %w", label, path, err)
	}
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return providerInputStableFileIdentity{}, nil, fmt.Errorf("derive stable %s identity for %q: %w", label, path, err)
	}
	return identity, info, nil
}

// inspectPathWithoutLinks walks the caller-visible path one component at a
// time with Lstat. EvalSymlinks is intentionally insufficient here: an in-root
// link, a Windows junction, or another reparse point is still an unstable
// input boundary even when it resolves to a regular file inside the root.
func inspectPathWithoutLinks(path, label string) (string, os.FileInfo, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil, fmt.Errorf("%s path is empty", label)
	}
	if err := validateProviderInputPathSyntax(path, label); err != nil {
		return "", nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", nil, fmt.Errorf("resolve %s path %q: %w", label, path, err)
	}
	absolute = filepath.Clean(absolute)
	volume := filepath.VolumeName(absolute)
	remainder := strings.TrimPrefix(absolute, volume)
	remainder = strings.TrimLeft(remainder, string(filepath.Separator))
	current := volume
	if filepath.IsAbs(absolute) {
		current += string(filepath.Separator)
	}
	components := strings.Split(remainder, string(filepath.Separator))
	if len(components) == 0 {
		return "", nil, fmt.Errorf("%s path %q does not name a filesystem object", label, path)
	}
	var leaf os.FileInfo
	for index, component := range components {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return "", nil, fmt.Errorf("inspect %s path component %q: %w", label, current, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || fileInfoHasReparsePoint(info) {
			return "", nil, fmt.Errorf("%s path %q contains a symbolic link or reparse point at %q", label, path, current)
		}
		if index != len(components)-1 && !info.IsDir() {
			return "", nil, fmt.Errorf("%s path %q has non-directory parent component %q", label, path, current)
		}
		leaf = info
	}
	return absolute, leaf, nil
}

func (accumulator *providerInputAdmissionAccumulator) rejectDuplicatePathIdentity(path string, _ os.FileInfo) error {
	if accumulator == nil {
		return fmt.Errorf("provider input admission accumulator is nil")
	}
	key := canonicalProviderInputPathKey(path)
	accumulator.ensurePathIdentityIndexes()
	if _, duplicate := accumulator.pathKeys[key]; duplicate {
		return fmt.Errorf("provider input admission rejects duplicate path or file identity %q", path)
	}
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) rejectDuplicateOpenFileIdentity(path string, file *os.File) error {
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return fmt.Errorf("derive stable provider input file identity for %q: %w", path, err)
	}
	accumulator.ensurePathIdentityIndexes()
	if _, duplicate := accumulator.fileIdentities[identity]; duplicate {
		return fmt.Errorf("provider input admission rejects duplicate path or file identity %q", path)
	}
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) addPathIdentity(path string, file *os.File) error {
	if err := accumulator.rejectDuplicatePathIdentity(path, nil); err != nil {
		return err
	}
	key := canonicalProviderInputPathKey(path)
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return fmt.Errorf("derive stable provider input file identity for %q: %w", path, err)
	}
	accumulator.pathIdentities = append(accumulator.pathIdentities, providerInputAdmissionPathIdentity{
		key:      key,
		identity: identity,
	})
	accumulator.pathKeys[key] = struct{}{}
	accumulator.fileIdentities[identity] = struct{}{}
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) ensurePathIdentityIndexes() {
	if accumulator.pathKeys == nil {
		accumulator.pathKeys = make(map[string]struct{}, len(accumulator.pathIdentities))
	}
	if accumulator.fileIdentities == nil {
		accumulator.fileIdentities = make(map[providerInputStableFileIdentity]struct{}, len(accumulator.pathIdentities))
	}
	if len(accumulator.pathKeys) == len(accumulator.pathIdentities) && len(accumulator.fileIdentities) == len(accumulator.pathIdentities) {
		return
	}
	for _, prior := range accumulator.pathIdentities {
		accumulator.pathKeys[prior.key] = struct{}{}
		accumulator.fileIdentities[prior.identity] = struct{}{}
	}
}
