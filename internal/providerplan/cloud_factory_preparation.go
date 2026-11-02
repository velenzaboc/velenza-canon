package providerplan

// Preparation composes existing candidate builders. It is reproducible offline
// and cannot issue an owner qualification, publication certificate or admission.
import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

const cloudPreparationManifestPath = "preparation-manifest.json"

type CloudPreparationDocument struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type CloudPreparationManifest struct {
	Version           string                        `json:"version"`
	Status            string                        `json:"status"`
	ScopeID           string                        `json:"scope_id"`
	ScopeSHA256       string                        `json:"scope_sha256"`
	ProfileSetID      string                        `json:"profile_set_id"`
	ProfileSHA256     string                        `json:"profile_sha256"`
	Providers         int                           `json:"providers"`
	Services          int                           `json:"services"`
	Resources         int                           `json:"resources"`
	OperationTargets  int                           `json:"operation_targets"`
	DispositionTotals CloudMappingDispositionTotals `json:"disposition_totals"`
	Documents         []CloudPreparationDocument    `json:"documents"`
}

// CloudFactoryPreparation is an opaque, immutable result of the checked
// builders. Its accessors return copies; a zero value cannot be published.
type CloudFactoryPreparation struct {
	files    []factorySourceOutputFile
	manifest []byte
}

func (prepared CloudFactoryPreparation) ManifestJSON() []byte {
	return append([]byte(nil), prepared.manifest...)
}

// BuildCloudFactoryPreparation validates all nested profile/model/target
// references and composes the selected mapping and coverage exactly once.
func BuildCloudFactoryPreparation(request CloudSourceCandidateRequest, scope CloudMappingPackageScope, profiles CloudAPIProfileDocument, policy CloudIngestionHandoffPolicy) (CloudFactoryPreparation, error) {
	if err := ValidateCloudAPIProfileDocument(profiles, request.Catalogs, request.Targets); err != nil {
		return CloudFactoryPreparation{}, fmt.Errorf("prepare profiles: %w", err)
	}
	pkg, err := BuildCloudMappingPackage(request, scope)
	if err != nil {
		return CloudFactoryPreparation{}, fmt.Errorf("prepare mappings: %w", err)
	}
	coverage, err := buildCloudCoverageBacklogFromValidatedPackage(pkg, scope)
	if err != nil {
		return CloudFactoryPreparation{}, fmt.Errorf("prepare coverage: %w", err)
	}
	handoff, err := BuildCloudIngestionHandoff(request, profiles, policy)
	if err != nil {
		return CloudFactoryPreparation{}, fmt.Errorf("prepare ingestion handoff: %w", err)
	}
	if err := ValidateCloudIngestionHandoff(handoff, request, profiles); err != nil {
		return CloudFactoryPreparation{}, err
	}
	profileRaw, err := CanonicalCloudAPIProfileDocument(profiles)
	if err != nil {
		return CloudFactoryPreparation{}, err
	}
	scopeRaw, err := canonicalFactoryJSON(scope)
	if err != nil {
		return CloudFactoryPreparation{}, err
	}
	files := []factorySourceOutputFile{
		{RelativePath: "profiles.json", Raw: profileRaw},
		{RelativePath: "coverage.json", Raw: coverage.Document},
		{RelativePath: "scope.json", Raw: scopeRaw},
		{RelativePath: "ingestion-handoff.json", Raw: handoff.Document},
	}
	for role, raw := range pkg.Documents {
		files = append(files, factorySourceOutputFile{RelativePath: "mapping/" + role + ".json", Raw: raw})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].RelativePath < files[j].RelativePath })
	resourceSet := map[string]struct{}{}
	for _, target := range scope.Targets {
		resourceSet[cloudCatalogKey(target.ProviderID, target.ServiceID, target.APISurfaceID)+"\x00"+target.SourceObjectType] = struct{}{}
	}
	manifest := CloudPreparationManifest{
		Version: "1", Status: "candidate_prepared_unqualified", ScopeID: scope.ScopeID,
		ScopeSHA256: pkg.ScopeSHA256, ProfileSetID: profiles.ProfileSetID,
		ProfileSHA256: sha256Hex(profileRaw), Providers: len(pkg.ProviderPackages),
		Services: len(scope.Catalogs), Resources: len(resourceSet), OperationTargets: len(scope.Targets), DispositionTotals: pkg.DispositionTotals,
	}
	for _, file := range files {
		manifest.Documents = append(manifest.Documents, CloudPreparationDocument{Path: file.RelativePath, SHA256: sha256Hex(file.Raw), Bytes: len(file.Raw)})
	}
	manifestRaw, err := canonicalFactoryJSON(manifest)
	if err != nil {
		return CloudFactoryPreparation{}, err
	}
	manifestRaw = append(manifestRaw, '\n')
	files = append(files, factorySourceOutputFile{RelativePath: cloudPreparationManifestPath, Raw: manifestRaw})
	// Validate the output namespace before any filesystem side effect.
	if _, err := prepareSourcePackageOutputRoster(files); err != nil {
		return CloudFactoryPreparation{}, err
	}
	return CloudFactoryPreparation{files: files, manifest: manifestRaw}, nil
}

// PublishExclusive uses the factory's existing private staging and exact-byte
// publication checks. It refuses every existing destination object.
func (prepared CloudFactoryPreparation) PublishExclusive(root string) error {
	if len(prepared.files) == 0 || len(prepared.manifest) == 0 {
		return fmt.Errorf("unconstructed cloud factory preparation")
	}
	return publishFactorySourceOutputDirectoryExclusive(root, prepared.files)
}

// ValidateCloudFactoryPreparation reconstructs expected bytes from checked
// inputs. No manifest hash, status or caller-provided artifact is an authority.
func ValidateCloudFactoryPreparation(root string, request CloudSourceCandidateRequest, scope CloudMappingPackageScope, profiles CloudAPIProfileDocument, policy CloudIngestionHandoffPolicy) error {
	expected, err := BuildCloudFactoryPreparation(request, scope, profiles, policy)
	if err != nil {
		return err
	}
	return expected.VerifyDirectory(root)
}

// VerifyDirectory checks the complete tree against this opaque constructed
// preparation. Extra files, links, missing members and byte changes all fail.
func (prepared CloudFactoryPreparation) VerifyDirectory(root string) error {
	if len(prepared.files) == 0 || len(prepared.manifest) == 0 {
		return fmt.Errorf("unconstructed cloud factory preparation")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("preparation root is not an ordinary directory")
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer opened.Close()
	expected := make(map[string][]byte, len(prepared.files))
	dirs := map[string]bool{".": true}
	for _, file := range prepared.files {
		expected[file.RelativePath] = file.Raw
		for parent := filepath.ToSlash(filepath.Dir(file.RelativePath)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			dirs[parent] = true
		}
	}
	seen := 0
	err = fs.WalkDir(opened.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("preparation contains symbolic link")
		}
		if entry.IsDir() {
			if !dirs[path] {
				return fmt.Errorf("preparation contains unexpected directory")
			}
			return nil
		}
		raw, found := expected[path]
		if !found || !entry.Type().IsRegular() {
			return fmt.Errorf("preparation contains unexpected member")
		}
		file, err := opened.Open(path)
		if err != nil {
			return err
		}
		got, readErr := io.ReadAll(io.LimitReader(file, int64(len(raw))+1))
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if !bytes.Equal(got, raw) {
			return fmt.Errorf("preparation member %q differs from checked inputs", path)
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(expected) {
		return fmt.Errorf("preparation member roster is incomplete")
	}
	return nil
}
