package providerplan

import (
	"fmt"
	"path/filepath"
	"strings"
)

type stageCompileFileManifest struct {
	RequestPath             string                         `json:"request_path"`
	PredecessorReceiptPaths []string                       `json:"predecessor_receipt_paths"`
	Materials               []stageCompileFileMaterial     `json:"materials"`
	EvidenceBodies          []stageCompileFileEvidenceBody `json:"evidence_bodies"`
}

type stageCompileFileMaterial struct {
	Role    string `json:"role"`
	ID      string `json:"id"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

type stageCompileFileEvidenceBody struct {
	ManifestRole     string `json:"manifest_role"`
	ManifestID       string `json:"manifest_id"`
	ManifestVersion  string `json:"manifest_version"`
	ComponentOrdinal uint64 `json:"component_ordinal"`
	Path             string `json:"path"`
}

type stageCompileInputAdmissionItem struct {
	Raw              []byte
	Resource         providerInputAdmissionResourceReceipt
	ContentValidated bool
}

// stageCompileInputAdmissionBinding keeps the exact stage bytes and their
// content-derived, path-independent receipts together until the complete
// provider-input proof is sealed. It is deliberately not part of the public
// stage compiler contract: it is process-local admission evidence, not a new
// provider or tenant policy surface.
type stageCompileInputAdmissionBinding struct {
	ProofSHA256           string
	ResourceSetRootSHA256 string
	Items                 []stageCompileInputAdmissionItem
}

func (binding stageCompileInputAdmissionBinding) resources() []providerInputAdmissionResourceReceipt {
	resources := make([]providerInputAdmissionResourceReceipt, 0, len(binding.Items))
	for _, item := range binding.Items {
		resources = append(resources, item.Resource)
	}
	return resources
}

// LoadStageCompileFileManifest resolves one strict stage input manifest to the
// exact request, receipt, material, and evidence bytes consumed by the shared
// stage compiler. Both command-line entry points use this one loader so a
// graph plan cannot be validated under two path-resolution contracts.
func LoadStageCompileFileManifest(manifestPath string) ([]byte, StageCompileInputs, error) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	requestRaw, inputs, binding, err := loadStageCompileFileManifestWithAdmission(manifestPath, accumulator)
	if err != nil {
		return nil, StageCompileInputs{}, err
	}
	proof, err := accumulator.seal()
	if err != nil {
		return nil, StageCompileInputs{}, fmt.Errorf("seal exact stage input file admission: %w", err)
	}
	if err := bindAndValidateStageCompileInputAdmission(&binding, proof, accumulator.resources); err != nil {
		return nil, StageCompileInputs{}, err
	}
	return requestRaw, inputs, nil
}

func loadStageCompileFileManifestWithAdmission(manifestPath string, accumulator *providerInputAdmissionAccumulator) ([]byte, StageCompileInputs, stageCompileInputAdmissionBinding, error) {
	if accumulator == nil {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, fmt.Errorf("provider input admission accumulator is nil")
	}
	if strings.TrimSpace(manifestPath) == "" || manifestPath != strings.TrimSpace(manifestPath) {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, fmt.Errorf("stage input manifest path is empty or padded")
	}
	manifestFile, err := readBoundedProviderInputFile(manifestPath, "stage input manifest", providerInputAdmissionResourceKindStageManifest, "", accumulator)
	if err != nil {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, err
	}
	if err := accumulator.admitStructuredJSONDocument(manifestPath, "stage input manifest", providerInputAdmissionResourceKindStageManifest, manifestFile.Bytes); err != nil {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, err
	}
	binding := stageCompileInputAdmissionBinding{Items: []stageCompileInputAdmissionItem{{Raw: manifestFile.Bytes, Resource: manifestFile.Resource}}}
	var manifest stageCompileFileManifest
	if err := strictUnmarshal(manifestFile.Bytes, &manifest); err != nil {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, fmt.Errorf("decode stage input manifest: %w", err)
	}
	if err := preflightStageCompileInputManifest(manifest, accumulator); err != nil {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, err
	}
	baseDir, err := filepath.Abs(filepath.Dir(manifestPath))
	if err != nil {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, fmt.Errorf("resolve stage input manifest directory: %w", err)
	}
	requestFile, err := readExactStageManifestFileWithAdmission(baseDir, manifest.RequestPath, "request_path", "", accumulator)
	if err != nil {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, err
	}
	requestPath, err := resolveRelativeStageManifestPath(baseDir, manifest.RequestPath, "request_path")
	if err != nil {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, err
	}
	if err := accumulator.admitStructuredJSONAuto(requestPath, "stage request", providerInputAdmissionResourceKindStageFile, requestFile.Bytes); err != nil {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, err
	}
	binding.Items = append(binding.Items, stageCompileInputAdmissionItem{Raw: requestFile.Bytes, Resource: requestFile.Resource})
	inputs := StageCompileInputs{
		PredecessorReceipts: make([][]byte, 0, len(manifest.PredecessorReceiptPaths)),
		Materials:           make([]StageMaterial, 0, len(manifest.Materials)),
		EvidenceBodies:      make([]StageEvidenceBody, 0, len(manifest.EvidenceBodies)),
	}
	for index, path := range manifest.PredecessorReceiptPaths {
		file, readErr := readExactStageManifestFileWithAdmission(baseDir, path, fmt.Sprintf("predecessor_receipt_paths[%d]", index), "", accumulator)
		if readErr != nil {
			return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, readErr
		}
		resolvedPath, resolveErr := resolveRelativeStageManifestPath(baseDir, path, fmt.Sprintf("predecessor_receipt_paths[%d]", index))
		if resolveErr != nil {
			return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, resolveErr
		}
		if err := accumulator.admitStructuredJSONAuto(resolvedPath, fmt.Sprintf("predecessor receipt[%d]", index), providerInputAdmissionResourceKindStageFile, file.Bytes); err != nil {
			return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, err
		}
		inputs.PredecessorReceipts = append(inputs.PredecessorReceipts, file.Bytes)
		binding.Items = append(binding.Items, stageCompileInputAdmissionItem{Raw: file.Bytes, Resource: file.Resource})
	}
	for index, material := range manifest.Materials {
		file, readErr := readExactStageManifestFileWithAdmission(
			baseDir,
			material.Path,
			fmt.Sprintf("materials[%d].path", index),
			"stage_input_material_v1|"+lengthPrefixedIdentityKey(material.Role, material.ID, material.Version),
			accumulator,
		)
		if readErr != nil {
			return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, readErr
		}
		resolvedPath, resolveErr := resolveRelativeStageManifestPath(baseDir, material.Path, fmt.Sprintf("materials[%d].path", index))
		if resolveErr != nil {
			return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, resolveErr
		}
		if err := accumulator.admitStructuredJSONAuto(resolvedPath, fmt.Sprintf("stage material[%d]", index), providerInputAdmissionResourceKindStageFile, file.Bytes); err != nil {
			return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, err
		}
		inputs.Materials = append(inputs.Materials, StageMaterial{Role: material.Role, ID: material.ID, Version: material.Version, Raw: file.Bytes})
		binding.Items = append(binding.Items, stageCompileInputAdmissionItem{Raw: file.Bytes, Resource: file.Resource})
	}
	for index, body := range manifest.EvidenceBodies {
		file, readErr := readExactStageManifestFileWithAdmission(
			baseDir,
			body.Path,
			fmt.Sprintf("evidence_bodies[%d].path", index),
			"stage_input_evidence_body_v1|"+lengthPrefixedIdentityKey(body.ManifestRole, body.ManifestID, body.ManifestVersion, fmt.Sprintf("%d", body.ComponentOrdinal)),
			accumulator,
		)
		if readErr != nil {
			return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, readErr
		}
		inputs.EvidenceBodies = append(inputs.EvidenceBodies, StageEvidenceBody{
			ManifestRole: body.ManifestRole, ManifestID: body.ManifestID, ManifestVersion: body.ManifestVersion,
			ComponentOrdinal: body.ComponentOrdinal, Raw: file.Bytes,
		})
		binding.Items = append(binding.Items, stageCompileInputAdmissionItem{Raw: file.Bytes, Resource: file.Resource})
	}
	return requestFile.Bytes, inputs, binding, nil
}

func preflightStageCompileInputManifest(manifest stageCompileFileManifest, accumulator *providerInputAdmissionAccumulator) error {
	if err := rejectDuplicateStageManifestDeclaredPaths(manifest); err != nil {
		return err
	}
	counts := []struct {
		label string
		count int
	}{
		{"predecessor_receipt_paths", len(manifest.PredecessorReceiptPaths)},
		{"materials", len(manifest.Materials)},
		{"evidence_bodies", len(manifest.EvidenceBodies)},
	}
	total := int64(1) // request_path
	for _, candidate := range counts {
		if int64(candidate.count) > accumulator.limits.StageInputFileCount {
			return fmt.Errorf("stage input manifest %s count %d exceeds limit %d", candidate.label, candidate.count, accumulator.limits.StageInputFileCount)
		}
		if int64(candidate.count) > accumulator.limits.StageInputFileCount-total {
			return fmt.Errorf("stage input file path count would exceed limit %d", accumulator.limits.StageInputFileCount)
		}
		total += int64(candidate.count)
	}
	if err := accumulator.preflightPathCount(providerInputAdmissionResourceKindStageFile, int(total)); err != nil {
		return fmt.Errorf("stage input manifest: %w", err)
	}
	for index, material := range manifest.Materials {
		if strings.TrimSpace(material.Role) == "" || strings.TrimSpace(material.ID) == "" || strings.TrimSpace(material.Version) == "" {
			return fmt.Errorf("materials[%d] has an empty role, id, or version", index)
		}
	}
	for index, body := range manifest.EvidenceBodies {
		if strings.TrimSpace(body.ManifestRole) == "" || strings.TrimSpace(body.ManifestID) == "" || strings.TrimSpace(body.ManifestVersion) == "" {
			return fmt.Errorf("evidence_bodies[%d] has an empty manifest role, id, or version", index)
		}
	}
	return nil
}

func rejectDuplicateStageManifestDeclaredPaths(manifest stageCompileFileManifest) error {
	type declaredPath struct {
		label string
		path  string
	}
	declared := []declaredPath{{label: "request_path", path: manifest.RequestPath}}
	for index, path := range manifest.PredecessorReceiptPaths {
		declared = append(declared, declaredPath{label: fmt.Sprintf("predecessor_receipt_paths[%d]", index), path: path})
	}
	for index, material := range manifest.Materials {
		declared = append(declared, declaredPath{label: fmt.Sprintf("materials[%d].path", index), path: material.Path})
	}
	for index, body := range manifest.EvidenceBodies {
		declared = append(declared, declaredPath{label: fmt.Sprintf("evidence_bodies[%d].path", index), path: body.Path})
	}
	seen := make(map[string]string, len(declared))
	for _, candidate := range declared {
		key := canonicalProviderInputPathKey(filepath.Clean(filepath.FromSlash(candidate.path)))
		if prior, duplicate := seen[key]; duplicate {
			return fmt.Errorf("stage input manifest has duplicate declared path %q at %s and %s", candidate.path, prior, candidate.label)
		}
		seen[key] = candidate.label
	}
	return nil
}

func readExactStageManifestFile(baseDir, path, label string) ([]byte, error) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	file, err := readExactStageManifestFileWithAdmission(baseDir, path, label, "", accumulator)
	if err != nil {
		return nil, err
	}
	if _, err := accumulator.seal(); err != nil {
		return nil, fmt.Errorf("seal exact %s admission: %w", label, err)
	}
	return file.Bytes, nil
}

func readExactStageManifestFileWithAdmission(baseDir, declared, label, stableCoordinate string, accumulator *providerInputAdmissionAccumulator) (boundedProviderInputFile, error) {
	resolvedBefore, err := resolveRelativeStageManifestPath(baseDir, declared, label)
	if err != nil {
		return boundedProviderInputFile{}, err
	}
	file, err := readBoundedProviderInputFile(resolvedBefore, label, providerInputAdmissionResourceKindStageFile, stableCoordinate, accumulator)
	if err != nil {
		return boundedProviderInputFile{}, err
	}
	if file.Size == 0 {
		return boundedProviderInputFile{}, fmt.Errorf("%s %q is empty", label, declared)
	}
	resolvedAfter, err := resolveRelativeStageManifestPath(baseDir, declared, label)
	if err != nil {
		return boundedProviderInputFile{}, fmt.Errorf("re-resolve %s %q after read: %w", label, declared, err)
	}
	if resolvedAfter != resolvedBefore {
		return boundedProviderInputFile{}, fmt.Errorf("%s %q changed identity while being read", label, declared)
	}
	return file, nil
}

func resolveRelativeStageManifestPath(baseDir, declared, label string) (string, error) {
	nativeDeclared := filepath.FromSlash(declared)
	if declared == "" || declared != strings.TrimSpace(declared) || !filepath.IsLocal(nativeDeclared) || filepath.IsAbs(nativeDeclared) || filepath.VolumeName(nativeDeclared) != "" || !validEvidenceStagingPathComponents(nativeDeclared) {
		return "", fmt.Errorf("%s is empty, padded, or non-relative", label)
	}
	root, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("resolve stage input manifest directory %q: %w", baseDir, err)
	}
	target := filepath.Clean(filepath.Join(root, nativeDeclared))
	if err := requirePathWithinRoot(root, target); err != nil {
		return "", fmt.Errorf("%s %q: %w", label, declared, err)
	}
	if _, rootInfo, err := inspectPathWithoutLinks(root, "stage input manifest directory"); err != nil {
		return "", err
	} else if !rootInfo.IsDir() {
		return "", fmt.Errorf("stage input manifest directory %q is not a directory", root)
	}
	if _, _, err := inspectPathWithoutLinks(target, label); err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve stage input manifest directory %q: %w", root, err)
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", fmt.Errorf("resolve %s %q: %w", label, target, err)
	}
	if err := requirePathWithinRoot(resolvedRoot, resolvedTarget); err != nil {
		return "", fmt.Errorf("%s %q follows a link outside its stage manifest directory: %w", label, declared, err)
	}
	_, info, err := inspectPathWithoutLinks(resolvedTarget, label)
	if err != nil {
		return "", fmt.Errorf("inspect resolved %s %q: %w", label, resolvedTarget, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s %q is not a regular file", label, declared)
	}
	return resolvedTarget, nil
}

func bindAndValidateStageCompileInputAdmission(binding *stageCompileInputAdmissionBinding, proof providerInputAdmissionProof, allResources []providerInputAdmissionResourceReceipt) error {
	if binding == nil || len(binding.Items) == 0 {
		return fmt.Errorf("stage input file admission binding is empty")
	}
	binding.ProofSHA256 = proof.ProofSHA256
	resources := binding.resources()
	root, err := providerInputAdmissionResourceSetRoot(resources)
	if err != nil {
		return err
	}
	binding.ResourceSetRootSHA256 = root
	resourceByReceipt := make(map[string]providerInputAdmissionResourceReceipt, len(allResources))
	for _, resource := range allResources {
		resourceByReceipt[resource.ResourceReceiptSHA256] = resource
	}
	manifestCount := 0
	fileCount := 0
	for _, item := range binding.Items {
		resource := item.Resource
		if !item.ContentValidated && (resource.ContentBytes != int64(len(item.Raw)) || resource.ContentSHA256 != sha256Hex(item.Raw)) {
			return fmt.Errorf("stage input %q is not exactly bound to its admission resource", resource.StableCoordinate)
		}
		if resourceByReceipt[resource.ResourceReceiptSHA256].ResourceReceiptSHA256 != resource.ResourceReceiptSHA256 {
			return fmt.Errorf("stage input %q is absent from the sealed provider input roster", resource.StableCoordinate)
		}
		switch resource.ResourceKind {
		case providerInputAdmissionResourceKindStageManifest:
			manifestCount++
		case providerInputAdmissionResourceKindStageFile:
			fileCount++
		default:
			return fmt.Errorf("stage input file admission carries non-stage resource kind %q", resource.ResourceKind)
		}
	}
	if manifestCount != 1 || fileCount == 0 {
		return fmt.Errorf("stage input file admission has manifest/file counts %d/%d, want one manifest and at least one input file", manifestCount, fileCount)
	}
	return nil
}

func compactStageCompileInputAdmissionBinding(binding *stageCompileInputAdmissionBinding) error {
	if binding == nil || len(binding.Items) == 0 {
		return fmt.Errorf("stage input file admission binding is empty")
	}
	for index := range binding.Items {
		item := &binding.Items[index]
		if item.Resource.ContentBytes != int64(len(item.Raw)) || item.Resource.ContentSHA256 != sha256Hex(item.Raw) {
			return fmt.Errorf("stage input %q is not exactly bound before release", item.Resource.StableCoordinate)
		}
		item.ContentValidated = true
		item.Raw = nil
	}
	return nil
}
