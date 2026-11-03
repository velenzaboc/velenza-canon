package providerplan

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Each service owns its target recipes. The candidate pins their original
// bytes and the exact catalog coordinate allowed to contribute targets.
type CloudServiceTargetReference struct {
	ProviderID   string `json:"provider_id"`
	ServiceID    string `json:"service_id"`
	APISurfaceID string `json:"api_surface_id"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
}

func readCloudCandidateInput(filename string) (CloudSourceCandidateInput, error) {
	var input CloudSourceCandidateInput
	raw, err := os.ReadFile(filename)
	if err != nil {
		return input, err
	}
	if err := strictUnmarshal(raw, &input); err != nil {
		return CloudSourceCandidateInput{}, fmt.Errorf("decode cloud candidate input: %w", err)
	}
	return resolveCloudServiceDocuments(filepath.Dir(filename), input)
}

func resolveCloudServiceDocuments(base string, input CloudSourceCandidateInput) (CloudSourceCandidateInput, error) {
	if len(input.TargetDocuments) == 0 {
		return input, nil
	}
	if len(input.Targets) != 0 || len(input.TargetDocuments) > len(input.Models) {
		return CloudSourceCandidateInput{}, fmt.Errorf("service target documents require distinct model coordinates and exclude inline targets")
	}
	type surface struct{ provider, service, api string }
	available := make(map[surface]bool, len(input.Models))
	for _, model := range input.Models {
		available[surface{model.ProviderID, model.ServiceID, model.APISurfaceID}] = true
	}
	seenTargets := make(map[string]bool)
	for _, ref := range input.TargetDocuments {
		coordinate := surface{ref.ProviderID, ref.ServiceID, ref.APISurfaceID}
		if ref.ProviderID == "" || ref.ServiceID == "" || ref.APISurfaceID == "" || !available[coordinate] || !isLowerSHA256(ref.SHA256) {
			return CloudSourceCandidateInput{}, fmt.Errorf("service document has a missing, foreign or repeated coordinate or invalid digest")
		}
		delete(available, coordinate)
		targets, err := readCloudServiceTargets(base, ref)
		if err != nil {
			return CloudSourceCandidateInput{}, fmt.Errorf("service targets %s/%s/%s: %w", ref.ProviderID, ref.ServiceID, ref.APISurfaceID, err)
		}
		for _, target := range targets {
			key := cloudTargetKey(target)
			if (surface{target.ProviderID, target.ServiceID, target.APISurfaceID}) != coordinate || seenTargets[key] {
				return CloudSourceCandidateInput{}, fmt.Errorf("foreign or duplicate service target in %q", ref.Path)
			}
			seenTargets[key] = true
			input.Targets = append(input.Targets, target)
		}
	}
	if len(available) != 0 {
		return CloudSourceCandidateInput{}, fmt.Errorf("candidate is missing service target documents for %d model coordinates", len(available))
	}
	// Refresh works on this detached closed input. Its output carries inline
	// successor recipes so a later edit of an authoring document cannot alter it.
	input.TargetDocuments = nil
	return input, nil
}

func readCloudServiceTargets(base string, ref CloudServiceTargetReference) ([]CloudSourceObjectTarget, error) {
	path, err := cloudCandidateLocalPath(base, ref.Path)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const maxBytes = 16 << 20
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes || sha256Hex(raw) != ref.SHA256 {
		return nil, fmt.Errorf("target document exceeds size limit or differs from its pinned bytes")
	}
	if err := requireValidUTF8("service target document", raw); err != nil {
		return nil, err
	}
	var document struct {
		Targets []CloudSourceObjectTarget `json:"targets"`
	}
	if err := strictUnmarshal(raw, &document); err != nil {
		return nil, err
	}
	if len(document.Targets) == 0 {
		return nil, fmt.Errorf("service target document is empty")
	}
	return document.Targets, nil
}
