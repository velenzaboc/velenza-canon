package providerplan

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// Measure exact source ranges for a mapping author. Preparing a candidate
// independently reads and verifies these bindings through LoadCloudMappingEvidence.
func MeasureCloudModelEvidence(model, selection []byte) ([]CloudMappingEvidenceBinding, error) {
	var request struct {
		SourcePath     string `json:"source_path"`
		SourceURI      string `json:"source_uri"`
		ExpectedSHA256 string `json:"expected_sha256"`
		Selections     []struct {
			ID      string `json:"id"`
			Pointer string `json:"json_pointer"`
		} `json:"selections"`
	}
	if len(selection) > 1<<20 || requireValidUTF8("evidence selection", selection) != nil || strictUnmarshal(selection, &request) != nil {
		return nil, fmt.Errorf("invalid evidence selection manifest")
	}
	if len(model) > 64<<20 || requireValidUTF8("model", model) != nil || !json.Valid(model) || rejectDuplicateJSONKeys(model) != nil || sha256Hex(model) != request.ExpectedSHA256 {
		return nil, fmt.Errorf("model is not strict JSON with the declared digest")
	}
	if request.SourceURI == "" || request.SourcePath == "" || request.SourcePath == "." || request.SourcePath == ".." || strings.HasPrefix(request.SourcePath, "../") || strings.HasPrefix(request.SourcePath, "/") || strings.ContainsAny(request.SourcePath, "\\:") || path.Clean(request.SourcePath) != request.SourcePath || len(request.Selections) == 0 || len(request.Selections) > 4096 {
		return nil, fmt.Errorf("invalid source coordinate or selection count")
	}
	spans, err := cloudCatalogJSONPointerSpans(model)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]CloudMappingEvidenceBinding, 0, len(request.Selections))
	for _, s := range request.Selections {
		span, ok := spans[s.Pointer]
		if !ok || !strings.HasPrefix(s.Pointer, "/") || s.ID == "" || seen[s.ID] {
			return nil, fmt.Errorf("unknown pointer or duplicate evidence ID %q", s.ID)
		}
		seen[s.ID] = true
		out = append(out, CloudMappingEvidenceBinding{ID: s.ID, SourcePath: request.SourcePath, SourceURI: request.SourceURI, ExpectedSHA256: request.ExpectedSHA256, StartByte: span.start, EndByte: span.end, SliceSHA256: sha256Hex(model[span.start:span.end])})
	}
	return out, nil
}
