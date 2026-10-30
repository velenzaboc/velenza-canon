package providerplan

import (
	"fmt"
	"os"
	"sort"
	"unicode/utf8"
)

// LoadCloudMappingEvidence verifies offline, unqualified candidate evidence.
// It intentionally grants no semantic or runtime authority.
func LoadCloudMappingEvidence(base string, contract *CloudMappingContract) error {
	if contract == nil {
		return fmt.Errorf("mapping contract is nil")
	}
	contract.evidenceStamp = ""
	seen := map[string]struct{}{}
	for _, b := range contract.EvidenceBindings {
		if b.ID == "" || b.SourceURI == "" || !isLowerSHA256(b.ExpectedSHA256) || !isLowerSHA256(b.SliceSHA256) || b.StartByte < 0 || b.EndByte <= b.StartByte {
			return fmt.Errorf("invalid mapping evidence binding")
		}
		if _, ok := seen[b.ID]; ok {
			return fmt.Errorf("duplicate mapping evidence %q", b.ID)
		}
		seen[b.ID] = struct{}{}
		resolved, e := cloudCandidateLocalPath(base, b.SourcePath)
		if e != nil {
			return e
		}
		raw, e := os.ReadFile(resolved)
		if e != nil {
			return e
		}
		if !utf8.Valid(raw) || sha256Hex(raw) != b.ExpectedSHA256 || b.EndByte > len(raw) {
			return fmt.Errorf("mapping evidence %q bytes mismatch", b.ID)
		}
		if slice := raw[b.StartByte:b.EndByte]; !utf8.Valid(slice) || sha256Hex(slice) != b.SliceSHA256 {
			return fmt.Errorf("mapping evidence %q slice mismatch", b.ID)
		}
	}
	stamp, err := cloudMappingEvidenceStamp(contract.EvidenceBindings)
	if err != nil {
		return err
	}
	contract.evidenceStamp = stamp
	return nil
}

func cloudMappingEvidenceStamp(bindings []CloudMappingEvidenceBinding) (string, error) {
	values := append([]CloudMappingEvidenceBinding(nil), bindings...)
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	raw, err := canonicalFactoryJSON(values)
	if err != nil {
		return "", err
	}
	return sha256Hex(raw), nil
}

func mappingEvidenceIDs(contract CloudMappingContract) map[string]struct{} {
	ids := map[string]struct{}{}
	for _, b := range contract.EvidenceBindings {
		ids[b.ID] = struct{}{}
	}
	return ids
}
