package providerplan

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadCloudMappingEvidencePinsFullBindingAndBytes(t *testing.T) {
	base := t.TempDir()
	raw := []byte("lifecycle evidence\n")
	if err := os.WriteFile(filepath.Join(base, "e.txt"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	c := CloudMappingContract{EvidenceBindings: []CloudMappingEvidenceBinding{{ID: "e", SourceURI: "https://example.invalid/e", SourcePath: "e.txt", ExpectedSHA256: sha256Hex(raw), StartByte: 0, EndByte: len(raw), SliceSHA256: sha256Hex(raw)}}}
	if err := LoadCloudMappingEvidence(base, &c); err != nil {
		t.Fatal(err)
	}
	stamp := c.evidenceStamp
	c.EvidenceBindings[0].SourceURI = "https://changed.invalid/e"
	if got, _ := cloudMappingEvidenceStamp(c.EvidenceBindings); got == stamp {
		t.Fatal("stamp ignored URI mutation")
	}
	c.EvidenceBindings[0].SourcePath = "../e.txt"
	if err := LoadCloudMappingEvidence(base, &c); err == nil {
		t.Fatal("unsafe path accepted")
	}
	if c.evidenceStamp != "" {
		t.Fatal("failed load retained old stamp")
	}
}

func TestCloudMappingEvidenceCannotBeBypassedOrMutated(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range request.Targets {
		if target.RecordClassSymbol != "compute_instance" && target.RecordClassSymbol != "compute_volume" {
			continue
		}
		catalog, _ := findCloudCandidateCatalog(request.Catalogs, target)
		original := *target.MappingContract
		if err := ValidateCloudMappingContract(catalog, original); err != nil {
			t.Fatal(err)
		}
		t.Run(target.ProviderID+"/"+target.SourceObjectType, func(t *testing.T) {
			mutated := original
			mutated.EvidenceBindings = append([]CloudMappingEvidenceBinding{}, original.EvidenceBindings...)
			mutated.EvidenceBindings[0].SourceURI += "?changed"
			if err := ValidateCloudMappingContract(catalog, mutated); err == nil {
				t.Fatal("post-load evidence mutation accepted")
			}
			removed := original
			removed.EvidenceBindings = nil
			if err := ValidateCloudMappingContract(catalog, removed); err == nil {
				t.Fatal("removal of required evidence accepted")
			}
			if target.RecordClassSymbol != "compute_instance" {
				return
			}
			bypass := original
			bypass.EvidenceBindings = nil
			bypass.evidenceStamp = ""
			bypass.Fields = append([]CloudMappingContractField{}, original.Fields...)
			bypass.Nested = append([]CloudNestedDecomposition{}, original.Nested...)
			count := 0
			rewrite := func(fields []CloudMappingContractField) {
				for i := range fields {
					if fields[i].TargetField == "lifecycle_state" {
						fields[i].Disposition = CloudSourceMapsExactSourceFact
						fields[i].LifecycleRecipe = nil
						count++
					}
				}
			}
			rewrite(bypass.Fields)
			for i := range bypass.Nested {
				bypass.Nested[i].Fields = append([]CloudMappingContractField{}, original.Nested[i].Fields...)
				rewrite(bypass.Nested[i].Fields)
			}
			if count != 1 {
				t.Fatalf("expected one actual lifecycle mapping, got %d", count)
			}
			if err := ValidateCloudMappingContract(catalog, bypass); err == nil {
				t.Fatal("lifecycle exact-copy evidence bypass accepted")
			}
		})
	}
	neutral := map[string]CloudNeutralFieldSchema{"capacity_bytes": {ID: "capacity_bytes", ValueType: "unsigned_integer", Cardinality: "one", Unit: "bytes"}}
	field := cloudResolvedField{ID: "size", ValueType: "unsigned_integer", Cardinality: "one"}
	mapping := CloudMappingContractField{SourceFieldID: "size", Disposition: CloudSourceMapsExactSourceFact, TargetField: "capacity_bytes", Projection: CloudMappingProjectionGiBToBytes, SourceUnit: "gib", UnitEvidenceRef: "documented-unit"}
	if err := validateCloudMappingField(mapping, field, neutral); err != nil {
		t.Fatalf("well-typed primitive setup: %v", err)
	}
	mapping.UnitEvidenceRef = ""
	if err := validateCloudMappingField(mapping, field, neutral); err == nil {
		t.Fatal("unsigned GiB conversion without unit evidence accepted")
	}
	mapping.Projection = CloudMappingProjectionExact
	mapping.SourceUnit = "bytes"
	if err := validateCloudMappingField(mapping, field, neutral); err == nil {
		t.Fatal("exact byte-unit claim without evidence accepted")
	}
}

func TestCloudMappingEvidenceRejectsCorruptionAndEscapes(t *testing.T) {
	base := t.TempDir()
	raw := []byte("candidate documentation\n")
	if err := os.WriteFile(filepath.Join(base, "e.txt"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	valid := CloudMappingEvidenceBinding{ID: "e", SourceURI: "https://example.invalid/e", SourcePath: "e.txt", ExpectedSHA256: sha256Hex(raw), StartByte: 0, EndByte: len(raw), SliceSHA256: sha256Hex(raw)}
	for name, mutate := range map[string]func(*CloudMappingEvidenceBinding){
		"full-hash":     func(b *CloudMappingEvidenceBinding) { b.ExpectedSHA256 = sha256Hex([]byte("wrong")) },
		"slice-hash":    func(b *CloudMappingEvidenceBinding) { b.SliceSHA256 = sha256Hex([]byte("wrong")) },
		"slice-range":   func(b *CloudMappingEvidenceBinding) { b.StartByte = 1 },
		"out-of-bounds": func(b *CloudMappingEvidenceBinding) { b.EndByte++ },
		"parent-path":   func(b *CloudMappingEvidenceBinding) { b.SourcePath = "../e.txt" },
		"volume-path":   func(b *CloudMappingEvidenceBinding) { b.SourcePath = "C:e.txt" },
	} {
		t.Run(name, func(t *testing.T) {
			b := valid
			mutate(&b)
			contract := CloudMappingContract{EvidenceBindings: []CloudMappingEvidenceBinding{b}}
			if err := LoadCloudMappingEvidence(base, &contract); err == nil {
				t.Fatal("hostile evidence accepted")
			}
			if contract.evidenceStamp != "" {
				t.Fatal("failed evidence load installed a stamp")
			}
		})
	}
	t.Run("symlink-escape", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "outside.txt")
		if err := os.WriteFile(outside, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(base, "escape.txt")); err != nil {
			if runtime.GOOS == "windows" {
				t.Skip("host cannot create test symlinks; Linux CI exercises escape refusal")
			}
			t.Fatal(err)
		}
		b := valid
		b.SourcePath = "escape.txt"
		c := CloudMappingContract{EvidenceBindings: []CloudMappingEvidenceBinding{b}}
		if err := LoadCloudMappingEvidence(base, &c); err == nil {
			t.Fatal("out-of-package symlink accepted")
		}
	})
}
