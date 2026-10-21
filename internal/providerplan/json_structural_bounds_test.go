package providerplan

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProviderJSONStructuralDepthBoundary(t *testing.T) {
	atLimit := []byte(strings.Repeat("[", maxProviderJSONNestingDepth) + "0" + strings.Repeat("]", maxProviderJSONNestingDepth))
	if _, err := validateProviderJSONStructure(atLimit); err != nil {
		t.Fatalf("depth exactly at limit failed: %v", err)
	}
	overLimit := []byte(strings.Repeat("[", maxProviderJSONNestingDepth+1) + "0" + strings.Repeat("]", maxProviderJSONNestingDepth+1))
	for run := 0; run < 8; run++ {
		_, err := validateProviderJSONStructure(overLimit)
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("nesting depth %d", maxProviderJSONNestingDepth)) {
			t.Fatalf("run %d error = %v, want deterministic depth refusal", run, err)
		}
	}
}

func TestProviderJSONStructuralBroadValueExceedsNodeBound(t *testing.T) {
	var raw strings.Builder
	raw.Grow((maxProviderJSONNodesPerValue + 2) * 2)
	raw.WriteByte('[')
	for index := 0; index < maxProviderJSONNodesPerValue; index++ {
		if index != 0 {
			raw.WriteByte(',')
		}
		raw.WriteByte('0')
	}
	raw.WriteByte(']')
	if _, err := validateProviderJSONStructure([]byte(raw.String())); err == nil || !strings.Contains(err.Error(), "node limit") {
		t.Fatalf("broad JSON error = %v, want node-bound refusal", err)
	}
}

func TestProviderJSONAggregateAdmissionExactBoundaries(t *testing.T) {
	row := providerJSONStructure{Tokens: 1, Nodes: 1, StringBytes: 1, DecodedBytes: 1}
	artifact := providerJSONArtifactStructure{
		Rows: maxProviderJSONRowsPerArtifact - 1,
		providerJSONStructure: providerJSONStructure{
			Tokens:       maxProviderJSONTokensPerArtifact - 1,
			Nodes:        maxProviderJSONNodesPerArtifact - 1,
			StringBytes:  maxProviderJSONStringBytesArtifact - 1,
			DecodedBytes: maxProviderJSONDecodedBytesArtifact - 1,
		},
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	accumulator.actuals.StructuredJSONRowCount = maxProviderJSONRowsPerCorpus - 1
	accumulator.actuals.StructuredJSONTokenCount = maxProviderJSONTokensPerCorpus - 1
	accumulator.actuals.StructuredJSONNodeCount = maxProviderJSONNodesPerCorpus - 1
	accumulator.actuals.StructuredJSONStringBytes = maxProviderJSONStringBytesCorpus - 1
	accumulator.actuals.StructuredJSONDecodedBytes = maxProviderJSONDecodedBytesCorpus - 1
	if err := accumulator.admitStructuredJSONRow(providerInputAdmissionResourceKindArtifact, &artifact, row); err != nil {
		t.Fatalf("exact aggregate boundaries were rejected: %v", err)
	}
	if artifact.Rows != maxProviderJSONRowsPerArtifact || artifact.Nodes != maxProviderJSONNodesPerArtifact || artifact.Tokens != maxProviderJSONTokensPerArtifact || artifact.StringBytes != maxProviderJSONStringBytesArtifact || artifact.DecodedBytes != maxProviderJSONDecodedBytesArtifact {
		t.Fatalf("artifact aggregate = %+v, want every exact boundary", artifact)
	}
	if accumulator.actuals.StructuredJSONRowCount != maxProviderJSONRowsPerCorpus || accumulator.actuals.StructuredJSONNodeCount != maxProviderJSONNodesPerCorpus || accumulator.actuals.StructuredJSONTokenCount != maxProviderJSONTokensPerCorpus || accumulator.actuals.StructuredJSONStringBytes != maxProviderJSONStringBytesCorpus || accumulator.actuals.StructuredJSONDecodedBytes != maxProviderJSONDecodedBytesCorpus {
		t.Fatalf("corpus aggregate actuals=%+v, want every exact boundary", accumulator.actuals)
	}
}

func TestProviderJSONAggregateAdmissionRejectsEveryBoundaryPlusOneDeterministically(t *testing.T) {
	tests := []struct {
		name       string
		want       string
		initialize func(*providerInputAdmissionAccumulator, *providerJSONArtifactStructure) providerJSONStructure
	}{
		{name: "artifact_rows", want: "row count", initialize: func(_ *providerInputAdmissionAccumulator, artifact *providerJSONArtifactStructure) providerJSONStructure {
			artifact.Rows = maxProviderJSONRowsPerArtifact
			return providerJSONStructure{}
		}},
		{name: "corpus_rows", want: "row count", initialize: func(accumulator *providerInputAdmissionAccumulator, _ *providerJSONArtifactStructure) providerJSONStructure {
			accumulator.actuals.StructuredJSONRowCount = maxProviderJSONRowsPerCorpus
			return providerJSONStructure{}
		}},
		{name: "artifact_nodes", want: "node count", initialize: func(_ *providerInputAdmissionAccumulator, artifact *providerJSONArtifactStructure) providerJSONStructure {
			artifact.Nodes = maxProviderJSONNodesPerArtifact
			return providerJSONStructure{Nodes: 1}
		}},
		{name: "corpus_nodes", want: "node count", initialize: func(accumulator *providerInputAdmissionAccumulator, _ *providerJSONArtifactStructure) providerJSONStructure {
			accumulator.actuals.StructuredJSONNodeCount = maxProviderJSONNodesPerCorpus
			return providerJSONStructure{Nodes: 1}
		}},
		{name: "artifact_tokens", want: "token count", initialize: func(_ *providerInputAdmissionAccumulator, artifact *providerJSONArtifactStructure) providerJSONStructure {
			artifact.Tokens = maxProviderJSONTokensPerArtifact
			return providerJSONStructure{Tokens: 1}
		}},
		{name: "corpus_tokens", want: "token count", initialize: func(accumulator *providerInputAdmissionAccumulator, _ *providerJSONArtifactStructure) providerJSONStructure {
			accumulator.actuals.StructuredJSONTokenCount = maxProviderJSONTokensPerCorpus
			return providerJSONStructure{Tokens: 1}
		}},
		{name: "artifact_string_bytes", want: "string bytes", initialize: func(_ *providerInputAdmissionAccumulator, artifact *providerJSONArtifactStructure) providerJSONStructure {
			artifact.StringBytes = maxProviderJSONStringBytesArtifact
			return providerJSONStructure{StringBytes: 1}
		}},
		{name: "corpus_string_bytes", want: "string bytes", initialize: func(accumulator *providerInputAdmissionAccumulator, _ *providerJSONArtifactStructure) providerJSONStructure {
			accumulator.actuals.StructuredJSONStringBytes = maxProviderJSONStringBytesCorpus
			return providerJSONStructure{StringBytes: 1}
		}},
		{name: "artifact_decoded_bytes", want: "decoded bytes", initialize: func(_ *providerInputAdmissionAccumulator, artifact *providerJSONArtifactStructure) providerJSONStructure {
			artifact.DecodedBytes = maxProviderJSONDecodedBytesArtifact
			return providerJSONStructure{DecodedBytes: 1}
		}},
		{name: "corpus_decoded_bytes", want: "decoded bytes", initialize: func(accumulator *providerInputAdmissionAccumulator, _ *providerJSONArtifactStructure) providerJSONStructure {
			accumulator.actuals.StructuredJSONDecodedBytes = maxProviderJSONDecodedBytesCorpus
			return providerJSONStructure{DecodedBytes: 1}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for run := 0; run < 8; run++ {
				accumulator := newCanonicalProviderInputAdmissionAccumulator()
				artifact := providerJSONArtifactStructure{}
				row := test.initialize(accumulator, &artifact)
				err := accumulator.admitStructuredJSONRow(providerInputAdmissionResourceKindArtifact, &artifact, row)
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("run %d error = %v, want deterministic %s refusal", run, err, test.want)
				}
			}
		})
	}
}

func TestProviderJSONPerValueLimitsAreTheFixedCanonicalParserProfile(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*providerInputAdmissionLimits)
	}{
		{name: "nesting_depth", mutate: func(limits *providerInputAdmissionLimits) { limits.StructuredJSONNestingDepth-- }},
		{name: "nodes", mutate: func(limits *providerInputAdmissionLimits) { limits.StructuredJSONNodesPerValue-- }},
		{name: "tokens", mutate: func(limits *providerInputAdmissionLimits) { limits.StructuredJSONTokensPerValue-- }},
		{name: "string_bytes", mutate: func(limits *providerInputAdmissionLimits) { limits.StructuredJSONStringBytesPerValue-- }},
		{name: "decoded_bytes", mutate: func(limits *providerInputAdmissionLimits) { limits.StructuredJSONDecodedBytesPerValue-- }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := canonicalProviderInputAdmissionLimits
			test.mutate(&limits)
			if _, err := newProviderInputAdmissionAccumulator(limits); err == nil || !strings.Contains(err.Error(), "fixed canonical parser profile") {
				t.Fatalf("lower %s limit error = %v, want fixed-profile refusal", test.name, err)
			}
		})
	}
}

func TestProviderJSONWholeRunMultiRoleRowBoundaryAndAliasDedup(t *testing.T) {
	directory := t.TempDir()
	write := func(name string) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	stagePath := write("stage.json")
	authorityPath := write("authority.json")
	dependencyPath := write("dependency.json")
	limits := canonicalProviderInputAdmissionLimits
	limits.StructuredJSONRowsPerArtifact = 1
	limits.StructuredJSONRowsPerCorpus = 2
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	admit := func(path, label, kind, coordinate string) error {
		file, err := readBoundedProviderInputFile(path, label, kind, coordinate, accumulator)
		if err != nil {
			return err
		}
		return accumulator.admitStructuredJSONDocument(path, label, kind, file.Bytes)
	}
	if err := admit(stagePath, "stage JSON", providerInputAdmissionResourceKindStageFile, "stage|fixture"); err != nil {
		t.Fatal(err)
	}
	if err := admit(authorityPath, "authority JSON", providerInputAdmissionResourceKindAuthority, "authority|fixture"); err != nil {
		t.Fatal(err)
	}
	proof, err := accumulator.seal()
	if err != nil {
		t.Fatal(err)
	}
	if proof.Actuals.StructuredJSONRowCount != 2 || proof.Actuals.StructuredJSONNodeCount != 2 || proof.Actuals.StructuredJSONTokenCount != 4 {
		t.Fatalf("sealed multi-role structured actuals = %+v, want exact two-document traversal", proof.Actuals)
	}
	if err := admit(dependencyPath, "dependency JSON", providerInputAdmissionResourceKindArtifact, "dependency|fixture"); err == nil || !strings.Contains(err.Error(), "row count exceeds fixed artifact/corpus bound") {
		t.Fatalf("third structured role error = %v, want corpus boundary+1 refusal", err)
	}

	aliasAccumulator := newCanonicalProviderInputAdmissionAccumulator()
	stage, err := readBoundedProviderInputFile(stagePath, "stage JSON", providerInputAdmissionResourceKindStageFile, "stage|alias", aliasAccumulator)
	if err != nil {
		t.Fatal(err)
	}
	if err := aliasAccumulator.admitStructuredJSONDocument(stagePath, "stage JSON", providerInputAdmissionResourceKindStageFile, stage.Bytes); err != nil {
		t.Fatal(err)
	}
	aliasAccumulator.enableFactorySnapshotAliases()
	if err := aliasAccumulator.authorizeFactorySnapshotAlias(stagePath, "authority JSON", providerInputAdmissionResourceKindAuthority); err != nil {
		t.Fatal(err)
	}
	authority, err := readBoundedProviderInputFile(stagePath, "authority JSON", providerInputAdmissionResourceKindAuthority, "authority|alias", aliasAccumulator)
	if err != nil {
		t.Fatal(err)
	}
	if err := aliasAccumulator.admitStructuredJSONDocument(stagePath, "authority JSON", providerInputAdmissionResourceKindAuthority, authority.Bytes); err != nil {
		t.Fatal(err)
	}
	if aliasAccumulator.actuals.StructuredJSONRowCount != 1 || aliasAccumulator.actuals.StructuredJSONNodeCount != 1 {
		t.Fatalf("physical structured alias was charged more than once: %+v", aliasAccumulator.actuals)
	}
}

func TestProviderJSONAutoClassificationIsByteDerivedAndPathIndependent(t *testing.T) {
	tests := []struct {
		name     string
		raw      []byte
		wantRows int64
	}{
		{name: "whole_document_with_newlines", raw: []byte("{\n  \"value\": 1\n}\n"), wantRows: 1},
		{name: "two_jsonl_objects", raw: []byte("{}\n{\"value\":1}\n"), wantRows: 2},
		{name: "single_row_ambiguity_prefers_whole_document", raw: []byte("{}\n"), wantRows: 1},
		{name: "string_scalar", raw: []byte(`"scalar"`), wantRows: 1},
		{name: "number_scalar", raw: []byte(`123456789`), wantRows: 1},
		{name: "boolean_scalar", raw: []byte(`true`), wantRows: 1},
		{name: "null_scalar", raw: []byte(`null`), wantRows: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var first providerInputAdmissionProof
			for index, extension := range []string{".json", ".jsonl", ".txt", ""} {
				path := filepath.Join(t.TempDir(), "same-bytes"+extension)
				if err := os.WriteFile(path, test.raw, 0o600); err != nil {
					t.Fatal(err)
				}
				accumulator := newCanonicalProviderInputAdmissionAccumulator()
				file, err := readBoundedProviderInputFile(path, "byte-derived structured input", providerInputAdmissionResourceKindStageFile, "stage|byte-derived", accumulator)
				if err != nil {
					t.Fatal(err)
				}
				if err := accumulator.admitStructuredJSONAuto(path, "byte-derived structured input", providerInputAdmissionResourceKindStageFile, file.Bytes); err != nil {
					t.Fatal(err)
				}
				proof, err := accumulator.seal()
				if err != nil {
					t.Fatal(err)
				}
				if proof.Actuals.StructuredJSONRowCount != test.wantRows {
					t.Fatalf("extension %q row count = %d, want %d", extension, proof.Actuals.StructuredJSONRowCount, test.wantRows)
				}
				if index == 0 {
					first = proof
				} else if proof != first {
					t.Fatalf("extension %q changed byte-derived admission proof:\nfirst=%+v\ncurrent=%+v", extension, first, proof)
				}
			}
		})
	}
}

func TestProviderJSONAutoScalarExactStringBoundaryAndPlusOne(t *testing.T) {
	admit := func(size int) (providerInputAdmissionProof, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "scalar.txt")
		raw := make([]byte, size+2)
		raw[0] = '"'
		for index := 1; index <= size; index++ {
			raw[index] = 'a'
		}
		raw[len(raw)-1] = '"'
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		accumulator := newCanonicalProviderInputAdmissionAccumulator()
		file, err := readBoundedProviderInputFile(path, "scalar structured input", providerInputAdmissionResourceKindStageFile, "stage|scalar", accumulator)
		if err != nil {
			return providerInputAdmissionProof{}, err
		}
		if err := accumulator.admitStructuredJSONAuto(path, "scalar structured input", providerInputAdmissionResourceKindStageFile, file.Bytes); err != nil {
			return providerInputAdmissionProof{}, err
		}
		return accumulator.seal()
	}
	proof, err := admit(int(maxProviderJSONStringBytesPerValue))
	if err != nil {
		t.Fatalf("scalar string exactly at structural limit failed: %v", err)
	}
	if proof.Actuals.StructuredJSONRowCount != 1 || proof.Actuals.StructuredJSONStringBytes != maxProviderJSONStringBytesPerValue {
		t.Fatalf("scalar boundary actuals = %+v, want one charged %d-byte string", proof.Actuals, maxProviderJSONStringBytesPerValue)
	}
	if _, err := admit(int(maxProviderJSONStringBytesPerValue + 1)); err == nil || !strings.Contains(err.Error(), "decoded string-byte limit") {
		t.Fatalf("scalar string boundary+1 error = %v, want deterministic structural refusal", err)
	}
}

func TestDependencyArtifactParserEnforcesAggregateRowsBeforeRetainingSecondObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dependency.jsonl")
	raw := []byte("{\"row_kind\":\"artifact_manifest\",\"artifact\":\"fixture\",\"artifact_version\":\"1\"}\n{\"row_kind\":\"validation_summary\"}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	limits := canonicalProviderInputAdmissionLimits
	limits.StructuredJSONRowsPerArtifact = 1
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifactInputWithAdmission(path, accumulator); err == nil || !strings.Contains(err.Error(), "row count exceeds fixed artifact/corpus bound") {
		t.Fatalf("dependency second-row error = %v, want pre-retention artifact-row refusal", err)
	}
	if accumulator.actuals.StructuredJSONRowCount != 1 {
		t.Fatalf("charged rows = %d, want only the admitted first row", accumulator.actuals.StructuredJSONRowCount)
	}
}

func TestDependencyArtifactParserReusesOneBoundedDecodedRowGraph(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dependency.jsonl")
	raw := []byte("{\"row_kind\":\"artifact_manifest\",\"artifact\":\"fixture\",\"artifact_version\":\"1\"}\n{\"row_kind\":\"validation_summary\"}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	input, err := readArtifactInputWithAdmission(path, accumulator)
	if err != nil {
		t.Fatal(err)
	}
	if len(input.ParsedRows) != 2 || len(input.RowsByKind["artifact_manifest"]) != 1 {
		t.Fatalf("retained row roster = parsed %d manifest %d, want 2/1", len(input.ParsedRows), len(input.RowsByKind["artifact_manifest"]))
	}
	input.ParsedRows[0].Data["shared_decode_probe"] = "same-object"
	if got := input.RowsByKind["artifact_manifest"][0]["shared_decode_probe"]; got != "same-object" {
		t.Fatalf("RowsByKind retained a second decoded object graph: got %#v", got)
	}
	rows, err := parseDependencySemanticRows(input)
	if err != nil {
		t.Fatal(err)
	}
	rows.byKind["artifact_manifest"][0].data["semantic_probe"] = "same-object"
	if got := input.ParsedRows[0].Data["semantic_probe"]; got != "same-object" {
		t.Fatalf("semantic parser retained a second decoded object graph: got %#v", got)
	}
}

func TestStructuredJSONCorpusLimitSpansDistinctDependencyDocuments(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "first.json"), filepath.Join(dir, "second.json")}
	for index, path := range paths {
		if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"authority":"bounded-%d"}`, index)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	limits := canonicalProviderInputAdmissionLimits
	limits.StructuredJSONRowsPerArtifact = 1
	limits.StructuredJSONRowsPerCorpus = 1
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifactInputWithAdmission(paths[0], accumulator); err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifactInputWithAdmission(paths[1], accumulator); err == nil || !strings.Contains(err.Error(), "row count exceeds fixed artifact/corpus bound") {
		t.Fatalf("second dependency document error = %v, want whole-corpus row refusal", err)
	}
}

func TestSequentialEvidenceClosureRescansChargeRawTraversalWork(t *testing.T) {
	raw := []byte(`{"carrier":"ordinary-metadata"}`)
	item := evidenceClosureItem{label: "bounded", raw: raw, structured: true}
	budget := &canonicalEvidenceClosureWorkBudget{limit: int64(len(raw))*2 + 4}
	for pass := 0; pass < 2; pass++ {
		err := scanEvidenceClosureItemWithOrderBudget(item, jsonCarrierSourceOrder, budget, func(orderedJSONCarrier) error { return nil })
		if pass == 0 && err != nil {
			t.Fatalf("first bounded traversal failed: %v", err)
		}
		if pass == 1 && (err == nil || !strings.Contains(err.Error(), "aggregate work-unit limit")) {
			t.Fatalf("second traversal error = %v, want aggregate raw/token work refusal", err)
		}
	}
	if budget.used <= int64(len(raw)) {
		t.Fatalf("charged byte work = %d, want raw bytes plus structural tokens", budget.used)
	}
}

func TestWalkJSONCarriersDefenseInDepthMatchesStructuralBoundary(t *testing.T) {
	atLimit := []byte(strings.Repeat("[", maxProviderJSONNestingDepth) + `"safe"` + strings.Repeat("]", maxProviderJSONNestingDepth))
	var carriers int
	if err := walkJSONCarriers(atLimit, jsonCarrierSourceOrder, func(orderedJSONCarrier) error { carriers++; return nil }); err != nil {
		t.Fatalf("carrier walk at depth limit failed: %v", err)
	}
	if carriers != 1 {
		t.Fatalf("carrier count = %d, want 1", carriers)
	}
	overLimit := bytes.Replace(atLimit, []byte(`"safe"`), []byte(`["safe"]`), 1)
	if err := walkJSONCarriers(overLimit, jsonCarrierSourceOrder, func(orderedJSONCarrier) error { return nil }); err == nil {
		t.Fatal("carrier walk above depth limit succeeded")
	}
}
