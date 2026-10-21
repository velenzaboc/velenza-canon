package providerplan

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
)

type stageContractFixture struct {
	evidenceRequest semanticStageRequestHolder[evidenceIntakeStageRequest]
	evidenceReceipt []byte
	evidenceSummary StageReceiptSummary
	semanticRequest semanticStageRequestHolder[semanticExtractionStageRequest]
	semanticReceipt []byte
	semanticSummary StageReceiptSummary
	graphRequest    semanticStageRequestHolder[graphCompileStageRequest]
	graphReceipt    []byte
	graphSummary    StageReceiptSummary
	fullRequest     semanticStageRequestHolder[fullFactoryStageRequest]
	fullReceipt     []byte
	fullSummary     StageReceiptSummary
	body            []byte
}

type semanticStageRequestHolder[T any] struct {
	request T
	raw     []byte
	inputs  StageCompileInputs
}

type testStageTarget struct {
	identity  stageArtifactIdentity
	raw       []byte
	schemaPin immutableStageArtifactPin
	schemaRaw []byte
}

func TestStageContractValidatesExactBytesAndComposesDeterministically(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	again, err := CompileStageReceipt(fixture.fullRequest.raw, fixture.fullRequest.inputs)
	if err != nil {
		t.Fatalf("compile identical full stage: %v", err)
	}
	if !bytes.Equal(again, fixture.fullReceipt) {
		t.Fatalf("same exact inputs produced different commitments")
	}

	for name, raw := range map[string][]byte{
		"evidence": fixture.evidenceReceipt,
		"semantic": fixture.semanticReceipt,
		"graph":    fixture.graphReceipt,
		"full":     fixture.fullReceipt,
	} {
		t.Run(name, func(t *testing.T) {
			summary, err := ValidateStageReceipt(raw)
			if err != nil {
				t.Fatalf("validate stage commitment: %v", err)
			}
			if !isLowerSHA256(summary.ReceiptSHA256) || !isLowerSHA256(summary.OutputRootSHA256) {
				t.Fatalf("non-exact commitment identity: %+v", summary)
			}
			var receipt stageReceipt
			if err := json.Unmarshal(raw, &receipt); err != nil {
				t.Fatal(err)
			}
			if !receipt.BodyFree || receipt.DerivationExecuted || receipt.AuthoritySelected || receipt.AdmissionAuthorized || receipt.FactoryComplete {
				t.Fatalf("commitment overclaims execution/authority/admission/completion: %+v", receipt)
			}
			if bytes.Contains(raw, fixture.body) {
				t.Fatal("commitment copied exact provider evidence body")
			}
		})
	}
	if len(fixture.evidenceSummary.EvidenceCommitments) != 1 {
		t.Fatalf("evidence commitment roster length = %d", len(fixture.evidenceSummary.EvidenceCommitments))
	}
	for name, summary := range map[string]StageReceiptSummary{
		"semantic": fixture.semanticSummary,
		"graph":    fixture.graphSummary,
		"full":     fixture.fullSummary,
	} {
		if !equalStageEvidenceCommitments(fixture.evidenceSummary.EvidenceCommitments, summary.EvidenceCommitments) {
			t.Fatalf("%s stage did not inherit the exact intake evidence commitment roster", name)
		}
	}
}

func TestStageContractRequiresExactEvidenceBodiesAtEveryDownstreamStage(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	stages := []struct {
		name    string
		request []byte
		inputs  StageCompileInputs
	}{
		{"semantic", fixture.semanticRequest.raw, fixture.semanticRequest.inputs},
		{"graph", fixture.graphRequest.raw, fixture.graphRequest.inputs},
		{"full", fixture.fullRequest.raw, fixture.fullRequest.inputs},
	}
	for _, stage := range stages {
		t.Run(stage.name+"_missing", func(t *testing.T) {
			inputs := stage.inputs
			inputs.EvidenceBodies = nil
			if _, err := CompileStageReceipt(stage.request, inputs); err == nil || !strings.Contains(err.Error(), "exact bodies were supplied") {
				t.Fatalf("missing lineage body error = %v", err)
			}
		})
		t.Run(stage.name+"_substituted", func(t *testing.T) {
			inputs := stage.inputs
			inputs.EvidenceBodies = cloneStageEvidenceBodies(stage.inputs.EvidenceBodies)
			inputs.EvidenceBodies[0].Raw = append([]byte(nil), stage.inputs.EvidenceBodies[0].Raw...)
			inputs.EvidenceBodies[0].Raw[0] ^= 1
			if _, err := CompileStageReceipt(stage.request, inputs); err == nil || !strings.Contains(err.Error(), "immutable lineage digest/byte commitment") {
				t.Fatalf("substituted lineage body error = %v", err)
			}
		})
		t.Run(stage.name+"_extra", func(t *testing.T) {
			inputs := stage.inputs
			inputs.EvidenceBodies = append(cloneStageEvidenceBodies(stage.inputs.EvidenceBodies), stage.inputs.EvidenceBodies[0])
			if _, err := CompileStageReceipt(stage.request, inputs); err == nil || !strings.Contains(err.Error(), "exact bodies were supplied") {
				t.Fatalf("extra lineage body error = %v", err)
			}
		})
	}
}

func TestStageContractPreservesByteEqualOccurrencesAndRejectsReorderedOrSubstitutedEvidence(t *testing.T) {
	t.Parallel()
	leftBody := []byte("first exact evidence body")
	rightBody := []byte("second exact evidence body")
	commitments := []StageEvidenceCommitment{
		{ManifestRole: "selected_evidence", ManifestID: "manifest", ManifestVersion: "1", ComponentOrdinal: 0, BodySHA256: sha256Hex(leftBody), ByteCount: uint64(len(leftBody))},
		{ManifestRole: "selected_evidence", ManifestID: "manifest", ManifestVersion: "1", ComponentOrdinal: 1, BodySHA256: sha256Hex(rightBody), ByteCount: uint64(len(rightBody))},
	}
	bodies := []StageEvidenceBody{
		{ManifestRole: "selected_evidence", ManifestID: "manifest", ManifestVersion: "1", ComponentOrdinal: 0, Raw: leftBody},
		{ManifestRole: "selected_evidence", ManifestID: "manifest", ManifestVersion: "1", ComponentOrdinal: 1, Raw: rightBody},
	}

	reorderedBodies := []StageEvidenceBody{bodies[1], bodies[0]}
	if _, err := validateInheritedStageEvidence(commitments, reorderedBodies); err == nil || !strings.Contains(err.Error(), "reordered or substituted") {
		t.Fatalf("reordered exact bodies error = %v", err)
	}
	reorderedCommitments := []StageEvidenceCommitment{commitments[1], commitments[0]}
	if err := validateStageEvidenceCommitmentRoster(reorderedCommitments); err == nil || !strings.Contains(err.Error(), "ordinal zero") {
		t.Fatalf("reordered commitments error = %v", err)
	}
	aliased := append([]StageEvidenceCommitment(nil), commitments...)
	aliased[1].BodySHA256 = aliased[0].BodySHA256
	aliased[1].ByteCount = aliased[0].ByteCount
	if err := validateStageEvidenceCommitmentRoster(aliased); err != nil {
		t.Fatalf("byte-equal occurrence commitments were rejected: %v", err)
	}
	substituted := append([]StageEvidenceCommitment(nil), commitments...)
	substituted[1].BodySHA256 = stageDigest("substituted body commitment")
	if _, err := validateInheritedStageEvidence(substituted, bodies); err == nil || !strings.Contains(err.Error(), "immutable lineage digest/byte commitment") {
		t.Fatalf("substituted commitment error = %v", err)
	}

	manifestCoordinate := stageMaterialCoordinate{Role: "selected_evidence", ID: "manifest", Version: "1"}
	manifestRaw := mustStageJSONL(t,
		map[string]interface{}{"row_kind": "external_evidence_body", "component_ordinal": 0, "content_sha256": sha256Hex(leftBody), "content_bytes": len(leftBody)},
		map[string]interface{}{"row_kind": "external_evidence_body", "component_ordinal": 1, "content_sha256": sha256Hex(rightBody), "content_bytes": len(rightBody)},
	)
	binding := evidenceIntakeStageBinding{EvidenceManifests: []evidenceManifestStageBinding{{
		Role: manifestCoordinate.Role, ArtifactID: manifestCoordinate.ID, ArtifactVersion: manifestCoordinate.Version,
		ArtifactRawSHA256: sha256Hex(manifestRaw), BodyCount: 2, ByteCount: uint64(len(leftBody) + len(rightBody)),
	}}}
	materials := map[stageMaterialCoordinate]StageMaterial{manifestCoordinate: {
		Role: manifestCoordinate.Role, ID: manifestCoordinate.ID, Version: manifestCoordinate.Version, Raw: manifestRaw,
	}}
	if _, _, err := validateExactStageEvidence(binding, materials, reorderedBodies); err == nil || !strings.Contains(err.Error(), "reordered or substituted") {
		t.Fatalf("reordered intake bodies error = %v", err)
	}

	aliasManifestRaw := mustStageJSONL(t,
		map[string]interface{}{"row_kind": "external_evidence_body", "component_ordinal": 0, "content_sha256": sha256Hex(leftBody), "content_bytes": len(leftBody)},
		map[string]interface{}{"row_kind": "external_evidence_body", "component_ordinal": 1, "content_sha256": sha256Hex(leftBody), "content_bytes": len(leftBody)},
	)
	binding.EvidenceManifests[0].ArtifactRawSHA256 = sha256Hex(aliasManifestRaw)
	binding.EvidenceManifests[0].ByteCount = uint64(len(leftBody) * 2)
	materials[manifestCoordinate] = StageMaterial{Role: manifestCoordinate.Role, ID: manifestCoordinate.ID, Version: manifestCoordinate.Version, Raw: aliasManifestRaw}
	aliasedBodies := []StageEvidenceBody{bodies[0], bodies[0]}
	aliasedBodies[1].ComponentOrdinal = 1
	exactBodies, occurrenceCommitments, err := validateExactStageEvidence(binding, materials, aliasedBodies)
	if err != nil {
		t.Fatalf("byte-equal evidence occurrences were rejected: %v", err)
	}
	if len(exactBodies) != 1 || len(occurrenceCommitments) != 2 || occurrenceCommitments[0].ComponentOrdinal != 0 || occurrenceCommitments[1].ComponentOrdinal != 1 {
		t.Fatalf("byte-equal occurrence/content cardinality = %d/%d with commitments %+v, want one content and two ordered occurrences", len(exactBodies), len(occurrenceCommitments), occurrenceCommitments)
	}
	if inherited, err := validateInheritedStageEvidence(occurrenceCommitments, aliasedBodies); err != nil || len(inherited) != 1 {
		t.Fatalf("inherited byte-equal occurrence roster = %d, %v; want one deduplicated scanner content", len(inherited), err)
	}
	receipt := stageReceipt{
		RequestSHA256: stageDigest("byte-equal request"), OutputRootSHA256: stageDigest("byte-equal output"), ReceiptSHA256: stageDigest("byte-equal receipt"),
		EvidenceCommitments: occurrenceCommitments,
	}
	if err := validateGeneratedReceiptDigestSeparation(receipt); err != nil {
		t.Fatalf("generated receipt rejected distinct byte-equal evidence occurrences: %v", err)
	}
	receipt.RequestSHA256 = occurrenceCommitments[0].BodySHA256
	if err := validateGeneratedReceiptDigestSeparation(receipt); err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Fatalf("generated receipt accepted evidence/control digest alias: %v", err)
	}
}

func TestStageContractRejectsEvidenceBodyLeakAtEveryDownstreamStage(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)

	t.Run("semantic_decoded", func(t *testing.T) {
		request := fixture.semanticRequest.request
		inputs := fixture.semanticRequest.inputs
		pin := &request.DerivationBindings[0].Extractor
		leak := mustStageJSON(t, map[string]interface{}{"row_kind": "extractor", "value": string(fixture.body)})
		inputs.Materials = replaceStageMaterialRaw(inputs.Materials, pin.Role, pin.ID, pin.Version, leak)
		pin.RawSHA256 = sha256Hex(leak)
		assertStageBodyLeakRejected(t, mustStageJSON(t, request), inputs)
	})

	t.Run("semantic_hex", func(t *testing.T) {
		request := fixture.semanticRequest.request
		inputs := fixture.semanticRequest.inputs
		pin := &request.DerivationBindings[0].Extractor
		leak := mustStageJSON(t, map[string]interface{}{"row_kind": "extractor", "value": hex.EncodeToString(fixture.body)})
		inputs.Materials = replaceStageMaterialRaw(inputs.Materials, pin.Role, pin.ID, pin.Version, leak)
		pin.RawSHA256 = sha256Hex(leak)
		assertStageBodyLeakRejected(t, mustStageJSON(t, request), inputs)
	})

	t.Run("graph_base64", func(t *testing.T) {
		request := fixture.graphRequest.request
		inputs := fixture.graphRequest.inputs
		replaceGraphTargetSchemaWithField(t, &request, &inputs, request.Plan, "$comment", base64.StdEncoding.EncodeToString(fixture.body))
		assertStageBodyLeakRejected(t, mustStageJSON(t, request), inputs)
	})

	t.Run("full_reconstructed", func(t *testing.T) {
		request := fixture.fullRequest.request
		inputs := fixture.fullRequest.inputs
		pin := &request.StageValidation.Schema
		midpoint := len(fixture.body) / 2
		leak := stageSchemaWithField(t, inputs.Materials, *pin, "x-lineage-copy", []string{string(fixture.body[:midpoint]), string(fixture.body[midpoint:])})
		inputs.Materials = replaceStageMaterialRaw(inputs.Materials, pin.Role, pin.ID, pin.Version, leak)
		pin.RawSHA256 = sha256Hex(leak)
		assertStageBodyLeakRejected(t, mustStageJSON(t, request), inputs)
	})

	t.Run("full_substantial_fragment", func(t *testing.T) {
		request := fixture.fullRequest.request
		inputs := fixture.fullRequest.inputs
		pin := &request.StageValidation.Schema
		leak := stageSchemaWithField(t, inputs.Materials, *pin, "$comment", string(fixture.body[256:1536]))
		inputs.Materials = replaceStageMaterialRaw(inputs.Materials, pin.Role, pin.ID, pin.Version, leak)
		pin.RawSHA256 = sha256Hex(leak)
		assertStageBodyLeakRejected(t, mustStageJSON(t, request), inputs)
	})
}

func TestStageBodyFreeClosureAcceptsUnchangedReal6160ByteComposition(t *testing.T) {
	t.Parallel()
	if len(testProtocolEvidenceBody) != 6_160 {
		t.Fatalf("real protocol evidence fixture length = %d, want unchanged 6,160 bytes", len(testProtocolEvidenceBody))
	}
	fixture := newTestFixture(t)
	lineage := newRealVerifyFactoryLineage(t, fixture)
	for index := range lineage.requests {
		receipt, err := CompileStageReceipt(lineage.requests[index], lineage.inputs[index])
		if err != nil {
			t.Fatalf("compile real candidate-only lineage stage %d: %v", index, err)
		}
		if _, err := ValidateStageReceipt(receipt); err != nil {
			t.Fatalf("validate real candidate-only lineage stage %d: %v", index, err)
		}
	}
}

func TestStageContractRejectsEvidenceReconstructedAcrossPredecessorReceipts(t *testing.T) {
	t.Parallel()
	body := []byte("Exact provider evidence body carried only as two disordered receipt fragments for the closure regression.")
	fixture := newStageContractFixtureWithBody(t, body)
	encoded := hex.EncodeToString(body)
	midpoint := len(encoded) / 2
	if midpoint%2 != 0 {
		midpoint++
	}

	semanticReceipt := reissueStageReceipt(t, fixture.semanticReceipt, func(receipt *stageReceipt) {
		var binding semanticExtractionStageBinding
		if err := json.Unmarshal(receipt.Binding, &binding); err != nil {
			t.Fatal(err)
		}
		binding.DerivationBindings[0].Extractor.ID = encoded[:midpoint]
		receipt.Binding = mustStageJSON(t, binding)
	})
	semanticSummary := mustValidateStage(t, semanticReceipt)
	graphReceipt := reissueStageReceipt(t, fixture.graphReceipt, func(receipt *stageReceipt) {
		var binding graphCompileStageBinding
		if err := json.Unmarshal(receipt.Binding, &binding); err != nil {
			t.Fatal(err)
		}
		binding.Plan.ID = encoded[midpoint:]
		receipt.Binding = mustStageJSON(t, binding)
		receipt.Predecessors = []StageReceiptReference{stageRef(semanticSummary)}
	})
	graphSummary := mustValidateStage(t, graphReceipt)

	request := fixture.fullRequest.request
	request.PriorReceipts[1] = stageRef(semanticSummary)
	request.PriorReceipts[2] = stageRef(graphSummary)
	inputs := fixture.fullRequest.inputs
	inputs.PredecessorReceipts = [][]byte{fixture.evidenceReceipt, semanticReceipt, graphReceipt}
	if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "unordered exact scalar carriers reconstruct") {
		t.Fatalf("cross-receipt evidence reconstruction error = %v", err)
	}
}

func TestStageContractRejectsEvidenceReconstructedAgainstMaterialCoordinateOrder(t *testing.T) {
	t.Parallel()
	body := []byte("Exact provider evidence body whose first and second fragments occupy reverse material coordinates.")
	fixture := newStageContractFixtureWithBody(t, body)
	midpoint := len(body) / 2
	request := fixture.graphRequest.request
	inputs := fixture.graphRequest.inputs

	replaceGraphTargetSchemaWithField(t, &request, &inputs, request.Plan, "$comment", string(body[midpoint:]))
	replaceGraphTargetSchemaWithField(t, &request, &inputs, request.DependencyArtifacts[0], "$comment", string(body[:midpoint]))

	if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "unordered exact scalar carriers reconstruct") {
		t.Fatalf("reverse-coordinate evidence reconstruction error = %v", err)
	}
}

func TestStageEvidenceUnorderedSegmentationDoesNotReuseOneScalarOccurrence(t *testing.T) {
	t.Parallel()
	target := []byte("abcabc")
	carriers := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("abc")}}}
	index := newStageEvidenceSegmentationIndex(carriers)
	reconstructed, err := stageEvidenceTargetHasUnorderedSegmentation(target, carriers, index)
	if err != nil {
		t.Fatalf("single-occurrence segmentation error = %v", err)
	}
	if reconstructed {
		t.Fatal("one scalar occurrence was reused to reconstruct two target segments")
	}

	carriers = append(carriers, stageEvidenceCarrierOccurrence{representations: [][]byte{[]byte("abc")}})
	index = newStageEvidenceSegmentationIndex(carriers)
	reconstructed, err = stageEvidenceTargetHasUnorderedSegmentation(target, carriers, index)
	if err != nil {
		t.Fatalf("two-occurrence segmentation error = %v", err)
	}
	if !reconstructed {
		t.Fatal("two distinct scalar occurrences did not reconstruct the exact target")
	}
}

func TestStageEvidenceUnorderedSegmentationNormalizesUppercaseOddNibbleHexPerOccurrence(t *testing.T) {
	t.Parallel()
	body := []byte{0xab, 0xcd, 0xef}
	digest := sha256Hex(body)
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("dEf")}},
		{representations: [][]byte{[]byte("AbC")}},
	}
	gotDigest, encoding, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, map[string]exactEvidenceBody{
		digest: {Bytes: body},
	})
	if err != nil {
		t.Fatalf("mixed-case odd-nibble hexadecimal reconstruction error = %v", err)
	}
	if !reconstructed || gotDigest != digest || encoding != "complete hexadecimal body" {
		t.Fatalf("mixed-case odd-nibble hexadecimal reconstruction = (%q, %q, %t), want (%q, complete hexadecimal body, true)", gotDigest, encoding, reconstructed, digest)
	}

	caseSensitiveBody := []byte("abcdef")
	_, encoding, reconstructed, err = reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, map[string]exactEvidenceBody{
		sha256Hex(caseSensitiveBody): {Bytes: caseSensitiveBody},
	})
	if err != nil {
		t.Fatalf("case-sensitive raw metadata control error = %v", err)
	}
	if reconstructed {
		t.Fatalf("hexadecimal normalization leaked into the case-sensitive raw target as %s", encoding)
	}
}

func TestStageEvidenceWrappedTwoOccurrenceSegmentationPreservesOccurrenceMultiplicity(t *testing.T) {
	t.Parallel()
	target := []byte("ExactBody")
	digest := sha256Hex(target)
	bodies := map[string]exactEvidenceBody{digest: {Bytes: target}}

	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("BodySuffix")}},
		{representations: [][]byte{[]byte("prefixExact")}},
	}
	gotDigest, encoding, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, bodies)
	if err != nil {
		t.Fatalf("reverse-order wrapped-fragment reconstruction error = %v", err)
	}
	if !reconstructed || gotDigest != digest || encoding != "complete decoded body" {
		t.Fatalf("reverse-order wrapped-fragment reconstruction = (%q, %q, %t), want (%q, complete decoded body, true)", gotDigest, encoding, reconstructed, digest)
	}

	carriers = []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("prefixExact"), []byte("BodySuffix")}}}
	_, encoding, reconstructed, err = reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, bodies)
	if err != nil {
		t.Fatalf("single-occurrence alternate-representation control error = %v", err)
	}
	if reconstructed {
		t.Fatalf("one scalar occurrence was reused through alternate representations to reconstruct %s", encoding)
	}

	carriers = []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("ordinary-E-metadata")}},
		{representations: [][]byte{[]byte("ordinary-y-metadata")}},
	}
	_, encoding, reconstructed, err = reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, bodies)
	if err != nil {
		t.Fatalf("ordinary metadata acceptance control error = %v", err)
	}
	if reconstructed {
		t.Fatalf("ordinary metadata falsely reconstructed %s", encoding)
	}
}

func TestStageEvidenceWrappedReconstructionUsesAnyDistinctOccurrenceCount(t *testing.T) {
	t.Parallel()
	target := []byte("ABCDEFGHIJKL")
	digest := sha256Hex(target)
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("xxABCDyy")}},
		{representations: [][]byte{[]byte("xxEFGHyy")}},
		{representations: [][]byte{[]byte("xxIJKLyy")}},
	}
	gotDigest, encoding, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, map[string]exactEvidenceBody{
		digest: {Bytes: target},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reconstructed || gotDigest != digest || encoding != "complete decoded body" {
		t.Fatalf("three-occurrence wrapped reconstruction = (%q, %q, %t), want (%q, complete decoded body, true)", gotDigest, encoding, reconstructed, digest)
	}
}

func TestStageEvidenceWrappedReconstructionCoversThreeEncodedFragments(t *testing.T) {
	t.Parallel()
	body := []byte{0xfb, 0xff, 0xef, 0x01, 0x25, 0x77, 0x9a, 0xbc, 0xde}
	digest := sha256Hex(body)
	tests := []struct {
		name     string
		target   string
		encoding string
	}{
		{name: "padded standard base64", target: base64.StdEncoding.EncodeToString(body), encoding: "complete padded standard base64 body"},
		{name: "hexadecimal", target: hex.EncodeToString(body), encoding: "complete hexadecimal body"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := len(test.target) / 3
			second := (2 * len(test.target)) / 3
			carriers := []stageEvidenceCarrierOccurrence{
				{representations: [][]byte{[]byte("left[" + test.target[:first] + "]")}},
				{representations: [][]byte{[]byte("middle[" + test.target[first:second] + "]")}},
				{representations: [][]byte{[]byte("right[" + test.target[second:] + "]")}},
			}
			gotDigest, gotEncoding, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, map[string]exactEvidenceBody{digest: {Bytes: body}})
			if err != nil {
				t.Fatal(err)
			}
			if !reconstructed || gotDigest != digest || gotEncoding != test.encoding {
				t.Fatalf("reconstructed=%v digest=%q encoding=%q, want %q / %q", reconstructed, gotDigest, gotEncoding, digest, test.encoding)
			}
		})
	}
}

func TestStageEvidenceWrappedReconstructionCoversDecodedBase64Carriers(t *testing.T) {
	t.Parallel()
	body := []byte("raw evidence bytes reconstructed only after decoding three independently wrapped base64 scalars")
	digest := sha256Hex(body)
	first, second := len(body)/3, (2*len(body))/3
	parts := [][]byte{body[:first], body[first:second], body[second:]}
	storage := &stageEvidenceCarrierStorageBudget{}
	carriers := make([]stageEvidenceCarrierOccurrence, len(parts))
	for index, part := range parts {
		wrapped := append([]byte(fmt.Sprintf("wrapper-%d[", index)), part...)
		wrapped = append(wrapped, "]suffix"...)
		scalar := []byte(base64.StdEncoding.EncodeToString(wrapped))
		representations, err := stageEvidenceCarrierRepresentations(orderedJSONCarrier{bytes: scalar, kind: orderedJSONStringValue}, storage)
		if err != nil {
			t.Fatal(err)
		}
		carriers[index] = stageEvidenceCarrierOccurrence{representations: representations}
	}
	gotDigest, encoding, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, map[string]exactEvidenceBody{digest: {Bytes: body}})
	if err != nil {
		t.Fatal(err)
	}
	if !reconstructed || gotDigest != digest || encoding != "complete decoded body" {
		t.Fatalf("decoded-base64 wrapped reconstruction = (%q, %q, %t), want (%q, complete decoded body, true)", gotDigest, encoding, reconstructed, digest)
	}
}

func TestStageEvidenceWrappedReconstructionCoversEveryThreeFragmentBase64Variant(t *testing.T) {
	t.Parallel()
	body := []byte{0xfb, 0xff, 0xef, 0x01, 0x25, 0x77, 0x9a, 0xbc}
	digest := sha256Hex(body)
	tests := []struct {
		name     string
		encoding *base64.Encoding
		label    string
		padded   bool
	}{
		{name: "standard padded with actual padding", encoding: base64.StdEncoding, label: "complete padded standard base64 body", padded: true},
		{name: "standard raw", encoding: base64.RawStdEncoding, label: "complete unpadded standard base64 body"},
		{name: "URL padded with actual padding", encoding: base64.URLEncoding, label: "complete padded URL-safe base64 body", padded: true},
		{name: "URL raw", encoding: base64.RawURLEncoding, label: "complete unpadded URL-safe base64 body"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := test.encoding.EncodeToString(body)
			if test.padded && !strings.HasSuffix(target, "=") {
				t.Fatalf("fixture %q lacks actual padding", target)
			}
			first, second := len(target)/3, (2*len(target))/3
			carriers := []stageEvidenceCarrierOccurrence{
				{representations: [][]byte{[]byte("right[" + target[second:] + "]")}},
				{representations: [][]byte{[]byte("left[" + target[:first] + "]")}},
				{representations: [][]byte{[]byte("middle[" + target[first:second] + "]")}},
			}
			gotDigest, gotEncoding, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, map[string]exactEvidenceBody{digest: {Bytes: body}})
			if err != nil {
				t.Fatal(err)
			}
			if !reconstructed || gotDigest != digest || gotEncoding != test.label {
				t.Fatalf("reconstructed=%v digest=%q encoding=%q, want %q / %q", reconstructed, gotDigest, gotEncoding, digest, test.label)
			}
		})
	}
}

func TestStageEvidenceWrappedHexReconstructionFoldsMixedCaseAcrossOddNibbleFragments(t *testing.T) {
	t.Parallel()
	body := []byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0xfa}
	digest := sha256Hex(body)
	target := hex.EncodeToString(body)
	first, second := 3, 9
	parts := []string{target[:first], target[first:second], target[second:]}
	for index := range parts {
		var mixed strings.Builder
		for ordinal, current := range parts[index] {
			if current >= 'a' && current <= 'f' && ordinal%2 == 0 {
				current -= 'a' - 'A'
			}
			mixed.WriteRune(current)
		}
		parts[index] = mixed.String()
	}
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("third[" + parts[2] + "]")}},
		{representations: [][]byte{[]byte("first[" + parts[0] + "]")}},
		{representations: [][]byte{[]byte("second[" + parts[1] + "]")}},
	}
	gotDigest, encoding, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, map[string]exactEvidenceBody{digest: {Bytes: body}})
	if err != nil {
		t.Fatal(err)
	}
	if !reconstructed || gotDigest != digest || encoding != "complete hexadecimal body" {
		t.Fatalf("mixed-case odd-nibble wrapped reconstruction = (%q, %q, %t)", gotDigest, encoding, reconstructed)
	}
}

func TestStageEvidenceWrappedSubstringEligibilityBoundary(t *testing.T) {
	t.Parallel()
	t.Run("exact one and two byte scalar fragments remain eligible", func(t *testing.T) {
		target := []byte("abcdef")
		carriers := []stageEvidenceCarrierOccurrence{
			{representations: [][]byte{[]byte("a")}},
			{representations: [][]byte{[]byte("bc")}},
			{representations: [][]byte{[]byte("def")}},
		}
		index := newStageEvidenceSegmentationIndex(carriers)
		reconstructed, err := stageEvidenceTargetHasUnorderedSegmentation(target, carriers, index)
		if err != nil {
			t.Fatal(err)
		}
		if !reconstructed {
			t.Fatal("exact one/two-byte scalar fragments fell through the all-length exact scan")
		}
	})

	t.Run("three target byte wrapped fragments are eligible", func(t *testing.T) {
		target := []byte("abcdefghi")
		carriers := []stageEvidenceCarrierOccurrence{
			{representations: [][]byte{[]byte("[ghi]")}},
			{representations: [][]byte{[]byte("[abc]")}},
			{representations: [][]byte{[]byte("[def]")}},
		}
		budget := &stageEvidenceSegmentationBudget{statesRemaining: 1024, comparisonsRemaining: 1 << 20}
		reconstructed, err := stageEvidenceTargetHasWrappedSegmentationWithBudget(target, carriers, budget)
		if err != nil {
			t.Fatal(err)
		}
		if !reconstructed {
			t.Fatal("wrapped fragments at the receipt-bound three-target-byte boundary were not detected")
		}
	})

	for name, target := range map[string][]byte{
		"padded base64":  []byte(base64.StdEncoding.EncodeToString([]byte{0xfb, 0xff, 0xef, 0x01, 0x25, 0x77, 0x9a})),
		"odd-nibble hex": []byte(hex.EncodeToString([]byte{0xab, 0xcd, 0xef, 0x01, 0x23})),
	} {
		t.Run(name+" detects three-target-byte boundary", func(t *testing.T) {
			carriers := []stageEvidenceCarrierOccurrence{
				{representations: [][]byte{append(append([]byte{'['}, target[6:]...), ']')}},
				{representations: [][]byte{append(append([]byte{'['}, target[:3]...), ']')}},
				{representations: [][]byte{append(append([]byte{'['}, target[3:6]...), ']')}},
			}
			budget := &stageEvidenceSegmentationBudget{statesRemaining: 1024, comparisonsRemaining: 1 << 20}
			reconstructed, err := stageEvidenceTargetHasWrappedSegmentationWithBudget(target, carriers, budget)
			if err != nil {
				t.Fatal(err)
			}
			if !reconstructed {
				t.Fatalf("%s fragments at the three-target-byte boundary were not detected", name)
			}
		})
	}

	for name, target := range map[string][]byte{
		"base64 safe alphabet": []byte(base64.StdEncoding.EncodeToString([]byte("rich safe alphabet corpus"))),
		"hex safe alphabet":    []byte(hex.EncodeToString([]byte("rich safe alphabet corpus"))),
	} {
		t.Run(name+" two byte incidental substrings stay outside wrapped rule", func(t *testing.T) {
			carriers := make([]stageEvidenceCarrierOccurrence, 0, (len(target)+1)/2)
			for offset := 0; offset < len(target); offset += 2 {
				end := offset + 2
				if end > len(target) {
					end = len(target)
				}
				wrapped := append([]byte{'['}, target[offset:end]...)
				wrapped = append(wrapped, ']')
				carriers = append(carriers, stageEvidenceCarrierOccurrence{representations: [][]byte{wrapped}})
			}
			budget := &stageEvidenceSegmentationBudget{statesRemaining: 4096, comparisonsRemaining: 1 << 20}
			reconstructed, err := stageEvidenceTargetHasWrappedSegmentationWithBudget(target, carriers, budget)
			if err != nil {
				t.Fatal(err)
			}
			if reconstructed {
				t.Fatal("rich safe-alphabet corpus reconstructed a target one/two incidental characters at a time")
			}
		})
	}
}

func TestStageValidationScopeBindsWrappedSubstringEligibility(t *testing.T) {
	t.Parallel()
	if !strings.Contains(stageValidationScope, "full_scalar_any_length") ||
		!strings.Contains(stageValidationScope, "wrapped_substring_min_3_target_bytes") {
		t.Fatalf("stage validation identity %q does not bind the exact/all-length and wrapped/three-target-byte rules", stageValidationScope)
	}
}

func TestStageBodyFreeUnknownDigestLookingPointersRemainOpen(t *testing.T) {
	t.Parallel()
	body := []byte("unknown pointer provenance must remain open")
	target := hex.EncodeToString(body)
	first, second := len(target)/3, (2*len(target))/3
	for _, field := range []string{"sha256", "unknown_digest_sha256"} {
		t.Run(field, func(t *testing.T) {
			raw := mustStageJSON(t, []map[string]string{
				{field: "right[" + target[second:] + "]"},
				{field: "left[" + target[:first] + "]"},
				{field: "middle[" + target[first:second] + "]"},
			})
			err := validateStageBodyFreeClosure("unknown digest pointer", []stageBodyFreeItem{{label: "unknown", raw: raw, structured: true}}, map[string]exactEvidenceBody{sha256Hex(body): {Bytes: body}})
			if err == nil || !strings.Contains(err.Error(), "unordered exact scalar carriers reconstruct") {
				t.Fatalf("unknown digest-looking pointer was closed: %v", err)
			}
		})
	}
}

func TestStageBodyFreeDynamicObjectKeyFragmentsRemainOpen(t *testing.T) {
	t.Parallel()
	body := []byte("dynamic-key-fragments")
	target := hex.EncodeToString(body)
	first, second := len(target)/3, (2*len(target))/3
	raw := mustStageJSON(t, map[string]string{
		"right[" + target[second:] + "]":       "r",
		"left[" + target[:first] + "]":         "l",
		"middle[" + target[first:second] + "]": "m",
	})
	err := validateStageBodyFreeClosure("dynamic object keys", []stageBodyFreeItem{{label: "dynamic", raw: raw, structured: true}}, map[string]exactEvidenceBody{sha256Hex(body): {Bytes: body}})
	if err == nil || !strings.Contains(err.Error(), "unordered exact scalar carriers reconstruct") {
		t.Fatalf("dynamic object-key fragments were closed: %v", err)
	}
}

func TestStageBodyFreeSchemaProvenanceDoesNotTrustMimickedIdentityShapes(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	parsed, err := parseStageReceipt(fixture.evidenceReceipt)
	if err != nil {
		t.Fatal(err)
	}
	material := fixture.evidenceRequest.inputs.Materials[0]
	materialDigest := sha256Hex(material.Raw)
	commitment := parsed.Receipt.EvidenceCommitments[0]
	objects := []map[string]interface{}{
		{"role": material.Role, "id": material.ID, "version": material.Version, "raw_sha256": materialDigest},
		{"stage_kind": parsed.Summary.StageKind, "receipt_sha256": parsed.Summary.ReceiptSHA256, "output_root_sha256": parsed.Summary.OutputRootSHA256},
		{"manifest_role": commitment.ManifestRole, "manifest_id": commitment.ManifestID, "manifest_version": commitment.ManifestVersion, "component_ordinal": commitment.ComponentOrdinal, "body_sha256": commitment.BodySHA256, "byte_count": commitment.ByteCount},
	}
	artifact := mustStageJSON(t, map[string]interface{}{"payload": objects})
	schema := mustStageJSON(t, map[string]interface{}{
		"type": "object", "required": []string{"payload"}, "additionalProperties": false,
		"properties": map[string]interface{}{"payload": map[string]interface{}{
			"type": "array", "items": map[string]interface{}{"type": "object", "additionalProperties": true},
		}},
	})
	proofs := stageBodyFreeSchemaValidatedProofs(artifact, schema)
	for index, field := range []string{"raw_sha256", "receipt_sha256", "body_sha256"} {
		pointer := fmt.Sprintf("/payload/%d/%s", index, field)
		if _, proven := proofs[stageBodyFreePointerCoordinate{row: 1, pointer: pointer}]; proven {
			t.Fatalf("mimicked tuple pointer %s acquired provenance", pointer)
		}
	}
	target := []byte(materialDigest + parsed.Summary.ReceiptSHA256 + commitment.BodySHA256)
	err = validateStageBodyFreeClosure("mimicked typed tuples", []stageBodyFreeItem{{
		label: "dynamic payload", raw: artifact, structured: true, provenContentIdentities: proofs,
	}}, map[string]exactEvidenceBody{sha256Hex(target): {Bytes: target}})
	if err == nil || !strings.Contains(err.Error(), "unordered exact scalar carriers reconstruct") {
		t.Fatalf("mimicked material/receipt/commitment tuples were not kept open and rejected: %v", err)
	}
}

func TestStageBodyFreeVerifiedCommitmentProofIsValidationDerivedAndItemBound(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	parsed, err := parseStageReceipt(fixture.evidenceReceipt)
	if err != nil {
		t.Fatal(err)
	}
	commitment := parsed.Receipt.EvidenceCommitments[0]
	bodies := map[string]exactEvidenceBody{commitment.BodySHA256: {Bytes: fixture.body}}
	reference := StageReceiptReference{
		StageKind: parsed.Summary.StageKind, ReceiptSHA256: parsed.Summary.ReceiptSHA256, OutputRootSHA256: parsed.Summary.OutputRootSHA256,
	}
	proofs := stageBodyFreeReceiptPointerProofs(parsed, map[StageReceiptReference]struct{}{reference: {}}, bodies)
	pointer := "/evidence_commitments/0/body_sha256"
	item := stageBodyFreeItem{label: "validated receipt", raw: fixture.evidenceReceipt, structured: true, provenContentIdentities: proofs}
	if !item.provenance(1, pointer, []byte(commitment.BodySHA256)) {
		t.Fatal("recomputed typed receipt commitment did not emit exact pointer/value provenance")
	}
	seenProven := false
	err = scanJSONLClosureItemWithOrderBudgetAndProvenance(candidateClosureItem{label: item.label, raw: item.raw}, jsonCarrierSourceOrder, nil, item.provenance, func(carrier orderedJSONCarrier) error {
		if bytes.Equal(carrier.bytes, []byte(commitment.BodySHA256)) && carrier.provenDigestIdentity {
			seenProven = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !seenProven {
		t.Fatal("scanner lost validation-derived commitment provenance")
	}
	if err := validateStageBodyFreeClosure("validated receipt", []stageBodyFreeItem{item}, bodies); err != nil {
		t.Fatalf("verified commitment metadata synthesized a body leak: %v", err)
	}

	unknown := stageBodyFreeItem{
		label: "unknown copy", structured: true,
		raw: mustStageJSON(t, map[string]interface{}{"payload": map[string]interface{}{
			"evidence_commitments": []map[string]interface{}{{"body_sha256": commitment.BodySHA256, "byte_count": commitment.ByteCount}},
		}}),
	}
	seenOpen := false
	err = scanJSONLClosureItemWithOrderBudgetAndProvenance(candidateClosureItem{label: unknown.label, raw: unknown.raw}, jsonCarrierSourceOrder, nil, unknown.provenance, func(carrier orderedJSONCarrier) error {
		if bytes.Equal(carrier.bytes, []byte(commitment.BodySHA256)) && !carrier.provenDigestIdentity {
			seenOpen = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !seenOpen {
		t.Fatal("same commitment tuple copied under a different item acquired receipt provenance")
	}
}

func TestStageBodyFreeExternalComponentDigestProofRequiresExactSelectedBody(t *testing.T) {
	t.Parallel()
	body := []byte("exact selected component body")
	digest := sha256Hex(body)
	bodies := map[string]exactEvidenceBody{digest: {Bytes: body}}
	row := func(componentDigest string, componentBytes int) []byte {
		return mustStageJSON(t, map[string]interface{}{
			"row_kind":       "external_evidence_body",
			"content_sha256": digest, "content_bytes": len(body),
			"component_sha256": componentDigest, "component_byte_length": componentBytes,
		})
	}

	proofs := stageBodyFreeExternalBodyRowProofs(row(digest, len(body)), bodies)
	for _, pointer := range []string{"/content_sha256", "/component_sha256"} {
		if got := proofs[stageBodyFreePointerCoordinate{row: 1, pointer: pointer}]; got != digest {
			t.Fatalf("exact selected body proof %s = %q, want %q", pointer, got, digest)
		}
	}

	for _, test := range []struct {
		name           string
		componentHash  string
		componentBytes int
	}{
		{name: "wrong digest", componentHash: strings.Repeat("0", 64), componentBytes: len(body)},
		{name: "wrong length", componentHash: digest, componentBytes: len(body) + 1},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			proofs := stageBodyFreeExternalBodyRowProofs(row(test.componentHash, test.componentBytes), bodies)
			if _, proven := proofs[stageBodyFreePointerCoordinate{row: 1, pointer: "/component_sha256"}]; proven {
				t.Fatal("non-exact component digest acquired selected-body provenance")
			}
		})
	}
}

func TestStageBodyFreeProvenanceIsBoundToExactJSONLRow(t *testing.T) {
	t.Parallel()
	value := strings.Repeat("a", 64)
	raw := []byte(fmt.Sprintf("{\"value\":%q}\n{\"value\":%q}\n", value, value))
	item := stageBodyFreeItem{
		label: "row-bound", raw: raw, structured: true,
		provenContentIdentities: map[stageBodyFreePointerCoordinate]string{{row: 1, pointer: "/value"}: value},
	}
	proven := []bool{}
	err := scanJSONLClosureItemWithOrderBudgetAndProvenance(candidateClosureItem{label: item.label, raw: raw}, jsonCarrierSourceOrder, nil, item.provenance, func(carrier orderedJSONCarrier) error {
		if bytes.Equal(carrier.bytes, []byte(value)) {
			proven = append(proven, carrier.provenDigestIdentity)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(proven, []bool{true, false}) {
		t.Fatalf("row-bound provenance = %v, want [true false]", proven)
	}
}

func TestStageEvidenceEncodedFragmentsExcludeOnlyProvenDigestIdentities(t *testing.T) {
	t.Parallel()
	body := []byte("0123456789abcdef0123456789abcdef")
	digest := sha256Hex(body)
	target := hex.EncodeToString(body)
	first := len(target) / 3
	second := (2 * len(target)) / 3
	representations := [][]byte{
		[]byte(target[:first] + strings.Repeat("a", 64-first)),
		[]byte(strings.Repeat("b", 8) + target[first:second] + strings.Repeat("b", 64-8-(second-first))),
		[]byte(strings.Repeat("c", 64-(len(target)-second)) + target[second:]),
	}
	proven := make([]stageEvidenceCarrierOccurrence, len(representations))
	ordinary := make([]stageEvidenceCarrierOccurrence, len(representations))
	for index, representation := range representations {
		proven[index] = stageEvidenceCarrierOccurrence{representations: [][]byte{representation}, provenDigestIdentity: true}
		ordinary[index] = stageEvidenceCarrierOccurrence{representations: [][]byte{representation}}
	}
	if _, _, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(proven, map[string]exactEvidenceBody{digest: {Bytes: body}}); err != nil || reconstructed {
		t.Fatalf("proven digest metadata reconstructed=%v error=%v, want excluded from arbitrary encoded-fragment search", reconstructed, err)
	}
	if _, encoding, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(ordinary, map[string]exactEvidenceBody{digest: {Bytes: body}}); err != nil || !reconstructed || encoding != "complete hexadecimal body" {
		t.Fatalf("ordinary digest-looking scalars reconstructed=%v encoding=%q error=%v, want included", reconstructed, encoding, err)
	}
}

func TestStageEvidenceProvenDigestIdentitiesRemainInWholeAndExactScans(t *testing.T) {
	t.Parallel()
	body := []byte("abcdef")
	digest := sha256Hex(body)
	raw := mustStageJSON(t, map[string]string{"value": string(body)})
	item := stageBodyFreeItem{
		label: "proven whole scalar", raw: raw, structured: true,
		provenContentIdentities: map[stageBodyFreePointerCoordinate]string{{row: 1, pointer: "/value"}: string(body)},
	}
	if err := validateStageBodyFreeClosure("proven whole scalar", []stageBodyFreeItem{item}, map[string]exactEvidenceBody{digest: {Bytes: body}}); err == nil || !strings.Contains(err.Error(), "complete decoded body") {
		t.Fatalf("proven identity escaped the whole-scalar scan: %v", err)
	}

	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("ab")}, provenDigestIdentity: true},
		{representations: [][]byte{[]byte("cdef")}, provenDigestIdentity: true},
	}
	_, encoding, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, map[string]exactEvidenceBody{digest: {Bytes: body}})
	if err != nil {
		t.Fatal(err)
	}
	if !reconstructed || encoding != "complete decoded body" {
		t.Fatalf("proven exact fragments reconstructed=%v encoding=%q, want exact scan rejection", reconstructed, encoding)
	}
}

func TestStageEvidenceUnorderedReconstructionUsesFiveThreeByteOccurrences(t *testing.T) {
	t.Parallel()
	target := []byte("A!B?C#D$E%F^G&H")
	digest := sha256Hex(target)
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("G&H")}},
		{representations: [][]byte{[]byte("%F^")}},
		{representations: [][]byte{[]byte("D$E")}},
		{representations: [][]byte{[]byte("?C#")}},
		{representations: [][]byte{[]byte("A!B")}},
	}
	_, _, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, map[string]exactEvidenceBody{digest: {Bytes: target}})
	if err != nil {
		t.Fatal(err)
	}
	if !reconstructed {
		t.Fatal("five distinct reversed three-byte occurrences did not reconstruct the exact body")
	}
}

func TestStageEvidenceReuseRelaxedReachabilityPrunesRepeatedDeadPrefix(t *testing.T) {
	t.Parallel()
	target := []byte("abc")
	carriers := make([]stageEvidenceCarrierOccurrence, 0, 77+231+1)
	for range 77 {
		carriers = append(carriers, stageEvidenceCarrierOccurrence{representations: [][]byte{[]byte("a")}})
	}
	for range 231 {
		carriers = append(carriers, stageEvidenceCarrierOccurrence{representations: [][]byte{[]byte("b")}})
	}
	// This occurrence keeps the exact capacity/frequency impossibility gate
	// feasible while remaining unreachable at the final target offset.
	carriers = append(carriers, stageEvidenceCarrierOccurrence{representations: [][]byte{[]byte("xc")}})

	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      10,
		comparisonsRemaining: 1 << 20,
	}
	index, err := newStageEvidenceSegmentationIndexBounded(carriers, budget)
	if err != nil {
		t.Fatal(err)
	}
	statesBefore := budget.statesRemaining
	reconstructed, err := stageEvidenceTargetHasUnorderedSegmentationWithBudget(target, carriers, index, budget)
	if err != nil {
		t.Fatalf("dead-prefix proof exhausted the witness-search state budget: %v", err)
	}
	if reconstructed {
		t.Fatal("unreachable dead-prefix carrier set reconstructed the target")
	}
	if budget.statesRemaining != statesBefore {
		t.Fatalf("dead-prefix impossibility proof consumed %d witness-search states, want zero", statesBefore-budget.statesRemaining)
	}
}

func TestStageEvidenceReuseRelaxedReachabilityNeverAuthorizesOccurrenceReuse(t *testing.T) {
	t.Parallel()
	target := []byte("abcabc")
	run := func(carriers []stageEvidenceCarrierOccurrence) (bool, error) {
		budget := &stageEvidenceSegmentationBudget{
			statesRemaining:      stageEvidenceSegmentationMaxStates,
			comparisonsRemaining: 1 << 20,
		}
		index, err := newStageEvidenceSegmentationIndexBounded(carriers, budget)
		if err != nil {
			return false, err
		}
		return stageEvidenceTargetHasUnorderedSegmentationWithBudget(target, carriers, index, budget)
	}

	oneOccurrence := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("abc")}}}
	if reconstructed, err := run(oneOccurrence); err != nil || reconstructed {
		t.Fatalf("one occurrence reused across two segments: reconstructed=%v error=%v", reconstructed, err)
	}
	twoOccurrences := append(oneOccurrence, stageEvidenceCarrierOccurrence{representations: [][]byte{[]byte("abc")}})
	if reconstructed, err := run(twoOccurrences); err != nil || !reconstructed {
		t.Fatalf("two distinct identical occurrences did not reconstruct: reconstructed=%v error=%v", reconstructed, err)
	}
}

func TestStageEvidenceMultiplicityGroupsPreserveDistinctOccurrenceSemantics(t *testing.T) {
	target := []byte("abcabc")
	runExact := func(multiplicity int) (bool, error) {
		carriers := []stageEvidenceCarrierOccurrence{{
			representations: [][]byte{[]byte("abc")},
			multiplicity:    multiplicity,
		}}
		return stageEvidenceTargetHasUnorderedSegmentation(target, carriers, newStageEvidenceSegmentationIndex(carriers))
	}
	if reconstructed, err := runExact(1); err != nil || reconstructed {
		t.Fatalf("one grouped exact occurrence reconstructed=%v error=%v", reconstructed, err)
	}
	if reconstructed, err := runExact(2); err != nil || !reconstructed {
		t.Fatalf("two grouped exact occurrences reconstructed=%v error=%v", reconstructed, err)
	}

	runWrapped := func(multiplicity int) (bool, error) {
		carriers := []stageEvidenceCarrierOccurrence{{
			representations: [][]byte{[]byte("wrapper[abc]tail")},
			multiplicity:    multiplicity,
		}}
		return stageEvidenceTargetHasWrappedTwoOccurrenceSegmentation(target, carriers)
	}
	if reconstructed, err := runWrapped(1); err != nil || reconstructed {
		t.Fatalf("one grouped wrapped occurrence reconstructed=%v error=%v", reconstructed, err)
	}
	if reconstructed, err := runWrapped(2); err != nil || !reconstructed {
		t.Fatalf("two grouped wrapped occurrences reconstructed=%v error=%v", reconstructed, err)
	}
}

func TestStageEvidenceOrdinaryShortBodyReconstructionIsRejected(t *testing.T) {
	t.Parallel()
	target := []byte("exact protocol evidence")
	digest := sha256Hex(target)
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("exact ")}},
		{representations: [][]byte{[]byte("protocol ")}},
		{representations: [][]byte{[]byte("evidence")}},
	}
	_, _, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, map[string]exactEvidenceBody{digest: {Bytes: target}})
	if err != nil {
		t.Fatal(err)
	}
	if !reconstructed {
		t.Fatal("ordinary short body reconstructed from three exact scalar occurrences was accepted")
	}
}

func TestStageEvidenceAnalyzerSharesCarrierIndexAcrossBodiesAndTargets(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{bytes.Repeat([]byte{'z'}, 512*1024)}},
		{representations: [][]byte{bytes.Repeat([]byte{'q'}, 512*1024)}},
	}
	bodies := make(map[string]exactEvidenceBody, 87)
	for index := 0; index < 87; index++ {
		body := []byte(fmt.Sprintf("body-%04d", index))
		bodies[sha256Hex(body)] = exactEvidenceBody{Bytes: body}
	}
	_, _, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers, bodies)
	if reconstructed {
		t.Fatal("adversarial no-match corpus reconstructed evidence")
	}
	if err != nil {
		t.Fatalf("shared scalar index rejected bounded adversarial no-match corpus: %v", err)
	}
}

func TestStageEvidenceAnalyzerPeakAuxiliaryStorageIsBoundedAtAdmissionCeiling(t *testing.T) {
	peak, ok := stageEvidenceAnalyzerPeakAuxiliaryBytes(maxEvidenceBodyBytesPerFile)
	if !ok {
		t.Fatal("maximum admitted evidence body has no finite stage-analyzer auxiliary bound")
	}
	want := stageEvidenceMaxRetainedCarrierBytes + stageEvidenceMaxSegmentationIndexBytes +
		stageEvidenceMaxWrappedCandidateCacheBytes + stageEvidenceMaxOccurrenceAuxiliaryBytes +
		(12 * maxEvidenceBodyBytesPerFile)
	if peak != want {
		t.Fatalf("stage analyzer peak auxiliary bytes = %d, want structural bound %d", peak, want)
	}
	if peak > stageEvidenceMaxAnalyzerAuxiliaryBytes {
		t.Fatalf("stage analyzer peak auxiliary bytes %d exceed fixed limit %d", peak, stageEvidenceMaxAnalyzerAuxiliaryBytes)
	}
	if stageEvidenceMaxAnalyzerAuxiliaryBytes != 1280<<20 {
		t.Fatalf("stage analyzer fixed auxiliary limit = %d, want frozen 1280 MiB contract", stageEvidenceMaxAnalyzerAuxiliaryBytes)
	}
}

func TestStageEvidenceSegmentationImpossibilityGates(t *testing.T) {
	t.Parallel()
	t.Run("capacity short is a clean no-match", func(t *testing.T) {
		carriers := []stageEvidenceCarrierOccurrence{
			{representations: [][]byte{[]byte("abcd")}},
			{representations: [][]byte{[]byte("efghijk")}},
		}
		budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 1 << 20}
		_, capacity, feasible, err := stageEvidenceSegmentationFeasible([]byte("abcdefghijkl"), carriers, false, budget)
		if err != nil {
			t.Fatal(err)
		}
		if feasible || capacity != 11 {
			t.Fatalf("capacity-short gate = feasible %v capacity %d, want false/11", feasible, capacity)
		}
	})

	for name, target := range map[string][]byte{
		"base64": []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 9))),
		"hex":    []byte(hex.EncodeToString(bytes.Repeat([]byte{0xff}, 9))),
	} {
		t.Run(name+" frequency short is a clean no-match", func(t *testing.T) {
			carriers := []stageEvidenceCarrierOccurrence{
				{representations: [][]byte{bytes.Repeat([]byte{'A'}, len(target))}},
				{representations: [][]byte{bytes.Repeat([]byte{'0'}, len(target))}},
			}
			budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 1 << 20}
			_, capacity, feasible, err := stageEvidenceSegmentationFeasible(target, carriers, false, budget)
			if err != nil {
				t.Fatal(err)
			}
			if feasible || capacity < int64(len(target)) {
				t.Fatalf("frequency-short gate = feasible %v capacity %d for target length %d", feasible, capacity, len(target))
			}
		})
	}
}

func TestStageEvidenceFrequencyBookkeepingUsesScalarIndexWorkBudget(t *testing.T) {
	target := []byte("abc")
	profile := stageEvidenceSegmentationProfile{totalCapacity: int64(len(target)), hasFrequency: true}
	for _, current := range target {
		profile.available[current]++
	}
	budget := &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: int64(len(target))}
	capacity, feasible, err := stageEvidenceProfileFeasible(target, profile, budget)
	if err != nil || !feasible || capacity != int64(len(target)) {
		t.Fatalf("profile frequency bookkeeping result = capacity %d feasible %v error %v", capacity, feasible, err)
	}
	if budget.comparisonsRemaining != 0 || budget.scalarIndexWorkUsed != int64(len(target)) {
		t.Fatalf("profile frequency bookkeeping used comparisons/work %d/%d, want 0/%d", budget.comparisonsRemaining, budget.scalarIndexWorkUsed, len(target))
	}
	budget = &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: int64(len(target)) - 1}
	if _, _, err := stageEvidenceProfileFeasible(target, profile, budget); err == nil || !strings.Contains(err.Error(), "linear-work") {
		t.Fatalf("profile frequency bookkeeping accepted linear-work bound minus one: %v", err)
	}

	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{target}},
		{representations: [][]byte{target}},
	}
	const fallbackWork = int64(2*3 + 3)
	budget = &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: fallbackWork}
	_, _, feasible, err = stageEvidenceSegmentationFeasible(target, carriers, false, budget)
	if err != nil || !feasible || budget.comparisonsRemaining != 0 || budget.scalarIndexWorkUsed != fallbackWork {
		t.Fatalf("fallback frequency bookkeeping = feasible %v comparisons/work %d/%d error %v, want true 0/%d nil", feasible, budget.comparisonsRemaining, budget.scalarIndexWorkUsed, err, fallbackWork)
	}

	const indexWork = int64(3 + 4)
	budget = &stageEvidenceSegmentationBudget{comparisonsRemaining: 0, scalarIndexWorkLimit: indexWork}
	if _, err := newStageEvidenceSegmentationIndexBounded(carriers[:1], budget); err != nil {
		t.Fatalf("segmentation index at exact scalar-work bound: %v", err)
	}
	if budget.comparisonsRemaining != 0 || budget.scalarIndexWorkUsed != indexWork {
		t.Fatalf("segmentation index used comparisons/work %d/%d, want 0/%d", budget.comparisonsRemaining, budget.scalarIndexWorkUsed, indexWork)
	}
	budget = &stageEvidenceSegmentationBudget{comparisonsRemaining: 0, scalarIndexWorkLimit: indexWork - 1}
	if _, err := newStageEvidenceSegmentationIndexBounded(carriers[:1], budget); err == nil || !strings.Contains(err.Error(), "linear-work") {
		t.Fatalf("segmentation index accepted scalar-work bound minus one: %v", err)
	}
}

func TestStageEvidenceOccurrenceGroupBoundAtLimitAndLimitPlusOne(t *testing.T) {
	carriers := make([]stageEvidenceCarrierOccurrence, stageEvidenceMaxCarrierOccurrences)
	shared := [][]byte{[]byte("x")}
	for index := range carriers {
		carriers[index].representations = shared
	}
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 1 << 20}
	if _, _, feasible, err := stageEvidenceSegmentationFeasible([]byte("xx"), carriers, false, budget); err != nil || !feasible {
		t.Fatalf("duplicate occurrence bound value rejected or declared impossible: feasible=%v error=%v", feasible, err)
	}
	carriers = append(carriers, stageEvidenceCarrierOccurrence{})
	if _, _, _, err := stageEvidenceSegmentationFeasible([]byte("xx"), carriers, false, budget); err == nil || !strings.Contains(err.Error(), "occurrence-group limit") {
		t.Fatalf("occurrence-group bound+1 error = %v", err)
	}
}

func TestStageEvidenceCandidateCacheByteBoundAtLimitAndLimitPlusOne(t *testing.T) {
	budget := &stageEvidenceSegmentationBudget{candidateBytesLimit: 256}
	cache := map[int][]stageEvidenceWrappedCandidate{}
	if err := stageEvidenceCacheWrappedCandidates(cache, 0, nil, budget); err != nil {
		t.Fatalf("first exact cache allocation: %v", err)
	}
	if err := stageEvidenceCacheWrappedCandidates(cache, 1, nil, budget); err != nil {
		t.Fatalf("candidate cache exact bound: %v", err)
	}
	if budget.candidateBytesUsed != 256 {
		t.Fatalf("candidate cache used %d bytes, want exact 256-byte bound", budget.candidateBytesUsed)
	}
	if err := stageEvidenceCacheWrappedCandidates(cache, 2, nil, budget); err == nil || !strings.Contains(err.Error(), "candidate cache") {
		t.Fatalf("candidate cache bound+1 allocation error = %v", err)
	}
}

func TestStageEvidenceSegmentationIndexByteBoundAtLimitAndLimitPlusOne(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("a")}}}
	const exactEntryBytes = int64(8 + 48 + 2 + 128)
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 1024, indexBytesLimit: exactEntryBytes}
	if _, err := newStageEvidenceSegmentationIndexBounded(carriers, budget); err != nil {
		t.Fatalf("segmentation index exact bound: %v", err)
	}
	if budget.indexBytesUsed != exactEntryBytes {
		t.Fatalf("segmentation index charged %d bytes, want %d", budget.indexBytesUsed, exactEntryBytes)
	}
	budget = &stageEvidenceSegmentationBudget{comparisonsRemaining: 1024, indexBytesLimit: exactEntryBytes - 1}
	if _, err := newStageEvidenceSegmentationIndexBounded(carriers, budget); err == nil || !strings.Contains(err.Error(), "segmentation index") {
		t.Fatalf("segmentation index bound+1 error = %v", err)
	}
	budget = &stageEvidenceSegmentationBudget{comparisonsRemaining: 1024, indexBytesLimit: 7}
	index, err := newStageEvidenceSegmentationIndexBounded(carriers, budget)
	if err == nil || index.byPrefix != nil || index.profile.maxLengths != nil {
		t.Fatalf("segmentation profile allocated before debit: index=%+v error=%v", index, err)
	}
}

func TestStageEvidenceCarrierDecodePeakCoversUnpaddedLengths(t *testing.T) {
	for _, length := range []int{2, 3, 6, 7} {
		peak, ok := stageEvidenceCarrierDecodePeakBytes(length)
		if !ok {
			t.Fatalf("decode peak length %d overflowed", length)
		}
		want := int64(length + base64.StdEncoding.DecodedLen(length) + base64.RawStdEncoding.DecodedLen(length) + hex.DecodedLen(length))
		if peak != want {
			t.Fatalf("decode peak length %d = %d, want raw+padded+raw-base64+hex capacity %d", length, peak, want)
		}
	}
}

func TestStageEvidencePrefixTableConstructionChargesAggregateWork(t *testing.T) {
	pattern := []byte("aaaa")
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 5}
	if _, err := budget.stageEvidencePatternPrefixTable(pattern); err != nil {
		t.Fatalf("prefix table at exact comparison bound: %v", err)
	}
	if budget.comparisonsRemaining != 0 {
		t.Fatalf("prefix construction left %d comparisons, want zero after exact five-comparison charge", budget.comparisonsRemaining)
	}
	budget = &stageEvidenceSegmentationBudget{comparisonsRemaining: 4}
	if _, err := budget.stageEvidencePatternPrefixTable(pattern); err == nil || !strings.Contains(err.Error(), "aggregate budget") {
		t.Fatalf("prefix construction comparison bound+1 error = %v", err)
	}
}

func TestStageEvidenceUnorderedSegmentationCommonPrefixIndexAvoidsCorpusRetraversal(t *testing.T) {
	target := append(bytes.Repeat([]byte{'a'}, 8192), 'z')
	commonPrefixMismatch := append(bytes.Repeat([]byte{'a'}, 4096), 'x')
	carriers := make([]stageEvidenceCarrierOccurrence, 1100)
	for index := range carriers {
		carriers[index] = stageEvidenceCarrierOccurrence{representations: [][]byte{bytes.Clone(commonPrefixMismatch)}}
	}
	segmentationIndex := newStageEvidenceSegmentationIndex(carriers)
	reconstructed, err := stageEvidenceTargetHasUnorderedSegmentation(target, carriers, segmentationIndex)
	if reconstructed {
		t.Fatal("common-prefix non-matches reconstructed the target")
	}
	if err != nil {
		t.Fatalf("common-prefix indexed no-match failed: %v", err)
	}
}

func TestStageContractRejectsMismatchedGraphAndFullPredecessorEvidenceRosters(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	replacement := fixture.evidenceSummary.EvidenceCommitments[0]
	replacement.BodySHA256 = stageDigest("different exact evidence")

	t.Run("graph", func(t *testing.T) {
		altered := reissueStageReceipt(t, fixture.semanticReceipt, func(receipt *stageReceipt) {
			receipt.RequestSHA256 = stageDigest("distinct semantic request")
			receipt.EvidenceCommitments = []StageEvidenceCommitment{replacement}
		})
		alteredSummary := mustValidateStage(t, altered)
		refs := []StageReceiptReference{stageRef(fixture.semanticSummary), stageRef(alteredSummary)}
		raws := [][]byte{fixture.semanticReceipt, altered}
		if refs[1].ReceiptSHA256 < refs[0].ReceiptSHA256 {
			refs[0], refs[1] = refs[1], refs[0]
			raws[0], raws[1] = raws[1], raws[0]
		}
		request := fixture.graphRequest.request
		request.ExtractionReceipts = refs
		inputs := fixture.graphRequest.inputs
		inputs.PredecessorReceipts = raws
		if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "not set-equal") {
			t.Fatalf("mismatched graph predecessor roster error = %v", err)
		}
	})

	t.Run("full", func(t *testing.T) {
		altered := reissueStageReceipt(t, fixture.graphReceipt, func(receipt *stageReceipt) {
			receipt.EvidenceCommitments = []StageEvidenceCommitment{replacement}
		})
		alteredSummary := mustValidateStage(t, altered)
		request := fixture.fullRequest.request
		request.PriorReceipts[len(request.PriorReceipts)-1] = stageRef(alteredSummary)
		inputs := fixture.fullRequest.inputs
		inputs.PredecessorReceipts = append([][]byte(nil), inputs.PredecessorReceipts...)
		inputs.PredecessorReceipts[len(inputs.PredecessorReceipts)-1] = altered
		if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "not set-equal") {
			t.Fatalf("mismatched full predecessor roster error = %v", err)
		}
	})
}

func TestStageContractRejectsAssertionsWithoutExactMaterials(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	request := fixture.evidenceRequest.request
	request.AuthorityPins.GrandVision.RawSHA256 = stageDigest("random unverified assertion")
	_, err := CompileStageReceipt(mustStageJSON(t, request), fixture.evidenceRequest.inputs)
	if err == nil || !strings.Contains(err.Error(), "raw digest mismatch") {
		t.Fatalf("random caller digest error = %v", err)
	}

	inputs := fixture.evidenceRequest.inputs
	inputs.Materials = append([]StageMaterial(nil), inputs.Materials...)
	inputs.Materials[0].Raw = []byte("mutated exact bytes")
	if _, err := CompileStageReceipt(fixture.evidenceRequest.raw, inputs); err == nil {
		t.Fatal("mutated exact material produced a stage commitment")
	}
}

func TestStageContractSemanticRosterControlsOptionalAndInapplicableAbsence(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	if _, err := CompileStageReceipt(fixture.semanticRequest.raw, fixture.semanticRequest.inputs); err != nil {
		t.Fatalf("omitted optional/inapplicable role: %v", err)
	}

	request := fixture.semanticRequest.request
	request.ArtifactOutputs = nil
	if _, err := CompileStageReceipt(mustStageJSON(t, request), fixture.semanticRequest.inputs); err == nil || !strings.Contains(err.Error(), "required artifact role") {
		t.Fatalf("omitted required role error = %v", err)
	}

	request = fixture.semanticRequest.request
	request.ArtifactOutputs = append(request.ArtifactOutputs, semanticArtifactOutput{
		Role: "protocol_artifact", ArtifactID: "protocol_output", ArtifactVersion: "1",
		ArtifactRawSHA256: stageDigest("fabricated protocol"), DerivationBindingIDs: []string{"primary_binding"},
	})
	if _, err := CompileStageReceipt(mustStageJSON(t, request), fixture.semanticRequest.inputs); err == nil || !strings.Contains(err.Error(), "inapplicable") {
		t.Fatalf("supplied inapplicable role error = %v", err)
	}
}

func TestStageContractRejectsCredentialMaterialInIdentifierButPreservesSelectedEvidencePayload(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	request := fixture.evidenceRequest.request
	request.SelectionRoster.ID = "sk-live-1234567890abcdef1234567890"
	if _, err := CompileStageReceipt(mustStageJSON(t, request), fixture.evidenceRequest.inputs); err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("lowercase live-token identifier error = %v", err)
	}

	body := []byte("# Official authentication examples\nAuthorization: Basic UHVibGljRXhhbXBsZUNsaWVudDpQdWJsaWNFbmNvZGVkRXhhbXBsZQ==\nAuthorization: Bearer PublicDocumentationExampleToken123456\naccess_token=PublicDocumentationAccessToken123456\nrefresh_token=PublicDocumentationRefreshToken123456\nclient_secret=<CLIENT_SECRET>\n-----BEGIN PRIVATE KEY-----\nPUBLIC-DOCUMENTATION-PLACEHOLDER\n-----END PRIVATE KEY-----\n")
	credentialDocumentation := newStageContractFixtureWithBody(t, body)
	for stage, receipt := range map[string][]byte{
		"evidence_intake":     credentialDocumentation.evidenceReceipt,
		"semantic_extraction": credentialDocumentation.semanticReceipt,
		"graph_compile":       credentialDocumentation.graphReceipt,
		"full_factory":        credentialDocumentation.fullReceipt,
	} {
		if _, err := ValidateStageReceipt(receipt); err != nil {
			t.Fatalf("%s receipt failed validation: %v", stage, err)
		}
		for encoding, forbidden := range map[string][]byte{
			"decoded": body,
			"base64":  []byte(base64.StdEncoding.EncodeToString(body)),
			"hex":     []byte(hex.EncodeToString(body)),
			"token":   []byte("PublicDocumentationAccessToken123456"),
		} {
			if bytes.Contains(receipt, forbidden) {
				t.Fatalf("%s receipt leaked %s selected evidence payload", stage, encoding)
			}
		}
	}
}

func TestStageContractRejectsAlteredPredecessorAndStageSubstitution(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	alteredCommitment := mutateStageObject(t, fixture.semanticReceipt, func(object map[string]interface{}) {
		rows := object["evidence_commitments"].([]interface{})
		row := rows[0].(map[string]interface{})
		row["byte_count"] = json.Number("9999")
	})
	if _, err := ValidateStageReceipt(alteredCommitment); err == nil || !strings.Contains(err.Error(), "output_root_sha256 mismatch") {
		t.Fatalf("altered evidence commitment output-root error = %v", err)
	}

	for name, mutate := range map[string]func(*semanticExtractionStageRequest){
		"hash": func(request *semanticExtractionStageRequest) {
			request.IntakeReceipt.ReceiptSHA256 = stageDigest("altered predecessor")
		},
		"root": func(request *semanticExtractionStageRequest) {
			request.IntakeReceipt.OutputRootSHA256 = stageDigest("altered predecessor root")
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := fixture.semanticRequest.request
			mutate(&request)
			if _, err := CompileStageReceipt(mustStageJSON(t, request), fixture.semanticRequest.inputs); err == nil || !strings.Contains(err.Error(), "exact request binding") {
				t.Fatalf("altered predecessor %s error = %v", name, err)
			}
		})
	}

	mutated := mutateStageObject(t, fixture.graphReceipt, func(object map[string]interface{}) {
		object["stage_kind"] = stageEvidenceIntake
	})
	if _, err := ValidateStageReceipt(mutated); err == nil {
		t.Fatal("graph commitment substituted as evidence intake")
	}

	request := fixture.fullRequest.request
	request.PriorReceipts[0], request.PriorReceipts[1] = request.PriorReceipts[1], request.PriorReceipts[0]
	inputs := fixture.fullRequest.inputs
	inputs.PredecessorReceipts = [][]byte{fixture.semanticReceipt, fixture.evidenceReceipt, fixture.graphReceipt}
	if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "stage order") {
		t.Fatalf("wrong predecessor order error = %v", err)
	}
}

func TestStageContractRejectsDigestAliasesUnknownFieldsAndDuplicateKeys(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	request := fixture.evidenceRequest.request
	request.AuthorityPins.GrandVision.RawSHA256 = request.AuthorityPins.OODGraph.RawSHA256
	if _, err := CompileStageReceipt(mustStageJSON(t, request), fixture.evidenceRequest.inputs); err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Fatalf("aliased request digest error = %v", err)
	}

	inputs := fixture.semanticRequest.inputs
	inputs.Materials = append([]StageMaterial(nil), inputs.Materials...)
	inputs.Materials[1].Raw = append([]byte(nil), inputs.Materials[0].Raw...)
	if _, err := CompileStageReceipt(fixture.semanticRequest.raw, inputs); err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Fatalf("aliased exact material error = %v", err)
	}

	var object map[string]interface{}
	if err := json.Unmarshal(fixture.evidenceRequest.raw, &object); err != nil {
		t.Fatal(err)
	}
	object["organization_id"] = "caller-forged"
	if _, err := CompileStageReceipt(mustStageJSON(t, object), fixture.evidenceRequest.inputs); err == nil || !strings.Contains(err.Error(), "organization") {
		t.Fatalf("tenant field error = %v", err)
	}

	duplicate := bytes.Replace(fixture.evidenceRequest.raw, []byte(`"request_kind":`), []byte(`"request_kind":"provider_documentation_factory_stage_request","request_kind":`), 1)
	if _, err := CompileStageReceipt(duplicate, fixture.evidenceRequest.inputs); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate JSON key error = %v", err)
	}
}

func TestStageContractReusesValidationSchemaByExactCoordinateAndDigest(t *testing.T) {
	t.Parallel()
	t.Run("exact schema coordinate reused by two bindings", func(t *testing.T) {
		request, inputs, _, _, _ := sharedEvidenceStageValidation(t)
		receipt, err := CompileStageReceipt(mustStageJSON(t, request), inputs)
		if err != nil {
			t.Fatalf("compile stage with one exact schema reused by two profile bindings: %v", err)
		}
		if _, err := ValidateStageReceipt(receipt); err != nil {
			t.Fatalf("validate stage receipt with reused exact schema: %v", err)
		}
	})

	t.Run("same coordinate with different digest is rejected", func(t *testing.T) {
		request, inputs, profile, _, _ := sharedEvidenceStageValidation(t)
		profile.BoundArtifactSchemas[1].SchemaRawSHA256 = stageDigest("different bytes at reused schema coordinate")
		replaceEvidenceStageValidationProfile(t, &request, &inputs, profile)
		if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "aliases two raw digests") {
			t.Fatalf("schema-coordinate collision error = %v", err)
		}
	})

	t.Run("same digest under aliased coordinate is rejected", func(t *testing.T) {
		request, inputs, profile, sharedCoordinate, sharedSchemaRaw := sharedEvidenceStageValidation(t)
		profile.BoundArtifactSchemas[1].SchemaRole = "aliased_validation_schema"
		replaceEvidenceStageValidationProfile(t, &request, &inputs, profile)
		inputs.Materials = append(inputs.Materials, StageMaterial{
			Role: "aliased_validation_schema", ID: sharedCoordinate.ID, Version: sharedCoordinate.Version, Raw: sharedSchemaRaw,
		})
		if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "exact material digest") || !strings.Contains(err.Error(), "aliases") {
			t.Fatalf("schema-coordinate alias error = %v", err)
		}
	})
}

func TestStageContractRecomputesEvidenceCountsAndGraphRoots(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	evidence := fixture.evidenceRequest.request
	evidence.EvidenceManifests[0].ByteCount++
	if _, err := CompileStageReceipt(mustStageJSON(t, evidence), fixture.evidenceRequest.inputs); err == nil || !strings.Contains(err.Error(), "byte_count assertion") {
		t.Fatalf("evidence byte count error = %v", err)
	}

	graph := fixture.graphRequest.request
	graph.Subjects.RootSHA256 = stageDigest("caller invented graph root")
	if _, err := CompileStageReceipt(mustStageJSON(t, graph), fixture.graphRequest.inputs); err == nil || !strings.Contains(err.Error(), "plan-derived") {
		t.Fatalf("graph root assertion error = %v", err)
	}
}

func TestGraphCompileDependencyArtifactRosterFailsClosed(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)

	t.Run("missing", func(t *testing.T) {
		request := fixture.graphRequest.request
		request.DependencyArtifacts = nil
		if _, err := CompileStageReceipt(mustStageJSON(t, request), fixture.graphRequest.inputs); err == nil || !strings.Contains(err.Error(), "no exact dependency_artifacts roster") {
			t.Fatalf("missing dependency roster error = %v", err)
		}
	})

	t.Run("duplicate", func(t *testing.T) {
		request := fixture.graphRequest.request
		request.DependencyArtifacts = append(request.DependencyArtifacts, request.DependencyArtifacts[0])
		if _, err := CompileStageReceipt(mustStageJSON(t, request), fixture.graphRequest.inputs); err == nil || !strings.Contains(err.Error(), "aliases") {
			t.Fatalf("duplicate dependency error = %v", err)
		}
	})

	t.Run("out_of_order", func(t *testing.T) {
		request := fixture.graphRequest.request
		later := stageArtifactIdentity{Role: "zzzzzzzzzzzzzzzzzzzz_dependency", ID: "z_dependency", Version: "1", RawSHA256: stageDigest("later graph dependency")}
		request.DependencyArtifacts = append([]stageArtifactIdentity{later}, request.DependencyArtifacts...)
		if _, err := CompileStageReceipt(mustStageJSON(t, request), fixture.graphRequest.inputs); err == nil || !strings.Contains(err.Error(), "not strictly ordered") {
			t.Fatalf("out-of-order dependency error = %v", err)
		}
	})

	t.Run("profile_omission", func(t *testing.T) {
		request := fixture.graphRequest.request
		extraRaw := []byte(`{"row_kind":"dependency","value":"exact"}` + "\n")
		extra := stageArtifactIdentity{Role: "zzzzzzzzzzzzzzzzzzzz_dependency", ID: "z_dependency", Version: "1", RawSHA256: sha256Hex(extraRaw)}
		request.DependencyArtifacts = append(request.DependencyArtifacts, extra)
		inputs := fixture.graphRequest.inputs
		inputs.Materials = append(append([]StageMaterial(nil), inputs.Materials...), StageMaterial{Role: extra.Role, ID: extra.ID, Version: extra.Version, Raw: extraRaw})
		if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "omits required artifact bindings") {
			t.Fatalf("profile omission error = %v", err)
		}
	})

	t.Run("digest_alias", func(t *testing.T) {
		request := fixture.graphRequest.request
		request.DependencyArtifacts[0].RawSHA256 = request.Plan.RawSHA256
		if _, err := CompileStageReceipt(mustStageJSON(t, request), fixture.graphRequest.inputs); err == nil || !strings.Contains(err.Error(), "aliases") {
			t.Fatalf("dependency/plan digest alias error = %v", err)
		}
	})

	t.Run("extra_nested_key", func(t *testing.T) {
		var object map[string]interface{}
		decoder := json.NewDecoder(bytes.NewReader(fixture.graphRequest.raw))
		decoder.UseNumber()
		if err := decoder.Decode(&object); err != nil {
			t.Fatal(err)
		}
		dependencies := object["dependency_artifacts"].([]interface{})
		dependencies[0].(map[string]interface{})["provider_hint"] = "forbidden"
		raw := mustStageJSON(t, object)
		if _, err := CompileStageReceipt(raw, fixture.graphRequest.inputs); err == nil || !strings.Contains(err.Error(), `unknown field "provider_hint"`) {
			t.Fatalf("nested extra-key error = %v", err)
		}
	})
}

func TestGraphCompileProfileIsSoleExactTargetSchemaAuthority(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)

	t.Run("missing plan target binding", func(t *testing.T) {
		request := fixture.graphRequest.request
		inputs := fixture.graphRequest.inputs
		profile := graphStageValidationProfile(t, request, inputs)
		planCoordinate := stageCoordinateForIdentity(request.Plan)
		bindings := profile.BoundArtifactSchemas[:0]
		for _, binding := range profile.BoundArtifactSchemas {
			if (stageMaterialCoordinate{Role: binding.Role, ID: binding.ArtifactID, Version: binding.ArtifactVersion}) != planCoordinate {
				bindings = append(bindings, binding)
			}
		}
		profile.BoundArtifactSchemas = bindings
		replaceGraphStageValidationProfile(t, &request, &inputs, profile)
		if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "omits required artifact bindings") {
			t.Fatalf("missing plan target binding error = %v", err)
		}
	})

	t.Run("target schema coordinate mismatch", func(t *testing.T) {
		request := fixture.graphRequest.request
		inputs := fixture.graphRequest.inputs
		profile := graphStageValidationProfile(t, request, inputs)
		binding := graphTargetProfileBinding(t, &profile, request.Plan)
		binding.SchemaRole = "missing_graph_plan_schema"
		replaceGraphStageValidationProfile(t, &request, &inputs, profile)
		if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "has no exact bytes") {
			t.Fatalf("target schema coordinate mismatch error = %v", err)
		}
	})

	t.Run("target schema digest mismatch", func(t *testing.T) {
		request := fixture.graphRequest.request
		inputs := fixture.graphRequest.inputs
		profile := graphStageValidationProfile(t, request, inputs)
		binding := graphTargetProfileBinding(t, &profile, request.Plan)
		binding.SchemaRawSHA256 = stageDigest("wrong graph plan target schema digest")
		replaceGraphStageValidationProfile(t, &request, &inputs, profile)
		if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "does not match supplied exact artifact/schema bytes") {
			t.Fatalf("target schema digest mismatch error = %v", err)
		}
	})

	t.Run("target schema material mismatch", func(t *testing.T) {
		request := fixture.graphRequest.request
		inputs := fixture.graphRequest.inputs
		profile := graphStageValidationProfile(t, request, inputs)
		binding := graphTargetProfileBinding(t, &profile, request.Plan)
		inputs.Materials = replaceStageMaterialRaw(inputs.Materials, binding.SchemaRole, binding.SchemaID, binding.SchemaVersion,
			[]byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:mismatched:graph-plan","type":"object"}`))
		if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "does not match supplied exact artifact/schema bytes") {
			t.Fatalf("target schema material mismatch error = %v", err)
		}
	})

	t.Run("arbitrary extra unbound schema material", func(t *testing.T) {
		inputs := fixture.graphRequest.inputs
		extra, _ := standaloneStageSchema(t, "unbound_graph_schema")
		inputs.Materials = append(append([]StageMaterial(nil), inputs.Materials...), extra)
		if _, err := CompileStageReceipt(fixture.graphRequest.raw, inputs); err == nil {
			t.Fatal("arbitrary extra unbound schema material was accepted")
		}
	})

	t.Run("legacy three-slot request fields", func(t *testing.T) {
		for _, legacy := range []string{"applicability_schema", "property_schema", "derivation_schema"} {
			t.Run(legacy, func(t *testing.T) {
				var request map[string]interface{}
				if err := json.Unmarshal(fixture.graphRequest.raw, &request); err != nil {
					t.Fatal(err)
				}
				request[legacy] = map[string]interface{}{
					"role": "legacy_schema", "id": "urn:legacy:schema", "version": "1",
					"raw_sha256": stageDigest(legacy), "expected_authority_class": "canonical",
				}
				if _, err := CompileStageReceipt(mustStageJSON(t, request), fixture.graphRequest.inputs); err == nil || !strings.Contains(err.Error(), `unbound field "`+legacy+`"`) {
					t.Fatalf("legacy graph request field error = %v", err)
				}

				receipt := reissueStageReceipt(t, fixture.graphReceipt, func(receipt *stageReceipt) {
					var binding map[string]interface{}
					if err := json.Unmarshal(receipt.Binding, &binding); err != nil {
						t.Fatal(err)
					}
					binding[legacy] = request[legacy]
					receipt.Binding = mustStageJSON(t, binding)
				})
				if _, err := ValidateStageReceipt(receipt); err == nil || !strings.Contains(err.Error(), `unbound field "`+legacy+`"`) {
					t.Fatalf("legacy graph receipt-binding field error = %v", err)
				}
			})
		}
	})

	t.Run("every dependency target schema validates", func(t *testing.T) {
		request := fixture.graphRequest.request
		inputs := fixture.graphRequest.inputs
		profile := graphStageValidationProfile(t, request, inputs)
		binding := graphTargetProfileBinding(t, &profile, request.DependencyArtifacts[0])
		replacement := []byte(`{"row_kind":"not_a_schema","value":"artifact-shaped"}` + "\n")
		inputs.Materials = replaceStageMaterialRaw(inputs.Materials, binding.SchemaRole, binding.SchemaID, binding.SchemaVersion, replacement)
		for index := range profile.BoundArtifactSchemas {
			candidate := &profile.BoundArtifactSchemas[index]
			if candidate.SchemaRole == binding.SchemaRole && candidate.SchemaID == binding.SchemaID && candidate.SchemaVersion == binding.SchemaVersion {
				candidate.SchemaRawSHA256 = sha256Hex(replacement)
			}
		}
		replaceGraphStageValidationProfile(t, &request, &inputs, profile)
		if _, err := CompileStageReceipt(mustStageJSON(t, request), inputs); err == nil || !strings.Contains(err.Error(), "fail their bound validation schemas") {
			t.Fatalf("dependency non-schema target error = %v", err)
		}
	})
}

func TestDeriveStageGraphSetsSupportsDualMembershipAndUnusedOptionalDisposition(t *testing.T) {
	t.Parallel()
	raw := []byte("{\"row_kind\":\"candidate_api_relationship\",\"id\":\"relationship-1\"}\n")
	dispositions := []stageGraphRowDisposition{
		{RowKind: "candidate_api_relationship", SetKinds: []string{"fact", "subject"}},
		{RowKind: "candidate_graph_gap", SetKinds: []string{"gap"}},
	}
	sets, err := deriveStageGraphSets(raw, dispositions)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(bytes.TrimSpace(raw))
	if err != nil {
		t.Fatal(err)
	}
	wantRoot := stageCanonicalSetRoot([][]byte{canonical})
	for _, setKind := range []string{"fact", "subject"} {
		if got := sets[setKind]; got.Count != 1 || got.RootSHA256 != wantRoot {
			t.Fatalf("%s set = %+v, want count=1 root=%s", setKind, got, wantRoot)
		}
	}
	if got := sets["gap"]; got.Count != 0 || got.RootSHA256 != sha256Hex(nil) {
		t.Fatalf("unused optional gap disposition produced %+v", got)
	}
}

func newStageContractFixture(t *testing.T) stageContractFixture {
	t.Helper()
	body := []byte("# Exact selected documentation\n" + strings.Repeat("source-declared machine export evidence line with safe public fields.\n", 40))
	return newStageContractFixtureWithBody(t, body)
}

func newStageContractFixtureWithBody(t *testing.T, body []byte) stageContractFixture {
	t.Helper()
	fixture := stageContractFixture{}

	fixture.body = append([]byte(nil), body...)
	bodyDigest := sha256Hex(fixture.body)
	selectionRaw := []byte(`{"row_kind":"selection","value":"selected"}` + "\n")
	manifestRaw := mustStageJSONL(t,
		map[string]interface{}{"row_kind": "artifact_manifest", "value": "selected"},
		map[string]interface{}{"row_kind": "external_evidence_body", "component_ordinal": 0, "content_sha256": bodyDigest, "content_bytes": len(fixture.body)},
		map[string]interface{}{"row_kind": "validation_summary", "value": "complete"},
	)
	selectionTarget := newStageTarget(t, "selection_roster", "selection_roster", selectionRaw)
	manifestTarget := newStageTarget(t, "selected_evidence", "selected_evidence_manifest", manifestRaw)
	evidenceValidation, evidenceMaterials := newStageValidation(t, stageEvidenceIntake, []testStageTarget{selectionTarget, manifestTarget}, nil)
	evidenceAuthorityMaterials := []StageMaterial{
		{Role: "ood_graph", ID: "ood_graph", Version: "1", Raw: []byte("canonical OOD Graph exact bytes")},
		{Role: "grand_vision", ID: "grand_vision", Version: "1", Raw: []byte("canonical Grand Vision exact bytes")},
		{Role: "source_record", ID: "source_record", Version: "1", Raw: []byte("canonical source record exact bytes")},
		{Role: "extension_protocol", ID: "extension_protocol", Version: "1", Raw: []byte("canonical extension protocol exact bytes")},
	}
	evidenceRequest := evidenceIntakeStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageEvidenceIntake,
		StageValidation: evidenceValidation,
		AuthorityPins: stageAuthorityPins{
			OODGraph:          pinForStageMaterial(evidenceAuthorityMaterials[0], "canonical"),
			GrandVision:       pinForStageMaterial(evidenceAuthorityMaterials[1], "canonical"),
			SourceRecord:      pinForStageMaterial(evidenceAuthorityMaterials[2], "canonical"),
			ExtensionProtocol: pinForStageMaterial(evidenceAuthorityMaterials[3], "canonical"),
		},
		SelectionRoster: selectionTarget.identity,
		EvidenceManifests: []evidenceManifestStageBinding{{
			Role: manifestTarget.identity.Role, ArtifactID: manifestTarget.identity.ID, ArtifactVersion: "1",
			ArtifactRawSHA256: manifestTarget.identity.RawSHA256, BodyCount: 1, ByteCount: uint64(len(fixture.body)),
		}},
	}
	evidenceInputs := StageCompileInputs{
		Materials: append(evidenceMaterials, evidenceAuthorityMaterials...),
		EvidenceBodies: []StageEvidenceBody{{
			ManifestRole: manifestTarget.identity.Role, ManifestID: manifestTarget.identity.ID,
			ManifestVersion: "1", ComponentOrdinal: 0, Raw: fixture.body,
		}},
	}
	fixture.evidenceRequest = semanticStageRequestHolder[evidenceIntakeStageRequest]{evidenceRequest, mustStageJSON(t, evidenceRequest), evidenceInputs}
	fixture.evidenceReceipt = mustCompileStage(t, fixture.evidenceRequest.raw, evidenceInputs)
	fixture.evidenceSummary = mustValidateStage(t, fixture.evidenceReceipt)

	applicabilityRaw := []byte(`{"row_kind":"applicability_profile","value":"closed"}` + "\n")
	primaryRaw := []byte(`{"row_kind":"primary_contract","value":"compiled"}` + "\n")
	applicabilityTarget := newStageTarget(t, "applicability_profile", "applicability_profile", applicabilityRaw)
	primaryTarget := newStageTarget(t, "primary_contract", "primary_contract_artifact", primaryRaw)
	semanticValidation, semanticMaterials := newStageValidation(t, stageSemanticExtraction, []testStageTarget{applicabilityTarget, primaryTarget}, nil)
	extractorMaterial := StageMaterial{Role: "primary_extractor", ID: "primary_extractor", Version: "1", Raw: []byte(`{"row_kind":"extractor","value":"bounded"}` + "\n")}
	semanticRequest := semanticExtractionStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageSemanticExtraction,
		IntakeReceipt: stageRef(fixture.evidenceSummary), StageValidation: semanticValidation,
		ApplicabilityProfile: pinForTarget(applicabilityTarget, "canonical"),
		ArtifactRoleRoster: []semanticArtifactRole{
			{Role: "primary_contract", Disposition: "required"},
			{Role: "protocol_artifact", Disposition: "inapplicable"},
			{Role: "sample_artifact", Disposition: "optional"},
		},
		ArtifactOutputs: []semanticArtifactOutput{{
			Role: primaryTarget.identity.Role, ArtifactID: primaryTarget.identity.ID, ArtifactVersion: "1",
			ArtifactRawSHA256: primaryTarget.identity.RawSHA256, DerivationBindingIDs: []string{"primary_binding"},
		}},
		DerivationBindings: []semanticDerivationBinding{{
			BindingID: "primary_binding", Extractor: pinForStageMaterial(extractorMaterial, "admitted"),
			Schema: primaryTarget.schemaPin,
		}},
	}
	semanticInputs := StageCompileInputs{
		PredecessorReceipts: [][]byte{fixture.evidenceReceipt},
		Materials:           append(semanticMaterials, extractorMaterial),
		EvidenceBodies: []StageEvidenceBody{{
			ManifestRole: manifestTarget.identity.Role, ManifestID: manifestTarget.identity.ID,
			ManifestVersion: "1", ComponentOrdinal: 0, Raw: fixture.body,
		}},
	}
	fixture.semanticRequest = semanticStageRequestHolder[semanticExtractionStageRequest]{semanticRequest, mustStageJSON(t, semanticRequest), semanticInputs}
	fixture.semanticReceipt = mustCompileStage(t, fixture.semanticRequest.raw, semanticInputs)
	fixture.semanticSummary = mustValidateStage(t, fixture.semanticReceipt)

	planRaw := mustStageJSONL(t,
		map[string]interface{}{"row_kind": "artifact_manifest", "value": "graph"},
		map[string]interface{}{"row_kind": "fact_row", "value": "f1"},
		map[string]interface{}{"row_kind": "subject_row", "value": "s1"},
	)
	planTarget := newStageTarget(t, "graph_plan", "compiled_graph_plan", planRaw)
	dispositions := []stageGraphRowDisposition{
		{RowKind: "artifact_manifest", SetKinds: []string{"metadata"}},
		{RowKind: "fact_row", SetKinds: []string{"fact"}},
		{RowKind: "subject_row", SetKinds: []string{"subject"}},
	}
	graphValidation, graphMaterials := newStageValidation(t, stageGraphCompile, []testStageTarget{planTarget, primaryTarget}, dispositions)
	sets, err := deriveStageGraphSets(planRaw, dispositions)
	if err != nil {
		t.Fatal(err)
	}
	graphRequest := graphCompileStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageGraphCompile,
		ExtractionReceipts: []StageReceiptReference{stageRef(fixture.semanticSummary)}, StageValidation: graphValidation,
		DependencyArtifacts: []stageArtifactIdentity{primaryTarget.identity},
		Plan:                planTarget.identity, Subjects: sets["subject"], Facts: sets["fact"], Gaps: sets["gap"],
	}
	graphInputs := StageCompileInputs{
		PredecessorReceipts: [][]byte{fixture.semanticReceipt},
		Materials:           graphMaterials,
		EvidenceBodies: []StageEvidenceBody{{
			ManifestRole: manifestTarget.identity.Role, ManifestID: manifestTarget.identity.ID,
			ManifestVersion: "1", ComponentOrdinal: 0, Raw: fixture.body,
		}},
	}
	fixture.graphRequest = semanticStageRequestHolder[graphCompileStageRequest]{graphRequest, mustStageJSON(t, graphRequest), graphInputs}
	fixture.graphReceipt = mustCompileStage(t, fixture.graphRequest.raw, graphInputs)
	fixture.graphSummary = mustValidateStage(t, fixture.graphReceipt)

	fullValidation, fullMaterials := newStageValidation(t, stageFullFactory, nil, nil)
	fullRequest := fullFactoryStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageFullFactory,
		StageValidation: fullValidation,
		PriorReceipts:   []StageReceiptReference{stageRef(fixture.evidenceSummary), stageRef(fixture.semanticSummary), stageRef(fixture.graphSummary)},
	}
	fullInputs := StageCompileInputs{
		PredecessorReceipts: [][]byte{fixture.evidenceReceipt, fixture.semanticReceipt, fixture.graphReceipt},
		Materials:           fullMaterials,
		EvidenceBodies: []StageEvidenceBody{{
			ManifestRole: manifestTarget.identity.Role, ManifestID: manifestTarget.identity.ID,
			ManifestVersion: "1", ComponentOrdinal: 0, Raw: fixture.body,
		}},
	}
	fixture.fullRequest = semanticStageRequestHolder[fullFactoryStageRequest]{fullRequest, mustStageJSON(t, fullRequest), fullInputs}
	fixture.fullReceipt = mustCompileStage(t, fixture.fullRequest.raw, fullInputs)
	fixture.fullSummary = mustValidateStage(t, fixture.fullReceipt)
	return fixture
}

func sharedEvidenceStageValidation(t *testing.T) (evidenceIntakeStageRequest, StageCompileInputs, stageValidationProfileDocument, stageMaterialCoordinate, []byte) {
	t.Helper()
	fixture := newStageContractFixture(t)
	request := fixture.evidenceRequest.request
	inputs := fixture.evidenceRequest.inputs
	inputs.Materials = append([]StageMaterial(nil), inputs.Materials...)

	profileCoordinate := stageCoordinateForPin(request.StageValidation.Profile)
	var profile stageValidationProfileDocument
	foundProfile := false
	for _, material := range inputs.Materials {
		coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
		if coordinate == profileCoordinate {
			if err := json.Unmarshal(material.Raw, &profile); err != nil {
				t.Fatal(err)
			}
			foundProfile = true
			break
		}
	}
	if !foundProfile || len(profile.BoundArtifactSchemas) < 2 {
		t.Fatal("evidence stage fixture lacks its two validation-profile bindings")
	}

	var combinedArtifacts bytes.Buffer
	originalSchemaCoordinates := make(map[stageMaterialCoordinate]struct{}, len(profile.BoundArtifactSchemas))
	for _, binding := range profile.BoundArtifactSchemas {
		artifactCoordinate := stageMaterialCoordinate{Role: binding.Role, ID: binding.ArtifactID, Version: binding.ArtifactVersion}
		foundArtifact := false
		for _, material := range inputs.Materials {
			coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
			if coordinate != artifactCoordinate {
				continue
			}
			combinedArtifacts.Write(material.Raw)
			if len(material.Raw) == 0 || material.Raw[len(material.Raw)-1] != '\n' {
				combinedArtifacts.WriteByte('\n')
			}
			foundArtifact = true
			break
		}
		if !foundArtifact {
			t.Fatalf("validation target %s/%s/%s is absent", artifactCoordinate.Role, artifactCoordinate.ID, artifactCoordinate.Version)
		}
		originalSchemaCoordinates[stageMaterialCoordinate{Role: binding.SchemaRole, ID: binding.SchemaID, Version: binding.SchemaVersion}] = struct{}{}
	}

	sharedCoordinate := stageMaterialCoordinate{
		Role:    profile.BoundArtifactSchemas[0].SchemaRole,
		ID:      profile.BoundArtifactSchemas[0].SchemaID,
		Version: profile.BoundArtifactSchemas[0].SchemaVersion,
	}
	sharedSchemaRaw := exactStageArtifactSchema(t, sharedCoordinate.ID, combinedArtifacts.Bytes())
	sharedSchemaDigest := sha256Hex(sharedSchemaRaw)
	for index := range profile.BoundArtifactSchemas {
		profile.BoundArtifactSchemas[index].SchemaRole = sharedCoordinate.Role
		profile.BoundArtifactSchemas[index].SchemaID = sharedCoordinate.ID
		profile.BoundArtifactSchemas[index].SchemaVersion = sharedCoordinate.Version
		profile.BoundArtifactSchemas[index].SchemaRawSHA256 = sharedSchemaDigest
	}

	materials := make([]StageMaterial, 0, len(inputs.Materials)-len(originalSchemaCoordinates)+1)
	for _, material := range inputs.Materials {
		coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
		if _, wasTargetSchema := originalSchemaCoordinates[coordinate]; wasTargetSchema {
			if coordinate == sharedCoordinate {
				material.Raw = sharedSchemaRaw
				materials = append(materials, material)
			}
			continue
		}
		materials = append(materials, material)
	}
	inputs.Materials = materials
	replaceEvidenceStageValidationProfile(t, &request, &inputs, profile)
	return request, inputs, profile, sharedCoordinate, sharedSchemaRaw
}

func replaceEvidenceStageValidationProfile(t *testing.T, request *evidenceIntakeStageRequest, inputs *StageCompileInputs, profile stageValidationProfileDocument) {
	t.Helper()
	profileRaw := mustStageJSON(t, profile)
	profileCoordinate := stageCoordinateForPin(request.StageValidation.Profile)
	found := false
	for index := range inputs.Materials {
		material := &inputs.Materials[index]
		coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
		if coordinate == profileCoordinate {
			material.Raw = profileRaw
			found = true
			break
		}
	}
	if !found {
		t.Fatal("stage validation profile material is absent")
	}
	request.StageValidation.Profile.RawSHA256 = sha256Hex(profileRaw)
}

func graphStageValidationProfile(t *testing.T, request graphCompileStageRequest, inputs StageCompileInputs) stageValidationProfileDocument {
	t.Helper()
	profileCoordinate := stageCoordinateForPin(request.StageValidation.Profile)
	for _, material := range inputs.Materials {
		coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
		if coordinate != profileCoordinate {
			continue
		}
		var profile stageValidationProfileDocument
		if err := json.Unmarshal(material.Raw, &profile); err != nil {
			t.Fatal(err)
		}
		return profile
	}
	t.Fatal("graph stage validation profile material is absent")
	return stageValidationProfileDocument{}
}

func replaceGraphStageValidationProfile(t *testing.T, request *graphCompileStageRequest, inputs *StageCompileInputs, profile stageValidationProfileDocument) {
	t.Helper()
	profileRaw := mustStageJSON(t, profile)
	profileCoordinate := stageCoordinateForPin(request.StageValidation.Profile)
	inputs.Materials = replaceStageMaterialRaw(inputs.Materials, profileCoordinate.Role, profileCoordinate.ID, profileCoordinate.Version, profileRaw)
	request.StageValidation.Profile.RawSHA256 = sha256Hex(profileRaw)
}

func graphTargetProfileBinding(t *testing.T, profile *stageValidationProfileDocument, target stageArtifactIdentity) *stageValidationProfileArtifactBinding {
	t.Helper()
	targetCoordinate := stageCoordinateForIdentity(target)
	for index := range profile.BoundArtifactSchemas {
		binding := &profile.BoundArtifactSchemas[index]
		coordinate := stageMaterialCoordinate{Role: binding.Role, ID: binding.ArtifactID, Version: binding.ArtifactVersion}
		if coordinate == targetCoordinate {
			return binding
		}
	}
	t.Fatalf("graph validation profile has no target binding for %+v", targetCoordinate)
	return nil
}

func replaceGraphTargetSchemaWithField(t *testing.T, request *graphCompileStageRequest, inputs *StageCompileInputs, target stageArtifactIdentity, field string, value interface{}) {
	t.Helper()
	profile := graphStageValidationProfile(t, *request, *inputs)
	binding := graphTargetProfileBinding(t, &profile, target)
	pin := immutableStageArtifactPin{
		Role: binding.SchemaRole, ID: binding.SchemaID, Version: binding.SchemaVersion,
		RawSHA256: binding.SchemaRawSHA256,
	}
	replacement := stageSchemaWithField(t, inputs.Materials, pin, field, value)
	inputs.Materials = replaceStageMaterialRaw(inputs.Materials, pin.Role, pin.ID, pin.Version, replacement)
	for index := range profile.BoundArtifactSchemas {
		candidate := &profile.BoundArtifactSchemas[index]
		if candidate.SchemaRole == pin.Role && candidate.SchemaID == pin.ID && candidate.SchemaVersion == pin.Version {
			candidate.SchemaRawSHA256 = sha256Hex(replacement)
		}
	}
	replaceGraphStageValidationProfile(t, request, inputs, profile)
}

func newStageTarget(t *testing.T, role, id string, raw []byte) testStageTarget {
	t.Helper()
	schemaID := "urn:test:stage-contract:" + id + ":schema"
	schemaRaw := exactStageArtifactSchema(t, schemaID, raw)
	return testStageTarget{
		identity: stageArtifactIdentity{Role: role, ID: id, Version: "1", RawSHA256: sha256Hex(raw)}, raw: raw,
		schemaPin: immutableStageArtifactPin{Role: role + "_schema", ID: schemaID, Version: "1", RawSHA256: sha256Hex(schemaRaw), AuthorityClass: "canonical"},
		schemaRaw: schemaRaw,
	}
}

func newStageValidation(t *testing.T, stageKind string, targets []testStageTarget, dispositions []stageGraphRowDisposition) (stageValidationBinding, []StageMaterial) {
	t.Helper()
	bindings := make([]stageValidationProfileArtifactBinding, 0, len(targets))
	materials := make([]StageMaterial, 0, len(targets)*2+2)
	for _, target := range targets {
		bindings = append(bindings, stageValidationProfileArtifactBinding{
			Role: target.identity.Role, ArtifactID: target.identity.ID, ArtifactVersion: target.identity.Version,
			ArtifactRawSHA256: target.identity.RawSHA256, SchemaRole: target.schemaPin.Role,
			SchemaID: target.schemaPin.ID, SchemaVersion: target.schemaPin.Version, SchemaRawSHA256: target.schemaPin.RawSHA256,
		})
		materials = append(materials,
			StageMaterial{Role: target.identity.Role, ID: target.identity.ID, Version: target.identity.Version, Raw: target.raw},
			StageMaterial{Role: target.schemaPin.Role, ID: target.schemaPin.ID, Version: target.schemaPin.Version, Raw: target.schemaRaw},
		)
	}
	sort.Slice(bindings, func(i, j int) bool {
		left := lengthPrefixedIdentityKey(bindings[i].Role, bindings[i].ArtifactID, bindings[i].ArtifactVersion)
		right := lengthPrefixedIdentityKey(bindings[j].Role, bindings[j].ArtifactID, bindings[j].ArtifactVersion)
		return left < right
	})
	profileID := stageKind + "_validation_profile"
	profile := stageValidationProfileDocument{
		RowKind: stageValidationProfileKind, ProfileVersion: stageContractVersion, StageKind: stageKind,
		ProfileID: profileID, BoundArtifactSchemas: bindings,
		GraphRowDispositions: append([]stageGraphRowDisposition{}, dispositions...),
	}
	profileRaw := mustStageJSON(t, profile)
	profileSchemaID := "urn:test:stage-contract:" + stageKind + ":profile-schema"
	profileSchemaRaw := stageValidationProfileSchema(t, profileSchemaID)
	profileMaterial := StageMaterial{Role: stageKind + "_validation_profile", ID: profileID, Version: "1", Raw: profileRaw}
	profileSchemaMaterial := StageMaterial{Role: stageKind + "_validation_profile_schema", ID: profileSchemaID, Version: "1", Raw: profileSchemaRaw}
	materials = append(materials, profileMaterial, profileSchemaMaterial)
	return stageValidationBinding{
		Profile: pinForStageMaterial(profileMaterial, "admitted"),
		Schema:  pinForStageMaterial(profileSchemaMaterial, "canonical"),
	}, materials
}

func exactStageArtifactSchema(t *testing.T, id string, artifact []byte) []byte {
	t.Helper()
	shapes := make([]interface{}, 0)
	for _, line := range bytes.Split(artifact, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var object map[string]interface{}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&object); err != nil {
			t.Fatal(err)
		}
		keys := make([]string, 0, len(object))
		properties := map[string]interface{}{}
		for key, value := range object {
			keys = append(keys, key)
			properties[key] = exactStageValueSchema(value)
		}
		sort.Strings(keys)
		shapes = append(shapes, map[string]interface{}{
			"type": "object", "required": keys, "additionalProperties": false, "properties": properties,
		})
	}
	return mustStageJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012, "$id": id, "oneOf": shapes,
	})
}

func exactStageValueSchema(value interface{}) map[string]interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(typed))
		properties := make(map[string]interface{}, len(typed))
		for key, child := range typed {
			keys = append(keys, key)
			properties[key] = exactStageValueSchema(child)
		}
		sort.Strings(keys)
		return map[string]interface{}{"type": "object", "required": keys, "additionalProperties": false, "properties": properties}
	case []interface{}:
		if len(typed) == 0 {
			return map[string]interface{}{"type": "array", "maxItems": 0}
		}
		itemSchemas := make([]interface{}, 0, len(typed))
		seen := map[string]struct{}{}
		for _, child := range typed {
			schema := exactStageValueSchema(child)
			canonical, _ := canonicalizeCandidateJSON(mustJSON(schema))
			if _, duplicate := seen[string(canonical)]; duplicate {
				continue
			}
			seen[string(canonical)] = struct{}{}
			itemSchemas = append(itemSchemas, schema)
		}
		itemSchema := itemSchemas[0]
		if len(itemSchemas) > 1 {
			itemSchema = map[string]interface{}{"oneOf": itemSchemas}
		}
		return map[string]interface{}{"type": "array", "minItems": len(typed), "maxItems": len(typed), "items": itemSchema}
	case nil:
		return map[string]interface{}{"type": "null"}
	default:
		return map[string]interface{}{"const": typed}
	}
}

func mustJSON(value interface{}) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func stageValidationProfileSchema(t *testing.T, id string) []byte {
	t.Helper()
	stringProperty := func() map[string]interface{} { return map[string]interface{}{"type": "string"} }
	bindingProperties := map[string]interface{}{}
	for _, name := range []string{"role", "artifact_id", "artifact_version", "artifact_raw_sha256", "schema_role", "schema_id", "schema_version", "schema_raw_sha256"} {
		bindingProperties[name] = stringProperty()
	}
	dispositionProperties := map[string]interface{}{"row_kind": stringProperty(), "set_kinds": map[string]interface{}{"type": "array", "minItems": 1, "uniqueItems": true, "items": stringProperty()}}
	return mustStageJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012, "$id": id, "type": "object", "additionalProperties": false,
		"required": []string{"row_kind", "profile_version", "stage_kind", "profile_id", "bound_artifact_schemas", "graph_row_dispositions"},
		"properties": map[string]interface{}{
			"row_kind":        map[string]interface{}{"const": stageValidationProfileKind},
			"profile_version": stringProperty(), "stage_kind": stringProperty(), "profile_id": stringProperty(),
			"bound_artifact_schemas": map[string]interface{}{
				"type": "array", "items": map[string]interface{}{
					"type": "object", "additionalProperties": false,
					"required":   []string{"role", "artifact_id", "artifact_version", "artifact_raw_sha256", "schema_role", "schema_id", "schema_version", "schema_raw_sha256"},
					"properties": bindingProperties,
				},
			},
			"graph_row_dispositions": map[string]interface{}{
				"type": "array", "items": map[string]interface{}{
					"type": "object", "additionalProperties": false,
					"required": []string{"row_kind", "set_kinds"}, "properties": dispositionProperties,
				},
			},
		},
	})
}

func standaloneStageSchema(t *testing.T, role string) (StageMaterial, immutableStageArtifactPin) {
	t.Helper()
	id := "urn:test:stage-contract:" + role
	raw := exactStageArtifactSchema(t, id, []byte(`{"row_kind":"unused_schema_fixture","value":"closed"}`+"\n"))
	material := StageMaterial{Role: role, ID: id, Version: "1", Raw: raw}
	return material, pinForStageMaterial(material, "canonical")
}

func pinForTarget(target testStageTarget, authority string) immutableStageArtifactPin {
	return immutableStageArtifactPin{
		Role: target.identity.Role, ID: target.identity.ID, Version: target.identity.Version,
		RawSHA256: target.identity.RawSHA256, AuthorityClass: authority,
	}
}

func pinForStageMaterial(material StageMaterial, authority string) immutableStageArtifactPin {
	return immutableStageArtifactPin{
		Role: material.Role, ID: material.ID, Version: material.Version,
		RawSHA256: sha256Hex(material.Raw), AuthorityClass: authority,
	}
}

func stageRef(summary StageReceiptSummary) StageReceiptReference {
	return StageReceiptReference{StageKind: summary.StageKind, ReceiptSHA256: summary.ReceiptSHA256, OutputRootSHA256: summary.OutputRootSHA256}
}

func stageDigest(seed string) string { return sha256Hex([]byte("stage-contract-test:" + seed)) }

func mustStageJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustStageJSONL(t *testing.T, rows ...interface{}) []byte {
	t.Helper()
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	return output.Bytes()
}

func mustCompileStage(t *testing.T, request []byte, inputs StageCompileInputs) []byte {
	t.Helper()
	receipt, err := memoizedCompileStageReceipt(request, inputs)
	if err != nil {
		t.Fatalf("compile stage commitment: %v", err)
	}
	return receipt
}

func mustValidateStage(t *testing.T, raw []byte) StageReceiptSummary {
	t.Helper()
	summary, err := memoizedValidateStageReceipt(raw)
	if err != nil {
		t.Fatalf("validate stage commitment: %v", err)
	}
	return summary
}

func cloneStageEvidenceBodies(bodies []StageEvidenceBody) []StageEvidenceBody {
	cloned := make([]StageEvidenceBody, len(bodies))
	for index, body := range bodies {
		cloned[index] = body
		cloned[index].Raw = append([]byte(nil), body.Raw...)
	}
	return cloned
}

func replaceStageMaterialRaw(materials []StageMaterial, role, id, version string, replacement []byte) []StageMaterial {
	cloned := append([]StageMaterial(nil), materials...)
	found := false
	for index := range cloned {
		if cloned[index].Role == role && cloned[index].ID == id && cloned[index].Version == version {
			cloned[index].Raw = append([]byte(nil), replacement...)
			found = true
		}
	}
	if !found {
		panic("stage material coordinate to replace was not found")
	}
	return cloned
}

func stageSchemaWithField(t *testing.T, materials []StageMaterial, pin immutableStageArtifactPin, field string, value interface{}) []byte {
	t.Helper()
	for _, material := range materials {
		if material.Role != pin.Role || material.ID != pin.ID || material.Version != pin.Version {
			continue
		}
		var schema map[string]interface{}
		if err := json.Unmarshal(material.Raw, &schema); err != nil {
			t.Fatal(err)
		}
		schema[field] = value
		return mustStageJSON(t, schema)
	}
	t.Fatal("stage schema material was not found")
	return nil
}

func assertStageBodyLeakRejected(t *testing.T, request []byte, inputs StageCompileInputs) {
	t.Helper()
	_, err := CompileStageReceipt(request, inputs)
	if err == nil || !strings.Contains(err.Error(), "not body-free") || !strings.Contains(err.Error(), "evidence digest") {
		t.Fatalf("evidence body leak error = %v", err)
	}
}

func reissueStageReceipt(t *testing.T, raw []byte, mutate func(*stageReceipt)) []byte {
	t.Helper()
	var receipt stageReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	mutate(&receipt)
	outputRaw, err := canonicalStageValue(stageOutputCommitment{
		StageKind: receipt.StageKind, Predecessors: receipt.Predecessors,
		EvidenceCommitments: receipt.EvidenceCommitments, Binding: receipt.Binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt.OutputRootSHA256 = sha256Hex(outputRaw)
	identityRaw, err := canonicalStageValue(stageReceiptIdentity{
		ReceiptKind: receipt.ReceiptKind, ReceiptVersion: receipt.ReceiptVersion, StageKind: receipt.StageKind,
		RequestSHA256: receipt.RequestSHA256, Predecessors: receipt.Predecessors,
		EvidenceCommitments: receipt.EvidenceCommitments, Binding: receipt.Binding,
		OutputRootSHA256: receipt.OutputRootSHA256, ValidationScope: receipt.ValidationScope, BodyFree: receipt.BodyFree,
		DerivationExecuted: receipt.DerivationExecuted, AuthoritySelected: receipt.AuthoritySelected,
		AdmissionAuthorized: receipt.AdmissionAuthorized, FactoryComplete: receipt.FactoryComplete,
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt.ReceiptSHA256 = sha256Hex(identityRaw)
	result, err := canonicalStageValue(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mutateStageObject(t *testing.T, raw []byte, mutate func(map[string]interface{})) []byte {
	t.Helper()
	var object map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	mutate(object)
	return mustStageJSON(t, object)
}
