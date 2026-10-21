package providerplan

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// These tests exercise the scanner's private batch seams with small, exact
// fixtures.  The production entry point drives the same seams with the fixed
// ceiling; keeping the fixtures here makes precedence and fail-closed behavior
// independently observable without requiring a large evidence corpus.
func TestClosureScannerBatchModesPreservePriorityAndCarrierBoundaries(t *testing.T) {
	bodies := map[string]exactEvidenceBody{
		"a": {Bytes: []byte("first-body")},
		"b": {Bytes: []byte("second-body")},
	}
	digests := []string{"a", "b"}
	budget := &canonicalEvidenceClosureWorkBudget{limit: 100_000}

	// Raw batches consider all canonical encodings, then return the lowest
	// precedence match even when a later target is encountered first.
	items := []evidenceClosureItem{{label: "raw", raw: []byte("prefix second-body suffix"), structured: false}}
	label, digest, encoding, found, err := scanCanonicalEvidenceRawBatches(items, jsonCarrierSourceOrder, digests, bodies, 4, budget)
	if err != nil || !found || label != "raw" || digest != "b" || encoding != "complete decoded body" {
		t.Fatalf("raw batch label=%q digest=%q encoding=%q found=%v err=%v", label, digest, encoding, found, err)
	}

	base64Item := []evidenceClosureItem{{label: "base64", raw: []byte(`{"payload":"c2Vjb25kLWJvZHk="}`), structured: true}}
	label, digest, found, err = scanCanonicalEvidenceDecodedBatches(base64Item, jsonCarrierSourceOrder, digests, bodies, 4, canonicalEvidenceCarrierBase64, &canonicalEvidenceClosureWorkBudget{limit: 100_000})
	if err != nil || !found || label != "base64" || digest != "b" {
		t.Fatalf("base64 batch label=%q digest=%q found=%v err=%v", label, digest, found, err)
	}

	hexItem := []evidenceClosureItem{{label: "hex", raw: []byte(`{"payload":"7365636f6e642d626f6479"}`), structured: true}}
	label, digest, encoding, found, err = scanCanonicalEvidenceHexAndReversibleBatches(hexItem, jsonCarrierSourceOrder, digests, bodies, 4, &canonicalEvidenceClosureWorkBudget{limit: 100_000})
	if err != nil || !found || label != "hex" || digest != "b" || encoding != "decoded hexadecimal carrier body" {
		t.Fatalf("hex batch label=%q digest=%q encoding=%q found=%v err=%v", label, digest, encoding, found, err)
	}

	// A byte array is eligible only for the binary mode; a scalar must not
	// silently become a binary carrier.
	binaryItems := []evidenceClosureItem{{label: "bytes", raw: []byte(`{"payload":[102,105,114,115,116,45,98,111,100,121]}`), structured: true}}
	label, digest, found, err = scanCanonicalEvidenceDecodedBatches(binaryItems, jsonCarrierSourceOrder, digests, bodies, 4, canonicalEvidenceCarrierBinary, &canonicalEvidenceClosureWorkBudget{limit: 100_000})
	if err != nil || !found || label != "bytes" || digest != "a" {
		t.Fatalf("binary batch label=%q digest=%q found=%v err=%v", label, digest, found, err)
	}
}

func TestClosureScannerReversibleAndLargeFragmentBatchFallbacks(t *testing.T) {
	fragment := bytes.Repeat([]byte("x"), 1024)
	body := append(append([]byte("prefix-"), fragment...), []byte("-suffix")...)
	bodies := map[string]exactEvidenceBody{"body": {Bytes: body}}
	items := []evidenceClosureItem{{label: "fragment", raw: []byte(`{"fragment":"` + string(fragment) + `"}`), structured: true}}
	label, digest, found, err := scanCanonicalEvidenceSubstantialFragmentBatches(items, jsonCarrierSourceOrder, []string{"body"}, bodies, &canonicalEvidenceClosureWorkBudget{limit: 1_000_000})
	if err != nil || !found || label != "fragment" || digest != "body" {
		t.Fatalf("fragment batch label=%q digest=%q found=%v err=%v", label, digest, found, err)
	}

	// Reversible alternatives begin at the automaton root, so this is a single
	// numeric carrier match rather than cross-scalar reconstruction.
	// This is the big-endian representation of 2^128-1.
	reversible := bytes.Repeat([]byte{0xff}, 16)
	number := "340282366920938463463374607431768211455"
	reversibleBodies := map[string]exactEvidenceBody{"integer": {Bytes: reversible}}
	match, err := scanCanonicalEvidenceReversibleBatch([]evidenceClosureItem{{label: "integer", raw: []byte(`{"n":` + number + `}`), structured: true}}, jsonCarrierSourceOrder, []canonicalEvidenceBatchTarget{{digest: "integer", target: reversible, priority: 0}}, &canonicalEvidenceClosureWorkBudget{limit: 100_000})
	if err != nil || !match.found || match.itemLabel != "integer" || match.target.digest != "integer" {
		t.Fatalf("reversible match=%#v err=%v", match, err)
	}
	if len(reversibleBodies["integer"].Bytes) != len(reversible) {
		t.Fatal("fixture body unexpectedly changed")
	}
}

func TestClosureScannerPatternAndMatcherFailureBoundaries(t *testing.T) {
	target := []byte("needle")
	base64Value := make([]byte, base64.StdEncoding.EncodedLen(len(target)))
	base64.StdEncoding.Encode(base64Value, target)
	hexValue := make([]byte, hex.EncodedLen(len(target)))
	hex.Encode(hexValue, target)

	for _, candidate := range []struct {
		name  string
		mode  canonicalEvidenceCarrierMode
		value []byte
	}{
		{name: "base64", mode: canonicalEvidenceCarrierBase64, value: base64Value},
		{name: "hex", mode: canonicalEvidenceCarrierHex, value: hexValue},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			label, found, err := scanCanonicalEvidencePattern([]evidenceClosureItem{{label: candidate.name, raw: []byte(`{"v":"` + string(candidate.value) + `"}`), structured: true}}, jsonCarrierCanonicalObjectOrder, "digest", candidate.name, target, false, false, candidate.mode, &canonicalEvidenceClosureWorkBudget{limit: 100_000})
			if err != nil || !found || label != candidate.name {
				t.Fatalf("pattern label=%q found=%v err=%v", label, found, err)
			}
		})
	}

	matcher, err := newCanonicalEvidenceBatchMatcher([]canonicalEvidenceBatchTarget{{digest: "low", target: []byte("hers"), priority: 1}, {digest: "high", target: []byte("he"), priority: 0}, {digest: "other", target: []byte("his"), priority: 2}}, false, &canonicalEvidenceClosureWorkBudget{limit: 100_000})
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := matcher.advanceFrom(0, []byte("ushers"), false, &canonicalEvidenceClosureWorkBudget{limit: 100_000}); err != nil || found != 1 {
		t.Fatalf("failure transition match=%d err=%v", found, err)
	}
	if _, err := matcher.findChild(uint32(len(matcher.nodes)), 'x', &canonicalEvidenceClosureWorkBudget{limit: 100_000}); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("out-of-range transition error=%v", err)
	}
}

func TestClosureScannerFailClosedHelpersAndCredentialStateMachine(t *testing.T) {
	for _, test := range []struct {
		name string
		ok   bool
	}{
		{name: "bounded matcher", ok: func() bool { _, ok := canonicalEvidenceMatcherAuxiliaryBytes(7, true); return ok }()},
		{name: "negative matcher rejected", ok: func() bool { _, ok := canonicalEvidenceMatcherAuxiliaryBytes(-1, false); return !ok }()},
		{name: "bounded peak", ok: func() bool { _, ok := canonicalEvidenceClosurePeakAuxiliaryBytesForBodyLength(7); return ok }()},
		{name: "overflow peak rejected", ok: func() bool { _, ok := canonicalEvidenceClosurePeakAuxiliaryBytesForBodyLength(-1); return !ok }()},
		{name: "base64 strict", ok: func() bool {
			got, ok := exactBase64Carrier(base64.StdEncoding, []byte("bmVlZGxl"))
			return ok && bytes.Equal(got, []byte("needle"))
		}()},
		{name: "base64 newline rejected", ok: func() bool { _, ok := exactBase64Carrier(base64.StdEncoding, []byte("bmVl\ndGxl")); return !ok }()},
		{name: "mixed base64 alphabet rejected", ok: func() bool {
			padded, raw := canonicalEvidenceBase64Alphabet([]byte("ab-_+/"))
			return padded == nil && raw == nil
		}()},
		{name: "invalid hexadecimal rejected", ok: func() bool { _, ok := exactHexCarrier([]byte("abc")); return !ok }()},
		{name: "assignment prefix", ok: credentialClosureCarrierCanStart([]byte(" API_KEY ="))},
		{name: "token prefix", ok: credentialClosureCarrierCanStart([]byte("ghp_"))},
		{name: "header prefix", ok: credentialClosureCarrierCanStart([]byte("Bearer "))},
		{name: "cross kind open", ok: credentialClosureCrossKindJoinOpen([]byte("prefix-"))},
		{name: "cross kind start", ok: credentialClosureCrossKindJoinStarts([]byte(" \t_suffix"))},
		{name: "strict introducer", ok: credentialClosureStrictIntroducerPrefix([]byte("api"))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !test.ok {
				t.Fatal("expected accepted boundary")
			}
		})
	}
	if got := credentialClosureTrimLeftHorizontalSpace([]byte(" \tvalue")); string(got) != "value" {
		t.Fatalf("horizontal trim=%q", got)
	}
	if credentialClosureEqualFoldASCII([]byte("abc"), []byte("abd")) || credentialClosureStartsOrIsPrefix(nil, []byte("abc")) {
		t.Fatal("case folding or empty prefix accepted unexpectedly")
	}

	scanner := newCredentialClosureScanner()
	if err := scanner.scanJSON([]byte(`{"safe":"ordinary text","bytes":[65,66]}`)); err != nil {
		t.Fatalf("safe scanner input: %v", err)
	}
	if err := scanner.finish(); err != nil {
		t.Fatalf("safe scanner finish: %v", err)
	}
	if err := scanner.advance(orderedJSONCarrier{bytes: []byte("api_"), kind: orderedJSONStringValue}); err != nil {
		t.Fatalf("credential introducer: %v", err)
	}
	if err := scanner.advance(orderedJSONCarrier{bytes: []byte("key=not-a-secret"), kind: orderedJSONStringValue}); err != nil {
		t.Fatalf("non-secret continuation: %v", err)
	}
	if err := scanner.advance(orderedJSONCarrier{bytes: []byte("ghp_abcdefghijklmnopqrstuvwxyz0123456789"), kind: orderedJSONStringValue}); err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("credential-carrier error=%v", err)
	}

	values, err := orderedJSONScalarByteValues([]byte(`{"z":"last","a":[65,66]}`))
	if err != nil || len(values) == 0 {
		t.Fatalf("scalar byte values=%q err=%v", values, err)
	}
	if err := rejectReconstructedCredentialMaterial([]byte(`{"safe":"ordinary text"}`)); err != nil {
		t.Fatalf("safe reconstructed-material scan: %v", err)
	}
}

func TestClosureScannerCombinedBatchPrioritizesDirectOverReversible(t *testing.T) {
	targets := []canonicalEvidenceBatchTarget{
		{digest: "direct", target: []byte("direct"), priority: 0},
		{digest: "reversible", target: bytes.Repeat([]byte{0xff}, 16), priority: 1},
	}
	items := []evidenceClosureItem{
		{label: "integer", raw: []byte(`{"n":340282366920938463463374607431768211455}`), structured: true},
		{label: "direct", raw: []byte(`{"v":"direct"}`), structured: true},
	}
	primary, reversible, err := scanCanonicalEvidenceBatchAndReversible(items, jsonCarrierSourceOrder, targets, canonicalEvidenceCarrierRawRepresentations, false, &canonicalEvidenceClosureWorkBudget{limit: 100_000})
	if err != nil || !primary.found || primary.itemLabel != "direct" || primary.target.digest != "direct" {
		t.Fatalf("primary=%#v reversible=%#v err=%v", primary, reversible, err)
	}
	if !reversible.found || reversible.itemLabel != "integer" || reversible.target.digest != "reversible" {
		t.Fatalf("reversible=%#v", reversible)
	}
}

func TestClosureScannerBatchNoMatchAndLargeFragmentBranches(t *testing.T) {
	bodies := map[string]exactEvidenceBody{
		"large": {Bytes: []byte("prefix needle suffix")},
		"short": {Bytes: []byte("no")},
	}
	if digest, found, err := scanCanonicalEvidenceLargeSubstantialFragment([]byte("needle"), []string{"large", "short"}, bodies, &canonicalEvidenceClosureWorkBudget{limit: 100_000}); err != nil || !found || digest != "large" {
		t.Fatalf("large fragment digest=%q found=%v err=%v", digest, found, err)
	}
	items := []evidenceClosureItem{{label: "safe", raw: []byte(`{"v":"safe"}`), structured: true}}
	if label, digest, encoding, found, err := detectCanonicalEvidenceBodyClosureWithBudget(items, jsonCarrierSourceOrder, map[string]exactEvidenceBody{"short": bodies["short"]}, 3, &canonicalEvidenceClosureWorkBudget{limit: 100_000}); err != nil || found || label != "" || digest != "" || encoding != "" {
		t.Fatalf("short-only closure label=%q digest=%q encoding=%q found=%v err=%v", label, digest, encoding, found, err)
	}
	if label, digest, encoding, found, err := detectCanonicalEvidenceBodyClosureWithBudget(nil, jsonCarrierSourceOrder, bodies, 1, &canonicalEvidenceClosureWorkBudget{limit: 100_000}); err != nil || found || label != "" || digest != "" || encoding != "" {
		t.Fatalf("empty closure label=%q digest=%q encoding=%q found=%v err=%v", label, digest, encoding, found, err)
	}
	for _, scan := range []struct {
		name string
		run  func() error
	}{
		{name: "raw no match", run: func() error {
			_, _, _, _, err := scanCanonicalEvidenceRawBatches(items, jsonCarrierSourceOrder, []string{"large", "short"}, bodies, 3, &canonicalEvidenceClosureWorkBudget{limit: 100_000})
			return err
		}},
		{name: "decoded no match", run: func() error {
			_, _, _, err := scanCanonicalEvidenceDecodedBatches(items, jsonCarrierSourceOrder, []string{"large", "short"}, bodies, 3, canonicalEvidenceCarrierBinary, &canonicalEvidenceClosureWorkBudget{limit: 100_000})
			return err
		}},
		{name: "hex no match", run: func() error {
			_, _, _, _, err := scanCanonicalEvidenceHexAndReversibleBatches(items, jsonCarrierSourceOrder, []string{"large", "short"}, bodies, 3, &canonicalEvidenceClosureWorkBudget{limit: 100_000})
			return err
		}},
	} {
		t.Run(scan.name, func(t *testing.T) {
			if err := scan.run(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, _, err := scanCanonicalEvidencePattern(items, jsonCarrierSourceOrder, "digest", "binary", []byte("needle"), false, false, canonicalEvidenceCarrierMode(77), &canonicalEvidenceClosureWorkBudget{limit: 100_000}); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown pattern mode error=%v", err)
	}
}

func TestClosureScannerPlanAndDocumentationClosureFailClosedBindings(t *testing.T) {
	planRaw, plan, dependencies, semantic := scannerSemanticClosureFixture(t, []byte(`{"safe":"first"}`), []byte(`{"safe":"second"}`))
	items, err := canonicalPlanDependencyClosure("plan", planRaw, plan, dependencies, semantic)
	if err != nil || len(items) <= 1 || !bytes.Equal(items[0].raw, planRaw) {
		t.Fatalf("canonical closure items=%d err=%v", len(items), err)
	}
	targets, schemas, err := canonicalDocumentationTargetClosureBindings(semantic, dependencies)
	if err != nil || len(targets) != 1 || len(schemas) != 1 {
		t.Fatalf("documentation closure targets=%#v schemas=%#v err=%v", targets, schemas, err)
	}
	if _, err := canonicalPlanDependencyClosure("plan", planRaw, nil, dependencies, semantic); err == nil || !strings.Contains(err.Error(), "no parsed") {
		t.Fatalf("nil plan error=%v", err)
	}

	missing := make(map[string]artifactInput, len(dependencies)-1)
	for digest, input := range dependencies {
		missing[digest] = input
	}
	delete(missing, plan.Manifest.ProviderNeutralProfileSHA256)
	if _, err := canonicalPlanDependencyClosure("plan", planRaw, plan, missing, semantic); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("missing direct dependency error=%v", err)
	}

	aliased := *plan.Manifest
	aliased.SampleShapeIndexSHA256 = aliased.ProtocolContractIndexSHA256
	if _, err := canonicalPlanDependencyClosure("plan", planRaw, &parsedPlan{Manifest: &aliased}, dependencies, semantic); err == nil || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("aliased direct dependency error=%v", err)
	}

	badAuthority := semantic
	badAuthority.derivationTargets = dependencySemanticDerivationTargetSchemaAuthority{}
	if _, _, err := canonicalDocumentationTargetClosureBindings(badAuthority, dependencies); err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Fatalf("unsealed documentation authority error=%v", err)
	}
	for _, mutate := range []struct {
		name  string
		apply func(*dependencySemanticDerivationTargetSchema)
	}{
		{name: "role mismatch", apply: func(target *dependencySemanticDerivationTargetSchema) { target.artifactRole = "other" }},
		{name: "artifact digest mismatch", apply: func(target *dependencySemanticDerivationTargetSchema) {
			target.artifactSHA256 = strings.Repeat("A", 64)
		}},
		{name: "schema coordinate mismatch", apply: func(target *dependencySemanticDerivationTargetSchema) { target.schemaID = "" }},
		{name: "schema digest mismatch", apply: func(target *dependencySemanticDerivationTargetSchema) { target.schemaSHA256 = strings.Repeat("a", 64) }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			invalid := semantic
			invalid.derivationTargets.byRole = make(map[string]dependencySemanticDerivationTargetSchema, len(semantic.derivationTargets.byRole))
			for key, target := range semantic.derivationTargets.byRole {
				invalid.derivationTargets.byRole[key] = target
			}
			for key, target := range invalid.derivationTargets.byRole {
				mutate.apply(&target)
				invalid.derivationTargets.byRole[key] = target
				break
			}
			if _, _, err := canonicalDocumentationTargetClosureBindings(invalid, dependencies); err == nil {
				t.Fatal("invalid documentation target authority accepted")
			}
		})
	}

	role := dependencySemanticRequiredRoles[0]
	if err := requireClosureSchemaProofArtifact(semantic.proof, role, semantic.roleArtifacts[role]); err != nil {
		t.Fatalf("exact semantic proof: %v", err)
	}
	badProof := semantic.proof
	badProof.seal = nil
	if err := requireClosureSchemaProofArtifact(badProof, role, semantic.roleArtifacts[role]); err == nil || !strings.Contains(err.Error(), "requires") {
		t.Fatalf("unsealed proof error=%v", err)
	}
	missingProof := semantic.proof
	missingProof.byRole = map[string]dependencySemanticValidatedArtifact{}
	if err := requireClosureSchemaProofArtifact(missingProof, role, semantic.roleArtifacts[role]); err == nil || !strings.Contains(err.Error(), "missing role") {
		t.Fatalf("missing proof role error=%v", err)
	}
	wrongInput := semantic.roleArtifacts[role]
	wrongInput.Raw = []byte("not the pinned artifact")
	if err := requireClosureSchemaProofArtifact(semantic.proof, role, wrongInput); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("wrong proof artifact error=%v", err)
	}
	badCoordinateProof := semantic.proof
	badCoordinateProof.byRole = make(map[string]dependencySemanticValidatedArtifact, len(semantic.proof.byRole))
	for key, binding := range semantic.proof.byRole {
		badCoordinateProof.byRole[key] = binding
	}
	binding := badCoordinateProof.byRole[role]
	binding.schemaID = ""
	badCoordinateProof.byRole[role] = binding
	if err := requireClosureSchemaProofArtifact(badCoordinateProof, role, semantic.roleArtifacts[role]); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("bad proof coordinate error=%v", err)
	}
}

func TestClosureScannerClosureIdentityHelperRejections(t *testing.T) {
	if !canonicalUniqueOrderedOpaqueStrings([]string{"first", "second"}) {
		t.Fatal("unique opaque strings rejected")
	}
	for _, values := range [][]string{nil, {"first", "first"}, {strings.Repeat("x", 513)}} {
		if canonicalUniqueOrderedOpaqueStrings(values) {
			t.Fatalf("non-canonical opaque values accepted: %#v", values)
		}
	}
	if ordinal, ok := exactMappingPrecedenceOrdinal(json.Number("12")); !ok || ordinal != 12 {
		t.Fatalf("ordinal=%d ok=%v", ordinal, ok)
	}
	for _, value := range []interface{}{json.Number("012"), json.Number("-1"), "12"} {
		if _, ok := exactMappingPrecedenceOrdinal(value); ok {
			t.Fatalf("non-canonical ordinal accepted: %#v", value)
		}
	}
	for _, test := range []struct {
		key  string
		want int
		ok   bool
	}{
		{key: "byte_12", want: 12, ok: true},
		{key: "byte-3", want: 3, ok: true},
		{key: "byte", ok: false},
		{key: "byte_-1", ok: false},
		{key: "not-byte", ok: false},
	} {
		got, ok := byteIndexKey(test.key)
		if ok != test.ok || (ok && got != test.want) {
			t.Fatalf("byte index key %q got=%d ok=%v", test.key, got, ok)
		}
	}
	if _, err := decodeOrderedJSONObjectPairs([]byte(`[]`)); err == nil || !strings.Contains(err.Error(), "object") {
		t.Fatalf("array object decode error=%v", err)
	}
	if _, err := decodeOrderedJSONObjectPairs([]byte(`{"unterminated"`)); err == nil {
		t.Fatal("malformed object accepted")
	}
}

func TestClosureScannerCarrierModeRefusalsRemainClosed(t *testing.T) {
	var carriers []orderedJSONCarrier
	if err := scanEvidenceClosureItemWithOrder(evidenceClosureItem{label: "raw", raw: []byte("safe"), structured: false}, jsonCarrierSourceOrder, func(carrier orderedJSONCarrier) error {
		carriers = append(carriers, carrier)
		return nil
	}); err != nil || len(carriers) != 1 || string(carriers[0].bytes) != "safe" {
		t.Fatalf("wrapper carriers=%#v err=%v", carriers, err)
	}
	if _, err := newCanonicalEvidenceBatchMatcherWithAuxiliaryLimit([]canonicalEvidenceBatchTarget{{digest: "target", target: []byte("needle")}}, false, nil, canonicalEvidenceClosureMaxMatcherAuxiliaryBytes); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("nil batch budget error=%v", err)
	}
	matcher, err := newCanonicalEvidenceBatchMatcher([]canonicalEvidenceBatchTarget{{digest: "target", target: []byte("needle"), priority: 0}}, false, &canonicalEvidenceClosureWorkBudget{limit: 100_000})
	if err != nil {
		t.Fatal(err)
	}
	if found, err := matcher.advanceCarrier(orderedJSONCarrier{bytes: []byte("needle"), kind: orderedJSONStringValue}, canonicalEvidenceCarrierBinary, false, &canonicalEvidenceClosureWorkBudget{limit: 100_000}); err != nil || found >= 0 {
		t.Fatalf("non-binary carrier found=%d err=%v", found, err)
	}
	if found, err := matcher.advanceCarrier(orderedJSONCarrier{bytes: []byte("not-base64!"), kind: orderedJSONStringValue}, canonicalEvidenceCarrierBase64, false, &canonicalEvidenceClosureWorkBudget{limit: 100_000}); err != nil || found >= 0 {
		t.Fatalf("invalid base64 carrier found=%d err=%v", found, err)
	}
	stream, err := newStreamingExactMatcher([]byte("needle"), false)
	if err != nil {
		t.Fatal(err)
	}
	pattern := evidencePatternMatcher{matcher: stream}
	if found, overflow, err := pattern.advanceCarrier(orderedJSONCarrier{bytes: []byte("needle"), kind: orderedJSONStringValue}, canonicalEvidenceCarrierBinary, &canonicalEvidenceClosureWorkBudget{limit: 100_000}); err != nil || found || overflow {
		t.Fatalf("pattern non-binary found=%v overflow=%v err=%v", found, overflow, err)
	}
	if found, overflow, err := pattern.advanceCarrier(orderedJSONCarrier{bytes: []byte("zz"), kind: orderedJSONStringValue}, canonicalEvidenceCarrierHex, &canonicalEvidenceClosureWorkBudget{limit: 100_000}); err != nil || found || overflow {
		t.Fatalf("pattern invalid hex found=%v overflow=%v err=%v", found, overflow, err)
	}
}

func TestClosureScannerArithmeticAndBudgetBoundaries(t *testing.T) {
	if size, ok := canonicalEvidenceBatchMatcherAuxiliaryBytes(3, 2); !ok || size == 0 {
		t.Fatalf("batch matcher size=%d ok=%v", size, ok)
	}
	if _, ok := canonicalEvidenceBatchMatcherAuxiliaryBytes(-1, 0); ok {
		t.Fatal("negative batch matcher size accepted")
	}
	if _, ok := canonicalEvidenceBatchMatcherAuxiliaryBytes(math.MaxInt64, 0); ok {
		t.Fatal("overflowing batch matcher size accepted")
	}
	if size, ok := canonicalEvidenceBatchPeakAuxiliaryBytes(3, 2); !ok || size == 0 {
		t.Fatalf("batch peak size=%d ok=%v", size, ok)
	}
	if _, ok := canonicalEvidenceBatchPeakAuxiliaryBytes(math.MaxInt64, 0); ok {
		t.Fatal("overflowing batch peak accepted")
	}
	if got := canonicalEvidenceRawEncodedLength(3, 99); got != -1 {
		t.Fatalf("unknown raw encoding length=%d", got)
	}
	if reversedBytes(nil) != nil {
		t.Fatal("nil bytes gained a representation")
	}
	if _, ok := exactBase64Carrier(base64.StdEncoding, nil); ok {
		t.Fatal("empty base64 carrier accepted")
	}
	if credentialClosureCrossKindJoinOpen(nil) || credentialClosureCrossKindJoinStarts([]byte(" \t")) {
		t.Fatal("empty cross-kind boundary accepted")
	}
	if err := scanEvidenceClosureItemWithOrderBudget(evidenceClosureItem{label: "budget", raw: []byte("safe"), structured: false}, jsonCarrierSourceOrder, &canonicalEvidenceClosureWorkBudget{limit: 1}, func(orderedJSONCarrier) error { return nil }); err == nil || !strings.Contains(err.Error(), "work-unit") {
		t.Fatalf("unstructured budget error=%v", err)
	}
}
