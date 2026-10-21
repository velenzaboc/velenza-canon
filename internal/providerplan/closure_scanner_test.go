package providerplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEvidenceClosureScannerRejectsCanonicalBase64AndHexVariants(t *testing.T) {
	body := []byte{0xfb, 0xff, 0xef, 0x01, 0x25}
	bodies := scannerTestBodies(body)
	tests := []struct {
		name  string
		value string
		split bool
	}{
		{name: "padded standard base64 single scalar", value: base64.StdEncoding.EncodeToString(body)},
		{name: "padded standard base64 split scalar", value: base64.StdEncoding.EncodeToString(body), split: true},
		{name: "unpadded standard base64 single scalar", value: base64.RawStdEncoding.EncodeToString(body)},
		{name: "unpadded standard base64 split scalar", value: base64.RawStdEncoding.EncodeToString(body), split: true},
		{name: "padded URL-safe base64 single scalar", value: base64.URLEncoding.EncodeToString(body)},
		{name: "padded URL-safe base64 split scalar", value: base64.URLEncoding.EncodeToString(body), split: true},
		{name: "unpadded URL-safe base64 single scalar", value: base64.RawURLEncoding.EncodeToString(body)},
		{name: "unpadded URL-safe base64 split scalar", value: base64.RawURLEncoding.EncodeToString(body), split: true},
		{name: "lowercase hex single scalar", value: hex.EncodeToString(body)},
		{name: "uppercase hex split scalar", value: bytesToUpperASCII([]byte(hex.EncodeToString(body))), split: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var candidate []byte
			if test.split {
				cut := len(test.value) / 2
				candidate = []byte(fmt.Sprintf(`["%s","%s"]`, test.value[:cut], test.value[cut:]))
			} else {
				candidate = []byte(fmt.Sprintf(`{"carrier":"%s"}`, test.value))
			}
			if err := validateNoEmbeddedEvidenceBodies("candidate", candidate, bodies, 1); err == nil {
				t.Fatal("canonical encoded evidence body was accepted")
			}
		})
	}
}

func TestEvidenceClosureScannerRequiresExactBase64RoundTrip(t *testing.T) {
	body := []byte{0x00}
	// AB== decodes under permissive padding-bit rules but does not encode back
	// to itself. It must not be treated as a canonical carrier for AA==.
	if err := validateNoEmbeddedEvidenceBodies("candidate", []byte(`{"carrier":"AB=="}`), scannerTestBodies(body), 1); err != nil {
		t.Fatalf("noncanonical base64 was treated as an exact carrier: %v", err)
	}
}

func TestEvidenceClosureScannerRejectsIndividuallyEncodedFragments(t *testing.T) {
	body := []byte("evidence-body-across-carriers")
	fragments := [][]byte{body[:4], body[4:13], body[13:]}
	encodings := []struct {
		name   string
		encode func([]byte) string
	}{
		{name: "padded standard", encode: base64.StdEncoding.EncodeToString},
		{name: "unpadded standard", encode: base64.RawStdEncoding.EncodeToString},
		{name: "padded URL-safe", encode: base64.URLEncoding.EncodeToString},
		{name: "unpadded URL-safe", encode: base64.RawURLEncoding.EncodeToString},
	}
	for _, encoding := range encodings {
		t.Run(encoding.name, func(t *testing.T) {
			candidate := []byte(fmt.Sprintf(`["%s","%s","%s"]`, encoding.encode(fragments[0]), encoding.encode(fragments[1]), encoding.encode(fragments[2])))
			if err := validateNoEmbeddedEvidenceBodies("candidate", candidate, scannerTestBodies(body), 1); err == nil {
				t.Fatal("evidence body reconstructed from individually encoded fragments was accepted")
			}
		})
	}
}

func TestEvidenceClosureScannerRejectsMixedCanonicalBase64FragmentVariants(t *testing.T) {
	fragments := [][]byte{
		{0xfb, 0xff, 0xef},
		{0xfa, 0xfe, 0xfd, 0x01},
		[]byte("mixed canonical base64 tail"),
	}
	body := bytes.Join(fragments, nil)
	candidate := []byte(fmt.Sprintf(
		`["%s","%s","%s"]`,
		base64.StdEncoding.EncodeToString(fragments[0]),
		base64.RawURLEncoding.EncodeToString(fragments[1]),
		base64.URLEncoding.EncodeToString(fragments[2]),
	))
	if err := validateNoEmbeddedEvidenceBodies("candidate", candidate, scannerTestBodies(body), 1); err == nil {
		t.Fatal("evidence body reconstructed from mixed canonical base64 variants was accepted")
	}
}

func TestEvidenceClosureScannerRejectsDecodedFragments(t *testing.T) {
	body := []byte(`"12.34"`)
	candidate := []byte(`["\"","12",".34","\""]`)
	values, err := orderedJSONScalarByteValues(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if reconstructed := bytes.Join(values, nil); !bytes.Equal(reconstructed, body) {
		t.Fatalf("ordered scalar reconstruction = %q, want %q", reconstructed, body)
	}
	if err := validateNoEmbeddedEvidenceBodies("candidate", candidate, scannerTestBodies(body), 1); err == nil {
		t.Fatal("decoded evidence body reconstructed across scalar fragments was accepted")
	}
}

func TestEvidenceClosureScannerRejectsArrayAndIndexedObjectCarriers(t *testing.T) {
	body := []byte("indexed evidence")
	array := bytes.NewBufferString("[")
	indexed := bytes.NewBufferString("{")
	for index, value := range body {
		if index != 0 {
			array.WriteByte(',')
			indexed.WriteByte(',')
		}
		fmt.Fprintf(array, "%d", value)
		fmt.Fprintf(indexed, `"byte_%03d":%d`, index, value)
	}
	array.WriteByte(']')
	indexed.WriteByte('}')
	mixedArray := bytes.Replace(array.Bytes(), []byte(","), []byte(",null,"), 1)
	mixedIndexed := bytes.Replace(indexed.Bytes(), []byte("{"), []byte(`{"metadata":"safe",`), 1)
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{name: "byte array", raw: array.Bytes()},
		{name: "byte array with noncarrier member", raw: mixedArray},
		{name: "byte index object", raw: indexed.Bytes()},
		{name: "byte index object with ordinary property", raw: mixedIndexed},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateNoEmbeddedEvidenceBodies("candidate", test.raw, scannerTestBodies(body), 1); err == nil {
				t.Fatal("explicit byte carrier was accepted")
			}
		})
	}
}

func TestCandidateClosureRejectsEvidenceBodySplitAcrossTwoArtifacts(t *testing.T) {
	body := []byte("cross-artifact-evidence-body")
	for _, test := range []struct {
		name          string
		reverseDigest bool
	}{
		{name: "digest order happens to agree", reverseDigest: false},
		{name: "semantic order reverses real digest order", reverseDigest: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			first, second := scannerFragmentPairWithDigestOrder(t, body[:12], body[12:], test.reverseDigest)
			planRaw, plan, dependencies, proof := scannerSemanticClosureFixture(t, first, second)
			err := validateCandidateClosureSecurity("plan", planRaw, plan, dependencies, proof, scannerTestBodies(body), 1)
			if err == nil {
				t.Fatal("evidence body split across two semantically ordered dependency artifacts was accepted")
			}
		})
	}
}

func TestCandidateClosureAcceptsCompleteSafeSchemaBoundFixture(t *testing.T) {
	planRaw, plan, dependencies, semanticValidation := scannerSemanticClosureFixture(t, []byte(`["safe-direct-first"]`), []byte(`["safe-direct-second"]`))
	if err := validateCandidateClosureSecurity("plan", planRaw, plan, dependencies, semanticValidation, nil, 1); err != nil {
		t.Fatalf("safe complete semantic dependency closure failed: %v", err)
	}
}

func TestStructuredSecurityRejectsCredentialAcrossRows(t *testing.T) {
	raw := []byte("[\"api_\"]\n[\"key=live-\",\"A1b2C3d4E5f6G7h8I9j0\"]\n")
	err := validateStructuredDependencySecurity(artifactInput{Path: "split.jsonl", Raw: raw, Structured: true})
	if err == nil {
		t.Fatal("credential material reconstructed across JSONL rows was accepted")
	}
}

func TestStructuredSecurityPreservesJSONCarrierBoundariesForDocumentationTerms(t *testing.T) {
	raw := []byte(`{"semantic_key":"oauth2:authorization_code_refresh_token:realm_bound","display_name":"OAuth 2.0 realm-bound grant"}`)
	if err := validateStructuredDependencySecurity(artifactInput{Path: "safe-auth-semantics.jsonl", Raw: raw, Structured: true}); err != nil {
		t.Fatalf("safe documentation terms were reconstructed into a credential: %v", err)
	}
}

func TestStructuredSecurityRejectsCredentialAcrossExplicitMixedCarrierJoin(t *testing.T) {
	raw := []byte(`{"api_":"key=live-A1b2C3d4E5f6G7h8I9j0"}`)
	if err := validateStructuredDependencySecurity(artifactInput{Path: "mixed-carrier-split.jsonl", Raw: raw, Structured: true}); err == nil {
		t.Fatal("credential split across an explicit object-key/value join was accepted")
	}
}

func TestStructuredSecurityRejectsCredentialAcrossAdversarialCarrierBoundaries(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "separator starts next carrier", raw: `{"api":"_key=live-A1b2C3d4E5f6G7h8I9j0"}`},
		{name: "short known-prefix fragment", raw: `["g","hp_A1b2C3d4E5f6G7h8I9j0"]`},
		{name: "split fixed-width access-key prefix", raw: `["AK","IAIOSFODNN7EXAMPLE"]`},
		{name: "introducer is an interior suffix", raw: `["documentation note api_","key=live-A1b2C3d4E5f6G7h8I9j0"]`},
		{name: "canonical object order", raw: `{"key=live-A1b2C3d4E5f6G7h8I9j0":0,"api_":0}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStructuredDependencySecurity(artifactInput{Path: "adversarial-carrier.json", Raw: []byte(test.raw), Structured: true}); err == nil {
				t.Fatal("credential reconstructed across adversarial carrier boundaries was accepted")
			}
		})
	}
}

func TestEvidenceClosureScannerRejectsCanonicalObjectOrderReconstruction(t *testing.T) {
	body := []byte("api_key=live-A1b2C3d4E5f6G7h8I9j0")
	raw := []byte(`{"key=live-A1b2C3d4E5f6G7h8I9j0":0,"api_":0}`)
	if err := validateNoEmbeddedEvidenceBodies("canonical-object-order", raw, scannerTestBodies(body), 1); err == nil {
		t.Fatal("evidence body reconstructed in canonical object-member order was accepted")
	}
}

func TestStructuredSecurityRejectsNumericAndBooleanCredentialCarriers(t *testing.T) {
	credential := []byte("api_key=live-A1b2C3d4E5f6G7h8I9j0")
	numeric := make(map[string]uint8, len(credential))
	for index, value := range credential {
		numeric[fmt.Sprintf("n%03d", index)] = value
	}
	numericRaw, err := json.Marshal(numeric)
	if err != nil {
		t.Fatal(err)
	}

	bits := make([]bool, 0, len(credential)*8)
	for _, value := range credential {
		for shift := 7; shift >= 0; shift-- {
			bits = append(bits, value&(1<<shift) != 0)
		}
	}
	booleanRaw, err := json.Marshal(bits)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{name: "canonical numeric object value roster", raw: numericRaw},
		{name: "MSB-first boolean bit vector", raw: booleanRaw},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStructuredDependencySecurity(artifactInput{Path: "encoded-credential.json", Raw: test.raw, Structured: true}); err == nil {
				t.Fatal("credential reconstructed from a dense reversible scalar carrier was accepted")
			}
		})
	}
}

func TestStructuredSecurityRejectsLSBAndBigIntegerCredentialCarriers(t *testing.T) {
	credential := []byte("api_key=live-A1b2C3d4E5f6G7h8I9j0")
	lsbRaw := mustBooleanVectorJSON(t, credential, false)
	bigEndian := new(big.Int).SetBytes(credential).String()
	littleEndian := new(big.Int).SetBytes(reversedBytes(credential)).String()
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{name: "LSB-first boolean bit vector", raw: lsbRaw},
		{name: "big-endian integer magnitude", raw: []byte(`{"encoded":` + bigEndian + `}`)},
		{name: "little-endian integer magnitude", raw: []byte(`{"encoded":` + littleEndian + `}`)},
		{name: "negative signed integer magnitude", raw: []byte(`{"encoded":-` + bigEndian + `}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStructuredDependencySecurity(artifactInput{Path: "reversible-credential.json", Raw: test.raw, Structured: true}); err == nil {
				t.Fatal("credential reconstructed from a reversible scalar carrier was accepted")
			}
		})
	}
}

func TestStructuredSecurityRejectsCredentialSplitFromReversibleCarrier(t *testing.T) {
	credentialSuffix := "live-A1b2C3d4E5f6G7h8I9j0"
	lsbPrefix := mustBooleanVectorJSON(t, []byte("api_key="), false)
	bigIntegerPrefix := new(big.Int).SetBytes([]byte("document-note-api_")).String()
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{name: "LSB boolean prefix then string suffix", raw: []byte(fmt.Sprintf(`[%s,%q]`, lsbPrefix, credentialSuffix))},
		{name: "big integer interior prefix then string suffix", raw: []byte(fmt.Sprintf(`[%s,%q]`, bigIntegerPrefix, "key="+credentialSuffix))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStructuredDependencySecurity(artifactInput{Path: "split-reversible-credential.json", Raw: test.raw, Structured: true}); err == nil {
				t.Fatal("credential split across a decoded reversible carrier and an ordinary carrier was accepted")
			}
		})
	}
}

func TestEvidenceClosureScannerRejectsDenseNumericBooleanAndBigIntegerCarriers(t *testing.T) {
	body := []byte("dense-reversible-evidence-body")
	numeric := make(map[string]uint8, len(body))
	for index, value := range body {
		numeric[fmt.Sprintf("n%03d", index)] = value
	}
	numericRaw, err := json.Marshal(numeric)
	if err != nil {
		t.Fatal(err)
	}
	minimalNumeric := make(map[string]uint8, len(body))
	for index, value := range body {
		minimalNumeric[fmt.Sprintf("n%d", index)] = value
	}
	minimalNumericRaw, err := json.Marshal(minimalNumeric)
	if err != nil {
		t.Fatal(err)
	}
	bigEndian := new(big.Int).SetBytes(body).String()
	littleEndian := new(big.Int).SetBytes(reversedBytes(body)).String()
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{name: "canonical numeric object values", raw: numericRaw},
		{name: "minimal-index numeric object values", raw: minimalNumericRaw},
		{name: "MSB-first boolean vector", raw: mustBooleanVectorJSON(t, body, true)},
		{name: "LSB-first boolean vector", raw: mustBooleanVectorJSON(t, body, false)},
		{name: "big-endian integer magnitude", raw: []byte(`{"encoded":` + bigEndian + `}`)},
		{name: "little-endian integer magnitude", raw: []byte(`{"encoded":` + littleEndian + `}`)},
		{name: "negative signed integer magnitude", raw: []byte(`{"encoded":-` + bigEndian + `}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateNoEmbeddedEvidenceBodies(test.name, test.raw, scannerTestBodies(body), 1); err == nil {
				t.Fatal("selected evidence reconstructed from a reversible scalar carrier was accepted")
			}
		})
	}
}

func TestEvidenceClosureScannerRejectsBodySplitFromReversibleCarrier(t *testing.T) {
	body := []byte("body-split-across-reversible-carrier")
	lsbPrefix := mustBooleanVectorJSON(t, body[:8], false)
	raw := []byte(fmt.Sprintf(`[%s,%q]`, lsbPrefix, body[8:]))
	if err := validateNoEmbeddedEvidenceBodies("split-reversible-body", raw, scannerTestBodies(body), 1); err == nil {
		t.Fatal("selected evidence split across a decoded reversible carrier and an ordinary carrier was accepted")
	}
}

func mustBooleanVectorJSON(t *testing.T, value []byte, msbFirst bool) []byte {
	t.Helper()
	bits := make([]bool, 0, len(value)*8)
	for _, current := range value {
		if msbFirst {
			for shift := 7; shift >= 0; shift-- {
				bits = append(bits, current&(1<<shift) != 0)
			}
			continue
		}
		for shift := 0; shift < 8; shift++ {
			bits = append(bits, current&(1<<shift) != 0)
		}
	}
	raw, err := json.Marshal(bits)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCredentialClosureScannerDoesNotAllocatePerFragment(t *testing.T) {
	allocations := testing.AllocsPerRun(1, func() {
		scanner := newCredentialClosureScanner()
		if err := scanner.advance(orderedJSONCarrier{bytes: []byte("api_key="), kind: orderedJSONStringValue}); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < 8000; index++ {
			if err := scanner.advance(orderedJSONCarrier{bytes: []byte("A"), kind: orderedJSONStringValue}); err != nil {
				t.Fatal(err)
			}
		}
		if err := scanner.finish(); err != nil {
			t.Fatal(err)
		}
	})
	if allocations > 128 {
		t.Fatalf("fragment scan allocated %.0f times; want bounded state rather than per-fragment candidate rescans", allocations)
	}
}

func TestCandidateClosureRejectsCredentialAcrossArtifacts(t *testing.T) {
	for _, test := range []struct {
		name          string
		reverseDigest bool
	}{
		{name: "digest order happens to agree", reverseDigest: false},
		{name: "semantic order reverses real digest order", reverseDigest: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			first, second := scannerFragmentPairWithDigestOrder(t, []byte("api_key=live-"), []byte("A1b2C3d4E5f6G7h8I9j0"), test.reverseDigest)
			planRaw, plan, dependencies, proof := scannerSemanticClosureFixture(t, first, second)
			err := validateCandidateClosureSecurity("plan", planRaw, plan, dependencies, proof, nil, 1)
			if err == nil {
				t.Fatal("credential material reconstructed across semantically ordered artifacts was accepted")
			}
		})
	}
}

func TestCandidateClosureOrderIsIndependentOfManifestMemberOrder(t *testing.T) {
	body := []byte("manifest-order-cannot-reorder-the-semantic-closure")
	first, second := scannerFragmentPairWithDigestOrder(t, body[:18], body[18:], true)
	_, plan, dependencies, proof := scannerSemanticClosureFixture(t, first, second)
	manifest := plan.Manifest
	// Put the second semantic role before the first in the JSON object. Object
	// member order is not authority and must not change scanner reconstruction
	// order.
	planRaw := []byte(fmt.Sprintf(
		`{"source_contract_index_sha256":"%s","provider_neutral_compilation_profile_sha256":"%s","evidence_selection_roster_sha256":"%s","field_mapping_candidate_sha256":"%s","protocol_contract_index_sha256":"%s","sample_shape_index_sha256":"%s","row_kind":"artifact_manifest"}`,
		manifest.SourceContractIndexSHA256,
		manifest.ProviderNeutralProfileSHA256,
		manifest.EvidenceSelectionRosterSHA256,
		manifest.FieldMappingCandidateSHA256,
		manifest.ProtocolContractIndexSHA256,
		manifest.SampleShapeIndexSHA256,
	))
	if err := validateCandidateClosureSecurity("plan", planRaw, plan, dependencies, proof, scannerTestBodies(body), 1); err == nil {
		t.Fatal("manifest member order changed the semantic dependency closure and hid reconstructed evidence")
	}
}

func TestCandidateClosureUsesMappingTransitivePrecedenceNotDigestOrRowOrder(t *testing.T) {
	body := []byte("transitive-mapping-artifacts-cannot-hide-evidence")
	prior, override := scannerStructuredFragmentPairWithDigestOrder(t, body[:22], body[22:], true)
	planRaw, plan, dependencies, proof := scannerSemanticClosureFixtureWithTransitiveRows(t, []byte(`["safe-direct-first"]`), []byte(`["safe-direct-second"]`), prior, override, []int{1, 0}, []uint64{0, 1})
	if sha256Hex(prior) <= sha256Hex(override) {
		t.Fatal("fixture does not reverse the real artifact digest order")
	}
	if err := validateCandidateClosureSecurity("plan", planRaw, plan, dependencies, proof, scannerTestBodies(body), 1); err == nil {
		t.Fatal("shuffled roster rows or real digest order changed explicit mapping precedence and hid reconstructed evidence")
	}
}

func TestCandidateClosureRejectsCredentialAcrossReverseDigestTransitivePrecedence(t *testing.T) {
	prior, override := scannerStructuredFragmentPairWithDigestOrder(t, []byte("api_key=live-"), []byte("A1b2C3d4E5f6G7h8I9j0"), true)
	planRaw, plan, dependencies, semanticValidation := scannerSemanticClosureFixtureWithTransitiveRows(
		t,
		[]byte(`["safe-direct-first"]`),
		[]byte(`["safe-direct-second"]`),
		prior,
		override,
		[]int{1, 0},
		[]uint64{0, 1},
	)
	if sha256Hex(prior) <= sha256Hex(override) {
		t.Fatal("fixture does not reverse the real transitive artifact digest order")
	}
	if err := validateCandidateClosureSecurity("plan", planRaw, plan, dependencies, semanticValidation, nil, 1); err == nil {
		t.Fatal("credential split across explicit transitive precedence was accepted")
	}
}

func TestMappingTransitiveClosureRejectsDuplicateAndGapOrdinals(t *testing.T) {
	for _, test := range []struct {
		name     string
		ordinals []uint64
		want     string
	}{
		{name: "duplicate", ordinals: []uint64{0, 0}, want: "duplicates precedence_ordinal"},
		{name: "gap", ordinals: []uint64{0, 2}, want: "gap at precedence_ordinal 1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			planRaw, plan, dependencies, proof := scannerSemanticClosureFixtureWithTransitiveRows(t, []byte(`["safe-direct-first"]`), []byte(`["safe-direct-second"]`), []byte("{\"row_kind\":\"artifact_manifest\",\"artifact\":\"prior_map\",\"artifact_version\":\"1\"}\n{\"row_kind\":\"mapping_row\",\"safe-prior\":true}"), []byte("{\"safe-override\":true,\"row_kind\":\"mapping_row\"}\n{\"row_kind\":\"artifact_manifest\",\"artifact\":\"domain_override\",\"artifact_version\":\"1\"}"), []int{0, 1}, test.ordinals)
			err := validateCandidateClosureSecurity("plan", planRaw, plan, dependencies, proof, nil, 1)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ordinal error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMappingTransitiveClosureAcceptsSchemaProvenThirdOpaqueRoleAndRejectsUnrosteredRole(t *testing.T) {
	_, _, _, semanticValidation := scannerSemanticClosureFixture(t, []byte(`["safe-direct-first"]`), []byte(`["safe-direct-second"]`))
	base := semanticValidation.roleArtifacts[dependencySemanticRoleMappingTransitiveRoster]
	baseRows := base.RowsByKind["mapping_transitive_dependency"]
	thirdRole := "schema_proven_third_opaque_role"
	third := map[string]interface{}{
		"row_kind": "mapping_transitive_dependency", "dependency_binding_id": "third_binding", "precedence_ordinal": json.Number("2"), "dependency_role": thirdRole,
		"artifact_identity": map[string]interface{}{"artifact": "third_artifact", "artifact_version": "1", "artifact_sha256": strings.Repeat("a", 64)},
		"applicability":     map[string]interface{}{"selector_kind": "opaque_selector", "selector_values": []interface{}{"opaque_value"}},
		"authority_posture": "schema_owned", "exact_revalidation_required": true,
		"validation_binding": map[string]interface{}{
			"validation_schema_id": "urn:scanner:schema:third", "validation_schema_version": "1", "validation_schema_sha256": strings.Repeat("b", 64),
			"validation_profile_id": "third_profile", "validation_profile_version": "1", "validation_profile_sha256": strings.Repeat("c", 64),
		},
	}
	makeInput := func(includeThirdRole bool) (artifactInput, dependencySemanticValidationProof) {
		manifest := make(map[string]interface{}, len(base.Manifest))
		for key, value := range base.Manifest {
			manifest[key] = value
		}
		manifest["dependency_count"] = json.Number("3")
		roles := []interface{}{"prior_provider_field_mapping_seed", "owning_domain_field_mapping_override"}
		if includeThirdRole {
			roles = append(roles, thirdRole)
		}
		manifest["closed_dependency_role_roster"] = roles
		summary := map[string]interface{}{"row_kind": "validation_summary", "dependency_count": json.Number("3"), "validation_schema_count": json.Number("3"), "validation_profile_count": json.Number("3"), "canonical_admission_authorized": false, "result": "schema_owned"}
		raw := scannerJSONLRows(t, manifest, baseRows[0], baseRows[1], third, summary)
		input := base
		input.Raw = raw
		input.SHA256 = sha256Hex(raw)
		input.Manifest = manifest
		input.ValidationSummary = summary
		input.RowsByKind = map[string][]map[string]interface{}{"mapping_transitive_dependency": {baseRows[0], baseRows[1], third}}
		proof := dependencySemanticValidationProof{seal: dependencySemanticValidationAuthority, byRole: map[string]dependencySemanticValidatedArtifact{}}
		for role, binding := range semanticValidation.proof.byRole {
			proof.byRole[role] = binding
		}
		binding := proof.byRole[dependencySemanticRoleMappingTransitiveRoster]
		binding.artifactSHA256 = input.SHA256
		proof.byRole[dependencySemanticRoleMappingTransitiveRoster] = binding
		return input, proof
	}

	accepted, acceptedProof := makeInput(true)
	bindings, err := mappingTransitiveDependencyClosureBindings(accepted, acceptedProof)
	if err != nil {
		t.Fatalf("schema-proven third opaque role was rejected: %v", err)
	}
	if len(bindings) != 3 || bindings[2].dependencyRole != thirdRole {
		t.Fatalf("third opaque role closure = %#v", bindings)
	}

	unrostered, unrosteredProof := makeInput(false)
	if _, err := mappingTransitiveDependencyClosureBindings(unrostered, unrosteredProof); err == nil {
		t.Fatal("dependency row carrying an unrostered opaque role was accepted")
	}
}

func TestMappingTransitiveArtifactMustValidateAgainstExactBoundSchema(t *testing.T) {
	_, _, dependencies, semanticValidation := scannerSemanticClosureFixture(t, []byte(`["safe-direct-first"]`), []byte(`["safe-direct-second"]`))
	roster := semanticValidation.roleArtifacts[dependencySemanticRoleMappingTransitiveRoster]
	bindings, err := mappingTransitiveDependencyClosureBindings(roster, semanticValidation.proof)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindings[0]
	artifact := dependencies[binding.artifactDigest]
	schema := dependencies[binding.validationSchemaDigest]
	if err := validateMappingTransitiveArtifactSchema(artifact, schema, binding); err != nil {
		t.Fatalf("valid exact transitive artifact/schema pair failed: %v", err)
	}

	payloadProperty := scannerMappingArtifactFragmentProperty(t, artifact.Raw)
	artifact.Raw = bytes.Replace(artifact.Raw, []byte(fmt.Sprintf("%q:", payloadProperty)), []byte(`"schema_forbidden_field":`), 1)
	artifact.SHA256 = sha256Hex(artifact.Raw)
	binding.artifactDigest = artifact.SHA256
	if err := validateMappingTransitiveArtifactSchema(artifact, schema, binding); err == nil || !strings.Contains(err.Error(), "fails its bound schema") {
		t.Fatalf("schema-invalid transitive artifact error = %v", err)
	}
}

func TestMappingTransitiveValidationProfileMustSetEqualRosterBinding(t *testing.T) {
	_, plan, dependencies, semanticValidation := scannerSemanticClosureFixture(t, []byte("[\"safe-direct-first\"]"), []byte("[\"safe-direct-second\"]"))
	roster := semanticValidation.roleArtifacts[dependencySemanticRoleMappingTransitiveRoster]
	bindings, err := mappingTransitiveDependencyClosureBindings(roster, semanticValidation.proof)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindings[0]
	profile := dependencies[binding.validationProfileDigest]
	original := profile.RowsByKind["artifact_schema_binding"][0]
	mutatedBinding := make(map[string]interface{}, len(original))
	for key, value := range original {
		mutatedBinding[key] = value
	}
	mutatedBinding["artifact_raw_sha256"] = strings.Repeat("d", 64)
	profile.Raw = scannerJSONLRows(t, profile.Manifest, mutatedBinding, profile.ValidationSummary)
	profile.SHA256 = sha256Hex(profile.Raw)
	profile.RowsByKind = map[string][]map[string]interface{}{"artifact_schema_binding": {mutatedBinding}}
	binding.validationProfileDigest = profile.SHA256

	profileSchemaPin := plan.Manifest.DependencySemanticValidation.Schema
	profileSchema := dependencies[profileSchemaPin.RawSHA256]
	err = validateMappingTransitiveValidationProfile(profile, profileSchema, profileSchemaPin, binding)
	if err == nil || !strings.Contains(err.Error(), "not set-equal") {
		t.Fatalf("profile/roster mismatch error = %v", err)
	}
}

func TestMappingTransitiveValidationSchemaReuseIsExactAndFirstPrecedenceOnly(t *testing.T) {
	sharedDigest := strings.Repeat("a", 64)
	base := []mappingTransitiveClosureBinding{
		{bindingID: "first", precedenceOrdinal: 0, validationSchemaID: "urn:scanner:schema:shared", validationSchemaVersion: "1", validationSchemaDigest: sharedDigest},
		{bindingID: "second", precedenceOrdinal: 1, validationSchemaID: "urn:scanner:schema:shared", validationSchemaVersion: "1", validationSchemaDigest: sharedDigest},
	}
	unique, err := uniqueMappingTransitiveValidationSchemaBindings(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(unique) != 1 || unique[0].bindingID != "first" {
		t.Fatalf("schema reuse closure = %#v", unique)
	}

	coordinateAlias := append([]mappingTransitiveClosureBinding(nil), base...)
	coordinateAlias[1].validationSchemaDigest = strings.Repeat("b", 64)
	if _, err := uniqueMappingTransitiveValidationSchemaBindings(coordinateAlias); err == nil || !strings.Contains(err.Error(), "coordinate") {
		t.Fatalf("same-coordinate/different-digest error = %v", err)
	}

	digestAlias := append([]mappingTransitiveClosureBinding(nil), base...)
	digestAlias[1].validationSchemaID = "urn:scanner:schema:different"
	if _, err := uniqueMappingTransitiveValidationSchemaBindings(digestAlias); err == nil || !strings.Contains(err.Error(), "aliases coordinates") {
		t.Fatalf("same-digest/different-coordinate error = %v", err)
	}
}

func scannerFragmentPairWithDigestOrder(t *testing.T, firstFragment, secondFragment []byte, reverse bool) ([]byte, []byte) {
	t.Helper()
	second := []byte(fmt.Sprintf(`["%s"]`, secondFragment))
	secondDigest := sha256Hex(second)
	for whitespaceBytes := 0; whitespaceBytes < 10000; whitespaceBytes++ {
		first := append([]byte(fmt.Sprintf(`["%s"]`, firstFragment)), bytes.Repeat([]byte{' '}, whitespaceBytes)...)
		firstDigest := sha256Hex(first)
		if (firstDigest > secondDigest) == reverse {
			return first, second
		}
	}
	t.Fatal("could not construct requested real digest order")
	return nil, nil
}

func scannerStructuredFragmentPairWithDigestOrder(t *testing.T, firstFragment, secondFragment []byte, reverse bool) ([]byte, []byte) {
	t.Helper()
	firstManifest := `{"row_kind":"artifact_manifest","artifact":"prior_map","artifact_version":"1"}`
	secondManifest := `{"row_kind":"artifact_manifest","artifact":"domain_override","artifact_version":"1"}`
	second := []byte(fmt.Sprintf(`{"%s":true,"row_kind":"mapping_row"}
%s`, secondFragment, secondManifest))
	secondDigest := sha256Hex(second)
	for whitespaceBytes := 0; whitespaceBytes < 10000; whitespaceBytes++ {
		first := []byte(fmt.Sprintf(`%s
{"row_kind":"mapping_row","%s":true}%s`, firstManifest, firstFragment, bytes.Repeat([]byte{' '}, whitespaceBytes)))
		firstDigest := sha256Hex(first)
		if (firstDigest > secondDigest) == reverse {
			return first, second
		}
	}
	t.Fatal("could not construct requested structured real digest order")
	return nil, nil
}

func scannerSemanticClosureFixture(t *testing.T, first, second []byte) ([]byte, *parsedPlan, map[string]artifactInput, dependencySemanticValidationResolution) {
	return scannerSemanticClosureFixtureWithTransitiveRows(
		t,
		first,
		second,
		[]byte("{\"row_kind\":\"artifact_manifest\",\"artifact\":\"prior_map\",\"artifact_version\":\"1\"}\n{\"row_kind\":\"mapping_row\",\"safe-prior\":true}"),
		[]byte("{\"safe-override\":true,\"row_kind\":\"mapping_row\"}\n{\"row_kind\":\"artifact_manifest\",\"artifact\":\"domain_override\",\"artifact_version\":\"1\"}"),
		[]int{0, 1},
		[]uint64{0, 1},
	)
}

func scannerSemanticClosureFixtureWithTransitiveRows(t *testing.T, first, second, priorRaw, overrideRaw []byte, physicalRowOrder []int, ordinals []uint64) ([]byte, *parsedPlan, map[string]artifactInput, dependencySemanticValidationResolution) {
	t.Helper()
	dependencies := map[string]artifactInput{}
	add := func(path string, raw []byte, manifest map[string]interface{}, structured bool) string {
		digest := sha256Hex(raw)
		dependencies[digest] = artifactInput{Path: path, SHA256: digest, Raw: bytes.Clone(raw), Structured: structured, Manifest: manifest}
		return digest
	}
	addRaw := func(path string, raw []byte) string { return add(path, raw, nil, false) }
	priorManifest := map[string]interface{}{"row_kind": "artifact_manifest", "artifact": "prior_map", "artifact_version": "1"}
	overrideManifest := map[string]interface{}{"row_kind": "artifact_manifest", "artifact": "domain_override", "artifact_version": "1"}
	priorDigest := add("prior-map.jsonl", priorRaw, priorManifest, true)
	overrideDigest := add("domain-override.jsonl", overrideRaw, overrideManifest, true)
	priorSchemaID := "urn:scanner:schema:prior-map"
	overrideSchemaID := "urn:scanner:schema:domain-override"
	priorSchemaDigest := addRaw("prior-schema.json", scannerMappingArtifactSchema(t, "prior_map", priorSchemaID, scannerMappingArtifactFragmentProperty(t, priorRaw)))
	overrideSchemaDigest := addRaw("override-schema.json", scannerMappingArtifactSchema(t, "domain_override", overrideSchemaID, scannerMappingArtifactFragmentProperty(t, overrideRaw)))
	mappingRoles := []string{"prior_provider_field_mapping_seed", "owning_domain_field_mapping_override"}
	priorProfileID := "prior_profile"
	overrideProfileID := "override_profile"
	priorProfile := scannerValidationProfileInput(t, "prior-profile.jsonl", priorProfileID, mappingRoles[0], "prior_map", priorDigest, priorSchemaID, priorSchemaDigest)
	overrideProfile := scannerValidationProfileInput(t, "override-profile.jsonl", overrideProfileID, mappingRoles[1], "domain_override", overrideDigest, overrideSchemaID, overrideSchemaDigest)
	dependencies[priorProfile.SHA256] = priorProfile
	dependencies[overrideProfile.SHA256] = overrideProfile

	row := func(bindingID, role, artifactID, artifactDigest, schemaID, schemaDigest, profileID, profileDigest string, ordinal uint64, selector string) map[string]interface{} {
		return map[string]interface{}{
			"row_kind": "mapping_transitive_dependency", "dependency_binding_id": bindingID, "precedence_ordinal": json.Number(strconv.FormatUint(ordinal, 10)), "dependency_role": role,
			"artifact_identity": map[string]interface{}{"artifact": artifactID, "artifact_version": "1", "artifact_sha256": artifactDigest},
			"applicability":     map[string]interface{}{"selector_kind": "source_object_type", "selector_values": []interface{}{selector}},
			"authority_posture": "candidate_exact_dependency", "exact_revalidation_required": true,
			"validation_binding": map[string]interface{}{"validation_schema_id": schemaID, "validation_schema_version": "1", "validation_schema_sha256": schemaDigest, "validation_profile_id": profileID, "validation_profile_version": "1", "validation_profile_sha256": profileDigest},
		}
	}
	rows := []map[string]interface{}{
		row("prior_seed", mappingRoles[0], "prior_map", priorDigest, priorSchemaID, priorSchemaDigest, priorProfileID, priorProfile.SHA256, ordinals[0], "*"),
		row("domain_override", mappingRoles[1], "domain_override", overrideDigest, overrideSchemaID, overrideSchemaDigest, overrideProfileID, overrideProfile.SHA256, ordinals[1], "Invoice"),
	}
	rosterManifest := map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": "provider_mapping_transitive_dependency_roster", "artifact_version": "1", "status": "candidate_not_admissible", "provider": "scanner_provider",
		"dependency_count": json.Number("2"), "closed_dependency_role_roster": []interface{}{mappingRoles[0], mappingRoles[1]}, "canonical_admission_authorized": false,
	}
	rosterSummary := map[string]interface{}{"row_kind": "validation_summary", "dependency_count": json.Number("2"), "validation_schema_count": json.Number("2"), "validation_profile_count": json.Number("2"), "canonical_admission_authorized": false, "result": "structural_candidate_transitive_dependency_roster"}
	rosterRaw := scannerJSONLRows(t, rosterManifest, rows[physicalRowOrder[0]], rows[physicalRowOrder[1]], rosterSummary)
	rosterDigest := sha256Hex(rosterRaw)
	dependencies[rosterDigest] = artifactInput{
		Path: "mapping-transitive-roster.jsonl", SHA256: rosterDigest, Raw: rosterRaw, Structured: true, Manifest: rosterManifest, ValidationSummary: rosterSummary,
		RowKindCounts: map[string]int{"artifact_manifest": 1, "mapping_transitive_dependency": 2, "validation_summary": 1}, RowsByKind: map[string][]map[string]interface{}{"mapping_transitive_dependency": {rows[physicalRowOrder[0]], rows[physicalRowOrder[1]]}},
	}
	surfaceManifest := map[string]interface{}{"row_kind": "artifact_manifest", "artifact": "scanner_surface_disposition", "artifact_version": "1"}
	surfaceDigest := add("surface.jsonl", scannerJSONLRows(t, surfaceManifest, map[string]interface{}{"row_kind": "surface_disposition", "value": "safe-surface"}), surfaceManifest, true)
	securityManifest := map[string]interface{}{"row_kind": "artifact_manifest", "artifact": "scanner_field_security_policy", "artifact_version": "1"}
	securityDigest := add("field-security.jsonl", scannerJSONLRows(t, securityManifest, map[string]interface{}{"row_kind": "security_policy", "value": "safe-security"}), securityManifest, true)
	derivationManifest := map[string]interface{}{"row_kind": "artifact_manifest", "artifact": "scanner_claim_derivation_profile", "artifact_version": "1"}
	derivationDigest := add("claim-derivation.jsonl", scannerJSONLRows(t, derivationManifest, map[string]interface{}{"row_kind": "derivation_rule", "value": "safe-derivation"}), derivationManifest, true)
	fieldMappingManifest := map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": "scanner_field_mapping", "artifact_version": "1",
		"surface_family_disposition_sha256": surfaceDigest, "field_security_policy_artifact_sha256": securityDigest,
		"mapping_transitive_dependency_roster_sha256": rosterDigest, "documentation_claim_derivation_profile_sha256": derivationDigest,
	}
	fieldMappingRaw := scannerJSONLRows(t, fieldMappingManifest, map[string]interface{}{"row_kind": "mapping", "value": "safe-mapping"})
	fieldMappingDigest := add("mapping.jsonl", fieldMappingRaw, fieldMappingManifest, true)
	profileDigest := addRaw("first.jsonl", first)
	sourceDigest := addRaw("second.jsonl", second)
	sampleDigest := addRaw("sample.jsonl", []byte(`["safe-sample"]`))
	protocolDigest := addRaw("protocol.jsonl", []byte(`["safe-protocol"]`))
	operationApplicabilityManifest := map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": "scanner_operation_applicability_profile", "artifact_version": "1",
	}
	operationApplicabilityDigest := add(
		"operation-applicability.jsonl",
		scannerJSONLRows(t, operationApplicabilityManifest, map[string]interface{}{"row_kind": "operation_applicability", "semantic_identity": "source_neutral_operation"}),
		operationApplicabilityManifest,
		true,
	)
	apiGraphApplicabilityManifest := map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": "scanner_api_graph_applicability_profile", "artifact_version": "1",
	}
	apiGraphApplicabilityDigest := add(
		"api-graph-applicability.jsonl",
		scannerJSONLRows(t, apiGraphApplicabilityManifest, map[string]interface{}{"row_kind": "api_graph_applicability", "semantic_identity": "source_neutral_api_graph"}),
		apiGraphApplicabilityManifest,
		true,
	)
	semanticProfileDigest := addRaw("dependency-semantic-profile.jsonl", []byte(`{"profile":"safe-dependency-semantic-profile"}`))
	semanticProfileSchemaID := "urn:scanner:schema:artifact-validation-profile"
	semanticProfileSchemaDigest := addRaw("dependency-semantic-profile.schema.json", scannerValidationProfileSchema(t, semanticProfileSchemaID))
	manifest := &artifactManifest{
		Provider:                            "scanner_provider",
		ProviderNeutralProfileSHA256:        profileDigest,
		SourceContractIndexSHA256:           sourceDigest,
		SampleShapeIndexSHA256:              sampleDigest,
		ProtocolContractIndexSHA256:         protocolDigest,
		FieldMappingCandidateSHA256:         fieldMappingDigest,
		OperationApplicabilityProfileSHA256: operationApplicabilityDigest,
		APIGraphApplicabilityProfileSHA256:  apiGraphApplicabilityDigest,
		EvidenceSelectionRosterSHA256:       add("selection.jsonl", []byte(`["safe-selection"]`), map[string]interface{}{}, true),
		DependencySemanticValidation: dependencySemanticValidationPlanBinding{
			Profile: dependencySemanticValidationPin{Role: "dependency_semantic_validation_profile", ID: "scanner_dependency_semantic_profile", Version: "1", RawSHA256: semanticProfileDigest},
			Schema:  dependencySemanticValidationPin{Role: "dependency_semantic_validation_profile_schema", ID: semanticProfileSchemaID, Version: "1", RawSHA256: semanticProfileSchemaDigest},
		},
	}
	semanticArtifactDigests := map[string]string{
		"provider_neutral_compilation_profile":       profileDigest,
		"source_contract_index":                      sourceDigest,
		"sample_shape_index":                         sampleDigest,
		"protocol_contract_index":                    protocolDigest,
		"field_mapping_candidate":                    fieldMappingDigest,
		dependencySemanticRoleOperationApplicability: operationApplicabilityDigest,
		dependencySemanticRoleAPIGraphApplicability:  apiGraphApplicabilityDigest,
		"surface_family_disposition":                 surfaceDigest,
		"field_security_policy":                      securityDigest,
		"mapping_transitive_dependency_roster":       rosterDigest,
		"documentation_claim_derivation_profile":     derivationDigest,
	}
	proof := dependencySemanticValidationProof{
		seal:   dependencySemanticValidationAuthority,
		byRole: make(map[string]dependencySemanticValidatedArtifact, len(dependencySemanticRequiredRoles)),
	}
	for index, role := range dependencySemanticRequiredRoles {
		schemaID := fmt.Sprintf("scanner_semantic_schema_%02d", index)
		schemaDigest := addRaw(schemaID+".json", []byte(fmt.Sprintf(`{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"%s"}`, schemaID)))
		proof.byRole[role] = dependencySemanticValidatedArtifact{
			artifactSHA256: semanticArtifactDigests[role],
			schemaRole:     fmt.Sprintf("scanner_semantic_schema_role_%02d", index),
			schemaID:       schemaID,
			schemaVersion:  "1",
			schemaSHA256:   schemaDigest,
		}
	}
	roleArtifacts := make(map[string]artifactInput, len(semanticArtifactDigests))
	for role, digest := range semanticArtifactDigests {
		roleArtifacts[role] = dependencies[digest]
	}
	targetRole := dependencySemanticRoleSourceContract
	targetRaw := []byte(`{"row_kind":"artifact_manifest","artifact":"scanner_exact_documentation_target","artifact_version":"1"}
{"row_kind":"safe_target","value":"safe-exact-documentation-target"}
`)
	targetDigest := add("exact-documentation-target.jsonl", targetRaw, map[string]interface{}{"row_kind": "artifact_manifest", "artifact": "scanner_exact_documentation_target", "artifact_version": "1"}, true)
	targetSchemaID := "urn:scanner:schema:exact-documentation-target"
	targetSchemaBytes := []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"safe exact documentation target"}`)
	targetSchemaDigest := addRaw("exact-documentation-target.schema.json", targetSchemaBytes)
	semanticValidation := dependencySemanticValidationResolution{
		proof:         proof,
		roleArtifacts: roleArtifacts,
		derivationTargets: dependencySemanticDerivationTargetSchemaAuthority{
			seal: dependencySemanticDerivationTargetSchemaAuthorityIdentity,
			byRole: map[string]dependencySemanticDerivationTargetSchema{
				targetRole: {
					artifactRole: targetRole, artifactSHA256: targetDigest,
					schemaRole: "scanner_exact_documentation_target_schema", schemaID: targetSchemaID, schemaVersion: "1", schemaSHA256: targetSchemaDigest,
					schemaBytes: targetSchemaBytes, discriminatorProperty: "row_kind", discriminatorValues: map[string]struct{}{"artifact_manifest": {}, "safe_target": {}},
				},
			},
		},
		derivationTargetArtifacts: map[string]artifactInput{targetRole: dependencies[targetDigest]},
	}
	planRaw := []byte(fmt.Sprintf(
		`{"row_kind":"artifact_manifest","provider_neutral_compilation_profile_sha256":"%s","source_contract_index_sha256":"%s","sample_shape_index_sha256":"%s","protocol_contract_index_sha256":"%s","field_mapping_candidate_sha256":"%s","operation_applicability_profile_sha256":"%s","api_graph_applicability_profile_sha256":"%s","evidence_selection_roster_sha256":"%s","dependency_semantic_validation":{"profile":{"role":"%s","id":"%s","version":"%s","raw_sha256":"%s"},"schema":{"role":"%s","id":"%s","version":"%s","raw_sha256":"%s"}}}`,
		manifest.ProviderNeutralProfileSHA256,
		manifest.SourceContractIndexSHA256,
		manifest.SampleShapeIndexSHA256,
		manifest.ProtocolContractIndexSHA256,
		manifest.FieldMappingCandidateSHA256,
		manifest.OperationApplicabilityProfileSHA256,
		manifest.APIGraphApplicabilityProfileSHA256,
		manifest.EvidenceSelectionRosterSHA256,
		manifest.DependencySemanticValidation.Profile.Role,
		manifest.DependencySemanticValidation.Profile.ID,
		manifest.DependencySemanticValidation.Profile.Version,
		manifest.DependencySemanticValidation.Profile.RawSHA256,
		manifest.DependencySemanticValidation.Schema.Role,
		manifest.DependencySemanticValidation.Schema.ID,
		manifest.DependencySemanticValidation.Schema.Version,
		manifest.DependencySemanticValidation.Schema.RawSHA256,
	))
	return planRaw, &parsedPlan{Manifest: manifest}, dependencies, semanticValidation
}

func scannerJSONLRows(t *testing.T, rows ...map[string]interface{}) []byte {
	t.Helper()
	var result bytes.Buffer
	for _, row := range rows {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		result.Write(raw)
		result.WriteByte('\n')
	}
	return result.Bytes()
}

func scannerMappingArtifactFragmentProperty(t *testing.T, raw []byte) string {
	t.Helper()
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		row, err := decodeJSONObject(line)
		if err != nil {
			t.Fatal(err)
		}
		if rowKind, _ := manifestString(row, "row_kind"); rowKind != "mapping_row" {
			continue
		}
		var property string
		for key := range row {
			if key == "row_kind" {
				continue
			}
			if property != "" {
				t.Fatalf("mapping-row fixture has more than one payload property")
			}
			property = key
		}
		if property == "" {
			t.Fatal("mapping-row fixture has no payload property")
		}
		return property
	}
	t.Fatal("mapping artifact fixture has no mapping_row")
	return ""
}

func scannerMappingArtifactSchema(t *testing.T, artifactID, schemaID, fragmentProperty string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     schemaID,
		"$defs": map[string]interface{}{
			"manifest": map[string]interface{}{
				"type":                 "object",
				"required":             []string{"row_kind", "artifact", "artifact_version"},
				"additionalProperties": false,
				"properties": map[string]interface{}{
					"row_kind":         map[string]interface{}{"const": "artifact_manifest"},
					"artifact":         map[string]interface{}{"const": artifactID},
					"artifact_version": map[string]interface{}{"const": "1"},
				},
			},
			"mapping_row": map[string]interface{}{
				"type":                 "object",
				"required":             []string{"row_kind", fragmentProperty},
				"additionalProperties": false,
				"properties": map[string]interface{}{
					"row_kind":       map[string]interface{}{"const": "mapping_row"},
					fragmentProperty: map[string]interface{}{"const": true},
				},
			},
		},
		"oneOf": []interface{}{
			map[string]interface{}{"$ref": "#/$defs/manifest"},
			map[string]interface{}{"$ref": "#/$defs/mapping_row"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func scannerValidationProfileInput(t *testing.T, path, profileID, role, artifactID, artifactDigest, schemaID, schemaDigest string) artifactInput {
	t.Helper()
	manifest := map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": "provider_documentation_artifact_validation_profile", "artifact_version": "1",
		"status": "structural_candidate_not_admissible", "profile_id": profileID, "profile_version": "1",
		"binding_count": json.Number("1"), "canonical_admission_authorized": false,
	}
	binding := map[string]interface{}{
		"row_kind": "artifact_schema_binding", "role": role,
		"artifact_id": artifactID, "artifact_version": "1", "artifact_raw_sha256": artifactDigest,
		"schema_role": "target_artifact_schema", "schema_id": schemaID, "schema_version": "1", "schema_raw_sha256": schemaDigest,
	}
	summary := map[string]interface{}{
		"row_kind": "validation_summary", "binding_count": json.Number("1"), "artifact_count": json.Number("1"), "schema_count": json.Number("1"),
		"canonical_admission_authorized": false, "result": "structural_candidate_closed_artifact_schema_bindings",
	}
	raw := scannerJSONLRows(t, manifest, binding, summary)
	digest := sha256Hex(raw)
	return artifactInput{
		Path: path, SHA256: digest, Raw: raw, Structured: true, Manifest: manifest, ValidationSummary: summary,
		RowsByKind:    map[string][]map[string]interface{}{"artifact_schema_binding": {binding}},
		RowKindCounts: map[string]int{"artifact_manifest": 1, "artifact_schema_binding": 1, "validation_summary": 1},
	}
}

func scannerValidationProfileSchema(t *testing.T, schemaID string) []byte {
	t.Helper()
	stringProperty := func() map[string]interface{} { return map[string]interface{}{"type": "string"} }
	raw, err := json.Marshal(map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     schemaID,
		"oneOf": []interface{}{
			map[string]interface{}{
				"type": "object", "additionalProperties": false,
				"required": []string{"row_kind", "artifact", "artifact_version", "status", "profile_id", "profile_version", "binding_count", "canonical_admission_authorized"},
				"properties": map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "artifact_manifest"}, "artifact": map[string]interface{}{"const": "provider_documentation_artifact_validation_profile"},
					"artifact_version": map[string]interface{}{"const": "1"}, "status": map[string]interface{}{"const": "structural_candidate_not_admissible"},
					"profile_id": stringProperty(), "profile_version": stringProperty(), "binding_count": map[string]interface{}{"type": "integer", "minimum": 1},
					"canonical_admission_authorized": map[string]interface{}{"const": false},
				},
			},
			map[string]interface{}{
				"type": "object", "additionalProperties": false,
				"required": []string{"row_kind", "role", "artifact_id", "artifact_version", "artifact_raw_sha256", "schema_role", "schema_id", "schema_version", "schema_raw_sha256"},
				"properties": map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "artifact_schema_binding"}, "role": stringProperty(),
					"artifact_id": stringProperty(), "artifact_version": stringProperty(), "artifact_raw_sha256": stringProperty(),
					"schema_role": stringProperty(), "schema_id": stringProperty(), "schema_version": stringProperty(), "schema_raw_sha256": stringProperty(),
				},
			},
			map[string]interface{}{
				"type": "object", "additionalProperties": false,
				"required": []string{"row_kind", "binding_count", "artifact_count", "schema_count", "canonical_admission_authorized", "result"},
				"properties": map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "validation_summary"}, "binding_count": map[string]interface{}{"type": "integer", "minimum": 1},
					"artifact_count": map[string]interface{}{"type": "integer", "minimum": 1}, "schema_count": map[string]interface{}{"type": "integer", "minimum": 1},
					"canonical_admission_authorized": map[string]interface{}{"const": false}, "result": map[string]interface{}{"const": "structural_candidate_closed_artifact_schema_bindings"},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCredentialPlaceholderIsAClosedReconstructionBoundary(t *testing.T) {
	raw := []byte("[\"api_\"]\n[\"key=\",\"<API_KEY>\",\"ActualOpaqueCredentialValue123456\"]\n")
	if err := validateStructuredDependencySecurity(artifactInput{Path: "placeholder.jsonl", Raw: raw, Structured: true}); err != nil {
		t.Fatalf("exact placeholder did not terminate credential reconstruction: %v", err)
	}
}

func TestCredentialPlaceholderSubstringIsNotAReconstructionBoundary(t *testing.T) {
	raw := []byte(`["api_key=prefix","<API_KEY>-suffix-A1b2C3d4E5f6G7h8I9j0"]`)
	if err := validateStructuredDependencySecurity(artifactInput{Path: "placeholder-substring.jsonl", Raw: raw, Structured: true}); err == nil {
		t.Fatal("credential-bearing value containing a placeholder substring was accepted")
	}
}

func TestStructuredSecurityRejectsGenericTerminalCredentialFieldsAndNestedKeyCarrier(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "terminal credential", raw: `{"row_kind":"fact","provider_credential":"ActualOpaqueCredentialValue123456"}`},
		{name: "terminal credential value", raw: `{"row_kind":"fact","provider_credential_value":"ActualOpaqueCredentialValue123456"}`},
		{name: "terminal secret", raw: `{"row_kind":"fact","provider_secret":"ActualOpaqueCredentialValue123456"}`},
		{name: "indirect property declaration", raw: `{"row_kind":"fact","property_name":"credential_value","candidate_value":"ActualOpaqueCredentialValue123456"}`},
		{name: "nested object key carrier", raw: `{"row_kind":"fact","property_name":"credential_value","candidate_value":{"ActualOpaqueCredentialValue123456":true}}`, want: `["candidate_value"]["ActualOpaqueCredentialValue123456"]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateStructuredDependencySecurity(artifactInput{Path: "credential.jsonl", Raw: []byte(test.raw), Structured: true})
			if err == nil {
				t.Fatal("generic credential carrier was accepted")
			}
			if test.want != "" && !bytes.Contains([]byte(err.Error()), []byte(test.want)) {
				t.Fatalf("error = %v, want nested carrier path %q", err, test.want)
			}
		})
	}
}

func TestIndexedByteCarrierScanIsLinearAtMultiMegabyteScale(t *testing.T) {
	// 196,608 indexed bytes produce a JSON carrier larger than 2 MiB. The old
	// reachable-position subsequence DP grows quadratically on this shape; the
	// explicit carrier decoder plus streaming matcher stays linear.
	body := bytes.Repeat([]byte("Z"), 192*1024)
	carrier := bytes.NewBuffer(make([]byte, 0, 3*1024*1024))
	carrier.WriteByte('{')
	for index, value := range body {
		if index != 0 {
			carrier.WriteByte(',')
		}
		fmt.Fprintf(carrier, `"%d":%d`, index, value)
	}
	carrier.WriteByte('}')
	if carrier.Len() < 2*1024*1024 {
		t.Fatalf("scale fixture is only %d bytes", carrier.Len())
	}
	started := time.Now()
	err := validateNoEmbeddedEvidenceBodies("large-indexed-carrier", carrier.Bytes(), scannerTestBodies(body), 1)
	if err == nil {
		t.Fatal("multi-megabyte indexed-byte carrier was accepted")
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("linear scanner exceeded scale bound: %s", elapsed)
	}
}

func TestEvidenceClosureScannerPeakAuxiliaryStorageIsBoundedAtAdmissionCeiling(t *testing.T) {
	peak, ok := canonicalEvidenceClosurePeakAuxiliaryBytesForBodyLength(maxEvidenceBodyBytesPerFile)
	if !ok {
		t.Fatal("maximum admitted evidence body has no finite scanner auxiliary bound")
	}
	// One owned hexadecimal target is 2N bytes and its compact uint32 KMP
	// table is 8N bytes. One maximum carrier decode is the only other full-size
	// allocation that may coexist with a matcher.
	want := (10 * maxEvidenceBodyBytesPerFile) + maxEvidenceCarrierBytesPerFile
	if peak != want {
		t.Fatalf("peak auxiliary bytes = %d, want structural bound %d", peak, want)
	}
	if peak > canonicalEvidenceClosureMaxMatcherAuxiliaryBytes {
		t.Fatalf("peak auxiliary bytes %d exceed fixed scanner limit %d", peak, canonicalEvidenceClosureMaxMatcherAuxiliaryBytes)
	}

	// The retired eager roster retained raw, four base64, hexadecimal, and six
	// decoded-body KMP tables together. Keep this arithmetic regression so a
	// future refactor cannot mistake the per-pattern bound for permission to
	// retain the whole roster again.
	body := maxEvidenceBodyBytesPerFile
	base64Bytes := int64(base64.StdEncoding.EncodedLen(int(body)))
	eager := (4 * body) + (4 * (5 * base64Bytes)) + (5 * (2 * body)) + (6 * (4 * body))
	if eager <= 4<<30 {
		t.Fatalf("retired all-encoding matcher roster bound = %d, want proof it exceeds 4 GiB per maximum body", eager)
	}
}

func TestExactCarrierDecodersAllocateOnlyOneBoundedDestination(t *testing.T) {
	const (
		decodedBytes   = 4 << 20
		allocationRuns = 20
		// Go 1.26 AllocsPerRun reports an integer-divided per-run average from
		// process-wide allocation counters. Repeated steady-state samples
		// amortize nonpersistent runtime noise while still rejecting a second
		// allocation made on every decode.
		maxAverageAllocations = 1
	)
	body := bytes.Repeat([]byte{0xa5}, decodedBytes)
	base64Carrier := make([]byte, base64.StdEncoding.EncodedLen(len(body)))
	base64.StdEncoding.Encode(base64Carrier, body)
	hexCarrier := make([]byte, hex.EncodedLen(len(body)))
	hex.Encode(hexCarrier, body)

	if allocations := testing.AllocsPerRun(allocationRuns, func() {
		decoded, ok := exactBase64Carrier(base64.StdEncoding, base64Carrier)
		if !ok || len(decoded) != len(body) {
			panic("base64 decode failed")
		}
	}); allocations > maxAverageAllocations {
		t.Fatalf("strict base64 carrier decode allocations = %.2f per run, want one bounded destination", allocations)
	}
	if allocations := testing.AllocsPerRun(allocationRuns, func() {
		decoded, ok := exactHexCarrier(hexCarrier)
		if !ok || len(decoded) != len(body) {
			panic("hex decode failed")
		}
	}); allocations > maxAverageAllocations {
		t.Fatalf("strict hexadecimal carrier decode allocations = %.2f per run, want one bounded destination", allocations)
	}
}

func TestCanonicalEvidenceClosureBatchesBoundedStageScaleAndRetainsLateScalarDetection(t *testing.T) {
	const bodyCount = 87
	bodies := make(map[string]exactEvidenceBody, bodyCount)
	for index := 0; index < bodyCount; index++ {
		body := []byte(fmt.Sprintf("safe-distinct-selected-evidence-%03d", index))
		bodies[sha256Hex(body)] = exactEvidenceBody{Bytes: body}
	}
	// Keep every scalar under the substantial-fragment threshold. This is a
	// closure-scale regression, not a fragment-scanner benchmark.
	carriers := make([]string, 96)
	for index := range carriers {
		carriers[index] = strings.Repeat("ordinary-stage-metadata-", 36)
	}
	raw, err := json.Marshal(map[string]any{"carriers": carriers})
	if err != nil {
		t.Fatal(err)
	}
	item := evidenceClosureItem{label: "bounded provider stage", raw: raw, structured: true}
	budget := &canonicalEvidenceClosureWorkBudget{limit: 4 << 20}
	if _, _, _, found, err := detectCanonicalEvidenceBodyClosureWithBudget([]evidenceClosureItem{item}, jsonCarrierSourceOrder, bodies, 1, budget); err != nil || found {
		t.Fatalf("batched closure result found=%t err=%v, want safe bounded acceptance", found, err)
	}

	// Mutation sensitivity: restoring the per-body raw route under the same
	// test-only ceiling exhausts aggregate work. The production detector has no
	// configurable limit; this only proves the batching assertion is observed.
	legacyBudget := &canonicalEvidenceClosureWorkBudget{limit: 4 << 20}
	digests := make([]string, 0, len(bodies))
	for digest := range bodies {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	legacyRefused := false
	for _, digest := range digests {
		if _, found, err := scanCanonicalEvidencePattern([]evidenceClosureItem{item}, jsonCarrierSourceOrder, digest, "complete decoded body", bodies[digest].Bytes, false, false, canonicalEvidenceCarrierRawRepresentations, legacyBudget); err != nil {
			if !strings.Contains(err.Error(), "aggregate work-unit limit") {
				t.Fatalf("legacy per-body route error = %v, want aggregate-work refusal", err)
			}
			legacyRefused = true
			break
		} else if found {
			t.Fatal("safe scaling fixture unexpectedly reconstructed a body")
		}
	}
	if !legacyRefused {
		t.Fatal("legacy per-body route did not exhaust the private work budget")
	}
	if legacyBudget.used <= budget.used {
		t.Fatalf("legacy per-body work = %d, batched work = %d; scaling mutation was not observed", legacyBudget.used, budget.used)
	}
	t.Logf("batched work-units=%d; forced legacy per-body route refused at work-units=%d under limit=%d", budget.used, legacyBudget.used, legacyBudget.limit)

	lateBody := []byte("late-target-reconstructed-across-scalar-carriers")
	lateDigest := sha256Hex(lateBody)
	lateRaw, err := json.Marshal(map[string]any{"carriers": []string{"prefix[" + string(lateBody[:17]), string(lateBody[17:]) + "]suffix"}})
	if err != nil {
		t.Fatal(err)
	}
	itemLabel, digest, encoding, found, err := detectCanonicalEvidenceBodyClosureWithBudget(
		[]evidenceClosureItem{{label: "late scalar closure", raw: lateRaw, structured: true}},
		jsonCarrierSourceOrder,
		map[string]exactEvidenceBody{lateDigest: {Bytes: lateBody}},
		1,
		&canonicalEvidenceClosureWorkBudget{limit: 1 << 20},
	)
	if err != nil || !found || itemLabel != "late scalar closure" || digest != lateDigest || encoding != "complete decoded body" {
		t.Fatalf("late scalar reconstruction = (%q, %q, %q, %t, %v), want exact raw closure finding", itemLabel, digest, encoding, found, err)
	}
}

func TestCanonicalEvidenceBatchPeakReservesConcurrentDecodeBeforeMatcherAllocation(t *testing.T) {
	targets := []canonicalEvidenceBatchTarget{{
		digest:   "bounded-target",
		target:   []byte("bounded-target-body"),
		priority: 0,
	}}
	matcherOnly, ok := canonicalEvidenceBatchMatcherAuxiliaryBytes(int64(len(targets[0].target)), 0)
	if !ok {
		t.Fatal("small batch has no finite matcher-only auxiliary bound")
	}
	peak, ok := canonicalEvidenceBatchPeakAuxiliaryBytes(int64(len(targets[0].target)), 0)
	if !ok || peak != matcherOnly+maxEvidenceCarrierBytesPerFile {
		t.Fatalf("batch peak = (%d, %t), want matcher %d plus decode reserve %d", peak, ok, matcherOnly, maxEvidenceCarrierBytesPerFile)
	}

	budget := &canonicalEvidenceClosureWorkBudget{limit: 1 << 20}
	matcher, err := newCanonicalEvidenceBatchMatcherWithAuxiliaryLimit(targets, false, budget, matcherOnly)
	if err == nil || matcher != nil {
		t.Fatalf("matcher without concurrent decode reserve = (%v, %v), want pre-allocation refusal", matcher, err)
	}
	if budget.used != 0 {
		t.Fatalf("pre-allocation auxiliary refusal consumed %d work units", budget.used)
	}
	if !strings.Contains(err.Error(), "concurrent carrier decode") {
		t.Fatalf("auxiliary refusal = %v, want concurrent-decode identity", err)
	}

	if matcher, err := newCanonicalEvidenceBatchMatcherWithAuxiliaryLimit(targets, false, &canonicalEvidenceClosureWorkBudget{limit: 1 << 20}, peak); err != nil || matcher == nil {
		t.Fatalf("matcher at exact combined peak = (%v, %v), want bounded construction", matcher, err)
	}
}

func TestCanonicalEvidenceBatchTransitionWorkIsBoundedForHostileFanout(t *testing.T) {
	targets := make([]canonicalEvidenceBatchTarget, 256)
	for index := range targets {
		targets[index] = canonicalEvidenceBatchTarget{
			digest:   fmt.Sprintf("fanout-%03d", index),
			target:   []byte{byte(index)},
			priority: index,
		}
	}
	matcher, err := newCanonicalEvidenceBatchMatcher(targets, false, &canonicalEvidenceClosureWorkBudget{limit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}

	const inputBytes = 4096
	// A 256-way hostile fanout crosses the fixed dense-transition threshold and
	// therefore costs exactly one charged direct lookup per input byte.
	runtimeBudget := &canonicalEvidenceClosureWorkBudget{limit: inputBytes}
	state, matched, err := matcher.advanceFrom(0, bytes.Repeat([]byte{0xff}, inputBytes), false, runtimeBudget)
	if err != nil {
		t.Fatal(err)
	}
	if matched < 0 || matcher.targets[matched].priority != 255 {
		t.Fatalf("hostile fanout match index = %d, want priority 255", matched)
	}
	if runtimeBudget.used != runtimeBudget.limit {
		t.Fatalf("hostile fanout transition work = %d, want exact charged bound %d", runtimeBudget.used, runtimeBudget.limit)
	}
	if _, _, err := matcher.advanceFrom(state, []byte{0xff}, false, runtimeBudget); err == nil || !strings.Contains(err.Error(), "aggregate work-unit limit") {
		t.Fatalf("transition beyond charged fanout bound = %v, want deterministic refusal", err)
	}
}

func TestCanonicalEvidenceBatchReturnsHighestPriorityFindingBeforeLaterBudgetExhaustion(t *testing.T) {
	targets := []canonicalEvidenceBatchTarget{
		{digest: "priority-zero", target: []byte("highest-priority-leak"), priority: 0},
		{digest: "priority-one", target: []byte("lower-priority-leak"), priority: 1},
	}
	first, err := json.Marshal(map[string]any{"carrier": "highest-priority-leak"})
	if err != nil {
		t.Fatal(err)
	}
	later, err := json.Marshal(map[string]any{"carrier": strings.Repeat("x", 8<<10)})
	if err != nil {
		t.Fatal(err)
	}
	items := []evidenceClosureItem{
		{label: "first leak", raw: first, structured: true},
		{label: "later exhaustion", raw: later, structured: true},
	}
	match, err := scanCanonicalEvidenceBatch(items, jsonCarrierSourceOrder, targets, canonicalEvidenceCarrierRawRepresentations, false, &canonicalEvidenceClosureWorkBudget{limit: 2 << 10})
	if err != nil || !match.found || match.itemLabel != "first leak" || match.target.priority != 0 {
		t.Fatalf("highest-priority early finding = (%+v, %v), want priority-zero leak", match, err)
	}

	controlFirst, err := json.Marshal(map[string]any{"carrier": "ordinary-safe-value"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = scanCanonicalEvidenceBatch(
		[]evidenceClosureItem{{label: "safe first", raw: controlFirst, structured: true}, {label: "later exhaustion", raw: later, structured: true}},
		jsonCarrierSourceOrder,
		targets,
		canonicalEvidenceCarrierRawRepresentations,
		false,
		&canonicalEvidenceClosureWorkBudget{limit: 2 << 10},
	)
	if err == nil || !strings.Contains(err.Error(), "aggregate work-unit limit") {
		t.Fatalf("control scan without early leak = %v, want later aggregate refusal", err)
	}
}

func TestCanonicalEvidenceSubstantialFragmentBatchesBoundCorpusScan(t *testing.T) {
	const (
		bodyCount    = 87
		carrierCount = 96
	)
	bodies := make(map[string]exactEvidenceBody, bodyCount)
	var bodyBytes int64
	for index := 0; index < bodyCount; index++ {
		body := bytes.Repeat([]byte(fmt.Sprintf("selected-body-%03d-", index)), 1024)
		bodies[sha256Hex(body)] = exactEvidenceBody{Bytes: body}
		bodyBytes += int64(len(body))
	}
	carriers := make([]string, carrierCount)
	for index := range carriers {
		carriers[index] = strings.Repeat(fmt.Sprintf("safe-substantial-carrier-%03d-", index), 40)
		if len(carriers[index]) < 1024 {
			t.Fatalf("carrier %d is only %d bytes", index, len(carriers[index]))
		}
	}
	raw, err := json.Marshal(map[string]any{"carriers": carriers})
	if err != nil {
		t.Fatal(err)
	}
	digests := make([]string, 0, len(bodies))
	for digest := range bodies {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	budget := &canonicalEvidenceClosureWorkBudget{limit: 16 << 20}
	if itemLabel, digest, found, err := scanCanonicalEvidenceSubstantialFragmentBatches(
		[]evidenceClosureItem{{label: "bounded substantial fragments", raw: raw, structured: true}},
		jsonCarrierSourceOrder,
		digests,
		bodies,
		budget,
	); err != nil || found {
		t.Fatalf("substantial fragment batch result = (%q, %q, %t, %v), want bounded clean scan", itemLabel, digest, found, err)
	}
	legacyPairwiseBodyBytes := int64(carrierCount) * bodyBytes
	if legacyPairwiseBodyBytes <= budget.limit {
		t.Fatalf("fixture legacy pairwise body work = %d, want above bounded batch limit %d", legacyPairwiseBodyBytes, budget.limit)
	}
	if budget.used >= budget.limit {
		t.Fatalf("batched substantial fragment work = %d, want below fixed test limit %d", budget.used, budget.limit)
	}
}

func scannerTestBodies(body []byte) map[string]exactEvidenceBody {
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	return map[string]exactEvidenceBody{digest: {Bytes: bytes.Clone(body)}}
}

func bytesToUpperASCII(value []byte) string {
	result := bytes.Clone(value)
	for index, current := range result {
		if current >= 'a' && current <= 'f' {
			result[index] = current - ('a' - 'A')
		}
	}
	return string(result)
}
