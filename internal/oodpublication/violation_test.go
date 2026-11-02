package oodpublication

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestViolationLocatorManifestReferencesAreTypedAndCanonical(t *testing.T) {
	root := strings.Repeat("a", 64)
	raw := CanonicalJSON(`{"references":[{"ref_kind":"graph_fact_locator_manifest_ref","ref_value":"` + root + `"}]}`)
	roots, err := ViolationGraphFactLocatorManifestRoots(raw)
	if err != nil || len(roots) != 1 || roots[0] != root {
		t.Fatalf("typed locator reference: %v %v", roots, err)
	}
	for _, bad := range []string{strings.ToUpper(root), root[:63], "sha256:" + root} {
		if _, err := ViolationGraphFactLocatorManifestRoots(CanonicalJSON(`{"references":[{"ref_kind":"graph_fact_locator_manifest_ref","ref_value":"` + bad + `"}]}`)); err == nil {
			t.Fatal("noncanonical typed root accepted")
		}
	}
	roots, err = ViolationGraphFactLocatorManifestRoots(CanonicalJSON(`{"digests":{"evidence_digest":"` + root + `"}}`))
	if err != nil || len(roots) != 0 {
		t.Fatal("opaque digest was interpreted as a locator reference")
	}
}

const violationEvidenceUnordered = `{"redacted_diagnostics":{"violation_code":"bad","invalid":true},"digests":{"evidence_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`
const violationEvidenceJCS = `{"digests":{"evidence_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"redacted_diagnostics":{"invalid":true,"violation_code":"bad"}}`

func TestCanonicalViolationEvidenceBytesMatchesJCSGolden(t *testing.T) {
	got, err := CanonicalViolationEvidenceBytes(CanonicalJSON(violationEvidenceUnordered))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(violationEvidenceJCS)) {
		t.Fatalf("JCS bytes = %s", got)
	}
}

func TestViolationJCSUsesUTF16MemberOrderingAndMinimalEscapes(t *testing.T) {
	if !utf16Less("😀", "\ue000") || utf16Less("\ue000", "😀") {
		t.Fatal("RFC 8785 UTF-16 key ordering")
	}
	got := appendJSONString(nil, "<>&😀")
	if string(got) != `"<>&😀"` {
		t.Fatalf("non-minimal JCS escaping: %q", got)
	}
}

func TestCanonicalViolationEvidenceRejectsForbiddenGrammar(t *testing.T) {
	for _, raw := range []string{
		`{"digests":{"evidence_digest":null}}`, `{"digests":{"evidence_digest":1}}`,
		`{"digests":{"evidence_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`,
		`{"unknown":true}`, `{"identity_tuple_field_names":["z","a"]}`,
		`{"references":[{"ref_kind":"unknown","ref_value":"x"}]}`,
	} {
		if _, err := CanonicalViolationEvidenceBytes(CanonicalJSON(raw)); err == nil {
			t.Fatalf("forbidden evidence accepted: %s", raw)
		}
	}
}

func TestCanonicalViolationMemberDigestBindsEvidenceAndRejectsPhysicalViolations(t *testing.T) {
	row := violationRow(t, CanonicalJSON(violationEvidenceUnordered))
	a, err := CanonicalViolationMemberDigest(row)
	if err != nil {
		t.Fatal(err)
	}
	row.Columns["evidence"] = CanonicalJSON(`{"redacted_diagnostics":{"invalid":false}}`)
	b, err := CanonicalViolationMemberDigest(row)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("evidence mutation did not change member digest")
	}
	row = violationRow(t, CanonicalJSON(violationEvidenceUnordered))
	row.Columns["status"] = nil
	if _, err := CanonicalViolationMemberDigest(row); err == nil {
		t.Fatal("required physical column null accepted")
	}
	row = violationRow(t, CanonicalJSON(violationEvidenceUnordered))
	row.Columns["evidence"] = CanonicalJSON(`{"digests":{"evidence_digest":0}}`)
	if _, err := CanonicalViolationMemberDigest(row); err == nil {
		t.Fatal("numeric evidence accepted")
	}
}

func violationRow(t *testing.T, evidence CanonicalJSON) SpannerRow {
	t.Helper()
	cols := validPhysicalFixture("OODGraphViolations", immutablePhysicalContracts["OODGraphViolations"])
	for _, n := range immutablePhysicalContracts["OODGraphViolations"].columns {
		if physicalUUIDColumn("OODGraphViolations", n) {
			cols[n] = evidenceUUID(1)
		}
	}
	cols["organization_id"], cols["violation_id"], cols["evidence"] = "org", evidenceUUID(2), evidence
	cols["graph_snapshot_id"], cols["materialization_run_id"], cols["sentinel_candidate"], cols["source_authority_id"], cols["source_stable_reference"], cols["version_coordinate"], cols["section_path"], cols["graph_object_id"], cols["symbol_id"], cols["graph_edge_id"] = nil, nil, nil, nil, nil, nil, nil, nil, nil, nil
	cols["created_at"], cols["updated_at"] = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	if _, err := BuildImmutableRow("OODGraphViolations", cols); err != nil {
		t.Fatal(err)
	}
	return SpannerRow{Table: "OODGraphViolations", KeyColumns: []string{"organization_id", "violation_id"}, Columns: cols}
}
