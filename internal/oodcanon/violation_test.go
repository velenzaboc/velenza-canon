package oodcanon

import "testing"

func TestViolationManifestMemberV1ClosedRoster(t *testing.T) {
	p := ViolationManifestMemberV1()
	if p.Name != "ood_graph_violation_manifest_member_v1" || len(p.Fields) != 16 {
		t.Fatalf("profile: %#v", p)
	}
	if p.Fields[0].Name != "canonicalization_profile" || p.Fields[15].Name != "evidence_sha256" || p.Fields[15].Type != SHA256 {
		t.Fatalf("wrong owner field bindings: %#v", p.Fields)
	}
	if _, err := ProfileFor(p.Name); err != nil {
		t.Fatal(err)
	}
}
