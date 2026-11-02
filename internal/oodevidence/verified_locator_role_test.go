package oodevidence

import "testing"

func TestVerifiedAPIRoleLocatorRequiresExactNativeRoles(t *testing.T) {
	v := VerifiedLocatorV8{organizationID: "org", relationshipHash: "relationship", locatorHash: "locator", sourceStableReference: "source", targetStableReference: "target", verified: true}
	if err := ValidateVerifiedAPIRoleLocatorV8(v); err == nil {
		t.Fatal("generic locator proof admitted as an API role proof")
	}
	v.sourceAPIElementRole, v.targetAPIElementRole = "operation", "resource"
	if err := ValidateVerifiedAPIRoleLocatorV8(v); err == nil {
		t.Fatal("roles without exact role-manifest and evidence-locator bindings were accepted")
	}
	v.sourceRoleManifest, v.targetRoleManifest, v.evidenceLocatorHash = "source-root", "target-root", "evidence-locator"
	if err := ValidateVerifiedAPIRoleLocatorV8(v); err == nil {
		t.Fatal("legacy role proof accepted without independent role-manifest authority")
	}
	v.roleManifestsVerified = true
	if err := ValidateVerifiedAPIRoleLocatorV8(v); err != nil {
		t.Fatal(err)
	}
	if v.SourceAPIElementRole() != "operation" || v.TargetAPIElementRole() != "resource" {
		t.Fatal("exact derived roles not retained in opaque proof")
	}
}
