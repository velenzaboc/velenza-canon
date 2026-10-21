package providerplan

import (
	"strings"
	"testing"
)

func documentationClaimSchemaReferenceForTest(schema string) dependencyProfileReference {
	return dependencyProfileReference{id: "schema_fixture", version: "1", digest: sha256Hex([]byte(schema))}
}

func TestDocumentationClaimSchemaRejectsMalformedAuthorityBytes(t *testing.T) {
	tests := []struct {
		name      string
		claimKind string
		reference dependencyProfileReference
		schema    string
		want      string
	}{
		{
			name: "noncanonical claim kind", claimKind: "", schema: "{}",
			reference: documentationClaimSchemaReferenceForTest("{}"), want: "claim_kind",
		},
		{
			name: "noncanonical schema coordinate", claimKind: "field_contract", schema: "{}",
			reference: dependencyProfileReference{id: "", version: "1", digest: sha256Hex([]byte("{}"))}, want: "empty",
		},
		{
			name: "digest mismatch", claimKind: "field_contract", schema: "{}",
			reference: dependencyProfileReference{id: "schema_fixture", version: "1", digest: strings.Repeat("0", 64)}, want: "digest",
		},
		{
			name: "invalid UTF-8", claimKind: "field_contract", schema: string([]byte{0xff}),
			reference: documentationClaimSchemaReferenceForTest(string([]byte{0xff})), want: "UTF-8",
		},
		{
			name: "duplicate keys", claimKind: "field_contract", schema: `{"$id":"schema_fixture","$id":"schema_fixture"}`,
			reference: documentationClaimSchemaReferenceForTest(`{"$id":"schema_fixture","$id":"schema_fixture"}`), want: "duplicate JSON keys",
		},
		{
			name: "noncanonical JSON", claimKind: "field_contract", schema: `{"$schema": "wrong"}`,
			reference: documentationClaimSchemaReferenceForTest(`{"$schema": "wrong"}`), want: "RFC-canonical",
		},
		{
			name: "non-object JSON", claimKind: "field_contract", schema: "[]",
			reference: documentationClaimSchemaReferenceForTest("[]"), want: "decode validation schema JSON object",
		},
		{
			name: "wrong dialect", claimKind: "field_contract", schema: `{"$id":"schema_fixture","$schema":"wrong"}`,
			reference: documentationClaimSchemaReferenceForTest(`{"$id":"schema_fixture","$schema":"wrong"}`), want: "$schema",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveDocumentationClaimSchema(tc.reference, tc.claimKind, tc.schema); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("resolve error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDocumentationClaimSchemaGenerationAndOutputBoundaries(t *testing.T) {
	_, validation := exactValueClassifierFactAndSchemaFixture(t)
	authority := validation.authority
	if _, err := newDocumentationSemanticGenerationBinding(
		authority.claimKind,
		dependencyProfileReference{id: "", version: "1", digest: strings.Repeat("a", 64)},
		authority,
	); err == nil {
		t.Fatal("semantic generation accepted a noncanonical program coordinate")
	}
	if _, err := newDocumentationSemanticGenerationBinding(
		"other_claim",
		dependencyProfileReference{id: "program_fixture", version: "1", digest: strings.Repeat("a", 64)},
		authority,
	); err == nil {
		t.Fatal("semantic generation accepted a mismatched claim kind")
	}

	if err := validateDocumentationClaimOutput(documentationClaimSchemaAuthority{}, []byte("{}")); err == nil {
		t.Fatal("claim output without exact schema authority was accepted")
	}
	if err := validateDocumentationClaimOutput(authority, []byte("{")); err == nil {
		t.Fatal("invalid JSON claim output was accepted")
	}
	if err := validateDocumentationClaimOutput(authority, []byte(`{"provider_type": "Decimal"}`)); err == nil {
		t.Fatal("noncanonical claim output was accepted")
	}
	if err := validateDocumentationClaimOutput(authority, []byte("[]")); err == nil {
		t.Fatal("non-object claim output was accepted")
	}
	if err := validateDocumentationClaimOutput(authority, []byte("{}")); err == nil {
		t.Fatal("claim output that violates its exact schema was accepted")
	}
}
