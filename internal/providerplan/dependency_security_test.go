package providerplan

import (
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func TestValidateStructuredDependencySecurityRejectsForbiddenFacts(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "organization id equivalent",
			raw:  "{\"row_kind\":\"manifest\"}\n\n{\"outer\":{\"org_id\":\"caller-forged\"}}\n",
			want: `row 3 path $["outer"]["org_id"]: organization scope key`,
		},
		{
			name: "qualified organization id equivalent",
			raw:  `{"row_kind":"manifest","tenant_organization_id":"caller-forged"}`,
			want: `path $["tenant_organization_id"]: organization scope key`,
		},
		{
			name: "credential under credential key",
			raw:  `{"row_kind":"manifest","client_secret":"s3cr3t-value"}`,
			want: `path $["client_secret"]: credential or secret material`,
		},
		{
			name: "credential shaped neutral value",
			raw:  `{"row_kind":"manifest","diagnostic":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ"}`,
			want: `path $["diagnostic"]: credential or secret material`,
		},
		{
			name: "documentation word embedded in live credential assignment",
			raw:  `{"row_kind":"manifest","diagnostic":"api_key=live-example-9F4a8B7c6D5e"}`,
			want: `path $["diagnostic"]: credential or secret material`,
		},
		{
			name: "documentation word embedded in known credential prefix",
			raw:  `{"row_kind":"manifest","diagnostic":"sk-live-example-9F4a8B7c6D5e"}`,
			want: `path $["diagnostic"]: credential or secret material`,
		},
		{
			name: "embedded source body",
			raw:  `{"row_kind":"manifest","source_body":"{\"amount\":\"1.25\"}"}`,
			want: `path $["source_body"]: embedded provider/document/source body payload`,
		},
		{
			name: "embedded provider payload",
			raw:  `{"row_kind":"manifest","provider_response_payload":{"items":[]}}`,
			want: `path $["provider_response_payload"]: embedded provider/document/source body payload`,
		},
		{
			name: "embedded raw document",
			raw:  `{"row_kind":"manifest","raw_document":"Copy-all body"}`,
			want: `path $["raw_document"]: embedded provider/document/source body payload`,
		},
		{
			name: "embedded source byte array",
			raw:  `{"row_kind":"manifest","source_content_bytes":[123,34,97,34,58,49,125]}`,
			want: `path $["source_content_bytes"]: embedded provider/document/source body payload`,
		},
		{
			name: "binary float authority true",
			raw:  `{"row_kind":"manifest","numeric_policy":{"binary_float_authority":{"enabled":true}}}`,
			want: `path $["numeric_policy"]["binary_float_authority"]["enabled"]: binary-float authority`,
		},
		{
			name: "raw source value embedding true",
			raw:  `{"row_kind":"manifest","raw_source_value_embedding":{"allowed":true}}`,
			want: `path $["raw_source_value_embedding"]["allowed"]: raw provider/source value embedding`,
		},
		{
			name: "raw provider passthrough true",
			raw:  `{"row_kind":"manifest","provider_payload_passthrough":true}`,
			want: `path $["provider_payload_passthrough"]: raw provider/source value embedding`,
		},
		{
			name: "raw field value embedding true",
			raw:  `{"row_kind":"manifest","embedding_raw_field_values_allowed":true}`,
			want: `path $["embedding_raw_field_values_allowed"]: raw provider/source value embedding`,
		},
		{
			name: "noninteger number",
			raw:  `{"row_kind":"manifest","count":1.25}`,
			want: `row 1: binary-float-shaped JSON number "1.25"`,
		},
		{
			name: "duplicate key",
			raw:  `{"row_kind":"manifest","row_kind":"summary"}`,
			want: `row 1: duplicate JSON key "row_kind"`,
		},
		{
			name: "tenant id alias",
			raw:  `{"row_kind":"manifest","tenant_id":"caller-forged"}`,
			want: `path $["tenant_id"]: organization scope key`,
		},
		{
			name: "tenant scope id alias",
			raw:  `{"row_kind":"manifest","tenant_scope_id":"caller-forged"}`,
			want: `path $["tenant_scope_id"]: organization scope key`,
		},
		{
			name: "generic API token material",
			raw:  `{"row_kind":"manifest","api_token":"abcdefghijklmnopqrstuvwx"}`,
			want: `path $["api_token"]: credential or secret material`,
		},
		{
			name: "authorization value material",
			raw:  `{"row_kind":"manifest","authorization_value":"abcdefghijklmnopqrstuvwx"}`,
			want: `path $["authorization_value"]: credential or secret material`,
		},
		{
			name: "binary float authority string enabled",
			raw:  `{"row_kind":"manifest","binary_float_authority":"allowed"}`,
			want: `path $["binary_float_authority"]: unsafe numeric, embedding, or passthrough policy`,
		},
		{
			name: "provider passthrough string enabled",
			raw:  `{"row_kind":"manifest","provider_payload_passthrough":"enabled"}`,
			want: `path $["provider_payload_passthrough"]: unsafe numeric, embedding, or passthrough policy`,
		},
		{
			name: "raw source payload disguised as profile",
			raw:  `{"row_kind":"manifest","raw_source_payload_profile":"{\"amount\":\"1.25\"}"}`,
			want: `path $["raw_source_payload_profile"]: embedded provider/document/source body payload`,
		},
		{
			name: "credential hidden under nested description",
			raw:  `{"row_kind":"manifest","client_secret":{"description":"ActualOpaqueCredentialValue123456"}}`,
			want: `path $["client_secret"]["description"]: credential or secret material`,
		},
		{
			name: "credential hidden in sibling candidate value",
			raw:  `{"row_kind":"candidate_api_property_claim","property_name":"access_token","candidate_value":"ActualOpaqueCredentialValue123456"}`,
			want: `path $["candidate_value"]: credential or secret material`,
		},
		{
			name: "opaque credential disguised as schema reference",
			raw:  `{"row_kind":"auth_schema","property_name":"access_token","schema_ref":"abcdefghijklmnopqrstuvwx"}`,
			want: `path $["schema_ref"]: credential or secret material`,
		},
		{
			name: "credential query disguised as schema reference",
			raw:  `{"row_kind":"auth_schema","property_name":"access_token","schema_ref":"https://example.com/schema?api_key=live-A1b2C3d4E5f6G7h8"}`,
			want: `path $["schema_ref"]: credential or secret material`,
		},
		{
			name: "opaque credential in urn schema reference",
			raw:  `{"row_kind":"auth_schema","property_name":"access_token","schema_ref":"urn:velenza:schema:abcdefghijklmnopqrstuvwx:v1"}`,
			want: `path $["schema_ref"]: credential or secret material`,
		},
		{
			name: "opaque credential in https schema reference",
			raw:  `{"row_kind":"auth_schema","property_name":"access_token","schema_ref":"https://example.com/schema/abcdefghijklmnopqrstuvwx"}`,
			want: `path $["schema_ref"]: credential or secret material`,
		},
		{
			name: "opaque bytes appended to evidence descriptor",
			raw:  `{"row_kind":"manifest","provider_evidence_body":"exact source-declared machine-export bytes selected by an admitted representation declaration ActualOpaqueCredentialValue123456"}`,
			want: `path $["provider_evidence_body"]: embedded provider/document/source body payload`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateStructuredDependencySecurity(artifactInput{
				Path:       "dependency.jsonl",
				Raw:        []byte(test.raw),
				Structured: true,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestValidateStructuredDependencySecurityRejectsInvalidUTF8AtExactRow(t *testing.T) {
	raw := append([]byte("{\"row_kind\":\"manifest\"}\n{\"note\":\""), 0xff)
	raw = append(raw, []byte("\"}\n")...)
	err := validateStructuredDependencySecurity(artifactInput{Path: "dependency.jsonl", Raw: raw, Structured: true})
	if err == nil || !strings.Contains(err.Error(), `dependency.jsonl" row 2 contains invalid UTF-8`) {
		t.Fatalf("got %v, want exact invalid-UTF-8 row refusal", err)
	}
}

func TestValidateStructuredDependencySecurityAllowsSymbolicAndMetadataFacts(t *testing.T) {
	raw := strings.Join([]string{
		`{"row_kind":"artifact_manifest","auth_parameter":{"name":"AccessToken","type":"string","required":true}}`,
		`{"row_kind":"schema_fact","exact_numeric_lexemes":["1.25","-2.0e3","0007"]}`,
		`{"row_kind":"evidence_fact","source_body_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","source_body_byte_count":4096,"source_content_bytes":4096,"document_content_digest":"sha256:abc123","provider_payload_length":512,"raw_source_ref":"official-page-export"}`,
		`{"row_kind":"security_policy","binary_float_authority":false,"raw_source_value_embedding":{"allowed":false},"provider_payload_passthrough":false,"caller_supplied_organization_id":"forbidden"}`,
		`{"row_kind":"evidence_policy","provider_evidence_body":"exact source-declared machine-export bytes selected by an admitted representation declaration"}`,
		`{"row_kind":"auth_schema","access_token":{"type":"string","format":"opaque","name":"AccessToken"},"client_secret":"<connector-vault-reference>"}`,
	}, "\n") + "\n"

	if err := validateStructuredDependencySecurity(artifactInput{
		Path:       "dependency.jsonl",
		Raw:        []byte(raw),
		Structured: true,
	}); err != nil {
		t.Fatalf("symbolic documentation and metadata facts must pass: %v", err)
	}
}

func TestValidateStructuredDependencySecurityDoesNotTreatOrdinaryTokenFieldsAsSecrets(t *testing.T) {
	raw := strings.Join([]string{
		`{"row_kind":"candidate_api_property_claim","property_name":"SyncToken","candidate_value":"7"}`,
		`{"row_kind":"candidate_api_property_claim","property_name":"page_token","candidate_value":"next-page-2"}`,
		`{"row_kind":"candidate_api_property_claim","source_field":"continuation_token","candidate_value":"opaque-provider-cursor"}`,
		`{"row_kind":"schema_fact","SyncToken":"8","page_token":"next-page-3","continuation_token":"opaque-provider-cursor-2"}`,
	}, "\n") + "\n"
	if err := validateStructuredDependencySecurity(artifactInput{Path: "ordinary-token-fields.jsonl", Raw: []byte(raw), Structured: true}); err != nil {
		t.Fatalf("ordinary API token vocabulary was misclassified as credential material: %v", err)
	}
}

func TestCredentialShapedValuePrefiltersPreserveEveryCredentialCarrier(t *testing.T) {
	credential := "LiveCredential-A1b2C3d4E5f6"
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "authorization bearer", value: "AUTHORIZATION: BeArEr " + credential},
		{name: "authorization basic", value: "Authorization: BaSiC " + credential},
		{name: "access token", value: "AcCeSs-ToKeN=" + credential},
		{name: "refresh token", value: "ReFrEsH_ToKeN:" + credential},
		{name: "client secret", value: "ClIeNt SeCrEt=" + credential},
		{name: "api key", value: "ApI-KeY=" + credential},
		{name: "password", value: "PaSsWoRd=" + credential},
		{name: "bearer token", value: "BeArEr_ToKeN=" + credential},
		{name: "aws secret access key", value: "AwS-SeCrEt_AcCeSs KeY=" + credential},
		{name: "consumer secret", value: "CoNsUmEr-SeCrEt=" + credential},
		{name: "signing secret", value: "SiGnInG_SeCrEt=" + credential},
		{name: "webhook secret", value: "WeBhOoK SeCrEt=" + credential},
		{name: "verification token", value: "VeRiFiCaTiOn-ToKeN=" + credential},
		{name: "later credential after placeholder", value: "api_key=<API_KEY>; API KEY=" + credential},
		{name: "jwt", value: "prefix eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ suffix"},
		{name: "known token", value: "GhP_" + credential},
		{name: "akia token", value: "aKiA1234567890ABCDEF"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !credentialShapedValue(test.value) {
				t.Fatalf("credential carrier %q was missed", test.value)
			}
		})
	}
}

func TestKnownCredentialTokenAnywhereASCIIPathPreservesEveryPrefix(t *testing.T) {
	suffix := "LiveCredential-A1b2C3d4E5f6"
	for _, prefix := range []string{"ghp_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "sk-", "ya29."} {
		value := []byte("safe-prefix [" + strings.ToUpper(prefix) + suffix + "] safe-suffix")
		if !knownCredentialTokenAnywhere(value) {
			t.Fatalf("known token prefix %q was missed", prefix)
		}
	}
	if !knownCredentialTokenAnywhere([]byte("safe-prefix [aKiA1234567890ABCDEF] safe-suffix")) {
		t.Fatal("embedded AKIA token was missed")
	}
	for _, value := range [][]byte{
		[]byte("ordinary provider documentation with API token vocabulary"),
		[]byte("ghp_<GITHUB_TOKEN>"),
		[]byte("prefix sk-example suffix"),
	} {
		if knownCredentialTokenAnywhere(value) {
			t.Fatalf("safe value %q was misclassified", value)
		}
	}
}

func TestValidateStructuredDependencySecurityStillRejectsClosedTokenSecretCarriers(t *testing.T) {
	for _, raw := range []string{
		`{"row_kind":"fact","access_token":"ActualOpaqueCredentialValue123456"}`,
		`{"row_kind":"fact","property_name":"refresh_token","candidate_value":"ActualOpaqueCredentialValue123456"}`,
		`{"row_kind":"fact","api_token":"ActualOpaqueCredentialValue123456"}`,
	} {
		if err := validateStructuredDependencySecurity(artifactInput{Path: "token-secret-carrier.jsonl", Raw: []byte(raw), Structured: true}); err == nil || !strings.Contains(err.Error(), "credential or secret material") {
			t.Fatalf("closed token-secret carrier was accepted: %v", err)
		}
	}
}

func TestValidateStructuredDependencySecurityAllowsProvenIntegerByteCountPropertySchema(t *testing.T) {
	raw := `{"$schema":"https://json-schema.org/draft/2020-12/schema","oneOf":[{"type":"object","properties":{"total_exact_source_bytes":{"type":"integer","minimum":0}}}]}`
	if err := validateStructuredDependencySchemaSecurity(artifactInput{Path: "count-schema.json", Raw: []byte(raw), Structured: true}); err != nil {
		t.Fatalf("body-free integer count schema was rejected: %v", err)
	}
}

func TestValidateStructuredDependencySecurityAllowsBodyNamedJSONSchemaPropertyDeclarations(t *testing.T) {
	const dialect = `"$schema":"https://json-schema.org/draft/2020-12/schema"`
	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "boolean type declaration", raw: `{` + dialect + `,"oneOf":[{"type":"object"},{"properties":{"source_bytes_present":{"type":"boolean"}}}]}`},
		{name: "safe boolean const declaration", raw: `{` + dialect + `,"properties":{"source_bytes_present":{"const":false}}}`},
		{name: "string type declaration", raw: `{` + dialect + `,"properties":{"source_content_bytes":{"type":"string"}}}`},
		{name: "array type declaration", raw: `{` + dialect + `,"properties":{"source_content_bytes":{"type":"array","items":{"type":"integer"}}}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStructuredDependencySchemaSecurity(artifactInput{Path: "body-named-schema.json", Raw: []byte(test.raw), Structured: true}); err != nil {
				t.Fatalf("body-free JSON Schema property declaration was rejected: %v", err)
			}
		})
	}
}

func TestValidateStructuredDependencySecurityRejectsSchemaShapedInstanceWithoutDialectAuthority(t *testing.T) {
	raw := `{"properties":{"source_content_bytes":{"type":"string"}}}`
	err := validateStructuredDependencySchemaSecurity(artifactInput{Path: "schema-shaped-instance.json", Raw: []byte(raw), Structured: true})
	if err == nil || !strings.Contains(err.Error(), "embedded provider/document/source body payload") {
		t.Fatalf("error = %v, want no-marker schema masquerade refusal", err)
	}
}

func TestValidateStructuredDependencySecurityDistinguishesSchemaDeclarationsFromPolicyFacts(t *testing.T) {
	const dialect = `"$schema":"https://json-schema.org/draft/2020-12/schema"`
	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "kernel scope property declaration", raw: `{` + dialect + `,"type":"object","properties":{"caller_supplied_organization_id":{"type":"string"}}}`},
		{name: "binary float policy type declaration", raw: `{` + dialect + `,"type":"object","properties":{"binary_float_authoritative":{"type":"boolean"}}}`},
		{name: "raw passthrough policy type declaration", raw: `{` + dialect + `,"type":"object","properties":{"raw_provider_value_passthrough":{"type":"boolean"}}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStructuredDependencySchemaSecurity(artifactInput{Path: "semantic.schema.json", Raw: []byte(test.raw), Structured: true}); err != nil {
				t.Fatalf("exact JSON Schema declaration was rejected as an instance fact: %v", err)
			}
		})
	}
}

func TestValidateStructuredDependencySecuritySchemaContextDoesNotLaunderUnsafeValues(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "schema marker with instance-shaped organization value",
			raw:  `{"$schema":"https://json-schema.org/draft/2020-12/schema","properties":{"caller_supplied_organization_id":"tenant-a"}}`,
			want: "organization scope key",
		},
		{
			name: "binary float const true",
			raw:  `{"$schema":"https://json-schema.org/draft/2020-12/schema","properties":{"binary_float_authoritative":{"type":"boolean","const":true}}}`,
			want: "binary-float authority",
		},
		{
			name: "raw passthrough default true",
			raw:  `{"$schema":"https://json-schema.org/draft/2020-12/schema","properties":{"raw_provider_value_passthrough":{"type":"boolean","default":true}}}`,
			want: "passthrough",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateStructuredDependencySchemaSecurity(artifactInput{Path: "unsafe.schema.json", Raw: []byte(test.raw), Structured: true})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q refusal", err, test.want)
			}
		})
	}
}

func TestStageSchemaSyntaxRequiresExactSchemaCoordinateAuthority(t *testing.T) {
	coordinate := stageMaterialCoordinate{Role: "semantic_profile_schema", ID: "urn:fixture:semantic-profile-schema", Version: "1"}
	material := StageMaterial{
		Role: coordinate.Role, ID: coordinate.ID, Version: coordinate.Version,
		Raw: []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"caller_supplied_organization_id":{"type":"string"},"binary_float_authoritative":{"type":"boolean"}}}`),
	}
	materials := map[stageMaterialCoordinate]StageMaterial{coordinate: material}

	if err := scanExactStageMaterialSecurity(materials, nil); err == nil {
		t.Fatal("unbound schema-shaped stage material was accepted")
	}
	wrong := stageMaterialCoordinate{Role: coordinate.Role, ID: coordinate.ID + "-other", Version: coordinate.Version}
	if err := scanExactStageMaterialSecurity(materials, map[stageMaterialCoordinate]struct{}{wrong: {}}); err == nil {
		t.Fatal("wrong-coordinate schema authority was accepted")
	}
	if err := scanExactStageMaterialSecurity(materials, map[stageMaterialCoordinate]struct{}{coordinate: {}}); err != nil {
		t.Fatalf("exact schema-coordinate authority was rejected: %v", err)
	}
}

func TestStageOrganizationScopeVocabularyRequiresExactAuthorityCoordinate(t *testing.T) {
	coordinate := stageMaterialCoordinate{Role: "ood_graph", ID: "fixture_ood_graph", Version: "1"}
	material := StageMaterial{
		Role: coordinate.Role, ID: coordinate.ID, Version: coordinate.Version,
		Raw: []byte(`{"row_kind":"tenant_scope_contract","organization_id":"kernel_injected_request_context"}`),
	}
	materials := map[stageMaterialCoordinate]StageMaterial{coordinate: material}

	if err := scanExactStageMaterialSecurity(materials, nil); err == nil {
		t.Fatal("derived stage material carrying organization scope was accepted")
	}
	wrong := stageMaterialCoordinate{Role: coordinate.Role, ID: coordinate.ID + "_other", Version: coordinate.Version}
	if err := scanExactStageMaterialSecurityWithAuthorities(materials, nil, map[stageMaterialCoordinate]string{wrong: sha256Hex(material.Raw)}); err == nil {
		t.Fatal("wrong-coordinate organization-scope authority was accepted")
	}
	if err := scanExactStageMaterialSecurityWithAuthorities(materials, nil, map[stageMaterialCoordinate]string{coordinate: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("wrong-digest organization-scope authority was accepted")
	}
	if err := scanExactStageMaterialSecurityWithAuthorities(materials, nil, map[stageMaterialCoordinate]string{coordinate: sha256Hex(material.Raw)}); err != nil {
		t.Fatalf("exact organization-scope authority coordinate was rejected: %v", err)
	}

	material.Raw = []byte(`{"row_kind":"tenant_scope_contract","organization_id":"kernel_injected_request_context","client_secret":"actual-secret-material"}`)
	materials[coordinate] = material
	if err := scanExactStageMaterialSecurityWithAuthorities(materials, nil, map[stageMaterialCoordinate]string{coordinate: sha256Hex(material.Raw)}); err == nil {
		t.Fatal("exact authority coordinate laundered credential material")
	}
}

func TestStructuredDescriptiveAuthorityRetainsEveryNonScopeSecurityGate(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "credential", raw: `{"organization_id":"kernel_injected_request_context","client_secret":"actual-secret-material"}`},
		{name: "provider body", raw: `{"organization_id":"kernel_injected_request_context","provider_payload":"embedded body"}`},
		{name: "binary float authority", raw: `{"organization_id":"kernel_injected_request_context","binary_float_authoritative":true}`},
		{name: "raw passthrough", raw: `{"organization_id":"kernel_injected_request_context","raw_provider_value_passthrough":true}`},
		{name: "duplicate key", raw: `{"organization_id":"first","organization_id":"second"}`},
		{name: "noninteger number", raw: `{"organization_id":"kernel_injected_request_context","value":1.5}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStructuredAuthoritySecurity(artifactInput{Path: "authority.json", Raw: []byte(test.raw), Structured: true}); err == nil {
				t.Fatal("descriptive authority mode accepted a non-scope security violation")
			}
		})
	}
}

func TestValidateStructuredDependencySecurityRejectsIntegerSchemaByteRosterExamples(t *testing.T) {
	raw := `{"type":"object","properties":{"source_content_bytes":{"type":"integer","examples":[97,112,105,95,107,101,121,61,108,105,118,101,45,65,49,98,50,67,51,100,52,69,53,102,54,71,55,104,56]}}}`
	if err := validateStructuredDependencySchemaSecurity(artifactInput{Path: "integer-byte-roster-schema.json", Raw: []byte(raw), Structured: true}); err == nil {
		t.Fatal("integer-schema examples reconstructed into credential bytes were accepted")
	}
}

func TestValidateStructuredDependencySecurityRejectsIntegerSchemaBigIntegerCarrier(t *testing.T) {
	encoded := new(big.Int).SetBytes([]byte("api_key=live-A1b2C3d4E5f6G7h8I9j0")).String()
	raw := fmt.Sprintf(`{"type":"object","properties":{"source_content_bytes":{"type":"integer","const":%s}}}`, encoded)
	if err := validateStructuredDependencySchemaSecurity(artifactInput{Path: "integer-bigint-schema.json", Raw: []byte(raw), Structured: true}); err == nil {
		t.Fatal("integer-schema const carrying credential bytes was accepted")
	}
}

func TestValidateStructuredDependencySecurityRejectsRawPropertySchemaPayloadCarriers(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "integer schema with unproven default", raw: `{"type":"object","properties":{"source_content_bytes":{"type":"integer","default":"embedded-body"}}}`},
		{name: "string const payload", raw: `{"properties":{"source_content_bytes":{"type":"string","const":"exact-evidence-body"}}}`},
		{name: "nonempty enum payload", raw: `{"properties":{"source_content_bytes":{"type":"string","enum":["exact-evidence-body"]}}}`},
		{name: "nonempty examples payload", raw: `{"properties":{"source_content_bytes":{"type":"array","examples":[[97,112,105,95,107,101,121]]}}}`},
		{name: "not a schema declaration", raw: `{"properties":{"source_content_bytes":{"payload":"embedded-body"}}}`},
		{name: "actual scalar payload", raw: `{"source_bytes_present":"embedded-body"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateStructuredDependencySchemaSecurity(artifactInput{Path: "unsafe-schema.json", Raw: []byte(test.raw), Structured: true})
			if err == nil || !strings.Contains(err.Error(), "embedded provider/document/source body payload") {
				t.Fatalf("error = %v, want raw-body refusal", err)
			}
		})
	}
}
