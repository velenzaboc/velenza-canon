package providerplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
)

const exactDocumentationSemanticGenerationKind = "exact_documentation_semantic_generation_v1"

// documentationClaimSchemaAuthority is the resolved, exact-byte authority for
// one documentation-derived claim kind. The schema coordinate is not a label:
// its digest binds the exact canonical JSON Schema bytes evaluated below.
type documentationClaimSchemaAuthority struct {
	reference            dependencyProfileReference
	claimKind            string
	canonicalSchemaBytes []byte
	resolved             *jsonschema.Resolved
}

type documentationSemanticGenerationIdentity struct {
	GenerationKind          string `json:"generation_kind"`
	ClaimKind               string `json:"claim_kind"`
	ProgramID               string `json:"program_id"`
	ProgramVersion          string `json:"program_version"`
	ProgramSHA256           string `json:"program_sha256"`
	ValidationSchemaID      string `json:"validation_schema_id"`
	ValidationSchemaVersion string `json:"validation_schema_version"`
	ValidationSchemaSHA256  string `json:"validation_schema_sha256"`
}

type documentationSemanticGenerationBinding struct {
	claimKind      string
	program        dependencyProfileReference
	claimSchema    documentationClaimSchemaAuthority
	identitySHA256 string
}

func resolveDocumentationClaimSchema(
	reference dependencyProfileReference,
	claimKind string,
	canonicalSchemaJSON string,
) (documentationClaimSchemaAuthority, error) {
	var authority documentationClaimSchemaAuthority
	if !isCanonicalValidationProfileIdentity(claimKind) {
		return authority, fmt.Errorf("claim_kind %q is noncanonical", claimKind)
	}
	if _, err := newValidationProfileCoordinate("validation_schema", reference.id, reference.version); err != nil {
		return authority, err
	}
	schemaBytes := []byte(canonicalSchemaJSON)
	if !isLowerSHA256(reference.digest) || sha256Hex(schemaBytes) != reference.digest {
		return authority, fmt.Errorf("validation schema digest does not equal its exact canonical_schema_json bytes")
	}
	if !utf8.Valid(schemaBytes) {
		return authority, fmt.Errorf("validation schema bytes are not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(schemaBytes); err != nil {
		return authority, fmt.Errorf("validation schema has duplicate JSON keys: %w", err)
	}
	canonical, err := canonicalizeCandidateJSON(schemaBytes)
	if err != nil {
		return authority, fmt.Errorf("canonicalize validation schema: %w", err)
	}
	if !bytes.Equal(canonical, schemaBytes) {
		return authority, fmt.Errorf("validation schema canonical_schema_json is not encoded as exact RFC-canonical JSON")
	}
	var rawObject map[string]interface{}
	if err := decodeOneValidationProfileJSON(schemaBytes, &rawObject); err != nil {
		return authority, fmt.Errorf("decode validation schema JSON object: %w", err)
	}
	dialect, ok := rawObject["$schema"].(string)
	if !ok || dialect != validationProfileDraft202012 {
		return authority, fmt.Errorf("validation schema $schema must equal %q", validationProfileDraft202012)
	}
	if id, ok := rawObject["$id"].(string); !ok || id != reference.id {
		return authority, fmt.Errorf("validation schema $id does not equal bound validation_schema_id %q", reference.id)
	}
	if err := validateValidationProfileSchemaNumbers(rawObject, "$"); err != nil {
		return authority, err
	}
	if err := validateValidationProfileClosedObjectShapes(rawObject); err != nil {
		return authority, err
	}
	var schema jsonschema.Schema
	if err := decodeOneValidationProfileJSON(schemaBytes, &schema); err != nil {
		return authority, fmt.Errorf("decode validation JSON Schema: %w", err)
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{
		Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
			return nil, fmt.Errorf("external documentation claim-schema reference %q is forbidden", uri.String())
		},
	})
	if err != nil {
		return authority, fmt.Errorf("resolve draft 2020-12 validation schema without external references: %w", err)
	}
	return documentationClaimSchemaAuthority{
		reference: reference, claimKind: claimKind,
		canonicalSchemaBytes: bytes.Clone(schemaBytes), resolved: resolved,
	}, nil
}

func newDocumentationSemanticGenerationBinding(
	claimKind string,
	program dependencyProfileReference,
	claimSchema documentationClaimSchemaAuthority,
) (documentationSemanticGenerationBinding, error) {
	var binding documentationSemanticGenerationBinding
	if _, err := newValidationProfileCoordinate("derivation_profile", program.id, program.version); err != nil {
		return binding, err
	}
	if claimKind == "" || claimKind != claimSchema.claimKind || claimSchema.resolved == nil ||
		!isLowerSHA256(program.digest) || !isLowerSHA256(claimSchema.reference.digest) ||
		sha256Hex(claimSchema.canonicalSchemaBytes) != claimSchema.reference.digest {
		return binding, fmt.Errorf("documentation semantic generation does not close one exact claim, program, and validation-schema binding")
	}
	identity := documentationSemanticGenerationIdentity{
		GenerationKind: exactDocumentationSemanticGenerationKind,
		ClaimKind:      claimKind,
		ProgramID:      program.id, ProgramVersion: program.version, ProgramSHA256: program.digest,
		ValidationSchemaID:      claimSchema.reference.id,
		ValidationSchemaVersion: claimSchema.reference.version,
		ValidationSchemaSHA256:  claimSchema.reference.digest,
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		return binding, err
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		return binding, err
	}
	return documentationSemanticGenerationBinding{
		claimKind: claimKind, program: program, claimSchema: claimSchema,
		identitySHA256: sha256Hex(canonical),
	}, nil
}

func validateDocumentationSemanticGenerationBinding(binding documentationSemanticGenerationBinding) error {
	recomputed, err := newDocumentationSemanticGenerationBinding(binding.claimKind, binding.program, binding.claimSchema)
	if err != nil {
		return err
	}
	if !isLowerSHA256(binding.identitySHA256) || binding.identitySHA256 != recomputed.identitySHA256 {
		return fmt.Errorf("documentation semantic generation differs from its exact content-derived identity")
	}
	return nil
}

func validateDocumentationClaimOutput(authority documentationClaimSchemaAuthority, canonicalOutput []byte) error {
	if authority.resolved == nil || !isLowerSHA256(authority.reference.digest) ||
		sha256Hex(authority.canonicalSchemaBytes) != authority.reference.digest {
		return fmt.Errorf("documentation claim output has no exact resolved validation-schema authority")
	}
	canonical, err := canonicalizeCandidateJSON(canonicalOutput)
	if err != nil {
		return fmt.Errorf("canonicalize documentation claim output: %w", err)
	}
	if !bytes.Equal(canonical, canonicalOutput) {
		return fmt.Errorf("documentation claim output is not encoded as exact RFC-canonical JSON")
	}
	var instance interface{}
	if err := decodeOneValidationProfileJSON(canonicalOutput, &instance); err != nil {
		return fmt.Errorf("decode documentation claim output: %w", err)
	}
	instance, err = normalizeValidationProfileNumbers(instance, "documentation claim output")
	if err != nil {
		return err
	}
	if _, ok := instance.(map[string]interface{}); !ok {
		return fmt.Errorf("documentation claim output is not an object")
	}
	if err := authority.resolved.Validate(instance); err != nil {
		return fmt.Errorf("documentation claim output fails exact validation schema %q version %q: %w", authority.reference.id, authority.reference.version, err)
	}
	return nil
}
