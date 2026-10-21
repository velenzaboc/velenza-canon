package providerplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	stageEvidenceStateBoundError          = errors.New("analysis exceeded the deterministic state bound")
	stageEvidenceAggregateStateBoundError = errors.New("analysis exceeded the deterministic aggregate state bound")
)

// PublicStageCompileDiagnostic projects a validation error onto the command's
// fixed, content-neutral diagnostic vocabulary. Deterministic state exhaustion
// is safe to distinguish because the classification carries no caller path,
// digest, coordinate, source bytes, or wrapped error detail.
func PublicStageCompileDiagnostic(err error) string {
	if errors.Is(err, stageEvidenceStateBoundError) || errors.Is(err, stageEvidenceAggregateStateBoundError) {
		return "stage validation failed: analysis exceeded the deterministic state bound"
	}
	return "stage validation failed"
}

const (
	stageRequestKind     = "provider_documentation_factory_stage_request"
	stageReceiptKind     = "provider_documentation_factory_validated_stage_commitment"
	stageContractVersion = "1"
	// This value is a receipt-visible validation identity, not a descriptive
	// comment. Full scalar and exact distinct-occurrence fragments remain eligible
	// at every non-empty length. Only arbitrary substrings embedded inside a
	// larger scalar use the explicit three-target-byte minimum: treating one- and
	// two-byte alphabet coincidences as copied content makes every sufficiently
	// rich, body-free base64/hex metadata corpus synthesize an unrelated body.
	stageValidationScope = "exact_bytes_bound_schemas_body_free_lineage_full_scalar_any_length_wrapped_substring_min_3_target_bytes_v2"

	stageEvidenceIntake     = "evidence_intake"
	stageSemanticExtraction = "semantic_extraction"
	stageGraphCompile       = "graph_compile"
	stageFullFactory        = "full_factory"

	maxExactStageCount         = uint64(1<<53 - 1)
	stageValidationProfileKind = "provider_documentation_stage_validation_profile"
)

var (
	stageIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	stageVersionPattern    = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	stageCoordinatePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9:._/-]{0,255}$`)
)

// StageReceiptReference is the complete, body-free identity needed to bind a
// predecessor stage. ReceiptSHA256 commits to the predecessor receipt's
// canonical closed JSON; OutputRootSHA256 commits to its stage output.
type StageReceiptReference struct {
	StageKind        string `json:"stage_kind"`
	ReceiptSHA256    string `json:"receipt_sha256"`
	OutputRootSHA256 string `json:"output_root_sha256"`
}

// StageReceiptSummary exposes only the source-neutral receipt identity and
// lineage needed by a caller. It carries no provider body, credential, tenant,
// authority-selection, or admission state.
type StageReceiptSummary struct {
	StageKind           string
	ReceiptSHA256       string
	OutputRootSHA256    string
	Predecessors        []StageReceiptReference
	EvidenceCommitments []StageEvidenceCommitment
}

type stageRequestHeader struct {
	RequestKind    string `json:"request_kind"`
	RequestVersion string `json:"request_version"`
	StageKind      string `json:"stage_kind"`
}

type stageAuthorityPins struct {
	OODGraph          immutableStageArtifactPin `json:"ood_graph"`
	GrandVision       immutableStageArtifactPin `json:"grand_vision"`
	SourceRecord      immutableStageArtifactPin `json:"source_record"`
	ExtensionProtocol immutableStageArtifactPin `json:"extension_protocol"`
}

type evidenceManifestStageBinding struct {
	Role              string `json:"role"`
	ArtifactID        string `json:"artifact_id"`
	ArtifactVersion   string `json:"artifact_version"`
	ArtifactRawSHA256 string `json:"artifact_raw_sha256"`
	BodyCount         uint64 `json:"body_count"`
	ByteCount         uint64 `json:"byte_count"`
}

type evidenceIntakeStageRequest struct {
	RequestKind       string                         `json:"request_kind"`
	RequestVersion    string                         `json:"request_version"`
	StageKind         string                         `json:"stage_kind"`
	StageValidation   stageValidationBinding         `json:"stage_validation"`
	AuthorityPins     stageAuthorityPins             `json:"authority_pins"`
	SelectionRoster   stageArtifactIdentity          `json:"selection_roster"`
	EvidenceManifests []evidenceManifestStageBinding `json:"evidence_manifests"`
}

type evidenceIntakeStageBinding struct {
	StageValidation   stageValidationBinding         `json:"stage_validation"`
	AuthorityPins     stageAuthorityPins             `json:"authority_pins"`
	SelectionRoster   stageArtifactIdentity          `json:"selection_roster"`
	EvidenceManifests []evidenceManifestStageBinding `json:"evidence_manifests"`
}

type immutableStageArtifactPin struct {
	Role           string `json:"role"`
	ID             string `json:"id"`
	Version        string `json:"version"`
	RawSHA256      string `json:"raw_sha256"`
	AuthorityClass string `json:"expected_authority_class"`
}

type stageValidationBinding struct {
	Schema  immutableStageArtifactPin `json:"schema"`
	Profile immutableStageArtifactPin `json:"profile"`
}

type semanticArtifactRole struct {
	Role        string `json:"role"`
	Disposition string `json:"disposition"`
}

type semanticArtifactOutput struct {
	Role                 string   `json:"role"`
	ArtifactID           string   `json:"artifact_id"`
	ArtifactVersion      string   `json:"artifact_version"`
	ArtifactRawSHA256    string   `json:"artifact_raw_sha256"`
	DerivationBindingIDs []string `json:"derivation_binding_ids"`
}

type semanticDerivationBinding struct {
	BindingID string                    `json:"binding_id"`
	Extractor immutableStageArtifactPin `json:"extractor"`
	Schema    immutableStageArtifactPin `json:"schema"`
}

type semanticExtractionStageRequest struct {
	RequestKind          string                      `json:"request_kind"`
	RequestVersion       string                      `json:"request_version"`
	StageKind            string                      `json:"stage_kind"`
	IntakeReceipt        StageReceiptReference       `json:"intake_receipt"`
	StageValidation      stageValidationBinding      `json:"stage_validation"`
	ApplicabilityProfile immutableStageArtifactPin   `json:"applicability_profile"`
	ArtifactRoleRoster   []semanticArtifactRole      `json:"artifact_role_roster"`
	ArtifactOutputs      []semanticArtifactOutput    `json:"artifact_outputs"`
	DerivationBindings   []semanticDerivationBinding `json:"derivation_bindings"`
}

type semanticExtractionStageBinding struct {
	StageValidation      stageValidationBinding      `json:"stage_validation"`
	ApplicabilityProfile immutableStageArtifactPin   `json:"applicability_profile"`
	ArtifactRoleRoster   []semanticArtifactRole      `json:"artifact_role_roster"`
	ArtifactOutputs      []semanticArtifactOutput    `json:"artifact_outputs"`
	DerivationBindings   []semanticDerivationBinding `json:"derivation_bindings"`
}

type compactStageSet struct {
	RootSHA256 string `json:"root_sha256"`
	Count      uint64 `json:"count"`
}

type graphCompileStageRequest struct {
	RequestKind         string                  `json:"request_kind"`
	RequestVersion      string                  `json:"request_version"`
	StageKind           string                  `json:"stage_kind"`
	ExtractionReceipts  []StageReceiptReference `json:"extraction_receipts"`
	StageValidation     stageValidationBinding  `json:"stage_validation"`
	DependencyArtifacts []stageArtifactIdentity `json:"dependency_artifacts"`
	Plan                stageArtifactIdentity   `json:"plan"`
	Subjects            compactStageSet         `json:"subjects"`
	Facts               compactStageSet         `json:"facts"`
	Gaps                compactStageSet         `json:"gaps"`
}

type graphCompileStageBinding struct {
	StageValidation     stageValidationBinding  `json:"stage_validation"`
	DependencyArtifacts []stageArtifactIdentity `json:"dependency_artifacts"`
	Plan                stageArtifactIdentity   `json:"plan"`
	Subjects            compactStageSet         `json:"subjects"`
	Facts               compactStageSet         `json:"facts"`
	Gaps                compactStageSet         `json:"gaps"`
}

type fullFactoryStageRequest struct {
	RequestKind     string                  `json:"request_kind"`
	RequestVersion  string                  `json:"request_version"`
	StageKind       string                  `json:"stage_kind"`
	StageValidation stageValidationBinding  `json:"stage_validation"`
	PriorReceipts   []StageReceiptReference `json:"prior_receipts"`
}

type fullFactoryStageBinding struct {
	StageValidation stageValidationBinding `json:"stage_validation"`
}

type stageArtifactIdentity struct {
	Role      string `json:"role"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	RawSHA256 string `json:"raw_sha256"`
}

// StageEvidenceCommitment is the immutable, body-free identity of one exact
// selected documentation body. The roster is derived from the intake body's
// exact bytes and inherited without alteration by every later stage.
type StageEvidenceCommitment struct {
	ManifestRole     string `json:"manifest_role"`
	ManifestID       string `json:"manifest_id"`
	ManifestVersion  string `json:"manifest_version"`
	ComponentOrdinal uint64 `json:"component_ordinal"`
	BodySHA256       string `json:"body_sha256"`
	ByteCount        uint64 `json:"byte_count"`
}

type stageReceipt struct {
	ReceiptKind         string                    `json:"receipt_kind"`
	ReceiptVersion      string                    `json:"receipt_version"`
	StageKind           string                    `json:"stage_kind"`
	RequestSHA256       string                    `json:"request_sha256"`
	Predecessors        []StageReceiptReference   `json:"predecessors"`
	EvidenceCommitments []StageEvidenceCommitment `json:"evidence_commitments"`
	Binding             json.RawMessage           `json:"binding"`
	OutputRootSHA256    string                    `json:"output_root_sha256"`
	ValidationScope     string                    `json:"validation_scope"`
	BodyFree            bool                      `json:"body_free"`
	DerivationExecuted  bool                      `json:"derivation_executed"`
	AuthoritySelected   bool                      `json:"authority_selected"`
	AdmissionAuthorized bool                      `json:"admission_authorized"`
	FactoryComplete     bool                      `json:"factory_complete"`
	ReceiptSHA256       string                    `json:"receipt_sha256"`
}

type stageReceiptIdentity struct {
	ReceiptKind         string                    `json:"receipt_kind"`
	ReceiptVersion      string                    `json:"receipt_version"`
	StageKind           string                    `json:"stage_kind"`
	RequestSHA256       string                    `json:"request_sha256"`
	Predecessors        []StageReceiptReference   `json:"predecessors"`
	EvidenceCommitments []StageEvidenceCommitment `json:"evidence_commitments"`
	Binding             json.RawMessage           `json:"binding"`
	OutputRootSHA256    string                    `json:"output_root_sha256"`
	ValidationScope     string                    `json:"validation_scope"`
	BodyFree            bool                      `json:"body_free"`
	DerivationExecuted  bool                      `json:"derivation_executed"`
	AuthoritySelected   bool                      `json:"authority_selected"`
	AdmissionAuthorized bool                      `json:"admission_authorized"`
	FactoryComplete     bool                      `json:"factory_complete"`
}

type stageOutputCommitment struct {
	StageKind           string                    `json:"stage_kind"`
	Predecessors        []StageReceiptReference   `json:"predecessors"`
	EvidenceCommitments []StageEvidenceCommitment `json:"evidence_commitments"`
	Binding             json.RawMessage           `json:"binding"`
}

type parsedStageReceipt struct {
	Receipt stageReceipt
	Summary StageReceiptSummary
}

// StageMaterial supplies exact bytes for one role/id/version coordinate. Every
// material must be named by the request or by its exact validation profile;
// unbound extras and digest aliases fail closed.
type StageMaterial struct {
	Role    string
	ID      string
	Version string
	Raw     []byte
}

// StageEvidenceBody supplies one exact selected documentation body for one
// evidence-manifest component ordinal. Intake derives its digest and byte count
// from Raw; every later stage must resupply the same exact roster and bytes.
// Raw is transient evidence-plane plaintext and may contain credential-shaped
// provider documentation examples. It is never serialized into a receipt or
// derived artifact; durable custody belongs to the separately authorized,
// encrypted, per-occurrence deletion and crypto-shred archive domain.
type StageEvidenceBody struct {
	ManifestRole     string
	ManifestID       string
	ManifestVersion  string
	ComponentOrdinal uint64
	Raw              []byte
}

// StageCompileInputs is the complete exact-byte input to one stage. A receipt
// is never emitted from digest assertions alone, and no downstream stage may
// rely on a predecessor's evidence digest without rehydrating the exact bodies.
type StageCompileInputs struct {
	PredecessorReceipts [][]byte
	Materials           []StageMaterial
	EvidenceBodies      []StageEvidenceBody
}

type stageMaterialCoordinate struct {
	Role    string
	ID      string
	Version string
}

type stageExpectedMaterial struct {
	coordinate stageMaterialCoordinate
	digest     string
}

type stageEvidenceValidation struct {
	bodies             map[string]exactEvidenceBody
	commitments        []StageEvidenceCommitment
	graphStructural    *graphPlanSchemaBindingProof
	materialProvenance map[stageMaterialCoordinate]map[stageBodyFreePointerCoordinate]string
}

type stageValidationProfileDocument struct {
	RowKind              string                                  `json:"row_kind"`
	ProfileVersion       string                                  `json:"profile_version"`
	StageKind            string                                  `json:"stage_kind"`
	ProfileID            string                                  `json:"profile_id"`
	BoundArtifactSchemas []stageValidationProfileArtifactBinding `json:"bound_artifact_schemas"`
	GraphRowDispositions []stageGraphRowDisposition              `json:"graph_row_dispositions"`
}

type stageValidationProfileArtifactBinding struct {
	Role              string `json:"role"`
	ArtifactID        string `json:"artifact_id"`
	ArtifactVersion   string `json:"artifact_version"`
	ArtifactRawSHA256 string `json:"artifact_raw_sha256"`
	SchemaRole        string `json:"schema_role"`
	SchemaID          string `json:"schema_id"`
	SchemaVersion     string `json:"schema_version"`
	SchemaRawSHA256   string `json:"schema_raw_sha256"`
}

type stageGraphRowDisposition struct {
	RowKind  string   `json:"row_kind"`
	SetKinds []string `json:"set_kinds"`
}

func scanStageStructuredMetadata(label string, raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("%s contains invalid UTF-8", label)
	}
	return validateStructuredDependencySecurity(artifactInput{Path: label, Raw: raw, Structured: true})
}

func validateStageBodyFreeInputs(stageKind string, requestRaw, bindingRaw []byte, inputs StageCompileInputs, bodies map[string]exactEvidenceBody, materialProvenance map[stageMaterialCoordinate]map[stageBodyFreePointerCoordinate]string) error {
	materialDigests := make(map[stageMaterialCoordinate]string, len(inputs.Materials))
	for _, material := range inputs.Materials {
		materialDigests[stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}] = sha256Hex(material.Raw)
	}
	receiptReferences := make(map[StageReceiptReference]struct{}, len(inputs.PredecessorReceipts))
	parsedReceipts := make([]parsedStageReceipt, len(inputs.PredecessorReceipts))
	for index, raw := range inputs.PredecessorReceipts {
		parsed, err := parseStageReceipt(raw)
		if err != nil {
			return fmt.Errorf("%s predecessor receipt %d body-free provenance: %w", stageKind, index, err)
		}
		parsedReceipts[index] = parsed
		receiptReferences[StageReceiptReference{
			StageKind:        parsed.Summary.StageKind,
			ReceiptSHA256:    parsed.Summary.ReceiptSHA256,
			OutputRootSHA256: parsed.Summary.OutputRootSHA256,
		}] = struct{}{}
	}
	bindingItem := stageBodyFreeItem{
		label: stageKind + " stage binding", raw: bindingRaw, structured: true,
		provenContentIdentities: stageBodyFreeBindingPointerProofs(stageKind, bindingRaw, materialDigests),
	}
	if err := validateStageBodyFreeClosure(stageKind+" binding", []stageBodyFreeItem{bindingItem}, bodies); err != nil {
		return err
	}
	closureItems := []stageBodyFreeItem{{
		label: stageKind + " stage request", raw: requestRaw, structured: true,
		provenContentIdentities: stageBodyFreeRequestPointerProofs(stageKind, requestRaw, materialDigests, receiptReferences),
	}}
	for index, raw := range inputs.PredecessorReceipts {
		proofs := stageBodyFreeReceiptPointerProofs(parsedReceipts[index], receiptReferences, bodies)
		closureItems = append(closureItems, stageBodyFreeItem{
			label: fmt.Sprintf("%s predecessor receipt %d", stageKind, index), raw: raw, structured: true,
			provenContentIdentities: proofs,
		})
	}

	ordered := append([]StageMaterial(nil), inputs.Materials...)
	sort.Slice(ordered, func(i, j int) bool {
		left := lengthPrefixedIdentityKey(ordered[i].Role, ordered[i].ID, ordered[i].Version)
		right := lengthPrefixedIdentityKey(ordered[j].Role, ordered[j].ID, ordered[j].Version)
		return left < right
	})
	for _, material := range ordered {
		label := fmt.Sprintf("%s exact material %s/%s/%s", stageKind, material.Role, material.ID, material.Version)
		coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
		closureItems = append(closureItems, stageBodyFreeItem{
			label: label, raw: material.Raw, structured: stageBytesAreJSONOrJSONL(material.Raw),
			provenContentIdentities: materialProvenance[coordinate],
		})
	}
	if err := validateStageBodyFreeClosure(stageKind+" complete request-lineage-material closure", closureItems, bodies); err != nil {
		return err
	}
	return nil
}

type stageBodyFreeItem struct {
	label                   string
	raw                     []byte
	structured              bool
	provenContentIdentities map[stageBodyFreePointerCoordinate]string
}

type stageBodyFreePointerCoordinate struct {
	row     int
	pointer string
}

func (item stageBodyFreeItem) provenance(row int, pointer string, value []byte) bool {
	expected, proven := item.provenContentIdentities[stageBodyFreePointerCoordinate{row: row, pointer: pointer}]
	return proven && bytes.Equal(value, []byte(expected))
}

// These proof builders enumerate pointers from the exact typed/closed values
// whose validation has already succeeded. They never rediscover trust from raw
// object shape. Consequently an allowed extension object can copy every field
// of a real pin/reference/commitment and still remains open to wrapped-fragment
// synthesis because its pointer was not emitted by the typed validation path.
func stageBodyFreeRequestPointerProofs(stageKind string, raw []byte, materials map[stageMaterialCoordinate]string, receipts map[StageReceiptReference]struct{}) map[stageBodyFreePointerCoordinate]string {
	proofs := map[stageBodyFreePointerCoordinate]string{}
	switch stageKind {
	case stageEvidenceIntake:
		var request evidenceIntakeStageRequest
		if json.Unmarshal(raw, &request) != nil {
			return proofs
		}
		stageBodyFreeProveValidationBinding(proofs, "/stage_validation", request.StageValidation, materials)
		stageBodyFreeProvePin(proofs, "/authority_pins/ood_graph", request.AuthorityPins.OODGraph, materials)
		stageBodyFreeProvePin(proofs, "/authority_pins/grand_vision", request.AuthorityPins.GrandVision, materials)
		stageBodyFreeProvePin(proofs, "/authority_pins/source_record", request.AuthorityPins.SourceRecord, materials)
		stageBodyFreeProvePin(proofs, "/authority_pins/extension_protocol", request.AuthorityPins.ExtensionProtocol, materials)
		stageBodyFreeProveIdentity(proofs, "/selection_roster", "raw_sha256", request.SelectionRoster, materials)
		for index, manifest := range request.EvidenceManifests {
			stageBodyFreeProveIdentity(proofs, fmt.Sprintf("/evidence_manifests/%d", index), "artifact_raw_sha256", stageArtifactIdentity{Role: manifest.Role, ID: manifest.ArtifactID, Version: manifest.ArtifactVersion, RawSHA256: manifest.ArtifactRawSHA256}, materials)
		}
	case stageSemanticExtraction:
		var request semanticExtractionStageRequest
		if json.Unmarshal(raw, &request) != nil {
			return proofs
		}
		stageBodyFreeProveReceipt(proofs, "/intake_receipt", request.IntakeReceipt, receipts)
		stageBodyFreeProveValidationBinding(proofs, "/stage_validation", request.StageValidation, materials)
		stageBodyFreeProvePin(proofs, "/applicability_profile", request.ApplicabilityProfile, materials)
		for index, output := range request.ArtifactOutputs {
			stageBodyFreeProveIdentity(proofs, fmt.Sprintf("/artifact_outputs/%d", index), "artifact_raw_sha256", stageArtifactIdentity{Role: output.Role, ID: output.ArtifactID, Version: output.ArtifactVersion, RawSHA256: output.ArtifactRawSHA256}, materials)
		}
		for index, binding := range request.DerivationBindings {
			base := fmt.Sprintf("/derivation_bindings/%d", index)
			stageBodyFreeProvePin(proofs, base+"/extractor", binding.Extractor, materials)
			stageBodyFreeProvePin(proofs, base+"/schema", binding.Schema, materials)
		}
	case stageGraphCompile:
		var request graphCompileStageRequest
		if json.Unmarshal(raw, &request) != nil {
			return proofs
		}
		for index, receipt := range request.ExtractionReceipts {
			stageBodyFreeProveReceipt(proofs, fmt.Sprintf("/extraction_receipts/%d", index), receipt, receipts)
		}
		stageBodyFreeProveValidationBinding(proofs, "/stage_validation", request.StageValidation, materials)
		for index, identity := range request.DependencyArtifacts {
			stageBodyFreeProveIdentity(proofs, fmt.Sprintf("/dependency_artifacts/%d", index), "raw_sha256", identity, materials)
		}
		stageBodyFreeProveIdentity(proofs, "/plan", "raw_sha256", request.Plan, materials)
	case stageFullFactory:
		var request fullFactoryStageRequest
		if json.Unmarshal(raw, &request) != nil {
			return proofs
		}
		stageBodyFreeProveValidationBinding(proofs, "/stage_validation", request.StageValidation, materials)
		for index, receipt := range request.PriorReceipts {
			stageBodyFreeProveReceipt(proofs, fmt.Sprintf("/prior_receipts/%d", index), receipt, receipts)
		}
	}
	return proofs
}

func stageBodyFreeBindingPointerProofs(stageKind string, raw []byte, materials map[stageMaterialCoordinate]string) map[stageBodyFreePointerCoordinate]string {
	proofs := map[stageBodyFreePointerCoordinate]string{}
	switch stageKind {
	case stageEvidenceIntake:
		var binding evidenceIntakeStageBinding
		if json.Unmarshal(raw, &binding) != nil {
			return proofs
		}
		stageBodyFreeProveValidationBinding(proofs, "/stage_validation", binding.StageValidation, materials)
		stageBodyFreeProvePin(proofs, "/authority_pins/ood_graph", binding.AuthorityPins.OODGraph, materials)
		stageBodyFreeProvePin(proofs, "/authority_pins/grand_vision", binding.AuthorityPins.GrandVision, materials)
		stageBodyFreeProvePin(proofs, "/authority_pins/source_record", binding.AuthorityPins.SourceRecord, materials)
		stageBodyFreeProvePin(proofs, "/authority_pins/extension_protocol", binding.AuthorityPins.ExtensionProtocol, materials)
		stageBodyFreeProveIdentity(proofs, "/selection_roster", "raw_sha256", binding.SelectionRoster, materials)
		for index, manifest := range binding.EvidenceManifests {
			stageBodyFreeProveIdentity(proofs, fmt.Sprintf("/evidence_manifests/%d", index), "artifact_raw_sha256", stageArtifactIdentity{Role: manifest.Role, ID: manifest.ArtifactID, Version: manifest.ArtifactVersion, RawSHA256: manifest.ArtifactRawSHA256}, materials)
		}
	case stageSemanticExtraction:
		var binding semanticExtractionStageBinding
		if json.Unmarshal(raw, &binding) != nil {
			return proofs
		}
		stageBodyFreeProveValidationBinding(proofs, "/stage_validation", binding.StageValidation, materials)
		stageBodyFreeProvePin(proofs, "/applicability_profile", binding.ApplicabilityProfile, materials)
		for index, output := range binding.ArtifactOutputs {
			stageBodyFreeProveIdentity(proofs, fmt.Sprintf("/artifact_outputs/%d", index), "artifact_raw_sha256", stageArtifactIdentity{Role: output.Role, ID: output.ArtifactID, Version: output.ArtifactVersion, RawSHA256: output.ArtifactRawSHA256}, materials)
		}
		for index, derivation := range binding.DerivationBindings {
			base := fmt.Sprintf("/derivation_bindings/%d", index)
			stageBodyFreeProvePin(proofs, base+"/extractor", derivation.Extractor, materials)
			stageBodyFreeProvePin(proofs, base+"/schema", derivation.Schema, materials)
		}
	case stageGraphCompile:
		var binding graphCompileStageBinding
		if json.Unmarshal(raw, &binding) != nil {
			return proofs
		}
		stageBodyFreeProveValidationBinding(proofs, "/stage_validation", binding.StageValidation, materials)
		for index, identity := range binding.DependencyArtifacts {
			stageBodyFreeProveIdentity(proofs, fmt.Sprintf("/dependency_artifacts/%d", index), "raw_sha256", identity, materials)
		}
		stageBodyFreeProveIdentity(proofs, "/plan", "raw_sha256", binding.Plan, materials)
	case stageFullFactory:
		var binding fullFactoryStageBinding
		if json.Unmarshal(raw, &binding) != nil {
			return proofs
		}
		stageBodyFreeProveValidationBinding(proofs, "/stage_validation", binding.StageValidation, materials)
	}
	return proofs
}

func stageBodyFreeReceiptPointerProofs(parsed parsedStageReceipt, receipts map[StageReceiptReference]struct{}, bodies map[string]exactEvidenceBody) map[stageBodyFreePointerCoordinate]string {
	proofs := map[stageBodyFreePointerCoordinate]string{}
	stageBodyFreePutProof(proofs, "/receipt_sha256", parsed.Summary.ReceiptSHA256)
	stageBodyFreePutProof(proofs, "/output_root_sha256", parsed.Summary.OutputRootSHA256)
	for index, receipt := range parsed.Receipt.Predecessors {
		stageBodyFreeProveReceipt(proofs, fmt.Sprintf("/predecessors/%d", index), receipt, receipts)
	}
	for index, commitment := range parsed.Receipt.EvidenceCommitments {
		body, found := bodies[commitment.BodySHA256]
		if found && sha256Hex(body.Bytes) == commitment.BodySHA256 && uint64(len(body.Bytes)) == commitment.ByteCount {
			stageBodyFreePutProof(proofs, fmt.Sprintf("/evidence_commitments/%d/body_sha256", index), commitment.BodySHA256)
		}
	}
	return proofs
}

func stageBodyFreeProveValidationBinding(proofs map[stageBodyFreePointerCoordinate]string, base string, binding stageValidationBinding, materials map[stageMaterialCoordinate]string) {
	stageBodyFreeProvePin(proofs, base+"/schema", binding.Schema, materials)
	stageBodyFreeProvePin(proofs, base+"/profile", binding.Profile, materials)
}

func stageBodyFreeProvePin(proofs map[stageBodyFreePointerCoordinate]string, pointer string, pin immutableStageArtifactPin, materials map[stageMaterialCoordinate]string) {
	if exact, found := materials[stageCoordinateForPin(pin)]; found && exact == pin.RawSHA256 {
		stageBodyFreePutProof(proofs, pointer+"/raw_sha256", pin.RawSHA256)
	}
}

func stageBodyFreeProveIdentity(proofs map[stageBodyFreePointerCoordinate]string, pointer, digestField string, identity stageArtifactIdentity, materials map[stageMaterialCoordinate]string) {
	if exact, found := materials[stageCoordinateForIdentity(identity)]; found && exact == identity.RawSHA256 {
		stageBodyFreePutProof(proofs, pointer+"/"+digestField, identity.RawSHA256)
	}
}

func stageBodyFreeProveReceipt(proofs map[stageBodyFreePointerCoordinate]string, pointer string, receipt StageReceiptReference, receipts map[StageReceiptReference]struct{}) {
	if _, found := receipts[receipt]; !found {
		return
	}
	stageBodyFreePutProof(proofs, pointer+"/receipt_sha256", receipt.ReceiptSHA256)
	stageBodyFreePutProof(proofs, pointer+"/output_root_sha256", receipt.OutputRootSHA256)
}

func stageBodyFreePutProof(proofs map[stageBodyFreePointerCoordinate]string, pointer, value string) {
	proofs[stageBodyFreePointerCoordinate{row: 1, pointer: pointer}] = value
}

func stageBodyFreeMaterialPointerProofs(profile stageValidationProfileDocument, stageValidation stageValidationBinding, materials map[stageMaterialCoordinate]StageMaterial, bodies map[string]exactEvidenceBody) map[stageMaterialCoordinate]map[stageBodyFreePointerCoordinate]string {
	result := map[stageMaterialCoordinate]map[stageBodyFreePointerCoordinate]string{}
	merge := func(coordinate stageMaterialCoordinate, additions map[stageBodyFreePointerCoordinate]string) {
		if len(additions) == 0 {
			return
		}
		if result[coordinate] == nil {
			result[coordinate] = map[stageBodyFreePointerCoordinate]string{}
		}
		for pointer, value := range additions {
			result[coordinate][pointer] = value
		}
	}
	derive := func(artifactCoordinate, schemaCoordinate stageMaterialCoordinate) {
		artifact, artifactOK := materials[artifactCoordinate]
		schema, schemaOK := materials[schemaCoordinate]
		if !artifactOK || !schemaOK {
			return
		}
		merge(artifactCoordinate, stageBodyFreeSchemaValidatedProofs(artifact.Raw, schema.Raw))
		merge(schemaCoordinate, stageBodyFreeJSONSchemaDocumentProofs(schema.Raw))
	}

	profileCoordinate := stageCoordinateForPin(stageValidation.Profile)
	profileSchemaCoordinate := stageCoordinateForPin(stageValidation.Schema)
	derive(profileCoordinate, profileSchemaCoordinate)
	profileProofs := result[profileCoordinate]
	if profileProofs == nil {
		profileProofs = map[stageBodyFreePointerCoordinate]string{}
		result[profileCoordinate] = profileProofs
	}
	for index, binding := range profile.BoundArtifactSchemas {
		artifactCoordinate := stageMaterialCoordinate{Role: binding.Role, ID: binding.ArtifactID, Version: binding.ArtifactVersion}
		schemaCoordinate := stageMaterialCoordinate{Role: binding.SchemaRole, ID: binding.SchemaID, Version: binding.SchemaVersion}
		derive(artifactCoordinate, schemaCoordinate)
		if material, found := materials[artifactCoordinate]; found && sha256Hex(material.Raw) == binding.ArtifactRawSHA256 {
			profileProofs[stageBodyFreePointerCoordinate{row: 1, pointer: fmt.Sprintf("/bound_artifact_schemas/%d/artifact_raw_sha256", index)}] = binding.ArtifactRawSHA256
		}
		if schema, found := materials[schemaCoordinate]; found && sha256Hex(schema.Raw) == binding.SchemaRawSHA256 {
			profileProofs[stageBodyFreePointerCoordinate{row: 1, pointer: fmt.Sprintf("/bound_artifact_schemas/%d/schema_raw_sha256", index)}] = binding.SchemaRawSHA256
		}
		if material, found := materials[artifactCoordinate]; found {
			merge(artifactCoordinate, stageBodyFreeExternalBodyRowProofs(material.Raw, bodies))
		}
	}
	return result
}

func stageBodyFreeSchemaValidatedProofs(artifactRaw, schemaRaw []byte) map[stageBodyFreePointerCoordinate]string {
	proofs := map[stageBodyFreePointerCoordinate]string{}
	var schema interface{}
	decoder := json.NewDecoder(bytes.NewReader(schemaRaw))
	decoder.UseNumber()
	if decoder.Decode(&schema) != nil {
		return proofs
	}
	for lineIndex, line := range bytes.Split(artifactRaw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var value interface{}
		rowDecoder := json.NewDecoder(bytes.NewReader(line))
		rowDecoder.UseNumber()
		if rowDecoder.Decode(&value) != nil {
			continue
		}
		stageBodyFreeDeriveSchemaProofs(value, schema, lineIndex+1, "", proofs, 0)
	}
	return proofs
}

func stageBodyFreeDeriveSchemaProofs(value, schema interface{}, row int, pointer string, proofs map[stageBodyFreePointerCoordinate]string, depth int) {
	if depth > maxProviderJSONNestingDepth {
		return
	}
	schemaObject, ok := schema.(map[string]interface{})
	if !ok {
		return
	}
	if constant, found := schemaObject["const"]; found && stageBodyFreeJSONEqual(value, constant) {
		stageBodyFreeProveConstantValue(value, row, pointer, proofs, depth)
	}
	if allOf, ok := schemaObject["allOf"].([]interface{}); ok {
		for _, branch := range allOf {
			stageBodyFreeDeriveSchemaProofs(value, branch, row, pointer, proofs, depth+1)
		}
	}
	for _, keyword := range []string{"oneOf", "anyOf"} {
		branches, ok := schemaObject[keyword].([]interface{})
		if !ok {
			continue
		}
		matching := make([]interface{}, 0, len(branches))
		for _, branch := range branches {
			if stageBodyFreeSchemaCouldMatch(value, branch, depth+1) {
				matching = append(matching, branch)
			}
		}
		if len(matching) == 1 {
			stageBodyFreeDeriveSchemaProofs(value, matching[0], row, pointer, proofs, depth+1)
		} else if len(matching) > 1 {
			var intersection map[stageBodyFreePointerCoordinate]string
			for _, branch := range matching {
				branchProofs := map[stageBodyFreePointerCoordinate]string{}
				stageBodyFreeDeriveSchemaProofs(value, branch, row, pointer, branchProofs, depth+1)
				if intersection == nil {
					intersection = branchProofs
					continue
				}
				for coordinate, exact := range intersection {
					if other, found := branchProofs[coordinate]; !found || other != exact {
						delete(intersection, coordinate)
					}
				}
			}
			for coordinate, exact := range intersection {
				proofs[coordinate] = exact
			}
		}
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		properties, _ := schemaObject["properties"].(map[string]interface{})
		for key, child := range typed {
			childSchema, fixed := properties[key]
			if !fixed {
				continue
			}
			proofs[stageBodyFreePointerCoordinate{row: row, pointer: jsonPointerObjectKey(pointer, key)}] = key
			stageBodyFreeDeriveSchemaProofs(child, childSchema, row, jsonPointerChild(pointer, key), proofs, depth+1)
		}
	case []interface{}:
		if prefix, ok := schemaObject["prefixItems"].([]interface{}); ok {
			for index, child := range typed {
				if index < len(prefix) {
					stageBodyFreeDeriveSchemaProofs(child, prefix[index], row, jsonPointerChild(pointer, strconv.Itoa(index)), proofs, depth+1)
				}
			}
		}
		if items, found := schemaObject["items"]; found {
			for index, child := range typed {
				stageBodyFreeDeriveSchemaProofs(child, items, row, jsonPointerChild(pointer, strconv.Itoa(index)), proofs, depth+1)
			}
		}
	}
}

func stageBodyFreeSchemaCouldMatch(value, schema interface{}, depth int) bool {
	if depth > maxProviderJSONNestingDepth {
		return true
	}
	object, ok := schema.(map[string]interface{})
	if !ok {
		return true
	}
	if constant, found := object["const"]; found && !stageBodyFreeJSONEqual(value, constant) {
		return false
	}
	if required, ok := object["required"].([]interface{}); ok {
		valueObject, objectOK := value.(map[string]interface{})
		if !objectOK {
			return false
		}
		for _, rawKey := range required {
			key, stringKey := rawKey.(string)
			if !stringKey {
				continue
			}
			if _, found := valueObject[key]; !found {
				return false
			}
		}
	}
	if properties, ok := object["properties"].(map[string]interface{}); ok {
		if valueObject, objectOK := value.(map[string]interface{}); objectOK {
			for key, childSchema := range properties {
				if child, found := valueObject[key]; found && !stageBodyFreeSchemaCouldMatch(child, childSchema, depth+1) {
					return false
				}
			}
		}
	}
	return true
}

func stageBodyFreeJSONEqual(left, right interface{}) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func stageBodyFreeProveConstantValue(value interface{}, row int, pointer string, proofs map[stageBodyFreePointerCoordinate]string, depth int) {
	if depth > maxProviderJSONNestingDepth {
		return
	}
	switch typed := value.(type) {
	case string:
		proofs[stageBodyFreePointerCoordinate{row: row, pointer: pointer}] = typed
	case map[string]interface{}:
		for key, child := range typed {
			proofs[stageBodyFreePointerCoordinate{row: row, pointer: jsonPointerObjectKey(pointer, key)}] = key
			stageBodyFreeProveConstantValue(child, row, jsonPointerChild(pointer, key), proofs, depth+1)
		}
	case []interface{}:
		for index, child := range typed {
			stageBodyFreeProveConstantValue(child, row, jsonPointerChild(pointer, strconv.Itoa(index)), proofs, depth+1)
		}
	}
}

func stageBodyFreeExternalBodyRowProofs(raw []byte, bodies map[string]exactEvidenceBody) map[stageBodyFreePointerCoordinate]string {
	proofs := map[stageBodyFreePointerCoordinate]string{}
	for lineIndex, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var row map[string]interface{}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if decoder.Decode(&row) != nil || row["row_kind"] != "external_evidence_body" {
			continue
		}
		digest, digestOK := row["content_sha256"].(string)
		byteCount, countOK := stageBodyFreeJSONUint64(row["content_bytes"])
		body, bodyOK := bodies[digest]
		if digestOK && countOK && bodyOK && sha256Hex(body.Bytes) == digest && uint64(len(body.Bytes)) == byteCount {
			proofs[stageBodyFreePointerCoordinate{row: lineIndex + 1, pointer: "/content_sha256"}] = digest
			componentDigest, componentDigestOK := row["component_sha256"].(string)
			componentByteCount, componentCountOK := stageBodyFreeJSONUint64(row["component_byte_length"])
			if componentDigestOK && componentCountOK && componentDigest == digest && componentByteCount == byteCount {
				proofs[stageBodyFreePointerCoordinate{row: lineIndex + 1, pointer: "/component_sha256"}] = componentDigest
			}
		}
	}
	return proofs
}

func stageBodyFreeJSONUint64(value interface{}) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok || strings.ContainsAny(string(number), ".eE-") {
		return 0, false
	}
	parsed, err := strconv.ParseUint(string(number), 10, 64)
	return parsed, err == nil
}

func stageBodyFreeJSONSchemaDocumentProofs(raw []byte) map[stageBodyFreePointerCoordinate]string {
	proofs := map[stageBodyFreePointerCoordinate]string{}
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return proofs
	}
	stageBodyFreeProveJSONSchemaKeywords(value, 1, "", false, proofs, 0)
	return proofs
}

func stageBodyFreeProveJSONSchemaKeywords(value interface{}, row int, pointer string, dynamicKeys bool, proofs map[stageBodyFreePointerCoordinate]string, depth int) {
	if depth > maxProviderJSONNestingDepth {
		return
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			if !dynamicKeys && stageBodyFreeJSONSchemaKeyword(key) {
				proofs[stageBodyFreePointerCoordinate{row: row, pointer: jsonPointerObjectKey(pointer, key)}] = key
			}
			childDynamic := key == "properties" || key == "$defs" || key == "patternProperties" || key == "dependentSchemas"
			stageBodyFreeProveJSONSchemaKeywords(child, row, jsonPointerChild(pointer, key), childDynamic, proofs, depth+1)
		}
	case []interface{}:
		for index, child := range typed {
			stageBodyFreeProveJSONSchemaKeywords(child, row, jsonPointerChild(pointer, strconv.Itoa(index)), false, proofs, depth+1)
		}
	}
}

func stageBodyFreeJSONSchemaKeyword(value string) bool {
	switch value {
	case "$anchor", "$comment", "$defs", "$dynamicAnchor", "$dynamicRef", "$id", "$ref", "$schema", "$vocabulary",
		"additionalProperties", "allOf", "anyOf", "const", "contains", "contentEncoding", "contentMediaType", "contentSchema",
		"default", "dependentRequired", "dependentSchemas", "deprecated", "description", "else", "enum", "examples", "exclusiveMaximum",
		"exclusiveMinimum", "format", "if", "items", "maxContains", "maximum", "maxItems", "maxLength", "maxProperties", "minContains",
		"minimum", "minItems", "minLength", "minProperties", "multipleOf", "not", "oneOf", "pattern", "patternProperties", "prefixItems",
		"properties", "propertyNames", "readOnly", "required", "then", "title", "type", "unevaluatedItems", "unevaluatedProperties", "uniqueItems", "writeOnly":
		return true
	default:
		return false
	}
}

func validateStageStructuredBodyFreeClosure(label string, items []candidateClosureItem, bodies map[string]exactEvidenceBody) error {
	structured := make([]stageBodyFreeItem, len(items))
	for index, item := range items {
		structured[index] = stageBodyFreeItem{label: item.label, raw: item.raw, structured: true}
	}
	return validateStageBodyFreeClosure(label, structured, bodies)
}

func validateStageBodyFreeClosure(label string, items []stageBodyFreeItem, bodies map[string]exactEvidenceBody) error {
	if len(items) == 0 {
		return nil
	}
	closureItems := make([]evidenceClosureItem, len(items))
	for index, item := range items {
		closureItems[index] = evidenceClosureItem{label: item.label, raw: item.raw, structured: item.structured}
	}
	if itemLabel, digest, encoding, found, err := detectCanonicalEvidenceBodyClosure(closureItems, jsonCarrierSourceOrder, bodies, 1); err != nil {
		return fmt.Errorf("%s is not body-free: %w", label, err)
	} else if found {
		return fmt.Errorf("%s is not body-free: %s reconstructs %s from selected evidence digest %s", label, itemLabel, encoding, digest)
	}
	carrierDigests := map[[32]byte][]byte{}
	carrierOccurrences := []stageEvidenceCarrierOccurrence{}
	carrierOccurrenceGroups := map[[32]byte][]int{}
	carrierStorage := &stageEvidenceCarrierStorageBudget{}
	if err := carrierStorage.retainAuxiliary(128); err != nil {
		return fmt.Errorf("%s is not body-free: %w", label, err)
	}
	advance := func(itemLabel string, carrier orderedJSONCarrier) error {
		occurrence := stageEvidenceCarrierOccurrence{provenDigestIdentity: carrier.provenDigestIdentity, multiplicity: 1}
		occurrenceRepresentations := map[[32]byte]struct{}{}
		representations, err := stageEvidenceCarrierRepresentations(carrier, carrierStorage)
		if err != nil {
			return fmt.Errorf("%s: %w", itemLabel, err)
		}
		for index, candidate := range representations {
			if len(candidate) == 0 {
				continue
			}
			key := sha256.Sum256(candidate)
			canonical := carrierDigests[key]
			if prior, exists := carrierDigests[key]; exists {
				if !bytes.Equal(prior, candidate) {
					return fmt.Errorf("%s has two scalar carriers with one SHA-256 identity", itemLabel)
				}
			} else {
				if err := carrierStorage.retain(len(candidate)); err != nil {
					return fmt.Errorf("%s: %w", itemLabel, err)
				}
				if index == 0 {
					canonical = bytes.Clone(candidate)
				} else {
					// Decoders already return a newly owned exact byte slice. Retain
					// that allocation directly instead of cloning it a second time.
					canonical = candidate
				}
				carrierDigests[key] = canonical
			}
			// A raw scalar and one of its alternate decoding interpretations are
			// one occurrence, not independently reusable fragments. Preserve the
			// occurrence identity while removing only byte-identical alternatives
			// within that occurrence.
			if _, duplicate := occurrenceRepresentations[key]; !duplicate {
				if len(occurrence.representations) == stageEvidenceMaxRepresentationsPerOccurrence {
					return fmt.Errorf("%s: body-free scalar carrier occurrence exceeds fixed representation limit %d", itemLabel, stageEvidenceMaxRepresentationsPerOccurrence)
				}
				occurrenceRepresentations[key] = struct{}{}
				occurrence.representations = append(occurrence.representations, canonical)
			}
		}
		if len(occurrence.representations) != 0 {
			identity := stageEvidenceCarrierOccurrenceIdentity(occurrence)
			for _, groupIndex := range carrierOccurrenceGroups[identity] {
				group := &carrierOccurrences[groupIndex]
				if !stageEvidenceCarrierOccurrencesEquivalent(*group, occurrence) {
					continue
				}
				if group.multiplicity == int(^uint(0)>>1) {
					return fmt.Errorf("%s: body-free scalar carrier multiplicity overflows local integer capacity", itemLabel)
				}
				group.multiplicity++
				return nil
			}
			if len(carrierOccurrences) == stageEvidenceMaxCarrierOccurrences {
				return fmt.Errorf("%s: body-free scalar carrier analysis exceeds fixed occurrence-group limit %d", itemLabel, stageEvidenceMaxCarrierOccurrences)
			}
			if err := carrierStorage.retainAuxiliary(192); err != nil {
				return fmt.Errorf("%s: %w", itemLabel, err)
			}
			groupIndex := len(carrierOccurrences)
			carrierOccurrences = append(carrierOccurrences, occurrence)
			carrierOccurrenceGroups[identity] = append(carrierOccurrenceGroups[identity], groupIndex)
		}
		return nil
	}
	for _, item := range items {
		if item.structured {
			if err := scanJSONLClosureItemWithOrderBudgetAndProvenance(candidateClosureItem{label: item.label, raw: item.raw}, jsonCarrierSourceOrder, nil, item.provenance, func(carrier orderedJSONCarrier) error {
				return advance(item.label, carrier)
			}); err != nil {
				return fmt.Errorf("%s is not body-free: %w", label, err)
			}
			continue
		}
		if err := advance(item.label, orderedJSONCarrier{bytes: item.raw, kind: orderedJSONStringValue}); err != nil {
			return fmt.Errorf("%s is not body-free: %w", label, err)
		}
	}
	if digest, encoding, reconstructed, err := reconstructsStageEvidenceBodyWithoutCarrierOrder(carrierOccurrences, bodies); err != nil {
		return fmt.Errorf("%s is not body-free: %w", label, err)
	} else if reconstructed {
		return fmt.Errorf("%s is not body-free: unordered exact scalar carriers reconstruct %s from selected evidence digest %s", label, encoding, digest)
	}
	return nil
}

type stageEvidenceCarrierOccurrence struct {
	representations      [][]byte
	provenDigestIdentity bool
	multiplicity         int
}

func stageEvidenceCarrierOccurrenceMultiplicity(occurrence stageEvidenceCarrierOccurrence) int {
	if occurrence.multiplicity == 0 {
		return 1
	}
	return occurrence.multiplicity
}

func stageEvidenceMultiplicitiesAtLeast(multiplicities []int, required int) bool {
	remaining := required
	for _, multiplicity := range multiplicities {
		if multiplicity <= 0 {
			continue
		}
		remaining -= multiplicity
		if remaining <= 0 {
			return true
		}
	}
	return required <= 0
}

func stageEvidenceCarrierOccurrenceIdentity(occurrence stageEvidenceCarrierOccurrence) [32]byte {
	hasher := sha256.New()
	if occurrence.provenDigestIdentity {
		_, _ = hasher.Write([]byte{1})
	} else {
		_, _ = hasher.Write([]byte{0})
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(occurrence.representations)))
	_, _ = hasher.Write(length[:])
	for _, representation := range occurrence.representations {
		binary.BigEndian.PutUint64(length[:], uint64(len(representation)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write(representation)
	}
	var identity [32]byte
	copy(identity[:], hasher.Sum(nil))
	return identity
}

func stageEvidenceCarrierOccurrencesEquivalent(left, right stageEvidenceCarrierOccurrence) bool {
	if left.provenDigestIdentity != right.provenDigestIdentity || len(left.representations) != len(right.representations) {
		return false
	}
	for index := range left.representations {
		if !bytes.Equal(left.representations[index], right.representations[index]) {
			return false
		}
	}
	return true
}

type stageEvidenceCarrierRepresentation struct {
	occurrence int
	raw        []byte
}

type stageEvidenceSegmentationIndex struct {
	byPrefix map[string][]stageEvidenceCarrierRepresentation
	profile  stageEvidenceSegmentationProfile
}

const (
	stageEvidenceSegmentationPrefixBytes = 8
	// This minimum is measured in the target representation: decoded bytes for
	// the raw target, base64 characters for each base64 target, and nibbles for
	// the hexadecimal target. Consequently a three-nibble odd-boundary fragment
	// remains eligible. It applies only to a substring inside a larger scalar;
	// the exact-scalar index above continues to admit one- and two-byte fragments.
	stageEvidenceWrappedMinFragmentBytes               = 3
	stageEvidenceSegmentationMaxStates                 = 250_000
	stageEvidenceSegmentationMinCompareBudget          = 4 * 1024 * 1024
	stageEvidenceAggregateMaxComparisons               = 64 * 1024 * 1024
	stageEvidenceSegmentationCompareMultiplier         = 4
	stageEvidenceMaxCarrierOccurrences                 = 131_072
	stageEvidenceMaxUniqueRepresentations              = 262_144
	stageEvidenceMaxRepresentationsPerOccurrence       = 8
	stageEvidenceMaxRetainedCarrierBytes         int64 = 384 << 20
	stageEvidenceMaxSegmentationIndexBytes       int64 = 64 << 20
	stageEvidenceMaxWrappedCandidateCacheBytes   int64 = 48 << 20
	stageEvidenceMaxOccurrenceAuxiliaryBytes     int64 = 16 << 20
	stageEvidenceMaxAnalyzerAuxiliaryBytes       int64 = 1280 << 20
	stageEvidenceRetainedEntryOverheadBytes      int64 = 96
	// Index bookkeeping is not a byte comparison. Its fixed linear-work ceiling
	// is derived from, and cannot outgrow, the unchanged 64 MiB index-storage
	// ceiling; exact candidate bytes remain under the separate unchanged 64 MiB
	// aggregate comparison ceiling.
	stageEvidenceMaxScalarIndexWork int64 = 3 * stageEvidenceMaxSegmentationIndexBytes
)

type stageEvidenceCarrierStorageBudget struct {
	retainedBytes         int64
	uniqueRepresentations int
}

func (budget *stageEvidenceCarrierStorageBudget) retainAuxiliary(byteCount int64) error {
	if byteCount < 0 || byteCount > stageEvidenceMaxRetainedCarrierBytes-budget.retainedBytes {
		return fmt.Errorf("body-free scalar carrier analysis exceeds fixed retained storage limit %d", stageEvidenceMaxRetainedCarrierBytes)
	}
	budget.retainedBytes += byteCount
	return nil
}

func (budget *stageEvidenceCarrierStorageBudget) ensureDecodePeak(carrierBytes int) error {
	if carrierBytes < 0 {
		return fmt.Errorf("negative scalar carrier byte length")
	}
	// One raw clone, at most one failed padded base64 destination plus one
	// successful raw destination, and one hexadecimal destination can coexist.
	// Reserve their conservative decoded capacities before any decoder allocates.
	peak, ok := stageEvidenceCarrierDecodePeakBytes(carrierBytes)
	if !ok {
		return fmt.Errorf("scalar carrier decode storage bound overflows int64")
	}
	if peak > stageEvidenceMaxRetainedCarrierBytes-budget.retainedBytes {
		return fmt.Errorf("body-free scalar carrier analysis exceeds fixed retained/decode storage limit %d before allocation", stageEvidenceMaxRetainedCarrierBytes)
	}
	return nil
}

func stageEvidenceCarrierDecodePeakBytes(carrierBytes int) (int64, bool) {
	if carrierBytes < 0 {
		return 0, false
	}
	paddedBase64Capacity := int64(base64.StdEncoding.DecodedLen(carrierBytes))
	rawBase64Capacity := int64(base64.RawStdEncoding.DecodedLen(carrierBytes))
	hexCapacity := int64(hex.DecodedLen(carrierBytes))
	peak := int64(carrierBytes)
	for _, addition := range []int64{paddedBase64Capacity, rawBase64Capacity, hexCapacity} {
		if addition > math.MaxInt64-peak {
			return 0, false
		}
		peak += addition
	}
	return peak, true
}

func (budget *stageEvidenceCarrierStorageBudget) retain(byteCount int) error {
	if byteCount < 0 || budget.uniqueRepresentations == stageEvidenceMaxUniqueRepresentations {
		return fmt.Errorf("body-free scalar carrier analysis exceeds fixed unique representation limit %d", stageEvidenceMaxUniqueRepresentations)
	}
	allocation := int64(byteCount) + stageEvidenceRetainedEntryOverheadBytes
	if err := budget.retainAuxiliary(allocation); err != nil {
		return err
	}
	budget.uniqueRepresentations++
	return nil
}

func stageEvidenceCarrierRepresentations(carrier orderedJSONCarrier, storage *stageEvidenceCarrierStorageBudget) ([][]byte, error) {
	if err := storage.ensureDecodePeak(len(carrier.bytes)); err != nil {
		return nil, err
	}
	representations := [][]byte{carrier.bytes}
	if carrier.kind == orderedJSONByteArray || carrier.kind == orderedJSONByteIndexObject {
		return representations, nil
	}
	if decoded, ok := exactCanonicalBase64Carrier(carrier.bytes); ok {
		representations = append(representations, decoded)
	}
	if len(carrier.bytes)%2 == 0 && stageEvidenceASCIIHex(carrier.bytes) {
		decoded, ok := exactHexCarrier(carrier.bytes)
		if !ok {
			return nil, fmt.Errorf("internally classified hexadecimal carrier did not decode exactly")
		}
		representations = append(representations, decoded)
	}
	return representations, nil
}

// Hexadecimal evidence is case-insensitive, including when an author splits it
// across odd nibble boundaries that are not independently decodable. Fold only
// the carrier set used for the hexadecimal target: folding the ordinary raw
// target would incorrectly make unrelated case-sensitive metadata equivalent.
// Alternate interpretations remain attached to their original occurrence, so
// the search cannot reuse one scalar twice.
func stageEvidenceHexFoldedCarrierOccurrences(carriers []stageEvidenceCarrierOccurrence, storage *stageEvidenceCarrierStorageBudget) ([]stageEvidenceCarrierOccurrence, error) {
	result := make([]stageEvidenceCarrierOccurrence, len(carriers))
	foldedCanonical := map[[32]byte][]byte{}
	for occurrence, carrier := range carriers {
		result[occurrence].provenDigestIdentity = carrier.provenDigestIdentity
		result[occurrence].multiplicity = carrier.multiplicity
		seen := map[[32]byte]struct{}{}
		for _, representation := range carrier.representations {
			if len(representation) == 0 {
				continue
			}
			key := sha256.Sum256(representation)
			if _, duplicate := seen[key]; !duplicate {
				seen[key] = struct{}{}
				result[occurrence].representations = append(result[occurrence].representations, representation)
			}
			if !stageEvidenceHasUpperHex(representation) {
				continue
			}
			foldedKey := stageEvidenceFoldedHexSHA256(representation)
			if _, duplicate := seen[foldedKey]; duplicate {
				continue
			}
			seen[foldedKey] = struct{}{}
			folded := foldedCanonical[foldedKey]
			if folded == nil {
				if err := storage.retain(len(representation)); err != nil {
					return nil, err
				}
				folded = stageEvidenceFoldHexBytes(representation)
				foldedCanonical[foldedKey] = folded
			}
			result[occurrence].representations = append(result[occurrence].representations, folded)
		}
	}
	return result, nil
}

func stageEvidenceFoldHexBytes(value []byte) []byte {
	result := bytes.Clone(value)
	for index, current := range result {
		if current >= 'A' && current <= 'F' {
			result[index] = current + ('a' - 'A')
		}
	}
	return result
}

func stageEvidenceHasUpperHex(value []byte) bool {
	for _, current := range value {
		if current >= 'A' && current <= 'F' {
			return true
		}
	}
	return false
}

func stageEvidenceFoldedHexSHA256(value []byte) [32]byte {
	hasher := sha256.New()
	var scratch [4096]byte
	for len(value) != 0 {
		count := len(value)
		if count > len(scratch) {
			count = len(scratch)
		}
		for index, current := range value[:count] {
			if current >= 'A' && current <= 'F' {
				current += 'a' - 'A'
			}
			scratch[index] = current
		}
		_, _ = hasher.Write(scratch[:count])
		value = value[count:]
	}
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

func stageEvidenceASCIIHex(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, item := range value {
		if !((item >= '0' && item <= '9') || (item >= 'a' && item <= 'f') || (item >= 'A' && item <= 'F')) {
			return false
		}
	}
	return true
}

func reconstructsStageEvidenceBodyWithoutCarrierOrder(carriers []stageEvidenceCarrierOccurrence, bodies map[string]exactEvidenceBody) (string, string, bool, error) {
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	if len(carriers) > stageEvidenceMaxCarrierOccurrences {
		return "", "", false, fmt.Errorf("body-free scalar carrier analysis exceeds fixed occurrence-group limit %d", stageEvidenceMaxCarrierOccurrences)
	}
	index, err := newStageEvidenceSegmentationIndexBounded(carriers, budget)
	if err != nil {
		return "", "", false, fmt.Errorf("raw scalar index after %d auxiliary bytes: %w", budget.indexBytesUsed, err)
	}
	storage := &stageEvidenceCarrierStorageBudget{}
	retainedRepresentations := map[[32]byte]struct{}{}
	for _, carrier := range carriers {
		for _, representation := range carrier.representations {
			identity := sha256.Sum256(representation)
			if _, duplicate := retainedRepresentations[identity]; duplicate {
				continue
			}
			retainedRepresentations[identity] = struct{}{}
			if err := storage.retain(len(representation)); err != nil {
				return "", "", false, err
			}
		}
	}
	hexFoldedCarriers, err := stageEvidenceHexFoldedCarrierOccurrences(carriers, storage)
	if err != nil {
		return "", "", false, err
	}
	hexFoldedIndex, err := newStageEvidenceSegmentationIndexBounded(hexFoldedCarriers, budget)
	if err != nil {
		return "", "", false, fmt.Errorf("hex-folded scalar index after %d auxiliary bytes: %w", budget.indexBytesUsed, err)
	}
	openCarriers := stageEvidenceEncodedFragmentCarrierOccurrences(carriers)
	wrappedFilter, err := newStageEvidenceWrappedTrigramFilter(bodies, budget)
	if err != nil {
		return "", "", false, fmt.Errorf("wrapped scalar target filter after %d auxiliary bytes: %w", budget.indexBytesUsed, err)
	}
	wrappedIndex, err := newStageEvidenceWrappedIndexFilteredBounded(openCarriers, &wrappedFilter, budget)
	if err != nil {
		return "", "", false, fmt.Errorf("wrapped scalar index after %d auxiliary bytes: %w", budget.indexBytesUsed, err)
	}
	digests := make([]string, 0, len(bodies))
	for digest := range bodies {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	var targetScratch []byte
	for _, digest := range digests {
		body := bodies[digest].Bytes
		peak, ok := stageEvidenceAnalyzerPeakAuxiliaryBytes(int64(len(body)))
		if !ok || peak > stageEvidenceMaxAnalyzerAuxiliaryBytes {
			return "", "", false, fmt.Errorf("selected evidence digest %s requires %d body-free analyzer auxiliary bytes above fixed limit %d", digest, peak, stageEvidenceMaxAnalyzerAuxiliaryBytes)
		}
		seenTargets := map[string]struct{}{}
		for targetIndex := 0; targetIndex < 6; targetIndex++ {
			targetName, targetRaw, targetCarriers, targetIndexValue, nextScratch := stageEvidenceAnalysisTarget(body, targetIndex, targetScratch, carriers, index, hexFoldedCarriers, hexFoldedIndex)
			targetScratch = nextScratch
			key := sha256Hex(targetRaw)
			if _, duplicate := seenTargets[key]; duplicate {
				continue
			}
			seenTargets[key] = struct{}{}
			reconstructed, err := stageEvidenceTargetHasUnorderedSegmentationWithBudget(targetRaw, targetCarriers, targetIndexValue, budget)
			if err != nil {
				return "", "", false, fmt.Errorf("unordered exact scalar carrier analysis for selected evidence digest %s %s: %w", digest, targetName, err)
			}
			if reconstructed {
				return digest, targetName, true, nil
			}
			foldHex := targetIndex == 5
			reconstructed, err = stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex(targetRaw, &wrappedIndex, foldHex, budget)
			if err != nil {
				return "", "", false, fmt.Errorf("wrapped exact scalar carrier analysis for selected evidence digest %s %s: %w", digest, targetName, err)
			}
			if reconstructed {
				return digest, targetName, true, nil
			}
		}
	}
	return "", "", false, nil
}

func stageEvidenceRawCarrierOccurrences(carriers []stageEvidenceCarrierOccurrence) []stageEvidenceCarrierOccurrence {
	result := make([]stageEvidenceCarrierOccurrence, len(carriers))
	for index, carrier := range carriers {
		result[index].provenDigestIdentity = carrier.provenDigestIdentity
		result[index].multiplicity = carrier.multiplicity
		if len(carrier.representations) != 0 {
			result[index].representations = carrier.representations[:1]
		}
	}
	return result
}

func stageEvidenceEncodedFragmentCarrierOccurrences(carriers []stageEvidenceCarrierOccurrence) []stageEvidenceCarrierOccurrence {
	result := make([]stageEvidenceCarrierOccurrence, len(carriers))
	for index, carrier := range carriers {
		result[index].provenDigestIdentity = carrier.provenDigestIdentity
		result[index].multiplicity = carrier.multiplicity
		if !carrier.provenDigestIdentity {
			result[index].representations = carrier.representations
		}
	}
	return result
}

func stageEvidenceAnalysisTarget(body []byte, targetIndex int, scratch []byte, carriers []stageEvidenceCarrierOccurrence, index stageEvidenceSegmentationIndex, hexCarriers []stageEvidenceCarrierOccurrence, hexIndex stageEvidenceSegmentationIndex) (string, []byte, []stageEvidenceCarrierOccurrence, stageEvidenceSegmentationIndex, []byte) {
	switch targetIndex {
	case 0:
		return "complete decoded body", body, carriers, index, scratch
	case 1:
		scratch = resizeStageEvidenceTargetScratch(scratch, base64.StdEncoding.EncodedLen(len(body)))
		base64.StdEncoding.Encode(scratch, body)
		return "complete padded standard base64 body", scratch, carriers, index, scratch
	case 2:
		scratch = resizeStageEvidenceTargetScratch(scratch, base64.RawStdEncoding.EncodedLen(len(body)))
		base64.RawStdEncoding.Encode(scratch, body)
		return "complete unpadded standard base64 body", scratch, carriers, index, scratch
	case 3:
		scratch = resizeStageEvidenceTargetScratch(scratch, base64.URLEncoding.EncodedLen(len(body)))
		base64.URLEncoding.Encode(scratch, body)
		return "complete padded URL-safe base64 body", scratch, carriers, index, scratch
	case 4:
		scratch = resizeStageEvidenceTargetScratch(scratch, base64.RawURLEncoding.EncodedLen(len(body)))
		base64.RawURLEncoding.Encode(scratch, body)
		return "complete unpadded URL-safe base64 body", scratch, carriers, index, scratch
	default:
		scratch = resizeStageEvidenceTargetScratch(scratch, hex.EncodedLen(len(body)))
		hex.Encode(scratch, body)
		return "complete hexadecimal body", scratch, hexCarriers, hexIndex, scratch
	}
}

func resizeStageEvidenceTargetScratch(scratch []byte, length int) []byte {
	if cap(scratch) < length {
		return make([]byte, length)
	}
	return scratch[:length]
}

func stageEvidenceAnalyzerPeakAuxiliaryBytes(bodyBytes int64) (int64, bool) {
	if bodyBytes < 0 || bodyBytes > math.MaxInt64/12 {
		return 0, false
	}
	// The maximum target is hexadecimal (2N), the reusable reversed target is
	// 2N, and its compact uint32 prefix scratch is 8N. The exact-scalar
	// reuse-relaxed reachability bitset reuses that same prefix scratch and does
	// not add another peak allocation. The fixed portion includes
	// retained canonical carriers plus the segmentation index, wrapped candidate
	// cache, and occurrence work arrays; all four have independently enforced
	// limits and can coexist at peak.
	fixed := stageEvidenceMaxRetainedCarrierBytes + stageEvidenceMaxSegmentationIndexBytes + stageEvidenceMaxWrappedCandidateCacheBytes + stageEvidenceMaxOccurrenceAuxiliaryBytes
	if fixed > math.MaxInt64-(12*bodyBytes) {
		return 0, false
	}
	return fixed + (12 * bodyBytes), true
}

func newStageEvidenceSegmentationIndex(carriers []stageEvidenceCarrierOccurrence) stageEvidenceSegmentationIndex {
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: stageEvidenceAggregateMaxComparisons}
	index, _ := newStageEvidenceSegmentationIndexBounded(carriers, budget)
	return index
}

func newStageEvidenceSegmentationIndexBounded(carriers []stageEvidenceCarrierOccurrence, budget *stageEvidenceSegmentationBudget) (stageEvidenceSegmentationIndex, error) {
	result := stageEvidenceSegmentationIndex{}
	if len(carriers) > stageEvidenceMaxCarrierOccurrences {
		return result, fmt.Errorf("body-free segmentation index exceeds fixed occurrence-group limit %d", stageEvidenceMaxCarrierOccurrences)
	}
	if err := budget.consumeIndexBytes(int64(len(carriers)) * 8); err != nil {
		return result, err
	}
	result.byPrefix = map[string][]stageEvidenceCarrierRepresentation{}
	result.profile.maxLengths = make([]int, len(carriers))
	for occurrence, carrier := range carriers {
		multiplicity := stageEvidenceCarrierOccurrenceMultiplicity(carrier)
		if multiplicity <= 0 {
			return result, fmt.Errorf("body-free segmentation index occurrence group has nonpositive multiplicity")
		}
		if len(carrier.representations) > stageEvidenceMaxRepresentationsPerOccurrence {
			return result, fmt.Errorf("body-free segmentation index occurrence exceeds fixed representation limit %d", stageEvidenceMaxRepresentationsPerOccurrence)
		}
		var occurrenceMax [256]int
		for _, representation := range carrier.representations {
			if len(representation) == 0 {
				continue
			}
			if len(representation) > result.profile.maxLengths[occurrence] {
				result.profile.maxLengths[occurrence] = len(representation)
			}
			if err := budget.consumeScalarIndexWork(int64(len(representation))); err != nil {
				return result, err
			}
			var counts [256]int
			for _, current := range representation {
				counts[current]++
			}
			for current, count := range counts {
				if count > occurrenceMax[current] {
					occurrenceMax[current] = count
				}
			}
			key := stageEvidenceSegmentationPrefix(representation)
			entryBytes := int64(48)
			if _, exists := result.byPrefix[key]; !exists {
				entryBytes += int64(len(key)) + 128
			}
			if err := budget.consumeIndexBytes(entryBytes); err != nil {
				return result, err
			}
			if err := budget.consumeScalarIndexWork(int64(len(key))); err != nil {
				return result, err
			}
			result.byPrefix[key] = append(result.byPrefix[key], stageEvidenceCarrierRepresentation{occurrence: occurrence, raw: representation})
		}
		maximumLength := int64(result.profile.maxLengths[occurrence])
		if maximumLength != 0 && int64(multiplicity) > math.MaxInt64/maximumLength {
			return result, fmt.Errorf("body-free segmentation index capacity overflows int64")
		}
		groupCapacity := maximumLength * int64(multiplicity)
		if groupCapacity > math.MaxInt64-result.profile.totalCapacity {
			return result, fmt.Errorf("body-free segmentation index capacity overflows int64")
		}
		result.profile.totalCapacity += groupCapacity
		for current, count := range occurrenceMax {
			if count != 0 && int64(multiplicity) > math.MaxInt64/int64(count) {
				return result, fmt.Errorf("body-free segmentation index frequency capacity overflows int64")
			}
			groupAvailable := int64(count) * int64(multiplicity)
			if groupAvailable > math.MaxInt64-result.profile.available[current] {
				return result, fmt.Errorf("body-free segmentation index frequency capacity overflows int64")
			}
			result.profile.available[current] += groupAvailable
		}
	}
	result.profile.hasFrequency = true
	for key := range result.byPrefix {
		count := len(result.byPrefix[key])
		if err := budget.consumeScalarIndexWork(stageEvidenceSortComparisonBound(count)); err != nil {
			return result, err
		}
		sort.SliceStable(result.byPrefix[key], func(left, right int) bool {
			leftValue := result.byPrefix[key][left]
			rightValue := result.byPrefix[key][right]
			if len(leftValue.raw) != len(rightValue.raw) {
				return len(leftValue.raw) > len(rightValue.raw)
			}
			// Carrier and representation input order is already deterministic.
			// Keep the comparator constant-work instead of hiding an uncharged
			// O(representation bytes) bytes.Compare inside every sort comparison.
			if leftValue.occurrence != rightValue.occurrence {
				return leftValue.occurrence < rightValue.occurrence
			}
			return false
		})
	}
	return result, nil
}

func stageEvidenceSortComparisonBound(count int) int64 {
	if count < 2 {
		return 0
	}
	levels := 0
	for value := count; value > 1; value = (value + 1) / 2 {
		levels++
	}
	return int64(count) * int64(levels+1)
}

func stageEvidenceSegmentationPrefix(value []byte) string {
	length := len(value)
	if length > stageEvidenceSegmentationPrefixBytes {
		length = stageEvidenceSegmentationPrefixBytes
	}
	return string(append([]byte{byte(length)}, value[:length]...))
}

func stageEvidenceTargetCandidateBucket(target []byte, offset, length int, index stageEvidenceSegmentationIndex) []stageEvidenceCarrierRepresentation {
	var keyBytes [stageEvidenceSegmentationPrefixBytes + 1]byte
	keyBytes[0] = byte(length)
	copy(keyBytes[1:length+1], target[offset:offset+length])
	return index.byPrefix[string(keyBytes[:length+1])]
}

type stageEvidenceSegmentationBudget struct {
	statesRemaining      int
	comparisonsRemaining int64
	prefixScratch        []uint32
	reverseScratch       []byte
	indexBytesUsed       int64
	indexBytesLimit      int64
	candidateBytesUsed   int64
	candidateBytesLimit  int64
	scalarIndexWorkUsed  int64
	scalarIndexWorkLimit int64
}

func (budget *stageEvidenceSegmentationBudget) consumeComparisons(count int64, phase string) error {
	if count < 0 || count > budget.comparisonsRemaining {
		return fmt.Errorf("analysis exceeded the deterministic byte-comparison bound (aggregate budget) during %s", phase)
	}
	budget.comparisonsRemaining -= count
	return nil
}

func (budget *stageEvidenceSegmentationBudget) consumeIndexBytes(count int64) error {
	limit := budget.indexBytesLimit
	if limit == 0 {
		limit = stageEvidenceMaxSegmentationIndexBytes
	}
	if count < 0 || count > limit-budget.indexBytesUsed {
		return fmt.Errorf("body-free segmentation index exceeds fixed auxiliary byte limit %d (used %d, requested %d)", limit, budget.indexBytesUsed, count)
	}
	budget.indexBytesUsed += count
	return nil
}

func (budget *stageEvidenceSegmentationBudget) consumeCandidateBytes(count int64) error {
	limit := budget.candidateBytesLimit
	if limit == 0 {
		limit = stageEvidenceMaxWrappedCandidateCacheBytes
	}
	if count < 0 || count > limit-budget.candidateBytesUsed {
		return fmt.Errorf("body-free wrapped candidate cache exceeds fixed auxiliary byte limit %d", limit)
	}
	budget.candidateBytesUsed += count
	return nil
}

func (budget *stageEvidenceSegmentationBudget) consumeScalarIndexWork(count int64) error {
	limit := budget.scalarIndexWorkLimit
	if limit == 0 {
		limit = stageEvidenceMaxScalarIndexWork
	}
	if count < 0 || count > limit-budget.scalarIndexWorkUsed {
		return fmt.Errorf("body-free scalar index exceeds fixed linear-work limit %d", limit)
	}
	budget.scalarIndexWorkUsed += count
	return nil
}

func stageEvidenceTargetHasUnorderedSegmentation(target []byte, carriers []stageEvidenceCarrierOccurrence, index stageEvidenceSegmentationIndex) (bool, error) {
	compareBudget := int64(len(target)) * stageEvidenceSegmentationCompareMultiplier
	if compareBudget < stageEvidenceSegmentationMinCompareBudget {
		compareBudget = stageEvidenceSegmentationMinCompareBudget
	}
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: compareBudget,
	}
	return stageEvidenceTargetHasUnorderedSegmentationWithBudget(target, carriers, index, budget)
}

func stageEvidenceTargetHasUnorderedSegmentationWithBudget(target []byte, carriers []stageEvidenceCarrierOccurrence, index stageEvidenceSegmentationIndex, budget *stageEvidenceSegmentationBudget) (bool, error) {
	if len(target) == 0 {
		return false, nil
	}
	maxUsableLength := index.profile.maxLengths
	totalCapacity, feasible, profileErr := stageEvidenceProfileFeasible(target, index.profile, budget)
	if profileErr != nil {
		return false, profileErr
	}
	if len(maxUsableLength) != len(carriers) {
		var err error
		maxUsableLength, totalCapacity, feasible, err = stageEvidenceSegmentationFeasible(target, carriers, true, budget)
		if err != nil {
			return false, err
		}
	}
	if !feasible {
		return false, nil
	}
	reachable, err := stageEvidenceTargetReachableWithoutOccurrenceReuse(target, index, budget)
	if err != nil {
		return false, err
	}
	if !reachable {
		return false, nil
	}
	const frameBytes = int64(64)
	// Every exact segment consumes at least one target byte, so compression of
	// repeated occurrence groups never requires more live frames than the
	// target length plus the root frame.
	frameCount := int64(len(target)) + 1
	auxiliaryBytes := int64(len(maxUsableLength))*8 + int64(len(carriers))*8 + frameCount*frameBytes
	if auxiliaryBytes < 0 || auxiliaryBytes > stageEvidenceMaxOccurrenceAuxiliaryBytes {
		return false, fmt.Errorf("body-free unordered segmentation exceeds fixed occurrence auxiliary byte limit %d", stageEvidenceMaxOccurrenceAuxiliaryBytes)
	}
	if totalCapacity < int64(len(target)) {
		return false, nil
	}
	used := make([]int, len(carriers))
	return stageEvidenceUnorderedSegmentationSearch(target, totalCapacity, maxUsableLength, used, carriers, index, budget)
}

// stageEvidenceTargetReachableWithoutOccurrenceReuse is an exact
// impossibility gate, never a reconstruction witness. It removes the
// one-use-per-occurrence constraint and asks whether the target is reachable
// in that strictly larger segmentation graph. If even the relaxed graph is
// unreachable, no legal distinct-occurrence segmentation can exist. A
// reachable result still enters the occurrence-aware search below.
func stageEvidenceTargetReachableWithoutOccurrenceReuse(target []byte, index stageEvidenceSegmentationIndex, budget *stageEvidenceSegmentationBudget) (bool, error) {
	if len(target) == 0 {
		return false, nil
	}
	wordCount := (len(target) + 1 + 31) / 32
	if cap(budget.prefixScratch) < wordCount {
		budget.prefixScratch = make([]uint32, wordCount)
	} else {
		budget.prefixScratch = budget.prefixScratch[:wordCount]
		clear(budget.prefixScratch)
	}
	if err := budget.consumeScalarIndexWork(int64(wordCount)); err != nil {
		return false, err
	}
	reachable := budget.prefixScratch
	setReachable := func(offset int) {
		reachable[offset>>5] |= uint32(1) << uint(offset&31)
	}
	isReachable := func(offset int) bool {
		return reachable[offset>>5]&(uint32(1)<<uint(offset&31)) != 0
	}
	setReachable(0)
	if err := budget.consumeScalarIndexWork(int64(len(target))); err != nil {
		return false, err
	}
	for offset := 0; offset < len(target); offset++ {
		if !isReachable(offset) {
			continue
		}
		prefixLimit := len(target) - offset
		if prefixLimit > stageEvidenceSegmentationPrefixBytes {
			prefixLimit = stageEvidenceSegmentationPrefixBytes
		}
		if err := budget.consumeScalarIndexWork(int64(prefixLimit)); err != nil {
			return false, err
		}
		for prefixLength := 1; prefixLength <= prefixLimit; prefixLength++ {
			bucket := stageEvidenceTargetCandidateBucket(target, offset, prefixLength, index)
			if err := budget.consumeScalarIndexWork(int64(len(bucket))); err != nil {
				return false, err
			}
			matchedLength := -1
			for _, candidate := range bucket {
				length := len(candidate.raw)
				// Buckets are ordered by descending representation length. Once
				// one representation of a length matches, every other matching
				// representation of that length reaches the same offset.
				if length == matchedLength {
					continue
				}
				if length >= len(target) || offset+length > len(target) {
					continue
				}
				matches, err := stageEvidenceRepresentationMatches(target[offset:offset+length], candidate.raw, budget)
				if err != nil {
					return false, err
				}
				if !matches {
					continue
				}
				matchedLength = length
				next := offset + length
				if next == len(target) {
					return true, nil
				}
				setReachable(next)
			}
		}
	}
	return false, nil
}

type stageEvidenceUnorderedSearchFrame struct {
	offset            int
	segmentCount      int
	availableCapacity int64
	prefixLength      int
	candidateIndex    int
	chosenOccurrence  int
}

func stageEvidenceUnorderedSegmentationSearch(target []byte, totalCapacity int64, maxUsableLength []int, used []int, carriers []stageEvidenceCarrierOccurrence, index stageEvidenceSegmentationIndex, budget *stageEvidenceSegmentationBudget) (bool, error) {
	frames := make([]stageEvidenceUnorderedSearchFrame, 0, len(target)+1)
	push := func(frame stageEvidenceUnorderedSearchFrame) error {
		budget.statesRemaining--
		if budget.statesRemaining < 0 {
			return stageEvidenceStateBoundError
		}
		frames = append(frames, frame)
		return nil
	}
	pop := func() {
		frame := frames[len(frames)-1]
		if frame.chosenOccurrence >= 0 {
			used[frame.chosenOccurrence]--
		}
		frames = frames[:len(frames)-1]
	}
	if err := push(stageEvidenceUnorderedSearchFrame{availableCapacity: totalCapacity, prefixLength: 1, chosenOccurrence: -1}); err != nil {
		return false, err
	}
	for len(frames) != 0 {
		frame := &frames[len(frames)-1]
		if frame.offset == len(target) {
			if frame.segmentCount >= 2 {
				return true, nil
			}
			pop()
			continue
		}
		if frame.availableCapacity < int64(len(target)-frame.offset) {
			pop()
			continue
		}
		prefixLimit := len(target) - frame.offset
		if prefixLimit > stageEvidenceSegmentationPrefixBytes {
			prefixLimit = stageEvidenceSegmentationPrefixBytes
		}
		if frame.prefixLength > prefixLimit {
			pop()
			continue
		}
		bucket := stageEvidenceTargetCandidateBucket(target, frame.offset, frame.prefixLength, index)
		if frame.candidateIndex >= len(bucket) {
			frame.prefixLength++
			frame.candidateIndex = 0
			continue
		}
		candidate := bucket[frame.candidateIndex]
		frame.candidateIndex++
		multiplicity := stageEvidenceCarrierOccurrenceMultiplicity(carriers[candidate.occurrence])
		if multiplicity <= 0 {
			return false, fmt.Errorf("body-free unordered segmentation occurrence group has nonpositive multiplicity")
		}
		if used[candidate.occurrence] >= multiplicity || len(candidate.raw) >= len(target) || frame.offset+len(candidate.raw) > len(target) {
			continue
		}
		matches, err := stageEvidenceRepresentationMatches(target[frame.offset:frame.offset+len(candidate.raw)], candidate.raw, budget)
		if err != nil {
			return false, err
		}
		if !matches {
			continue
		}
		used[candidate.occurrence]++
		if err := push(stageEvidenceUnorderedSearchFrame{
			offset: frame.offset + len(candidate.raw), segmentCount: frame.segmentCount + 1,
			availableCapacity: frame.availableCapacity - int64(maxUsableLength[candidate.occurrence]),
			prefixLength:      1, chosenOccurrence: candidate.occurrence,
		}); err != nil {
			used[candidate.occurrence]--
			return false, err
		}
	}
	return false, nil
}

func stageEvidenceRepresentationMatches(target, candidate []byte, budget *stageEvidenceSegmentationBudget) (bool, error) {
	for index := range candidate {
		budget.comparisonsRemaining--
		if budget.comparisonsRemaining < 0 {
			return false, fmt.Errorf("analysis exceeded the deterministic byte-comparison bound")
		}
		if target[index] != candidate[index] {
			return false, nil
		}
	}
	return true, nil
}

// stageEvidenceTargetHasWrappedTwoOccurrenceSegmentation is retained for direct
// unit callers; the implementation now detects any bounded number of distinct
// scalar occurrences. One occurrence is never reusable through alternate
// representations.
func stageEvidenceTargetHasWrappedTwoOccurrenceSegmentation(target []byte, carriers []stageEvidenceCarrierOccurrence) (bool, error) {
	budget := &stageEvidenceSegmentationBudget{
		statesRemaining:      stageEvidenceSegmentationMaxStates,
		comparisonsRemaining: stageEvidenceAggregateMaxComparisons,
	}
	return stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithBudget(target, carriers, budget)
}

func stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithBudget(target []byte, carriers []stageEvidenceCarrierOccurrence, budget *stageEvidenceSegmentationBudget) (bool, error) {
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		return false, err
	}
	return stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithIndex(target, &index, false, budget)
}

func stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithIndex(target []byte, index *stageEvidenceWrappedIndex, foldHex bool, budget *stageEvidenceSegmentationBudget) (bool, error) {
	if len(target) < 2*stageEvidenceWrappedMinFragmentBytes || !stageEvidenceMultiplicitiesAtLeast(index.multiplicities, 2) {
		return false, nil
	}
	_, feasible, err := stageEvidenceProfileFeasible(target, index.profile, budget)
	if err != nil {
		return false, err
	}
	if !feasible {
		return false, nil
	}
	if int64(len(index.profile.maxLengths))*16 > stageEvidenceMaxOccurrenceAuxiliaryBytes {
		return false, fmt.Errorf("body-free two-occurrence segmentation exceeds fixed occurrence auxiliary byte limit %d", stageEvidenceMaxOccurrenceAuxiliaryBytes)
	}
	prefixLengths, suffixLengths, err := stageEvidenceIndexedWrappedEnds(target, index, foldHex, budget)
	if err != nil {
		return false, err
	}
	// The best and second-best suffixes are sufficient: for each prefix use
	// the best suffix unless it belongs to the same occurrence, in which case
	// use the second-best. This proves the exact two-distinct-occurrence
	// condition in two linear scans instead of an unmetered occurrence square.
	if err := budget.consumeScalarIndexWork(int64(len(suffixLengths)) * 2); err != nil {
		return false, err
	}
	bestSuffixOccurrence, bestSuffixLength, secondSuffixLength := -1, 0, 0
	for occurrence, length := range suffixLengths {
		if length > bestSuffixLength {
			secondSuffixLength = bestSuffixLength
			bestSuffixOccurrence = occurrence
			bestSuffixLength = length
		} else if length > secondSuffixLength {
			secondSuffixLength = length
		}
	}
	for prefixOccurrence, prefixLength := range prefixLengths {
		if prefixLength < stageEvidenceWrappedMinFragmentBytes {
			continue
		}
		suffixLength := bestSuffixLength
		if prefixOccurrence == bestSuffixOccurrence && index.multiplicities[prefixOccurrence] < 2 {
			suffixLength = secondSuffixLength
		}
		if suffixLength >= stageEvidenceWrappedMinFragmentBytes && prefixLength+suffixLength >= len(target) {
			return true, nil
		}
	}
	return false, nil
}

func stageEvidenceTargetHasWrappedSegmentationWithBudget(target []byte, carriers []stageEvidenceCarrierOccurrence, budget *stageEvidenceSegmentationBudget) (bool, error) {
	index, err := newStageEvidenceWrappedIndexBounded(carriers, budget)
	if err != nil {
		return false, err
	}
	return stageEvidenceTargetHasWrappedSegmentationWithIndex(target, &index, false, budget)
}

func stageEvidenceTargetHasWrappedSegmentationWithIndex(target []byte, index *stageEvidenceWrappedIndex, foldHex bool, budget *stageEvidenceSegmentationBudget) (bool, error) {
	if len(target) < 2 || !stageEvidenceMultiplicitiesAtLeast(index.multiplicities, 2) {
		return false, nil
	}
	_, feasible, err := stageEvidenceProfileFeasible(target, index.profile, budget)
	if err != nil {
		return false, err
	}
	if !feasible {
		return false, nil
	}
	return stageEvidenceTargetHasWrappedSegmentationSearchWithCache(target, index, foldHex, nil, budget)
}

// stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex performs the
// two-occurrence fast path and the general distinct-occurrence search as one
// bounded operation. Its exact prefix candidates are materialized once and
// reused at offset zero by the general search; candidate identities remain
// occurrence-specific and the witness search remains unchanged.
func stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex(target []byte, index *stageEvidenceWrappedIndex, foldHex bool, budget *stageEvidenceSegmentationBudget) (bool, error) {
	if len(target) < 2 || !stageEvidenceMultiplicitiesAtLeast(index.multiplicities, 2) {
		return false, nil
	}
	_, feasible, err := stageEvidenceProfileFeasible(target, index.profile, budget)
	if err != nil {
		return false, fmt.Errorf("shared feasibility gate: %w", err)
	}
	if !feasible {
		return false, nil
	}
	reachable, err := stageEvidenceTargetReachableWithWrappedLengthUpperBounds(target, index, foldHex, budget)
	if err != nil {
		return false, fmt.Errorf("wrapped upper-bound reachability gate: %w", err)
	}
	if !reachable {
		return false, nil
	}
	// Reserve the general-search cache before materializing the reusable prefix
	// candidates. The entry and backing slice are charged by their existing
	// helpers exactly as they would be in an uncached offset-zero query.
	if err := budget.consumeCandidateBytes(128); err != nil {
		return false, fmt.Errorf("two-occurrence gate: %w", err)
	}
	cache := map[int][]stageEvidenceWrappedCandidate{}
	prefixCandidates, err := stageEvidenceIndexedWrappedCandidates(target, 0, index, foldHex, true, budget)
	if err != nil {
		return false, fmt.Errorf("two-occurrence gate: %w", err)
	}
	if err := stageEvidenceCacheWrappedCandidates(cache, 0, prefixCandidates, budget); err != nil {
		return false, fmt.Errorf("two-occurrence gate: %w", err)
	}
	bestSuffixOccurrence, bestSuffixLength, secondSuffixLength, err := stageEvidenceIndexedWrappedBestSuffixes(target, index, foldHex, budget)
	if err != nil {
		return false, fmt.Errorf("two-occurrence gate: %w", err)
	}
	if err := budget.consumeScalarIndexWork(int64(len(prefixCandidates))); err != nil {
		return false, fmt.Errorf("two-occurrence gate: %w", err)
	}
	for _, prefix := range prefixCandidates {
		suffixLength := bestSuffixLength
		if prefix.occurrence == bestSuffixOccurrence && index.multiplicities[prefix.occurrence] < 2 {
			suffixLength = secondSuffixLength
		}
		if suffixLength >= stageEvidenceWrappedMinFragmentBytes && prefix.length+suffixLength >= len(target) {
			return true, nil
		}
	}
	reconstructed, err := stageEvidenceTargetHasWrappedSegmentationSearchWithCache(target, index, foldHex, cache, budget)
	if err != nil {
		return false, fmt.Errorf("multi-occurrence gate: %w", err)
	}
	return reconstructed, nil
}

func stageEvidenceTargetHasWrappedSegmentationSearchWithCache(target []byte, index *stageEvidenceWrappedIndex, foldHex bool, cache map[int][]stageEvidenceWrappedCandidate, budget *stageEvidenceSegmentationBudget) (bool, error) {
	// Every wrapped segment consumes at least three target bytes. Repeated
	// occurrence groups therefore need no more live frames than this exact
	// target-derived ceiling.
	maxFrameCount := len(target)/stageEvidenceWrappedMinFragmentBytes + 1
	const frameBytes = int64(64)
	auxiliaryBytes := int64(len(index.profile.maxLengths))*8 + 2*int64(len(target)+1) + int64(maxFrameCount)*frameBytes
	if auxiliaryBytes < 0 || auxiliaryBytes > stageEvidenceMaxOccurrenceAuxiliaryBytes {
		return false, fmt.Errorf("body-free wrapped segmentation exceeds fixed occurrence auxiliary byte limit %d", stageEvidenceMaxOccurrenceAuxiliaryBytes)
	}
	used := make([]int, len(index.profile.maxLengths))
	if cache == nil {
		// Reserve the cache map itself before allocation. Individual entries and
		// candidate backing arrays are charged when they are first materialized.
		if err := budget.consumeCandidateBytes(128); err != nil {
			return false, err
		}
		cache = map[int][]stageEvidenceWrappedCandidate{}
	}
	reachable := make([]bool, len(target)+1)
	reachable[0] = true
	for offset := 0; offset < len(target); offset++ {
		if !reachable[offset] {
			continue
		}
		candidates, cached := cache[offset]
		if !cached {
			var err error
			candidates, err = stageEvidenceIndexedWrappedCandidates(target, offset, index, foldHex, offset == 0, budget)
			if err != nil {
				return false, err
			}
			if err := stageEvidenceCacheWrappedCandidates(cache, offset, candidates, budget); err != nil {
				return false, err
			}
		}
		if len(candidates) == 0 {
			continue
		}
		// Every length from the minimum through the longest match is a legal
		// substring of the same matched representation. Candidate intervals at
		// one offset are nested, so their union is exactly this single range.
		longest := candidates[0].length
		if err := budget.consumeScalarIndexWork(int64(longest - stageEvidenceWrappedMinFragmentBytes + 1)); err != nil {
			return false, err
		}
		for length := stageEvidenceWrappedMinFragmentBytes; length <= longest; length++ {
			reachable[offset+length] = true
		}
	}
	if !reachable[len(target)] {
		return false, nil
	}
	canFinish := make([]bool, len(target)+1)
	canFinish[len(target)] = true
	for offset := len(target) - 1; offset >= 0; offset-- {
		if !reachable[offset] {
			continue
		}
		candidates := cache[offset]
		if len(candidates) == 0 {
			continue
		}
		longest := candidates[0].length
		if err := budget.consumeScalarIndexWork(int64(longest - stageEvidenceWrappedMinFragmentBytes + 1)); err != nil {
			return false, err
		}
		for length := stageEvidenceWrappedMinFragmentBytes; length <= longest; length++ {
			if canFinish[offset+length] {
				canFinish[offset] = true
				break
			}
		}
	}
	return stageEvidenceWrappedSegmentationSearch(target, used, cache, canFinish, maxFrameCount, index, foldHex, budget)
}

// stageEvidenceSegmentationFeasible is an exact impossibility gate. Capacity
// is the maximum number of target bytes each distinct occurrence could supply;
// byte frequency is the maximum count of every byte available from any one of
// that occurrence's alternate representations. Failure is proof that no legal
// distinct-occurrence segmentation exists, so the exponential search is
// skipped without weakening detection.
func stageEvidenceSegmentationFeasible(target []byte, carriers []stageEvidenceCarrierOccurrence, exact bool, budget *stageEvidenceSegmentationBudget) ([]int, int64, bool, error) {
	if len(carriers) > stageEvidenceMaxCarrierOccurrences {
		return nil, 0, false, fmt.Errorf("body-free segmentation exceeds fixed occurrence-group limit %d", stageEvidenceMaxCarrierOccurrences)
	}
	maxLengths := make([]int, len(carriers))
	var available [256]int64
	totalCapacity := int64(0)
	for occurrence, carrier := range carriers {
		multiplicity := stageEvidenceCarrierOccurrenceMultiplicity(carrier)
		if multiplicity <= 0 {
			return nil, 0, false, fmt.Errorf("body-free segmentation occurrence group has nonpositive multiplicity")
		}
		var occurrenceMax [256]int
		for _, representation := range carrier.representations {
			if exact && len(representation) >= len(target) {
				continue
			}
			length := len(representation)
			if !exact && length >= len(target) {
				length = len(target) - 1
			}
			if length > maxLengths[occurrence] {
				maxLengths[occurrence] = length
			}
			var counts [256]int
			if err := budget.consumeScalarIndexWork(int64(len(representation))); err != nil {
				return nil, 0, false, err
			}
			for _, current := range representation {
				counts[current]++
			}
			for current, count := range counts {
				if count > occurrenceMax[current] {
					occurrenceMax[current] = count
				}
			}
		}
		maximumLength := int64(maxLengths[occurrence])
		if maximumLength != 0 && int64(multiplicity) > math.MaxInt64/maximumLength {
			return nil, 0, false, fmt.Errorf("body-free segmentation capacity overflows int64")
		}
		groupCapacity := maximumLength * int64(multiplicity)
		if groupCapacity > math.MaxInt64-totalCapacity {
			return nil, 0, false, fmt.Errorf("body-free segmentation capacity overflows int64")
		}
		totalCapacity += groupCapacity
		for current, count := range occurrenceMax {
			if count != 0 && int64(multiplicity) > math.MaxInt64/int64(count) {
				return nil, 0, false, fmt.Errorf("body-free segmentation frequency capacity overflows int64")
			}
			groupAvailable := int64(count) * int64(multiplicity)
			if groupAvailable > math.MaxInt64-available[current] {
				return nil, 0, false, fmt.Errorf("body-free segmentation frequency capacity overflows int64")
			}
			available[current] += groupAvailable
		}
	}
	if totalCapacity < int64(len(target)) {
		return maxLengths, totalCapacity, false, nil
	}
	var required [256]int64
	if err := budget.consumeScalarIndexWork(int64(len(target))); err != nil {
		return nil, 0, false, err
	}
	for _, current := range target {
		required[current]++
	}
	for current, count := range required {
		if available[current] < count {
			return maxLengths, totalCapacity, false, nil
		}
	}
	return maxLengths, totalCapacity, true, nil
}

type stageEvidenceWrappedCandidate struct {
	occurrence int
	length     int
}

type stageEvidenceWrappedSearchFrame struct {
	offset           int
	segmentCount     int
	candidateIndex   int
	candidateLength  int
	chosenOccurrence int
}

func stageEvidenceWrappedSegmentationSearch(target []byte, used []int, cache map[int][]stageEvidenceWrappedCandidate, canFinish []bool, maxFrameCount int, index *stageEvidenceWrappedIndex, foldHex bool, budget *stageEvidenceSegmentationBudget) (bool, error) {
	frames := make([]stageEvidenceWrappedSearchFrame, 0, maxFrameCount)
	push := func(frame stageEvidenceWrappedSearchFrame) error {
		budget.statesRemaining--
		if budget.statesRemaining < 0 {
			return stageEvidenceAggregateStateBoundError
		}
		frames = append(frames, frame)
		return nil
	}
	pop := func() {
		frame := frames[len(frames)-1]
		if frame.chosenOccurrence >= 0 {
			used[frame.chosenOccurrence]--
		}
		frames = frames[:len(frames)-1]
	}
	if err := push(stageEvidenceWrappedSearchFrame{chosenOccurrence: -1}); err != nil {
		return false, err
	}
	for len(frames) != 0 {
		frame := &frames[len(frames)-1]
		if frame.offset == len(target) {
			if frame.segmentCount >= 2 {
				return true, nil
			}
			pop()
			continue
		}
		if !canFinish[frame.offset] {
			pop()
			continue
		}
		candidates, cached := cache[frame.offset]
		if !cached {
			var err error
			candidates, err = stageEvidenceIndexedWrappedCandidates(target, frame.offset, index, foldHex, frame.offset == 0, budget)
			if err != nil {
				return false, err
			}
			if err := stageEvidenceCacheWrappedCandidates(cache, frame.offset, candidates, budget); err != nil {
				return false, err
			}
		}
		if frame.candidateIndex >= len(candidates) {
			pop()
			continue
		}
		candidate := candidates[frame.candidateIndex]
		// Charge every candidate disposition or legal-length branch. A used
		// occurrence is skipped once; an unused occurrence explores every
		// substring length from its exact maximum down to the three-byte floor.
		if err := budget.consumeScalarIndexWork(1); err != nil {
			return false, err
		}
		multiplicity := index.multiplicities[candidate.occurrence]
		if multiplicity <= 0 {
			return false, fmt.Errorf("body-free wrapped segmentation occurrence group has nonpositive multiplicity")
		}
		if used[candidate.occurrence] >= multiplicity {
			frame.candidateIndex++
			frame.candidateLength = 0
			continue
		}
		if frame.candidateLength == 0 {
			frame.candidateLength = candidate.length
		}
		length := frame.candidateLength
		if length == stageEvidenceWrappedMinFragmentBytes {
			frame.candidateIndex++
			frame.candidateLength = 0
		} else {
			frame.candidateLength--
		}
		if !canFinish[frame.offset+length] {
			continue
		}
		used[candidate.occurrence]++
		if err := push(stageEvidenceWrappedSearchFrame{
			offset: frame.offset + length, segmentCount: frame.segmentCount + 1,
			chosenOccurrence: candidate.occurrence,
		}); err != nil {
			used[candidate.occurrence]--
			return false, err
		}
	}
	return false, nil
}

func stageEvidenceWrappedCandidates(target []byte, offset int, carriers []stageEvidenceCarrierOccurrence, initial bool, budget *stageEvidenceSegmentationBudget) ([]stageEvidenceWrappedCandidate, error) {
	remaining := target[offset:]
	prefixTable, err := budget.stageEvidencePatternPrefixTable(remaining)
	if err != nil {
		return nil, err
	}
	var candidates []stageEvidenceWrappedCandidate
	for occurrence, carrier := range carriers {
		longest := 0
		for _, representation := range carrier.representations {
			length, err := stageEvidenceLongestPatternPrefixContained(remaining, prefixTable, representation, false, budget)
			if err != nil {
				return nil, err
			}
			if length > longest {
				longest = length
			}
		}
		if longest >= len(remaining) && initial {
			longest = len(remaining) - 1
		}
		if longest >= stageEvidenceWrappedMinFragmentBytes {
			if err := budget.consumeCandidateBytes(32); err != nil {
				return nil, err
			}
			candidates = append(candidates, stageEvidenceWrappedCandidate{occurrence: occurrence, length: longest})
		}
	}
	sort.SliceStable(candidates, func(left, right int) bool {
		if candidates[left].length != candidates[right].length {
			return candidates[left].length > candidates[right].length
		}
		return candidates[left].occurrence < candidates[right].occurrence
	})
	return candidates, nil
}

func stageEvidenceCacheWrappedCandidates(cache map[int][]stageEvidenceWrappedCandidate, offset int, candidates []stageEvidenceWrappedCandidate, budget *stageEvidenceSegmentationBudget) error {
	if _, exists := cache[offset]; exists {
		return nil
	}
	// A conservative map-entry, slice-header, and allocator/bucket allowance.
	// Candidate backing storage was charged before append.
	if err := budget.consumeCandidateBytes(128); err != nil {
		return err
	}
	cache[offset] = candidates
	return nil
}

func (budget *stageEvidenceSegmentationBudget) stageEvidencePatternPrefixTable(pattern []byte) ([]uint32, error) {
	if cap(budget.prefixScratch) < len(pattern) {
		budget.prefixScratch = make([]uint32, len(pattern))
	} else {
		budget.prefixScratch = budget.prefixScratch[:len(pattern)]
	}
	table := budget.prefixScratch
	if len(table) != 0 {
		table[0] = 0
	}
	for index := 1; index < len(pattern); index++ {
		matched := int(table[index-1])
		for matched > 0 {
			equal, err := stageEvidenceBudgetedByteEqual(pattern[index], pattern[matched], budget)
			if err != nil {
				return nil, err
			}
			if equal {
				break
			}
			matched = int(table[matched-1])
		}
		equal, err := stageEvidenceBudgetedByteEqual(pattern[index], pattern[matched], budget)
		if err != nil {
			return nil, err
		}
		if equal {
			matched++
		}
		table[index] = uint32(matched)
	}
	return table, nil
}

func stageEvidenceLongestPatternPrefixContained(pattern []byte, prefixTable []uint32, representation []byte, reverseRepresentation bool, budget *stageEvidenceSegmentationBudget) (int, error) {
	if len(pattern) == 0 || len(representation) == 0 {
		return 0, nil
	}
	matched, longest := 0, 0
	for index := 0; index < len(representation); index++ {
		value := representation[index]
		if reverseRepresentation {
			value = representation[len(representation)-1-index]
		}
		for matched > 0 {
			equal, err := stageEvidenceBudgetedByteEqual(value, pattern[matched], budget)
			if err != nil {
				return 0, err
			}
			if equal {
				break
			}
			matched = int(prefixTable[matched-1])
		}
		equal, err := stageEvidenceBudgetedByteEqual(value, pattern[matched], budget)
		if err != nil {
			return 0, err
		}
		if equal {
			matched++
			if matched > longest {
				longest = matched
			}
			if matched == len(pattern) {
				matched = int(prefixTable[matched-1])
			}
		}
	}
	return longest, nil
}

func stageEvidenceBudgetedByteEqual(left, right byte, budget *stageEvidenceSegmentationBudget) (bool, error) {
	budget.comparisonsRemaining--
	if budget.comparisonsRemaining < 0 {
		return false, fmt.Errorf("analysis exceeded the deterministic byte-comparison bound (aggregate budget)")
	}
	return left == right, nil
}

func validateExactStageCompileInputs(stageKind string, bindingRaw []byte, inputs StageCompileInputs, lineage []StageEvidenceCommitment) (*stageEvidenceValidation, error) {
	expected := map[stageMaterialCoordinate]stageExpectedMaterial{}
	targets := map[stageMaterialCoordinate]string{}
	var (
		stageValidation              stageValidationBinding
		evidenceBinding              *evidenceIntakeStageBinding
		semanticBinding              *semanticExtractionStageBinding
		graphBinding                 *graphCompileStageBinding
		organizationScopeAuthorities = map[stageMaterialCoordinate]string{}
	)
	addExpected := func(coordinate stageMaterialCoordinate, digest string) error {
		if err := validateStageMaterialCoordinate(coordinate); err != nil {
			return err
		}
		if !isLowerSHA256(digest) {
			return fmt.Errorf("material %s/%s/%s does not bind a lowercase raw SHA-256", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		if prior, exists := expected[coordinate]; exists && prior.digest != digest {
			return fmt.Errorf("material coordinate %s/%s/%s aliases two raw digests", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		expected[coordinate] = stageExpectedMaterial{coordinate: coordinate, digest: digest}
		return nil
	}
	addPin := func(pin immutableStageArtifactPin) error {
		return addExpected(stageCoordinateForPin(pin), pin.RawSHA256)
	}
	addIdentity := func(identity stageArtifactIdentity) error {
		return addExpected(stageCoordinateForIdentity(identity), identity.RawSHA256)
	}
	addTarget := func(identity stageArtifactIdentity) error {
		if err := addIdentity(identity); err != nil {
			return err
		}
		coordinate := stageCoordinateForIdentity(identity)
		if _, duplicate := targets[coordinate]; duplicate {
			return fmt.Errorf("validation target %s/%s/%s is duplicated", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		targets[coordinate] = identity.RawSHA256
		return nil
	}

	switch stageKind {
	case stageEvidenceIntake:
		var binding evidenceIntakeStageBinding
		if err := decodeEvidenceIntakeBinding(bindingRaw, &binding); err != nil {
			return nil, err
		}
		stageValidation = binding.StageValidation
		evidenceBinding = &binding
		for _, pin := range []immutableStageArtifactPin{
			binding.StageValidation.Schema, binding.StageValidation.Profile,
			binding.AuthorityPins.OODGraph, binding.AuthorityPins.GrandVision,
			binding.AuthorityPins.SourceRecord, binding.AuthorityPins.ExtensionProtocol,
		} {
			if err := addPin(pin); err != nil {
				return nil, err
			}
		}
		for _, pin := range []immutableStageArtifactPin{
			binding.AuthorityPins.OODGraph, binding.AuthorityPins.GrandVision,
			binding.AuthorityPins.SourceRecord, binding.AuthorityPins.ExtensionProtocol,
		} {
			organizationScopeAuthorities[stageCoordinateForPin(pin)] = pin.RawSHA256
		}
		if err := addTarget(binding.SelectionRoster); err != nil {
			return nil, err
		}
		for _, manifest := range binding.EvidenceManifests {
			identity := stageArtifactIdentity{Role: manifest.Role, ID: manifest.ArtifactID, Version: manifest.ArtifactVersion, RawSHA256: manifest.ArtifactRawSHA256}
			if err := addTarget(identity); err != nil {
				return nil, err
			}
		}
	case stageSemanticExtraction:
		var binding semanticExtractionStageBinding
		if err := decodeSemanticExtractionBinding(bindingRaw, &binding); err != nil {
			return nil, err
		}
		stageValidation = binding.StageValidation
		semanticBinding = &binding
		for _, pin := range []immutableStageArtifactPin{binding.StageValidation.Schema, binding.StageValidation.Profile, binding.ApplicabilityProfile} {
			if err := addPin(pin); err != nil {
				return nil, err
			}
		}
		applicabilityIdentity := stageArtifactIdentity{
			Role: binding.ApplicabilityProfile.Role, ID: binding.ApplicabilityProfile.ID,
			Version: binding.ApplicabilityProfile.Version, RawSHA256: binding.ApplicabilityProfile.RawSHA256,
		}
		targets[stageCoordinateForIdentity(applicabilityIdentity)] = applicabilityIdentity.RawSHA256
		for _, derivation := range binding.DerivationBindings {
			if err := addPin(derivation.Extractor); err != nil {
				return nil, err
			}
			if err := addPin(derivation.Schema); err != nil {
				return nil, err
			}
		}
		for _, output := range binding.ArtifactOutputs {
			if err := addTarget(stageArtifactIdentity{Role: output.Role, ID: output.ArtifactID, Version: output.ArtifactVersion, RawSHA256: output.ArtifactRawSHA256}); err != nil {
				return nil, err
			}
		}
	case stageGraphCompile:
		var binding graphCompileStageBinding
		if err := decodeGraphCompileBinding(bindingRaw, &binding); err != nil {
			return nil, err
		}
		stageValidation = binding.StageValidation
		graphBinding = &binding
		for _, pin := range []immutableStageArtifactPin{binding.StageValidation.Schema, binding.StageValidation.Profile} {
			if err := addPin(pin); err != nil {
				return nil, err
			}
		}
		for _, dependency := range binding.DependencyArtifacts {
			if err := addTarget(dependency); err != nil {
				return nil, err
			}
		}
		if err := addTarget(binding.Plan); err != nil {
			return nil, err
		}
	case stageFullFactory:
		var binding fullFactoryStageBinding
		if err := decodeClosedStageJSON(bindingRaw, &binding, "stage_validation"); err != nil {
			return nil, err
		}
		stageValidation = binding.StageValidation
		for _, pin := range []immutableStageArtifactPin{binding.StageValidation.Schema, binding.StageValidation.Profile} {
			if err := addPin(pin); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unknown stage_kind %q", stageKind)
	}

	materials, err := indexExactStageMaterials(inputs.Materials)
	if err != nil {
		return nil, err
	}
	profileCoordinate := stageCoordinateForPin(stageValidation.Profile)
	profileSchemaCoordinate := stageCoordinateForPin(stageValidation.Schema)
	profileMaterial, ok := materials[profileCoordinate]
	if !ok {
		return nil, fmt.Errorf("stage validation profile material %s/%s/%s is absent", profileCoordinate.Role, profileCoordinate.ID, profileCoordinate.Version)
	}
	profileSchemaMaterial, ok := materials[profileSchemaCoordinate]
	if !ok {
		return nil, fmt.Errorf("stage validation profile schema material %s/%s/%s is absent", profileSchemaCoordinate.Role, profileSchemaCoordinate.ID, profileSchemaCoordinate.Version)
	}
	if sha256Hex(profileMaterial.Raw) != stageValidation.Profile.RawSHA256 || sha256Hex(profileSchemaMaterial.Raw) != stageValidation.Schema.RawSHA256 {
		return nil, fmt.Errorf("stage validation profile or profile-schema bytes do not match their exact request pins")
	}
	if err := scanStageMaterialBytes(profileMaterial, false); err != nil {
		return nil, err
	}
	if err := scanStageMaterialBytes(profileSchemaMaterial, true); err != nil {
		return nil, err
	}
	if err := validateValidationProfileBindings(
		[]validationProfileBinding{{
			Role: stageValidation.Profile.Role, ArtifactID: stageValidation.Profile.ID, ArtifactVersion: stageValidation.Profile.Version,
			ArtifactSHA256: stageValidation.Profile.RawSHA256, SchemaID: stageValidation.Schema.ID,
			SchemaVersion: stageValidation.Schema.Version, SchemaSHA256: stageValidation.Schema.RawSHA256,
		}},
		[]validationProfileArtifact{{ID: profileMaterial.ID, Version: profileMaterial.Version, Bytes: profileMaterial.Raw}},
		[]validationProfileSchema{{ID: profileSchemaMaterial.ID, Version: profileSchemaMaterial.Version, Bytes: profileSchemaMaterial.Raw}},
	); err != nil {
		return nil, fmt.Errorf("stage validation profile does not validate against its exact bound schema: %w", err)
	}
	profile, err := decodeStageValidationProfile(profileMaterial.Raw, stageKind, stageValidation.Profile)
	if err != nil {
		return nil, err
	}
	// The validated profile's exact artifact-to-schema bindings are the sole
	// target-schema authority. Request-specific schema slots would duplicate
	// that mapping and permit the two surfaces to drift.
	schemaAuthorities := map[stageMaterialCoordinate]struct{}{profileSchemaCoordinate: {}}
	if semanticBinding != nil {
		for _, derivation := range semanticBinding.DerivationBindings {
			schemaAuthorities[stageCoordinateForPin(derivation.Schema)] = struct{}{}
		}
	}
	profileTargets := map[stageMaterialCoordinate]struct{}{}
	validationBindings := make([]validationProfileBinding, 0, len(profile.BoundArtifactSchemas))
	validationArtifacts := make([]validationProfileArtifact, 0, len(profile.BoundArtifactSchemas))
	validationSchemas := make([]validationProfileSchema, 0, len(profile.BoundArtifactSchemas))
	validationSchemaDigests := make(map[stageMaterialCoordinate]string, len(profile.BoundArtifactSchemas))
	validationSchemaDigestOwners := make(map[string]stageMaterialCoordinate, len(profile.BoundArtifactSchemas))
	for _, profileBinding := range profile.BoundArtifactSchemas {
		artifactCoordinate := stageMaterialCoordinate{Role: profileBinding.Role, ID: profileBinding.ArtifactID, Version: profileBinding.ArtifactVersion}
		wantDigest, target := targets[artifactCoordinate]
		if !target {
			return nil, fmt.Errorf("stage validation profile binds orphan artifact role %s coordinate %s/%s", profileBinding.Role, profileBinding.ArtifactID, profileBinding.ArtifactVersion)
		}
		if wantDigest != profileBinding.ArtifactRawSHA256 {
			return nil, fmt.Errorf("stage validation profile artifact %s digest differs from the request binding", profileBinding.Role)
		}
		if _, duplicate := profileTargets[artifactCoordinate]; duplicate {
			return nil, fmt.Errorf("stage validation profile duplicates artifact role %s coordinate %s/%s", profileBinding.Role, profileBinding.ArtifactID, profileBinding.ArtifactVersion)
		}
		profileTargets[artifactCoordinate] = struct{}{}
		artifact, exists := materials[artifactCoordinate]
		if !exists {
			return nil, fmt.Errorf("stage validation profile artifact %s/%s/%s has no exact bytes", artifactCoordinate.Role, artifactCoordinate.ID, artifactCoordinate.Version)
		}
		schemaCoordinate := stageMaterialCoordinate{Role: profileBinding.SchemaRole, ID: profileBinding.SchemaID, Version: profileBinding.SchemaVersion}
		schemaAuthorities[schemaCoordinate] = struct{}{}
		if err := addExpected(schemaCoordinate, profileBinding.SchemaRawSHA256); err != nil {
			return nil, err
		}
		schema, exists := materials[schemaCoordinate]
		if !exists {
			return nil, fmt.Errorf("stage validation profile schema %s/%s/%s has no exact bytes", schemaCoordinate.Role, schemaCoordinate.ID, schemaCoordinate.Version)
		}
		if sha256Hex(artifact.Raw) != profileBinding.ArtifactRawSHA256 || sha256Hex(schema.Raw) != profileBinding.SchemaRawSHA256 {
			return nil, fmt.Errorf("stage validation profile binding %s does not match supplied exact artifact/schema bytes", profileBinding.Role)
		}
		validationBindings = append(validationBindings, validationProfileBinding{
			Role: profileBinding.Role, ArtifactID: profileBinding.ArtifactID, ArtifactVersion: profileBinding.ArtifactVersion,
			ArtifactSHA256: profileBinding.ArtifactRawSHA256, SchemaID: profileBinding.SchemaID,
			SchemaVersion: profileBinding.SchemaVersion, SchemaSHA256: profileBinding.SchemaRawSHA256,
		})
		validationArtifacts = append(validationArtifacts, validationProfileArtifact{ID: artifact.ID, Version: artifact.Version, Bytes: artifact.Raw})
		if priorDigest, reused := validationSchemaDigests[schemaCoordinate]; reused {
			if priorDigest != profileBinding.SchemaRawSHA256 {
				return nil, fmt.Errorf("stage validation schema coordinate %s/%s/%s aliases two raw digests", schemaCoordinate.Role, schemaCoordinate.ID, schemaCoordinate.Version)
			}
			continue
		}
		if priorCoordinate, aliased := validationSchemaDigestOwners[profileBinding.SchemaRawSHA256]; aliased {
			return nil, fmt.Errorf("stage validation schema digest %s aliases %s/%s/%s and %s/%s/%s",
				profileBinding.SchemaRawSHA256,
				priorCoordinate.Role, priorCoordinate.ID, priorCoordinate.Version,
				schemaCoordinate.Role, schemaCoordinate.ID, schemaCoordinate.Version)
		}
		validationSchemaDigests[schemaCoordinate] = profileBinding.SchemaRawSHA256
		validationSchemaDigestOwners[profileBinding.SchemaRawSHA256] = schemaCoordinate
		validationSchemas = append(validationSchemas, validationProfileSchema{ID: schema.ID, Version: schema.Version, Bytes: schema.Raw})
	}
	if len(profileTargets) != len(targets) {
		missing := make([]string, 0)
		for coordinate := range targets {
			if _, found := profileTargets[coordinate]; !found {
				missing = append(missing, coordinate.Role+"/"+coordinate.ID+"/"+coordinate.Version)
			}
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("stage validation profile omits required artifact bindings: %s", strings.Join(missing, ", "))
	}
	if err := scanExactStageMaterialSecurityWithAuthorities(materials, schemaAuthorities, organizationScopeAuthorities); err != nil {
		return nil, err
	}
	if len(validationBindings) > 0 {
		if err := validateValidationProfileBindings(validationBindings, validationArtifacts, validationSchemas); err != nil {
			return nil, fmt.Errorf("exact stage artifacts fail their bound validation schemas: %w", err)
		}
	}
	for _, coordinate := range sortedStageMaterialCoordinateKeys(expected) {
		item := expected[coordinate]
		material, found := materials[coordinate]
		if !found {
			return nil, fmt.Errorf("exact material %s/%s/%s is absent", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		if got := sha256Hex(material.Raw); got != item.digest {
			return nil, fmt.Errorf("exact material %s/%s/%s raw digest mismatch: got %s want %s", coordinate.Role, coordinate.ID, coordinate.Version, got, item.digest)
		}
	}
	if len(materials) != len(expected) {
		extras := make([]string, 0)
		for coordinate := range materials {
			if _, bound := expected[coordinate]; !bound {
				extras = append(extras, coordinate.Role+"/"+coordinate.ID+"/"+coordinate.Version)
			}
		}
		sort.Strings(extras)
		return nil, fmt.Errorf("stage compile has unbound exact materials: %s", strings.Join(extras, ", "))
	}
	if err := rejectStageDigestAliasesAcrossInputs(inputs, materials); err != nil {
		return nil, err
	}

	exactBodies := map[string]exactEvidenceBody{}
	commitments := append([]StageEvidenceCommitment(nil), lineage...)
	if evidenceBinding != nil {
		if len(lineage) != 0 {
			return nil, fmt.Errorf("evidence intake stage has inherited evidence commitments")
		}
		exactBodies, commitments, err = validateExactStageEvidence(*evidenceBinding, materials, inputs.EvidenceBodies)
		if err != nil {
			return nil, err
		}
	} else {
		exactBodies, err = validateInheritedStageEvidence(commitments, inputs.EvidenceBodies)
		if err != nil {
			return nil, fmt.Errorf("%s stage exact evidence lineage: %w", stageKind, err)
		}
	}
	if semanticBinding != nil {
		if err := validateSemanticProfileSchemas(*semanticBinding, profile); err != nil {
			return nil, err
		}
	}
	var graphStructural *graphPlanSchemaBindingProof
	if graphBinding != nil {
		proof, proofErr := validateGraphProfileAndDerivedSets(*graphBinding, profile, materials)
		if proofErr != nil {
			return nil, proofErr
		}
		graphStructural = &proof
	} else if len(profile.GraphRowDispositions) != 0 {
		return nil, fmt.Errorf("%s stage validation profile has orphan graph_row_dispositions", stageKind)
	}
	if err := rejectStageEvidenceMaterialDigestAliases(materials, commitments); err != nil {
		return nil, err
	}
	materialProvenance := stageBodyFreeMaterialPointerProofs(profile, stageValidation, materials, exactBodies)
	return &stageEvidenceValidation{
		bodies: exactBodies, commitments: commitments, graphStructural: graphStructural,
		materialProvenance: materialProvenance,
	}, nil
}

func stageCoordinateForPin(pin immutableStageArtifactPin) stageMaterialCoordinate {
	return stageMaterialCoordinate{Role: pin.Role, ID: pin.ID, Version: pin.Version}
}

func stageCoordinateForIdentity(identity stageArtifactIdentity) stageMaterialCoordinate {
	return stageMaterialCoordinate{Role: identity.Role, ID: identity.ID, Version: identity.Version}
}

func validateStageMaterialCoordinate(coordinate stageMaterialCoordinate) error {
	if err := validateStageIdentifier("material role", coordinate.Role); err != nil {
		return err
	}
	if err := validateStageCoordinate("material id", coordinate.ID); err != nil {
		return err
	}
	return validateStageVersion("material version", coordinate.Version)
}

func indexExactStageMaterials(supplied []StageMaterial) (map[stageMaterialCoordinate]StageMaterial, error) {
	if len(supplied) == 0 {
		return nil, fmt.Errorf("stage compile has no exact artifact/schema/profile materials")
	}
	indexed := make(map[stageMaterialCoordinate]StageMaterial, len(supplied))
	digestOwners := map[string]stageMaterialCoordinate{}
	for index, material := range supplied {
		coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
		if err := validateStageMaterialCoordinate(coordinate); err != nil {
			return nil, fmt.Errorf("stage material[%d]: %w", index, err)
		}
		if len(material.Raw) == 0 {
			return nil, fmt.Errorf("stage material %s/%s/%s has no exact bytes", material.Role, material.ID, material.Version)
		}
		if _, duplicate := indexed[coordinate]; duplicate {
			return nil, fmt.Errorf("stage material coordinate %s/%s/%s is duplicated", material.Role, material.ID, material.Version)
		}
		digest := sha256Hex(material.Raw)
		if prior, duplicate := digestOwners[digest]; duplicate {
			return nil, fmt.Errorf("exact material digest %s aliases %s/%s/%s and %s/%s/%s", digest, prior.Role, prior.ID, prior.Version, material.Role, material.ID, material.Version)
		}
		digestOwners[digest] = coordinate
		indexed[coordinate] = material
	}
	return indexed, nil
}

func scanExactStageMaterialSecurity(materials map[stageMaterialCoordinate]StageMaterial, schemaAuthorities map[stageMaterialCoordinate]struct{}) error {
	return scanExactStageMaterialSecurityWithAuthorities(materials, schemaAuthorities, nil)
}

func scanExactStageMaterialSecurityWithAuthorities(materials map[stageMaterialCoordinate]StageMaterial, schemaAuthorities map[stageMaterialCoordinate]struct{}, organizationScopeAuthorities map[stageMaterialCoordinate]string) error {
	coordinates := make([]stageMaterialCoordinate, 0, len(materials))
	for coordinate := range materials {
		coordinates = append(coordinates, coordinate)
	}
	sort.Slice(coordinates, func(left, right int) bool {
		return lengthPrefixedIdentityKey(coordinates[left].Role, coordinates[left].ID, coordinates[left].Version) < lengthPrefixedIdentityKey(coordinates[right].Role, coordinates[right].ID, coordinates[right].Version)
	})
	for _, coordinate := range coordinates {
		_, schemaAuthority := schemaAuthorities[coordinate]
		organizationScopeDigest, organizationScopeAuthority := organizationScopeAuthorities[coordinate]
		if organizationScopeAuthority && sha256Hex(materials[coordinate].Raw) != organizationScopeDigest {
			return fmt.Errorf("stage descriptive-authority material %s/%s/%s raw digest mismatch against its exact authority pin", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		if schemaAuthority && organizationScopeAuthority {
			return fmt.Errorf("stage material %s/%s/%s cannot be both schema and descriptive authority", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		authority := structuredSecurityOrdinary
		if schemaAuthority {
			authority = structuredSecuritySchema
		} else if organizationScopeAuthority {
			authority = structuredSecurityDescriptiveAuthority
		}
		if err := scanStageMaterialBytesWithAuthority(materials[coordinate], authority); err != nil {
			return err
		}
	}
	return nil
}

func scanStageMaterialBytes(material StageMaterial, schemaAuthority bool) error {
	authority := structuredSecurityOrdinary
	if schemaAuthority {
		authority = structuredSecuritySchema
	}
	return scanStageMaterialBytesWithAuthority(material, authority)
}

func scanStageMaterialBytesWithAuthority(material StageMaterial, authority structuredSecurityAuthority) error {
	label := fmt.Sprintf("stage material %s/%s/%s", material.Role, material.ID, material.Version)
	if !utf8.Valid(material.Raw) {
		return fmt.Errorf("%s contains invalid UTF-8", label)
	}
	if credentialShapedValue(string(material.Raw)) || knownCredentialTokenAnywhere(material.Raw) {
		return fmt.Errorf("%s contains credential or secret material", label)
	}
	if stageBytesAreJSONOrJSONL(material.Raw) {
		input := artifactInput{Path: label, Raw: material.Raw, Structured: true}
		err := validateStructuredDependencySecurityWithAuthority(input, authority)
		if err != nil {
			return err
		}
	}
	return nil
}

func stageBytesAreJSONOrJSONL(raw []byte) bool {
	seen := false
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		seen = true
		if err := rejectDuplicateJSONKeys(line); err != nil {
			return false
		}
	}
	return seen
}

func decodeStageValidationProfile(raw []byte, stageKind string, pin immutableStageArtifactPin) (stageValidationProfileDocument, error) {
	var profile stageValidationProfileDocument
	if err := decodeClosedStageJSON(raw, &profile,
		"row_kind", "profile_version", "stage_kind", "profile_id", "bound_artifact_schemas", "graph_row_dispositions"); err != nil {
		return profile, fmt.Errorf("stage validation profile: %w", err)
	}
	if profile.RowKind != stageValidationProfileKind || profile.ProfileVersion != stageContractVersion || profile.StageKind != stageKind || profile.ProfileID != pin.ID {
		return profile, fmt.Errorf("stage validation profile identity/stage discriminator does not equal its exact request binding")
	}
	var object map[string]json.RawMessage
	_ = json.Unmarshal(raw, &object)
	var bindingRows []json.RawMessage
	_ = json.Unmarshal(object["bound_artifact_schemas"], &bindingRows)
	prior := ""
	for index, bindingRaw := range bindingRows {
		if err := requireExactStageKeys(bindingRaw,
			"role", "artifact_id", "artifact_version", "artifact_raw_sha256", "schema_role", "schema_id", "schema_version", "schema_raw_sha256"); err != nil {
			return profile, fmt.Errorf("stage validation profile bound_artifact_schemas[%d]: %w", index, err)
		}
		binding := profile.BoundArtifactSchemas[index]
		coordinateKey := lengthPrefixedIdentityKey(binding.Role, binding.ArtifactID, binding.ArtifactVersion)
		if coordinateKey <= prior {
			return profile, fmt.Errorf("stage validation profile artifact bindings are not unique and strictly ordered")
		}
		prior = coordinateKey
		if err := validateStageMaterialCoordinate(stageMaterialCoordinate{binding.Role, binding.ArtifactID, binding.ArtifactVersion}); err != nil {
			return profile, err
		}
		if err := validateStageMaterialCoordinate(stageMaterialCoordinate{binding.SchemaRole, binding.SchemaID, binding.SchemaVersion}); err != nil {
			return profile, err
		}
		if !isLowerSHA256(binding.ArtifactRawSHA256) || !isLowerSHA256(binding.SchemaRawSHA256) || binding.ArtifactRawSHA256 == binding.SchemaRawSHA256 {
			return profile, fmt.Errorf("stage validation profile binding %s has invalid or aliased raw digests", binding.Role)
		}
	}
	var dispositionRows []json.RawMessage
	_ = json.Unmarshal(object["graph_row_dispositions"], &dispositionRows)
	prior = ""
	for index, dispositionRaw := range dispositionRows {
		if err := requireExactStageKeys(dispositionRaw, "row_kind", "set_kinds"); err != nil {
			return profile, fmt.Errorf("stage validation profile graph_row_dispositions[%d]: %w", index, err)
		}
		disposition := profile.GraphRowDispositions[index]
		if err := validateStageIdentifier("graph row_kind", disposition.RowKind); err != nil {
			return profile, err
		}
		if disposition.RowKind <= prior {
			return profile, fmt.Errorf("graph_row_dispositions are not unique and strictly ordered by row_kind")
		}
		prior = disposition.RowKind
		if len(disposition.SetKinds) == 0 {
			return profile, fmt.Errorf("graph row_kind %s has no set_kinds", disposition.RowKind)
		}
		priorSetKind := ""
		for _, setKind := range disposition.SetKinds {
			if setKind <= priorSetKind {
				return profile, fmt.Errorf("graph row_kind %s set_kinds are not unique and strictly ordered", disposition.RowKind)
			}
			priorSetKind = setKind
			switch setKind {
			case "fact", "gap", "metadata", "subject":
			default:
				return profile, fmt.Errorf("graph row_kind %s has unknown set_kind %q", disposition.RowKind, setKind)
			}
		}
		if slices.Contains(disposition.SetKinds, "metadata") && len(disposition.SetKinds) != 1 {
			return profile, fmt.Errorf("graph row_kind %s combines metadata with a committed graph set", disposition.RowKind)
		}
	}
	return profile, nil
}

func rejectStageDigestAliasesAcrossInputs(inputs StageCompileInputs, materials map[stageMaterialCoordinate]StageMaterial) error {
	ledger := newStageDigestLedger()
	for _, coordinate := range sortedStageMaterialCoordinateKeys(materials) {
		material := materials[coordinate]
		if err := ledger.add("material "+coordinate.Role+"/"+coordinate.ID+"/"+coordinate.Version, sha256Hex(material.Raw)); err != nil {
			return err
		}
	}
	for index, raw := range inputs.PredecessorReceipts {
		parsed, err := parseStageReceipt(raw)
		if err != nil {
			return fmt.Errorf("predecessor receipt %d: %w", index, err)
		}
		if err := ledger.add(fmt.Sprintf("predecessor[%d].receipt_sha256", index), parsed.Summary.ReceiptSHA256); err != nil {
			return err
		}
		if err := ledger.add(fmt.Sprintf("predecessor[%d].output_root_sha256", index), parsed.Summary.OutputRootSHA256); err != nil {
			return err
		}
	}
	return nil
}

type stageEvidenceComponentKey struct {
	manifest stageMaterialCoordinate
	ordinal  uint64
}

type stageEvidenceComponentClaim struct {
	digest string
	bytes  uint64
}

func validateExactStageEvidence(binding evidenceIntakeStageBinding, materials map[stageMaterialCoordinate]StageMaterial, supplied []StageEvidenceBody) (map[string]exactEvidenceBody, []StageEvidenceCommitment, error) {
	manifestBindings := make(map[stageMaterialCoordinate]evidenceManifestStageBinding, len(binding.EvidenceManifests))
	for _, manifest := range binding.EvidenceManifests {
		coordinate := stageMaterialCoordinate{manifest.Role, manifest.ArtifactID, manifest.ArtifactVersion}
		manifestBindings[coordinate] = manifest
	}
	suppliedByComponent := make(map[stageEvidenceComponentKey]StageEvidenceBody, len(supplied))
	for index, body := range supplied {
		coordinate := stageMaterialCoordinate{body.ManifestRole, body.ManifestID, body.ManifestVersion}
		if _, declared := manifestBindings[coordinate]; !declared {
			return nil, nil, fmt.Errorf("exact evidence body[%d] belongs to undeclared manifest %s/%s/%s", index, coordinate.Role, coordinate.ID, coordinate.Version)
		}
		if body.ComponentOrdinal > maxExactStageCount {
			return nil, nil, fmt.Errorf("exact evidence body[%d] component ordinal is unsafe", index)
		}
		key := stageEvidenceComponentKey{manifest: coordinate, ordinal: body.ComponentOrdinal}
		if _, duplicate := suppliedByComponent[key]; duplicate {
			return nil, nil, fmt.Errorf("exact evidence body component %s/%s/%s ordinal %d is duplicated", coordinate.Role, coordinate.ID, coordinate.Version, body.ComponentOrdinal)
		}
		if len(body.Raw) == 0 {
			return nil, nil, fmt.Errorf("exact evidence body %s/%s/%s ordinal %d is empty", coordinate.Role, coordinate.ID, coordinate.Version, body.ComponentOrdinal)
		}
		suppliedByComponent[key] = body
	}

	usedBodies := make(map[stageEvidenceComponentKey]struct{}, len(supplied))
	exactBodies := make(map[string]exactEvidenceBody, len(supplied))
	commitments := make([]StageEvidenceCommitment, 0, len(supplied))
	supplyIndex := 0
	for _, manifestBinding := range binding.EvidenceManifests {
		coordinate := stageMaterialCoordinate{manifestBinding.Role, manifestBinding.ArtifactID, manifestBinding.ArtifactVersion}
		manifest := materials[coordinate]
		claims, err := parseStageEvidenceComponentClaims(manifest.Raw)
		if err != nil {
			return nil, nil, fmt.Errorf("evidence manifest %s/%s/%s: %w", coordinate.Role, coordinate.ID, coordinate.Version, err)
		}
		if uint64(len(claims)) != manifestBinding.BodyCount {
			return nil, nil, fmt.Errorf("evidence manifest %s body_count assertion %d differs from %d validated component rows", coordinate.ID, manifestBinding.BodyCount, len(claims))
		}
		var totalBytes uint64
		for ordinal, claim := range claims {
			key := stageEvidenceComponentKey{manifest: coordinate, ordinal: uint64(ordinal)}
			if supplyIndex >= len(supplied) {
				return nil, nil, fmt.Errorf("exact evidence body roster is missing %s/%s/%s ordinal %d", coordinate.Role, coordinate.ID, coordinate.Version, ordinal)
			}
			orderedBody := supplied[supplyIndex]
			if orderedBody.ManifestRole != coordinate.Role || orderedBody.ManifestID != coordinate.ID || orderedBody.ManifestVersion != coordinate.Version || orderedBody.ComponentOrdinal != uint64(ordinal) {
				return nil, nil, fmt.Errorf("exact evidence body roster is reordered or substituted at index %d", supplyIndex)
			}
			supplyIndex++
			body, found := suppliedByComponent[key]
			if !found {
				return nil, nil, fmt.Errorf("evidence manifest %s component ordinal %d has no supplied exact body bytes", coordinate.ID, ordinal)
			}
			usedBodies[key] = struct{}{}
			digest := sha256Hex(body.Raw)
			if digest != claim.digest || uint64(len(body.Raw)) != claim.bytes {
				return nil, nil, fmt.Errorf("evidence manifest %s component ordinal %d digest/byte claim does not match supplied exact bytes", coordinate.ID, ordinal)
			}
			if err := addExactStageEvidenceContent(exactBodies, digest, body.Raw); err != nil {
				return nil, nil, fmt.Errorf("evidence manifest %s component ordinal %d: %w", coordinate.ID, ordinal, err)
			}
			commitments = append(commitments, StageEvidenceCommitment{
				ManifestRole: coordinate.Role, ManifestID: coordinate.ID, ManifestVersion: coordinate.Version,
				ComponentOrdinal: uint64(ordinal), BodySHA256: digest, ByteCount: uint64(len(body.Raw)),
			})
			if math.MaxUint64-totalBytes < uint64(len(body.Raw)) {
				return nil, nil, fmt.Errorf("evidence manifest %s byte total overflows", coordinate.ID)
			}
			totalBytes += uint64(len(body.Raw))
		}
		if totalBytes != manifestBinding.ByteCount {
			return nil, nil, fmt.Errorf("evidence manifest %s byte_count assertion %d differs from %d exact validated bytes", coordinate.ID, manifestBinding.ByteCount, totalBytes)
		}
	}
	if len(usedBodies) != len(suppliedByComponent) {
		return nil, nil, fmt.Errorf("evidence intake contains %d orphan exact body materials", len(suppliedByComponent)-len(usedBodies))
	}
	if supplyIndex != len(supplied) {
		return nil, nil, fmt.Errorf("evidence intake contains %d reordered or extra exact body materials", len(supplied)-supplyIndex)
	}
	if err := validateStageEvidenceCommitmentRoster(commitments); err != nil {
		return nil, nil, err
	}
	return exactBodies, commitments, nil
}

func validateInheritedStageEvidence(commitments []StageEvidenceCommitment, supplied []StageEvidenceBody) (map[string]exactEvidenceBody, error) {
	if err := validateStageEvidenceCommitmentRoster(commitments); err != nil {
		return nil, fmt.Errorf("inherited evidence commitment roster: %w", err)
	}
	if len(supplied) != len(commitments) {
		return nil, fmt.Errorf("receipt lineage commits %d exact evidence bodies but %d exact bodies were supplied", len(commitments), len(supplied))
	}
	exactBodies := make(map[string]exactEvidenceBody, len(commitments))
	for index, commitment := range commitments {
		body := supplied[index]
		if body.ManifestRole != commitment.ManifestRole || body.ManifestID != commitment.ManifestID || body.ManifestVersion != commitment.ManifestVersion || body.ComponentOrdinal != commitment.ComponentOrdinal {
			return nil, fmt.Errorf("exact evidence body roster is reordered or substituted at index %d", index)
		}
		if len(body.Raw) == 0 {
			return nil, fmt.Errorf("exact evidence body %s/%s/%s ordinal %d is empty", body.ManifestRole, body.ManifestID, body.ManifestVersion, body.ComponentOrdinal)
		}
		digest := sha256Hex(body.Raw)
		if digest != commitment.BodySHA256 || uint64(len(body.Raw)) != commitment.ByteCount {
			return nil, fmt.Errorf("exact evidence body %s/%s/%s ordinal %d does not match the immutable lineage digest/byte commitment", body.ManifestRole, body.ManifestID, body.ManifestVersion, body.ComponentOrdinal)
		}
		if err := addExactStageEvidenceContent(exactBodies, digest, body.Raw); err != nil {
			return nil, fmt.Errorf("exact evidence body %s/%s/%s ordinal %d: %w", body.ManifestRole, body.ManifestID, body.ManifestVersion, body.ComponentOrdinal, err)
		}
	}
	return exactBodies, nil
}

// addExactStageEvidenceContent deduplicates byte-equal content for leakage
// scanning without collapsing evidence occurrences. Occurrence identity and
// lifecycle stay in StageEvidenceCommitment's manifest coordinate + ordinal;
// the content map is only an in-memory digest-indexed scanner input.
func addExactStageEvidenceContent(exactBodies map[string]exactEvidenceBody, digest string, raw []byte) error {
	if prior, reused := exactBodies[digest]; reused {
		if !bytes.Equal(prior.Bytes, raw) {
			return fmt.Errorf("SHA-256 digest %s resolves to unequal exact bytes", digest)
		}
		return nil
	}
	exactBodies[digest] = exactEvidenceBody{Bytes: append([]byte(nil), raw...), Coordinates: map[evidenceSourceCoordinate]string{}}
	return nil
}

func validateStageEvidenceCommitmentRoster(commitments []StageEvidenceCommitment) error {
	if len(commitments) == 0 {
		return fmt.Errorf("evidence commitment roster is empty")
	}
	var totalBytes uint64
	priorManifest := stageMaterialCoordinate{}
	var priorOrdinal uint64
	for index, commitment := range commitments {
		coordinate := stageMaterialCoordinate{commitment.ManifestRole, commitment.ManifestID, commitment.ManifestVersion}
		if err := validateStageMaterialCoordinate(coordinate); err != nil {
			return fmt.Errorf("evidence_commitments[%d]: %w", index, err)
		}
		if !isLowerSHA256(commitment.BodySHA256) {
			return fmt.Errorf("evidence_commitments[%d].body_sha256 is not an exact lowercase SHA-256", index)
		}
		if commitment.ComponentOrdinal > maxExactStageCount {
			return fmt.Errorf("evidence_commitments[%d].component_ordinal is unsafe", index)
		}
		if commitment.ByteCount == 0 {
			return fmt.Errorf("evidence_commitments[%d].byte_count is zero", index)
		}
		if err := requireSafeStageCount(fmt.Sprintf("evidence_commitments[%d].byte_count", index), commitment.ByteCount); err != nil {
			return err
		}
		if math.MaxUint64-totalBytes < commitment.ByteCount {
			return fmt.Errorf("evidence commitment byte total overflows")
		}
		totalBytes += commitment.ByteCount

		if index == 0 {
			if commitment.ComponentOrdinal != 0 {
				return fmt.Errorf("evidence commitment roster does not begin at component ordinal zero")
			}
		} else {
			comparison := compareStageMaterialCoordinates(coordinate, priorManifest)
			switch {
			case comparison < 0:
				return fmt.Errorf("evidence commitment roster is not strictly ordered by manifest role/id/version")
			case comparison == 0 && commitment.ComponentOrdinal != priorOrdinal+1:
				return fmt.Errorf("evidence commitment roster manifest %s/%s/%s ordinals are not zero-based contiguous", coordinate.Role, coordinate.ID, coordinate.Version)
			case comparison > 0 && commitment.ComponentOrdinal != 0:
				return fmt.Errorf("evidence commitment roster manifest %s/%s/%s does not begin at ordinal zero", coordinate.Role, coordinate.ID, coordinate.Version)
			}
		}
		priorManifest = coordinate
		priorOrdinal = commitment.ComponentOrdinal
	}
	return requireSafeStageCount("total evidence commitment byte_count", totalBytes)
}

func compareStageMaterialCoordinates(left, right stageMaterialCoordinate) int {
	leftKey := lengthPrefixedIdentityKey(left.Role, left.ID, left.Version)
	rightKey := lengthPrefixedIdentityKey(right.Role, right.ID, right.Version)
	return strings.Compare(leftKey, rightKey)
}

func sortedStageMaterialCoordinateKeys[T any](values map[stageMaterialCoordinate]T) []stageMaterialCoordinate {
	coordinates := make([]stageMaterialCoordinate, 0, len(values))
	for coordinate := range values {
		coordinates = append(coordinates, coordinate)
	}
	sort.Slice(coordinates, func(left, right int) bool {
		return compareStageMaterialCoordinates(coordinates[left], coordinates[right]) < 0
	})
	return coordinates
}

func rejectStageEvidenceMaterialDigestAliases(materials map[stageMaterialCoordinate]StageMaterial, commitments []StageEvidenceCommitment) error {
	owners := make(map[string]stageMaterialCoordinate, len(materials))
	for coordinate, material := range materials {
		owners[sha256Hex(material.Raw)] = coordinate
	}
	for index, commitment := range commitments {
		if owner, alias := owners[commitment.BodySHA256]; alias {
			return fmt.Errorf("evidence_commitments[%d].body_sha256 aliases exact material %s/%s/%s", index, owner.Role, owner.ID, owner.Version)
		}
	}
	return nil
}

func parseStageEvidenceComponentClaims(raw []byte) ([]stageEvidenceComponentClaim, error) {
	claimsByOrdinal := map[uint64]stageEvidenceComponentClaim{}
	for lineNumber, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(line, &object); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		var rowKind string
		if rawKind, exists := object["row_kind"]; exists {
			if err := json.Unmarshal(rawKind, &rowKind); err != nil {
				return nil, fmt.Errorf("line %d row_kind: %w", lineNumber+1, err)
			}
		}
		if rowKind != "external_evidence_body" {
			continue
		}
		ordinal, err := exactStageUint(object["component_ordinal"])
		if err != nil {
			return nil, fmt.Errorf("line %d component_ordinal: %w", lineNumber+1, err)
		}
		byteCount, err := exactStageUint(object["content_bytes"])
		if err != nil || byteCount == 0 {
			return nil, fmt.Errorf("line %d content_bytes is absent, zero, or unsafe", lineNumber+1)
		}
		var digest string
		if err := json.Unmarshal(object["content_sha256"], &digest); err != nil || !isLowerSHA256(digest) {
			return nil, fmt.Errorf("line %d content_sha256 is not an exact lowercase SHA-256", lineNumber+1)
		}
		if _, duplicate := claimsByOrdinal[ordinal]; duplicate {
			return nil, fmt.Errorf("component_ordinal %d is duplicated", ordinal)
		}
		claimsByOrdinal[ordinal] = stageEvidenceComponentClaim{digest: digest, bytes: byteCount}
	}
	if len(claimsByOrdinal) == 0 {
		return nil, fmt.Errorf("no external_evidence_body rows")
	}
	claims := make([]stageEvidenceComponentClaim, len(claimsByOrdinal))
	for ordinal := range claims {
		claim, found := claimsByOrdinal[uint64(ordinal)]
		if !found {
			return nil, fmt.Errorf("component ordinals are not zero-based contiguous at %d", ordinal)
		}
		claims[ordinal] = claim
	}
	return claims, nil
}

func exactStageUint(raw []byte) (uint64, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("value is absent")
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(string(number), 10, 64)
	if err != nil || value > maxExactStageCount {
		return 0, fmt.Errorf("%q is not an exact interoperable unsigned integer", number)
	}
	return value, nil
}

func validateSemanticProfileSchemas(binding semanticExtractionStageBinding, profile stageValidationProfileDocument) error {
	profileSchemaByArtifact := map[stageMaterialCoordinate]stageMaterialCoordinate{}
	for _, item := range profile.BoundArtifactSchemas {
		profileSchemaByArtifact[stageMaterialCoordinate{item.Role, item.ArtifactID, item.ArtifactVersion}] = stageMaterialCoordinate{item.SchemaRole, item.SchemaID, item.SchemaVersion}
	}
	derivations := map[string]semanticDerivationBinding{}
	for _, item := range binding.DerivationBindings {
		derivations[item.BindingID] = item
	}
	for _, output := range binding.ArtifactOutputs {
		artifactCoordinate := stageMaterialCoordinate{output.Role, output.ArtifactID, output.ArtifactVersion}
		profileSchema := profileSchemaByArtifact[artifactCoordinate]
		matched := false
		for _, bindingID := range output.DerivationBindingIDs {
			derivation := derivations[bindingID]
			if profileSchema == stageCoordinateForPin(derivation.Schema) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("semantic output role %s is not schema-validated by any of its exact derivation bindings", output.Role)
		}
	}
	return nil
}

func validateGraphProfileAndDerivedSets(binding graphCompileStageBinding, profile stageValidationProfileDocument, materials map[stageMaterialCoordinate]StageMaterial) (graphPlanSchemaBindingProof, error) {
	if len(profile.GraphRowDispositions) == 0 {
		return graphPlanSchemaBindingProof{}, fmt.Errorf("graph compile validation profile has no exact row-kind dispositions")
	}
	planCoordinate := stageCoordinateForIdentity(binding.Plan)
	derived, err := deriveStageGraphSets(materials[planCoordinate].Raw, profile.GraphRowDispositions)
	if err != nil {
		return graphPlanSchemaBindingProof{}, err
	}
	setComparisons := []struct {
		name       string
		comparison [2]compactStageSet
	}{
		{name: "subjects", comparison: [2]compactStageSet{binding.Subjects, derived["subject"]}},
		{name: "facts", comparison: [2]compactStageSet{binding.Facts, derived["fact"]}},
		{name: "gaps", comparison: [2]compactStageSet{binding.Gaps, derived["gap"]}},
	}
	for _, item := range setComparisons {
		name, comparison := item.name, item.comparison
		if comparison[0] != comparison[1] {
			return graphPlanSchemaBindingProof{}, fmt.Errorf("graph compile %s asserted root/count %+v differs from exact plan-derived %+v", name, comparison[0], comparison[1])
		}
	}
	return buildGraphPlanSchemaBindingProof(binding, profile, materials)
}

func deriveStageGraphSets(raw []byte, dispositions []stageGraphRowDisposition) (map[string]compactStageSet, error) {
	setKindsByRowKind := make(map[string][]string, len(dispositions))
	for _, item := range dispositions {
		setKindsByRowKind[item.RowKind] = slices.Clone(item.SetKinds)
	}
	rows := map[string][][]byte{"subject": {}, "fact": {}, "gap": {}}
	for lineNumber, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(line, &object); err != nil {
			return nil, fmt.Errorf("graph plan line %d: %w", lineNumber+1, err)
		}
		var rowKind string
		if err := json.Unmarshal(object["row_kind"], &rowKind); err != nil || rowKind == "" {
			return nil, fmt.Errorf("graph plan line %d has no exact row_kind", lineNumber+1)
		}
		setKinds, declared := setKindsByRowKind[rowKind]
		if !declared {
			return nil, fmt.Errorf("graph plan row_kind %s is absent from the closed row disposition profile", rowKind)
		}
		if len(setKinds) == 1 && setKinds[0] == "metadata" {
			continue
		}
		canonical, err := canonicalizeCandidateJSON(line)
		if err != nil {
			return nil, fmt.Errorf("graph plan line %d canonicalization: %w", lineNumber+1, err)
		}
		for _, setKind := range setKinds {
			if setKind == "metadata" {
				return nil, fmt.Errorf("graph plan row_kind %s combines metadata with a committed graph set", rowKind)
			}
			rows[setKind] = append(rows[setKind], canonical)
		}
	}
	result := make(map[string]compactStageSet, 3)
	for _, setKind := range []string{"subject", "fact", "gap"} {
		result[setKind] = compactStageSet{RootSHA256: stageCanonicalSetRoot(rows[setKind]), Count: uint64(len(rows[setKind]))}
	}
	if result["subject"].Count == 0 {
		return nil, fmt.Errorf("exact graph plan derives no subjects")
	}
	return result, nil
}

func stageCanonicalSetRoot(rows [][]byte) string {
	if len(rows) == 0 {
		return sha256Hex(nil)
	}
	canonicalRows := make([]string, len(rows))
	for index, row := range rows {
		canonicalRows[index] = string(row)
	}
	sort.Strings(canonicalRows)
	return sha256Hex([]byte(lengthPrefixedIdentityKey(canonicalRows...)))
}

// CompileStageReceipt validates one closed stage request and the exact prior
// receipts it names, then emits a deterministic, body-free receipt. It is an
// offline structural compiler: it does not select authority or assert that any
// artifact is admitted.
func CompileStageReceipt(requestRaw []byte, inputs StageCompileInputs) ([]byte, error) {
	return compileStageReceipt(requestRaw, inputs, nil)
}

func compileGraphStageReceiptWithParseProof(requestRaw []byte, inputs StageCompileInputs) ([]byte, graphPlanParseProof, error) {
	var proof graphPlanParseProof
	receiptRaw, err := compileStageReceipt(requestRaw, inputs, func(validated graphPlanParseProof) {
		proof = validated
	})
	if err != nil {
		return nil, graphPlanParseProof{}, err
	}
	if proof.seal != graphPlanParseAuthority {
		return nil, graphPlanParseProof{}, fmt.Errorf("selected stage request is not a graph_compile request with sealed parse proofs")
	}
	return receiptRaw, proof, nil
}

func compileStageReceipt(requestRaw []byte, inputs StageCompileInputs, proofSink func(graphPlanParseProof)) ([]byte, error) {
	header, err := decodeStageRequestHeader(requestRaw)
	if err != nil {
		return nil, err
	}

	var (
		requestCanonical []byte
		bindingRaw       []byte
		predecessors     []StageReceiptReference
		resolved         []parsedStageReceipt
	)
	switch header.StageKind {
	case stageEvidenceIntake:
		var request evidenceIntakeStageRequest
		if err := decodeClosedStageJSON(requestRaw, &request,
			"request_kind", "request_version", "stage_kind", "stage_validation", "authority_pins", "selection_roster", "evidence_manifests"); err != nil {
			return nil, fmt.Errorf("%s request: %w", header.StageKind, err)
		}
		binding := evidenceIntakeStageBinding{
			StageValidation: request.StageValidation, AuthorityPins: request.AuthorityPins,
			SelectionRoster: request.SelectionRoster, EvidenceManifests: request.EvidenceManifests,
		}
		if err := validateEvidenceIntakeBinding(binding); err != nil {
			return nil, err
		}
		if len(inputs.PredecessorReceipts) != 0 {
			return nil, fmt.Errorf("%s request has %d unbound predecessor receipts", header.StageKind, len(inputs.PredecessorReceipts))
		}
		requestCanonical, err = canonicalStageValue(request)
		if err == nil {
			bindingRaw, err = canonicalStageValue(binding)
		}
	case stageSemanticExtraction:
		var request semanticExtractionStageRequest
		if err := decodeClosedStageJSON(requestRaw, &request,
			"request_kind", "request_version", "stage_kind", "intake_receipt", "stage_validation", "applicability_profile", "artifact_role_roster", "artifact_outputs", "derivation_bindings"); err != nil {
			return nil, fmt.Errorf("%s request: %w", header.StageKind, err)
		}
		if err := validateStageReference(request.IntakeReceipt); err != nil {
			return nil, fmt.Errorf("semantic extraction intake receipt: %w", err)
		}
		predecessors = []StageReceiptReference{request.IntakeReceipt}
		var resolveErr error
		resolved, resolveErr = resolveExactStagePredecessors(predecessors, inputs.PredecessorReceipts)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if resolved[0].Summary.StageKind != stageEvidenceIntake {
			return nil, fmt.Errorf("semantic extraction predecessor is %s, want %s", resolved[0].Summary.StageKind, stageEvidenceIntake)
		}
		binding := semanticExtractionStageBinding{
			StageValidation: request.StageValidation, ApplicabilityProfile: request.ApplicabilityProfile,
			ArtifactRoleRoster: request.ArtifactRoleRoster, ArtifactOutputs: request.ArtifactOutputs,
			DerivationBindings: request.DerivationBindings,
		}
		if err := validateSemanticExtractionBinding(binding); err != nil {
			return nil, err
		}
		requestCanonical, err = canonicalStageValue(request)
		if err == nil {
			bindingRaw, err = canonicalStageValue(binding)
		}
	case stageGraphCompile:
		var request graphCompileStageRequest
		if err := decodeClosedStageJSON(requestRaw, &request,
			"request_kind", "request_version", "stage_kind", "extraction_receipts", "stage_validation", "dependency_artifacts", "plan", "subjects", "facts", "gaps"); err != nil {
			return nil, fmt.Errorf("%s request: %w", header.StageKind, err)
		}
		if err := requireGraphCompileDependencyArtifactKeys(requestRaw); err != nil {
			return nil, fmt.Errorf("%s request: %w", header.StageKind, err)
		}
		predecessors = append([]StageReceiptReference(nil), request.ExtractionReceipts...)
		var resolveErr error
		resolved, resolveErr = resolveExactStagePredecessors(predecessors, inputs.PredecessorReceipts)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if err := validateGraphExtractionLineage(predecessors, resolved); err != nil {
			return nil, err
		}
		binding := graphCompileStageBinding{
			StageValidation:     request.StageValidation,
			DependencyArtifacts: request.DependencyArtifacts,
			Plan:                request.Plan, Subjects: request.Subjects, Facts: request.Facts, Gaps: request.Gaps,
		}
		if err := validateGraphCompileBinding(binding); err != nil {
			return nil, err
		}
		requestCanonical, err = canonicalStageValue(request)
		if err == nil {
			bindingRaw, err = canonicalStageValue(binding)
		}
	case stageFullFactory:
		var request fullFactoryStageRequest
		if err := decodeClosedStageJSON(requestRaw, &request,
			"request_kind", "request_version", "stage_kind", "stage_validation", "prior_receipts"); err != nil {
			return nil, fmt.Errorf("%s request: %w", header.StageKind, err)
		}
		predecessors = append([]StageReceiptReference(nil), request.PriorReceipts...)
		var resolveErr error
		resolved, resolveErr = resolveExactStagePredecessors(predecessors, inputs.PredecessorReceipts)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if err := validateFullFactoryLineage(predecessors, resolved); err != nil {
			return nil, err
		}
		requestCanonical, err = canonicalStageValue(request)
		if err == nil {
			bindingRaw, err = canonicalStageValue(fullFactoryStageBinding{StageValidation: request.StageValidation})
		}
	default:
		return nil, fmt.Errorf("unknown stage_kind %q", header.StageKind)
	}
	if err != nil {
		return nil, fmt.Errorf("canonicalize %s request: %w", header.StageKind, err)
	}
	lineageCommitments, err := resolveStageEvidenceLineage(header.StageKind, resolved)
	if err != nil {
		return nil, err
	}
	evidenceValidation, err := validateExactStageCompileInputs(header.StageKind, bindingRaw, inputs, lineageCommitments)
	if err != nil {
		return nil, err
	}
	exactBodies := evidenceValidation.bodies
	evidenceCommitments := evidenceValidation.commitments
	if err := validateStageBodyFreeInputs(header.StageKind, requestCanonical, bindingRaw, inputs, exactBodies, evidenceValidation.materialProvenance); err != nil {
		return nil, err
	}
	requestSHA := sha256Hex(requestCanonical)
	outputCommitment, err := canonicalStageValue(stageOutputCommitment{header.StageKind, predecessors, evidenceCommitments, bindingRaw})
	if err != nil {
		return nil, fmt.Errorf("canonicalize %s output commitment: %w", header.StageKind, err)
	}
	outputRoot := sha256Hex(outputCommitment)
	identity := stageReceiptIdentity{
		ReceiptKind: stageReceiptKind, ReceiptVersion: stageContractVersion, StageKind: header.StageKind,
		RequestSHA256: requestSHA, Predecessors: predecessors, EvidenceCommitments: evidenceCommitments, Binding: bindingRaw,
		OutputRootSHA256: outputRoot, ValidationScope: stageValidationScope, BodyFree: true,
		DerivationExecuted: false, AuthoritySelected: false, AdmissionAuthorized: false, FactoryComplete: false,
	}
	identityRaw, err := canonicalStageValue(identity)
	if err != nil {
		return nil, fmt.Errorf("canonicalize %s receipt identity: %w", header.StageKind, err)
	}
	receipt := stageReceipt{
		ReceiptKind: identity.ReceiptKind, ReceiptVersion: identity.ReceiptVersion, StageKind: identity.StageKind,
		RequestSHA256: identity.RequestSHA256, Predecessors: identity.Predecessors,
		EvidenceCommitments: identity.EvidenceCommitments, Binding: identity.Binding,
		OutputRootSHA256: identity.OutputRootSHA256, ValidationScope: identity.ValidationScope,
		BodyFree: true, DerivationExecuted: false, AuthoritySelected: false,
		AdmissionAuthorized: false, FactoryComplete: false, ReceiptSHA256: sha256Hex(identityRaw),
	}
	if err := validateGeneratedReceiptDigestSeparation(receipt); err != nil {
		return nil, err
	}
	receiptRaw, err := canonicalStageValue(receipt)
	if err != nil {
		return nil, err
	}
	if err := scanStageStructuredMetadata("generated stage receipt", receiptRaw); err != nil {
		return nil, fmt.Errorf("generated receipt security validation: %w", err)
	}
	if err := validateNoEmbeddedEvidenceBodies("generated stage receipt", receiptRaw, exactBodies, 1); err != nil {
		return nil, fmt.Errorf("generated receipt is not body-free: %w", err)
	}
	if evidenceValidation.graphStructural != nil {
		proof, err := newGraphPlanParseProof(*evidenceValidation.graphStructural, requestSHA, StageReceiptReference{
			StageKind: stageGraphCompile, ReceiptSHA256: receipt.ReceiptSHA256, OutputRootSHA256: outputRoot,
		})
		if err != nil {
			return nil, err
		}
		if proofSink != nil {
			proofSink(proof)
		}
	}
	return receiptRaw, nil
}

// ValidateStageReceipt proves the receipt's closed shape, digest identity,
// body-free posture, stage binding, and internally declared lineage shape.
// Cross-receipt lineage is proved by CompileStageReceipt when the next stage is
// compiled with the exact predecessor receipt bytes.
func ValidateStageReceipt(receiptRaw []byte) (StageReceiptSummary, error) {
	parsed, err := parseStageReceipt(receiptRaw)
	if err != nil {
		return StageReceiptSummary{}, err
	}
	return parsed.Summary, nil
}

func decodeStageRequestHeader(raw []byte) (stageRequestHeader, error) {
	if err := requireValidUTF8("stage request", raw); err != nil {
		return stageRequestHeader{}, err
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return stageRequestHeader{}, fmt.Errorf("stage request is not duplicate-key-safe JSON: %w", err)
	}
	if err := scanStageStructuredMetadata("stage request", raw); err != nil {
		return stageRequestHeader{}, fmt.Errorf("stage request security validation: %w", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		if err == nil {
			err = fmt.Errorf("root is not an object")
		}
		return stageRequestHeader{}, fmt.Errorf("stage request: %w", err)
	}
	var header stageRequestHeader
	headerFields := []struct {
		key         string
		destination *string
	}{
		{key: "request_kind", destination: &header.RequestKind},
		{key: "request_version", destination: &header.RequestVersion},
		{key: "stage_kind", destination: &header.StageKind},
	}
	for _, field := range headerFields {
		key, destination := field.key, field.destination
		value, ok := object[key]
		if !ok {
			return stageRequestHeader{}, fmt.Errorf("stage request is missing %s", key)
		}
		if err := strictUnmarshal(value, destination); err != nil {
			return stageRequestHeader{}, fmt.Errorf("stage request %s: %w", key, err)
		}
	}
	if header.RequestKind != stageRequestKind {
		return stageRequestHeader{}, fmt.Errorf("request_kind %q, want %q", header.RequestKind, stageRequestKind)
	}
	if header.RequestVersion != stageContractVersion {
		return stageRequestHeader{}, fmt.Errorf("request_version %q, want %q", header.RequestVersion, stageContractVersion)
	}
	if !validStageKind(header.StageKind) {
		return stageRequestHeader{}, fmt.Errorf("unknown stage_kind %q", header.StageKind)
	}
	return header, nil
}

func decodeClosedStageJSON(raw []byte, destination interface{}, keys ...string) error {
	if err := requireExactStageKeys(raw, keys...); err != nil {
		return err
	}
	if err := strictUnmarshal(raw, destination); err != nil {
		return err
	}
	return nil
}

func requireExactStageKeys(raw []byte, keys ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		if err == nil {
			err = fmt.Errorf("JSON value is not an object")
		}
		return err
	}
	expected := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		expected[key] = struct{}{}
	}
	objectKeys := make([]string, 0, len(object))
	for key := range object {
		objectKeys = append(objectKeys, key)
	}
	sort.Strings(objectKeys)
	for _, key := range objectKeys {
		if _, ok := expected[key]; !ok {
			return fmt.Errorf("closed JSON object has unbound field %q", key)
		}
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return fmt.Errorf("closed JSON object is missing field %q", key)
		}
	}
	return nil
}

func canonicalStageValue(value interface{}) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalizeCandidateJSON(raw)
}

func validateEvidenceIntakeBinding(binding evidenceIntakeStageBinding) error {
	ledger := newStageDigestLedger()
	if err := validateStageValidationBinding("evidence intake stage_validation", binding.StageValidation, ledger); err != nil {
		return err
	}
	authorityPins := []struct {
		label string
		pin   immutableStageArtifactPin
	}{
		{label: "authority_pins.ood_graph", pin: binding.AuthorityPins.OODGraph},
		{label: "authority_pins.grand_vision", pin: binding.AuthorityPins.GrandVision},
		{label: "authority_pins.source_record", pin: binding.AuthorityPins.SourceRecord},
		{label: "authority_pins.extension_protocol", pin: binding.AuthorityPins.ExtensionProtocol},
	}
	for _, authority := range authorityPins {
		label, pin := authority.label, authority.pin
		if err := validateImmutableStageArtifactPin(label, pin, ledger); err != nil {
			return fmt.Errorf("evidence intake: %w", err)
		}
	}
	if err := validateStageArtifactIdentity("selection_roster", binding.SelectionRoster, ledger); err != nil {
		return err
	}
	if len(binding.EvidenceManifests) == 0 {
		return fmt.Errorf("evidence intake has no exact evidence manifests")
	}
	var totalBodies, totalBytes uint64
	priorIdentity := ""
	for index, manifest := range binding.EvidenceManifests {
		if err := validateStageIdentifier("evidence manifest role", manifest.Role); err != nil {
			return err
		}
		if err := validateStageCoordinate("evidence manifest artifact_id", manifest.ArtifactID); err != nil {
			return err
		}
		if err := validateStageVersion("evidence manifest artifact_version", manifest.ArtifactVersion); err != nil {
			return err
		}
		identity := lengthPrefixedIdentityKey(manifest.Role, manifest.ArtifactID, manifest.ArtifactVersion)
		if identity <= priorIdentity {
			return fmt.Errorf("evidence intake manifests are not unique and strictly ordered by role/id/version at index %d", index)
		}
		priorIdentity = identity
		if err := ledger.add(fmt.Sprintf("evidence_manifests[%d].artifact_raw_sha256", index), manifest.ArtifactRawSHA256); err != nil {
			return fmt.Errorf("evidence intake: %w", err)
		}
		if manifest.BodyCount == 0 || manifest.ByteCount == 0 || manifest.ByteCount < manifest.BodyCount {
			return fmt.Errorf("evidence manifest %s has unsafe body_count/byte_count %d/%d", manifest.ArtifactID, manifest.BodyCount, manifest.ByteCount)
		}
		if err := requireSafeStageCount("evidence manifest body_count", manifest.BodyCount); err != nil {
			return err
		}
		if err := requireSafeStageCount("evidence manifest byte_count", manifest.ByteCount); err != nil {
			return err
		}
		if math.MaxUint64-totalBodies < manifest.BodyCount || math.MaxUint64-totalBytes < manifest.ByteCount {
			return fmt.Errorf("evidence manifest totals overflow")
		}
		totalBodies += manifest.BodyCount
		totalBytes += manifest.ByteCount
	}
	if err := requireSafeStageCount("total evidence body_count", totalBodies); err != nil {
		return err
	}
	return requireSafeStageCount("total evidence byte_count", totalBytes)
}

func validateSemanticExtractionBinding(binding semanticExtractionStageBinding) error {
	ledger := newStageDigestLedger()
	if err := validateStageValidationBinding("semantic extraction stage_validation", binding.StageValidation, ledger); err != nil {
		return err
	}
	if err := validateImmutableStageArtifactPin("applicability_profile", binding.ApplicabilityProfile, ledger); err != nil {
		return err
	}
	if len(binding.ArtifactRoleRoster) == 0 {
		return fmt.Errorf("semantic extraction artifact_role_roster is empty")
	}
	roster := make(map[string]string, len(binding.ArtifactRoleRoster))
	priorRole := ""
	requiredCount := 0
	for index, item := range binding.ArtifactRoleRoster {
		if err := validateStageIdentifier("artifact role", item.Role); err != nil {
			return err
		}
		if item.Role <= priorRole {
			return fmt.Errorf("artifact_role_roster is not unique and strictly ordered by role at index %d", index)
		}
		priorRole = item.Role
		switch item.Disposition {
		case "required":
			requiredCount++
		case "optional", "inapplicable":
		default:
			return fmt.Errorf("artifact role %s has unknown disposition %q", item.Role, item.Disposition)
		}
		roster[item.Role] = item.Disposition
	}
	if requiredCount == 0 {
		return fmt.Errorf("semantic extraction roster has no required artifact role")
	}

	bindings := make(map[string]struct{}, len(binding.DerivationBindings))
	usedBindings := make(map[string]struct{}, len(binding.DerivationBindings))
	priorBinding := ""
	for index, item := range binding.DerivationBindings {
		if err := validateStageIdentifier("derivation binding", item.BindingID); err != nil {
			return err
		}
		if item.BindingID <= priorBinding {
			return fmt.Errorf("derivation_bindings is not unique and strictly ordered by binding_id at index %d", index)
		}
		priorBinding = item.BindingID
		bindings[item.BindingID] = struct{}{}
		if err := validateImmutableStageArtifactPin("derivation binding "+item.BindingID+" extractor", item.Extractor, ledger); err != nil {
			return err
		}
		if err := validateImmutableStageArtifactPin("derivation binding "+item.BindingID+" schema", item.Schema, ledger); err != nil {
			return err
		}
	}

	outputs := make(map[string]struct{}, len(binding.ArtifactOutputs))
	priorRole = ""
	for index, output := range binding.ArtifactOutputs {
		if err := validateStageIdentifier("artifact output role", output.Role); err != nil {
			return err
		}
		if output.Role <= priorRole {
			return fmt.Errorf("artifact_outputs is not unique and strictly ordered by role at index %d", index)
		}
		priorRole = output.Role
		disposition, declared := roster[output.Role]
		if !declared {
			return fmt.Errorf("artifact output role %s is not declared by the closed roster", output.Role)
		}
		if disposition == "inapplicable" {
			return fmt.Errorf("artifact output role %s is supplied despite inapplicable disposition", output.Role)
		}
		if err := validateStageCoordinate("artifact output "+output.Role+" artifact_id", output.ArtifactID); err != nil {
			return err
		}
		if err := validateStageVersion("artifact output "+output.Role+" artifact_version", output.ArtifactVersion); err != nil {
			return err
		}
		if err := ledger.add("artifact output "+output.Role+" raw digest", output.ArtifactRawSHA256); err != nil {
			return fmt.Errorf("semantic extraction: %w", err)
		}
		if len(output.DerivationBindingIDs) == 0 {
			return fmt.Errorf("artifact output role %s has no admitted/canonical derivation binding", output.Role)
		}
		priorID := ""
		for _, bindingID := range output.DerivationBindingIDs {
			if bindingID <= priorID {
				return fmt.Errorf("artifact output role %s derivation_binding_ids are not unique and strictly ordered", output.Role)
			}
			priorID = bindingID
			if _, ok := bindings[bindingID]; !ok {
				return fmt.Errorf("artifact output role %s references undeclared derivation binding %s", output.Role, bindingID)
			}
			usedBindings[bindingID] = struct{}{}
		}
		outputs[output.Role] = struct{}{}
	}
	roles := make([]string, 0, len(roster))
	for role := range roster {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		disposition := roster[role]
		_, present := outputs[role]
		if disposition == "required" && !present {
			return fmt.Errorf("required artifact role %s is omitted", role)
		}
		if disposition == "inapplicable" && present {
			return fmt.Errorf("inapplicable artifact role %s is supplied", role)
		}
	}
	if len(outputs) == 0 {
		return fmt.Errorf("semantic extraction has no output artifacts")
	}
	bindingIDs := make([]string, 0, len(bindings))
	for bindingID := range bindings {
		bindingIDs = append(bindingIDs, bindingID)
	}
	sort.Strings(bindingIDs)
	for _, bindingID := range bindingIDs {
		if _, used := usedBindings[bindingID]; !used {
			return fmt.Errorf("derivation binding %s is an unbound extra", bindingID)
		}
	}
	return nil
}

func validateGraphCompileBinding(binding graphCompileStageBinding) error {
	ledger := newStageDigestLedger()
	if err := validateStageValidationBinding("graph compile stage_validation", binding.StageValidation, ledger); err != nil {
		return err
	}
	if len(binding.DependencyArtifacts) == 0 {
		return fmt.Errorf("graph compile has no exact dependency_artifacts roster")
	}
	var priorDependency stageMaterialCoordinate
	for index, dependency := range binding.DependencyArtifacts {
		if err := validateStageArtifactIdentity(fmt.Sprintf("graph compile dependency_artifacts[%d]", index), dependency, ledger); err != nil {
			return err
		}
		coordinate := stageCoordinateForIdentity(dependency)
		if index > 0 && compareStageMaterialCoordinates(coordinate, priorDependency) <= 0 {
			return fmt.Errorf("graph compile dependency_artifacts is not strictly ordered and unique at %s/%s/%s", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		priorDependency = coordinate
	}
	if err := validateStageArtifactIdentity("graph compile plan", binding.Plan, ledger); err != nil {
		return err
	}
	sets := []struct {
		name  string
		value compactStageSet
	}{
		{"subjects", binding.Subjects}, {"facts", binding.Facts}, {"gaps", binding.Gaps},
	}
	var total uint64
	for _, item := range sets {
		if err := requireSafeStageCount(item.name+" count", item.value.Count); err != nil {
			return err
		}
		if !isLowerSHA256(item.value.RootSHA256) {
			return fmt.Errorf("graph compile %s root_sha256 is not an exact lowercase SHA-256", item.name)
		}
		if item.value.Count == 0 {
			if item.value.RootSHA256 != sha256Hex(nil) {
				return fmt.Errorf("graph compile empty %s set does not use the canonical empty root", item.name)
			}
		} else if err := ledger.add(item.name+" root_sha256", item.value.RootSHA256); err != nil {
			return fmt.Errorf("graph compile: %w", err)
		}
		if math.MaxUint64-total < item.value.Count {
			return fmt.Errorf("graph compile set counts overflow")
		}
		total += item.value.Count
	}
	if binding.Subjects.Count == 0 {
		return fmt.Errorf("graph compile has no subjects")
	}
	if err := requireSafeStageCount("graph compile total count", total); err != nil {
		return err
	}
	return nil
}

func validateImmutableStageArtifactPin(label string, pin immutableStageArtifactPin, ledger *stageDigestLedger) error {
	if err := validateStageIdentifier(label+" role", pin.Role); err != nil {
		return err
	}
	if err := validateStageCoordinate(label+" id", pin.ID); err != nil {
		return err
	}
	if err := validateStageVersion(label+" version", pin.Version); err != nil {
		return err
	}
	if pin.AuthorityClass != "admitted" && pin.AuthorityClass != "canonical" {
		return fmt.Errorf("%s authority_class %q is neither admitted nor canonical", label, pin.AuthorityClass)
	}
	if err := ledger.add(label+" raw_sha256", pin.RawSHA256); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}

func validateStageValidationBinding(label string, binding stageValidationBinding, ledger *stageDigestLedger) error {
	if err := validateImmutableStageArtifactPin(label+" schema", binding.Schema, ledger); err != nil {
		return err
	}
	return validateImmutableStageArtifactPin(label+" profile", binding.Profile, ledger)
}

func validateStageArtifactIdentity(label string, identity stageArtifactIdentity, ledger *stageDigestLedger) error {
	if err := validateStageIdentifier(label+" role", identity.Role); err != nil {
		return err
	}
	if err := validateStageCoordinate(label+" id", identity.ID); err != nil {
		return err
	}
	if err := validateStageVersion(label+" version", identity.Version); err != nil {
		return err
	}
	if err := ledger.add(label+" raw_sha256", identity.RawSHA256); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}

func validateStageIdentifier(label, value string) error {
	if len(value) > 128 || !stageIdentifierPattern.MatchString(value) || strings.Contains(value, "organization_id") || value == "org_id" {
		return fmt.Errorf("%s %q is not a source-neutral lowercase identifier", label, value)
	}
	return nil
}

func validateStageCoordinate(label, value string) error {
	if !stageCoordinatePattern.MatchString(value) || strings.Contains(strings.ToLower(value), "organization_id") || strings.EqualFold(value, "org_id") {
		return fmt.Errorf("%s %q is not an immutable source-neutral coordinate", label, value)
	}
	return nil
}

func validateStageVersion(label, value string) error {
	if len(value) > 64 || !stageVersionPattern.MatchString(value) {
		return fmt.Errorf("%s %q is not a lowercase immutable version", label, value)
	}
	return nil
}

func validateStageReference(ref StageReceiptReference) error {
	if !validStageKind(ref.StageKind) {
		return fmt.Errorf("unknown predecessor stage_kind %q", ref.StageKind)
	}
	if !isLowerSHA256(ref.ReceiptSHA256) {
		return fmt.Errorf("receipt_sha256 for %s is not an exact lowercase SHA-256", ref.StageKind)
	}
	if !isLowerSHA256(ref.OutputRootSHA256) {
		return fmt.Errorf("output_root_sha256 for %s is not an exact lowercase SHA-256", ref.StageKind)
	}
	if ref.ReceiptSHA256 == ref.OutputRootSHA256 {
		return fmt.Errorf("predecessor %s aliases receipt_sha256 and output_root_sha256", ref.StageKind)
	}
	return nil
}

func resolveExactStagePredecessors(expected []StageReceiptReference, rawReceipts [][]byte) ([]parsedStageReceipt, error) {
	if len(rawReceipts) != len(expected) {
		return nil, fmt.Errorf("request binds %d predecessor receipts but %d exact receipt bodies were supplied", len(expected), len(rawReceipts))
	}
	resolved := make([]parsedStageReceipt, len(expected))
	seen := make(map[string]struct{}, len(expected))
	for index, ref := range expected {
		if err := validateStageReference(ref); err != nil {
			return nil, fmt.Errorf("predecessor %d: %w", index, err)
		}
		if _, duplicate := seen[ref.ReceiptSHA256]; duplicate {
			return nil, fmt.Errorf("predecessor receipt_sha256 %s is duplicated", ref.ReceiptSHA256)
		}
		seen[ref.ReceiptSHA256] = struct{}{}
		parsed, err := parseStageReceipt(rawReceipts[index])
		if err != nil {
			return nil, fmt.Errorf("predecessor receipt %d: %w", index, err)
		}
		actual := StageReceiptReference{parsed.Summary.StageKind, parsed.Summary.ReceiptSHA256, parsed.Summary.OutputRootSHA256}
		if actual != ref {
			return nil, fmt.Errorf("predecessor receipt %d identity/root does not equal its exact request binding", index)
		}
		resolved[index] = parsed
	}
	return resolved, nil
}

func validateGraphExtractionLineage(refs []StageReceiptReference, resolved []parsedStageReceipt) error {
	if len(refs) == 0 {
		return fmt.Errorf("graph compile has no semantic extraction receipts")
	}
	priorHash := ""
	var intake StageReceiptReference
	for index, parsed := range resolved {
		if refs[index].StageKind != stageSemanticExtraction || parsed.Summary.StageKind != stageSemanticExtraction {
			return fmt.Errorf("graph compile predecessor %d is %s, want %s", index, parsed.Summary.StageKind, stageSemanticExtraction)
		}
		if refs[index].ReceiptSHA256 <= priorHash {
			return fmt.Errorf("graph compile extraction receipts are not unique and strictly ordered by receipt_sha256")
		}
		priorHash = refs[index].ReceiptSHA256
		if len(parsed.Summary.Predecessors) != 1 || parsed.Summary.Predecessors[0].StageKind != stageEvidenceIntake {
			return fmt.Errorf("semantic extraction predecessor %d does not bind exactly one evidence intake receipt", index)
		}
		if index == 0 {
			intake = parsed.Summary.Predecessors[0]
		} else if parsed.Summary.Predecessors[0] != intake {
			return fmt.Errorf("graph compile extraction receipts do not share one exact evidence intake receipt")
		}
	}
	return nil
}

func validateFullFactoryLineage(refs []StageReceiptReference, resolved []parsedStageReceipt) error {
	if len(refs) < 3 {
		return fmt.Errorf("full factory requires evidence_intake, semantic_extraction, and graph_compile receipts in order")
	}
	if refs[0].StageKind != stageEvidenceIntake || refs[len(refs)-1].StageKind != stageGraphCompile {
		return fmt.Errorf("full factory predecessor stage order must begin with evidence_intake and end with graph_compile")
	}
	for index := 1; index < len(refs)-1; index++ {
		if refs[index].StageKind != stageSemanticExtraction {
			return fmt.Errorf("full factory predecessor %d is %s, want semantic_extraction", index, refs[index].StageKind)
		}
		if index > 1 && refs[index].ReceiptSHA256 <= refs[index-1].ReceiptSHA256 {
			return fmt.Errorf("full factory semantic extraction receipts are not strictly ordered by receipt_sha256")
		}
	}
	evidenceRef := refs[0]
	for index := 1; index < len(refs)-1; index++ {
		predecessors := resolved[index].Summary.Predecessors
		if len(predecessors) != 1 || predecessors[0] != evidenceRef {
			return fmt.Errorf("full factory semantic extraction receipt %d does not bind the exact evidence intake receipt", index)
		}
	}
	graphPredecessors := resolved[len(resolved)-1].Summary.Predecessors
	semanticRefs := refs[1 : len(refs)-1]
	if len(graphPredecessors) != len(semanticRefs) {
		return fmt.Errorf("full factory graph receipt does not bind every exact semantic extraction receipt")
	}
	for index := range semanticRefs {
		if graphPredecessors[index] != semanticRefs[index] {
			return fmt.Errorf("full factory graph receipt semantic predecessor %d differs from the exact factory binding", index)
		}
	}
	return nil
}

func resolveStageEvidenceLineage(stageKind string, resolved []parsedStageReceipt) ([]StageEvidenceCommitment, error) {
	if stageKind == stageEvidenceIntake {
		if len(resolved) != 0 {
			return nil, fmt.Errorf("evidence intake stage has predecessor receipt bodies")
		}
		return nil, nil
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("%s stage has no exact predecessor evidence lineage", stageKind)
	}
	expected := resolved[0].Receipt.EvidenceCommitments
	if err := validateStageEvidenceCommitmentRoster(expected); err != nil {
		return nil, fmt.Errorf("%s predecessor 0 evidence commitments: %w", stageKind, err)
	}
	for index := 1; index < len(resolved); index++ {
		actual := resolved[index].Receipt.EvidenceCommitments
		if !equalStageEvidenceCommitments(expected, actual) {
			return nil, fmt.Errorf("%s predecessor %d evidence commitment roster is not set-equal to predecessor 0", stageKind, index)
		}
	}
	return append([]StageEvidenceCommitment(nil), expected...), nil
}

func equalStageEvidenceCommitments(left, right []StageEvidenceCommitment) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func parseStageReceipt(raw []byte) (parsedStageReceipt, error) {
	if err := requireValidUTF8("stage receipt", raw); err != nil {
		return parsedStageReceipt{}, err
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt is not duplicate-key-safe JSON: %w", err)
	}
	var receipt stageReceipt
	if err := decodeClosedStageJSON(raw, &receipt,
		"receipt_kind", "receipt_version", "stage_kind", "request_sha256", "predecessors", "evidence_commitments", "binding", "output_root_sha256", "validation_scope", "body_free", "derivation_executed", "authority_selected", "admission_authorized", "factory_complete", "receipt_sha256"); err != nil {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt: %w", err)
	}
	var receiptObject map[string]json.RawMessage
	_ = json.Unmarshal(raw, &receiptObject)
	var commitmentRows []json.RawMessage
	if err := json.Unmarshal(receiptObject["evidence_commitments"], &commitmentRows); err != nil {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt evidence_commitments: %w", err)
	}
	for index, row := range commitmentRows {
		if err := requireExactStageKeys(row, "manifest_role", "manifest_id", "manifest_version", "component_ordinal", "body_sha256", "byte_count"); err != nil {
			return parsedStageReceipt{}, fmt.Errorf("stage receipt evidence_commitments[%d]: %w", index, err)
		}
	}
	if receipt.ReceiptKind != stageReceiptKind || receipt.ReceiptVersion != stageContractVersion {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt discriminator/version is unsupported")
	}
	if !validStageKind(receipt.StageKind) {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt has unknown stage_kind %q", receipt.StageKind)
	}
	if !receipt.BodyFree {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt body_free must be true")
	}
	if receipt.ValidationScope != stageValidationScope {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt validation_scope %q is unsupported", receipt.ValidationScope)
	}
	if receipt.DerivationExecuted || receipt.AuthoritySelected || receipt.AdmissionAuthorized || receipt.FactoryComplete {
		return parsedStageReceipt{}, fmt.Errorf("stage commitment must not claim derivation execution, authority selection, admission, or factory completion")
	}
	if err := scanStageStructuredMetadata("stage receipt", raw); err != nil {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt security validation: %w", err)
	}
	if !isLowerSHA256(receipt.RequestSHA256) || !isLowerSHA256(receipt.OutputRootSHA256) || !isLowerSHA256(receipt.ReceiptSHA256) {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt identity fields must be exact lowercase SHA-256 values")
	}
	for index, ref := range receipt.Predecessors {
		if err := validateStageReference(ref); err != nil {
			return parsedStageReceipt{}, fmt.Errorf("stage receipt predecessor %d: %w", index, err)
		}
	}
	if err := validateStageEvidenceCommitmentRoster(receipt.EvidenceCommitments); err != nil {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt: %w", err)
	}
	if err := validateReceiptStageShape(receipt); err != nil {
		return parsedStageReceipt{}, err
	}
	commitmentRaw, err := canonicalStageValue(stageOutputCommitment{receipt.StageKind, receipt.Predecessors, receipt.EvidenceCommitments, receipt.Binding})
	if err != nil {
		return parsedStageReceipt{}, err
	}
	if got := sha256Hex(commitmentRaw); got != receipt.OutputRootSHA256 {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt output_root_sha256 mismatch: got %s want %s", receipt.OutputRootSHA256, got)
	}
	identity := stageReceiptIdentity{
		ReceiptKind: receipt.ReceiptKind, ReceiptVersion: receipt.ReceiptVersion, StageKind: receipt.StageKind,
		RequestSHA256: receipt.RequestSHA256, Predecessors: receipt.Predecessors,
		EvidenceCommitments: receipt.EvidenceCommitments, Binding: receipt.Binding,
		OutputRootSHA256: receipt.OutputRootSHA256, ValidationScope: receipt.ValidationScope, BodyFree: receipt.BodyFree,
		DerivationExecuted: receipt.DerivationExecuted, AuthoritySelected: receipt.AuthoritySelected,
		AdmissionAuthorized: receipt.AdmissionAuthorized, FactoryComplete: receipt.FactoryComplete,
	}
	identityRaw, err := canonicalStageValue(identity)
	if err != nil {
		return parsedStageReceipt{}, err
	}
	if got := sha256Hex(identityRaw); got != receipt.ReceiptSHA256 {
		return parsedStageReceipt{}, fmt.Errorf("stage receipt receipt_sha256 mismatch: got %s want %s", receipt.ReceiptSHA256, got)
	}
	if err := validateGeneratedReceiptDigestSeparation(receipt); err != nil {
		return parsedStageReceipt{}, err
	}
	summary := StageReceiptSummary{
		StageKind: receipt.StageKind, ReceiptSHA256: receipt.ReceiptSHA256,
		OutputRootSHA256:    receipt.OutputRootSHA256,
		Predecessors:        append([]StageReceiptReference(nil), receipt.Predecessors...),
		EvidenceCommitments: append([]StageEvidenceCommitment(nil), receipt.EvidenceCommitments...),
	}
	return parsedStageReceipt{Receipt: receipt, Summary: summary}, nil
}

func validateReceiptStageShape(receipt stageReceipt) error {
	switch receipt.StageKind {
	case stageEvidenceIntake:
		if len(receipt.Predecessors) != 0 {
			return fmt.Errorf("evidence intake receipt has predecessors")
		}
		var binding evidenceIntakeStageBinding
		if err := decodeEvidenceIntakeBinding(receipt.Binding, &binding); err != nil {
			return err
		}
		return validateEvidenceIntakeBinding(binding)
	case stageSemanticExtraction:
		if len(receipt.Predecessors) != 1 || receipt.Predecessors[0].StageKind != stageEvidenceIntake {
			return fmt.Errorf("semantic extraction receipt does not bind exactly one evidence intake predecessor")
		}
		var binding semanticExtractionStageBinding
		if err := decodeSemanticExtractionBinding(receipt.Binding, &binding); err != nil {
			return err
		}
		return validateSemanticExtractionBinding(binding)
	case stageGraphCompile:
		if len(receipt.Predecessors) == 0 {
			return fmt.Errorf("graph compile receipt has no extraction predecessors")
		}
		prior := ""
		for _, ref := range receipt.Predecessors {
			if ref.StageKind != stageSemanticExtraction || ref.ReceiptSHA256 <= prior {
				return fmt.Errorf("graph compile receipt predecessors are not ordered unique semantic extraction receipts")
			}
			prior = ref.ReceiptSHA256
		}
		var binding graphCompileStageBinding
		if err := decodeGraphCompileBinding(receipt.Binding, &binding); err != nil {
			return err
		}
		return validateGraphCompileBinding(binding)
	case stageFullFactory:
		if len(receipt.Predecessors) < 3 || receipt.Predecessors[0].StageKind != stageEvidenceIntake || receipt.Predecessors[len(receipt.Predecessors)-1].StageKind != stageGraphCompile {
			return fmt.Errorf("full factory receipt has invalid predecessor stage order")
		}
		for _, ref := range receipt.Predecessors[1 : len(receipt.Predecessors)-1] {
			if ref.StageKind != stageSemanticExtraction {
				return fmt.Errorf("full factory receipt has invalid predecessor stage order")
			}
		}
		var binding fullFactoryStageBinding
		if err := decodeClosedStageJSON(receipt.Binding, &binding, "stage_validation"); err != nil {
			return err
		}
		ledger := newStageDigestLedger()
		return validateStageValidationBinding("full factory stage_validation", binding.StageValidation, ledger)
	default:
		return fmt.Errorf("unknown receipt stage_kind %q", receipt.StageKind)
	}
}

func decodeEvidenceIntakeBinding(raw []byte, destination *evidenceIntakeStageBinding) error {
	if err := decodeClosedStageJSON(raw, destination, "stage_validation", "authority_pins", "selection_roster", "evidence_manifests"); err != nil {
		return fmt.Errorf("evidence intake receipt binding: %w", err)
	}
	pinsRaw, manifests, err := stageNestedValues(raw, "authority_pins", "evidence_manifests")
	if err != nil {
		return err
	}
	if err := requireExactStageKeys(pinsRaw, "ood_graph", "grand_vision", "source_record", "extension_protocol"); err != nil {
		return fmt.Errorf("evidence intake authority_pins: %w", err)
	}
	var object map[string]json.RawMessage
	_ = json.Unmarshal(raw, &object)
	var authorityObject map[string]json.RawMessage
	_ = json.Unmarshal(pinsRaw, &authorityObject)
	for _, name := range []string{"ood_graph", "grand_vision", "source_record", "extension_protocol"} {
		if err := requireImmutableStagePinKeys(authorityObject[name]); err != nil {
			return fmt.Errorf("authority_pins.%s: %w", name, err)
		}
	}
	if err := requireStageValidationKeys(object["stage_validation"]); err != nil {
		return fmt.Errorf("stage_validation: %w", err)
	}
	if err := requireExactStageKeys(object["selection_roster"], "role", "id", "version", "raw_sha256"); err != nil {
		return fmt.Errorf("selection_roster: %w", err)
	}
	for index, manifestRaw := range manifests {
		if err := requireExactStageKeys(manifestRaw, "role", "artifact_id", "artifact_version", "artifact_raw_sha256", "body_count", "byte_count"); err != nil {
			return fmt.Errorf("evidence manifest %d: %w", index, err)
		}
	}
	return nil
}

func decodeSemanticExtractionBinding(raw []byte, destination *semanticExtractionStageBinding) error {
	if err := decodeClosedStageJSON(raw, destination, "stage_validation", "applicability_profile", "artifact_role_roster", "artifact_outputs", "derivation_bindings"); err != nil {
		return fmt.Errorf("semantic extraction receipt binding: %w", err)
	}
	var object map[string]json.RawMessage
	_ = json.Unmarshal(raw, &object)
	if err := requireStageValidationKeys(object["stage_validation"]); err != nil {
		return fmt.Errorf("stage_validation: %w", err)
	}
	if err := requireImmutableStagePinKeys(object["applicability_profile"]); err != nil {
		return fmt.Errorf("applicability_profile: %w", err)
	}
	checks := []struct {
		field string
		keys  []string
	}{
		{"artifact_role_roster", []string{"role", "disposition"}},
		{"artifact_outputs", []string{"role", "artifact_id", "artifact_version", "artifact_raw_sha256", "derivation_binding_ids"}},
		{"derivation_bindings", []string{"binding_id", "extractor", "schema"}},
	}
	for _, check := range checks {
		var rows []json.RawMessage
		if err := json.Unmarshal(object[check.field], &rows); err != nil {
			return fmt.Errorf("%s: %w", check.field, err)
		}
		for index, row := range rows {
			if err := requireExactStageKeys(row, check.keys...); err != nil {
				return fmt.Errorf("%s[%d]: %w", check.field, index, err)
			}
			if check.field == "derivation_bindings" {
				var nested map[string]json.RawMessage
				_ = json.Unmarshal(row, &nested)
				for _, name := range []string{"extractor", "schema"} {
					if err := requireImmutableStagePinKeys(nested[name]); err != nil {
						return fmt.Errorf("%s[%d].%s: %w", check.field, index, name, err)
					}
				}
			}
		}
	}
	return nil
}

func decodeGraphCompileBinding(raw []byte, destination *graphCompileStageBinding) error {
	if err := decodeClosedStageJSON(raw, destination, "stage_validation", "dependency_artifacts", "plan", "subjects", "facts", "gaps"); err != nil {
		return fmt.Errorf("graph compile receipt binding: %w", err)
	}
	var object map[string]json.RawMessage
	_ = json.Unmarshal(raw, &object)
	if err := requireStageValidationKeys(object["stage_validation"]); err != nil {
		return fmt.Errorf("stage_validation: %w", err)
	}
	if err := requireGraphCompileDependencyArtifactKeys(raw); err != nil {
		return err
	}
	for _, name := range []string{"subjects", "facts", "gaps"} {
		if err := requireExactStageKeys(object[name], "root_sha256", "count"); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := requireExactStageKeys(object["plan"], "role", "id", "version", "raw_sha256"); err != nil {
		return fmt.Errorf("plan: %w", err)
	}
	return nil
}

func requireGraphCompileDependencyArtifactKeys(raw []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	var dependencies []json.RawMessage
	if err := json.Unmarshal(object["dependency_artifacts"], &dependencies); err != nil {
		return fmt.Errorf("dependency_artifacts: %w", err)
	}
	for index, dependency := range dependencies {
		if err := requireExactStageKeys(dependency, "role", "id", "version", "raw_sha256"); err != nil {
			return fmt.Errorf("dependency_artifacts[%d]: %w", index, err)
		}
	}
	return nil
}

func requireStageValidationKeys(raw []byte) error {
	if err := requireExactStageKeys(raw, "schema", "profile"); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	_ = json.Unmarshal(raw, &object)
	for _, name := range []string{"schema", "profile"} {
		if err := requireImmutableStagePinKeys(object[name]); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func requireImmutableStagePinKeys(raw []byte) error {
	return requireExactStageKeys(raw, "role", "id", "version", "raw_sha256", "expected_authority_class")
}

func stageNestedValues(raw []byte, objectField, arrayField string) ([]byte, []json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, nil, err
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(object[arrayField], &rows); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", arrayField, err)
	}
	return object[objectField], rows, nil
}

func validateGeneratedReceiptDigestSeparation(receipt stageReceipt) error {
	ledger := newStageDigestLedger()
	digests := []struct {
		label  string
		digest string
	}{
		{label: "request_sha256", digest: receipt.RequestSHA256},
		{label: "output_root_sha256", digest: receipt.OutputRootSHA256},
		{label: "receipt_sha256", digest: receipt.ReceiptSHA256},
	}
	for _, item := range digests {
		label, digest := item.label, item.digest
		if err := ledger.add(label, digest); err != nil {
			return fmt.Errorf("stage receipt: %w", err)
		}
	}
	for index, ref := range receipt.Predecessors {
		if err := ledger.add(fmt.Sprintf("predecessors[%d].receipt_sha256", index), ref.ReceiptSHA256); err != nil {
			return fmt.Errorf("stage receipt: %w", err)
		}
		if err := ledger.add(fmt.Sprintf("predecessors[%d].output_root_sha256", index), ref.OutputRootSHA256); err != nil {
			return fmt.Errorf("stage receipt: %w", err)
		}
	}
	evidenceByDigest := map[string]StageEvidenceCommitment{}
	for index, commitment := range receipt.EvidenceCommitments {
		if prior, duplicateContent := evidenceByDigest[commitment.BodySHA256]; duplicateContent {
			if prior.ByteCount != commitment.ByteCount {
				return fmt.Errorf("stage receipt: byte-equal evidence commitments disagree on byte_count")
			}
			continue
		}
		if err := ledger.add(fmt.Sprintf("evidence_commitments[%d].body_sha256", index), commitment.BodySHA256); err != nil {
			return fmt.Errorf("stage receipt: %w", err)
		}
		evidenceByDigest[commitment.BodySHA256] = commitment
	}
	return nil
}

type stageDigestLedger struct{ labels map[string]string }

func newStageDigestLedger() *stageDigestLedger {
	return &stageDigestLedger{labels: map[string]string{}}
}

func (ledger *stageDigestLedger) add(label, digest string) error {
	if !isLowerSHA256(digest) {
		return fmt.Errorf("%s is not an exact lowercase SHA-256", label)
	}
	if prior, exists := ledger.labels[digest]; exists {
		return fmt.Errorf("digest %s aliases %s and %s", digest, prior, label)
	}
	ledger.labels[digest] = label
	return nil
}

func requireSafeStageCount(label string, count uint64) error {
	if count > maxExactStageCount {
		return fmt.Errorf("%s %d exceeds the exact interoperable count bound %d", label, count, maxExactStageCount)
	}
	return nil
}

func validStageKind(kind string) bool {
	switch kind {
	case stageEvidenceIntake, stageSemanticExtraction, stageGraphCompile, stageFullFactory:
		return true
	default:
		return false
	}
}
