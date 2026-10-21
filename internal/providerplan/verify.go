package providerplan

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	receiptKind           = "provider_documentation_graph_plan_preflight_receipt"
	receiptVersion        = "9"
	exactLocatorSemantics = "evidence_manifest_digest_plus_atomic_source_coordinate_plus_source_digest_plus_zero_based_half_open_byte_range_plus_selected_range_digest"
	locatorIdentityDomain = "provider_documentation_candidate_evidence_locator_v4"
	resultComplete        = "structural_candidate_only"
	resultCompleteWithGap = "structural_candidate_only_with_explicit_fail_closed_gaps"

	supportedEvidenceRepresentationKind = "source_declared_machine_export"
	evidenceManifestAuthorityExact      = "selected_source_declared_machine_export_is_the_documentation_evidence_body"
	evidenceBodyAuthorityExact          = "selected_source_declared_machine_export"
	symbolAuthorityStatusExact          = "structural_candidate_pending_independent_generic_reexecution_and_admission"
	relationAuthorityStatusExact        = "structural_candidate_pending_endpoint_role_validation_generic_reexecution_and_admission"
	propertyAuthorityStatusExact        = "structural_candidate_pending_property_schema_and_derivation_profile_admission"
	zeroBasedHalfOpenLocatorForm        = "zero_based_half_open_byte_range"
	componentByteDomainProfile          = "transport_decoded_representation_bytes_v1"
	sourceContentHashProfile            = "transport_decoded_representation_bytes_v1"
	manifestCanonicalBytesProfile       = "canonical_component_manifest_v1"
	selectedRosterCompletenessBasis     = "exact_selected_source_roster_binding_not_source_declared_component_completeness"
	evidenceBodyKindSourceDocument      = "source_document"
)

var (
	credentialAssignmentPattern       = regexp.MustCompile(`(?i)(?:access[ _-]?token|refresh[ _-]?token|client[ _-]?secret|api[ _-]?key|password|bearer[ _-]?token|aws[ _-]?secret[ _-]?access[ _-]?key|consumer[ _-]?secret|signing[ _-]?secret|webhook[ _-]?secret|verification[ _-]?token)\s*(?:=|:)\s*["']?([^\s"',;}{]+)`)
	authorizationCredentialPattern    = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{16,})`)
	jwtPattern                        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b`)
	evidenceBodyBaseKeys              = []string{"body_authority", "component_byte_domain_profile", "component_byte_length", "component_ordinal", "component_sha256", "component_stable_coordinate", "content_bytes", "content_sha256", "observed_line_delimiter_profile", "representation", "representation_coordinate", "row_kind", "source_content_hash_profile", "source_ref", "source_representation_kind", "source_url", "staging_file"}
	evidenceManifestBaseKeys          = []string{"artifact", "artifact_version", "canonical_bytes", "provider", "representation", "representation_coordinate", "row_kind", "source_representation_kind", "status"}
	evidenceSummaryKeys               = []string{"captured_source_count", "missing_source_refs", "rendered_dom_body_accepted", "result", "row_kind", "selected_representation_is_only_evidence_body", "selected_source_count", "total_exact_source_bytes", "unexpected_source_refs"}
	canonicalSurfaceKindPattern       = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	providerPlanEvidenceConsumerRoles = map[string]struct{}{
		"api_graph_projection":       {},
		"field_mapping_candidate":    {},
		"protocol_contract_index":    {},
		"sample_shape_index":         {},
		"source_contract_index":      {},
		"surface_family_disposition": {},
	}
)

// Options names every authority input used by the offline preflight. The
// verifier performs no network or graph write and never accepts an
// organization_id from the candidate plan.
type Options struct {
	OODSpecPath                   string
	ExpectedOODSpecSHA256         string
	GrandVisionPath               string
	ExpectedGrandVisionSHA256     string
	SourceRecordSpecPath          string
	ExpectedSourceRecordSHA256    string
	GraphCompileInputManifestPath string
	EvidenceManifestPath          []string
	DependencyArtifactPath        []string

	// Tests in this package may supply the same exact request/input values in
	// memory. Production callers use GraphCompileInputManifestPath; both paths
	// enter the identical stage compiler and proof-minting authority chain.
	graphCompileRequestRaw      []byte
	graphCompileInputs          StageCompileInputs
	graphCompileSelectionLoader func() ([]byte, StageCompileInputs, error)
	inputAdmissionObserver      func(providerInputAdmissionProof, []providerInputAdmissionResourceReceipt) error
	inputAdmissionAfterOpenStat func(resourceKind, path string) error
	inputAdmissionAccumulator   *providerInputAdmissionAccumulator
	inputAdmissionBeforeFinish  func() error
}

type Receipt struct {
	ReceiptKind                                     string                        `json:"receipt_kind"`
	ReceiptVersion                                  string                        `json:"receipt_version"`
	ReceiptSHA256                                   string                        `json:"receipt_sha256"`
	Result                                          string                        `json:"result"`
	Scope                                           string                        `json:"scope"`
	Provider                                        string                        `json:"provider"`
	OODSpecSHA256                                   string                        `json:"ood_spec_sha256"`
	OODSpecStatus                                   string                        `json:"ood_spec_status"`
	GrandVisionSHA256                               string                        `json:"grand_vision_sha256"`
	SourceRecordSpecSHA256                          string                        `json:"source_record_spec_sha256"`
	SourceRecordSpecStatus                          string                        `json:"source_record_spec_status"`
	PlanSHA256                                      string                        `json:"plan_sha256"`
	GraphCompileStageReceiptSHA256                  string                        `json:"graph_compile_stage_receipt_sha256"`
	GraphCompileStageOutputRootSHA256               string                        `json:"graph_compile_stage_output_root_sha256"`
	GraphPlanValidationProfileSHA256                string                        `json:"graph_plan_validation_profile_sha256"`
	GraphPlanProfileSchemaSHA256                    string                        `json:"graph_plan_profile_schema_sha256"`
	GraphPlanSchemaID                               string                        `json:"graph_plan_schema_id"`
	GraphPlanSchemaVersion                          string                        `json:"graph_plan_schema_version"`
	GraphPlanSchemaSHA256                           string                        `json:"graph_plan_schema_sha256"`
	EvidenceManifestSHA256                          []string                      `json:"evidence_manifest_sha256"`
	EvidenceBodyCount                               int                           `json:"evidence_body_count"`
	SelectedEvidenceRepresentationKind              string                        `json:"selected_evidence_representation_kind"`
	EvidenceCompletenessBasis                       string                        `json:"evidence_completeness_basis"`
	EvidenceSelectionRosterSHA256                   string                        `json:"evidence_selection_roster_sha256"`
	SelectedRosterCompletenessProven                bool                          `json:"selected_roster_completeness_proven"`
	SourceDeclaredCompletenessProven                bool                          `json:"source_declared_completeness_proven"`
	DependencyArtifactSHA256                        []string                      `json:"dependency_artifact_sha256"`
	DependencyArtifactCount                         int                           `json:"dependency_artifact_count"`
	ProviderInputAdmissionProofSHA256               string                        `json:"provider_input_admission_proof_sha256"`
	ProviderInputAdmissionResourceSetRootSHA256     string                        `json:"provider_input_admission_resource_set_root_sha256"`
	ProviderInputAdmissionLimits                    providerInputAdmissionLimits  `json:"provider_input_admission_limits"`
	ProviderInputAdmissionActuals                   providerInputAdmissionActuals `json:"provider_input_admission_actuals"`
	DependencyBindingRule                           string                        `json:"dependency_binding_rule"`
	DocumentationDerivationClosureProofSHA256       string                        `json:"documentation_derivation_closure_proof_sha256"`
	DocumentationDerivationProfileArtifactSHA256    string                        `json:"documentation_derivation_profile_artifact_sha256"`
	SourceClassificationProofSHA256                 string                        `json:"source_classification_proof_sha256"`
	DocumentationDerivationProfilePageSetRootSHA256 string                        `json:"documentation_derivation_profile_page_set_root_sha256"`
	DocumentationDerivationProfileResultRootSHA256  string                        `json:"documentation_derivation_profile_result_root_sha256"`
	DocumentationTargetMaterializationRootSHA256    string                        `json:"documentation_target_materialization_root_sha256"`
	DocumentationTargetBindingRosterRootSHA256      string                        `json:"documentation_target_binding_roster_root_sha256"`
	DocumentationDerivationProfileCount             int64                         `json:"documentation_derivation_profile_count"`
	DocumentationDerivationOutcomeCount             int64                         `json:"documentation_derivation_outcome_count"`
	DocumentationDerivedFactCount                   int64                         `json:"documentation_derived_fact_count"`
	DocumentationDerivationPageCount                int64                         `json:"documentation_derivation_page_count"`
	DocumentationWholeRowBindingCount               int64                         `json:"documentation_whole_row_binding_count"`
	DocumentationRowMemberBindingCount              int64                         `json:"documentation_row_member_binding_count"`
	ExactHydratedEvidenceLocatorCount               int                           `json:"exact_hydrated_evidence_locator_count"`
	ExactSourceCoordinateBindingCount               int                           `json:"exact_source_coordinate_binding_count"`
	SourceCoordinateBindingRule                     string                        `json:"source_coordinate_binding_rule"`
	APISymbolCount                                  int                           `json:"api_symbol_count"`
	APIRelationshipCount                            int                           `json:"api_relationship_count"`
	APIPropertyClaimCount                           int                           `json:"api_property_claim_count"`
	ExplicitGraphGapCount                           int                           `json:"explicit_graph_gap_count"`
	AllowedAPIElementRoleRegistry                   []string                      `json:"allowed_api_element_role_registry"`
	AllowedAPIRelationshipLabelRegistry             []string                      `json:"allowed_api_relationship_label_registry"`
	AllowedAPIPropertyFamilyRegistry                []string                      `json:"allowed_api_property_family_registry"`
	MaterializedAPIElementRoles                     []string                      `json:"materialized_api_element_roles"`
	MaterializedAPIRelationshipLabels               []string                      `json:"materialized_api_relationship_labels"`
	MaterializedAPIPropertyFamilies                 []string                      `json:"materialized_api_property_families"`
	ExplicitGraphGapIDs                             []string                      `json:"explicit_graph_gap_ids,omitempty"`
	AuthorityHashesMatchExpectedPins                bool                          `json:"authority_hashes_match_expected_pins"`
	AuthoritySelectionCanonicalized                 bool                          `json:"authority_selection_canonicalized"`
	SelectedEvidenceBodyInDerivedArtifactsDetected  bool                          `json:"selected_evidence_body_in_derived_artifacts_detected"`
	BodyFreeSchemaBindingVerified                   bool                          `json:"body_free_schema_binding_verified"`
	BodyFreeSchemaAuthorityVerified                 bool                          `json:"body_free_schema_authority_verified"`
	CredentialMaterialDetected                      bool                          `json:"credential_material_detected"`
	OrganizationIDPresentInPlan                     bool                          `json:"organization_id_present_in_plan"`
	BinaryFloatAuthorityPresent                     bool                          `json:"binary_float_authority_present"`
	RawValueEmbeddingAllowed                        bool                          `json:"raw_value_embedding_allowed"`
	CanonicalAdmissionAuthorized                    bool                          `json:"canonical_admission_authorized"`
	CanonicalAdmissionAuthorizationRule             string                        `json:"canonical_admission_authorization_rule"`
}

// canonicalReceiptIdentity returns the canonical JSON identity for the whole
// top-level receipt except for its self-hash. Marshaling the complete Receipt
// before removing only receipt_sha256 makes every present and future receipt
// field part of the identity without maintaining a second field list.
func canonicalReceiptIdentity(receipt Receipt) ([]byte, error) {
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("marshal top-level receipt identity: %w", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("decode top-level receipt identity: %w", err)
	}
	if _, ok := object["receipt_sha256"]; !ok {
		return nil, fmt.Errorf("top-level receipt identity omits receipt_sha256")
	}
	delete(object, "receipt_sha256")
	identityRaw, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("marshal top-level receipt identity without self-hash: %w", err)
	}
	canonical, err := canonicalizeCandidateJSON(identityRaw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize top-level receipt identity: %w", err)
	}
	return canonical, nil
}

func receiptIdentitySHA256(receipt Receipt) (string, error) {
	identity, err := canonicalReceiptIdentity(receipt)
	if err != nil {
		return "", err
	}
	return sha256Hex(identity), nil
}

func sealReceipt(receipt Receipt) (Receipt, error) {
	receipt.ReceiptSHA256 = ""
	digest, err := receiptIdentitySHA256(receipt)
	if err != nil {
		return Receipt{}, err
	}
	receipt.ReceiptSHA256 = digest
	return receipt, nil
}

func validateReceiptIdentity(receipt Receipt) error {
	if !isLowerSHA256(receipt.ReceiptSHA256) {
		return fmt.Errorf("top-level receipt_sha256 must be a lowercase SHA-256")
	}
	expected, err := receiptIdentitySHA256(receipt)
	if err != nil {
		return err
	}
	if receipt.ReceiptSHA256 != expected {
		return fmt.Errorf("top-level receipt_sha256 %s does not match canonical receipt identity %s", receipt.ReceiptSHA256, expected)
	}
	return nil
}

type oodContract struct {
	DocID    string      `json:"doc_id"`
	Version  json.Number `json:"version"`
	Status   string      `json:"status"`
	Sections struct {
		ObjectModel struct {
			Roles struct {
				Roles           []string `json:"roles"`
				CardinalityRule string   `json:"cardinality_rule"`
				AuthorityRule   string   `json:"authority_rule"`
			} `json:"api_symbol_role_registry"`
			Properties struct {
				EligibleSubjects     []string `json:"eligible_subjects"`
				Families             []string `json:"property_families"`
				SchemaGovernanceRule string   `json:"schema_governance_rule"`
				EvidenceRule         string   `json:"evidence_rule"`
				AuthorityExclusions  []string `json:"authority_exclusions"`
			} `json:"api_property_claim_model"`
			ExternalRelationshipAuthorityBoundary struct {
				MaterializationRule string `json:"materialization_rule"`
			} `json:"external_relationship_authority_boundary"`
		} `json:"s2_graph_object_model"`
		EdgeModel struct {
			Relationships struct {
				Family                                   string                   `json:"family"`
				SourceClass                              string                   `json:"source_class"`
				TargetClass                              string                   `json:"target_class"`
				ProviderSpecificLabelsAllowed            bool                     `json:"provider_specific_labels_allowed"`
				FreeFormSubtypeAllowed                   bool                     `json:"free_form_subtype_allowed"`
				ReferencesOrDependsOnSubstitutionAllowed bool                     `json:"references_or_depends_on_substitution_allowed"`
				Constraints                              []relationshipConstraint `json:"labels_and_role_constraints"`
			} `json:"api_relationship_contract"`
		} `json:"s4_edge_model"`
		StorageModel struct {
			TableSurfaces map[string]oodTableSurface `json:"table_surfaces"`
		} `json:"s6_spanner_storage_model"`
		IdentityModel struct {
			ExternalRepresentation struct {
				Kinds []string `json:"representation_kind_values"`
			} `json:"external_canonical_representation_contract"`
			VersionCoordinateGrammar struct {
				ExternalEvidenceHashContract struct {
					CanonicalByteProfiles map[string]json.RawMessage `json:"canonical_byte_profiles"`
				} `json:"external_evidence_hash_contract"`
			} `json:"version_coordinate_grammar"`
		} `json:"s3_symbol_identity_and_addressing"`
		GraphMaterialization struct {
			ExternalReferenceIngestion struct {
				SourceAuthorityPolicy struct {
					AllowedSourceClasses   []string `json:"allowed_source_classes"`
					ForbiddenSourceClasses []string `json:"forbidden_source_classes"`
					Rule                   string   `json:"rule"`
				} `json:"source_authority_policy"`
				CanonicalIngestionExecutionModel struct {
					CapabilitySequence []string `json:"capability_sequence"`
					EntryCapability    string   `json:"entry_capability"`
				} `json:"canonical_ingestion_execution_model"`
				ObjectClassesCreated []string `json:"object_classes_created"`
				EdgeLabelsCreated    []string `json:"edge_labels_created"`
			} `json:"external_reference_ingestion_contract"`
		} `json:"s8_graph_materialization_and_ingestion"`
	} `json:"sections"`
}

type relationshipConstraint struct {
	EdgeLabel  string `json:"edge_label"`
	SourceRole string `json:"source_role"`
	TargetRole string `json:"target_role"`
}

type oodTableSurface struct {
	PhysicalTableName string            `json:"physical_table_name"`
	Purpose           string            `json:"purpose"`
	PrimaryKey        []string          `json:"primary_key"`
	Columns           map[string]string `json:"columns"`
}

type structuredAuthorityIdentity struct {
	DocID   string      `json:"doc_id"`
	Version json.Number `json:"version"`
	Status  string      `json:"status"`
}

type rowEnvelope struct {
	RowKind string `json:"row_kind"`
	Kind    string `json:"kind"`
}

type artifactManifest struct {
	RowKind                                   string                                  `json:"row_kind"`
	Artifact                                  string                                  `json:"artifact"`
	ArtifactVersion                           string                                  `json:"artifact_version"`
	Status                                    string                                  `json:"status"`
	Provider                                  string                                  `json:"provider"`
	NamedSystem                               string                                  `json:"named_system"`
	CanonicalOODGraphSHA256                   string                                  `json:"canonical_ood_graph_sha256"`
	ProviderNeutralProfileSHA256              string                                  `json:"provider_neutral_compilation_profile_sha256"`
	SourceContractIndexSHA256                 string                                  `json:"source_contract_index_sha256"`
	SampleShapeIndexSHA256                    string                                  `json:"sample_shape_index_sha256"`
	ProtocolContractIndexSHA256               string                                  `json:"protocol_contract_index_sha256"`
	EvidenceSelectionRosterSHA256             string                                  `json:"evidence_selection_roster_sha256"`
	OperationApplicabilityProfileSHA256       string                                  `json:"operation_applicability_profile_sha256"`
	EvidenceManifestBindings                  []evidenceManifestBinding               `json:"evidence_manifest_bindings"`
	FieldMappingCandidateSHA256               string                                  `json:"field_mapping_candidate_sha256"`
	FieldSecurityPolicySHA256                 string                                  `json:"field_security_policy_sha256"`
	MappingTransitiveDependencyRosterSHA256   string                                  `json:"mapping_transitive_dependency_roster_sha256"`
	DocumentationClaimDerivationProfileSHA256 string                                  `json:"documentation_claim_derivation_profile_sha256"`
	APIGraphApplicabilityProfileSHA256        string                                  `json:"api_graph_applicability_profile_sha256"`
	DependencySemanticValidation              dependencySemanticValidationPlanBinding `json:"dependency_semantic_validation"`
	EvidenceLocatorManifestSHA256             string                                  `json:"evidence_locator_manifest_sha256"`
}

type evidenceManifestBinding struct {
	EvidenceManifestSHA256 string   `json:"evidence_manifest_sha256"`
	EvidenceBodyKind       string   `json:"evidence_body_kind"`
	ConsumerRoles          []string `json:"consumer_roles"`
}

type evidenceLocator struct {
	RowKind                string   `json:"row_kind"`
	ID                     string   `json:"evidence_locator_id"`
	EvidenceManifestSHA256 string   `json:"evidence_manifest_sha256"`
	SourceContentSHA256    string   `json:"source_content_sha256"`
	ByteStartOffset        int64    `json:"byte_start_offset"`
	ByteEndOffsetExclusive int64    `json:"byte_end_offset_exclusive"`
	SelectedRangeByteCount int64    `json:"selected_range_byte_count"`
	SelectedRangeSHA256    string   `json:"selected_range_sha256"`
	SourceRefs             []string `json:"source_refs"`
	SourceURLs             []string `json:"source_urls"`
	LocatorSemantics       string   `json:"locator_semantics"`
	SourceBytesPresent     bool     `json:"source_bytes_present"`
}

type apiSymbol struct {
	RowKind            string          `json:"row_kind"`
	ID                 string          `json:"candidate_api_symbol_id"`
	Role               string          `json:"api_element_role"`
	SemanticKey        string          `json:"semantic_key"`
	DisplayName        string          `json:"display_name"`
	EvidenceLocatorIDs []string        `json:"evidence_locator_ids"`
	DerivationBinding  json.RawMessage `json:"derivation_binding"`
	AuthorityStatus    string          `json:"authority_status"`
	SourceBytesPresent bool            `json:"source_bytes_present"`
}

type apiRelationship struct {
	RowKind            string          `json:"row_kind"`
	ID                 string          `json:"candidate_api_relationship_id"`
	Label              string          `json:"relationship_label"`
	SourceID           string          `json:"source_candidate_api_symbol_id"`
	TargetID           string          `json:"target_candidate_api_symbol_id"`
	LocatorIDs         []string        `json:"evidence_locator_ids"`
	DerivationBinding  json.RawMessage `json:"derivation_binding"`
	AuthorityStatus    string          `json:"authority_status"`
	SourceBytesPresent bool            `json:"source_bytes_present"`
}

type apiPropertyClaim struct {
	RowKind            string          `json:"row_kind"`
	ID                 string          `json:"candidate_api_property_claim_id"`
	Family             string          `json:"property_family"`
	SubjectKind        string          `json:"subject_kind"`
	SubjectID          string          `json:"subject_candidate_id"`
	PropertyName       string          `json:"property_name"`
	CandidateValue     json.RawMessage `json:"candidate_value"`
	LocatorIDs         []string        `json:"evidence_locator_ids"`
	DerivationBinding  json.RawMessage `json:"derivation_binding"`
	AuthorityStatus    string          `json:"authority_status"`
	SourceBytesPresent bool            `json:"source_bytes_present"`
}

type graphGap struct {
	RowKind                     string          `json:"row_kind"`
	ID                          string          `json:"candidate_graph_gap_id"`
	GapClass                    string          `json:"gap_class"`
	BlockedSubjectKind          string          `json:"blocked_subject_kind"`
	BlockedSubjectID            string          `json:"blocked_subject_id"`
	BlockedClaimKind            string          `json:"blocked_claim_kind"`
	BlockedClaimID              string          `json:"blocked_claim_id"`
	Disposition                 string          `json:"disposition"`
	MaterializationEligible     bool            `json:"materialization_eligible"`
	ApplicabilityProfileID      string          `json:"applicability_profile_id"`
	ApplicabilityProfileVersion string          `json:"applicability_profile_version"`
	ApplicabilityProfileSHA256  string          `json:"applicability_profile_sha256"`
	ApplicabilityRuleID         string          `json:"applicability_rule_id"`
	EvidenceLocatorIDs          []string        `json:"supporting_evidence_locator_ids"`
	GapProofBinding             json.RawMessage `json:"gap_proof_binding"`
	DerivationBinding           json.RawMessage `json:"derivation_binding"`
	SourceBytesPresent          bool            `json:"source_bytes_present"`
}

type operationKindCount struct {
	OperationKind string `json:"operation_kind"`
	Count         int    `json:"count"`
}

type validationSummary struct {
	RowKind                                   string               `json:"row_kind"`
	ExactSourceDocumentCount                  int                  `json:"exact_source_document_count"`
	CandidateOperationCount                   int                  `json:"candidate_operation_count"`
	CapturedOperationKindCounts               []operationKindCount `json:"captured_operation_kind_counts"`
	ExactDocumentedFieldOccurrenceCount       int                  `json:"exact_documented_field_occurrence_count"`
	SampleJSONBlockCount                      int                  `json:"sample_json_block_count"`
	ProtocolAssertionCount                    int                  `json:"protocol_assertion_count"`
	PreservedContradictionCount               int                  `json:"preserved_contradiction_count"`
	CandidateEvidenceLocatorCount             int                  `json:"candidate_evidence_locator_count"`
	CandidateAPISymbolCount                   int                  `json:"candidate_api_symbol_count"`
	CandidateAPIRelationshipCount             int                  `json:"candidate_api_relationship_count"`
	CandidateAPIPropertyClaimCount            int                  `json:"candidate_api_property_claim_count"`
	CandidateGraphGapCount                    int                  `json:"candidate_graph_gap_count"`
	APIElementRolesMaterialized               int                  `json:"api_element_roles_materialized"`
	APIRelationshipLabelsMaterialized         int                  `json:"api_relationship_labels_materialized"`
	APIPropertyFamiliesMaterialized           int                  `json:"api_property_families_materialized"`
	OperationApplicabilityCount               int                  `json:"operation_applicability_count"`
	CandidateSubjectCount                     int                  `json:"candidate_subject_count"`
	SubjectSetRootSHA256                      string               `json:"subject_set_root_sha256"`
	FactSetRootSHA256                         string               `json:"fact_set_root_sha256"`
	GapSetRootSHA256                          string               `json:"gap_set_root_sha256"`
	SourceBytesPresent                        bool                 `json:"source_bytes_present"`
	CredentialsPresent                        bool                 `json:"credentials_present"`
	OrganizationIDPresent                     bool                 `json:"organization_id_present"`
	CallerSuppliedOrganizationIDAllowed       bool                 `json:"caller_supplied_organization_id_allowed"`
	BinaryFloatAuthoritative                  bool                 `json:"binary_float_authoritative"`
	RawValueEmbeddingAllowed                  bool                 `json:"raw_value_embedding_allowed"`
	AdmittedDerivationProfileProofEstablished bool                 `json:"admitted_derivation_profile_proof_established"`
	ReadyForAdmission                         bool                 `json:"ready_for_admission"`
	Result                                    string               `json:"result"`
}

type evidenceManifestEnvelope struct {
	RowKind string `json:"row_kind"`
}

type externalEvidenceBody struct {
	RowKind                      string `json:"row_kind"`
	ComponentOrdinal             int64  `json:"component_ordinal"`
	ComponentStableCoordinate    string `json:"component_stable_coordinate"`
	ComponentByteLength          int64  `json:"component_byte_length"`
	ComponentSHA256              string `json:"component_sha256"`
	ComponentByteDomainProfile   string `json:"component_byte_domain_profile"`
	SourceRef                    string `json:"source_ref"`
	SourceURL                    string `json:"source_url"`
	Representation               string `json:"representation"`
	RepresentationCoordinate     string `json:"representation_coordinate"`
	SourceRepresentationKind     string `json:"source_representation_kind"`
	ContentSHA256                string `json:"content_sha256"`
	ContentBytes                 int64  `json:"content_bytes"`
	SourceContentHashProfile     string `json:"source_content_hash_profile"`
	ObservedLineDelimiterProfile string `json:"observed_line_delimiter_profile"`
	StagingFile                  string `json:"staging_file"`
	BodyAuthority                string `json:"body_authority"`
}

type evidenceSourceCoordinate struct {
	Ref string
	URL string
}

type exactEvidenceBody struct {
	Bytes       []byte
	Coordinates map[evidenceSourceCoordinate]string
}

type evidenceBodyMetadata struct {
	ManifestSHA256             string
	SourceRef                  string
	SourceURL                  string
	ContentSHA256              string
	ContentBytes               int64
	Representation             string
	RepresentationCoordinate   string
	SourceRepresentationKind   string
	ComponentByteDomainProfile string
	SourceContentHashProfile   string
	ConsumerRoles              map[string]struct{}
}

type evidenceBodyIdentity struct {
	ManifestSHA256 string
	SourceRef      string
	ContentSHA256  string
}

func sortedEvidenceBodyIdentityKeys[T any](values map[evidenceBodyIdentity]T) []evidenceBodyIdentity {
	identities := make([]evidenceBodyIdentity, 0, len(values))
	for identity := range values {
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].ManifestSHA256 != identities[j].ManifestSHA256 {
			return identities[i].ManifestSHA256 < identities[j].ManifestSHA256
		}
		if identities[i].SourceRef != identities[j].SourceRef {
			return identities[i].SourceRef < identities[j].SourceRef
		}
		return identities[i].ContentSHA256 < identities[j].ContentSHA256
	})
	return identities
}

type artifactParsedRow struct {
	Line            int
	Discriminator   string
	Kind            string
	Data            map[string]interface{}
	CanonicalSHA256 string
	RawStart        int
	RawEnd          int
}

type artifactInput struct {
	Path                       string
	SHA256                     string
	Raw                        []byte
	Manifest                   map[string]interface{}
	ValidationSummary          map[string]interface{}
	RowKindCounts              map[string]int
	RowsByKind                 map[string][]map[string]interface{}
	ParsedRows                 []artifactParsedRow
	Discriminator              string
	Structured                 bool
	EvidenceBodyCount          int
	EvidenceByteCount          int64
	EvidenceBodyKind           string
	EvidenceRepresentationKind string
	InputAdmissionResource     providerInputAdmissionResourceReceipt
	InputAdmissionProofSHA256  string
}

type loadedEvidence struct {
	Bodies                         map[string]exactEvidenceBody
	Artifacts                      map[string]artifactInput
	MetadataByCoordinate           map[evidenceSourceCoordinate]evidenceBodyMetadata
	MetadataByIdentity             map[evidenceBodyIdentity]evidenceBodyMetadata
	ClassificationsBySourceSymbol  map[string][]sourceClassificationOccurrence
	ClassificationSelectionProofs  map[string]sourceClassificationSelectionProof
	CandidateSymbolsBySourceSymbol map[string]string
	BodyCoordinateRows             int
	InputAdmissionResources        []providerInputAdmissionResourceReceipt
	InputAdmissionProof            providerInputAdmissionProof
}

type parsedPlan struct {
	Manifest             *artifactManifest
	Summary              *validationSummary
	Locators             map[string]evidenceLocator
	LocatorCanonicalRows map[string][]byte
	LocatorOrder         []string
	Symbols              map[string]apiSymbol
	Relationships        map[string]apiRelationship
	Properties           map[string]apiPropertyClaim
	Gaps                 map[string]graphGap
}

func loadGraphCompileSelection(opts Options) ([]byte, StageCompileInputs, error) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	requestRaw, inputs, binding, err := loadGraphCompileSelectionWithAdmission(opts, accumulator)
	if err != nil {
		return nil, StageCompileInputs{}, err
	}
	if len(binding.Items) != 0 {
		proof, sealErr := accumulator.seal()
		if sealErr != nil {
			return nil, StageCompileInputs{}, fmt.Errorf("seal exact graph_compile file admission: %w", sealErr)
		}
		if bindErr := bindAndValidateStageCompileInputAdmission(&binding, proof, accumulator.resources); bindErr != nil {
			return nil, StageCompileInputs{}, bindErr
		}
	}
	return requestRaw, inputs, nil
}

func loadGraphCompileSelectionWithAdmission(opts Options, accumulator *providerInputAdmissionAccumulator) ([]byte, StageCompileInputs, stageCompileInputAdmissionBinding, error) {
	hasFileManifest := strings.TrimSpace(opts.GraphCompileInputManifestPath) != ""
	hasInMemory := len(opts.graphCompileRequestRaw) != 0 || len(opts.graphCompileInputs.Materials) != 0 || len(opts.graphCompileInputs.PredecessorReceipts) != 0 || len(opts.graphCompileInputs.EvidenceBodies) != 0
	hasInPackageLoader := opts.graphCompileSelectionLoader != nil
	selectionCount := 0
	for _, selected := range []bool{hasFileManifest, hasInMemory, hasInPackageLoader} {
		if selected {
			selectionCount++
		}
	}
	if selectionCount != 1 {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, fmt.Errorf("select exactly one graph_compile input manifest or in-package exact request/input source")
	}
	if hasFileManifest {
		return loadStageCompileFileManifestWithAdmission(opts.GraphCompileInputManifestPath, accumulator)
	}
	if hasInPackageLoader {
		requestRaw, inputs, err := opts.graphCompileSelectionLoader()
		return requestRaw, inputs, stageCompileInputAdmissionBinding{}, err
	}
	if len(opts.graphCompileRequestRaw) == 0 {
		return nil, StageCompileInputs{}, stageCompileInputAdmissionBinding{}, fmt.Errorf("in-package graph_compile request bytes are empty")
	}
	return opts.graphCompileRequestRaw, opts.graphCompileInputs, stageCompileInputAdmissionBinding{}, nil
}

func exactGraphPlanMaterial(proof graphPlanParseProof, inputs StageCompileInputs) ([]byte, error) {
	if proof.seal != graphPlanParseAuthority || proof.structural.seal != graphPlanSchemaBindingAuthority {
		return nil, fmt.Errorf("exact graph plan material requires a sealed graph_compile parse proof")
	}
	want := stageCoordinateForIdentity(proof.structural.plan)
	var selected []byte
	for _, material := range inputs.Materials {
		if (stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}) != want {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("graph_compile inputs duplicate the sealed plan coordinate")
		}
		selected = material.Raw
	}
	if selected == nil {
		return nil, fmt.Errorf("graph_compile inputs omit the sealed plan coordinate")
	}
	if got := sha256Hex(selected); got != proof.structural.plan.RawSHA256 {
		return nil, fmt.Errorf("graph_compile plan material digest %s differs from sealed digest %s", got, proof.structural.plan.RawSHA256)
	}
	return selected, nil
}

// Verify validates one body-free provider graph plan against the live OOD
// contract bytes and exact source-declared evidence bodies. It returns a
// body-free preflight receipt and never authorizes canonical admission.
func Verify(opts Options) (Receipt, error) {
	if opts.OODSpecPath == "" || opts.GrandVisionPath == "" || opts.SourceRecordSpecPath == "" || len(opts.EvidenceManifestPath) == 0 {
		return Receipt{}, fmt.Errorf("OOD spec, Grand Vision, Source Record spec, graph_compile stage inputs, and at least one evidence manifest are required")
	}
	if err := validateProviderVerificationTopLevelPathSyntax(opts); err != nil {
		return Receipt{}, err
	}
	expectedPins := []struct {
		name   string
		digest string
	}{
		{name: "expected OOD spec", digest: opts.ExpectedOODSpecSHA256},
		{name: "expected Grand Vision", digest: opts.ExpectedGrandVisionSHA256},
		{name: "expected Source Record", digest: opts.ExpectedSourceRecordSHA256},
	}
	for _, pin := range expectedPins {
		if !isLowerSHA256(pin.digest) {
			return Receipt{}, fmt.Errorf("%s authority digest must be supplied as lowercase SHA-256", pin.name)
		}
	}
	inputAdmission := opts.inputAdmissionAccumulator
	if inputAdmission == nil {
		inputAdmission = newCanonicalProviderInputAdmissionAccumulator()
	}
	// A factory run supplies the exact stage-input admission session that
	// already owns the graph selection and every stage material. Preserve that
	// closed pre-verifier roster so the downstream binding can prove set
	// equality without reopening or pretending those stage receipts belong to
	// the verifier's authority/evidence/dependency roles.
	priorInputAdmissionResources := inputAdmission.orderedResources()
	inputAdmission.afterOpenStat = opts.inputAdmissionAfterOpenStat
	if err := inputAdmission.preflightPathCount(providerInputAdmissionResourceKindAuthority, int(maxVerificationAuthorityCount)); err != nil {
		return Receipt{}, fmt.Errorf("verification authority inputs: %w", err)
	}
	authorityAdmission := verificationAuthorityInputAdmissionBinding{Items: make([]verificationAuthorityInputAdmissionItem, 0, maxVerificationAuthorityCount)}
	oodAuthority, err := readVerificationAuthorityWithAdmission(opts.OODSpecPath, verificationAuthorityRoleOODGraph, inputAdmission)
	if err != nil {
		return Receipt{}, err
	}
	authorityAdmission.Items = append(authorityAdmission.Items, oodAuthority)
	oodBytes := oodAuthority.Raw
	if err := requireValidUTF8("OOD spec", oodBytes); err != nil {
		return Receipt{}, err
	}
	if err := inputAdmission.admitStructuredJSONDocument(opts.OODSpecPath, "OOD spec", providerInputAdmissionResourceKindAuthority, oodBytes); err != nil {
		return Receipt{}, err
	}
	if err := rejectDuplicateJSONKeys(oodBytes); err != nil {
		return Receipt{}, fmt.Errorf("OOD spec: %w", err)
	}
	var ood oodContract
	if err := json.Unmarshal(oodBytes, &ood); err != nil {
		return Receipt{}, fmt.Errorf("decode OOD spec: %w", err)
	}
	if ood.DocID == "" || ood.Version.String() == "" || ood.Status != "locked" {
		return Receipt{}, fmt.Errorf("selected OOD authority has no locked doc_id/version identity")
	}
	if err := validateVerificationAuthorityExpectedPin(oodAuthority, opts.ExpectedOODSpecSHA256); err != nil {
		return Receipt{}, err
	}
	oodSHA := oodAuthority.Resource.ContentSHA256
	roles, constraints, families, eligiblePropertySubjects, err := normalizeOODContract(ood)
	if err != nil {
		return Receipt{}, err
	}
	representationKinds, err := normalizeExternalRepresentationKinds(ood)
	if err != nil {
		return Receipt{}, err
	}

	grandVisionAuthority, err := readVerificationAuthorityWithAdmission(opts.GrandVisionPath, verificationAuthorityRoleGrandVision, inputAdmission)
	if err != nil {
		return Receipt{}, err
	}
	authorityAdmission.Items = append(authorityAdmission.Items, grandVisionAuthority)
	grandVisionBytes := grandVisionAuthority.Raw
	if err := requireValidUTF8("selected Grand Vision authority", grandVisionBytes); err != nil {
		return Receipt{}, err
	}
	if len(bytes.TrimSpace(grandVisionBytes)) == 0 {
		return Receipt{}, fmt.Errorf("selected Grand Vision authority is empty")
	}
	if err := validateVerificationAuthorityExpectedPin(grandVisionAuthority, opts.ExpectedGrandVisionSHA256); err != nil {
		return Receipt{}, err
	}
	grandVisionSHA := grandVisionAuthority.Resource.ContentSHA256

	sourceRecordAuthority, err := readVerificationAuthorityWithAdmission(opts.SourceRecordSpecPath, verificationAuthorityRoleSourceRecord, inputAdmission)
	if err != nil {
		return Receipt{}, err
	}
	authorityAdmission.Items = append(authorityAdmission.Items, sourceRecordAuthority)
	sourceRecordBytes := sourceRecordAuthority.Raw
	if err := requireValidUTF8("selected Source Record authority", sourceRecordBytes); err != nil {
		return Receipt{}, err
	}
	if err := inputAdmission.admitStructuredJSONDocument(opts.SourceRecordSpecPath, "selected Source Record authority", providerInputAdmissionResourceKindAuthority, sourceRecordBytes); err != nil {
		return Receipt{}, err
	}
	if err := rejectDuplicateJSONKeys(sourceRecordBytes); err != nil {
		return Receipt{}, fmt.Errorf("selected Source Record authority: %w", err)
	}
	var sourceRecordIdentity structuredAuthorityIdentity
	if err := json.Unmarshal(sourceRecordBytes, &sourceRecordIdentity); err != nil {
		return Receipt{}, fmt.Errorf("decode selected Source Record authority: %w", err)
	}
	if sourceRecordIdentity.DocID == "" || sourceRecordIdentity.Version.String() == "" || sourceRecordIdentity.Status != "locked" {
		return Receipt{}, fmt.Errorf("selected Source Record authority has no locked doc_id/version identity")
	}
	if err := validateVerificationAuthorityExpectedPin(sourceRecordAuthority, opts.ExpectedSourceRecordSHA256); err != nil {
		return Receipt{}, err
	}
	sourceRecordSHA := sourceRecordAuthority.Resource.ContentSHA256

	graphRequestRaw, graphInputs, graphInputAdmission, err := loadGraphCompileSelectionWithAdmission(opts, inputAdmission)
	if err != nil {
		return Receipt{}, err
	}
	graphReceiptRaw, graphParseProof, err := compileGraphStageReceiptWithParseProof(graphRequestRaw, graphInputs)
	if err != nil {
		return Receipt{}, fmt.Errorf("validate exact graph_compile stage authority chain: %w", err)
	}
	graphReceipt, err := parseStageReceipt(graphReceiptRaw)
	if err != nil {
		return Receipt{}, fmt.Errorf("parse freshly validated graph_compile receipt: %w", err)
	}
	if graphReceipt.Summary.StageKind != graphParseProof.bodyFree.receipt.StageKind || graphReceipt.Summary.ReceiptSHA256 != graphParseProof.bodyFree.receipt.ReceiptSHA256 || graphReceipt.Summary.OutputRootSHA256 != graphParseProof.bodyFree.receipt.OutputRootSHA256 {
		return Receipt{}, fmt.Errorf("fresh graph_compile receipt identity differs from the sealed body-free proof")
	}
	planBytes, err := exactGraphPlanMaterial(graphParseProof, graphInputs)
	if err != nil {
		return Receipt{}, err
	}
	plan, err := parsePlan(planBytes, graphParseProof)
	if err != nil {
		return Receipt{}, err
	}
	if plan.Manifest.CanonicalOODGraphSHA256 != oodSHA {
		return Receipt{}, fmt.Errorf("plan OOD hash %q does not match selected OOD bytes %q", plan.Manifest.CanonicalOODGraphSHA256, oodSHA)
	}

	evidence, err := loadEvidenceBodiesWithAdmission(opts.EvidenceManifestPath, representationKinds, inputAdmission)
	if err != nil {
		return Receipt{}, err
	}
	dependencies, err := loadDependencyArtifactsWithAdmission(opts.DependencyArtifactPath, inputAdmission)
	if err != nil {
		return Receipt{}, err
	}
	if err := inputAdmission.revalidatePhysicalSnapshots(); err != nil {
		return Receipt{}, fmt.Errorf("revalidate exact provider input physical snapshots: %w", err)
	}
	inputAdmissionProof, err := inputAdmission.seal()
	if err != nil {
		return Receipt{}, fmt.Errorf("seal exact provider input admission: %w", err)
	}
	if err := bindAndValidateProviderInputAdmission(&evidence, dependencies, &authorityAdmission, &graphInputAdmission, priorInputAdmissionResources, inputAdmissionProof, inputAdmission.resources); err != nil {
		return Receipt{}, err
	}
	if opts.inputAdmissionObserver != nil {
		resources := append([]providerInputAdmissionResourceReceipt(nil), inputAdmission.resources...)
		if err := opts.inputAdmissionObserver(inputAdmissionProof, resources); err != nil {
			return Receipt{}, fmt.Errorf("observe exact provider input admission: %w", err)
		}
	}
	// Independently close selected-evidence reconstruction contained wholly in
	// the plan before semantic validation. The later whole-closure scan retains
	// transitive role ordering. Public commands separately enforce a
	// content-neutral diagnostic boundary for every validation failure.
	if err := validateNoEmbeddedEvidenceBodies("graph plan", planBytes, evidence.Bodies, 1); err != nil {
		return Receipt{}, err
	}
	semanticValidation, err := prepareDependencySemanticValidation(plan, dependencies)
	if err != nil {
		return Receipt{}, err
	}
	if err := validateGraphDependencySemanticClosure(plan, graphParseProof.structural, semanticValidation); err != nil {
		return Receipt{}, err
	}
	if err := validateCandidateClosureSecurity("graph plan", planBytes, plan, dependencies, semanticValidation, evidence.Bodies, 1); err != nil {
		return Receipt{}, err
	}
	if err := validatePlan(plan, roles, constraints, families, eligiblePropertySubjects, evidence.Bodies, graphParseProof.structural.derivedSets); err != nil {
		return Receipt{}, err
	}
	var derivationClosure documentationDerivationClosureProof
	if err := validateDependencyBindings(plan, ood, oodSHA, grandVisionSHA, sourceRecordIdentity, sourceRecordSHA, evidence, dependencies, semanticValidation, &derivationClosure); err != nil {
		return Receipt{}, err
	}
	if err := validateDocumentationDerivationClosureProof(derivationClosure); err != nil {
		return Receipt{}, fmt.Errorf("validate sealed documentation-derivation closure proof: %w", err)
	}
	roleList := sortedSetKeys(roles)
	labelList := sortedConstraintKeys(constraints)
	familyList := sortedSetKeys(families)
	materializedRoleList, materializedLabelList, materializedFamilyList := planMaterializedVocabulary(plan)
	gapIDs := make([]string, 0, len(plan.Gaps))
	for id := range plan.Gaps {
		gapIDs = append(gapIDs, id)
	}
	sort.Strings(gapIDs)
	evidenceHashes := sortedArtifactHashes(evidence.Artifacts)
	dependencyHashes := sortedArtifactHashes(dependencies)
	receipt := Receipt{
		ReceiptKind: receiptKind, ReceiptVersion: receiptVersion, Result: "pass",
		Scope:    "offline_exact_evidence_deterministic_documentation_derivation_and_structural_plan_preflight",
		Provider: plan.Manifest.Provider, OODSpecSHA256: oodSHA, OODSpecStatus: ood.Status, GrandVisionSHA256: grandVisionSHA, SourceRecordSpecSHA256: sourceRecordSHA, SourceRecordSpecStatus: sourceRecordIdentity.Status, PlanSHA256: sha256Hex(planBytes),
		GraphCompileStageReceiptSHA256:    graphReceipt.Summary.ReceiptSHA256,
		GraphCompileStageOutputRootSHA256: graphReceipt.Summary.OutputRootSHA256,
		GraphPlanValidationProfileSHA256:  graphParseProof.structural.profile.RawSHA256,
		GraphPlanProfileSchemaSHA256:      graphParseProof.structural.profileSchema.RawSHA256,
		GraphPlanSchemaID:                 graphParseProof.structural.planSchema.ID,
		GraphPlanSchemaVersion:            graphParseProof.structural.planSchema.Version,
		GraphPlanSchemaSHA256:             graphParseProof.structural.planSchema.RawSHA256,
		EvidenceManifestSHA256:            evidenceHashes, EvidenceBodyCount: evidence.BodyCoordinateRows,
		SelectedEvidenceRepresentationKind: supportedEvidenceRepresentationKind,
		EvidenceCompletenessBasis:          selectedRosterCompletenessBasis,
		EvidenceSelectionRosterSHA256:      plan.Manifest.EvidenceSelectionRosterSHA256,
		SelectedRosterCompletenessProven:   true,
		SourceDeclaredCompletenessProven:   false,
		DependencyArtifactSHA256:           dependencyHashes, DependencyArtifactCount: len(dependencies),
		ProviderInputAdmissionProofSHA256:               inputAdmissionProof.ProofSHA256,
		ProviderInputAdmissionResourceSetRootSHA256:     inputAdmissionProof.ResourceSetRootSHA256,
		ProviderInputAdmissionLimits:                    inputAdmissionProof.Limits,
		ProviderInputAdmissionActuals:                   inputAdmissionProof.Actuals,
		DependencyBindingRule:                           "graph_compile_dependency_roster_is_set_equal_to_the_plan_bound_semantic_validation_profile_and_closed_semantic_role_artifacts;every_declared_profile_intermediate_protocol_entity_transitive_artifact_and_validation_schema_digest_is_bound_to_exact_supplied_bytes;every_semantically_interpreted_artifact_is_validated_against_its_exact_plan_bound_json_schema_profile;every_documentation_derivation_program_is_reexecuted_over_the_sealed_exact_evidence_and_classification_selection_through_all_pages;every_emitted_fact_is_consumed_exactly_once_by_a_schema_authorized_whole_row_or_row_member;locator_and_operation_applicability_digests_are_bound_to_deterministic_candidate_graph_projections;every_evidence_and_candidate_dependency_summary_is_semantically_revalidated",
		DocumentationDerivationClosureProofSHA256:       derivationClosure.proofSHA256,
		DocumentationDerivationProfileArtifactSHA256:    derivationClosure.derivationProfileArtifactSHA256,
		SourceClassificationProofSHA256:                 derivationClosure.classificationProofSHA256,
		DocumentationDerivationProfilePageSetRootSHA256: derivationClosure.profilePageSetRootSHA256,
		DocumentationDerivationProfileResultRootSHA256:  derivationClosure.profileResultSetRootSHA256,
		DocumentationTargetMaterializationRootSHA256:    derivationClosure.targetMaterializationRootSHA256,
		DocumentationTargetBindingRosterRootSHA256:      derivationClosure.targetMaterializationBindingRosterRootSHA256,
		DocumentationDerivationProfileCount:             derivationClosure.profileCount,
		DocumentationDerivationOutcomeCount:             derivationClosure.outcomeCount,
		DocumentationDerivedFactCount:                   derivationClosure.factCount,
		DocumentationDerivationPageCount:                derivationClosure.pageCount,
		DocumentationWholeRowBindingCount:               derivationClosure.wholeRowBindingCount,
		DocumentationRowMemberBindingCount:              derivationClosure.rowMemberBindingCount,
		ExactHydratedEvidenceLocatorCount:               len(plan.Locators), ExactSourceCoordinateBindingCount: len(plan.Locators),
		SourceCoordinateBindingRule: "each_locator_has_exactly_one_atomic_stable_source_ref_plus_canonical_https_url_pair_bound_to_the_same_evidence_manifest_body_digest_and_the_pair_is_in_the_content_derived_locator_id",
		APISymbolCount:              len(plan.Symbols),
		APIRelationshipCount:        len(plan.Relationships), APIPropertyClaimCount: len(plan.Properties),
		ExplicitGraphGapCount:                          len(plan.Gaps),
		AllowedAPIElementRoleRegistry:                  roleList,
		AllowedAPIRelationshipLabelRegistry:            labelList,
		AllowedAPIPropertyFamilyRegistry:               familyList,
		MaterializedAPIElementRoles:                    materializedRoleList,
		MaterializedAPIRelationshipLabels:              materializedLabelList,
		MaterializedAPIPropertyFamilies:                materializedFamilyList,
		ExplicitGraphGapIDs:                            gapIDs,
		AuthorityHashesMatchExpectedPins:               true,
		AuthoritySelectionCanonicalized:                false,
		SelectedEvidenceBodyInDerivedArtifactsDetected: false,
		BodyFreeSchemaBindingVerified:                  true,
		BodyFreeSchemaAuthorityVerified:                false,
		CredentialMaterialDetected:                     false,
		OrganizationIDPresentInPlan:                    false,
		BinaryFloatAuthorityPresent:                    false,
		RawValueEmbeddingAllowed:                       false,
		CanonicalAdmissionAuthorized:                   false,
		CanonicalAdmissionAuthorizationRule:            "preflight_proves_expected_authority_hash_equality_exact_selected_bytes_direct_body_scan_deterministic_extractor_reexecution_all_page_completeness_and_exact_once_schema_authorized_candidate_materialization;current_origin_or_admitted_authority_selection_property_schema_admission_tenant_and_capability_bindings_remain_mandatory",
	}
	sealedReceipt, err := sealReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	if opts.inputAdmissionBeforeFinish != nil {
		if err := opts.inputAdmissionBeforeFinish(); err != nil {
			return Receipt{}, fmt.Errorf("provider input completion hook: %w", err)
		}
	}
	if err := inputAdmission.revalidatePhysicalSnapshots(); err != nil {
		return Receipt{}, fmt.Errorf("revalidate provider input physical snapshots at completion: %w", err)
	}
	completionInputAdmissionProof, err := inputAdmission.seal()
	if err != nil {
		return Receipt{}, fmt.Errorf("reseal exact provider input admission at completion: %w", err)
	}
	if completionInputAdmissionProof != inputAdmissionProof {
		return Receipt{}, fmt.Errorf("provider input admission proof changed before completion")
	}
	return sealedReceipt, nil
}

func validateProviderVerificationTopLevelPathSyntax(opts Options) error {
	paths := []struct {
		label string
		path  string
	}{
		{label: "OOD spec", path: opts.OODSpecPath},
		{label: "Grand Vision", path: opts.GrandVisionPath},
		{label: "Source Record spec", path: opts.SourceRecordSpecPath},
		{label: "graph_compile input manifest", path: opts.GraphCompileInputManifestPath},
	}
	for index, path := range opts.EvidenceManifestPath {
		paths = append(paths, struct {
			label string
			path  string
		}{label: fmt.Sprintf("evidence manifest[%d]", index), path: path})
	}
	for index, path := range opts.DependencyArtifactPath {
		paths = append(paths, struct {
			label string
			path  string
		}{label: fmt.Sprintf("dependency artifact[%d]", index), path: path})
	}
	for _, item := range paths {
		if item.path == "" {
			continue
		}
		if err := validateProviderInputPathSyntax(item.path, item.label); err != nil {
			return err
		}
	}
	return nil
}

func planMaterializedVocabulary(plan *parsedPlan) ([]string, []string, []string) {
	roles := map[string]struct{}{}
	labels := map[string]struct{}{}
	families := map[string]struct{}{}
	for _, symbol := range plan.Symbols {
		roles[symbol.Role] = struct{}{}
	}
	for _, relationship := range plan.Relationships {
		labels[relationship.Label] = struct{}{}
	}
	for _, property := range plan.Properties {
		families[property.Family] = struct{}{}
	}
	return sortedSetKeys(roles), sortedSetKeys(labels), sortedSetKeys(families)
}

func normalizeOODContract(ood oodContract) (map[string]struct{}, map[string]relationshipConstraint, map[string]struct{}, map[string]struct{}, error) {
	if strings.TrimSpace(ood.Sections.ObjectModel.Roles.CardinalityRule) == "" || strings.TrimSpace(ood.Sections.ObjectModel.Roles.AuthorityRule) == "" {
		return nil, nil, nil, nil, fmt.Errorf("OOD API role registry does not expose cardinality and immutable authority rules")
	}
	if strings.TrimSpace(ood.Sections.ObjectModel.Properties.SchemaGovernanceRule) == "" || strings.TrimSpace(ood.Sections.ObjectModel.Properties.EvidenceRule) == "" || len(ood.Sections.ObjectModel.Properties.AuthorityExclusions) == 0 || hasEmptyOrDuplicateSemanticStrings(ood.Sections.ObjectModel.Properties.AuthorityExclusions) {
		return nil, nil, nil, nil, fmt.Errorf("OOD API property model does not expose closed schema, evidence, and authority-exclusion rules")
	}
	if strings.TrimSpace(ood.Sections.ObjectModel.ExternalRelationshipAuthorityBoundary.MaterializationRule) == "" {
		return nil, nil, nil, nil, fmt.Errorf("OOD external relationship boundary does not expose an applicability/materialization rule")
	}
	relationshipContract := ood.Sections.EdgeModel.Relationships
	if relationshipContract.Family != "api_relationship" || relationshipContract.SourceClass != "api_symbol" || relationshipContract.TargetClass != "api_symbol" || relationshipContract.ProviderSpecificLabelsAllowed || relationshipContract.FreeFormSubtypeAllowed || relationshipContract.ReferencesOrDependsOnSubstitutionAllowed {
		return nil, nil, nil, nil, fmt.Errorf("OOD API relationship contract weakens its closed source-neutral api_symbol edge family")
	}
	ingestion := ood.Sections.GraphMaterialization.ExternalReferenceIngestion
	if len(ingestion.CanonicalIngestionExecutionModel.CapabilitySequence) == 0 || hasEmptyOrDuplicateSemanticStrings(ingestion.CanonicalIngestionExecutionModel.CapabilitySequence) || ingestion.CanonicalIngestionExecutionModel.EntryCapability != ingestion.CanonicalIngestionExecutionModel.CapabilitySequence[0] {
		return nil, nil, nil, nil, fmt.Errorf("OOD external-reference intake has no closed ordered capability sequence and matching entry")
	}
	closedRegistries := []struct {
		label  string
		values []string
	}{
		{label: "external object classes", values: ingestion.ObjectClassesCreated},
		{label: "external edge labels", values: ingestion.EdgeLabelsCreated},
		{label: "allowed source classes", values: ingestion.SourceAuthorityPolicy.AllowedSourceClasses},
		{label: "forbidden source classes", values: ingestion.SourceAuthorityPolicy.ForbiddenSourceClasses},
	}
	for _, registry := range closedRegistries {
		label, values := registry.label, registry.values
		if len(values) == 0 || hasEmptyOrDuplicateSemanticStrings(values) {
			return nil, nil, nil, nil, fmt.Errorf("OOD external-reference intake has no closed %s registry", label)
		}
	}
	if strings.TrimSpace(ingestion.SourceAuthorityPolicy.Rule) == "" {
		return nil, nil, nil, nil, fmt.Errorf("OOD external-reference intake has no source-authority policy rule")
	}
	allowedSourceClasses := stringSliceSet(ingestion.SourceAuthorityPolicy.AllowedSourceClasses)
	for _, sourceClass := range ingestion.SourceAuthorityPolicy.ForbiddenSourceClasses {
		if _, overlaps := allowedSourceClasses[sourceClass]; overlaps {
			return nil, nil, nil, nil, fmt.Errorf("OOD source-authority class %q is both allowed and forbidden", sourceClass)
		}
	}
	roles := make(map[string]struct{}, len(ood.Sections.ObjectModel.Roles.Roles))
	for _, role := range ood.Sections.ObjectModel.Roles.Roles {
		if role == "" {
			return nil, nil, nil, nil, fmt.Errorf("OOD API role registry contains an empty role")
		}
		if _, exists := roles[role]; exists {
			return nil, nil, nil, nil, fmt.Errorf("OOD API role registry duplicates %q", role)
		}
		roles[role] = struct{}{}
	}
	constraints := make(map[string]relationshipConstraint, len(ood.Sections.EdgeModel.Relationships.Constraints))
	for _, c := range ood.Sections.EdgeModel.Relationships.Constraints {
		if c.EdgeLabel == "" || c.SourceRole == "" || c.TargetRole == "" {
			return nil, nil, nil, nil, fmt.Errorf("OOD API relationship registry contains an incomplete row")
		}
		if _, exists := constraints[c.EdgeLabel]; exists {
			return nil, nil, nil, nil, fmt.Errorf("OOD API relationship registry duplicates %q", c.EdgeLabel)
		}
		if _, ok := roles[c.SourceRole]; !ok {
			return nil, nil, nil, nil, fmt.Errorf("OOD relationship %q names unknown source role %q", c.EdgeLabel, c.SourceRole)
		}
		if _, ok := roles[c.TargetRole]; !ok {
			return nil, nil, nil, nil, fmt.Errorf("OOD relationship %q names unknown target role %q", c.EdgeLabel, c.TargetRole)
		}
		constraints[c.EdgeLabel] = c
	}
	families := make(map[string]struct{}, len(ood.Sections.ObjectModel.Properties.Families))
	for _, family := range ood.Sections.ObjectModel.Properties.Families {
		if family == "" {
			return nil, nil, nil, nil, fmt.Errorf("OOD API property registry contains an empty family")
		}
		if _, exists := families[family]; exists {
			return nil, nil, nil, nil, fmt.Errorf("OOD API property registry duplicates %q", family)
		}
		families[family] = struct{}{}
	}
	eligibleSubjects := map[string]struct{}{}
	for _, subject := range ood.Sections.ObjectModel.Properties.EligibleSubjects {
		if subject == "" {
			return nil, nil, nil, nil, fmt.Errorf("OOD API property eligible-subject registry contains an empty member")
		}
		if _, duplicate := eligibleSubjects[subject]; duplicate {
			return nil, nil, nil, nil, fmt.Errorf("OOD API property eligible-subject registry duplicates %q", subject)
		}
		eligibleSubjects[subject] = struct{}{}
	}
	if len(roles) == 0 || len(constraints) == 0 || len(families) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("selected OOD spec does not expose the provider-documentation API contract")
	}
	if len(eligibleSubjects) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("selected OOD spec does not expose API property eligible subjects")
	}
	return roles, constraints, families, eligibleSubjects, nil
}

func normalizeExternalRepresentationKinds(ood oodContract) (map[string]struct{}, error) {
	registeredKinds := make(map[string]struct{}, len(ood.Sections.IdentityModel.ExternalRepresentation.Kinds))
	for _, kind := range ood.Sections.IdentityModel.ExternalRepresentation.Kinds {
		if kind == "" {
			return nil, fmt.Errorf("OOD external representation-kind registry contains an empty member")
		}
		if _, exists := registeredKinds[kind]; exists {
			return nil, fmt.Errorf("OOD external representation-kind registry duplicates %q", kind)
		}
		registeredKinds[kind] = struct{}{}
	}
	if len(registeredKinds) == 0 {
		return nil, fmt.Errorf("OOD external representation-kind registry is empty")
	}
	if _, ok := registeredKinds[supportedEvidenceRepresentationKind]; !ok {
		return nil, fmt.Errorf("OOD external representation-kind registry does not admit the verifier's format-neutral selected machine-export class %q", supportedEvidenceRepresentationKind)
	}
	byteProfiles := ood.Sections.IdentityModel.VersionCoordinateGrammar.ExternalEvidenceHashContract.CanonicalByteProfiles
	if _, ok := byteProfiles[componentByteDomainProfile]; !ok {
		return nil, fmt.Errorf("OOD external evidence hash contract does not register component/source content profile %q", componentByteDomainProfile)
	}
	if _, ok := byteProfiles[manifestCanonicalBytesProfile]; !ok {
		return nil, fmt.Errorf("OOD external evidence hash contract does not register component-manifest profile %q", manifestCanonicalBytesProfile)
	}
	// This executable validates exact selected machine-export bodies only. The
	// OOD registry's source-origin and component-manifest classes have distinct
	// authority and completeness semantics and must not be advertised as
	// supported until their own closed validators exist.
	return map[string]struct{}{supportedEvidenceRepresentationKind: {}}, nil
}

func parsePlan(planBytes []byte, proof graphPlanParseProof) (*parsedPlan, error) {
	if err := requireGraphPlanParseProof(proof, planBytes); err != nil {
		return nil, err
	}
	if err := requireValidUTF8("graph plan", planBytes); err != nil {
		return nil, err
	}
	plan := &parsedPlan{Locators: map[string]evidenceLocator{}, LocatorCanonicalRows: map[string][]byte{}, Symbols: map[string]apiSymbol{}, Relationships: map[string]apiRelationship{}, Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{}}
	scanner := bufio.NewScanner(bytes.NewReader(planBytes))
	scanner.Buffer(make([]byte, 64*1024), 32*1024*1024)
	lineNumber := 0
	allIDs := map[string]string{}
	parserSupportedRowKinds := map[string]struct{}{
		"artifact_manifest": {}, "candidate_evidence_locator": {}, "validation_summary": {},
		"candidate_api_symbol": {}, "candidate_api_relationship": {},
		"candidate_api_property_claim": {}, "candidate_graph_gap": {},
	}
	if err := requireExactSet("generic graph-plan parser row kinds versus sealed stage dispositions", parserSupportedRowKinds, stringMapKeysAsSet(proof.structural.setKindsByRowKind)); err != nil {
		return nil, err
	}
	for scanner.Scan() {
		lineNumber++
		rawLine := bytes.Clone(scanner.Bytes())
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 {
			continue
		}
		if err := rejectDuplicateJSONKeys(line); err != nil {
			return nil, fmt.Errorf("graph plan line %d: %w", lineNumber, err)
		}
		var envelope rowEnvelope
		if err := json.Unmarshal(line, &envelope); err != nil {
			return nil, fmt.Errorf("graph plan line %d: %w", lineNumber, err)
		}
		_, declared := graphPlanSetKinds(proof, envelope.RowKind)
		if !declared {
			return nil, fmt.Errorf("graph plan line %d row_kind %q is absent from the sealed stage profile", lineNumber, envelope.RowKind)
		}
		if _, supported := parserSupportedRowKinds[envelope.RowKind]; !supported {
			return nil, fmt.Errorf("graph plan line %d uses schema-proven row_kind %q with no generic semantic parser", lineNumber, envelope.RowKind)
		}
		switch envelope.RowKind {
		case "artifact_manifest":
			if plan.Manifest != nil {
				return nil, fmt.Errorf("graph plan has more than one artifact_manifest")
			}
			var row artifactManifest
			if err := strictUnmarshal(line, &row); err != nil {
				return nil, err
			}
			plan.Manifest = &row
		case "candidate_evidence_locator":
			var row evidenceLocator
			if err := strictUnmarshal(line, &row); err != nil {
				return nil, err
			}
			if err := addUniqueID(allIDs, row.ID, row.RowKind); err != nil {
				return nil, err
			}
			plan.Locators[row.ID] = row
			plan.LocatorCanonicalRows[row.ID] = rawLine
			plan.LocatorOrder = append(plan.LocatorOrder, row.ID)
		case "candidate_api_symbol":
			var row apiSymbol
			if err := strictUnmarshal(line, &row); err != nil {
				return nil, err
			}
			if err := addUniqueID(allIDs, row.ID, row.RowKind); err != nil {
				return nil, err
			}
			plan.Symbols[row.ID] = row
		case "candidate_api_relationship":
			var row apiRelationship
			if err := strictUnmarshal(line, &row); err != nil {
				return nil, err
			}
			if err := addUniqueID(allIDs, row.ID, row.RowKind); err != nil {
				return nil, err
			}
			plan.Relationships[row.ID] = row
		case "candidate_api_property_claim":
			var row apiPropertyClaim
			if err := strictUnmarshal(line, &row); err != nil {
				return nil, err
			}
			if err := addUniqueID(allIDs, row.ID, row.RowKind); err != nil {
				return nil, err
			}
			plan.Properties[row.ID] = row
		case "candidate_graph_gap":
			var row graphGap
			if err := strictUnmarshal(line, &row); err != nil {
				return nil, err
			}
			if err := addUniqueID(allIDs, row.ID, row.RowKind); err != nil {
				return nil, err
			}
			plan.Gaps[row.ID] = row
		case "validation_summary":
			if plan.Summary != nil {
				return nil, fmt.Errorf("graph plan has more than one validation_summary")
			}
			var row validationSummary
			if err := strictUnmarshal(line, &row); err != nil {
				return nil, err
			}
			plan.Summary = &row
		default:
			return nil, fmt.Errorf("graph plan line %d has unknown row_kind %q", lineNumber, envelope.RowKind)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan graph plan: %w", err)
	}
	if plan.Manifest == nil || plan.Summary == nil {
		return nil, fmt.Errorf("graph plan requires exactly one artifact_manifest and validation_summary")
	}
	return plan, nil
}

func validatePlan(plan *parsedPlan, roles map[string]struct{}, constraints map[string]relationshipConstraint, families, eligiblePropertySubjects map[string]struct{}, bodies map[string]exactEvidenceBody, derivedSets map[string]compactStageSet) error {
	if plan.Manifest.Provider == "" || plan.Manifest.Artifact == "" || plan.Manifest.ArtifactVersion == "" || plan.Manifest.NamedSystem != "Velenza BOC" || plan.Manifest.Status != "candidate_not_admissible_or_executable" {
		return fmt.Errorf("graph plan manifest is incomplete or uses the wrong named system")
	}
	manifestHashes := []string{
		plan.Manifest.ProviderNeutralProfileSHA256,
		plan.Manifest.SourceContractIndexSHA256,
		plan.Manifest.SampleShapeIndexSHA256,
		plan.Manifest.ProtocolContractIndexSHA256,
		plan.Manifest.FieldMappingCandidateSHA256,
		plan.Manifest.EvidenceSelectionRosterSHA256,
		plan.Manifest.EvidenceLocatorManifestSHA256,
	}
	for _, digest := range manifestHashes {
		if !isLowerSHA256(digest) {
			return fmt.Errorf("graph plan manifest carries a malformed artifact digest %q", digest)
		}
	}
	if err := validateEvidenceManifestBindingRoster(plan.Manifest.EvidenceManifestBindings); err != nil {
		return err
	}
	if len(plan.Locators) == 0 || len(plan.Symbols) == 0 {
		return fmt.Errorf("graph plan requires evidence locators and API symbols")
	}
	for _, locatorID := range sortedProviderStringMapKeys(plan.Locators) {
		locator := plan.Locators[locatorID]
		if err := validateLocator(locator, bodies); err != nil {
			return fmt.Errorf("locator %s: %w", locator.ID, err)
		}
	}

	materializedRoles := map[string]struct{}{}
	for _, symbolID := range sortedProviderStringMapKeys(plan.Symbols) {
		symbol := plan.Symbols[symbolID]
		if _, ok := roles[symbol.Role]; !ok {
			return fmt.Errorf("symbol %s uses unknown API role %q", symbol.ID, symbol.Role)
		}
		if symbol.SemanticKey == "" || symbol.DisplayName == "" || symbol.AuthorityStatus != symbolAuthorityStatusExact || symbol.SourceBytesPresent {
			return fmt.Errorf("symbol %s has an invalid identity, authority, or byte posture", symbol.ID)
		}
		if err := validateNonemptyCandidateObject("symbol derivation binding", symbol.ID, symbol.DerivationBinding); err != nil {
			return err
		}
		if symbol.ID != stableID("capi_sym", lengthPrefixedIdentityKey(symbol.Role, symbol.SemanticKey)) {
			return fmt.Errorf("symbol %s has a non-content-derived id", symbol.ID)
		}
		if err := validateLocatorRefs(symbol.ID, symbol.EvidenceLocatorIDs, plan.Locators); err != nil {
			return err
		}
		materializedRoles[symbol.Role] = struct{}{}
	}
	materializedLabels := map[string]struct{}{}
	for _, relationshipID := range sortedProviderStringMapKeys(plan.Relationships) {
		relationship := plan.Relationships[relationshipID]
		constraint, ok := constraints[relationship.Label]
		if !ok {
			return fmt.Errorf("relationship %s uses unknown label %q", relationship.ID, relationship.Label)
		}
		if relationship.AuthorityStatus != relationAuthorityStatusExact || relationship.SourceBytesPresent {
			return fmt.Errorf("relationship %s has an invalid authority posture", relationship.ID)
		}
		if err := validateNonemptyCandidateObject("relationship derivation binding", relationship.ID, relationship.DerivationBinding); err != nil {
			return err
		}
		if relationship.ID != stableID("capi_rel", lengthPrefixedIdentityKey(relationship.Label, relationship.SourceID, relationship.TargetID)) {
			return fmt.Errorf("relationship %s has a non-content-derived id", relationship.ID)
		}
		source, sourceOK := plan.Symbols[relationship.SourceID]
		target, targetOK := plan.Symbols[relationship.TargetID]
		if !sourceOK || !targetOK {
			return fmt.Errorf("relationship %s has an unresolved endpoint", relationship.ID)
		}
		if source.Role != constraint.SourceRole || target.Role != constraint.TargetRole {
			return fmt.Errorf("relationship %s label %q requires %s->%s, got %s->%s", relationship.ID, relationship.Label, constraint.SourceRole, constraint.TargetRole, source.Role, target.Role)
		}
		if err := validateLocatorRefs(relationship.ID, relationship.LocatorIDs, plan.Locators); err != nil {
			return err
		}
		materializedLabels[relationship.Label] = struct{}{}
	}

	materializedFamilies := map[string]struct{}{}
	propertyClaimKeys := map[string]string{}
	for _, propertyID := range sortedProviderStringMapKeys(plan.Properties) {
		property := plan.Properties[propertyID]
		if _, ok := families[property.Family]; !ok {
			return fmt.Errorf("property %s uses unknown family %q", property.ID, property.Family)
		}
		if _, eligible := eligiblePropertySubjects[property.SubjectKind]; !eligible {
			return fmt.Errorf("property %s uses subject_kind %q that the selected OOD contract does not admit", property.ID, property.SubjectKind)
		}
		subjectID := property.SubjectID
		switch property.SubjectKind {
		case "api_symbol_object":
			if _, ok := plan.Symbols[subjectID]; !ok {
				return fmt.Errorf("property %s names unknown symbol %s", property.ID, subjectID)
			}
		case "api_relationship_edge":
			if _, ok := plan.Relationships[subjectID]; !ok {
				return fmt.Errorf("property %s names unknown relationship %s", property.ID, subjectID)
			}
		default:
			return fmt.Errorf("property %s has unsupported schema-proven subject_kind %q", property.ID, property.SubjectKind)
		}
		if property.PropertyName == "" || property.AuthorityStatus != propertyAuthorityStatusExact || property.SourceBytesPresent {
			return fmt.Errorf("property %s has an incomplete candidate contract", property.ID)
		}
		if err := validateNonemptyCandidateObject("property derivation binding", property.ID, property.DerivationBinding); err != nil {
			return err
		}
		canonicalValue, err := canonicalizeCandidateJSON(property.CandidateValue)
		if err != nil {
			return fmt.Errorf("property %s candidate_value: %w", property.ID, err)
		}
		if err := rejectNonIntegerNumbers(property.CandidateValue); err != nil {
			return fmt.Errorf("property %s candidate_value: %w", property.ID, err)
		}
		claimKey := lengthPrefixedIdentityKey(property.Family, subjectID, property.PropertyName)
		if priorID, duplicate := propertyClaimKeys[claimKey]; duplicate {
			return fmt.Errorf("properties %s and %s duplicate the same family/subject/property_name claim key", priorID, property.ID)
		}
		propertyClaimKeys[claimKey] = property.ID
		expectedID := stableID("capi_prop", lengthPrefixedIdentityKey(property.Family, subjectID, property.PropertyName, string(canonicalValue)))
		if property.ID != expectedID {
			return fmt.Errorf("property %s has a non-content-derived id", property.ID)
		}
		if err := validateLocatorRefs(property.ID, property.LocatorIDs, plan.Locators); err != nil {
			return err
		}
		materializedFamilies[property.Family] = struct{}{}
	}

	for _, gapID := range sortedProviderStringMapKeys(plan.Gaps) {
		gap := plan.Gaps[gapID]
		if !canonicalSurfaceKindPattern.MatchString(gap.GapClass) ||
			!canonicalSurfaceKindPattern.MatchString(gap.BlockedSubjectKind) ||
			!canonicalEvidenceMetadataString(gap.BlockedSubjectID, 2048) ||
			!canonicalSurfaceKindPattern.MatchString(gap.BlockedClaimKind) ||
			!canonicalEvidenceMetadataString(gap.BlockedClaimID, 2048) ||
			gap.Disposition != "fail_closed" || gap.MaterializationEligible || gap.SourceBytesPresent ||
			!canonicalEvidenceMetadataString(gap.ApplicabilityProfileID, 512) ||
			!canonicalEvidenceMetadataString(gap.ApplicabilityProfileVersion, 128) ||
			!isLowerSHA256(gap.ApplicabilityProfileSHA256) ||
			!canonicalEvidenceMetadataString(gap.ApplicabilityRuleID, 512) {
			return fmt.Errorf("graph gap %s is incomplete", gap.ID)
		}
		if err := validateNonemptyCandidateObject("gap proof binding", gap.ID, gap.GapProofBinding); err != nil {
			return err
		}
		if err := validateNonemptyCandidateObject("gap derivation binding", gap.ID, gap.DerivationBinding); err != nil {
			return err
		}
		gapIdentityKey, err := candidateGraphGapIdentityKey(gap)
		if err != nil {
			return fmt.Errorf("graph gap %s identity: %w", gap.ID, err)
		}
		if gap.ID != stableID("capi_gap", gapIdentityKey) {
			return fmt.Errorf("graph gap %s has a non-content-derived id", gap.ID)
		}
		if err := validateOptionalLocatorRefs(gap.ID, gap.EvidenceLocatorIDs, plan.Locators); err != nil {
			return err
		}
	}
	referencedLocatorIDs := map[string]struct{}{}
	for _, symbolID := range sortedProviderStringMapKeys(plan.Symbols) {
		addLocatorIDsToSet(referencedLocatorIDs, plan.Symbols[symbolID].EvidenceLocatorIDs)
	}
	for _, relationshipID := range sortedProviderStringMapKeys(plan.Relationships) {
		addLocatorIDsToSet(referencedLocatorIDs, plan.Relationships[relationshipID].LocatorIDs)
	}
	for _, propertyID := range sortedProviderStringMapKeys(plan.Properties) {
		addLocatorIDsToSet(referencedLocatorIDs, plan.Properties[propertyID].LocatorIDs)
	}
	for _, gapID := range sortedProviderStringMapKeys(plan.Gaps) {
		addLocatorIDsToSet(referencedLocatorIDs, plan.Gaps[gapID].EvidenceLocatorIDs)
	}
	if err := requireExactSet("claim-referenced evidence locators", referencedLocatorIDs, stringMapKeysAsSet(plan.Locators)); err != nil {
		return err
	}

	return validateSummary(plan, materializedRoles, materializedLabels, materializedFamilies, derivedSets)
}

func validateSummary(plan *parsedPlan, materializedRoles, materializedLabels, materializedFamilies map[string]struct{}, derivedSets map[string]compactStageSet) error {
	s := plan.Summary
	if s.CandidateEvidenceLocatorCount != len(plan.Locators) || s.CandidateAPISymbolCount != len(plan.Symbols) || s.CandidateAPIRelationshipCount != len(plan.Relationships) || s.CandidateAPIPropertyClaimCount != len(plan.Properties) || s.CandidateGraphGapCount != len(plan.Gaps) {
		return fmt.Errorf("validation_summary row counts do not equal the candidate rows")
	}
	if s.APIElementRolesMaterialized != len(materializedRoles) || s.APIRelationshipLabelsMaterialized != len(materializedLabels) || s.APIPropertyFamiliesMaterialized != len(materializedFamilies) {
		return fmt.Errorf("validation_summary selected-vocabulary counts do not equal the materialized provider instance")
	}
	operationCount := 0
	for _, symbol := range plan.Symbols {
		if symbol.Role == "operation" {
			operationCount++
		}
	}
	operationKindCount := 0
	priorOperationKind := ""
	for index, entry := range s.CapturedOperationKindCounts {
		if !canonicalSurfaceKindPattern.MatchString(entry.OperationKind) || entry.Count <= 0 {
			return fmt.Errorf("validation_summary captured_operation_kind_counts[%d] has invalid member %q=%d", index, entry.OperationKind, entry.Count)
		}
		if entry.OperationKind <= priorOperationKind {
			return fmt.Errorf("validation_summary captured_operation_kind_counts is not strictly ordered and unique at %q", entry.OperationKind)
		}
		priorOperationKind = entry.OperationKind
		operationKindCount += entry.Count
	}
	if s.CandidateOperationCount != operationCount || operationKindCount != operationCount || s.OperationApplicabilityCount != operationCount {
		return fmt.Errorf("validation_summary operation counts do not equal materialized operation symbols")
	}
	if s.CandidateSubjectCount != len(plan.Symbols)+len(plan.Relationships) {
		return fmt.Errorf("validation_summary candidate_subject_count does not equal symbols plus relationships")
	}
	setSummaries := []struct {
		kind  string
		root  string
		count uint64
	}{
		{kind: "subject", root: s.SubjectSetRootSHA256, count: uint64(s.CandidateSubjectCount)},
		{kind: "fact", root: s.FactSetRootSHA256, count: uint64(len(plan.Relationships) + len(plan.Properties))},
		{kind: "gap", root: s.GapSetRootSHA256, count: uint64(s.CandidateGraphGapCount)},
	}
	for _, summary := range setSummaries {
		setKind := summary.kind
		if !isLowerSHA256(summary.root) {
			return fmt.Errorf("validation_summary %s_set_root_sha256 is not lowercase SHA-256", setKind)
		}
		derived, ok := derivedSets[setKind]
		if !ok || derived.RootSHA256 != summary.root || derived.Count != summary.count {
			return fmt.Errorf("validation_summary %s set commitment %+v differs from exact stage-derived %+v", setKind, summary, derived)
		}
	}
	expectedResult := resultComplete
	if len(plan.Gaps) > 0 {
		expectedResult = resultCompleteWithGap
	}
	if s.SourceBytesPresent || s.CredentialsPresent || s.OrganizationIDPresent || s.CallerSuppliedOrganizationIDAllowed || s.BinaryFloatAuthoritative || s.RawValueEmbeddingAllowed || s.AdmittedDerivationProfileProofEstablished || s.ReadyForAdmission {
		return fmt.Errorf("validation_summary must remain body-free, secret-free, tenant-unbound, exact-value-safe, and non-admissible")
	}
	if s.Result != expectedResult {
		return fmt.Errorf("validation_summary result %q is not the closed result %q for this gap posture", s.Result, expectedResult)
	}
	return nil
}

func validateLocator(locator evidenceLocator, bodies map[string]exactEvidenceBody) error {
	if locator.SourceBytesPresent || locator.LocatorSemantics != exactLocatorSemantics || len(locator.SourceRefs) != 1 || len(locator.SourceURLs) != 1 {
		return fmt.Errorf("incomplete or source-bearing locator")
	}
	if !isLowerSHA256(locator.EvidenceManifestSHA256) || !isLowerSHA256(locator.SourceContentSHA256) || !isLowerSHA256(locator.SelectedRangeSHA256) {
		return fmt.Errorf("digest is not lowercase SHA-256")
	}
	if locator.ByteStartOffset < 0 || locator.ByteEndOffsetExclusive <= locator.ByteStartOffset || locator.SelectedRangeByteCount != locator.ByteEndOffsetExclusive-locator.ByteStartOffset {
		return fmt.Errorf("invalid zero-based half-open range")
	}
	key := candidateEvidenceLocatorIdentityKey(locator)
	if locator.ID != stableID("evloc", key) {
		return fmt.Errorf("non-content-derived locator id")
	}
	evidence, ok := bodies[locator.SourceContentSHA256]
	if !ok {
		return fmt.Errorf("source digest has no exact evidence body")
	}
	coordinate := evidenceSourceCoordinate{Ref: locator.SourceRefs[0], URL: locator.SourceURLs[0]}
	manifestSHA256, ok := evidence.Coordinates[coordinate]
	if !ok {
		return fmt.Errorf("source coordinate ref=%q url=%q is not bound to the exact evidence-manifest body", coordinate.Ref, coordinate.URL)
	}
	if manifestSHA256 != locator.EvidenceManifestSHA256 {
		return fmt.Errorf("source coordinate ref=%q url=%q belongs to evidence manifest %s, not locator-bound manifest %s", coordinate.Ref, coordinate.URL, manifestSHA256, locator.EvidenceManifestSHA256)
	}
	body := evidence.Bytes
	if locator.ByteEndOffsetExclusive > int64(len(body)) {
		return fmt.Errorf("range exceeds exact evidence body")
	}
	selected := body[locator.ByteStartOffset:locator.ByteEndOffsetExclusive]
	if sha256Hex(selected) != locator.SelectedRangeSHA256 {
		return fmt.Errorf("selected bytes do not match selected_range_sha256")
	}
	return nil
}

func candidateEvidenceLocatorIdentityKey(locator evidenceLocator) string {
	return lengthPrefixedIdentityKey(
		locatorIdentityDomain,
		locator.EvidenceManifestSHA256,
		locator.SourceRefs[0],
		locator.SourceURLs[0],
		locator.SourceContentSHA256,
		fmt.Sprint(locator.ByteStartOffset),
		fmt.Sprint(locator.ByteEndOffsetExclusive),
		fmt.Sprint(locator.SelectedRangeByteCount),
		locator.SelectedRangeSHA256,
	)
}

func candidateGraphGapIdentityKey(gap graphGap) (string, error) {
	proof, err := canonicalizeCandidateJSON(gap.GapProofBinding)
	if err != nil {
		return "", fmt.Errorf("gap_proof_binding: %w", err)
	}
	derivation, err := canonicalizeCandidateJSON(gap.DerivationBinding)
	if err != nil {
		return "", fmt.Errorf("derivation_binding: %w", err)
	}
	locators := append([]string(nil), gap.EvidenceLocatorIDs...)
	sort.Strings(locators)
	return lengthPrefixedIdentityKey(
		gap.GapClass,
		gap.BlockedSubjectKind,
		gap.BlockedSubjectID,
		gap.BlockedClaimKind,
		gap.BlockedClaimID,
		gap.Disposition,
		gap.ApplicabilityProfileID,
		gap.ApplicabilityProfileVersion,
		gap.ApplicabilityProfileSHA256,
		gap.ApplicabilityRuleID,
		sha256Hex(proof),
		sha256Hex(derivation),
		lengthPrefixedIdentityKey(locators...),
	), nil
}

func validateNonemptyCandidateObject(kind, owner string, raw json.RawMessage) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("%s %s is absent", kind, owner)
	}
	var object map[string]interface{}
	if err := strictUnmarshal(raw, &object); err != nil {
		return fmt.Errorf("%s %s is not a closed JSON object: %w", kind, owner, err)
	}
	if len(object) == 0 {
		return fmt.Errorf("%s %s is empty", kind, owner)
	}
	return nil
}

func lengthPrefixedIdentityKey(fields ...string) string {
	var out strings.Builder
	for _, field := range fields {
		fmt.Fprintf(&out, "%d:", len([]byte(field)))
		out.WriteString(field)
	}
	return out.String()
}

func validateLocatorRefs(owner string, ids []string, locators map[string]evidenceLocator) error {
	if len(ids) == 0 {
		return fmt.Errorf("%s has no exact evidence locator", owner)
	}
	seen := map[string]struct{}{}
	for _, id := range ids {
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("%s duplicates evidence locator %s", owner, id)
		}
		seen[id] = struct{}{}
		if _, ok := locators[id]; !ok {
			return fmt.Errorf("%s references unknown evidence locator %s", owner, id)
		}
	}
	return nil
}

func validateOptionalLocatorRefs(owner string, ids []string, locators map[string]evidenceLocator) error {
	if len(ids) == 0 {
		return nil
	}
	return validateLocatorRefs(owner, ids, locators)
}

func addLocatorIDsToSet(target map[string]struct{}, ids []string) {
	for _, id := range ids {
		target[id] = struct{}{}
	}
}

func stringMapKeysAsSet[T any](values map[string]T) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for key := range values {
		result[key] = struct{}{}
	}
	return result
}

func validateEvidenceManifestBindingRoster(bindings []evidenceManifestBinding) error {
	if len(bindings) == 0 {
		return fmt.Errorf("graph plan manifest has no typed evidence_manifest_bindings roster")
	}
	seenDigests := map[string]struct{}{}
	for index, binding := range bindings {
		if !isLowerSHA256(binding.EvidenceManifestSHA256) {
			return fmt.Errorf("evidence_manifest_bindings[%d] has a malformed digest", index)
		}
		if _, duplicate := seenDigests[binding.EvidenceManifestSHA256]; duplicate {
			return fmt.Errorf("evidence_manifest_bindings duplicates manifest digest %s", binding.EvidenceManifestSHA256)
		}
		seenDigests[binding.EvidenceManifestSHA256] = struct{}{}
		if binding.EvidenceBodyKind != evidenceBodyKindSourceDocument {
			return fmt.Errorf("evidence_manifest_bindings[%d] has unsupported evidence_body_kind %q", index, binding.EvidenceBodyKind)
		}
		if !sort.StringsAreSorted(binding.ConsumerRoles) {
			return fmt.Errorf("evidence_manifest_bindings[%d].consumer_roles is not in canonical lexical order", index)
		}
		seenRoles := map[string]struct{}{}
		for roleIndex, role := range binding.ConsumerRoles {
			if _, allowed := providerPlanEvidenceConsumerRoles[role]; !allowed {
				return fmt.Errorf("evidence_manifest_bindings[%d].consumer_roles[%d] uses unknown factory consumer role %q", index, roleIndex, role)
			}
			if _, duplicate := seenRoles[role]; duplicate {
				return fmt.Errorf("evidence_manifest_bindings[%d] duplicates consumer role %q", index, role)
			}
			seenRoles[role] = struct{}{}
		}
	}
	return nil
}

func evidenceManifestDigestsByConsumer(bindings []evidenceManifestBinding) map[string]map[string]struct{} {
	byRole := map[string]map[string]struct{}{}
	for _, binding := range bindings {
		for _, role := range binding.ConsumerRoles {
			if byRole[role] == nil {
				byRole[role] = map[string]struct{}{}
			}
			byRole[role][binding.EvidenceManifestSHA256] = struct{}{}
		}
	}
	return byRole
}

func validateEvidenceClosure(plan *parsedPlan, loaded loadedEvidence) error {
	type bodyCoordinateKey struct {
		Digest string
		Ref    string
		URL    string
	}
	allowed := map[string]struct{}{}
	allCoordinates := map[bodyCoordinateKey]struct{}{}
	reachedCoordinates := map[bodyCoordinateKey]struct{}{}
	for _, binding := range plan.Manifest.EvidenceManifestBindings {
		allowed[binding.EvidenceManifestSHA256] = struct{}{}
		input, ok := loaded.Artifacts[binding.EvidenceManifestSHA256]
		if !ok {
			return fmt.Errorf("evidence_manifest_bindings digest %s is not bound to exact supplied evidence bytes", binding.EvidenceManifestSHA256)
		}
		if input.EvidenceBodyKind != binding.EvidenceBodyKind {
			return fmt.Errorf("evidence manifest %s has body kind %q, want typed binding kind %q", binding.EvidenceManifestSHA256, input.EvidenceBodyKind, binding.EvidenceBodyKind)
		}
	}
	if len(loaded.Artifacts) != len(allowed) {
		return fmt.Errorf("supplied evidence closure contains %d manifests, want exactly the %d typed plan-bound manifests", len(loaded.Artifacts), len(allowed))
	}
	for _, digest := range sortedProviderStringMapKeys(loaded.Bodies) {
		body := loaded.Bodies[digest]
		for _, coordinate := range sortedEvidenceSourceCoordinates(body.Coordinates) {
			manifestSHA := body.Coordinates[coordinate]
			if _, ok := allowed[manifestSHA]; !ok {
				return fmt.Errorf("evidence coordinate ref=%q url=%q is owned by unbound manifest %s", coordinate.Ref, coordinate.URL, manifestSHA)
			}
			allCoordinates[bodyCoordinateKey{Digest: digest, Ref: coordinate.Ref, URL: coordinate.URL}] = struct{}{}
		}
	}
	if len(allCoordinates) != loaded.BodyCoordinateRows {
		return fmt.Errorf("evidence body coordinate set has %d identities, want all %d manifest body rows", len(allCoordinates), loaded.BodyCoordinateRows)
	}
	for _, locatorID := range sortedProviderStringMapKeys(plan.Locators) {
		locator := plan.Locators[locatorID]
		if _, ok := allowed[locator.EvidenceManifestSHA256]; !ok {
			return fmt.Errorf("locator %s binds unselected evidence manifest %s", locator.ID, locator.EvidenceManifestSHA256)
		}
		body, ok := loaded.Bodies[locator.SourceContentSHA256]
		if !ok {
			return fmt.Errorf("locator %s resolves no exact evidence body", locator.ID)
		}
		coordinate := evidenceSourceCoordinate{Ref: locator.SourceRefs[0], URL: locator.SourceURLs[0]}
		manifestSHA, ok := body.Coordinates[coordinate]
		if !ok {
			return fmt.Errorf("locator %s resolves no exact evidence coordinate", locator.ID)
		}
		if manifestSHA != locator.EvidenceManifestSHA256 {
			return fmt.Errorf("locator %s evidence_manifest_sha256 %s does not equal the exact body-coordinate owner %s", locator.ID, locator.EvidenceManifestSHA256, manifestSHA)
		}
		if _, ok := allowed[manifestSHA]; !ok {
			return fmt.Errorf("locator %s draws authority from unbound evidence manifest %s", locator.ID, manifestSHA)
		}
		reachedCoordinates[bodyCoordinateKey{Digest: locator.SourceContentSHA256, Ref: coordinate.Ref, URL: coordinate.URL}] = struct{}{}
	}
	coordinateKeys := make([]bodyCoordinateKey, 0, len(allCoordinates))
	for key := range allCoordinates {
		coordinateKeys = append(coordinateKeys, key)
	}
	sort.Slice(coordinateKeys, func(i, j int) bool {
		if coordinateKeys[i].Digest != coordinateKeys[j].Digest {
			return coordinateKeys[i].Digest < coordinateKeys[j].Digest
		}
		if coordinateKeys[i].Ref != coordinateKeys[j].Ref {
			return coordinateKeys[i].Ref < coordinateKeys[j].Ref
		}
		return coordinateKeys[i].URL < coordinateKeys[j].URL
	})
	for _, key := range coordinateKeys {
		if _, reached := reachedCoordinates[key]; !reached {
			return fmt.Errorf("evidence coordinate digest=%s ref=%q url=%q is not reached by any exact graph-plan locator", key.Digest, key.Ref, key.URL)
		}
	}
	return nil
}

func loadEvidenceBodies(paths []string, representationKinds map[string]struct{}) (loadedEvidence, error) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	loaded, err := loadEvidenceBodiesWithAdmission(paths, representationKinds, accumulator)
	if err != nil {
		return loadedEvidence{}, err
	}
	proof, err := accumulator.seal()
	if err != nil {
		return loadedEvidence{}, err
	}
	if err := bindAndValidateProviderInputAdmission(&loaded, nil, nil, nil, nil, proof, accumulator.resources); err != nil {
		return loadedEvidence{}, err
	}
	return loaded, nil
}

func loadEvidenceBodiesWithAdmission(paths []string, representationKinds map[string]struct{}, accumulator *providerInputAdmissionAccumulator) (loadedEvidence, error) {
	if accumulator == nil {
		return loadedEvidence{}, fmt.Errorf("provider input admission accumulator is nil")
	}
	if err := accumulator.preflightPathCount(providerInputAdmissionResourceKindManifest, len(paths)); err != nil {
		return loadedEvidence{}, err
	}
	resourceStart := len(accumulator.resources)
	loaded := loadedEvidence{
		Bodies:                         map[string]exactEvidenceBody{},
		Artifacts:                      map[string]artifactInput{},
		MetadataByCoordinate:           map[evidenceSourceCoordinate]evidenceBodyMetadata{},
		MetadataByIdentity:             map[evidenceBodyIdentity]evidenceBodyMetadata{},
		ClassificationsBySourceSymbol:  map[string][]sourceClassificationOccurrence{},
		ClassificationSelectionProofs:  map[string]sourceClassificationSelectionProof{},
		CandidateSymbolsBySourceSymbol: map[string]string{},
	}
	coordinateOwner := map[evidenceSourceCoordinate]string{}
	for _, path := range paths {
		if path == "" {
			return loadedEvidence{}, fmt.Errorf("evidence manifest path is empty")
		}
		boundedManifest, err := readBoundedProviderInputFile(path, "evidence manifest", providerInputAdmissionResourceKindManifest, "", accumulator)
		if err != nil {
			return loadedEvidence{}, err
		}
		raw := boundedManifest.Bytes
		if err := requireValidUTF8(fmt.Sprintf("evidence manifest %q", path), raw); err != nil {
			return loadedEvidence{}, err
		}
		if err := validateStructuredDependencySecurity(artifactInput{Path: path, Raw: raw, Structured: true}); err != nil {
			return loadedEvidence{}, fmt.Errorf("evidence-manifest metadata security: %w", err)
		}
		structuredKey, chargeStructuredJSON, err := accumulator.beginStructuredJSONPhysicalInput(path, "evidence manifest", raw)
		if err != nil {
			return loadedEvidence{}, err
		}
		manifestHash := boundedManifest.SHA256
		if prior, exists := loaded.Artifacts[manifestHash]; exists {
			return loadedEvidence{}, fmt.Errorf("evidence manifests %q and %q have identical bytes", prior.Path, path)
		}
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		lineNo := 0
		var manifest map[string]interface{}
		var summary map[string]interface{}
		rowKindCounts := map[string]int{}
		artifactBodyCount := 0
		var artifactByteCount int64
		artifactStructure := providerJSONArtifactStructure{}
		evidenceRepresentationKind := ""
		seenStableCoordinates := map[string]struct{}{}
		for scanner.Scan() {
			lineNo++
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			structure, err := validateProviderJSONStructure(line)
			if err != nil {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d: %w", path, lineNo, err)
			}
			if chargeStructuredJSON {
				if err := accumulator.admitStructuredJSONRow(providerInputAdmissionResourceKindManifest, &artifactStructure, structure); err != nil {
					return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d: %w", path, lineNo, err)
				}
			}
			if err := rejectNonIntegerNumbersAfterStructuralValidation(line); err != nil {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d: %w", path, lineNo, err)
			}
			var env evidenceManifestEnvelope
			if err := json.Unmarshal(line, &env); err != nil {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d: %w", path, lineNo, err)
			}
			if env.RowKind == "artifact_manifest" {
				if manifest != nil || lineNo != 1 {
					return loadedEvidence{}, fmt.Errorf("evidence manifest %q has more than one artifact_manifest", path)
				}
				manifest, err = decodeJSONObject(line)
				if err != nil {
					return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d: %w", path, lineNo, err)
				}
				continue
			}
			rowKindCounts[env.RowKind]++
			if env.RowKind == "validation_summary" {
				if summary != nil || manifest == nil || artifactBodyCount == 0 {
					return loadedEvidence{}, fmt.Errorf("evidence manifest %q has more than one validation_summary", path)
				}
				summary, err = decodeJSONObject(line)
				if err != nil {
					return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d: %w", path, lineNo, err)
				}
				continue
			}
			if env.RowKind == "transport_realization_receipt" {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q carries an unsupported transport_realization_receipt whose closed semantics are outside the selected-document-corpus preflight", path)
			}
			if env.RowKind != "external_evidence_body" {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d has unknown row_kind %q", path, lineNo, env.RowKind)
			}
			if manifest == nil || summary != nil {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d places an evidence body outside the manifest-to-summary body roster", path, lineNo)
			}
			bodyObject, err := decodeJSONObject(line)
			if err != nil {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d: %w", path, lineNo, err)
			}
			if err := validateExternalEvidenceBodyShape(bodyObject); err != nil {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d: %w", path, lineNo, err)
			}
			var row externalEvidenceBody
			if err := strictUnmarshal(line, &row); err != nil {
				return loadedEvidence{}, err
			}
			if row.ComponentOrdinal != int64(artifactBodyCount) {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d has component_ordinal %d, want zero-based contiguous ordinal %d", path, lineNo, row.ComponentOrdinal, artifactBodyCount)
			}
			if !isLowerSHA256(row.ContentSHA256) || row.ContentBytes <= 0 || row.StagingFile == "" || !canonicalEvidenceSourceRef(row.SourceRef) || !canonicalEvidenceSourceURL(row.SourceURL) {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d is incomplete", path, lineNo)
			}
			if err := accumulator.checkReservation(providerInputAdmissionResourceKindBody, row.ContentBytes); err != nil {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d declared body: %w", path, lineNo, err)
			}
			if _, duplicate := seenStableCoordinates[row.ComponentStableCoordinate]; duplicate {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q duplicates component_stable_coordinate %q", path, row.ComponentStableCoordinate)
			}
			seenStableCoordinates[row.ComponentStableCoordinate] = struct{}{}
			coordinate := evidenceSourceCoordinate{Ref: row.SourceRef, URL: row.SourceURL}
			if priorPath, duplicate := coordinateOwner[coordinate]; duplicate {
				return loadedEvidence{}, fmt.Errorf("evidence manifests %q and %q duplicate source coordinate ref=%q url=%q", priorPath, path, coordinate.Ref, coordinate.URL)
			}
			coordinateOwner[coordinate] = path
			body, _, err := decodeBoundedRelativeEvidenceStagingFile(path, manifestHash, row.StagingFile, coordinate, row.ContentBytes, row.ContentSHA256, accumulator)
			if err != nil {
				return loadedEvidence{}, err
			}
			if err := validateExternalEvidenceBody(row, body, manifest); err != nil {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q line %d: %w", path, lineNo, err)
			}
			metadata := evidenceBodyMetadata{
				ManifestSHA256:             manifestHash,
				SourceRef:                  row.SourceRef,
				SourceURL:                  row.SourceURL,
				ContentSHA256:              row.ContentSHA256,
				ContentBytes:               row.ContentBytes,
				Representation:             row.Representation,
				RepresentationCoordinate:   row.RepresentationCoordinate,
				SourceRepresentationKind:   row.SourceRepresentationKind,
				ComponentByteDomainProfile: row.ComponentByteDomainProfile,
				SourceContentHashProfile:   row.SourceContentHashProfile,
				ConsumerRoles:              map[string]struct{}{},
			}
			identity := evidenceBodyIdentity{ManifestSHA256: manifestHash, SourceRef: row.SourceRef, ContentSHA256: row.ContentSHA256}
			if _, duplicate := loaded.MetadataByIdentity[identity]; duplicate {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q duplicates exact evidence identity manifest=%s source_ref=%q content_sha256=%s", path, manifestHash, row.SourceRef, row.ContentSHA256)
			}
			loaded.MetadataByCoordinate[coordinate] = metadata
			loaded.MetadataByIdentity[identity] = metadata
			if evidenceRepresentationKind == "" {
				evidenceRepresentationKind = row.SourceRepresentationKind
			} else if evidenceRepresentationKind != row.SourceRepresentationKind {
				return loadedEvidence{}, fmt.Errorf("evidence manifest %q mixes source_representation_kind values", path)
			}
			artifactBodyCount++
			loaded.BodyCoordinateRows++
			artifactByteCount += int64(len(body))
			prior, exists := loaded.Bodies[row.ContentSHA256]
			if exists && !bytes.Equal(prior.Bytes, body) {
				return loadedEvidence{}, fmt.Errorf("digest %s aliases unequal evidence bodies", row.ContentSHA256)
			}
			if !exists {
				prior = exactEvidenceBody{Bytes: body, Coordinates: map[evidenceSourceCoordinate]string{}}
			}
			prior.Coordinates[coordinate] = manifestHash
			loaded.Bodies[row.ContentSHA256] = prior
		}
		if err := scanner.Err(); err != nil {
			return loadedEvidence{}, err
		}
		if chargeStructuredJSON {
			accumulator.finishStructuredJSONPhysicalInput(structuredKey)
		}
		if manifest == nil {
			return loadedEvidence{}, fmt.Errorf("evidence manifest %q has no artifact_manifest", path)
		}
		rowKindCounts["artifact_manifest"] = 1
		input := artifactInput{Path: path, SHA256: manifestHash, Raw: raw, Manifest: manifest, ValidationSummary: summary, RowKindCounts: rowKindCounts, Structured: true, EvidenceBodyCount: artifactBodyCount, EvidenceByteCount: artifactByteCount, EvidenceBodyKind: evidenceBodyKindSourceDocument, EvidenceRepresentationKind: evidenceRepresentationKind, InputAdmissionResource: boundedManifest.Resource}
		if err := validateCandidateArtifactManifest(input, ""); err != nil {
			return loadedEvidence{}, err
		}
		if err := validateEvidenceArtifactManifest(input, representationKinds); err != nil {
			return loadedEvidence{}, err
		}
		if err := validateEvidenceValidationSummary(input); err != nil {
			return loadedEvidence{}, err
		}
		loaded.Artifacts[manifestHash] = input
	}
	if len(loaded.Bodies) == 0 {
		return loadedEvidence{}, fmt.Errorf("evidence manifests contain zero exact bodies")
	}
	loaded.InputAdmissionResources = append([]providerInputAdmissionResourceReceipt(nil), accumulator.resources[resourceStart:]...)
	return loaded, nil
}

func validateExternalEvidenceBodyShape(object map[string]interface{}) error {
	allowed := stringSliceSet(evidenceBodyBaseKeys)
	for _, key := range evidenceBodyBaseKeys {
		if _, present := object[key]; !present {
			return fmt.Errorf("external_evidence_body is missing required key %q", key)
		}
	}
	for _, key := range sortedProviderStringMapKeys(object) {
		if _, permitted := allowed[key]; !permitted {
			return fmt.Errorf("external_evidence_body has unknown key %q", key)
		}
	}
	return nil
}

func resolveRelativeEvidenceStagingPath(manifestPath, declared string) (string, error) {
	nativeDeclared := filepath.FromSlash(declared)
	if strings.TrimSpace(declared) == "" || !filepath.IsLocal(nativeDeclared) || filepath.IsAbs(nativeDeclared) || filepath.VolumeName(nativeDeclared) != "" || !validEvidenceStagingPathComponents(nativeDeclared) {
		return "", fmt.Errorf("evidence manifest %q has a non-relative staging_file %q", manifestPath, declared)
	}
	manifestAbs, err := filepath.Abs(manifestPath)
	if err != nil {
		return "", fmt.Errorf("resolve evidence manifest path %q: %w", manifestPath, err)
	}
	root := filepath.Dir(manifestAbs)
	target := filepath.Clean(filepath.Join(root, nativeDeclared))
	if err := requirePathWithinRoot(root, target); err != nil {
		return "", fmt.Errorf("evidence manifest %q staging_file %q: %w", manifestPath, declared, err)
	}
	if _, rootInfo, err := inspectPathWithoutLinks(root, "evidence manifest directory"); err != nil {
		return "", err
	} else if !rootInfo.IsDir() {
		return "", fmt.Errorf("evidence manifest directory %q is not a directory", root)
	}
	if _, _, err := inspectPathWithoutLinks(target, "evidence staging_file"); err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve evidence manifest directory %q: %w", root, err)
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", fmt.Errorf("resolve evidence staging_file %q: %w", target, err)
	}
	if err := requirePathWithinRoot(resolvedRoot, resolvedTarget); err != nil {
		return "", fmt.Errorf("evidence manifest %q staging_file %q follows a link outside its manifest directory: %w", manifestPath, declared, err)
	}
	_, info, err := inspectPathWithoutLinks(resolvedTarget, "evidence staging_file")
	if err != nil {
		return "", fmt.Errorf("inspect resolved evidence staging_file %q: %w", resolvedTarget, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("evidence manifest %q staging_file %q is not a regular file", manifestPath, declared)
	}
	return resolvedTarget, nil
}

func readRelativeEvidenceStagingFile(manifestPath, declared string) ([]byte, string, error) {
	return readBoundedRelativeEvidenceStagingCarrier(manifestPath, declared, newCanonicalProviderInputAdmissionAccumulator())
}

func validEvidenceStagingPathComponents(path string) bool {
	if filepath.Separator != '\\' {
		return true
	}
	if strings.Contains(path, ":") {
		return false
	}
	reserved := map[string]struct{}{"CON": {}, "PRN": {}, "AUX": {}, "NUL": {}}
	for index := 1; index <= 9; index++ {
		reserved[fmt.Sprintf("COM%d", index)] = struct{}{}
		reserved[fmt.Sprintf("LPT%d", index)] = struct{}{}
	}
	for _, component := range strings.FieldsFunc(path, func(char rune) bool { return char == '/' || char == '\\' }) {
		base := strings.ToUpper(strings.TrimRight(strings.SplitN(component, ".", 2)[0], " ."))
		if _, forbidden := reserved[base]; forbidden {
			return false
		}
	}
	return true
}

func requirePathWithinRoot(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes or names the manifest directory")
	}
	return nil
}

func validateExternalEvidenceBody(row externalEvidenceBody, body []byte, manifest map[string]interface{}) error {
	expectedStableCoordinate := "source_ref_url_pair_v1|" + lengthPrefixedIdentityKey(row.SourceRef, row.SourceURL)
	if row.ComponentStableCoordinate != expectedStableCoordinate {
		return fmt.Errorf("component_stable_coordinate %q does not equal the source_ref/source_url identity %q", row.ComponentStableCoordinate, expectedStableCoordinate)
	}
	if row.ComponentByteLength != int64(len(body)) || row.ComponentByteLength != row.ContentBytes || row.ComponentSHA256 != row.ContentSHA256 || row.ComponentSHA256 != sha256Hex(body) {
		return fmt.Errorf("component byte length/hash tuple does not equal the exact staged evidence body")
	}
	if row.ComponentByteDomainProfile != componentByteDomainProfile || row.SourceContentHashProfile != sourceContentHashProfile {
		return fmt.Errorf("component/source byte-domain profile is not the closed exact-byte contract")
	}
	representation, representationOK := manifestString(manifest, "representation")
	representationCoordinate, coordinateOK := manifestString(manifest, "representation_coordinate")
	sourceRepresentationKind, sourceRepresentationKindOK := manifestString(manifest, "source_representation_kind")
	if !representationOK || representation == "" || !coordinateOK || representationCoordinate == "" || !sourceRepresentationKindOK || row.Representation != representation || row.RepresentationCoordinate != representationCoordinate || row.SourceRepresentationKind != sourceRepresentationKind || row.BodyAuthority != evidenceBodyAuthorityExact {
		return fmt.Errorf("evidence body does not bind the manifest-declared source representation profile and coordinate")
	}
	if row.ObservedLineDelimiterProfile != exactLineDelimiterProfile(body) {
		return fmt.Errorf("observed_line_delimiter_profile %q does not match exact staged bytes", row.ObservedLineDelimiterProfile)
	}
	return nil
}

func exactLineDelimiterProfile(body []byte) string {
	var crlf, bareLF, bareCR int
	for index := 0; index < len(body); index++ {
		switch body[index] {
		case '\r':
			if index+1 < len(body) && body[index+1] == '\n' {
				crlf++
			} else {
				bareCR++
			}
		case '\n':
			if index == 0 || body[index-1] != '\r' {
				bareLF++
			}
		}
	}
	switch {
	case crlf > 0 && bareLF == 0 && bareCR == 0:
		return "CRLF"
	case bareLF > 0 && crlf == 0 && bareCR == 0:
		return "LF"
	case crlf == 0 && bareLF == 0 && bareCR == 0:
		return "none"
	default:
		return "mixed"
	}
}

func validateEvidenceArtifactManifest(input artifactInput, representationKinds map[string]struct{}) error {
	if !exactObjectKeys(input.Manifest, evidenceManifestBaseKeys) {
		return fmt.Errorf("evidence artifact_manifest in %q does not match the closed manifest key set: %s", input.Path, describeObjectKeyDelta(input.Manifest, evidenceManifestBaseKeys))
	}
	representation, representationOK := manifestString(input.Manifest, "representation")
	representationCoordinate, representationCoordinateOK := manifestString(input.Manifest, "representation_coordinate")
	sourceRepresentationKind, sourceRepresentationKindOK := manifestString(input.Manifest, "source_representation_kind")
	canonicalBytes, canonicalBytesOK := manifestString(input.Manifest, "canonical_bytes")
	_, registeredRepresentationKind := representationKinds[sourceRepresentationKind]
	if !representationOK || !canonicalEvidenceMetadataString(representation, 256) || !representationCoordinateOK || !canonicalEvidenceMetadataString(representationCoordinate, 2048) || !sourceRepresentationKindOK || sourceRepresentationKind != supportedEvidenceRepresentationKind || !registeredRepresentationKind || !canonicalBytesOK || canonicalBytes != manifestCanonicalBytesProfile {
		return fmt.Errorf("evidence artifact_manifest in %q does not carry the exact selected-machine-export contract", input.Path)
	}
	if input.EvidenceBodyKind != evidenceBodyKindSourceDocument {
		return fmt.Errorf("evidence artifact_manifest in %q is not the generic source_document body kind", input.Path)
	}
	return nil
}

func exactObjectKeys(object map[string]interface{}, expected []string) bool {
	if len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

func describeObjectKeyDelta(object map[string]interface{}, alternatives ...[]string) string {
	actual := make([]string, 0, len(object))
	for key := range object {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	expectedDescriptions := make([]string, 0, len(alternatives))
	for _, expected := range alternatives {
		copyExpected := append([]string(nil), expected...)
		sort.Strings(copyExpected)
		expectedDescriptions = append(expectedDescriptions, strings.Join(copyExpected, ","))
	}
	return fmt.Sprintf("actual=[%s] expected_one_of=[%s]", strings.Join(actual, ","), strings.Join(expectedDescriptions, "] ["))
}

func containsExactString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func hasEmptyOrDuplicateStrings(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			return true
		}
		if _, duplicate := seen[value]; duplicate {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func validateEvidenceValidationSummary(input artifactInput) error {
	summary := input.ValidationSummary
	if summary == nil {
		return fmt.Errorf("evidence validation_summary is missing from %q", input.Path)
	}
	if input.EvidenceBodyKind != evidenceBodyKindSourceDocument {
		return fmt.Errorf("evidence validation_summary in %q is not bound to the generic source_document body kind", input.Path)
	}
	if !exactObjectKeys(summary, evidenceSummaryKeys) {
		return fmt.Errorf("evidence validation_summary in %q does not match its closed key set: %s", input.Path, describeObjectKeyDelta(summary, evidenceSummaryKeys))
	}
	if rowKind, ok := manifestString(summary, "row_kind"); !ok || rowKind != "validation_summary" {
		return fmt.Errorf("evidence validation_summary in %q has an invalid row_kind", input.Path)
	}
	if input.RowKindCounts["external_evidence_body"] != input.EvidenceBodyCount || input.EvidenceBodyCount <= 0 {
		return fmt.Errorf("evidence validation_summary in %q cannot bind a positive exact body roster", input.Path)
	}
	totalBytes, ok := manifestInt64(summary, "total_exact_source_bytes")
	if !ok || totalBytes != input.EvidenceByteCount {
		return fmt.Errorf("evidence validation_summary in %q total_exact_source_bytes does not equal exact staged bytes", input.Path)
	}
	if value, ok := manifestBool(summary, "selected_representation_is_only_evidence_body"); !ok || !value {
		return fmt.Errorf("evidence validation_summary in %q must affirm selected_representation_is_only_evidence_body", input.Path)
	}
	if value, ok := manifestBool(summary, "rendered_dom_body_accepted"); !ok || value {
		return fmt.Errorf("evidence validation_summary in %q must reject rendered DOM as an evidence body", input.Path)
	}
	selected, selectedOK := manifestInteger(summary, "selected_source_count")
	captured, capturedOK := manifestInteger(summary, "captured_source_count")
	missing, missingOK := manifestStringSlice(summary, "missing_source_refs")
	unexpected, unexpectedOK := manifestStringSlice(summary, "unexpected_source_refs")
	result, resultOK := manifestString(summary, "result")
	if !selectedOK || !capturedOK || selected != input.EvidenceBodyCount || captured != selected || !missingOK || len(missing) != 0 || !unexpectedOK || len(unexpected) != 0 || !resultOK || result != "structural_candidate_selected_source_document_capture" {
		return fmt.Errorf("evidence validation_summary in %q does not prove the exact generic selected source-document roster", input.Path)
	}
	return nil
}

func loadDependencyArtifacts(paths []string) (map[string]artifactInput, error) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	artifacts, err := loadDependencyArtifactsWithAdmission(paths, accumulator)
	if err != nil {
		return nil, err
	}
	proof, err := accumulator.seal()
	if err != nil {
		return nil, err
	}
	for digest, artifact := range artifacts {
		artifact.InputAdmissionProofSHA256 = proof.ProofSHA256
		artifacts[digest] = artifact
	}
	if err := validateDependencyInputAdmissionBinding(artifacts, proof, accumulator.resources); err != nil {
		return nil, err
	}
	return artifacts, nil
}

func loadDependencyArtifactsWithAdmission(paths []string, accumulator *providerInputAdmissionAccumulator) (map[string]artifactInput, error) {
	if accumulator == nil {
		return nil, fmt.Errorf("provider input admission accumulator is nil")
	}
	if err := accumulator.preflightPathCount(providerInputAdmissionResourceKindArtifact, len(paths)); err != nil {
		return nil, err
	}
	artifacts := make(map[string]artifactInput, len(paths))
	for _, path := range paths {
		if path == "" {
			return nil, fmt.Errorf("dependency artifact path is empty")
		}
		artifact, err := readArtifactInputWithAdmission(path, accumulator)
		if err != nil {
			return nil, err
		}
		if artifact.Structured {
			if err := validateStructuredDependencySecurity(artifact); err != nil {
				return nil, err
			}
		}
		if prior, exists := artifacts[artifact.SHA256]; exists {
			return nil, fmt.Errorf("dependency artifacts %q and %q have identical bytes", prior.Path, artifact.Path)
		}
		artifacts[artifact.SHA256] = artifact
	}
	return artifacts, nil
}

func readArtifactInput(path string) (artifactInput, error) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	if err := accumulator.preflightPathCount(providerInputAdmissionResourceKindArtifact, 1); err != nil {
		return artifactInput{}, err
	}
	input, err := readArtifactInputWithAdmission(path, accumulator)
	if err != nil {
		return artifactInput{}, err
	}
	proof, err := accumulator.seal()
	if err != nil {
		return artifactInput{}, err
	}
	input.InputAdmissionProofSHA256 = proof.ProofSHA256
	if err := validateDependencyInputAdmissionBinding(map[string]artifactInput{input.SHA256: input}, proof, accumulator.resources); err != nil {
		return artifactInput{}, err
	}
	return input, nil
}

func readArtifactInputWithAdmission(path string, accumulator *providerInputAdmissionAccumulator) (artifactInput, error) {
	boundedArtifact, err := readBoundedProviderInputFile(path, "dependency artifact", providerInputAdmissionResourceKindArtifact, "", accumulator)
	if err != nil {
		return artifactInput{}, err
	}
	raw := boundedArtifact.Bytes
	if err := requireValidUTF8(fmt.Sprintf("dependency raw input %q", path), raw); err != nil {
		return artifactInput{}, err
	}
	input := artifactInput{Path: path, SHA256: boundedArtifact.SHA256, Raw: raw, RowKindCounts: map[string]int{}, RowsByKind: map[string][]map[string]interface{}{}, ParsedRows: []artifactParsedRow{}, InputAdmissionResource: boundedArtifact.Resource}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return artifactInput{}, fmt.Errorf("dependency raw input %q is empty", path)
	}
	// Canonical authority inputs such as Grand Vision Markdown and a complete
	// structured spec are exact raw dependencies, not JSONL candidate
	// artifacts. A single JSON object without row_kind is therefore retained as
	// raw authority bytes; direct candidate roles still require a manifest.
	if json.Valid(trimmed) {
		if err := rejectDuplicateJSONKeys(trimmed); err != nil {
			return artifactInput{}, fmt.Errorf("dependency raw input %q: %w", path, err)
		}
		object, err := decodeJSONObject(trimmed)
		if err == nil {
			_, hasRowKind := object["row_kind"]
			_, hasKind := object["kind"]
			if !hasRowKind && !hasKind {
				if err := accumulator.admitStructuredJSONDocument(path, "dependency JSON document", providerInputAdmissionResourceKindArtifact, raw); err != nil {
					return artifactInput{}, err
				}
				return input, nil
			}
		}
	} else if trimmed[0] != '{' {
		return input, nil
	}
	structuredKey, chargeStructuredJSON, err := accumulator.beginStructuredJSONPhysicalInput(path, "dependency structured artifact", raw)
	if err != nil {
		return artifactInput{}, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 32*1024*1024)
	lineNo := 0
	rawOffset := 0
	var manifest map[string]interface{}
	var summary map[string]interface{}
	discriminator := ""
	artifactStructure := providerJSONArtifactStructure{}
	for scanner.Scan() {
		lineNo++
		// ScanLines omits the newline and, for CRLF, the trailing carriage
		// return. Recover the exact slice in the already-retained artifact bytes
		// so semantic consumers can reuse it without cloning or reparsing a
		// second object graph.
		scannedLine := scanner.Bytes()
		physicalEnd := rawOffset + len(scannedLine)
		if physicalEnd < len(raw) && raw[physicalEnd] == '\r' && physicalEnd+1 < len(raw) && raw[physicalEnd+1] == '\n' {
			physicalEnd++
		}
		if physicalEnd > len(raw) {
			return artifactInput{}, fmt.Errorf("dependency artifact %q line %d has an invalid retained byte range", path, lineNo)
		}
		physicalLine := raw[rawOffset:physicalEnd]
		line := bytes.TrimSpace(physicalLine)
		nextOffset := physicalEnd
		if nextOffset < len(raw) && raw[nextOffset] == '\n' {
			nextOffset++
		}
		lineStart := rawOffset
		lineEnd := rawOffset
		if len(line) != 0 {
			relativeStart := bytes.Index(physicalLine, line)
			if relativeStart < 0 {
				return artifactInput{}, fmt.Errorf("dependency artifact %q line %d cannot bind its retained bytes", path, lineNo)
			}
			lineStart = rawOffset + relativeStart
			lineEnd = lineStart + len(line)
		}
		rawOffset = nextOffset
		if len(line) == 0 {
			continue
		}
		structure, err := validateProviderJSONStructure(line)
		if err != nil {
			return artifactInput{}, fmt.Errorf("dependency artifact %q line %d: %w", path, lineNo, err)
		}
		if chargeStructuredJSON {
			if err := accumulator.admitStructuredJSONRow(providerInputAdmissionResourceKindArtifact, &artifactStructure, structure); err != nil {
				return artifactInput{}, fmt.Errorf("dependency artifact %q line %d: %w", path, lineNo, err)
			}
		}
		if err := rejectNonIntegerNumbersAfterStructuralValidation(line); err != nil {
			return artifactInput{}, fmt.Errorf("dependency artifact %q line %d: %w", path, lineNo, err)
		}
		var envelope rowEnvelope
		if err := json.Unmarshal(line, &envelope); err != nil {
			return artifactInput{}, fmt.Errorf("dependency artifact %q line %d: %w", path, lineNo, err)
		}
		if (envelope.RowKind == "") == (envelope.Kind == "") {
			return artifactInput{}, fmt.Errorf("dependency artifact %q line %d must carry exactly one row_kind or kind discriminator", path, lineNo)
		}
		rowDiscriminator := "row_kind"
		rowKind := envelope.RowKind
		if rowKind == "" {
			rowDiscriminator = "kind"
			rowKind = envelope.Kind
		}
		if discriminator == "" {
			discriminator = rowDiscriminator
		} else if discriminator != rowDiscriminator {
			return artifactInput{}, fmt.Errorf("dependency artifact %q mixes row_kind and kind discriminator domains", path)
		}
		input.RowKindCounts[rowKind]++
		rowObject, err := decodeJSONObject(line)
		if err != nil {
			return artifactInput{}, fmt.Errorf("dependency artifact %q line %d: %w", path, lineNo, err)
		}
		input.RowsByKind[rowKind] = append(input.RowsByKind[rowKind], rowObject)
		canonicalSHA256 := ""
		if canonicalRow, canonicalErr := canonicalizeCandidateJSON(line); canonicalErr == nil && bytes.Equal(line, canonicalRow) {
			canonicalSHA256 = sha256Hex(canonicalRow)
		}
		input.ParsedRows = append(input.ParsedRows, artifactParsedRow{Line: lineNo, Discriminator: rowDiscriminator, Kind: rowKind, Data: rowObject, CanonicalSHA256: canonicalSHA256, RawStart: lineStart, RawEnd: lineEnd})
		if rowKind == "validation_summary" {
			if summary != nil {
				return artifactInput{}, fmt.Errorf("dependency artifact %q has more than one validation_summary", path)
			}
			summary = rowObject
			continue
		}
		manifestKind := "artifact_manifest"
		if discriminator == "kind" {
			manifestKind = "mapping_manifest"
		}
		if rowKind != manifestKind {
			continue
		}
		if manifest != nil {
			return artifactInput{}, fmt.Errorf("dependency artifact %q has more than one artifact_manifest", path)
		}
		manifest = rowObject
	}
	if err := scanner.Err(); err != nil {
		return artifactInput{}, fmt.Errorf("scan dependency artifact %q: %w", path, err)
	}
	if chargeStructuredJSON {
		accumulator.finishStructuredJSONPhysicalInput(structuredKey)
	}
	if manifest == nil {
		return artifactInput{}, fmt.Errorf("dependency artifact %q has no artifact_manifest", path)
	}
	input.Manifest = manifest
	input.ValidationSummary = summary
	input.Structured = true
	input.Discriminator = discriminator
	return input, nil
}

func decodeJSONObject(raw []byte) (map[string]interface{}, error) {
	var object map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, fmt.Errorf("JSON value is not an object")
	}
	return object, nil
}

func canonicalizeCandidateJSON(raw []byte) ([]byte, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, err
	}
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := consumeJSONValue(decoder); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("candidate JSON has a trailing value")
		}
		return nil, fmt.Errorf("candidate JSON trailing input: %w", err)
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func sortedArtifactHashes(values map[string]artifactInput) []string {
	hashes := make([]string, 0, len(values))
	for hash := range values {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)
	return hashes
}

func bindSelectedProfileAuthorities(profile artifactInput, ood oodContract, oodSHA, grandVisionSHA string, sourceRecord structuredAuthorityIdentity, sourceRecordSHA string) error {
	expectedPins := []struct {
		path string
		sha  string
	}{
		{path: "canonical_ood_graph_spec.raw_sha256", sha: oodSHA},
		{path: "grand_vision.raw_sha256", sha: grandVisionSHA},
		{path: "source_record_contract.raw_sha256", sha: sourceRecordSHA},
	}
	actualPins := map[string]string{}
	collectRawSHA256Pins(profile.Manifest, nil, actualPins)
	if len(actualPins) != len(expectedPins) {
		return fmt.Errorf("provider-neutral profile %q carries %d raw authority pins, want the exact three selected authority pins", profile.Path, len(actualPins))
	}
	for _, expected := range expectedPins {
		actual, ok := actualPins[expected.path]
		if !ok || actual != expected.sha {
			return fmt.Errorf("provider-neutral profile authority %s %q does not equal independently selected bytes %q", expected.path, actual, expected.sha)
		}
	}
	oodDocID, oodDocIDOK := manifestString(profile.Manifest, "canonical_ood_graph_spec", "doc_id")
	oodVersion, oodVersionOK := manifestString(profile.Manifest, "canonical_ood_graph_spec", "version")
	sourceDocID, sourceDocIDOK := manifestString(profile.Manifest, "source_record_contract", "doc_id")
	sourceVersion, sourceVersionOK := manifestString(profile.Manifest, "source_record_contract", "version")
	if !oodDocIDOK || !oodVersionOK || oodDocID != ood.DocID || oodVersion != ood.Version.String() {
		return fmt.Errorf("provider-neutral profile OOD identity does not equal the independently selected OOD authority")
	}
	if !sourceDocIDOK || !sourceVersionOK || sourceDocID != sourceRecord.DocID || sourceVersion != sourceRecord.Version.String() {
		return fmt.Errorf("provider-neutral profile Source Record identity does not equal the independently selected Source Record authority")
	}
	return nil
}

type evidenceSelectionIdentity struct {
	ManifestSHA256 string
	SourceRef      string
	ContentSHA256  string
}

type classificationArtifactBinding struct {
	ArtifactID      string
	ArtifactVersion string
	ArtifactSHA256  string
}

type sourceClassificationOccurrence struct {
	Binding      classificationArtifactBinding
	SourceSymbol string
	SurfaceKind  string
	Locator      evidenceLocator
}

func validateEvidenceSelectionRoster(roster artifactInput, provider string, loaded loadedEvidence, dependencies map[string]artifactInput, usedDependencyHashes map[string]struct{}, plan *parsedPlan) error {
	selectedClassifications := map[string][]sourceClassificationOccurrence{}
	if !roster.Structured || roster.Manifest == nil {
		return fmt.Errorf("evidence_selection_roster_sha256 must resolve to a structured selection artifact")
	}
	manifestKeys := []string{"artifact", "artifact_version", "classification_artifact_bindings", "provider", "row_kind", "selected_source_count", "status"}
	if !exactObjectKeys(roster.Manifest, manifestKeys) {
		return fmt.Errorf("evidence selection roster %q manifest does not match the closed key set: %s", roster.Path, describeObjectKeyDelta(roster.Manifest, manifestKeys))
	}
	artifact, artifactOK := manifestString(roster.Manifest, "artifact")
	version, versionOK := manifestString(roster.Manifest, "artifact_version")
	status, statusOK := manifestString(roster.Manifest, "status")
	rosterProvider, providerOK := manifestString(roster.Manifest, "provider")
	declaredCount, countOK := manifestInteger(roster.Manifest, "selected_source_count")
	if !artifactOK || !canonicalSurfaceKindPattern.MatchString(artifact) || !versionOK || version != "4" || !statusOK || status != "candidate_source_selection_input" || !providerOK || rosterProvider != provider || !countOK || declaredCount <= 0 {
		return fmt.Errorf("evidence selection roster %q does not carry the closed generic source-selection posture", roster.Path)
	}
	if len(roster.RowKindCounts) != 3 || roster.RowKindCounts["artifact_manifest"] != 1 || roster.RowKindCounts["selected_source_document"] != declaredCount || roster.RowKindCounts["validation_summary"] != 1 || roster.ValidationSummary == nil {
		return fmt.Errorf("evidence selection roster %q does not contain exactly one manifest, its declared source-document rows, and one summary", roster.Path)
	}

	classificationBindings, err := validateClassificationArtifactBindings(roster, provider, dependencies, usedDependencyHashes)
	if err != nil {
		return err
	}
	manifestDigestByArtifact := map[string]string{}
	for _, digest := range sortedProviderStringMapKeys(loaded.Artifacts) {
		input := loaded.Artifacts[digest]
		artifactID, artifactIDOK := manifestString(input.Manifest, "artifact")
		artifactVersion, artifactVersionOK := manifestString(input.Manifest, "artifact_version")
		if !artifactIDOK || !artifactVersionOK {
			return fmt.Errorf("evidence manifest %q has no stable artifact identity", input.Path)
		}
		key := lengthPrefixedIdentityKey(artifactID, artifactVersion)
		if prior, duplicate := manifestDigestByArtifact[key]; duplicate {
			return fmt.Errorf("evidence manifests %s and %s duplicate artifact identity %s@%s", prior, digest, artifactID, artifactVersion)
		}
		manifestDigestByArtifact[key] = digest
	}

	rosterSet := make(map[evidenceSelectionIdentity]struct{}, declaredCount)
	manifestRoles := map[string]map[string]struct{}{}
	consumerRoleCounts := map[string]int{}
	usedManifestDigests := map[string]struct{}{}
	usedClassificationBindings := map[classificationArtifactBinding]struct{}{}
	usedClassificationRows := map[string]struct{}{}
	usedClassificationOccurrences := map[string]string{}
	classifiedSourceDocumentCount := 0
	classificationOccurrenceCount := 0
	for index, row := range roster.RowsByKind["selected_source_document"] {
		expectedKeys := []string{"classification_occurrences", "consumer_roles", "current_reference_url", "evidence_manifest_artifact", "evidence_manifest_artifact_version", "representation", "representation_coordinate", "row_kind", "source_ref", "source_representation_kind"}
		if !exactObjectKeys(row, expectedKeys) {
			return fmt.Errorf("evidence selection roster %q selected_source_document row %d does not match the closed key set: %s", roster.Path, index, describeObjectKeyDelta(row, expectedKeys))
		}
		manifestArtifact, manifestArtifactOK := manifestString(row, "evidence_manifest_artifact")
		manifestVersion, manifestVersionOK := manifestString(row, "evidence_manifest_artifact_version")
		sourceRef, sourceRefOK := manifestString(row, "source_ref")
		currentURL, currentURLOK := manifestString(row, "current_reference_url")
		representation, representationOK := manifestString(row, "representation")
		representationCoordinate, representationCoordinateOK := manifestString(row, "representation_coordinate")
		representationKind, representationKindOK := manifestString(row, "source_representation_kind")
		consumerRoles, consumerRolesOK := manifestStringSlice(row, "consumer_roles")
		rawClassificationOccurrences, classificationOccurrencesOK := row["classification_occurrences"].([]interface{})
		if !manifestArtifactOK || !canonicalSurfaceKindPattern.MatchString(manifestArtifact) || !manifestVersionOK || !canonicalEvidenceMetadataString(manifestVersion, 64) || !sourceRefOK || !canonicalEvidenceSourceRef(sourceRef) || !currentURLOK || !canonicalEvidenceSourceURL(currentURL) || !representationOK || !canonicalEvidenceMetadataString(representation, 256) || !representationCoordinateOK || !canonicalEvidenceMetadataString(representationCoordinate, 2048) || !representationKindOK || representationKind != supportedEvidenceRepresentationKind || !consumerRolesOK || hasEmptyOrDuplicateStrings(consumerRoles) || !sort.StringsAreSorted(consumerRoles) || !classificationOccurrencesOK {
			return fmt.Errorf("evidence selection roster %q selected_source_document row %d has an invalid generic source coordinate or consumer-role roster", roster.Path, index)
		}
		for _, role := range consumerRoles {
			if _, allowed := providerPlanEvidenceConsumerRoles[role]; !allowed {
				return fmt.Errorf("evidence selection roster %q selected_source_document row %d has unknown factory consumer role %q", roster.Path, index, role)
			}
		}
		manifestDigest, ok := manifestDigestByArtifact[lengthPrefixedIdentityKey(manifestArtifact, manifestVersion)]
		if !ok {
			return fmt.Errorf("evidence selection roster %q selected_source_document row %d names unsupplied evidence artifact %s@%s", roster.Path, index, manifestArtifact, manifestVersion)
		}
		coordinate := evidenceSourceCoordinate{Ref: sourceRef, URL: currentURL}
		metadata, ok := loaded.MetadataByCoordinate[coordinate]
		if !ok || metadata.ManifestSHA256 != manifestDigest {
			return fmt.Errorf("evidence selection roster %q selected_source_document row %d has no exact matching manifest-bound evidence body", roster.Path, index)
		}
		if metadata.Representation != representation || metadata.RepresentationCoordinate != representationCoordinate || metadata.SourceRepresentationKind != representationKind {
			return fmt.Errorf("evidence selection roster %q selected_source_document row %d does not exactly equal its evidence representation metadata", roster.Path, index)
		}
		identity := evidenceSelectionIdentity{ManifestSHA256: manifestDigest, SourceRef: sourceRef, ContentSHA256: metadata.ContentSHA256}
		if _, duplicate := rosterSet[identity]; duplicate {
			return fmt.Errorf("evidence selection roster %q duplicates exact selected source identity %+v", roster.Path, identity)
		}
		rosterSet[identity] = struct{}{}
		usedManifestDigests[manifestDigest] = struct{}{}
		if manifestRoles[manifestDigest] == nil {
			manifestRoles[manifestDigest] = map[string]struct{}{}
		}
		metadata.ConsumerRoles = map[string]struct{}{}
		for _, role := range consumerRoles {
			manifestRoles[manifestDigest][role] = struct{}{}
			metadata.ConsumerRoles[role] = struct{}{}
			consumerRoleCounts[role]++
		}
		if len(rawClassificationOccurrences) > 0 {
			classifiedSourceDocumentCount++
		}
		priorOccurrenceOrderKey := ""
		for occurrenceIndex, rawOccurrence := range rawClassificationOccurrences {
			occurrence, err := bindSelectedSourceClassification(roster, index, occurrenceIndex, rawOccurrence, metadata, classificationBindings, loaded.Bodies, usedClassificationBindings, usedClassificationRows, usedClassificationOccurrences)
			if err != nil {
				return err
			}
			occurrenceOrderKey := strings.Join([]string{
				occurrence.SourceSymbol,
				occurrence.SurfaceKind,
				occurrence.Locator.EvidenceManifestSHA256,
				occurrence.Locator.SourceRefs[0],
				occurrence.Locator.SourceURLs[0],
				occurrence.Locator.SourceContentSHA256,
				fmt.Sprintf("%020d", occurrence.Locator.ByteStartOffset),
				fmt.Sprintf("%020d", occurrence.Locator.ByteEndOffsetExclusive),
				occurrence.Locator.SelectedRangeSHA256,
				occurrence.Binding.ArtifactSHA256,
			}, "\x00")
			if priorOccurrenceOrderKey != "" && occurrenceOrderKey <= priorOccurrenceOrderKey {
				return fmt.Errorf("evidence selection roster %q selected_source_document row %d classification_occurrences are not in canonical semantic-and-locator order", roster.Path, index)
			}
			priorOccurrenceOrderKey = occurrenceOrderKey
			selectedClassifications[occurrence.SourceSymbol] = append(selectedClassifications[occurrence.SourceSymbol], occurrence)
			classificationOccurrenceCount++
		}
		loaded.MetadataByCoordinate[coordinate] = metadata
		loaded.MetadataByIdentity[evidenceBodyIdentity{ManifestSHA256: manifestDigest, SourceRef: sourceRef, ContentSHA256: metadata.ContentSHA256}] = metadata
	}
	if len(rosterSet) != len(loaded.MetadataByIdentity) {
		return fmt.Errorf("evidence selection roster has %d selected source identities but exact evidence has %d", len(rosterSet), len(loaded.MetadataByIdentity))
	}
	for _, identity := range sortedEvidenceBodyIdentityKeys(loaded.MetadataByIdentity) {
		selectionIdentity := evidenceSelectionIdentity{ManifestSHA256: identity.ManifestSHA256, SourceRef: identity.SourceRef, ContentSHA256: identity.ContentSHA256}
		if _, selected := rosterSet[selectionIdentity]; !selected {
			return fmt.Errorf("exact evidence identity %+v is absent from the selected-source roster", selectionIdentity)
		}
	}
	if len(usedClassificationBindings) != len(classificationBindings) {
		return fmt.Errorf("evidence selection roster declares %d classification artifacts but selected rows reach %d", len(classificationBindings), len(usedClassificationBindings))
	}
	declaredClassificationRows := map[string]struct{}{}
	for binding, input := range classificationBindings {
		for _, row := range input.RowsByKind["source_symbol"] {
			symbol, _ := manifestString(row, "source_symbol")
			declaredClassificationRows[lengthPrefixedIdentityKey(binding.ArtifactSHA256, "source_symbol", symbol)] = struct{}{}
		}
	}
	if err := requireExactSet("selected classification rows", usedClassificationRows, declaredClassificationRows); err != nil {
		return err
	}
	planRoles := map[string]map[string]struct{}{}
	for _, binding := range plan.Manifest.EvidenceManifestBindings {
		roles := map[string]struct{}{}
		for _, role := range binding.ConsumerRoles {
			roles[role] = struct{}{}
		}
		planRoles[binding.EvidenceManifestSHA256] = roles
	}
	if err := requireExactSet("selection-roster evidence manifest closure", usedManifestDigests, stringMapKeysAsSet(planRoles)); err != nil {
		return err
	}
	for _, digest := range sortedProviderStringMapKeys(manifestRoles) {
		roles := manifestRoles[digest]
		if err := requireExactSet(fmt.Sprintf("evidence manifest %s consumer_roles", digest), roles, planRoles[digest]); err != nil {
			return err
		}
	}
	graphConsumedManifests := map[string]struct{}{}
	for _, locator := range plan.Locators {
		graphConsumedManifests[locator.EvidenceManifestSHA256] = struct{}{}
	}
	declaredGraphManifests := map[string]struct{}{}
	for digest, roles := range manifestRoles {
		if _, declared := roles["api_graph_projection"]; declared {
			declaredGraphManifests[digest] = struct{}{}
		}
	}
	if err := requireExactSet("api_graph_projection evidence manifests", declaredGraphManifests, graphConsumedManifests); err != nil {
		return err
	}

	summaryKeys := []string{"captured_consumer_role_counts", "classification_occurrence_count", "classified_source_document_count", "evidence_manifest_artifact_count", "result", "row_kind", "selected_source_count"}
	summary := roster.ValidationSummary
	selectedCount, selectedCountOK := manifestInteger(summary, "selected_source_count")
	manifestCount, manifestCountOK := manifestInteger(summary, "evidence_manifest_artifact_count")
	classifiedDocumentCount, classifiedDocumentCountOK := manifestInteger(summary, "classified_source_document_count")
	classificationCount, classificationCountOK := manifestInteger(summary, "classification_occurrence_count")
	declaredRoleCounts, roleCountsOK := manifestNonnegativeIntegerMap(summary, "captured_consumer_role_counts")
	result, resultOK := manifestString(summary, "result")
	if !exactObjectKeys(summary, summaryKeys) || selectedCount != len(rosterSet) || !selectedCountOK || manifestCount != len(usedManifestDigests) || !manifestCountOK || classifiedDocumentCount != classifiedSourceDocumentCount || !classifiedDocumentCountOK || classificationCount != classificationOccurrenceCount || !classificationCountOK || !roleCountsOK || !equalIntegerMaps(declaredRoleCounts, consumerRoleCounts) || !resultOK || result != "structural_candidate_source_selection_roster" {
		return fmt.Errorf("evidence selection roster %q validation_summary does not equal the recomputed generic selected-source closure", roster.Path)
	}
	if loaded.ClassificationsBySourceSymbol == nil || loaded.ClassificationSelectionProofs == nil {
		return fmt.Errorf("evidence selection roster validation requires initialized classification proof stores")
	}
	for sourceSymbol := range loaded.ClassificationsBySourceSymbol {
		delete(loaded.ClassificationsBySourceSymbol, sourceSymbol)
	}
	for sourceSymbol, occurrences := range selectedClassifications {
		loaded.ClassificationsBySourceSymbol[sourceSymbol] = append([]sourceClassificationOccurrence(nil), occurrences...)
	}
	rosterSHA256 := sha256Hex(roster.Raw)
	loaded.ClassificationSelectionProofs[rosterSHA256] = newSourceClassificationSelectionProof(provider, rosterSHA256, selectedClassifications)
	return nil
}

func validateClassificationArtifactBindings(roster artifactInput, provider string, dependencies map[string]artifactInput, usedDependencyHashes map[string]struct{}) (map[classificationArtifactBinding]artifactInput, error) {
	rawBindings, ok := roster.Manifest["classification_artifact_bindings"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("evidence selection roster %q classification_artifact_bindings is not an array", roster.Path)
	}
	bindings := make(map[classificationArtifactBinding]artifactInput, len(rawBindings))
	logicalCoordinates := map[string]struct{}{}
	semanticIdentityOwners := map[string]string{}
	for index, raw := range rawBindings {
		object, ok := raw.(map[string]interface{})
		expectedKeys := []string{"artifact_id", "artifact_sha256", "artifact_version"}
		if !ok || !exactObjectKeys(object, expectedKeys) {
			return nil, fmt.Errorf("evidence selection roster %q classification_artifact_bindings[%d] does not match the closed key set", roster.Path, index)
		}
		binding := classificationArtifactBinding{}
		binding.ArtifactID, _ = manifestString(object, "artifact_id")
		binding.ArtifactVersion, _ = manifestString(object, "artifact_version")
		binding.ArtifactSHA256, _ = manifestString(object, "artifact_sha256")
		if !canonicalSurfaceKindPattern.MatchString(binding.ArtifactID) || binding.ArtifactVersion != "2" || !isLowerSHA256(binding.ArtifactSHA256) {
			return nil, fmt.Errorf("evidence selection roster %q classification_artifact_bindings[%d] has invalid identity fields", roster.Path, index)
		}
		logicalCoordinate := lengthPrefixedIdentityKey(binding.ArtifactID, binding.ArtifactVersion)
		if _, duplicate := logicalCoordinates[logicalCoordinate]; duplicate {
			return nil, fmt.Errorf("evidence selection roster %q duplicates classification artifact coordinate %s@%s", roster.Path, binding.ArtifactID, binding.ArtifactVersion)
		}
		logicalCoordinates[logicalCoordinate] = struct{}{}
		if _, duplicate := bindings[binding]; duplicate {
			return nil, fmt.Errorf("evidence selection roster %q duplicates classification artifact binding %+v", roster.Path, binding)
		}
		input, exists := dependencies[binding.ArtifactSHA256]
		if !exists || !input.Structured || input.Manifest == nil {
			return nil, fmt.Errorf("evidence selection roster %q classification artifact %s is not supplied as exact structured bytes", roster.Path, binding.ArtifactSHA256)
		}
		artifactID, artifactIDOK := manifestString(input.Manifest, "artifact")
		artifactVersion, artifactVersionOK := manifestString(input.Manifest, "artifact_version")
		artifactProvider, providerOK := manifestString(input.Manifest, "provider")
		status, statusOK := manifestString(input.Manifest, "status")
		authorityPosture, authorityPostureOK := manifestString(input.Manifest, "authority_posture")
		declaredCount, declaredCountOK := manifestInteger(input.Manifest, "source_symbol_count")
		manifestKeys := []string{"artifact", "artifact_version", "authority_posture", "provider", "row_kind", "source_symbol_count", "status"}
		if !exactObjectKeys(input.Manifest, manifestKeys) || !artifactIDOK || artifactID != binding.ArtifactID || !artifactVersionOK || artifactVersion != binding.ArtifactVersion || !providerOK || artifactProvider != provider || !statusOK || status != "candidate_source_selection_input" || !authorityPostureOK || authorityPosture != "semantic_source_element_identity_only_not_documentation_evidence" || !declaredCountOK || declaredCount <= 0 {
			return nil, fmt.Errorf("classification artifact %q does not equal its exact selection-roster identity/provider/posture binding", input.Path)
		}
		if len(input.RowKindCounts) != 2 || input.RowKindCounts["artifact_manifest"] != 1 || input.RowKindCounts["source_symbol"] != declaredCount || input.ValidationSummary != nil {
			return nil, fmt.Errorf("classification artifact %q does not contain exactly its manifest-declared source_symbol roster", input.Path)
		}
		seenSymbols := map[string]struct{}{}
		rowKeys := []string{"row_kind", "source_symbol", "surface_kind"}
		for rowIndex, row := range input.RowsByKind["source_symbol"] {
			if !exactObjectKeys(row, rowKeys) {
				return nil, fmt.Errorf("classification artifact %q source_symbol row %d does not match the closed v2 key set", input.Path, rowIndex)
			}
			symbol, symbolOK := manifestString(row, "source_symbol")
			surfaceKind, surfaceKindOK := manifestString(row, "surface_kind")
			if !symbolOK || !canonicalEvidenceMetadataString(symbol, 512) || !surfaceKindOK || !canonicalSurfaceKindPattern.MatchString(surfaceKind) {
				return nil, fmt.Errorf("classification artifact %q source_symbol row %d has an invalid closed v2 identity", input.Path, rowIndex)
			}
			if _, duplicate := seenSymbols[symbol]; duplicate {
				return nil, fmt.Errorf("classification artifact %q duplicates source_symbol %q", input.Path, symbol)
			}
			if priorArtifact, duplicate := semanticIdentityOwners[symbol]; duplicate {
				return nil, fmt.Errorf("classification artifacts %s and %s alias semantic source_symbol %q", priorArtifact, input.Path, symbol)
			}
			seenSymbols[symbol] = struct{}{}
			semanticIdentityOwners[symbol] = input.Path
		}
		bindings[binding] = input
		usedDependencyHashes[binding.ArtifactSHA256] = struct{}{}
	}
	return bindings, nil
}

func bindSelectedSourceClassification(roster artifactInput, rowIndex, occurrenceIndex int, raw interface{}, metadata evidenceBodyMetadata, bindings map[classificationArtifactBinding]artifactInput, bodies map[string]exactEvidenceBody, used map[classificationArtifactBinding]struct{}, usedRows map[string]struct{}, usedOccurrences map[string]string) (sourceClassificationOccurrence, error) {
	object, ok := raw.(map[string]interface{})
	expectedKeys := []string{"artifact_id", "artifact_sha256", "artifact_version", "evidence_locator", "row_kind", "source_symbol", "surface_kind"}
	if !ok || !exactObjectKeys(object, expectedKeys) {
		return sourceClassificationOccurrence{}, fmt.Errorf("evidence selection roster %q selected_source_document row %d classification_occurrences[%d] does not match the closed key set", roster.Path, rowIndex, occurrenceIndex)
	}
	binding := classificationArtifactBinding{}
	binding.ArtifactID, _ = manifestString(object, "artifact_id")
	binding.ArtifactVersion, _ = manifestString(object, "artifact_version")
	binding.ArtifactSHA256, _ = manifestString(object, "artifact_sha256")
	rowKind, rowKindOK := manifestString(object, "row_kind")
	sourceSymbol, sourceSymbolOK := manifestString(object, "source_symbol")
	surfaceKind, surfaceKindOK := manifestString(object, "surface_kind")
	locator, locatorOK := manifestClassificationEvidenceLocator(object, "evidence_locator")
	input, bindingOK := bindings[binding]
	if !bindingOK || !rowKindOK || rowKind != "source_classification_occurrence" || !sourceSymbolOK || !canonicalEvidenceMetadataString(sourceSymbol, 512) || !surfaceKindOK || !canonicalSurfaceKindPattern.MatchString(surfaceKind) || !locatorOK {
		return sourceClassificationOccurrence{}, fmt.Errorf("evidence selection roster %q selected_source_document row %d classification_occurrences[%d] has an unresolved classification binding", roster.Path, rowIndex, occurrenceIndex)
	}
	if err := validateLocator(locator, bodies); err != nil {
		return sourceClassificationOccurrence{}, fmt.Errorf("evidence selection roster %q selected_source_document row %d classification_occurrences[%d] has an invalid exact evidence locator: %w", roster.Path, rowIndex, occurrenceIndex, err)
	}
	if locator.EvidenceManifestSHA256 != metadata.ManifestSHA256 ||
		locator.SourceContentSHA256 != metadata.ContentSHA256 ||
		len(locator.SourceRefs) != 1 || locator.SourceRefs[0] != metadata.SourceRef ||
		len(locator.SourceURLs) != 1 || locator.SourceURLs[0] != metadata.SourceURL {
		return sourceClassificationOccurrence{}, fmt.Errorf("evidence selection roster %q selected_source_document row %d classification_occurrences[%d] locator does not equal its selected document manifest/source/content identity", roster.Path, rowIndex, occurrenceIndex)
	}
	rowKey := lengthPrefixedIdentityKey(binding.ArtifactSHA256, "source_symbol", sourceSymbol)
	var matched map[string]interface{}
	for _, candidate := range input.RowsByKind["source_symbol"] {
		identity, identityOK := manifestString(candidate, "source_symbol")
		if identityOK && identity == sourceSymbol {
			if matched != nil {
				return sourceClassificationOccurrence{}, fmt.Errorf("classification artifact %q duplicates source_symbol identity %q", input.Path, sourceSymbol)
			}
			matched = candidate
		}
	}
	if matched == nil {
		return sourceClassificationOccurrence{}, fmt.Errorf("classification artifact %q has no source_symbol identity %q", input.Path, sourceSymbol)
	}
	matchedSymbol, matchedSymbolOK := manifestString(matched, "source_symbol")
	matchedSurfaceKind, matchedSurfaceKindOK := manifestString(matched, "surface_kind")
	if !matchedSymbolOK || matchedSymbol != sourceSymbol || !matchedSurfaceKindOK || matchedSurfaceKind != surfaceKind {
		return sourceClassificationOccurrence{}, fmt.Errorf("evidence selection roster %q selected_source_document row %d classification_occurrences[%d] semantic symbol/surface does not equal its bound classification row", roster.Path, rowIndex, occurrenceIndex)
	}
	semanticTarget := lengthPrefixedIdentityKey(binding.ArtifactSHA256, sourceSymbol)
	occurrencePair := lengthPrefixedIdentityKey(locator.ID, semanticTarget)
	if priorSurfaceKind, duplicate := usedOccurrences[occurrencePair]; duplicate {
		if priorSurfaceKind != surfaceKind {
			return sourceClassificationOccurrence{}, fmt.Errorf("evidence selection roster %q gives one semantic classification target conflicting surface definitions", roster.Path)
		}
		return sourceClassificationOccurrence{}, fmt.Errorf("evidence selection roster %q duplicates exact classification occurrence for source_symbol %q", roster.Path, sourceSymbol)
	}
	used[binding] = struct{}{}
	usedRows[rowKey] = struct{}{}
	usedOccurrences[occurrencePair] = surfaceKind
	return sourceClassificationOccurrence{Binding: binding, SourceSymbol: sourceSymbol, SurfaceKind: surfaceKind, Locator: locator}, nil
}

func manifestClassificationEvidenceLocator(object map[string]interface{}, key string) (evidenceLocator, bool) {
	raw, ok := object[key].(map[string]interface{})
	expectedKeys := []string{"byte_end_offset_exclusive", "byte_start_offset", "evidence_locator_id", "evidence_manifest_sha256", "locator_semantics", "row_kind", "selected_range_byte_count", "selected_range_sha256", "source_bytes_present", "source_content_sha256", "source_refs", "source_urls"}
	if !ok || !exactObjectKeys(raw, expectedKeys) {
		return evidenceLocator{}, false
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return evidenceLocator{}, false
	}
	var locator evidenceLocator
	if err := strictUnmarshal(encoded, &locator); err != nil || locator.RowKind != "candidate_evidence_locator" {
		return evidenceLocator{}, false
	}
	return locator, true
}

func collectRawSHA256Pins(value interface{}, path []string, out map[string]string) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			next := append(append([]string(nil), path...), key)
			if key == "raw_sha256" {
				if digest, ok := child.(string); ok {
					out[strings.Join(next, ".")] = digest
				} else {
					out[strings.Join(next, ".")] = ""
				}
				continue
			}
			collectRawSHA256Pins(child, next, out)
		}
	case []interface{}:
		for index, child := range typed {
			collectRawSHA256Pins(child, append(append([]string(nil), path...), strconv.Itoa(index)), out)
		}
	}
}

func validateDependencyBindings(plan *parsedPlan, ood oodContract, oodSHA, grandVisionSHA string, sourceRecordIdentity structuredAuthorityIdentity, sourceRecordSHA string, loaded loadedEvidence, dependencies map[string]artifactInput, semanticValidation dependencySemanticValidationResolution, derivationClosureOutput *documentationDerivationClosureProof) error {
	if derivationClosureOutput == nil {
		return fmt.Errorf("dependency binding validation requires a documentation-derivation closure output")
	}
	*derivationClosureOutput = documentationDerivationClosureProof{}
	evidence := loaded.Artifacts
	for _, digest := range sortedProviderStringMapKeys(evidence) {
		input := evidence[digest]
		provider, ok := manifestString(input.Manifest, "provider")
		if !ok || provider != plan.Manifest.Provider {
			return fmt.Errorf("evidence manifest %q provider %q does not match plan provider %q", input.Path, provider, plan.Manifest.Provider)
		}
	}

	type declaredBinding struct {
		field  string
		digest string
	}
	directBindings := []declaredBinding{
		{field: "provider_neutral_compilation_profile_sha256", digest: plan.Manifest.ProviderNeutralProfileSHA256},
		{field: "source_contract_index_sha256", digest: plan.Manifest.SourceContractIndexSHA256},
		{field: "sample_shape_index_sha256", digest: plan.Manifest.SampleShapeIndexSHA256},
		{field: "protocol_contract_index_sha256", digest: plan.Manifest.ProtocolContractIndexSHA256},
		{field: "field_mapping_candidate_sha256", digest: plan.Manifest.FieldMappingCandidateSHA256},
		{field: "evidence_selection_roster_sha256", digest: plan.Manifest.EvidenceSelectionRosterSHA256},
	}
	bound := make(map[string]artifactInput, len(directBindings))
	usedDependencyHashes := map[string]struct{}{}
	directDigestFields := map[string]string{}
	for _, binding := range directBindings {
		if !isLowerSHA256(binding.digest) {
			return fmt.Errorf("%s is not a lowercase SHA-256 digest", binding.field)
		}
		if priorField, duplicate := directDigestFields[binding.digest]; duplicate {
			return fmt.Errorf("plan dependency fields %s and %s alias the same exact artifact digest %s", priorField, binding.field, binding.digest)
		}
		directDigestFields[binding.digest] = binding.field
		input, ok := dependencies[binding.digest]
		if !ok {
			return fmt.Errorf("%s %s is not bound to exact supplied dependency-artifact bytes", binding.field, binding.digest)
		}
		if !input.Structured || input.Manifest == nil {
			return fmt.Errorf("%s %s resolves to raw authority bytes rather than a structured dependency artifact", binding.field, binding.digest)
		}
		bound[binding.field] = input
		usedDependencyHashes[binding.digest] = struct{}{}
	}
	if err := validateEvidenceClosure(plan, loaded); err != nil {
		return err
	}
	if err := validateEvidenceSelectionRoster(bound["evidence_selection_roster_sha256"], plan.Manifest.Provider, loaded, dependencies, usedDependencyHashes, plan); err != nil {
		return err
	}
	if err := validateCandidateAPISymbolDerivationBindings(plan, loaded, plan.Manifest.EvidenceSelectionRosterSHA256); err != nil {
		return err
	}
	evidenceByConsumer := evidenceManifestDigestsByConsumer(plan.Manifest.EvidenceManifestBindings)

	profile := bound["provider_neutral_compilation_profile_sha256"]
	profileStatus, statusOK := manifestString(profile.Manifest, "status")
	if !statusOK || profileStatus != "candidate_not_admissible" {
		return fmt.Errorf("provider-neutral profile %q must have status candidate_not_admissible", profile.Path)
	}
	profileVersion, ok := manifestString(profile.Manifest, "schema_version")
	if !ok || !strings.HasPrefix(profileVersion, "provider_documentation_compilation_profile_candidate.") {
		return fmt.Errorf("provider-neutral profile %q has no recognized candidate schema_version", profile.Path)
	}
	profileNamedSystem, ok := manifestString(profile.Manifest, "named_system")
	if !ok || profileNamedSystem != "Velenza BOC" {
		return fmt.Errorf("provider-neutral profile %q uses named_system %q", profile.Path, profileNamedSystem)
	}
	profileOOD, ok := manifestString(profile.Manifest, "canonical_ood_graph_spec", "raw_sha256")
	if !ok || profileOOD != oodSHA {
		return fmt.Errorf("provider-neutral profile embedded OOD digest %q does not match selected OOD bytes %q", profileOOD, oodSHA)
	}
	if err := bindSelectedProfileAuthorities(profile, ood, oodSHA, grandVisionSHA, sourceRecordIdentity, sourceRecordSHA); err != nil {
		return err
	}

	sourceContract := bound["source_contract_index_sha256"]
	if err := validateProviderArtifact(sourceContract, plan.Manifest.Provider); err != nil {
		return err
	}
	if err := validateEvidenceManifestReferences(sourceContract, "derived_from_manifest_sha256s", evidenceByConsumer["source_contract_index"], evidence); err != nil {
		return err
	}
	sampleShape := bound["sample_shape_index_sha256"]
	if err := validateProviderArtifact(sampleShape, plan.Manifest.Provider); err != nil {
		return err
	}
	if err := validateEvidenceManifestReferences(sampleShape, "derived_from_manifest_sha256s", evidenceByConsumer["sample_shape_index"], evidence); err != nil {
		return err
	}
	protocolContract := bound["protocol_contract_index_sha256"]
	if err := validateProviderArtifact(protocolContract, plan.Manifest.Provider); err != nil {
		return err
	}
	if err := validateEvidenceManifestReferences(protocolContract, "derived_from_manifest_sha256s", evidenceByConsumer["protocol_contract_index"], evidence); err != nil {
		return err
	}

	fieldMapping := bound["field_mapping_candidate_sha256"]
	if err := validateProviderArtifact(fieldMapping, plan.Manifest.Provider); err != nil {
		return err
	}
	if err := validateEvidenceManifestReferences(fieldMapping, "evidence_manifest_sha256s", evidenceByConsumer["field_mapping_candidate"], evidence); err != nil {
		return err
	}
	fieldMapSourceDigest, ok := manifestString(fieldMapping.Manifest, "source_contract_index_sha256")
	if !ok || fieldMapSourceDigest != plan.Manifest.SourceContractIndexSHA256 {
		return fmt.Errorf("field-mapping dependency %q source_contract_index_sha256 %q does not equal the plan binding %q", fieldMapping.Path, fieldMapSourceDigest, plan.Manifest.SourceContractIndexSHA256)
	}
	dispositionDigest, present := manifestString(fieldMapping.Manifest, "surface_family_disposition_sha256")
	if !present {
		return fmt.Errorf("field-mapping dependency %q must bind an exact surface_family_disposition_sha256", fieldMapping.Path)
	}
	if !isLowerSHA256(dispositionDigest) {
		return fmt.Errorf("field-mapping dependency %q has malformed surface_family_disposition_sha256 %q", fieldMapping.Path, dispositionDigest)
	}
	if directField, alias := directDigestFields[dispositionDigest]; alias {
		return fmt.Errorf("surface_family_disposition_sha256 aliases direct dependency field %s at digest %s", directField, dispositionDigest)
	}
	disposition, ok := dependencies[dispositionDigest]
	if !ok {
		return fmt.Errorf("field-mapping dependency %q surface_family_disposition_sha256 %s is not bound to exact supplied dependency-artifact bytes", fieldMapping.Path, dispositionDigest)
	}
	if !disposition.Structured || disposition.Manifest == nil {
		return fmt.Errorf("field-mapping dependency %q surface_family_disposition_sha256 %s resolves to raw authority bytes", fieldMapping.Path, dispositionDigest)
	}
	usedDependencyHashes[dispositionDigest] = struct{}{}
	if err := validateProviderArtifact(disposition, plan.Manifest.Provider); err != nil {
		return err
	}
	dispositionSource, ok := manifestString(disposition.Manifest, "source_contract_index_sha256")
	if !ok || dispositionSource != plan.Manifest.SourceContractIndexSHA256 {
		return fmt.Errorf("surface-family dependency %q source_contract_index_sha256 %q does not equal the plan binding %q", disposition.Path, dispositionSource, plan.Manifest.SourceContractIndexSHA256)
	}
	if err := validateEvidenceManifestReferences(disposition, "evidence_manifest_sha256s", evidenceByConsumer["surface_family_disposition"], evidence); err != nil {
		return err
	}
	surfaceDisposition := &disposition
	if err := validateDependencySummaryBindings(plan, oodSHA, evidence, profile, sourceContract, sampleShape, protocolContract, fieldMapping, surfaceDisposition); err != nil {
		return err
	}
	if err := validateDependencySemanticClosure(
		semanticValidation.proof,
		semanticValidation.derivationTargets,
		semanticValidation.derivationTargetArtifacts,
		plan,
		ood,
		loaded,
		profile,
		sourceContract,
		sampleShape,
		protocolContract,
		fieldMapping,
		disposition,
		dependencySemanticAuxiliaries{
			operationApplicability:              semanticValidation.roleArtifacts[dependencySemanticRoleOperationApplicability],
			apiGraphApplicability:               semanticValidation.roleArtifacts[dependencySemanticRoleAPIGraphApplicability],
			fieldSecurityPolicy:                 semanticValidation.roleArtifacts[dependencySemanticRoleFieldSecurityPolicy],
			mappingTransitiveDependencyRoster:   semanticValidation.roleArtifacts[dependencySemanticRoleMappingTransitiveRoster],
			documentationClaimDerivationProfile: semanticValidation.roleArtifacts[dependencySemanticRoleDocumentationClaimDerivation],
		},
		derivationClosureOutput,
	); err != nil {
		return err
	}

	locatorDigest := evidenceLocatorManifestSHA256(plan.LocatorCanonicalRows, plan.LocatorOrder)
	if plan.Manifest.EvidenceLocatorManifestSHA256 != locatorDigest {
		return fmt.Errorf("evidence_locator_manifest_sha256 %q does not match deterministic locator rows %q", plan.Manifest.EvidenceLocatorManifestSHA256, locatorDigest)
	}
	return nil
}

func validateDependencySummaryBindings(plan *parsedPlan, oodSHA string, evidence map[string]artifactInput, profile, sourceContract, sampleShape, protocolContract, fieldMapping artifactInput, surfaceDisposition *artifactInput) error {
	dependencies := []struct {
		role  string
		input artifactInput
	}{
		{role: "provider-neutral profile", input: profile},
		{role: "source-contract index", input: sourceContract},
		{role: "sample-shape index", input: sampleShape},
		{role: "protocol-contract index", input: protocolContract},
		{role: "field mapping", input: fieldMapping},
	}
	for _, dependency := range dependencies {
		role, input := dependency.role, dependency.input
		if input.RowKindCounts["validation_summary"] != 1 {
			return fmt.Errorf("%s dependency %q has %d validation_summary rows, want exactly 1", role, input.Path, input.RowKindCounts["validation_summary"])
		}
		if input.ValidationSummary == nil {
			return fmt.Errorf("%s dependency validation_summary %q is a marker without a semantic body", role, input.Path)
		}
	}
	if surfaceDisposition != nil && surfaceDisposition.RowKindCounts["validation_summary"] != 1 {
		return fmt.Errorf("surface-family dependency %q has %d validation_summary rows, want exactly 1", surfaceDisposition.Path, surfaceDisposition.RowKindCounts["validation_summary"])
	}
	if surfaceDisposition != nil && surfaceDisposition.ValidationSummary == nil {
		return fmt.Errorf("surface-family dependency validation_summary %q is a marker without a semantic body", surfaceDisposition.Path)
	}

	if err := validateProfileValidationSummary(profile, oodSHA, plan); err != nil {
		return err
	}
	evidenceByConsumer := evidenceManifestDigestsByConsumer(plan.Manifest.EvidenceManifestBindings)
	sourceContractEvidence, err := aggregateEvidenceArtifacts(evidenceByConsumer["source_contract_index"], evidence)
	if err != nil {
		return fmt.Errorf("source-contract dependency %q evidence closure: %w", sourceContract.Path, err)
	}
	protocolEvidence, err := aggregateEvidenceArtifacts(evidenceByConsumer["protocol_contract_index"], evidence)
	if err != nil {
		return fmt.Errorf("protocol-contract dependency %q evidence closure: %w", protocolContract.Path, err)
	}
	if err := validateSourceContractValidationSummary(sourceContract, sourceContractEvidence); err != nil {
		return err
	}
	if err := validateSampleShapeValidationSummary(sampleShape, sourceContract); err != nil {
		return err
	}
	if err := validateProtocolContractValidationSummary(protocolContract, protocolEvidence); err != nil {
		return err
	}
	if err := validateFieldMappingValidationSummary(fieldMapping, sourceContract); err != nil {
		return err
	}
	if surfaceDisposition != nil {
		if err := validateSurfaceDispositionValidationSummary(*surfaceDisposition, sourceContract); err != nil {
			return err
		}
	}

	summaryCounts := []struct {
		name string
		got  int
		want int
	}{
		{name: "exact_source_document_count", got: plan.Summary.ExactSourceDocumentCount, want: sourceContract.RowKindCounts["source_document"]},
		{name: "exact_documented_field_occurrence_count", got: plan.Summary.ExactDocumentedFieldOccurrenceCount, want: sourceContract.RowKindCounts["field_contract"]},
		{name: "sample_json_block_count", got: plan.Summary.SampleJSONBlockCount, want: sampleShape.RowKindCounts["sample_json_block"]},
		{name: "protocol_assertion_count", got: plan.Summary.ProtocolAssertionCount, want: protocolContract.RowKindCounts["protocol_assertion_projection"]},
		{name: "preserved_contradiction_count", got: plan.Summary.PreservedContradictionCount, want: protocolContract.RowKindCounts["provider_contract_contradiction"]},
	}
	for _, count := range summaryCounts {
		if count.got != count.want {
			return fmt.Errorf("validation_summary %s %d does not equal exact dependency row count %d", count.name, count.got, count.want)
		}
	}
	if fieldMapping.RowKindCounts["field_occurrence_disposition"] != sourceContract.RowKindCounts["field_contract"] {
		return fmt.Errorf("field-mapping dependency %q has %d field_occurrence_disposition rows, want one for each of %d exact field_contract rows", fieldMapping.Path, fieldMapping.RowKindCounts["field_occurrence_disposition"], sourceContract.RowKindCounts["field_contract"])
	}
	// Surface-family totality is evaluated later against the sealed typed
	// resource-symbol set. Document count is neither a surface count nor an API
	// role authority, so this artifact-only pass must not infer one from it.
	// Operation kinds, resource applicability, and schema-field rollups belong
	// to the exact profile-bound dependency artifacts. The generic verifier does
	// not infer provider semantics from free-form candidate properties.
	return nil
}

func validateDependencySummaryCommon(input artifactInput, expectedResult string) (map[string]interface{}, error) {
	summary := input.ValidationSummary
	if summary == nil {
		return nil, fmt.Errorf("dependency validation_summary in %q is missing", input.Path)
	}
	rowKind, ok := manifestString(summary, "row_kind")
	if !ok || rowKind != "validation_summary" {
		return nil, fmt.Errorf("dependency validation_summary in %q has an invalid row_kind", input.Path)
	}
	result, ok := manifestString(summary, "result")
	if !ok || result != expectedResult {
		return nil, fmt.Errorf("dependency validation_summary in %q result %q must equal %q", input.Path, result, expectedResult)
	}
	if hasManifestKey(summary, "source_bytes_present") {
		sourceBytes, ok := manifestBool(summary, "source_bytes_present")
		if !ok || sourceBytes {
			return nil, fmt.Errorf("dependency validation_summary in %q must set source_bytes_present=false when declared", input.Path)
		}
	}
	if hasManifestKey(summary, "issue_count") {
		issueCount, ok := manifestInteger(summary, "issue_count")
		if !ok || issueCount != 0 {
			return nil, fmt.Errorf("dependency validation_summary in %q must set integer issue_count=0 when declared", input.Path)
		}
	}
	return summary, nil
}

func validateProfileValidationSummary(profile artifactInput, oodSHA string, plan *parsedPlan) error {
	summary, err := validateDependencySummaryCommon(profile, "provider_neutral_profile_compiled_from_current_canonical_ood_graph_contract")
	if err != nil {
		return err
	}
	checks := []struct {
		field string
		want  int
	}{
		{field: "api_element_role_count", want: profile.RowKindCounts["api_element_role"]},
		{field: "api_relationship_count", want: profile.RowKindCounts["api_relationship"]},
		{field: "api_property_family_count", want: profile.RowKindCounts["api_property_family"]},
		{field: "canonical_capability_stage_count", want: profile.RowKindCounts["capability_stage"]},
		{field: "canonical_table_surface_count", want: profile.RowKindCounts["canonical_table_surface"]},
		{field: "external_document_object_class_count", want: profile.RowKindCounts["external_document_object_class"]},
		{field: "external_document_edge_label_count", want: profile.RowKindCounts["external_document_edge_label"]},
	}
	for _, check := range checks {
		value, ok := manifestInteger(summary, check.field)
		if !ok || value != check.want {
			return fmt.Errorf("provider-neutral profile dependency validation_summary %s %d does not equal exact row count %d", check.field, value, check.want)
		}
	}
	declaredOOD, ok := manifestString(summary, "canonical_ood_graph_sha256")
	if !ok || declaredOOD != oodSHA {
		return fmt.Errorf("provider-neutral profile dependency validation_summary canonical_ood_graph_sha256 %q does not equal selected OOD %q", declaredOOD, oodSHA)
	}
	for _, field := range []string{"organization_id_kernel_injected", "canonical_execution_is_admitted_nodes"} {
		value, ok := manifestBool(summary, field)
		if !ok || !value {
			return fmt.Errorf("provider-neutral profile dependency validation_summary must affirm %s", field)
		}
	}
	for _, field := range []string{"provider_specific_go_required", "kernel_go_required", "ready_to_execute"} {
		value, ok := manifestBool(summary, field)
		if !ok || value {
			return fmt.Errorf("provider-neutral profile dependency validation_summary must set %s=false", field)
		}
	}
	blockers, ok := manifestStringSlice(summary, "execution_blockers")
	if !ok || len(blockers) == 0 {
		return fmt.Errorf("provider-neutral profile dependency validation_summary must carry nonempty execution_blockers")
	}
	return nil
}

func validateSourceContractValidationSummary(input, evidence artifactInput) error {
	summary, err := validateDependencySummaryCommon(input, "candidate_parse_complete")
	if err != nil {
		return err
	}
	checks := []struct {
		field string
		want  int
	}{
		{field: "expected_source_documents", want: input.RowKindCounts["source_document"]},
		{field: "parsed_source_documents", want: input.RowKindCounts["source_document"]},
		{field: "section_count", want: input.RowKindCounts["section_index"]},
		{field: "field_contract_count", want: input.RowKindCounts["field_contract"]},
		{field: "documentation_table_row_count", want: input.RowKindCounts["documentation_table_row"]},
		{field: "api_operation_count", want: input.RowKindCounts["api_operation"]},
		{field: "parse_issue_count", want: input.RowKindCounts["parse_issue"]},
	}
	for _, check := range checks {
		value, ok := manifestInteger(summary, check.field)
		if !ok || value != check.want {
			return fmt.Errorf("source-contract dependency validation_summary %s %d does not equal exact row count %d", check.field, value, check.want)
		}
	}
	if input.RowKindCounts["source_document"] != evidence.EvidenceBodyCount {
		return fmt.Errorf("source-contract dependency has %d source_document rows, want one for each of %d evidence bodies", input.RowKindCounts["source_document"], evidence.EvidenceBodyCount)
	}
	if err := requireSummaryBool(summary, "exact_evidence_hydration_coordinates_present", true, input.Path); err != nil {
		return err
	}
	if err := requireSummaryBool(summary, "diagnostic_line_and_section_coordinates_are_authority", false, input.Path); err != nil {
		return err
	}
	if err := requireSummaryBool(summary, "source_neutral_targets_admitted", false, input.Path); err != nil {
		return err
	}
	return requireSummaryString(summary, "authoritative_locator_form", zeroBasedHalfOpenLocatorForm, input.Path)
}

func validateSampleShapeValidationSummary(input, sourceContract artifactInput) error {
	summary, err := validateDependencySummaryCommon(input, "candidate_sample_index_complete_with_explicit_parse_outcomes")
	if err != nil {
		return err
	}
	outcomeCounts, err := sampleParseOutcomeCountsFromArtifact(input)
	if err != nil {
		return err
	}
	checks := []struct {
		field string
		want  int
	}{
		{field: "expected_source_documents", want: sourceContract.RowKindCounts["source_document"]},
		{field: "sample_json_block_count", want: input.RowKindCounts["sample_json_block"]},
		{field: "sample_parse_profile_count", want: input.RowKindCounts["sample_parse_profile"]},
		{field: "parsed_sample_json_block_count", want: outcomeCounts[sampleParseOutcomeParsed]},
		{field: "unparsed_sample_json_block_count", want: input.RowKindCounts["sample_json_block"] - outcomeCounts[sampleParseOutcomeParsed]},
		{field: "failed_sample_json_block_count", want: outcomeCounts[sampleParseOutcomeFailed]},
		{field: "unsupported_sample_json_block_count", want: outcomeCounts[sampleParseOutcomeUnsupported]},
		{field: "not_applicable_sample_json_block_count", want: outcomeCounts[sampleParseOutcomeNotApplicable]},
		{field: "sample_json_shape_row_count", want: input.RowKindCounts["sample_json_shape"]},
		{field: "exact_evidence_locator_binding_count", want: input.RowKindCounts["sample_json_block"] + input.RowKindCounts["sample_json_shape"]},
	}
	for _, check := range checks {
		value, ok := manifestInteger(summary, check.field)
		if !ok || value != check.want {
			return fmt.Errorf("sample-shape dependency validation_summary %s %d does not equal exact row count %d", check.field, value, check.want)
		}
	}
	for _, check := range []struct {
		field string
		want  bool
	}{{"raw_numeric_lexemes_preserved", true}, {"source_examples_treated_as_schema", false}, {"exact_evidence_hydration_coordinates_present", true}, {"diagnostic_line_and_section_coordinates_are_authority", false}} {
		if err := requireSummaryBool(summary, check.field, check.want, input.Path); err != nil {
			return err
		}
	}
	return requireSummaryString(summary, "authoritative_locator_form", zeroBasedHalfOpenLocatorForm, input.Path)
}

func validateProtocolContractValidationSummary(input, evidence artifactInput) error {
	summary, err := validateDependencySummaryCommon(input, "candidate_protocol_contract_index_complete")
	if err != nil {
		return err
	}
	checks := []struct {
		field string
		want  int
	}{
		{field: "evidence_body_count", want: evidence.EvidenceBodyCount},
		{field: "protocol_section_projection_count", want: input.RowKindCounts["protocol_section_projection"]},
		{field: "protocol_assertion_projection_count", want: input.RowKindCounts["protocol_assertion_projection"]},
		{field: "preserved_provider_contradiction_count", want: input.RowKindCounts["provider_contract_contradiction"]},
	}
	for _, check := range checks {
		value, ok := manifestInteger(summary, check.field)
		if !ok || value != check.want {
			return fmt.Errorf("protocol-contract dependency validation_summary %s %d does not equal exact count %d", check.field, value, check.want)
		}
	}
	exactBytes, ok := manifestInt64(summary, "evidence_exact_source_bytes")
	if !ok || exactBytes != evidence.EvidenceByteCount {
		return fmt.Errorf("protocol-contract dependency validation_summary evidence_exact_source_bytes does not equal exact evidence bytes")
	}
	for _, check := range []struct {
		field string
		want  bool
	}{{"source_export_is_only_evidence_body", true}, {"exact_hydration_coordinates_present", true}, {"diagnostic_line_and_section_coordinates_are_authority", false}} {
		if err := requireSummaryBool(summary, check.field, check.want, input.Path); err != nil {
			return err
		}
	}
	locatorCount, ok := manifestInteger(summary, "exact_evidence_locator_binding_count")
	minimum := input.RowKindCounts["protocol_section_projection"] + input.RowKindCounts["protocol_assertion_projection"] + input.RowKindCounts["provider_contract_contradiction"]
	if !ok || locatorCount < minimum {
		return fmt.Errorf("protocol-contract dependency validation_summary exact_evidence_locator_binding_count %d is below exact candidate row count %d", locatorCount, minimum)
	}
	return requireSummaryString(summary, "authoritative_locator_form", zeroBasedHalfOpenLocatorForm, input.Path)
}

func validateFieldMappingValidationSummary(input, sourceContract artifactInput) error {
	summary, err := validateDependencySummaryCommon(input, "candidate_complete_atomic_field_occurrence_disposition_with_explicit_quarantine_and_no_passthrough")
	if err != nil {
		return err
	}
	fieldCount := input.RowKindCounts["field_occurrence_disposition"]
	checks := []struct {
		field string
		want  int
	}{
		{field: "source_document_count", want: sourceContract.RowKindCounts["source_document"]},
		{field: "documented_field_occurrence_count", want: sourceContract.RowKindCounts["field_contract"]},
		{field: "disposed_field_occurrence_count", want: fieldCount},
		{field: "exact_locator_binding_count", want: fieldCount},
		{field: "silent_unknown_count", want: 0},
		{field: "arbitrary_provider_json_passthrough_count", want: 0},
		{field: "raw_value_embedding_count", want: 0},
		{field: "binary_float_authoritative_count", want: 0},
	}
	for _, check := range checks {
		value, ok := manifestInteger(summary, check.field)
		if !ok || value != check.want {
			return fmt.Errorf("field-mapping dependency validation_summary %s %d does not equal exact count %d", check.field, value, check.want)
		}
	}
	restricted, restrictedOK := manifestInteger(summary, "restricted_no_embed_count")
	standard, standardOK := manifestInteger(summary, "standard_no_raw_value_embedding_count")
	if !restrictedOK || !standardOK || restricted+standard != fieldCount {
		return fmt.Errorf("field-mapping dependency validation_summary security-class counts do not partition %d field occurrences", fieldCount)
	}
	if err := requireSummaryBool(summary, "canonical_target_contracts_locked", false, input.Path); err != nil {
		return err
	}
	policyDigest, policyOK := manifestString(input.Manifest, "field_security_policy_sha256")
	summaryPolicyDigest, summaryPolicyOK := manifestString(summary, "security_policy_sha256")
	if !policyOK || !summaryPolicyOK || policyDigest != summaryPolicyDigest || !isLowerSHA256(policyDigest) {
		return fmt.Errorf("field-mapping dependency validation_summary security_policy_sha256 does not equal its manifest binding")
	}
	return nil
}

func validateSurfaceDispositionValidationSummary(input, _ artifactInput) error {
	summary, err := validateDependencySummaryCommon(input, "candidate_exhaustive_surface_family_disposition_complete")
	if err != nil {
		return err
	}
	surfaceCount := input.RowKindCounts["surface_disposition"]
	checks := []struct {
		field string
		want  int
	}{
		{field: "expected_surface_count", want: surfaceCount},
		{field: "disposed_surface_count", want: surfaceCount},
		{field: "silent_unknown_count", want: 0},
		{field: "universal_blob_targets", want: 0},
		{field: "exact_evidence_locator_binding_count", want: surfaceCount},
	}
	for _, check := range checks {
		value, ok := manifestInteger(summary, check.field)
		if !ok || value != check.want {
			return fmt.Errorf("surface-family dependency validation_summary %s %d does not equal exact count %d", check.field, value, check.want)
		}
	}
	unlocked, ok := manifestInteger(summary, "canonical_contracts_still_unlocked")
	if !ok || unlocked != surfaceCount {
		return fmt.Errorf("surface-family dependency validation_summary canonical_contracts_still_unlocked %d does not equal exact surface count %d", unlocked, surfaceCount)
	}
	disposedByKind, kindsOK := manifestNamedCountArray(summary, "disposed_surface_kind_counts", "surface_kind")
	capturedByKind, capturedKindsOK := manifestNamedCountArray(summary, "captured_surface_kind_counts", "surface_kind")
	disposedKindTotal := 0
	for _, kind := range sortedProviderStringMapKeys(disposedByKind) {
		count := disposedByKind[kind]
		if !canonicalSurfaceKindPattern.MatchString(kind) {
			return fmt.Errorf("surface-family dependency validation_summary has non-canonical surface kind %q", kind)
		}
		disposedKindTotal += count
	}
	if !kindsOK || !capturedKindsOK || !equalIntegerMaps(disposedByKind, capturedByKind) || disposedKindTotal != surfaceCount {
		return fmt.Errorf("surface-family dependency validation_summary dynamic surface-kind counts do not partition %d surfaces", surfaceCount)
	}
	if err := requireSummaryBool(summary, "diagnostic_coordinates_are_authority", false, input.Path); err != nil {
		return err
	}
	return requireSummaryString(summary, "authoritative_locator_form", zeroBasedHalfOpenLocatorForm, input.Path)
}

func requireSummaryBool(summary map[string]interface{}, field string, want bool, path string) error {
	value, ok := manifestBool(summary, field)
	if !ok || value != want {
		return fmt.Errorf("dependency validation_summary in %q must set %s=%t", path, field, want)
	}
	return nil
}

func requireSummaryString(summary map[string]interface{}, field, want, path string) error {
	value, ok := manifestString(summary, field)
	if !ok || value != want {
		return fmt.Errorf("dependency validation_summary in %q must set %s=%q", path, field, want)
	}
	return nil
}

func manifestInteger(object map[string]interface{}, key string) (int, bool) {
	number, ok := object[key].(json.Number)
	if !ok {
		return 0, false
	}
	value, err := strconv.Atoi(number.String())
	return value, err == nil
}

func manifestNonnegativeIntegerMap(object map[string]interface{}, key string) (map[string]int, bool) {
	rawMap, ok := object[key].(map[string]interface{})
	if !ok {
		return nil, false
	}
	result := make(map[string]int, len(rawMap))
	for name, value := range rawMap {
		if !canonicalSurfaceKindPattern.MatchString(name) {
			return nil, false
		}
		count, ok := semanticJSONInt64(value)
		if !ok || count <= 0 || count > int64(^uint(0)>>1) {
			return nil, false
		}
		result[name] = int(count)
	}
	return result, true
}

func manifestNamedCountArray(object map[string]interface{}, key, nameField string) (map[string]int, bool) {
	raw, ok := object[key].([]interface{})
	if !ok {
		return nil, false
	}
	result := make(map[string]int, len(raw))
	prior := ""
	for _, value := range raw {
		entry, ok := value.(map[string]interface{})
		if !ok || !exactObjectKeys(entry, []string{nameField, "count"}) {
			return nil, false
		}
		name, nameOK := manifestString(entry, nameField)
		count, countOK := manifestInteger(entry, "count")
		if !nameOK || !canonicalSurfaceKindPattern.MatchString(name) || name <= prior || !countOK || count <= 0 {
			return nil, false
		}
		prior = name
		result[name] = count
	}
	return result, true
}

func equalIntegerMaps(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func manifestInt64(object map[string]interface{}, key string) (int64, bool) {
	number, ok := object[key].(json.Number)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseInt(number.String(), 10, 64)
	return value, err == nil
}

func manifestBool(object map[string]interface{}, key string) (bool, bool) {
	value, ok := object[key].(bool)
	return value, ok
}

func manifestStringSlice(object map[string]interface{}, key string) ([]string, bool) {
	raw, ok := object[key].([]interface{})
	if !ok {
		return nil, false
	}
	values := make([]string, 0, len(raw))
	for _, entry := range raw {
		value, ok := entry.(string)
		if !ok {
			return nil, false
		}
		values = append(values, value)
	}
	return values, true
}

func hasManifestKey(object map[string]interface{}, key string) bool {
	_, ok := object[key]
	return ok
}

func validateProviderArtifact(input artifactInput, provider string) error {
	if err := validateCandidateArtifactManifest(input, provider); err != nil {
		return err
	}
	return nil
}

func validateCandidateArtifactManifest(input artifactInput, provider string) error {
	rowKind, rowKindOK := manifestString(input.Manifest, "row_kind")
	_, artifactOK := manifestString(input.Manifest, "artifact")
	_, versionOK := manifestString(input.Manifest, "artifact_version")
	status, statusOK := manifestString(input.Manifest, "status")
	declaredProvider, providerOK := manifestString(input.Manifest, "provider")
	if !rowKindOK || rowKind != "artifact_manifest" || !artifactOK || !versionOK || !statusOK || status != "candidate_not_admissible" || !providerOK {
		return fmt.Errorf("candidate artifact %q has an incomplete manifest or a status other than candidate_not_admissible", input.Path)
	}
	if provider != "" && declaredProvider != provider {
		return fmt.Errorf("dependency artifact %q provider %q does not match plan provider %q", input.Path, declaredProvider, provider)
	}
	return nil
}

func validateEvidenceManifestReferences(input artifactInput, field string, expected map[string]struct{}, evidence map[string]artifactInput) error {
	values, ok := manifestStringSlice(input.Manifest, field)
	if !ok || len(values) == 0 {
		return fmt.Errorf("dependency artifact %q has no nonempty typed %s roster", input.Path, field)
	}
	actual := map[string]struct{}{}
	for _, digest := range values {
		if !isLowerSHA256(digest) {
			return fmt.Errorf("dependency artifact %q %s contains malformed digest %q", input.Path, field, digest)
		}
		if _, duplicate := actual[digest]; duplicate {
			return fmt.Errorf("dependency artifact %q %s duplicates digest %s", input.Path, field, digest)
		}
		if _, exists := evidence[digest]; !exists {
			return fmt.Errorf("dependency artifact %q %s digest %s is not bound to exact supplied evidence bytes", input.Path, field, digest)
		}
		actual[digest] = struct{}{}
	}
	if err := requireExactSet(fmt.Sprintf("dependency artifact %q %s", input.Path, field), actual, expected); err != nil {
		return err
	}
	return nil
}

func aggregateEvidenceArtifacts(digests map[string]struct{}, evidence map[string]artifactInput) (artifactInput, error) {
	if len(digests) == 0 {
		return artifactInput{}, fmt.Errorf("empty typed evidence-manifest roster")
	}
	aggregate := artifactInput{
		Path:             "typed evidence-manifest roster",
		RowKindCounts:    map[string]int{},
		EvidenceBodyKind: evidenceBodyKindSourceDocument,
	}
	for _, digest := range sortedProviderStringMapKeys(digests) {
		input, ok := evidence[digest]
		if !ok {
			return artifactInput{}, fmt.Errorf("manifest digest %s is not supplied", digest)
		}
		if input.EvidenceBodyKind != evidenceBodyKindSourceDocument {
			return artifactInput{}, fmt.Errorf("manifest digest %s is not a generic source-document evidence manifest", digest)
		}
		aggregate.EvidenceBodyCount += input.EvidenceBodyCount
		aggregate.EvidenceByteCount += input.EvidenceByteCount
		for kind, count := range input.RowKindCounts {
			aggregate.RowKindCounts[kind] += count
		}
	}
	return aggregate, nil
}

func manifestString(manifest map[string]interface{}, path ...string) (string, bool) {
	var current interface{} = manifest
	for _, key := range path {
		object, ok := current.(map[string]interface{})
		if !ok {
			return "", false
		}
		current, ok = object[key]
		if !ok {
			return "", false
		}
	}
	value, ok := current.(string)
	return value, ok && value != ""
}

func evidenceLocatorManifestSHA256(rows map[string][]byte, order []string) string {
	var canonical bytes.Buffer
	for _, id := range order {
		canonical.Write(rows[id])
		canonical.WriteByte('\n')
	}
	return sha256Hex(canonical.Bytes())
}

func canonicalEvidenceSourceRef(value string) bool {
	return canonicalEvidenceMetadataString(value, 2048)
}

func canonicalEvidenceMetadataString(value string, maxBytes int) bool {
	if value == "" || len([]byte(value)) > maxBytes || strings.TrimSpace(value) != value || !utf8.ValidString(value) || credentialShapedValue(value) {
		return false
	}
	for _, char := range value {
		if char == 0 || char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func canonicalEvidenceSourceURL(value string) bool {
	if !canonicalEvidenceMetadataString(value, 2048) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Port() != "" || parsed.Hostname() != strings.ToLower(parsed.Hostname()) {
		return false
	}
	return parsed.String() == value
}

func rejectForbiddenPlanKeysAndNonIntegerNumbers(raw []byte) error {
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	if err := walkCandidateValue(value, true); err != nil {
		return err
	}
	return rejectReconstructedCredentialMaterial(raw)
}

func knownCredentialTokenAnywhere(value []byte) bool {
	if bytesAreASCII(value) {
		return knownCredentialTokenAnywhereASCII(value)
	}
	lower := bytes.ToLower(value)
	for _, prefix := range [][]byte{[]byte("ghp_"), []byte("github_pat_"), []byte("xoxb-"), []byte("xoxp-"), []byte("xoxa-"), []byte("xoxr-"), []byte("sk-"), []byte("ya29.")} {
		for searchFrom := 0; searchFrom < len(lower); {
			relative := bytes.Index(lower[searchFrom:], prefix)
			if relative < 0 {
				break
			}
			start := searchFrom + relative
			end := start + len(prefix)
			for end < len(value) && credentialTokenByte(value[end]) {
				end++
			}
			if knownCredentialToken(string(value[start:end])) {
				return true
			}
			searchFrom = start + 1
		}
	}
	for index := 0; index+20 <= len(value); index++ {
		if strings.EqualFold(string(value[index:index+4]), "AKIA") && knownCredentialToken(string(value[index:index+20])) {
			return true
		}
	}
	return false
}

func knownCredentialTokenAnywhereASCII(value []byte) bool {
	// The result is whether ANY (token prefix, start) pair yields a known
	// credential token, so the pairs may be visited start-first. At a given
	// start only prefixes whose first byte equals the folded value[start] can
	// pass hasASCIIFoldPrefixBytes; see knownCredentialTokenASCIIPrefixesByFirstByte.
	for start := range value {
		first := lowerASCII(value[start])
		for _, prefix := range knownCredentialTokenASCIIPrefixesByFirstByte[first] {
			if !hasASCIIFoldPrefixBytes(value[start:], prefix) {
				continue
			}
			end := start + len(prefix)
			for end < len(value) && credentialTokenByte(value[end]) {
				end++
			}
			if knownCredentialToken(string(value[start:end])) {
				return true
			}
		}
		if first == knownCredentialAWSAccessKeyIDPrefix[0] && start+knownCredentialAWSAccessKeyIDLength <= len(value) &&
			hasASCIIFoldPrefixBytes(value[start:], knownCredentialAWSAccessKeyIDPrefix) &&
			knownCredentialToken(string(value[start:start+knownCredentialAWSAccessKeyIDLength])) {
			return true
		}
	}
	return false
}

// knownCredentialTokenASCIIPrefixes are the token families that
// knownCredentialTokenAnywhereASCII searches for at every byte position.
var knownCredentialTokenASCIIPrefixes = []string{"ghp_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "sk-", "ya29."}

const (
	knownCredentialAWSAccessKeyIDPrefix = "akia"
	knownCredentialAWSAccessKeyIDLength = 20
)

// knownCredentialTokenASCIIPrefixesByFirstByte partitions
// knownCredentialTokenASCIIPrefixes by first byte. hasASCIIFoldPrefixBytes
// requires lowerASCII(value[start]) to equal prefix[0], so a prefix in any other
// bucket can never pass at that start and skipping it cannot change the result.
// Every prefix must be non-empty and already lower case, or it could never be
// found by that comparison under its own bucket; package initialization refuses
// a roster that breaks either condition.
var knownCredentialTokenASCIIPrefixesByFirstByte = newKnownCredentialTokenASCIIPrefixIndex(knownCredentialTokenASCIIPrefixes)

func newKnownCredentialTokenASCIIPrefixIndex(prefixes []string) *[256][]string {
	index := &[256][]string{}
	for _, prefix := range prefixes {
		if prefix == "" || lowerASCII(prefix[0]) != prefix[0] {
			panic("known credential token prefix roster contains an empty or non-lower-case prefix")
		}
		index[prefix[0]] = append(index[prefix[0]], prefix)
	}
	return index
}

func bytesAreASCII(value []byte) bool {
	for _, item := range value {
		if item >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func hasASCIIFoldPrefixBytes(value []byte, prefix string) bool {
	if len(value) < len(prefix) {
		return false
	}
	for index := 0; index < len(prefix); index++ {
		if lowerASCII(value[index]) != prefix[index] {
			return false
		}
	}
	return true
}

func credentialTokenByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("._~+/=-", rune(value))
}

func rejectNonIntegerNumbers(raw []byte) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("missing JSON value")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	return rejectNonIntegerNumbersAfterStructuralValidation(raw)
}

func rejectNonIntegerNumbersAfterStructuralValidation(raw []byte) error {
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	return walkCandidateValue(value, false)
}

func walkCandidateValue(value interface{}, inspectKeys bool) error {
	type entry struct {
		value interface{}
		depth int
	}
	stack := []entry{{value: value, depth: 1}}
	nodes := 0
	for len(stack) != 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.depth > maxProviderJSONNestingDepth {
			return fmt.Errorf("candidate JSON value exceeds fixed nesting depth %d", maxProviderJSONNestingDepth)
		}
		nodes++
		if nodes > maxProviderJSONNodesPerValue {
			return fmt.Errorf("candidate JSON value exceeds fixed node limit %d", maxProviderJSONNodesPerValue)
		}
		switch typed := current.value.(type) {
		case map[string]interface{}:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for index := len(keys) - 1; index >= 0; index-- {
				key := keys[index]
				if inspectKeys {
					if credentialShapedValue(key) {
						return fmt.Errorf("candidate plan carries credential or secret material in an object key")
					}
					canonicalKey := canonicalSensitiveKey(key)
					switch {
					case canonicalKey == "organizationid":
						return fmt.Errorf("candidate plan must not carry organization_id")
					case credentialShapedKey(canonicalKey):
						return fmt.Errorf("candidate plan carries forbidden credential field %q", key)
					}
				}
				stack = append(stack, entry{value: typed[key], depth: current.depth + 1})
			}
		case []interface{}:
			for index := len(typed) - 1; index >= 0; index-- {
				stack = append(stack, entry{value: typed[index], depth: current.depth + 1})
			}
		case json.Number:
			if _, ok := new(big.Int).SetString(string(typed), 10); !ok {
				return fmt.Errorf("binary-float-shaped JSON number %q is forbidden in candidate facts", typed)
			}
		case string:
			if inspectKeys && credentialShapedValue(typed) {
				return fmt.Errorf("candidate plan carries forbidden credential-shaped value")
			}
		}
	}
	return nil
}

func canonicalSensitiveKey(value string) string {
	var out strings.Builder
	for _, char := range strings.ToLower(value) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			out.WriteRune(char)
		}
	}
	return out.String()
}

func credentialShapedKey(canonicalKey string) bool {
	switch canonicalKey {
	case "authorization", "authorizationcredential", "authorizationvalue",
		"credential", "credentials", "credentialmaterial", "credentialvalue",
		"secret", "secretbytes", "secretvalue",
		"accesstoken", "refreshtoken", "clientsecret", "apikey", "bearertoken",
		"password", "oauthtoken", "authtoken", "privatekey", "serviceaccountkey",
		"secretaccesskey", "secretkey", "signingsecret", "webhooksecret",
		"consumersecret", "verificationtoken", "apitoken", "passphrase":
		return true
	}
	// "token" is an API-data vocabulary, not a secret type. SyncToken,
	// page_token, continuation_token, and similar provider fields are ordinary
	// source facts. Only closed, unambiguous credential/secret suffixes inherit
	// credential context; token-bearing secret carriers are enumerated above.
	for _, suffix := range []string{
		"accesstoken", "refreshtoken", "clientsecret", "apikey", "bearertoken", "password",
		"oauthtoken", "authtoken", "privatekey", "serviceaccountkey", "secretaccesskey",
		"secretkey", "signingsecret", "webhooksecret", "consumersecret", "verificationtoken",
		"apitoken", "authorizationvalue", "authorizationcredential", "passphrase",
		"credential", "credentials", "credentialvalue", "secret", "secretvalue",
	} {
		if strings.HasSuffix(canonicalKey, suffix) {
			return true
		}
	}
	return false
}

func credentialShapedValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	asciiOnly := stringIsASCII(trimmed)
	if strings.Contains(trimmed, "-----BEGIN PRIVATE KEY-----") ||
		strings.Contains(trimmed, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.Contains(trimmed, "-----BEGIN EC PRIVATE KEY-----") ||
		strings.Contains(trimmed, "-----BEGIN OPENSSH PRIVATE KEY-----") ||
		strings.Contains(trimmed, "-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
		(strings.Contains(trimmed, "eyJ") && jwtPattern.MatchString(trimmed)) {
		return true
	}
	if !asciiOnly || containsAuthorizationCredentialNameASCII(trimmed) {
		for _, match := range authorizationCredentialPattern.FindAllStringSubmatch(trimmed, -1) {
			if len(match) == 2 && credentialAssignmentValue(match[1]) {
				return true
			}
		}
	}
	if knownCredentialToken(trimmed) {
		return true
	}
	if !asciiOnly || containsCredentialAssignmentNameASCII(trimmed) {
		for _, match := range credentialAssignmentPattern.FindAllStringSubmatch(trimmed, -1) {
			if len(match) == 2 && credentialAssignmentValue(match[1]) {
				return true
			}
		}
	}
	return false
}

func stringIsASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func containsAuthorizationCredentialNameASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		switch lowerASCII(value[index]) {
		case 'b':
			if hasASCIIFoldPrefix(value[index:], "bearer") || hasASCIIFoldPrefix(value[index:], "basic") {
				return true
			}
		}
	}
	return false
}

func containsCredentialAssignmentNameASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		remainder := value[index:]
		switch lowerASCII(value[index]) {
		case 'a':
			if hasOptionalSeparatorCredentialNameASCII(remainder, "access", "token") ||
				hasOptionalSeparatorCredentialNameASCII(remainder, "api", "key") ||
				hasOptionalSeparatorCredentialNameASCII(remainder, "aws", "secret", "access", "key") {
				return true
			}
		case 'b':
			if hasOptionalSeparatorCredentialNameASCII(remainder, "bearer", "token") {
				return true
			}
		case 'c':
			if hasOptionalSeparatorCredentialNameASCII(remainder, "client", "secret") ||
				hasOptionalSeparatorCredentialNameASCII(remainder, "consumer", "secret") {
				return true
			}
		case 'p':
			if hasASCIIFoldPrefix(remainder, "password") {
				return true
			}
		case 'r':
			if hasOptionalSeparatorCredentialNameASCII(remainder, "refresh", "token") {
				return true
			}
		case 's':
			if hasOptionalSeparatorCredentialNameASCII(remainder, "signing", "secret") {
				return true
			}
		case 'v':
			if hasOptionalSeparatorCredentialNameASCII(remainder, "verification", "token") {
				return true
			}
		case 'w':
			if hasOptionalSeparatorCredentialNameASCII(remainder, "webhook", "secret") {
				return true
			}
		}
	}
	return false
}

func hasOptionalSeparatorCredentialNameASCII(value string, parts ...string) bool {
	offset := 0
	for index, part := range parts {
		if !hasASCIIFoldPrefix(value[offset:], part) {
			return false
		}
		offset += len(part)
		if index+1 < len(parts) && offset < len(value) && (value[offset] == ' ' || value[offset] == '_' || value[offset] == '-') {
			offset++
		}
	}
	return true
}

func hasASCIIFoldPrefix(value, prefix string) bool {
	if len(value) < len(prefix) {
		return false
	}
	for index := 0; index < len(prefix); index++ {
		if lowerASCII(value[index]) != prefix[index] {
			return false
		}
	}
	return true
}

func lowerASCII(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

func knownCredentialToken(value string) bool {
	if stringIsASCII(value) {
		for _, prefix := range []string{"ghp_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "sk-", "ya29."} {
			if hasASCIIFoldPrefix(value, prefix) && credentialAssignmentValue(value[len(prefix):]) {
				return true
			}
		}
		if len(value) == 20 && hasASCIIFoldPrefix(value, "akia") {
			return credentialAssignmentValue(value[4:])
		}
		return false
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"ghp_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "sk-", "ya29."} {
		if strings.HasPrefix(lower, prefix) && credentialAssignmentValue(value[len(prefix):]) {
			return true
		}
	}
	if strings.HasPrefix(strings.ToUpper(value), "AKIA") && len(value) == 20 {
		return credentialAssignmentValue(value[4:])
	}
	return false
}

func credentialAssignmentValue(value string) bool {
	value = strings.TrimSpace(value)
	if exactCredentialPlaceholder(value) {
		return false
	}
	if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
		value = value[1 : len(value)-1]
	}
	if len(value) < 16 {
		return false
	}
	distinct := map[rune]struct{}{}
	hasLetter := false
	hasDigit := false
	hasSpecial := false
	for _, char := range value {
		distinct[char] = struct{}{}
		switch {
		case char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z':
			hasLetter = true
		case char >= '0' && char <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	return hasLetter && len(distinct) >= 8 && (hasDigit || hasSpecial || len(value) >= 24)
}

// exactCredentialPlaceholder permits only a complete, closed placeholder
// token. Documentation words embedded inside an otherwise credential-shaped
// value are never an exemption.
func exactCredentialPlaceholder(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
		value = value[1 : len(value)-1]
	}
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	inner := value
	switch {
	case strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}"):
		inner = value[2 : len(value)-1]
	case strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}"):
		inner = value[2 : len(value)-2]
	case (strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">")) || (strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]")):
		inner = value[1 : len(value)-1]
	}
	if inner == "" || strings.TrimSpace(inner) != inner {
		return false
	}
	if inner == value {
		lower := strings.ToLower(inner)
		for _, prefix := range []string{"ghp_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "sk-", "ya29."} {
			if strings.HasPrefix(lower, prefix) {
				return exactCredentialPlaceholder(inner[len(prefix):])
			}
		}
	}
	for _, char := range inner {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.') {
			return false
		}
	}
	canonical := canonicalSensitiveKey(inner)
	switch canonical {
	case "placeholder", "documentationplaceholder", "redacted", "omitted", "masked", "notprovided", "notapplicable", "unavailable", "exampleonly", "sampleonly", "vaultbinding", "connectorvaultbinding", "connectorvaultreference":
		return true
	}
	if strings.HasPrefix(canonical, "your") && credentialShapedKey(strings.TrimPrefix(canonical, "your")) {
		return true
	}
	if strings.HasSuffix(canonical, "placeholder") && credentialShapedKey(strings.TrimSuffix(canonical, "placeholder")) {
		return true
	}
	if inner != value && credentialShapedKey(canonical) {
		return true
	}
	return false
}

func rejectDuplicateJSONKeys(raw []byte) error {
	_, err := validateProviderJSONStructure(raw)
	return err
}

func rejectInvalidJSONUnicodeScalars(raw []byte) error {
	for index := 0; index < len(raw); index++ {
		if raw[index] != '"' {
			continue
		}
		for index++; index < len(raw); index++ {
			switch raw[index] {
			case '"':
				goto nextToken
			case '\\':
				if index+1 >= len(raw) {
					return fmt.Errorf("JSON string ends after an escape prefix")
				}
				if raw[index+1] != 'u' {
					index++
					continue
				}
				codeUnit, ok := decodeJSONHexCodeUnit(raw, index+2)
				if !ok {
					return fmt.Errorf("JSON string carries an incomplete Unicode escape")
				}
				index += 5
				switch {
				case codeUnit >= 0xd800 && codeUnit <= 0xdbff:
					if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
						return fmt.Errorf("JSON string carries an unpaired high surrogate U+%04X", codeUnit)
					}
					low, ok := decodeJSONHexCodeUnit(raw, index+3)
					if !ok || low < 0xdc00 || low > 0xdfff {
						return fmt.Errorf("JSON string carries an unpaired high surrogate U+%04X", codeUnit)
					}
					index += 6
				case codeUnit >= 0xdc00 && codeUnit <= 0xdfff:
					return fmt.Errorf("JSON string carries an unpaired low surrogate U+%04X", codeUnit)
				}
			}
		}
	nextToken:
	}
	return nil
}

func decodeJSONHexCodeUnit(raw []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, char := range raw[start : start+4] {
		value <<= 4
		switch {
		case char >= '0' && char <= '9':
			value += uint16(char - '0')
		case char >= 'a' && char <= 'f':
			value += uint16(char-'a') + 10
		case char >= 'A' && char <= 'F':
			value += uint16(char-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func strictUnmarshal(raw []byte, destination interface{}) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON token %v", token)
		}
		return err
	}
	return nil
}

func requireValidUTF8(label string, raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("%s contains invalid UTF-8", label)
	}
	return nil
}

func requireObjectKeys(raw []byte, required ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return fmt.Errorf("required field %q is absent", key)
		}
	}
	return nil
}

func requireNestedObjectExactKeys(raw []byte, field string, required ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	nestedRaw, ok := object[field]
	if !ok {
		return fmt.Errorf("required field %q is absent", field)
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(nestedRaw, &nested); err != nil {
		return fmt.Errorf("field %q must be an object: %w", field, err)
	}
	if len(nested) != len(required) {
		return fmt.Errorf("field %q has %d members, want exactly %d", field, len(nested), len(required))
	}
	for _, key := range required {
		if _, ok := nested[key]; !ok {
			return fmt.Errorf("field %q required member %q is absent", field, key)
		}
	}
	return nil
}

func addUniqueID(ids map[string]string, id, kind string) error {
	if id == "" {
		return fmt.Errorf("%s row has an empty candidate id", kind)
	}
	if prior, exists := ids[id]; exists {
		return fmt.Errorf("candidate id %s is duplicated by %s and %s", id, prior, kind)
	}
	ids[id] = kind
	return nil
}

func stableID(prefix, semanticKey string) string {
	digest := sha256.Sum256([]byte(semanticKey))
	return prefix + "_" + hex.EncodeToString(digest[:16])
}

func sha256Hex(raw []byte) string { digest := sha256.Sum256(raw); return hex.EncodeToString(digest[:]) }

func isLowerSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sortedSetKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedConstraintKeys(values map[string]relationshipConstraint) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func constraintsToSet(values map[string]relationshipConstraint) map[string]struct{} {
	out := map[string]struct{}{}
	for value := range values {
		out[value] = struct{}{}
	}
	return out
}

func requireExactSet(name string, actual, expected map[string]struct{}) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("%s count %d does not equal OOD count %d", name, len(actual), len(expected))
	}
	for _, value := range sortedSetKeys(expected) {
		if _, ok := actual[value]; !ok {
			return fmt.Errorf("%s is missing %q", name, value)
		}
	}
	return nil
}

func requireSetWithExplicitGaps(name string, actual map[string]struct{}, gaps []string, expected map[string]struct{}) error {
	combined := map[string]struct{}{}
	for value := range actual {
		combined[value] = struct{}{}
	}
	for _, value := range gaps {
		if _, exists := combined[value]; exists {
			return fmt.Errorf("%s %q is both materialized and intentionally gapped", name, value)
		}
		combined[value] = struct{}{}
	}
	return requireExactSet(name, combined, expected)
}
