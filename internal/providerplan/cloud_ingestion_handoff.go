package providerplan

// The ingestion handoff is an offline candidate contract. It neither creates a
// source instance nor authorizes a collection, mutation, deletion, admission,
// or a semantic identity.

import (
	"bytes"
	"fmt"
	"os"
	"sort"
)

const cloudIngestionHandoffVersion = "1"

const (
	cloudSourceRecord17OwnerRef = "2853c68f-eae2-4a5c-a62d-e08a646f4f84#sections.s2_source_instance_and_stable_source_coordinate"
	cloudSourceRecord17SHA256   = "f4e0337dd23707a5f157a3ed3e20d43bfc1bc7cdbd960e130fc62fd50dba8273"
)

type CloudIngestionHandoffPolicy struct {
	PolicyID                 string   `json:"policy_id"`
	Version                  string   `json:"version"`
	CandidateOnly            bool     `json:"candidate_only"`
	SourceRecordOwnerRef     string   `json:"source_record_owner_ref"`
	SourceRecordOwnerVersion string   `json:"source_record_owner_version"`
	SourceRecordOwnerSHA256  string   `json:"source_record_owner_sha256"`
	CoordinateComponents     []string `json:"coordinate_components"`
	NoDeletionOutcomes       []string `json:"no_deletion_outcomes"`
}

type CloudSourceCoordinateExtractor struct {
	OrganizationID        string                      `json:"organization_id"`
	SourceInstanceID      string                      `json:"source_instance_id"`
	SourceObjectType      string                      `json:"source_object_type"`
	VendorRecordIDField   string                      `json:"vendor_record_id_field"`
	VendorRecordIDPointer string                      `json:"vendor_record_id_pointer"`
	EvidenceLocator       CloudCatalogEvidenceLocator `json:"evidence_locator"`
	ExtractorKind         string                      `json:"extractor_kind"`
	RequestSchemaID       string                      `json:"request_schema_id,omitempty"`
}

type CloudIngestionHandoffTarget struct {
	ProviderID            string                         `json:"provider_id"`
	ServiceID             string                         `json:"service_id"`
	APISurfaceID          string                         `json:"api_surface_id"`
	OperationID           string                         `json:"operation_id"`
	ProfileRef            CloudProfileReference          `json:"profile_ref"`
	ServiceProfileRef     CloudProfileReference          `json:"service_profile_ref"`
	ProfileDocumentSHA256 string                         `json:"profile_document_sha256"`
	CatalogModelSHA256    string                         `json:"catalog_model_sha256"`
	Coordinate            CloudSourceCoordinateExtractor `json:"coordinate_extractor"`
}

type CloudIngestionTransition struct {
	Outcome                   string `json:"outcome"`
	GenerationDisposition     string `json:"generation_disposition"`
	CutoverDisposition        string `json:"cutover_disposition"`
	RollbackDisposition       string `json:"rollback_disposition"`
	ReconciliationDisposition string `json:"reconciliation_disposition"`
	DeletionAuthorized        bool   `json:"deletion_authorized"`
}

type CloudIngestionHandoff struct {
	Status      string                        `json:"status"`
	Policy      CloudIngestionHandoffPolicy   `json:"policy"`
	Targets     []CloudIngestionHandoffTarget `json:"targets"`
	Transitions []CloudIngestionTransition    `json:"transitions"`
	Scenarios   []CloudIngestionScenario      `json:"scenarios"`
	Document    []byte                        `json:"-"`
}

type CloudIngestionScenario struct {
	Scenario                  string   `json:"scenario"`
	OwnerContractRefs         []string `json:"owner_contract_refs"`
	PrerequisiteDisposition   string   `json:"prerequisite_disposition"`
	ReplayDisposition         string   `json:"replay_disposition"`
	CutoverDisposition        string   `json:"cutover_disposition"`
	RollbackDisposition       string   `json:"rollback_disposition"`
	ReconciliationDisposition string   `json:"reconciliation_disposition"`
	DeletionAuthorized        bool     `json:"deletion_authorized"`
}

func LoadCloudIngestionHandoffPolicy(path string) (CloudIngestionHandoffPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return CloudIngestionHandoffPolicy{}, err
	}
	var policy CloudIngestionHandoffPolicy
	if err := strictUnmarshal(raw, &policy); err != nil {
		return CloudIngestionHandoffPolicy{}, err
	}
	return policy, validateCloudIngestionHandoffPolicy(policy)
}

func validateCloudIngestionHandoffPolicy(p CloudIngestionHandoffPolicy) error {
	if p.PolicyID == "" || p.Version != cloudIngestionHandoffVersion || !p.CandidateOnly || p.SourceRecordOwnerRef != cloudSourceRecord17OwnerRef || p.SourceRecordOwnerVersion != "17" || p.SourceRecordOwnerSHA256 != cloudSourceRecord17SHA256 || !strictlyEqualStrings(p.CoordinateComponents, []string{"organization_id", "source_instance_id", "source_object_type", "vendor_record_id"}) || !strictlyEqualStrings(p.NoDeletionOutcomes, []string{"partial", "interrupted", "revoked", "complete"}) {
		return fmt.Errorf("invalid source-record handoff policy")
	}
	return nil
}

func strictlyEqualStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// BuildCloudIngestionHandoff derives one coordinate extractor for every selected
// provider/service/resource/operation. The two caller-provided identity values
// are intentionally symbolic requirements, never invented instance IDs.
func BuildCloudIngestionHandoff(request CloudSourceCandidateRequest, profiles CloudAPIProfileDocument, policy CloudIngestionHandoffPolicy) (CloudIngestionHandoff, error) {
	if err := validateCloudIngestionHandoffPolicy(policy); err != nil {
		return CloudIngestionHandoff{}, err
	}
	if err := ValidateCloudAPIProfileDocument(profiles, request.Catalogs, request.Targets); err != nil {
		return CloudIngestionHandoff{}, err
	}
	profileRaw, err := CanonicalCloudAPIProfileDocument(profiles)
	if err != nil {
		return CloudIngestionHandoff{}, err
	}
	profileSHA := sha256Hex(profileRaw)
	catalogs := map[string]CloudCatalog{}
	for _, c := range request.Catalogs {
		catalogs[cloudCatalogKey(c.ProviderID, c.ServiceID, c.APISurfaceID)] = c
	}
	services := map[string]CloudServiceAPIResidual{}
	for _, p := range profiles.Providers {
		for _, s := range p.Services {
			services[cloudCatalogKey(p.ProviderID, s.ServiceID, s.APISurfaceID)] = s
		}
	}
	targets := make([]CloudIngestionHandoffTarget, 0, len(request.Targets))
	for _, target := range request.Targets {
		key := cloudCatalogKey(target.ProviderID, target.ServiceID, target.APISurfaceID)
		catalog, ok := catalogs[key]
		if !ok {
			return CloudIngestionHandoff{}, fmt.Errorf("selected target has no catalog")
		}
		service := services[key]
		if err := ValidateCloudSourceIdentityContract(target, catalog); err != nil {
			return CloudIngestionHandoff{}, fmt.Errorf("target %q identity: %w", target.OperationID, err)
		}
		extractor, err := cloudIngestionCoordinateExtractor(target)
		if err != nil {
			return CloudIngestionHandoff{}, err
		}
		serviceRef := CloudProfileReference{ProviderID: target.ProviderID, ProfileID: service.ProfileID, ProfileVersion: service.ProfileVersion}
		targets = append(targets, CloudIngestionHandoffTarget{target.ProviderID, target.ServiceID, target.APISurfaceID, target.OperationID, service.ProviderProfileRef, serviceRef, profileSHA, catalog.ModelSHA256, extractor})
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].ProviderID+targets[i].OperationID < targets[j].ProviderID+targets[j].OperationID
	})
	transitions := []CloudIngestionTransition{}
	for _, outcome := range policy.NoDeletionOutcomes {
		transitions = append(transitions, CloudIngestionTransition{outcome, "no_active_generation_authority", "refuse_cutover", "retain_prior_authority_or_refuse", "require_owner_reconciliation", false})
	}
	scenarios := cloudIngestionScenarios()
	result := CloudIngestionHandoff{"candidate_ingestion_handoff_unqualified", policy, targets, transitions, scenarios, nil}
	raw, err := canonicalCloudIngestionHandoffDocument(result)
	if err != nil {
		return CloudIngestionHandoff{}, err
	}
	result.Document = raw
	return result, nil
}

func cloudIngestionCoordinateExtractor(target CloudSourceObjectTarget) (CloudSourceCoordinateExtractor, error) {
	base := CloudSourceCoordinateExtractor{OrganizationID: "required_external_organization_id", SourceInstanceID: "required_existing_source_instance_id", SourceObjectType: target.SourceObjectType}
	if request := target.RequestIdentity; request != nil {
		base.VendorRecordIDField, base.VendorRecordIDPointer, base.EvidenceLocator, base.ExtractorKind, base.RequestSchemaID = request.SourceFieldID, request.SourcePointer, request.Locator, "request_member", request.RequestSchemaID
		return base, nil
	}
	if len(target.StableIdentitySourceFields) != 1 {
		return CloudSourceCoordinateExtractor{}, fmt.Errorf("target %q must declare exactly one response identity extractor", target.OperationID)
	}
	field := target.StableIdentitySourceFields[0]
	for _, evidence := range target.StableIdentityEvidence {
		if evidence.SourceFieldID == field {
			contractField, found := cloudNeutralContractField(*target.MappingContract, field)
			if !found || contractField.SourcePointer == "" {
				return CloudSourceCoordinateExtractor{}, fmt.Errorf("target %q response identity has no source extraction pointer", target.OperationID)
			}
			base.VendorRecordIDField, base.VendorRecordIDPointer, base.EvidenceLocator, base.ExtractorKind = field, contractField.SourcePointer, evidence.Locator, "response_member"
			return base, nil
		}
	}
	return CloudSourceCoordinateExtractor{}, fmt.Errorf("target %q response identity lacks exact locator", target.OperationID)
}

func canonicalCloudIngestionHandoffDocument(h CloudIngestionHandoff) ([]byte, error) {
	raw, err := canonicalFactoryJSON(struct {
		Status      string                        `json:"status"`
		Policy      CloudIngestionHandoffPolicy   `json:"policy"`
		Targets     []CloudIngestionHandoffTarget `json:"targets"`
		Transitions []CloudIngestionTransition    `json:"transitions"`
		Scenarios   []CloudIngestionScenario      `json:"scenarios"`
	}{h.Status, h.Policy, h.Targets, h.Transitions, h.Scenarios})
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func cloudIngestionScenarios() []CloudIngestionScenario {
	refs := []string{"2853c68f-eae2-4a5c-a62d-e08a646f4f84#sections.s6_semantic_mapping_generation_identity_and_mapping_epoch", "2853c68f-eae2-4a5c-a62d-e08a646f4f84#sections.s8_semantic_materialization_and_active_generation", "2853c68f-eae2-4a5c-a62d-e08a646f4f84#sections.s15_rebuild_replay_catch_up_and_cutover", "2853c68f-eae2-4a5c-a62d-e08a646f4f84#sections.s17_operational_observability_reconciliation_and_backpressure"}
	return []CloudIngestionScenario{
		{"idempotent_replay", refs, "exact sealed generation+coordinate equality", "reuse exact immutable receipt only", "no new cutover", "not applicable", "reconcile mismatched receipt", false},
		{"stale_generation", refs, "current generation fence is required", "refuse stale replay", "refuse stale cutover", "new successor only", "reconcile against current owner head", false},
		{"complete_collection_only", refs, "complete collection alone is insufficient", "no authority inferred", "refuse pending owner fences+coverage+authorization", "new successor only", "require coverage and currentness reconciliation", false},
		{"cutover", refs, "complete coverage, quiescent catch-up, current fences, owner authorization and exact predecessor/successor pins", "no replay without exact receipt", "owner-defined atomic cutover only", "new successor only", "refuse mixed visibility; reconcile current head", false},
		{"rollback", refs, "new rebuild definition, coverage, current head, historical target and current authorization", "no historical permit reactivation", "new owner-defined successor transition only", "never mutate/revive revoked generation", "reconcile current lineage", false},
		{"unknown_or_interrupted_commit", refs, "commit state is uncertain", "refuse speculative replay", "refuse cutover until resolved", "do not delete failed target", "owner reconciliation required before retry", false},
	}
}

func ValidateCloudIngestionHandoff(h CloudIngestionHandoff, request CloudSourceCandidateRequest, profiles CloudAPIProfileDocument) error {
	provided, err := canonicalCloudIngestionHandoffDocument(h)
	if err != nil {
		return err
	}
	if !bytes.Equal(provided, h.Document) {
		return fmt.Errorf("ingestion handoff public projection does not bind its document")
	}
	expected, err := BuildCloudIngestionHandoff(request, profiles, h.Policy)
	if err != nil {
		return err
	}
	if string(expected.Document) != string(h.Document) {
		return fmt.Errorf("ingestion handoff differs from exact selected source closure")
	}
	return nil
}
