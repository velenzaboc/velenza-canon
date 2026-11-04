// Package oodapi owns the reusable final API materialization validator.
//
// It deliberately accepts only opaque closure and roster proofs plus physical
// rows.  It has no source-package, callback, Spanner, or boot dependency.
package oodapi

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

type FactoryOutput struct {
	LocatorProofs         []oodevidence.VerifiedLocatorV8
	RoleProofs            []oodevidence.VerifiedAPIElementRoleV8
	EvidenceLocatorProofs []oodevidence.VerifiedGraphFactLocatorV8
	Plan                  oodpublication.SpannerWritePlan
}

type RelationshipContract struct{ SourceRole, TargetRole string }

var relationshipContracts = map[string]RelationshipContract{
	"provider_has_service": {"provider", "service"}, "service_has_api": {"service", "vendor_api"}, "api_has_resource": {"vendor_api", "resource"}, "resource_has_operation": {"resource", "operation"}, "provider_supports_auth_scheme": {"provider", "auth_scheme"}, "api_has_operation": {"vendor_api", "operation"}, "operation_reads_resource": {"operation", "resource"}, "operation_writes_resource": {"operation", "resource"}, "operation_requires_auth_scheme": {"operation", "auth_scheme"}, "operation_emits_webhook_event": {"operation", "webhook_event"}, "operation_uses_schema": {"operation", "schema_element"}, "operation_returns_error_shape": {"operation", "error_shape"}, "operation_has_rate_limit_rule": {"operation", "rate_limit_rule"}, "operation_uses_pagination_shape": {"operation", "pagination_shape"}, "operation_uses_request_response_envelope_shape": {"operation", "request_response_envelope_shape"}, "resource_uses_lifecycle_shape": {"resource", "lifecycle_shape"}, "operation_uses_concurrency_and_idempotency_shape": {"operation", "concurrency_and_idempotency_shape"}, "resource_has_polling_cdc_and_reconciliation_shape": {"resource", "polling_cdc_and_reconciliation_shape"}, "schema_uses_exact_numeric_identifier_timestamp_currency_and_string_encoded_numeric_shape": {"schema_element", "exact_value_shape"}, "schema_uses_reference_and_discriminated_union_shape": {"schema_element", "reference_and_discriminated_union_shape"}, "operation_uses_batch_and_partial_success_shape": {"operation", "batch_and_partial_success_shape"},
}

func RelationshipContracts() map[string]RelationshipContract {
	out := make(map[string]RelationshipContract, len(relationshipContracts))
	for k, v := range relationshipContracts {
		out[k] = v
	}
	return out
}
func RelationshipContractFor(label string) (RelationshipContract, bool) {
	x, ok := relationshipContracts[label]
	return x, ok
}

var sha256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidateRole(role, locatorManifestHash string) error {
	found := false
	for _, c := range relationshipContracts {
		found = found || c.SourceRole == role || c.TargetRole == role
	}
	if !found {
		return fmt.Errorf("api_symbol api_element_role %q is not in the OOD role registry", role)
	}
	if !sha256.MatchString(locatorManifestHash) {
		return errors.New("api_symbol api_element_role_locator_manifest_hash must be lowercase SHA-256")
	}
	return nil
}

// ValidateMaterialization is the one final proof boundary shared by service
// boot and protected source-package construction. It performs no mutation.
func ValidateMaterialization(proof oodevidence.VerifiedClosureV8, roster oodevidence.VerifiedPublicationRosterV8, in FactoryOutput) error {
	if err := oodevidence.ValidateVerifiedClosureV8(proof); err != nil {
		return fmt.Errorf("verified closure required: %w", err)
	}
	if err := oodevidence.ValidateVerifiedPublicationRosterV8(roster); err != nil {
		return err
	}
	if roster.OrganizationID() != proof.OrganizationID() || roster.ClosureHash() != proof.ClosureHash() {
		return errors.New("publication roster does not bind verified closure")
	}
	if in.Plan.OrganizationID != proof.OrganizationID() || in.Plan.ClosureHash != proof.ClosureHash() {
		return errors.New("write plan does not bind verified closure")
	}
	if err := verifyFactoryOutput(proof, in); err != nil {
		return err
	}
	rows, err := oodpublication.CanonicalImmutableRosterBytes(in.Plan.ImmutableRows)
	if err != nil {
		return err
	}
	if !roster.MatchesCanonicalRows(rows) {
		return errors.New("write plan immutable roster differs from protected complete roster")
	}
	return nil
}

type object struct{ id, class, role, root, authority, refKind, stable, version, section string }
type edge struct{ id, source, target, label, family string }

func str(r oodpublication.SpannerRow, n string) string { v, _ := r.Columns[n].(string); return v }
func nullable(r oodpublication.SpannerRow, n string) string {
	if r.Columns[n] == nil {
		return ""
	}
	return str(r, n)
}
func coordinate(r oodpublication.SpannerRow) oodevidence.APIElementSourceCoordinate {
	return oodevidence.APIElementSourceCoordinate{ObjectClass: str(r, "object_class"), AuthorityID: str(r, "source_authority_id"), RefKind: str(r, "source_ref_kind"), StableReference: str(r, "source_stable_reference"), VersionCoordinate: str(r, "version_coordinate"), SectionPath: str(r, "section_path")}
}

func contentTripleMatches(row oodpublication.SpannerRow, algorithm, profile, hash string) bool {
	return str(row, "source_content_hash_algorithm") == algorithm && str(row, "source_content_hash_profile") == profile && str(row, "source_content_hash") == hash
}

func derive(proof oodevidence.VerifiedClosureV8, rows []oodpublication.SpannerRow) (map[string]object, []edge, error) {
	objects := map[string]object{}
	edges := []edge{}
	required := map[string]bool{"OODGraphObjects": false, "OODGraphSymbols": false, "OODGraphEdges": false, "OODGraphGraphFactEvidenceLocators": false, "OODGraphManifestNodes": false, "OODGraphManifestEntries": false, "OODGraphClosureVerificationCertificates": false}
	for _, row := range rows {
		if str(row, "organization_id") != proof.OrganizationID() {
			return nil, nil, errors.New("cross-organization immutable publication row")
		}
		if _, ok := required[row.Table]; ok {
			required[row.Table] = true
		}
		switch row.Table {
		case "OODGraphObjects":
			x := object{id: str(row, "graph_object_id"), class: str(row, "object_class"), role: nullable(row, "api_element_role"), root: nullable(row, "api_element_role_locator_manifest_hash"), authority: str(row, "source_authority_id"), refKind: str(row, "source_ref_kind"), stable: str(row, "source_stable_reference"), version: str(row, "version_coordinate"), section: str(row, "section_path")}
			if x.class != "api_symbol" {
				continue
			}
			if err := ValidateRole(x.role, x.root); err != nil {
				return nil, nil, err
			}
			if _, dup := objects[x.id]; dup {
				return nil, nil, errors.New("duplicate API object physical row")
			}
			objects[x.id] = x
		case "OODGraphEdges":
			x := edge{id: str(row, "graph_edge_id"), source: str(row, "source_endpoint_id"), target: str(row, "target_endpoint_id"), label: str(row, "edge_label"), family: str(row, "edge_family")}
			if x.family == "api_relationship" {
				edges = append(edges, x)
			}
		}
	}
	for table, found := range required {
		if !found {
			return nil, nil, fmt.Errorf("native API publication misses required immutable %s row", table)
		}
	}
	if len(objects) == 0 {
		return nil, nil, errors.New("API physical roster has no typed objects")
	}
	return objects, edges, nil
}

func verifyFactoryOutput(proof oodevidence.VerifiedClosureV8, in FactoryOutput) error {
	if len(in.LocatorProofs) == 0 && len(in.RoleProofs) == 0 {
		return errors.New("API factory output has incomplete role, relationship, or locator roster")
	}
	objects, edges, err := derive(proof, in.Plan.ImmutableRows)
	if err != nil {
		return err
	}
	physicalObjects := map[string]oodpublication.SpannerRow{}
	physicalEdges := map[string]oodpublication.SpannerRow{}
	relationships := map[string]oodpublication.SpannerRow{}
	physicalLocators := map[string]bool{}
	locatorRows := map[string]oodpublication.SpannerRow{}
	for _, row := range in.Plan.ImmutableRows {
		switch row.Table {
		case "OODGraphObjects":
			physicalObjects[str(row, "graph_object_id")] = row
		case "OODGraphEdges":
			physicalEdges[str(row, "graph_edge_id")] = row
		case "OODGraphRelationshipEvidence":
			relationships[str(row, "relationship_evidence_hash")] = row
		case "OODGraphGraphFactEvidenceLocators":
			physicalLocators[str(row, "graph_fact_locator_hash")] = true
			locatorRows[str(row, "graph_fact_locator_hash")] = row
		}
	}
	verifiedEvidence := map[string]bool{}
	for _, p := range in.EvidenceLocatorProofs {
		if err := oodevidence.ValidateVerifiedGraphFactLocatorV8(p); err != nil {
			return err
		}
		if p.OrganizationID() != proof.OrganizationID() || !physicalLocators[p.LocatorHash()] || verifiedEvidence[p.LocatorHash()] {
			return errors.New("graph-fact byte proof is duplicate or outside the physical closure")
		}
		verifiedEvidence[p.LocatorHash()] = true
	}
	byRelationship := map[string][]oodevidence.VerifiedLocatorV8{}
	byRole := map[oodevidence.APIElementSourceCoordinate][]oodevidence.VerifiedAPIElementRoleV8{}
	proofKeys := map[string]bool{}
	for _, p := range in.LocatorProofs {
		if err := oodevidence.ValidateVerifiedAPIRoleLocatorV8(p); err != nil {
			return err
		}
		if p.OrganizationID() != proof.OrganizationID() {
			return errors.New("locator proof organization mismatch")
		}
		key := p.RelationshipHash() + "/" + p.EvidenceLocatorHash()
		if proofKeys[key] || !physicalLocators[p.EvidenceLocatorHash()] {
			return errors.New("relationship byte proof is duplicate or outside the physical closure")
		}
		proofKeys[key] = true
		r, ok := relationships[p.RelationshipHash()]
		if !ok || str(r, "graph_fact_locator_manifest_hash") != p.LocatorHash() || str(r, "edge_label") != p.EdgeLabel() {
			return errors.New("relationship proof is not bound to a physical relationship")
		}
		members, e := oodpublication.ResolveGraphFactLocatorManifestMembers(in.Plan.ImmutableRows, proof.OrganizationID(), p.LocatorHash())
		if e != nil {
			return e
		}
		found := false
		for _, hash := range members {
			found = found || hash == p.EvidenceLocatorHash()
		}
		if !found {
			return errors.New("relationship byte proof is not a member of its claim manifest")
		}
		verifiedEvidence[p.EvidenceLocatorHash()] = true
		byRelationship[p.RelationshipHash()] = append(byRelationship[p.RelationshipHash()], p)
	}
	type roleProofKey struct {
		coordinate oodevidence.APIElementSourceCoordinate
		binding    oodevidence.APIElementRoleBinding
		locator    string
	}
	roleProofKeys := map[roleProofKey]bool{}
	for _, p := range in.RoleProofs {
		if err := oodevidence.ValidateVerifiedAPIElementRoleV8(p); err != nil {
			return err
		}
		if p.OrganizationID() != proof.OrganizationID() || !physicalLocators[p.EvidenceLocatorHash()] {
			return errors.New("API element role proof is outside the physical closure")
		}
		key := roleProofKey{coordinate: p.SourceCoordinate(), binding: p.RoleBinding(), locator: p.EvidenceLocatorHash()}
		if roleProofKeys[key] {
			return errors.New("duplicate API element role proof")
		}
		roleProofKeys[key] = true
		members, e := oodpublication.ResolveGraphFactLocatorManifestMembers(in.Plan.ImmutableRows, proof.OrganizationID(), p.LocatorHash())
		if e != nil {
			return e
		}
		found := false
		for _, hash := range members {
			found = found || hash == p.EvidenceLocatorHash()
		}
		if !found {
			return errors.New("API element role primary locator is not a member of its claim manifest")
		}
		verifiedEvidence[p.EvidenceLocatorHash()] = true
		byRole[p.SourceCoordinate()] = append(byRole[p.SourceCoordinate()], p)
	}
	for hash := range physicalLocators {
		if !verifiedEvidence[hash] {
			return errors.New("physical graph-fact locator lacks a verified archived-byte proof")
		}
	}
	for _, x := range objects {
		row := physicalObjects[x.id]
		binding := oodevidence.APIElementRoleBinding{Role: x.role, LocatorManifestHash: x.root}
		if _, e := oodpublication.ResolveGraphFactLocatorManifestMembers(in.Plan.ImmutableRows, proof.OrganizationID(), binding.LocatorManifestHash); e != nil {
			return e
		}
		coord := coordinate(row)
		matched := false
		for _, p := range in.LocatorProofs {
			matched = matched || (((p.SourceCoordinate() == coord && p.SourceRoleBinding() == binding) || (p.TargetCoordinate() == coord && p.TargetRoleBinding() == binding)) && roleManifestBindsObjectContent(in.Plan.ImmutableRows, proof.OrganizationID(), binding.LocatorManifestHash, row, locatorRows))
		}
		for _, p := range byRole[coord] {
			matched = matched || (p.RoleBinding() == binding && contentTripleMatches(row, p.SourceContentHashAlgorithm(), p.SourceContentHashProfile(), p.SourceContentHash()))
		}
		if !matched {
			return errors.New("API role lacks matching verified locator")
		}
		if !hasVerifiedDocumentsProvenance(in.Plan.ImmutableRows, proof.OrganizationID(), row, physicalObjects, physicalEdges, relationships, locatorRows, verifiedEvidence) {
			return errors.New("API symbol lacks verified provider documentation provenance")
		}
	}
	for _, x := range edges {
		source, sok := objects[x.source]
		target, tok := objects[x.target]
		if !sok || !tok {
			return errors.New("API relationship lacks verified API endpoints")
		}
		contract, ok := RelationshipContractFor(x.label)
		if !ok || source.role != contract.SourceRole || target.role != contract.TargetRole {
			return errors.New("API relationship role contract mismatch")
		}
		sourceRow, targetRow := physicalObjects[source.id], physicalObjects[target.id]
		sourceCoord, targetCoord := coordinate(sourceRow), coordinate(targetRow)
		sb := oodevidence.APIElementRoleBinding{Role: source.role, LocatorManifestHash: source.root}
		tb := oodevidence.APIElementRoleBinding{Role: target.role, LocatorManifestHash: target.root}
		edgeRow := physicalEdges[x.id]
		matched := false
		for hash, r := range relationships {
			if str(r, "edge_label") != x.label || str(r, "authoring_source_path") != str(edgeRow, "authoring_source_path") || str(r, "evidence_authority_id") != str(edgeRow, "source_authority_id") || str(r, "evidence_stable_reference") != str(edgeRow, "source_stable_reference") || str(r, "evidence_content_hash") != str(edgeRow, "source_content_hash") {
				continue
			}
			for _, p := range byRelationship[hash] {
				matched = matched || (p.SourceCoordinate() == sourceCoord && p.TargetCoordinate() == targetCoord && p.SourceRoleBinding() == sb && p.TargetRoleBinding() == tb)
			}
		}
		if !matched {
			return errors.New("API relationship locator is not verified for both endpoints")
		}
	}
	return nil
}

// roleManifestBindsObjectContent prevents source-body substitution through a
// stable source coordinate. The claim root must contain a physical locator
// whose qualified content triple exactly equals the immutable object row.
func roleManifestBindsObjectContent(rows []oodpublication.SpannerRow, organizationID, root string, object oodpublication.SpannerRow, locators map[string]oodpublication.SpannerRow) bool {
	members, err := oodpublication.ResolveGraphFactLocatorManifestMembers(rows, organizationID, root)
	if err != nil {
		return false
	}
	for _, hash := range members {
		if locator, ok := locators[hash]; ok && contentTripleMatches(locator, str(object, "source_content_hash_algorithm"), str(object, "source_content_hash_profile"), str(object, "source_content_hash")) {
			return true
		}
	}
	return false
}

// hasVerifiedDocumentsProvenance keeps documentation provenance separate from
// API-role classification. Every provider-derived API symbol must be the
// target of a typed documents relationship from an immutable external document
// object. Its external-document evidence must match both endpoints and bind a
// nonempty, fully byte-verified claim manifest in the same snapshot.
func hasVerifiedDocumentsProvenance(rows []oodpublication.SpannerRow, organizationID string, api oodpublication.SpannerRow, objects, edges, relationships, locators map[string]oodpublication.SpannerRow, verifiedEvidence map[string]bool) bool {
	apiID := str(api, "graph_object_id")
	for _, edge := range edges {
		if str(edge, "edge_label") != "documents" || str(edge, "edge_family") != "external_reference" || str(edge, "target_endpoint_id") != apiID || str(edge, "target_endpoint_class") != "api_symbol" {
			continue
		}
		source, ok := objects[str(edge, "source_endpoint_id")]
		if !ok || (str(source, "object_class") != "external_reference_doc" && str(source, "object_class") != "reference_page") || str(edge, "source_endpoint_class") != str(source, "object_class") {
			continue
		}
		for _, evidence := range relationships {
			if !documentsEvidenceMatchesEdge(evidence, edge, source, api) {
				continue
			}
			root := str(evidence, "graph_fact_locator_manifest_hash")
			if root == "" {
				continue
			}
			members, err := oodpublication.ResolveGraphFactLocatorManifestMembers(rows, organizationID, root)
			if err != nil || len(members) == 0 {
				continue
			}
			allVerified := true
			for _, hash := range members {
				if _, physical := locators[hash]; !physical || !verifiedEvidence[hash] {
					allVerified = false
					break
				}
			}
			if allVerified {
				return true
			}
		}
	}
	return false
}

func documentsEvidenceMatchesEdge(evidence, edge, source, target oodpublication.SpannerRow) bool {
	if str(evidence, "evidence_source_kind") != "external_document_evidence" || str(evidence, "edge_label") != "documents" || str(evidence, "authoring_source_path") != str(edge, "authoring_source_path") {
		return false
	}
	if !relationshipEndpointMatches(evidence, "source", source) || !relationshipEndpointMatches(evidence, "target", target) {
		return false
	}
	return str(edge, "source_authority_id") == str(source, "source_authority_id") &&
		str(edge, "source_stable_reference") == str(source, "source_stable_reference") &&
		contentTripleMatches(source, str(edge, "source_content_hash_algorithm"), str(edge, "source_content_hash_profile"), str(edge, "source_content_hash")) &&
		str(evidence, "evidence_authority_id") == str(edge, "source_authority_id") &&
		str(evidence, "evidence_stable_reference") == str(edge, "source_stable_reference") &&
		str(evidence, "evidence_version_coordinate") == str(source, "version_coordinate") &&
		contentTripleMatches(edge, str(evidence, "evidence_content_hash_algorithm"), str(evidence, "evidence_content_hash_profile"), str(evidence, "evidence_content_hash"))
}

func relationshipEndpointMatches(evidence oodpublication.SpannerRow, prefix string, endpoint oodpublication.SpannerRow) bool {
	return str(evidence, prefix+"_object_class") == str(endpoint, "object_class") &&
		str(evidence, prefix+"_authority_id") == str(endpoint, "source_authority_id") &&
		str(evidence, prefix+"_ref_kind") == str(endpoint, "source_ref_kind") &&
		str(evidence, prefix+"_stable_reference") == str(endpoint, "source_stable_reference") &&
		str(evidence, prefix+"_version_coordinate") == str(endpoint, "version_coordinate") &&
		str(evidence, prefix+"_section_path") == str(endpoint, "section_path")
}
