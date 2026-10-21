package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// violations.go gives OODGraphViolations a producer.
//
// Until now the table had none: writeViolationInTx existed and was wired
// into CommitMaterializationRun, but MaterializationBatch.Violations was
// never populated by any caller, so the helper was dead and the table was
// permanently empty. The consequence is not cosmetic. Under
// §8.violation_emission.emission_rule — "Every rejected materialization
// fact emits one graph-owned violation record" — a violation IS the
// mechanism by which a rejection becomes queryable evidence. With no
// producer, every rejection was silent: a refused edge, a bad class or an
// unresolved endpoint left the substrate looking exactly like a corpus that
// had never contained the fact at all.
//
// Pairs with the run-lifecycle fix in ood_substrate.go. Together they close
// the blindness: OpenMaterializationRun records THAT an attempt happened,
// violations record WHAT it refused.

// Violation codes from §8.validation_gates_before_projection.*.violation_code
// and §8.unresolved_endpoint_handling.materialization_behavior. Declared as
// constants so a raise site cannot invent an unregistered code by typo — the
// code is the join key an operator queries the table by.
const (
	ViolationObjectClassNotInClosedSet    = "object_class_not_in_closed_set"
	ViolationEdgeLabelNotInClosedSet      = "edge_label_not_in_closed_set"
	ViolationEndpointReferenceUnresolved  = "endpoint_reference_unresolved_or_wrong_key"
	ViolationEndpointClassPairForbidden   = "endpoint_class_pair_forbidden"
	ViolationPropertyOrSearchPayloadLeak  = "property_or_search_payload_leak"
	ViolationContentHashBindingInvalid    = "content_hash_binding_invalid"
	ViolationPropertyGraphBoundaryInvalid = "property_graph_boundary_invalid"
	ViolationObjectIdentityConflict       = "object_identity_conflict"
	ViolationSymbolIdentityConflict       = "symbol_identity_conflict"
	ViolationEdgeIdentityConflict         = "edge_identity_conflict"
	ViolationReplayNonDeterministic       = "replay_determinism"
)

// violationSeverityBlocker is the §8.violation_emission.severity_values
// member that means the fact did not materialize. Every code this file
// raises today is a blocker: each one BLOCKS the row it describes, per
// §8.unresolved_endpoint_handling ("block active edge materialization") and
// the validation gates' reject_before_*_projection clauses. Lower
// severities exist in the spec's value set for advisory findings, which
// this pipeline does not yet produce.
const violationSeverityBlocker = "blocker"

// violationSentinelCandidates maps a violation_code to the sentinel
// identity §8.violation_emission.candidate_sentinel_mapping registers for
// it. The mapping is keyed by the spec's own mapping-key names, so a code
// with no registered sentinel resolves to "" rather than to a plausible
// guess — an invented sentinel identity would be worse than an absent one,
// because s15 owns the sentinel catalog and a fabricated name would not
// resolve there.
var violationSentinelCandidates = map[string]string{
	ViolationEndpointReferenceUnresolved:  "ErrOODGraphPropertyGraphEndpointReferenceInvalid",
	ViolationEndpointClassPairForbidden:   "ErrOODGraphPropertyGraphEndpointReferenceInvalid",
	ViolationPropertyOrSearchPayloadLeak:  "ErrOODGraphPropertyGraphPropertyLeak",
	ViolationContentHashBindingInvalid:    "ErrOODGraphContentHashBindingInvalid",
	ViolationPropertyGraphBoundaryInvalid: "ErrOODGraphPropertyGraphProjectionBoundaryViolation",
	ViolationObjectIdentityConflict:       "ErrOODGraphObjectIdentityConflict",
	ViolationSymbolIdentityConflict:       "ErrOODGraphSymbolIdentityConflict",
	ViolationEdgeIdentityConflict:         "ErrOODGraphEdgeIdentityConflict",
	ViolationReplayNonDeterministic:       "ErrOODGraphMaterializationReplayNonDeterministic",
}

// violationEvidenceAllowedFields is §8.violation_emission
// .evidence_allowed_fields verbatim. Evidence is filtered against this set
// rather than merely documented, because the sibling list
// evidence_forbidden_fields names exactly the things a careless raise site
// reaches for when explaining a rejection — target title, target summary,
// target status, admission hashes, rendered prose. An allowlist fails
// closed on a field nobody thought to forbid; a denylist does not.
var violationEvidenceAllowedFields = map[string]bool{
	"violation_code":             true,
	"sentinel_candidate":         true,
	"source_authority_id":        true,
	"source_stable_reference":    true,
	"version_coordinate":         true,
	"section_path":               true,
	"graph_address":              true,
	"graph_object_id":            true,
	"symbol_id":                  true,
	"graph_edge_id":              true,
	"edge_label":                 true,
	"source_endpoint_class":      true,
	"target_endpoint_class":      true,
	"identity_tuple_field_names": true,
	"rejected_value_class":       true,
	"redacted_reason":            true,
}

// ViolationCoordinate carries the graph-owned coordinates that locate a
// rejected fact. Every field is graph-owned; none is sibling payload.
type ViolationCoordinate struct {
	SourceAuthorityID     string
	SourceStableReference string
	VersionCoordinate     string
	SectionPath           string
	GraphAddress          string
	GraphObjectID         string
	SymbolID              string
	GraphEdgeID           string
	EdgeLabel             string
	SourceEndpointClass   string
	TargetEndpointClass   string

	// RejectedValueClass names the CLASS of the offending value rather than
	// the value itself — e.g. "object_class" or "edge_label".
	// evidence_allowed_fields registers rejected_value_class, not
	// rejected_value: the class is enough to act on and cannot smuggle
	// sibling content into the evidence blob.
	RejectedValueClass string

	// IdentityTupleFieldNames lists which identity-tuple FIELDS were
	// involved. Names only, never values, matching the registered field
	// identity_tuple_field_names.
	IdentityTupleFieldNames []string

	// RedactedReason is a graph-owned classification token explaining the
	// rejection. It must not carry rendered prose about the source.
	RedactedReason string
}

// NewViolation builds one OODGraphViolations row for a rejected fact.
//
// violation_id is deterministic over the tuple
// §8.violation_emission.violation_id_stability names: organization_id,
// materialization_run_id, violation_code, the source and graph coordinates,
// and the normalized evidence code fields. materialization_run_id is a
// member, so two runs that reject the same fact mint DIFFERENT violation
// ids — which is correct and is not in tension with
// §8.idempotency_and_replay_safety.same_inputs_same_outputs, whose
// determinism claim is over the "violation_code_and_coordinate_set", not
// over the ids. The id identifies an emission; the code+coordinate pair
// identifies the finding.
//
// Evidence is assembled here rather than accepted from the caller so the
// allowlist cannot be bypassed by a raise site in a hurry.
func NewViolation(orgID, runID, snapshotID, code string, coord ViolationCoordinate) Violation {
	sentinel := violationSentinelCandidates[code]
	graphAddress := normalizeViolationGraphAddress(coord.GraphAddress)
	identityTupleFieldNames := normalizedViolationIdentityTupleFieldNames(coord.IdentityTupleFieldNames)

	evidence := map[string]interface{}{
		"violation_code": code,
	}
	if sentinel != "" {
		evidence["sentinel_candidate"] = sentinel
	}
	putEvidence(evidence, "source_authority_id", coord.SourceAuthorityID)
	putEvidence(evidence, "source_stable_reference", coord.SourceStableReference)
	putEvidence(evidence, "version_coordinate", coord.VersionCoordinate)
	putEvidence(evidence, "section_path", coord.SectionPath)
	putEvidence(evidence, "graph_address", graphAddress)
	putEvidence(evidence, "graph_object_id", coord.GraphObjectID)
	putEvidence(evidence, "symbol_id", coord.SymbolID)
	putEvidence(evidence, "graph_edge_id", coord.GraphEdgeID)
	putEvidence(evidence, "edge_label", coord.EdgeLabel)
	putEvidence(evidence, "source_endpoint_class", coord.SourceEndpointClass)
	putEvidence(evidence, "target_endpoint_class", coord.TargetEndpointClass)
	putEvidence(evidence, "rejected_value_class", coord.RejectedValueClass)
	putEvidence(evidence, "redacted_reason", coord.RedactedReason)
	if len(identityTupleFieldNames) > 0 {
		anyNames := make([]interface{}, len(identityTupleFieldNames))
		for i, n := range identityTupleFieldNames {
			anyNames[i] = n
		}
		evidence["identity_tuple_field_names"] = anyNames
	}

	// Fail-closed allowlist sweep. Belt and braces over the putEvidence
	// calls above: a future field added to ViolationCoordinate and wired in
	// without a corresponding registered name is dropped here rather than
	// reaching the substrate.
	for k := range evidence {
		if !violationEvidenceAllowedFields[k] {
			delete(evidence, k)
		}
	}

	// Length-prefix every member instead of joining with a delimiter. Source
	// references and paths may themselves contain any plausible delimiter;
	// without framing, two distinct coordinate tuples can collapse to the
	// same byte string before UUID derivation.
	idMembers := []string{
		"violation", orgID, runID, code,
		coord.SourceAuthorityID, coord.SourceStableReference,
		coord.VersionCoordinate, coord.SectionPath, graphAddress,
		coord.GraphObjectID, coord.SymbolID, coord.GraphEdgeID,
		coord.EdgeLabel, coord.SourceEndpointClass, coord.TargetEndpointClass,
		coord.RejectedValueClass, coord.RedactedReason,
	}
	idMembers = append(idMembers, identityTupleFieldNames...)
	var idInput strings.Builder
	for _, member := range idMembers {
		_, _ = fmt.Fprintf(&idInput, "%d:%s", len(member), member)
	}
	violationID := uuid.NewSHA1(oodGraphIDNamespace, []byte(idInput.String())).String()

	return Violation{
		OrganizationID:        orgID,
		ViolationID:           violationID,
		GraphSnapshotID:       snapshotID,
		MaterializationRunID:  runID,
		ViolationCode:         code,
		SentinelCandidate:     sentinel,
		Severity:              violationSeverityBlocker,
		SourceAuthorityID:     coord.SourceAuthorityID,
		SourceStableReference: coord.SourceStableReference,
		VersionCoordinate:     coord.VersionCoordinate,
		SectionPath:           coord.SectionPath,
		GraphObjectID:         coord.GraphObjectID,
		SymbolID:              coord.SymbolID,
		GraphEdgeID:           coord.GraphEdgeID,
		Evidence:              evidence,
		// §8.violation_emission.status_values is the graph-row lifecycle
		// vocabulary; a new violation is active. resolution_rule states
		// explicitly that "OODGraphViolations.status never uses a resolved
		// value" — a violation stops being live only when a newer sealed
		// snapshot supersedes it, never by being marked fixed.
		Status:          "active",
		VisibilityScope: "organization",
	}
}

// normalizeViolationGraphAddress makes the registered graph_address
// coordinate canonical before it participates in evidence or stable
// identity. An invalid address is retained byte-for-byte: NewViolation is
// also used to describe boundary-invalid facts and has no error return, so
// silently dropping that rejected coordinate would create an ID collision.
func normalizeViolationGraphAddress(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := ParseGraphAddress(value)
	if err != nil {
		return value
	}
	return parsed.String()
}

func normalizedViolationIdentityTupleFieldNames(values []string) []string {
	normalized := append([]string(nil), values...)
	sort.Strings(normalized)
	return normalized
}

// putEvidence writes a key only when the value is non-empty, so the
// evidence blob does not carry a field the raise site had no coordinate
// for. An empty-string coordinate would read as "this fact has no section
// path" rather than "this raise site did not know it".
func putEvidence(evidence map[string]interface{}, key, value string) {
	if value == "" {
		return
	}
	evidence[key] = value
}
