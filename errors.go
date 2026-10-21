package main

import (
	"errors"
	"fmt"
)

// Sentinel errors. Each one tells the caller what's pending and where to look
// for the design decision that would unblock it.

var (
	// ErrSchemaPending — the column schema for the substrate this verb would
	// touch is still being designed. The verb's orchestration shape is real;
	// the column-level write is not yet defined.
	ErrSchemaPending = errors.New("schema pending: column-level design not finalized in Node Identity & Admission spec")

	// ErrSubstrateNotProvisioned — the bottom-tier substrate exists in the
	// design but its DDL has not been applied.
	ErrSubstrateNotProvisioned = errors.New("substrate not yet provisioned")

	// ErrRegistryNotLoaded — a closed-set registry is not yet populated.
	ErrRegistryNotLoaded = errors.New("registry not yet loaded")

	// ErrUnknownNodeKind — node_kind value not found in the registry.
	ErrUnknownNodeKind = errors.New("unknown node_kind")

	// ErrUnknownEdgeLabel — edge_label not found in the registry.
	ErrUnknownEdgeLabel = errors.New("unknown edge_label")

	// ErrReciprocityViolation — proposed edge would violate the reciprocity
	// rule the edge_label declares.
	ErrReciprocityViolation = errors.New("reciprocity violation")

	// ErrClosureWouldDangle — archive refused because dependents would orphan.
	ErrClosureWouldDangle = errors.New("archive refused: closure would dangle")

	// ErrContractDrift — re-admission's contract does not validate against the
	// prior version's contract (Vision Principle 11 invariant).
	ErrContractDrift = errors.New("contract drift: re-admission contract incompatible with prior")

	// ErrCeremonyAtomicityBroken — step inside the 10-step ceremony failed
	// after the transaction was opened; transaction aborted.
	ErrCeremonyAtomicityBroken = errors.New("admission ceremony aborted")

	// ErrSnapshotNotPinned — read verb invoked without a snapshot pin and the
	// active snapshot resolver returned no eligible snapshot.
	ErrSnapshotNotPinned = errors.New("no snapshot pinned and no active snapshot available")

	// ErrModeMismatch — verb invoked in a mode that doesn't support it.
	// REQUIREMENTS.md §7.
	ErrModeMismatch = errors.New("verb not available in this mode")

	// ErrForbiddenDatabaseTarget — spec-graph init or reset invoked against a
	// database whose name doesn't match the corpus-graph-* allowlist.
	// REQUIREMENTS.md §7.
	ErrForbiddenDatabaseTarget = errors.New("forbidden database target: only corpus-graph-* names are allowed for init/reset")

	// ErrSchemaNotApplied — any verb invoked before spec-graph init has
	// applied the schema. REQUIREMENTS.md §7.
	ErrSchemaNotApplied = errors.New("schema not yet applied — run `spec-graph init`")

	// ErrImportDependencyUnresolved — spec_graph_import cannot topologically
	// order the submissions because of a cycle or missing referent.
	// REQUIREMENTS.md §7.
	ErrImportDependencyUnresolved = errors.New("import dependency unresolved: cycle or missing referent")

	// ErrSchemaFingerprintMismatch — pre-drop guard refused because the
	// target database's schema does not match the spec-graph experimental
	// shape exactly. Catches the case where the allowlist passes
	// (config-driven, can be edited to permit anything) but the database
	// at the configured spanner_database is actually a different system —
	// e.g. a production graph database carries DocObjects + OODGraph* tables, not
	// Nodes / Edges / ArtifactAdmissionLog.
	ErrSchemaFingerprintMismatch = errors.New("schema fingerprint mismatch: target database does not look like a spec-graph experimental DB")

	// ErrEdgeKindMismatch — edge admission refused because a resolved
	// endpoint's node_kind is not in the edge_label's allowed kind set.
	// Source-side: src.node_kind not in desc.source_kinds. Target-side:
	// tgt.node_kind not in desc.target_kinds. Reciprocal pairs are
	// validated in both directions so an asymmetric config cannot half-admit.
	ErrEdgeKindMismatch = errors.New("edge endpoint kind mismatch: resolved node_kind not in edge_label's allowed kind set")

	// ErrEdgeSelfLoopForbidden — edge admission refused because source_id
	// equals target_id and the edge_label declares forbid_self_loops=true.
	// Per-label policy declared in config (no binary default).
	ErrEdgeSelfLoopForbidden = errors.New("self-loop forbidden by edge_label policy: source_id equals target_id")

	// ErrDuplicateCanonicalName — Layer-2 dedup refused: a node already
	// exists in the same organization + node_kind with the same
	// canonical_name. The (node_kind, canonical_name) pair is the logical
	// primary key for declaration-bearing kinds per AUTHORING_GUIDE §2
	// zero_duplication. Caller should either spec_graph_update the existing
	// node, choose a different canonical_name, or link to the existing one
	// via edges instead of re-declaring it.
	ErrDuplicateCanonicalName = errors.New("duplicate canonical_name: a node with this (node_kind, canonical_name) already exists in this organization")

	// ErrPossibleDuplicate — Layer-3 dedup refused: embedding-similarity
	// search surfaced one or more existing nodes within the configured
	// cosine-distance threshold that were NOT in the submission's
	// acknowledge_distinct_from list. Caller must examine each candidate
	// (via spec_graph_get) and either acknowledge it as distinct (add to
	// acknowledge_distinct_from and re-submit) or use the existing node
	// instead of creating a new one. The wrapping PossibleDuplicateDetail
	// carries the candidate list.
	ErrPossibleDuplicate = errors.New("possible duplicate: similar node(s) already exist; acknowledge them as distinct or use the existing one")

	// ErrOODGraphMaterializationReplayNonDeterministic is the §8 replay
	// sentinel: the same closed idempotency key produced a different required
	// output manifest. The candidate snapshot is never written.
	ErrOODGraphMaterializationReplayNonDeterministic = errors.New("ErrOODGraphMaterializationReplayNonDeterministic: same materialization input key produced different graph output")

	// ErrOODGraphExternalVersionTransitionUnrepresentable refuses a refresh
	// whose external stable coordinate changes version, digest, owner, or trust
	// class. OOD Graph Protocol v1
	// §8/§9 requires temporal supersession evidence for that transition,
	// while the closed §6 endpoint registry does not admit external-reference
	// classes on supersedes/superseded_by. Until the registry is amended, the
	// only conformant behavior is to preserve the prior sealed snapshot and
	// reject the new run before it opens.
	ErrOODGraphExternalVersionTransitionUnrepresentable = errors.New("ErrOODGraphExternalVersionTransitionUnrepresentable: external version transition cannot satisfy the closed temporal-edge registry")

	// ErrOODGraphExternalTopologyUnrepresentable is a runtime pending-state
	// refusal, not a newly minted protocol sentinel. It prevents an external
	// object from sealing when the object model requires a parent relation but
	// the closed edge registry has no legal endpoint pair that can express it.
	ErrOODGraphExternalTopologyUnrepresentable = errors.New("ErrOODGraphExternalTopologyUnrepresentable: required external topology cannot be expressed by the closed edge registry")

	// ErrOODGraphExternalNonGranularProofUnavailable refuses roots and whole
	// pages until an admitted descriptor contract can prove both their
	// coordinate-derived name and their expected content class/marker. A
	// nonempty 2xx body alone is not authoritative evidence.
	ErrOODGraphExternalNonGranularProofUnavailable = errors.New("ErrOODGraphExternalNonGranularProofUnavailable: external root/page authenticity and identity proof is not configured")

	// ErrOODGraphExternalVerificationReceiptUnavailable prevents a complete
	// snapshot from making an external row current without one body-free,
	// policy-bound verification occurrence receipt in that same source_set.
	ErrOODGraphExternalVerificationReceiptUnavailable = errors.New("ErrOODGraphExternalVerificationReceiptUnavailable: complete snapshot lacks run-scoped external verification evidence")

	// ErrOODGraphMaterializationScaleUnrepresentable prevents a bootstrap
	// source_set or external publication from approaching Spanner's per-JSON
	// cell / per-commit limits. The canonical fix is normalized immutable
	// content plus snapshot-membership/receipt manifests and a compact head CAS,
	// not a larger monolithic JSON cell or RWT.
	ErrOODGraphMaterializationScaleUnrepresentable = errors.New("ErrOODGraphMaterializationScaleUnrepresentable: atomic bootstrap materialization exceeds its fail-closed storage envelope")

	// ErrOODGraphExternalRetrievalPermissionProofUnavailable distinguishes
	// evidence coordinates/bytes from an executable permission grant. Neither
	// a URL string nor an immutable LICENSE digest proves affirmative scope,
	// status, authority, effective time, or expiry; HTTPS retrieval remains
	// disabled until the protocol admits such a typed decision receipt.
	ErrOODGraphExternalRetrievalPermissionProofUnavailable = errors.New("ErrOODGraphExternalRetrievalPermissionProofUnavailable: retrieval evidence is not an executable permission receipt")

	// ErrOODGraphExternalContentClassProofUnavailable prevents a successful
	// HTTP status plus a coincidental anchor/key from impersonating the
	// configured corpus. The descriptor/receipt contract does not yet bind an
	// expected media type and deterministic corpus/page marker.
	ErrOODGraphExternalContentClassProofUnavailable = errors.New("ErrOODGraphExternalContentClassProofUnavailable: fetched representation lacks descriptor-owned content-class proof")

	// ErrOODGraphImmutableRetirementUnavailable keeps the public archive verbs
	// fail-closed until retirement can publish a protocol-valid complete
	// successor snapshot. Updating rows in a sealed historical snapshot is
	// forbidden, and the former bespoke archive-event rows used unregistered
	// run/object classes and dangling endpoints.
	ErrOODGraphImmutableRetirementUnavailable = errors.New("ErrOODGraphImmutableRetirementUnavailable: retirement requires a protocol-valid complete successor snapshot")

	// ErrOODGraphImmutableReembeddingUnavailable retires the former helper
	// that UPDATEd embeddings in prior sealed rows. Embedding refresh is a
	// stage of a new complete immutable materialization run, never an in-place
	// mutation or a partial batch operation.
	ErrOODGraphImmutableReembeddingUnavailable = errors.New("ErrOODGraphImmutableReembeddingUnavailable: re-embedding requires a complete immutable successor snapshot")

	// ErrOODGraphSourcePayloadResolutionUnavailable prevents semantic dedup
	// from treating OOD retrieval metadata as the source artifact body. The
	// graph stores authority coordinates, not copied source contract/payload;
	// a sanctioned source-authority resolver must supply comparison content.
	ErrOODGraphSourcePayloadResolutionUnavailable = errors.New("ErrOODGraphSourcePayloadResolutionUnavailable: semantic comparison requires a sanctioned source-authority payload resolver")

	// ErrOODGraphCompleteArtifactCarryForwardUnavailable prevents a complete
	// successor from silently dropping projection or violation artifacts from
	// a selected predecessor. Those tables use emission identities that cannot
	// be rebound to a new snapshot/run without a protocol-defined remint rule.
	ErrOODGraphCompleteArtifactCarryForwardUnavailable = errors.New("ErrOODGraphCompleteArtifactCarryForwardUnavailable: selected snapshot contains projection or violation artifacts without a protocol-defined successor remint")

	// ErrProductionRuntimeCompositionUnavailable prevents the bare stateless
	// HTTP handler from serving production traffic. The SDK TokenInfo consumed
	// by CallerContext can only be populated by an in-process verifier, and
	// external ingestion additionally requires an admitted circuit/driver
	// adapter. Neither authority may be delegated to an unauthenticated proxy
	// header or the bootstrap Go HTTP fetcher.
	ErrProductionRuntimeCompositionUnavailable = errors.New("ErrProductionRuntimeCompositionUnavailable: production requires an in-process verified-bearer adapter and admitted external-ingestion circuit adapter")
)

// DuplicateCanonicalNameDetail wraps ErrDuplicateCanonicalName with the
// existing node's id + version so the caller can immediately fetch or update
// it without a second lookup.
type DuplicateCanonicalNameDetail struct {
	NodeKind        string
	CanonicalName   string
	ExistingNodeID  string
	ExistingVersion int
}

func (d DuplicateCanonicalNameDetail) Error() string {
	return fmt.Sprintf("%s: node_kind=%q canonical_name=%q already admitted as node_id=%q (version %d)",
		ErrDuplicateCanonicalName, d.NodeKind, d.CanonicalName, d.ExistingNodeID, d.ExistingVersion)
}

func (d DuplicateCanonicalNameDetail) Unwrap() error { return ErrDuplicateCanonicalName }

// PossibleDuplicateCandidate is one similarity-search hit reported back to the
// caller alongside ErrPossibleDuplicate.
type PossibleDuplicateCandidate struct {
	NodeID         string  `json:"node_id"`
	NodeKind       string  `json:"node_kind"`
	CanonicalName  string  `json:"canonical_name,omitempty"`
	CosineDistance float64 `json:"cosine_distance"`
}

// PossibleDuplicateDetail wraps ErrPossibleDuplicate with the list of
// candidates that breached the configured similarity threshold and were not
// in the submission's acknowledge_distinct_from list. The caller must
// inspect each candidate and either re-submit with the candidate's node_id
// added to acknowledge_distinct_from (proceed with admission) or abandon
// the create in favor of using the existing node.
type PossibleDuplicateDetail struct {
	Threshold  float64                      `json:"threshold"`
	Candidates []PossibleDuplicateCandidate `json:"candidates"`
}

func (d PossibleDuplicateDetail) Error() string {
	return fmt.Sprintf("%s: %d candidate(s) within cosine distance %.4f — re-submit with acknowledge_distinct_from=%v to proceed",
		ErrPossibleDuplicate, len(d.Candidates), d.Threshold, candidateIDs(d.Candidates))
}

func (d PossibleDuplicateDetail) Unwrap() error { return ErrPossibleDuplicate }

func candidateIDs(cs []PossibleDuplicateCandidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.NodeID
	}
	return out
}

// SchemaPendingDetail wraps ErrSchemaPending with a structured note about what
// design decision is missing.
type SchemaPendingDetail struct {
	Step      string
	Needs     string
	OwnerSpec string
}

func (d SchemaPendingDetail) Error() string {
	return fmt.Sprintf("%s: %s (needs %s; owner: %s)", ErrSchemaPending, d.Step, d.Needs, d.OwnerSpec)
}

func (d SchemaPendingDetail) Unwrap() error { return ErrSchemaPending }

// SubstrateNotProvisionedDetail names which substrate is missing.
type SubstrateNotProvisionedDetail struct {
	Substrate string
	NeededDDL string
}

func (d SubstrateNotProvisionedDetail) Error() string {
	return fmt.Sprintf("%s: substrate=%q needs DDL %s", ErrSubstrateNotProvisioned, d.Substrate, d.NeededDDL)
}

func (d SubstrateNotProvisionedDetail) Unwrap() error { return ErrSubstrateNotProvisioned }
