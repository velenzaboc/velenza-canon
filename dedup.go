package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

// runDedupGate runs the three-layer pre-admission duplicate-detection
// sequence on a proposed node submission. Called from handleCreate BEFORE
// AdmitArtifact when the config carries a DedupPolicy. Returns three things:
//
//   - idempotent: when non-nil, Layer 1 matched and the caller should return
//     this existing AdmissionRecord as a no-op success (same definition_hash
//     = byte-identical contract+payload = literal duplicate; re-admitting
//     would be a no-op write, so we short-circuit).
//
//   - err: when non-nil, dedup refused admission. Layer 2 returns a
//     DuplicateCanonicalNameDetail wrapping ErrDuplicateCanonicalName;
//     Layer 3 returns a PossibleDuplicateDetail wrapping
//     ErrPossibleDuplicate. The caller should bubble this back to the MCP
//     caller — strict-error response on Layers 2 & 3, no admission row
//     written.
//
//   - proceed (nil idempotent, nil err): no duplicate detected;
//     handleCreate should call AdmitArtifact normally.
//
// Layers run shortest-circuit-first: Layer 1 (hash) → Layer 2 (name) →
// Layer 3 (similarity). Layers 1 + 2 are deterministic free lookups;
// Layer 3 costs one Vertex embed + one APPROX_COSINE_DISTANCE query and
// is skipped when env.Embed is nil or the policy excludes this kind.
//
// Re-admission carve-out: when sub.PriorVersion != nil, the caller is
// explicitly re-admitting an existing stable_id; dedup is skipped
// entirely (validateContractMonotonicity handles the contract invariant
// for that path).
//
// Edge carve-out: when sub.EdgeLabel != "", dedup is skipped. Parallel
// edges with the same endpoints are legitimately distinct by label per
// 010_multi_role_same_target_edges_are_distinct_by_label.
//
// Empty-policy carve-out: when env.Config.Dedup == nil, dedup is
// skipped entirely (returns proceed). Production configs should always
// set Dedup; experimental configs may run without it.
func runDedupGate(ctx context.Context, env *Env, sub ArtifactSubmission, acknowledgeDistinctFrom []string) (idempotent *AdmissionRecord, err error) {
	policy := env.Config.Dedup
	if policy == nil {
		return nil, nil
	}
	if sub.PriorVersion != nil {
		return nil, nil
	}
	if sub.EdgeLabel != "" {
		return nil, nil
	}
	for _, k := range policy.SkipKinds {
		if k == sub.NodeKind {
			return nil, nil
		}
	}

	adapter, err := resolveAdapterForSubmission(ctx, env, sub)
	if err != nil {
		return nil, fmt.Errorf("resolve adapter for dedup: %w", err)
	}

	// Layer 1: definition_hash exact match → idempotent return.
	defHash, err := computeDefinitionHashForDedup(sub)
	if err != nil {
		return nil, fmt.Errorf("compute definition_hash for dedup: %w", err)
	}
	existing, found, err := adapter.FindByDefinitionHash(ctx, sub.OrganizationID, defHash)
	if err != nil {
		return nil, fmt.Errorf("layer 1 lookup: %w", err)
	}
	if found {
		// Reconstruct an AdmissionRecord from the existing node so the
		// caller sees the canonical receipt. Pass_report is empty — no
		// new ceremony ran.
		rec := AdmissionRecord{
			ArtifactType:    sub.ArtifactType,
			OrganizationID:  existing.OrganizationID,
			ArtifactID:      existing.NodeID,
			ArtifactVersion: existing.CurrentVersion.Version,
			AdmittedAt:      existing.CurrentVersion.AdmittedAt,
			AdmittedBy:      existing.CurrentVersion.AdmittedBy,
			DefinitionHash:  existing.CurrentVersion.DefinitionHash,
			ManifestHash:    existing.CurrentVersion.ManifestHash,
			SignatureChain:  existing.CurrentVersion.SignatureChain,
		}
		return &rec, nil
	}

	// Layer 2: (node_kind, canonical_name) exact match → refuse.
	if name, ok := extractCanonicalName(sub.Contract); ok {
		existing, found, err := adapter.FindByCanonicalName(ctx, sub.OrganizationID, sub.NodeKind, name)
		if err != nil {
			return nil, fmt.Errorf("layer 2 lookup: %w", err)
		}
		if found {
			return nil, DuplicateCanonicalNameDetail{
				NodeKind:        sub.NodeKind,
				CanonicalName:   name,
				ExistingNodeID:  existing.NodeID,
				ExistingVersion: existing.CurrentVersion.Version,
			}
		}
	}

	// Layer 3: embedding cosine similarity. Skipped silently if no embedder
	// is configured.
	if env.Embed == nil {
		return nil, nil
	}
	text, err := canonicalEmbedText(sub)
	if err != nil {
		return nil, fmt.Errorf("layer 3 canonical embed text: %w", err)
	}
	vec, err := env.Embed.Embed(ctx, text, vertexai.TaskTypeRetrievalDocument)
	if err != nil {
		return nil, fmt.Errorf("layer 3 embed query: %w", err)
	}
	hits, err := adapter.FindSimilarByEmbedding(ctx, sub.OrganizationID, vec, policy.EmbeddingSimilarityThreshold, policy.CandidateLimit)
	if err != nil {
		return nil, fmt.Errorf("layer 3 similarity lookup: %w", err)
	}
	unacked := filterUnacknowledged(hits, acknowledgeDistinctFrom)
	if len(unacked) > 0 {
		cands := make([]PossibleDuplicateCandidate, 0, len(unacked))
		for _, h := range unacked {
			name, _ := extractCanonicalName(h.Node.CurrentVersion.Contract)
			cands = append(cands, PossibleDuplicateCandidate{
				NodeID:         h.Node.NodeID,
				NodeKind:       h.Node.NodeKind,
				CanonicalName:  name,
				CosineDistance: h.Distance,
			})
		}
		return nil, PossibleDuplicateDetail{
			Threshold:  policy.EmbeddingSimilarityThreshold,
			Candidates: cands,
		}
	}
	return nil, nil
}

// computeDefinitionHashForDedup mirrors stepDefinitionHash but runs ahead of
// the ceremony so Layer 1 can short-circuit. The ceremony will compute the
// same hash again at step 4 — once dedup runs we know that recompute will
// match; the duplicate work is one extra SHA-256 per create, which is
// negligible compared to the round-trip cost dedup avoids.
func computeDefinitionHashForDedup(sub ArtifactSubmission) (string, error) {
	canon := map[string]interface{}{
		"artifact_type":      sub.ArtifactType,
		"organization_id":    sub.OrganizationID,
		"node_kind":          sub.NodeKind,
		"edge_label":         sub.EdgeLabel,
		"stable_id":          sub.StableID,
		"contract":           sub.Contract,
		"payload":            sub.Payload,
		"governing_spec_ref": sub.GoverningSpec,
		"spec_section_ref":   sub.SpecSection,
	}
	if sub.SourceCoordinate != nil {
		canon["source_coordinate"] = sub.SourceCoordinate
	}
	b, err := canonicalJSON(canon)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// extractCanonicalName pulls the canonical_name string from the contract
// map if present. Returns ("", false) when missing or the wrong type;
// dedup Layer 2 silently skips on absence (nodes without canonical_name
// can't collide on it).
func extractCanonicalName(contract map[string]interface{}) (string, bool) {
	if contract == nil {
		return "", false
	}
	v, ok := contract["canonical_name"]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// filterUnacknowledged returns the subset of similarity hits whose node_id
// is NOT in the caller's acknowledge_distinct_from list. The acknowledge
// list is the override mechanism: a candidate the caller has examined and
// confirmed is distinct from the proposed node passes through.
func filterUnacknowledged(hits []SimilarNode, acknowledged []string) []SimilarNode {
	if len(hits) == 0 {
		return nil
	}
	ack := make(map[string]struct{}, len(acknowledged))
	for _, id := range acknowledged {
		ack[id] = struct{}{}
	}
	out := make([]SimilarNode, 0, len(hits))
	for _, h := range hits {
		if _, ok := ack[h.Node.NodeID]; ok {
			continue
		}
		out = append(out, h)
	}
	return out
}

// errorsAreDedupGate is a tiny helper used by callers (and tests) to assert
// an error was produced by the dedup gate vs the ceremony. Returns true
// when the error wraps any of the dedup sentinels.
func errorsAreDedupGate(err error) bool {
	return errors.Is(err, ErrDuplicateCanonicalName) || errors.Is(err, ErrPossibleDuplicate)
}
