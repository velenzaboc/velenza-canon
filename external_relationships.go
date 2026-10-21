package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

var externalRelationshipCanonicalNamePattern = regexp.MustCompile(`^(?:[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*|[a-z][a-z0-9-]*|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

type externalRelationshipIdentity struct {
	Source string
	Label  string
	Target string
}

// plannedExternalRelationship is a relationship after all caller-controlled
// names have resolved to unique submissions and the registry has approved the
// actual endpoint classes. Indices point into the same submission/object
// slices, making it impossible to fall back to an object from another
// snapshot during materialization.
type plannedExternalRelationship struct {
	Relationship  ExternalRelationship
	Label         EdgeLabelDescriptor
	SourceIndex   int
	TargetIndex   int
	AuthoringPath string
}

// planExternalRelationships validates the complete relationship set before
// any substrate or embedding I/O. The stable input order is canonicalized by
// (source canonical name, edge label, target canonical name), so replaying the
// same logical set in a different JSON-array order derives identical edge IDs
// and source coordinates. Each authoring path is content-addressed from its
// own relationship triple, so adding an unrelated earlier relationship does
// not renumber or re-identify existing edges.
func planExternalRelationships(
	ctx context.Context,
	env *Env,
	canonicalNames []string,
	kindDescriptors []NodeKindDescriptor,
	externalPolicies []ExternalSourceDescriptor,
	relationships []ExternalRelationship,
) ([]plannedExternalRelationship, error) {
	if len(relationships) == 0 {
		if err := validateRequiredExternalTopology(kindDescriptors, externalPolicies, nil); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if env == nil || env.Edges == nil {
		return nil, fmt.Errorf("external relationships require the closed edge_label registry")
	}
	if len(canonicalNames) != len(kindDescriptors) || len(canonicalNames) != len(externalPolicies) {
		return nil, fmt.Errorf("internal relationship planning cardinality mismatch")
	}

	byCanonicalName := make(map[string]int, len(canonicalNames))
	for i, name := range canonicalNames {
		if prior, duplicate := byCanonicalName[name]; duplicate {
			return nil, fmt.Errorf("external relationship endpoint canonical_name %q is ambiguous between submissions[%d] and submissions[%d]", name, prior, i)
		}
		byCanonicalName[name] = i
	}

	normalized := append([]ExternalRelationship(nil), relationships...)
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].SourceCanonicalName != normalized[j].SourceCanonicalName {
			return normalized[i].SourceCanonicalName < normalized[j].SourceCanonicalName
		}
		if normalized[i].EdgeLabel != normalized[j].EdgeLabel {
			return normalized[i].EdgeLabel < normalized[j].EdgeLabel
		}
		return normalized[i].TargetCanonicalName < normalized[j].TargetCanonicalName
	})

	plans := make([]plannedExternalRelationship, 0, len(normalized))
	seen := make(map[externalRelationshipIdentity]struct{}, len(normalized))
	for i, relationship := range normalized {
		fields := []struct {
			name  string
			value string
			limit int
		}{
			{"edge_label", relationship.EdgeLabel, 64},
			{"source_canonical_name", relationship.SourceCanonicalName, 2048},
			{"target_canonical_name", relationship.TargetCanonicalName, 2048},
		}
		for _, field := range fields {
			if field.value == "" {
				return nil, fmt.Errorf("relationship[%d].%s required", i, field.name)
			}
			if strings.TrimSpace(field.value) != field.value || !utf8.ValidString(field.value) {
				return nil, fmt.Errorf("relationship[%d].%s must be canonical UTF-8 without leading or trailing whitespace", i, field.name)
			}
			if len(field.value) > field.limit {
				return nil, fmt.Errorf("relationship[%d].%s exceeds STRING(%d)", i, field.name, field.limit)
			}
		}
		if !externalRelationshipCanonicalNamePattern.MatchString(relationship.SourceCanonicalName) {
			return nil, fmt.Errorf("relationship[%d].source_canonical_name %q is not a canonical snake_case, dotted, kebab-case, or UUID name", i, relationship.SourceCanonicalName)
		}
		if !externalRelationshipCanonicalNamePattern.MatchString(relationship.TargetCanonicalName) {
			return nil, fmt.Errorf("relationship[%d].target_canonical_name %q is not a canonical snake_case, dotted, kebab-case, or UUID name", i, relationship.TargetCanonicalName)
		}

		protocolContract, allowed := externalReferenceEdgeContracts[relationship.EdgeLabel]
		if !allowed {
			return nil, fmt.Errorf("relationship[%d].edge_label %q is not an OOD external-ingestion edge label", i, relationship.EdgeLabel)
		}
		label, err := env.Edges.Resolve(ctx, relationship.EdgeLabel)
		if err != nil {
			return nil, fmt.Errorf("relationship[%d].edge_label: %w", i, err)
		}
		if label.EdgeFamily() != protocolContract.EdgeFamily ||
			!equalStringSets(label.SourceKinds(), protocolContract.SourceKinds) ||
			!equalStringSets(label.TargetKinds(), protocolContract.TargetKinds) ||
			label.ReciprocalLabel() != "" || label.DiagnosticOnly() {
			return nil, fmt.Errorf("relationship[%d].edge_label %q registry descriptor does not match the OOD external edge contract", i, relationship.EdgeLabel)
		}

		sourceIndex, sourceFound := byCanonicalName[relationship.SourceCanonicalName]
		if !sourceFound {
			return nil, fmt.Errorf("relationship[%d] source_canonical_name %q does not resolve inside this materialization batch", i, relationship.SourceCanonicalName)
		}
		targetIndex, targetFound := byCanonicalName[relationship.TargetCanonicalName]
		if !targetFound {
			return nil, fmt.Errorf("relationship[%d] target_canonical_name %q does not resolve inside this materialization batch", i, relationship.TargetCanonicalName)
		}
		if externalPolicies[sourceIndex].ID == "" && externalPolicies[targetIndex].ID == "" {
			return nil, fmt.Errorf("relationship[%d] %q -> %q has no external-reference endpoint", i, relationship.SourceCanonicalName, relationship.TargetCanonicalName)
		}
		if err := validateEdgeEndpointClasses(
			label,
			relationship.SourceCanonicalName,
			kindDescriptors[sourceIndex].Name(),
			relationship.TargetCanonicalName,
			kindDescriptors[targetIndex].Name(),
		); err != nil {
			return nil, fmt.Errorf("relationship[%d]: %w", i, err)
		}

		identity := externalRelationshipIdentity{
			Source: relationship.SourceCanonicalName,
			Label:  relationship.EdgeLabel,
			Target: relationship.TargetCanonicalName,
		}
		if _, duplicate := seen[identity]; duplicate {
			return nil, fmt.Errorf("relationship[%d] duplicates %q -[%s]-> %q", i, relationship.SourceCanonicalName, relationship.EdgeLabel, relationship.TargetCanonicalName)
		}
		seen[identity] = struct{}{}

		identityBytes, err := canonicalJSON(map[string]interface{}{
			"edge_label":            identity.Label,
			"source_canonical_name": identity.Source,
			"target_canonical_name": identity.Target,
		})
		if err != nil {
			return nil, fmt.Errorf("canonicalize relationship[%d] identity: %w", i, err)
		}
		relationshipDigest := sha256.Sum256(identityBytes)
		authoringPath := "$.relationships.sha256_" + hex.EncodeToString(relationshipDigest[:])
		if err := ValidateSectionPath(authoringPath); err != nil {
			return nil, fmt.Errorf("derive relationship[%d] authoring_source_path: %w", i, err)
		}
		plans = append(plans, plannedExternalRelationship{
			Relationship:  relationship,
			Label:         label,
			SourceIndex:   sourceIndex,
			TargetIndex:   targetIndex,
			AuthoringPath: authoringPath,
		})
	}
	if err := validateRequiredExternalTopology(kindDescriptors, externalPolicies, plans); err != nil {
		return nil, err
	}
	return plans, nil
}

// validateRequiredExternalTopology prevents externally sourced pages,
// symbols, examples and release notes from sealing as isolated vertices.
// OOD_GRAPH_PROTOCOL_v1 §2 assigns reference_page and api_symbol explicit
// parent edges, while §10's required traversal requires corpus→page→symbol,
// example and release-note paths. Roots (external_reference_doc/source_repo)
// remain independently admissible so a corpus can be established before its
// first child is published.
func validateRequiredExternalTopology(kindDescriptors []NodeKindDescriptor, externalPolicies []ExternalSourceDescriptor, plans []plannedExternalRelationship) error {
	for endpointIndex, policy := range externalPolicies {
		if policy.ID == "" {
			continue
		}
		kind := kindDescriptors[endpointIndex].Name()
		matched := false
		for _, plan := range plans {
			sourceKind := kindDescriptors[plan.SourceIndex].Name()
			switch kind {
			case "reference_page":
				matched = plan.TargetIndex == endpointIndex &&
					plan.Relationship.EdgeLabel == "official_source_for" &&
					sourceKind == "external_reference_doc"
			case "api_symbol":
				matched = plan.TargetIndex == endpointIndex &&
					plan.Relationship.EdgeLabel == "defines_external_symbol" &&
					(sourceKind == "reference_page" || sourceKind == "source_repo")
			case "code_example":
				matched = plan.SourceIndex == endpointIndex && plan.Relationship.EdgeLabel == "example_of"
			case "release_note":
				matched = plan.SourceIndex == endpointIndex && plan.Relationship.EdgeLabel == "version_note_for"
			case "repo_snapshot":
				// s2 requires a parent source_repo edge, but the closed s4
				// external-reference family currently admits no source_repo ->
				// repo_snapshot endpoint pair. Do not bless an orphan or invent
				// a label while that protocol contract is unresolved.
				matched = false
			default:
				matched = true
			}
			if matched {
				break
			}
		}
		if matched {
			continue
		}
		if kind == "repo_snapshot" {
			return fmt.Errorf("%w: external repo_snapshot submission[%d] requires its s2 parent source_repo edge, but no s4 edge label admits source_repo -> repo_snapshot", ErrOODGraphExternalTopologyUnrepresentable, endpointIndex)
		}
		required := map[string]string{
			"reference_page": "incoming external_reference_doc -[official_source_for]-> reference_page parent edge",
			"api_symbol":     "incoming reference_page/source_repo -[defines_external_symbol]-> api_symbol parent edge",
			"code_example":   "outgoing code_example -[example_of]-> api_symbol/reference_page/code_symbol_ref edge",
			"release_note":   "outgoing release_note -[version_note_for]-> api_symbol/reference_page/external_reference_doc/code_symbol_ref edge",
		}[kind]
		if required != "" {
			return fmt.Errorf("external %s submission[%d] requires %s in the same materialization batch", kind, endpointIndex, required)
		}
	}
	return nil
}

// materializeExternalRelationships resolves every planned endpoint against
// the object rows being written by this run, then prepares embeddings and
// source evidence before the single CommitMaterializationRun transaction.
func materializeExternalRelationships(
	ctx context.Context,
	env *Env,
	orgID, runID, snapshotID, visibility string,
	objects []GraphObject,
	plans []plannedExternalRelationship,
) ([]GraphEdge, error) {
	if len(plans) == 0 {
		return nil, nil
	}
	pending := make([]PendingEdge, 0, len(plans))
	for _, plan := range plans {
		source := objects[plan.SourceIndex]
		target := objects[plan.TargetIndex]
		pending = append(pending, PendingEdge{
			SourceEndpointID:    source.GraphObjectID,
			TargetEndpointID:    target.GraphObjectID,
			Label:               plan.Label,
			AuthoringSourcePath: plan.AuthoringPath,
			SourceAuthorityID:   source.SourceAuthorityID,
			VisibilityScope:     visibility,
		})
	}
	edges, violations := ResolveEdgeEndpointsInBatch(orgID, runID, snapshotID, objects, pending)
	if len(violations) != 0 {
		return nil, fmt.Errorf("external relationship endpoint resolution produced %d violation(s); refusing partial materialization", len(violations))
	}
	if len(edges) != len(plans) {
		return nil, fmt.Errorf("external relationship materialization produced %d edges for %d plans", len(edges), len(plans))
	}
	if env == nil || env.Embed == nil {
		return nil, fmt.Errorf("external relationship embeddings require the configured 3072-dimensional embedding provider")
	}

	for i := range edges {
		source := objects[plans[i].SourceIndex]
		edges[i].SourceContentHash = source.SourceContentHash
		edges[i].SearchText = fmt.Sprintf("%s %s %s", edges[i].EdgeLabel, edges[i].SourceEndpointClass, edges[i].TargetEndpointClass)
		edges[i].SearchPayload = map[string]interface{}{
			"edge_label":            edges[i].EdgeLabel,
			"edge_family":           edges[i].EdgeFamily,
			"source_endpoint_class": edges[i].SourceEndpointClass,
			"target_endpoint_class": edges[i].TargetEndpointClass,
		}
	}
	// Edge retrieval text is a closed relation-class signature, not endpoint
	// prose. Derive one vector per distinct signature and reuse it across the
	// bounded bootstrap batch; thousands of defines_external_symbol edges must
	// never trigger thousands of identical model RPCs.
	embeddingsBySignature := make(map[string][]float32)
	for i := range edges {
		vec, present := embeddingsBySignature[edges[i].SearchText]
		if !present {
			var err error
			vec, err = env.Embed.Embed(ctx, edges[i].SearchText, vertexai.TaskTypeRetrievalDocument)
			if err != nil {
				return nil, fmt.Errorf("embed external relationship %q -[%s]-> %q: %w",
					plans[i].Relationship.SourceCanonicalName,
					plans[i].Relationship.EdgeLabel,
					plans[i].Relationship.TargetCanonicalName,
					err)
			}
			if len(vec) != externalReferenceEmbeddingDimensions {
				return nil, fmt.Errorf("embed external relationship %q -[%s]-> %q: got %d dimensions, want %d",
					plans[i].Relationship.SourceCanonicalName,
					plans[i].Relationship.EdgeLabel,
					plans[i].Relationship.TargetCanonicalName,
					len(vec), externalReferenceEmbeddingDimensions)
			}
			embeddingsBySignature[edges[i].SearchText] = append([]float32(nil), vec...)
		}
		edges[i].Embedding = append([]float32(nil), vec...)
		edges[i].EmbeddingModel = embeddingModelOrEmpty(env)
	}
	return edges, nil
}
