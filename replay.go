package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"cloud.google.com/go/spanner"
	"google.golang.org/api/iterator"
)

type replayManifest struct {
	Objects          []map[string]interface{} `json:"objects"`
	Symbols          []map[string]interface{} `json:"symbols"`
	Edges            []map[string]interface{} `json:"edges"`
	ProjectionHashes []string                 `json:"projection_hashes"`
	Violations       []map[string]interface{} `json:"violations"`
}

type replayPrior struct {
	SnapshotID string
	RunID      string
}

func buildReplayManifest(batch MaterializationBatch) (replayManifest, error) {
	manifest := replayManifest{}
	for _, o := range batch.Objects {
		manifest.Objects = append(manifest.Objects, map[string]interface{}{
			"graph_object_id":         o.GraphObjectID,
			"object_class":            o.ObjectClass,
			"source_authority_id":     o.SourceAuthorityID,
			"source_ref_kind":         o.SourceRefKind,
			"source_stable_reference": o.SourceStableReference,
			"version_coordinate":      o.VersionCoordinate,
			"section_path":            o.SectionPath,
			"graph_address":           o.GraphAddress,
			"source_content_hash":     o.SourceContentHash,
		})
	}
	for _, s := range batch.Symbols {
		manifest.Symbols = append(manifest.Symbols, map[string]interface{}{
			"symbol_id":               s.SymbolID,
			"graph_object_id":         s.GraphObjectID,
			"object_class":            s.ObjectClass,
			"symbol_kind":             s.SymbolKind,
			"symbol_name":             s.SymbolName,
			"source_authority_id":     s.SourceAuthorityID,
			"source_stable_reference": s.SourceStableReference,
			"version_coordinate":      s.VersionCoordinate,
			"section_path":            s.SectionPath,
			"graph_address":           s.GraphAddress,
		})
	}
	for _, e := range batch.Edges {
		manifest.Edges = append(manifest.Edges, map[string]interface{}{
			"graph_edge_id":             e.GraphEdgeID,
			"source_endpoint_kind":      e.SourceEndpointKind,
			"source_endpoint_id":        e.SourceEndpointID,
			"target_endpoint_kind":      e.TargetEndpointKind,
			"target_endpoint_id":        e.TargetEndpointID,
			"edge_label":                e.EdgeLabel,
			"source_version_coordinate": e.SourceVersionCoordinate,
			"target_version_coordinate": e.TargetVersionCoordinate,
			"authoring_source_path":     e.AuthoringSourcePath,
			"source_authority_id":       e.SourceAuthorityID,
			"source_stable_reference":   e.SourceStableReference,
			"source_content_hash":       e.SourceContentHash,
		})
	}
	for _, projection := range batch.ProjectionArtifacts {
		manifest.ProjectionHashes = append(manifest.ProjectionHashes, projection.ProjectionHash)
	}
	for _, violation := range batch.Violations {
		entry, err := replayViolationManifestEntry(violation)
		if err != nil {
			return replayManifest{}, err
		}
		manifest.Violations = append(manifest.Violations, entry)
	}
	if err := sortStructuredSet(manifest.Objects); err != nil {
		return replayManifest{}, err
	}
	if err := sortStructuredSet(manifest.Symbols); err != nil {
		return replayManifest{}, err
	}
	if err := sortStructuredSet(manifest.Edges); err != nil {
		return replayManifest{}, err
	}
	if err := sortStructuredSet(manifest.Violations); err != nil {
		return replayManifest{}, err
	}
	sort.Strings(manifest.ProjectionHashes)
	return manifest, nil
}

// replayViolationManifestEntry includes both the indexed violation
// coordinates and the complete registered evidence-coordinate set. The
// latter lives in OODGraphViolations.evidence, so omitting it here would let
// two materially different rejected facts pass replay verification.
func replayViolationManifestEntry(violation Violation) (map[string]interface{}, error) {
	evidenceCoordinates, err := replayViolationEvidenceCoordinates(violation.Evidence)
	if err != nil {
		return nil, fmt.Errorf("violation_code=%q replay evidence: %w", violation.ViolationCode, err)
	}
	return map[string]interface{}{
		"violation_code":          violation.ViolationCode,
		"source_authority_id":     violation.SourceAuthorityID,
		"source_stable_reference": violation.SourceStableReference,
		"version_coordinate":      violation.VersionCoordinate,
		"section_path":            violation.SectionPath,
		"graph_object_id":         violation.GraphObjectID,
		"symbol_id":               violation.SymbolID,
		"graph_edge_id":           violation.GraphEdgeID,
		"evidence_coordinates":    evidenceCoordinates,
	}, nil
}

func replayViolationEvidenceCoordinates(evidence map[string]interface{}) (map[string]interface{}, error) {
	coordinates := make(map[string]interface{}, 14)
	stringFields := []string{
		"source_authority_id",
		"source_stable_reference",
		"version_coordinate",
		"section_path",
		"graph_address",
		"graph_object_id",
		"symbol_id",
		"graph_edge_id",
		"edge_label",
		"source_endpoint_class",
		"target_endpoint_class",
		"rejected_value_class",
		"redacted_reason",
	}
	for _, field := range stringFields {
		value, err := replayViolationEvidenceString(evidence, field)
		if err != nil {
			return nil, err
		}
		if field == "graph_address" && value != "" {
			parsed, err := ParseGraphAddress(value)
			if err != nil {
				return nil, fmt.Errorf("graph_address is not canonicalizable: %w", err)
			}
			value = parsed.String()
		}
		coordinates[field] = value
	}
	identityNames, err := replayViolationIdentityTupleFieldNames(evidence)
	if err != nil {
		return nil, err
	}
	coordinates["identity_tuple_field_names"] = identityNames
	return coordinates, nil
}

func replayViolationEvidenceString(evidence map[string]interface{}, field string) (string, error) {
	if evidence == nil {
		return "", nil
	}
	raw, ok := evidence[field]
	if !ok || raw == nil {
		return "", nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string, got %T", field, raw)
	}
	return value, nil
}

func replayViolationIdentityTupleFieldNames(evidence map[string]interface{}) ([]string, error) {
	if evidence == nil {
		return []string{}, nil
	}
	raw, ok := evidence["identity_tuple_field_names"]
	if !ok || raw == nil {
		return []string{}, nil
	}
	var names []string
	switch values := raw.(type) {
	case []string:
		names = append(names, values...)
	case []interface{}:
		names = make([]string, len(values))
		for i, value := range values {
			name, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("identity_tuple_field_names[%d] must be a string, got %T", i, value)
			}
			names[i] = name
		}
	default:
		return nil, fmt.Errorf("identity_tuple_field_names must be an array, got %T", raw)
	}
	sort.Strings(names)
	return names, nil
}

func sortStructuredSet(items []map[string]interface{}) error {
	for _, item := range items {
		_, err := canonicalJSON(item)
		if err != nil {
			return err
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		left, _ := canonicalJSON(items[i])
		right, _ := canonicalJSON(items[j])
		return bytes.Compare(left, right) < 0
	})
	return nil
}

func replayManifestDigest(batch MaterializationBatch) (string, error) {
	manifest, err := buildReplayManifest(batch)
	if err != nil {
		return "", err
	}
	b, err := canonicalJSON(manifest)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func replayOutputsEquivalent(left, right MaterializationBatch) (bool, error) {
	leftManifest, err := buildReplayManifest(left)
	if err != nil {
		return false, err
	}
	rightManifest, err := buildReplayManifest(right)
	if err != nil {
		return false, err
	}
	leftBytes, err := canonicalJSON(leftManifest)
	if err != nil {
		return false, err
	}
	rightBytes, err := canonicalJSON(rightManifest)
	if err != nil {
		return false, err
	}
	return bytes.Equal(leftBytes, rightBytes), nil
}

func findReplayPriorsInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, snapshotT, runT string, batch MaterializationBatch) ([]replayPrior, error) {
	stmt := spanner.Statement{
		SQL: fmt.Sprintf(`SELECT s.graph_snapshot_id, r.materialization_run_id, s.source_set
FROM %s s JOIN %s r
  ON r.organization_id=s.organization_id
 AND r.materialization_run_id=s.materialization_run_id
WHERE s.organization_id=@org
  AND s.snapshot_kind=@snapshot_kind
  AND s.snapshot_state='sealed'
  AND s.status='active'
  AND s.sealed_at IS NOT NULL
  AND s.source_set_hash=@source_hash
  AND r.target_graph_snapshot_id=s.graph_snapshot_id
  AND r.state='sealed'
  AND r.input_source_set_hash=s.source_set_hash
  AND r.finished_at IS NOT NULL
-- Compare only the current semantic head for this idempotency key. Every
-- previously admitted head was itself compared to its predecessor, so
-- equivalence is transitive; rereading every historical full corpus makes
-- repeated freshness attestations O(n^2) and eventually exceeds an RWT.
ORDER BY s.graph_version DESC, s.graph_snapshot_id DESC
LIMIT 1`, snapshotT, runT),
		Params: map[string]interface{}{
			"org":           batch.Run.OrganizationID,
			"snapshot_kind": batch.Snapshot.SnapshotKind,
			"source_hash":   batch.Run.InputSourceSetHash,
		},
	}
	iter := tx.Query(ctx, stmt)
	defer iter.Stop()
	var priors []replayPrior
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("find replay priors: %w", err)
		}
		var prior replayPrior
		var sourceSet spanner.NullJSON
		if err := row.Columns(&prior.SnapshotID, &prior.RunID, &sourceSet); err != nil {
			return nil, fmt.Errorf("decode replay prior: %w", err)
		}
		profile := ""
		if sourceSet.Valid {
			profile, _ = jsonValueToMap(sourceSet.Value)["materialization_profile_version"].(string)
		}
		if profile == MaterializationProfileVersion {
			priors = append(priors, prior)
		}
	}
	return priors, nil
}

func verifyReplayOutputsInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, snapshotT, objectT, symbolT, edgeT, runT, violationT, projectionT string, candidate MaterializationBatch) (map[string]bool, error) {
	priors, err := findReplayPriorsInTx(ctx, tx, snapshotT, runT, candidate)
	if err != nil {
		return nil, err
	}
	equivalent := make(map[string]bool, len(priors))
	for _, prior := range priors {
		priorBatch, err := loadReplayBatchInTx(ctx, tx, snapshotT, objectT, symbolT, edgeT, violationT, projectionT, candidate.Run.OrganizationID, prior)
		if err != nil {
			return nil, err
		}
		equal, err := replayOutputsEquivalent(candidate, priorBatch)
		if err != nil {
			return nil, err
		}
		if !equal {
			return nil, fmt.Errorf("%w: prior graph_snapshot_id=%q", ErrOODGraphMaterializationReplayNonDeterministic, prior.SnapshotID)
		}
		equivalent[prior.SnapshotID] = true
	}
	return equivalent, nil
}

func loadReplayBatchInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, snapshotT, objectT, symbolT, edgeT, violationT, projectionT, orgID string, prior replayPrior) (MaterializationBatch, error) {
	objects, err := loadCarryForwardObjects(ctx, tx, snapshotT, objectT, orgID, []string{prior.SnapshotID})
	if err != nil {
		return MaterializationBatch{}, err
	}
	symbols, err := loadCarryForwardSymbols(ctx, tx, snapshotT, symbolT, orgID, []string{prior.SnapshotID})
	if err != nil {
		return MaterializationBatch{}, err
	}
	edges, err := loadCarryForwardEdges(ctx, tx, snapshotT, edgeT, orgID, []string{prior.SnapshotID})
	if err != nil {
		return MaterializationBatch{}, err
	}
	projections, err := loadReplayProjectionHashes(ctx, tx, projectionT, orgID, prior.SnapshotID)
	if err != nil {
		return MaterializationBatch{}, err
	}
	violations, err := loadReplayViolations(ctx, tx, violationT, orgID, prior.SnapshotID, prior.RunID)
	if err != nil {
		return MaterializationBatch{}, err
	}
	return MaterializationBatch{Objects: objects, Symbols: symbols, Edges: edges, ProjectionArtifacts: projections, Violations: violations}, nil
}

func loadReplayProjectionHashes(ctx context.Context, queryer spannerStatementQueryer, table, orgID, snapshotID string) ([]ProjectionArtifact, error) {
	iter := queryer.Query(ctx, spanner.Statement{SQL: fmt.Sprintf(`SELECT projection_hash FROM %s WHERE organization_id=@org AND graph_snapshot_id=@snapshot ORDER BY projection_hash`, table), Params: map[string]interface{}{"org": orgID, "snapshot": snapshotID}})
	defer iter.Stop()
	var out []ProjectionArtifact
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		var projection ProjectionArtifact
		if err := row.Columns(&projection.ProjectionHash); err != nil {
			return nil, err
		}
		out = append(out, projection)
	}
	return out, nil
}

func loadReplayViolations(ctx context.Context, queryer spannerStatementQueryer, table, orgID, snapshotID, runID string) ([]Violation, error) {
	iter := queryer.Query(ctx, spanner.Statement{SQL: fmt.Sprintf(`SELECT violation_code, source_authority_id, source_stable_reference,
version_coordinate, section_path, graph_object_id, symbol_id, graph_edge_id, evidence
FROM %s
WHERE organization_id=@org AND (graph_snapshot_id=@snapshot OR materialization_run_id=@run)
ORDER BY violation_code, source_authority_id, source_stable_reference, version_coordinate,
section_path, graph_object_id, symbol_id, graph_edge_id`, table), Params: map[string]interface{}{"org": orgID, "snapshot": snapshotID, "run": runID}})
	defer iter.Stop()
	var out []Violation
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		var violation Violation
		var authority, reference, version, section, objectID, symbolID, edgeID spanner.NullString
		var evidence spanner.NullJSON
		if err := row.Columns(&violation.ViolationCode, &authority, &reference, &version, &section, &objectID, &symbolID, &edgeID, &evidence); err != nil {
			return nil, err
		}
		violation.SourceAuthorityID = authority.StringVal
		violation.SourceStableReference = reference.StringVal
		violation.VersionCoordinate = version.StringVal
		violation.SectionPath = section.StringVal
		violation.GraphObjectID = objectID.StringVal
		violation.SymbolID = symbolID.StringVal
		violation.GraphEdgeID = edgeID.StringVal
		if !evidence.Valid {
			return nil, fmt.Errorf("violation_code=%q evidence is NULL", violation.ViolationCode)
		}
		violation.Evidence = jsonValueToMap(evidence.Value)
		if violation.Evidence == nil {
			return nil, fmt.Errorf("violation_code=%q evidence must be a JSON object", violation.ViolationCode)
		}
		out = append(out, violation)
	}
	return out, nil
}
