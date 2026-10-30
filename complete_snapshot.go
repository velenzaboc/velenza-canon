package main

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/spanner"
	"google.golang.org/api/iterator"
)

type eligibleSnapshotSeed struct {
	SnapshotID   string
	GraphVersion int64
	Profile      string
	SourceSet    map[string]interface{}
}

type spannerStatementQueryer interface {
	Query(context.Context, spanner.Statement) *spanner.RowIterator
}

// PrepareCompleteMaterialization turns one import delta into a complete
// immutable active-candidate snapshot. The first current-profile materialization
// consolidates the union of every eligible legacy partial snapshot. Once a
// complete snapshot exists, it is the baseline and only any newer legacy
// partials (from a stale writer) are additionally folded in.
func (a *SpannerSubstrateAdapter) PrepareCompleteMaterialization(ctx context.Context, delta MaterializationBatch, deltaCoordinates []SourceCoordinate, authority MaterializationValidationAuthority) (MaterializationBatch, []SourceCoordinate, error) {
	snapshotT, objectT, symbolT, edgeT, runT, violationT, projectionT, err := a.requireOODGraphTables()
	if err != nil {
		return MaterializationBatch{}, nil, err
	}
	if delta.Run.OrganizationID == "" || delta.Run.MaterializationRunID == "" || delta.Snapshot.GraphSnapshotID == "" {
		return MaterializationBatch{}, nil, fmt.Errorf("prepare complete materialization requires organization, run, and snapshot ids")
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return MaterializationBatch{}, nil, err
	}
	// One multi-use read-only transaction supplies a single timestamp for the
	// seed list and all three carried row sets. client.Single() is one-use and
	// closes after its first query; reusing it silently made symbol/edge carry
	// fail after the object query.
	reader := client.ReadOnlyTransaction()
	defer reader.Close()
	seeds, err := loadEligibleActiveCandidateSeeds(ctx, reader, snapshotT, runT, delta.Run.OrganizationID)
	if err != nil {
		return MaterializationBatch{}, nil, err
	}
	selected := selectCarryForwardSeeds(seeds)
	snapshotIDs := make([]string, 0, len(selected))
	legacySnapshotIDs := make(map[string]bool, len(selected))
	for _, seed := range selected {
		snapshotIDs = append(snapshotIDs, seed.SnapshotID)
		legacySnapshotIDs[seed.SnapshotID] = seed.Profile != MaterializationProfileVersion
	}
	if err := refuseUnrepresentableCarriedArtifacts(ctx, reader, projectionT, violationT, delta.Run.OrganizationID, snapshotIDs); err != nil {
		return MaterializationBatch{}, nil, err
	}
	baselineVersion, err := latestOrganizationGraphVersion(ctx, reader, snapshotT, delta.Run.OrganizationID)
	if err != nil {
		return MaterializationBatch{}, nil, err
	}
	objects, err := loadCarryForwardObjects(ctx, reader, snapshotT, objectT, delta.Run.OrganizationID, snapshotIDs)
	if err != nil {
		return MaterializationBatch{}, nil, err
	}
	symbols, err := loadCarryForwardSymbols(ctx, reader, snapshotT, symbolT, delta.Run.OrganizationID, snapshotIDs)
	if err != nil {
		return MaterializationBatch{}, nil, err
	}
	edges, err := loadCarryForwardEdges(ctx, reader, snapshotT, edgeT, delta.Run.OrganizationID, snapshotIDs)
	if err != nil {
		return MaterializationBatch{}, nil, err
	}
	var carriedExternalReceipts []*stagedExternalVerificationReceipt
	for _, seed := range selected {
		receipts, receiptErr := ExternalVerificationReceiptsFromStoredSet(seed.SourceSet)
		if receiptErr != nil {
			if seed.Profile == MaterializationProfileVersion {
				return MaterializationBatch{}, nil, fmt.Errorf("decode current-profile external receipts for snapshot %q: %w", seed.SnapshotID, receiptErr)
			}
			continue
		}
		carriedExternalReceipts = append(carriedExternalReceipts, receipts...)
	}
	// Identity collisions are adjudicated against the rows exactly as they
	// were sealed. Known legacy re-rendering below is profile migration, not
	// permission to normalize divergent material into equality. Apart from
	// snapshot/run/timestamp rebinding, a same-ID carried/delta collision must
	// be byte-equivalent before any legacy field is rewritten.
	if err := requireExactSealedCarryForwardCollisionMaterial(objects, symbols, edges, delta); err != nil {
		return MaterializationBatch{}, nil, err
	}
	if err := normalizeKnownLegacyProjectionRoles(ctx, objects, legacySnapshotIDs, authority.Kinds); err != nil {
		return MaterializationBatch{}, nil, err
	}
	if err := normalizeKnownLegacyReciprocityStates(edges, legacySnapshotIDs); err != nil {
		return MaterializationBatch{}, nil, err
	}
	if err := normalizeKnownLegacyRetrievalMetadata(ctx, objects, symbols, edges, legacySnapshotIDs, authority); err != nil {
		return MaterializationBatch{}, nil, err
	}

	objectByID, err := mergeGraphObjectsByID(objects, delta.Objects)
	if err != nil {
		return MaterializationBatch{}, nil, err
	}
	if err := rejectUnrepresentableExternalVersionRefresh(objects, delta.Objects); err != nil {
		return MaterializationBatch{}, nil, err
	}
	symbolByID, err := mergeGraphSymbolsByID(symbols, delta.Symbols)
	if err != nil {
		return MaterializationBatch{}, nil, err
	}
	edgeByID, err := mergeGraphEdgesByID(edges, delta.Edges)
	if err != nil {
		return MaterializationBatch{}, nil, err
	}

	complete := delta
	complete.Objects = make([]GraphObject, 0, len(objectByID))
	for _, object := range objectByID {
		object.OrganizationID = delta.Run.OrganizationID
		object.GraphSnapshotID = delta.Snapshot.GraphSnapshotID
		object.MaterializationRunID = delta.Run.MaterializationRunID
		complete.Objects = append(complete.Objects, object)
	}
	sort.Slice(complete.Objects, func(i, j int) bool { return complete.Objects[i].GraphObjectID < complete.Objects[j].GraphObjectID })
	complete.ExternalVerificationReceipts, err = mergeExternalVerificationReceiptsForCompleteSnapshot(carriedExternalReceipts, delta.ExternalVerificationReceipts, complete.Objects)
	if err != nil {
		return MaterializationBatch{}, nil, err
	}
	complete.Symbols = make([]GraphSymbol, 0, len(symbolByID))
	for _, symbol := range symbolByID {
		symbol.OrganizationID = delta.Run.OrganizationID
		symbol.GraphSnapshotID = delta.Snapshot.GraphSnapshotID
		symbol.MaterializationRunID = delta.Run.MaterializationRunID
		complete.Symbols = append(complete.Symbols, symbol)
	}
	sort.Slice(complete.Symbols, func(i, j int) bool { return complete.Symbols[i].SymbolID < complete.Symbols[j].SymbolID })
	complete.Edges = make([]GraphEdge, 0, len(edgeByID))
	for _, edge := range edgeByID {
		edge.OrganizationID = delta.Run.OrganizationID
		edge.GraphSnapshotID = delta.Snapshot.GraphSnapshotID
		edge.MaterializationRunID = delta.Run.MaterializationRunID
		complete.Edges = append(complete.Edges, edge)
	}
	sort.Slice(complete.Edges, func(i, j int) bool { return complete.Edges[i].GraphEdgeID < complete.Edges[j].GraphEdgeID })
	complete.CompleteSnapshot = true
	complete.BaselineGraphVersion = baselineVersion
	if err := ensureChangedRowEmbeddings(ctx, &complete, delta, authority); err != nil {
		return MaterializationBatch{}, nil, err
	}
	if err := validateCompleteMaterializationRows(ctx, complete, authority); err != nil {
		return MaterializationBatch{}, nil, err
	}

	coords := make([]SourceCoordinate, 0, len(complete.Objects)+len(deltaCoordinates))
	activeSourceIdentity := make(map[string]struct{}, len(complete.Objects))
	for _, object := range complete.Objects {
		if object.Status != "active" {
			continue
		}
		coords = append(coords, SourceCoordinate{
			OrganizationID:        object.OrganizationID,
			SourceAuthorityID:     object.SourceAuthorityID,
			SourceArtifactClass:   object.SourceArtifactClass,
			SourceRefKind:         object.SourceRefKind,
			SourceStableReference: object.SourceStableReference,
			VersionCoordinate:     object.VersionCoordinate,
			SectionPath:           object.SectionPath,
			SourceContentHash:     object.SourceContentHash,
		})
		activeSourceIdentity[sourceEvidenceKey(object.SourceAuthorityID, object.SourceStableReference, object.VersionCoordinate, object.SourceContentHash)] = struct{}{}
	}
	// Preserve non-object authoring coordinates from selected complete source
	// sets (notably public-link inputs), but only while their source evidence
	// still names an active object. Legacy source sets may not have the v7
	// coordinate shape and are reconstructed from their active rows above.
	for _, seed := range selected {
		stored, decodeErr := SourceCoordinatesFromStoredSet(delta.Run.OrganizationID, seed.SourceSet)
		if decodeErr != nil {
			if seed.Profile == MaterializationProfileVersion {
				return MaterializationBatch{}, nil, fmt.Errorf("decode current-profile source_set for snapshot %q: %w", seed.SnapshotID, decodeErr)
			}
			continue
		}
		for _, coordinate := range stored {
			if coordinate.EdgeLabel == "" && coordinate.SymbolKind == "" {
				continue
			}
			if _, active := activeSourceIdentity[sourceEvidenceKey(coordinate.SourceAuthorityID, coordinate.SourceStableReference, coordinate.VersionCoordinate, coordinate.SourceContentHash)]; active {
				coords = append(coords, coordinate)
			}
		}
	}
	return complete, MergeSourceCoordinates(coords, deltaCoordinates), nil
}

func mergeExternalVerificationReceiptsForCompleteSnapshot(carried, delta []*stagedExternalVerificationReceipt, objects []GraphObject) ([]*stagedExternalVerificationReceipt, error) {
	activeExternal := make(map[string]GraphObject)
	for _, object := range objects {
		if object.Status != "active" {
			continue
		}
		if _, external := externalReferenceObjectClasses[object.ObjectClass]; external {
			activeExternal[externalVerificationReceiptObjectKey(object)] = object
		}
	}
	byObject := make(map[string]*stagedExternalVerificationReceipt, len(activeExternal))
	// Carried receipts establish the prior occurrence for unchanged rows;
	// delta receipts deliberately overlay them so exact-byte revalidation can
	// renew freshness without changing semantic object material.
	for _, group := range [][]*stagedExternalVerificationReceipt{carried, delta} {
		for _, receipt := range group {
			if err := validateStoredExternalVerificationReceiptShape(receipt); err != nil {
				return nil, err
			}
			key := externalVerificationReceiptSemanticKey(receipt)
			if _, active := activeExternal[key]; !active {
				continue
			}
			clone := *receipt
			byObject[key] = &clone
		}
	}
	if len(byObject) != len(activeExternal) {
		for key, object := range activeExternal {
			if byObject[key] == nil {
				return nil, fmt.Errorf("%w: object_class=%q source_stable_reference=%q version_coordinate=%q", ErrOODGraphExternalVerificationReceiptUnavailable, object.ObjectClass, object.SourceStableReference, object.VersionCoordinate)
			}
		}
	}
	out := make([]*stagedExternalVerificationReceipt, 0, len(byObject))
	for _, receipt := range byObject {
		out = append(out, receipt)
	}
	sort.Slice(out, func(i, j int) bool {
		return externalVerificationReceiptSemanticKey(out[i]) < externalVerificationReceiptSemanticKey(out[j])
	})
	return out, nil
}

func requireExactSealedCarryForwardCollisionMaterial(objects []GraphObject, symbols []GraphSymbol, edges []GraphEdge, delta MaterializationBatch) error {
	if _, err := mergeGraphObjectsByID(objects, delta.Objects); err != nil {
		return err
	}
	if _, err := mergeGraphSymbolsByID(symbols, delta.Symbols); err != nil {
		return err
	}
	if _, err := mergeGraphEdgesByID(edges, delta.Edges); err != nil {
		return err
	}
	return nil
}

func normalizeKnownLegacyProjectionRoles(ctx context.Context, objects []GraphObject, legacySnapshotIDs map[string]bool, kinds NodeKindRegistry) error {
	if kinds == nil {
		return fmt.Errorf("complete materialization requires node-kind authority before legacy projection-role normalization")
	}
	for i := range objects {
		desc, err := kinds.Resolve(ctx, objects[i].ObjectClass)
		if err != nil {
			return fmt.Errorf("carried object %q class registry: %w", objects[i].GraphObjectID, err)
		}
		current := desc.ProjectionRole()
		if objects[i].ProjectionRole == current {
			continue
		}
		if !legacySnapshotIDs[objects[i].GraphSnapshotID] {
			return fmt.Errorf("current-profile object %q projection_role=%q differs from registry role %q", objects[i].GraphObjectID, objects[i].ProjectionRole, current)
		}
		legacy := strings.Join(desc.Projections(), ",")
		if legacy == "" {
			legacy = "bootstrap_admission_vertex"
		}
		if objects[i].ProjectionRole != legacy {
			return fmt.Errorf("carried object %q projection_role=%q is neither current registry role %q nor the known legacy derivation %q", objects[i].GraphObjectID, objects[i].ProjectionRole, current, legacy)
		}
		// projection_role is graph-owned derived metadata. A successor may
		// rederive it under the current registry while leaving the prior sealed
		// row untouched; no source-owned identity or evidence is rewritten.
		objects[i].ProjectionRole = current
	}
	return nil
}

func refuseUnrepresentableCarriedArtifacts(ctx context.Context, queryer spannerStatementQueryer, projectionT, violationT, orgID string, snapshotIDs []string) error {
	if len(snapshotIDs) == 0 {
		return nil
	}
	for _, table := range []struct {
		name  string
		label string
	}{{projectionT, "projection"}, {violationT, "violation"}} {
		iter := queryer.Query(ctx, spanner.Statement{
			SQL:    fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE organization_id=@org AND graph_snapshot_id IN UNNEST(@snapshots)", table.name),
			Params: map[string]interface{}{"org": orgID, "snapshots": snapshotIDs},
		})
		row, err := iter.Next()
		if err != nil {
			iter.Stop()
			return fmt.Errorf("count carried %s artifacts: %w", table.label, err)
		}
		var count int64
		if err := row.Columns(&count); err != nil {
			iter.Stop()
			return fmt.Errorf("decode carried %s artifact count: %w", table.label, err)
		}
		iter.Stop()
		if count != 0 {
			return fmt.Errorf("%w: %d %s artifact(s) occur in selected snapshots %v", ErrOODGraphCompleteArtifactCarryForwardUnavailable, count, table.label, snapshotIDs)
		}
	}
	return nil
}

func canonicalObjectMaterial(object GraphObject) GraphObject {
	object.GraphSnapshotID = ""
	object.MaterializationRunID = ""
	object.CreatedAt = time.Time{}
	object.UpdatedAt = time.Time{}
	return object
}

func canonicalSymbolMaterial(symbol GraphSymbol) GraphSymbol {
	symbol.GraphSnapshotID = ""
	symbol.MaterializationRunID = ""
	symbol.CreatedAt = time.Time{}
	symbol.UpdatedAt = time.Time{}
	return symbol
}

func canonicalEdgeMaterial(edge GraphEdge) GraphEdge {
	edge.GraphSnapshotID = ""
	edge.MaterializationRunID = ""
	edge.CreatedAt = time.Time{}
	edge.UpdatedAt = time.Time{}
	return edge
}

func canonicalMaterialEqual(a, b interface{}) (bool, error) {
	aJSON, err := canonicalJSON(a)
	if err != nil {
		return false, fmt.Errorf("canonicalize first carry-forward row: %w", err)
	}
	bJSON, err := canonicalJSON(b)
	if err != nil {
		return false, fmt.Errorf("canonicalize second carry-forward row: %w", err)
	}
	return bytes.Equal(aJSON, bJSON), nil
}

func mergeGraphObjectsByID(groups ...[]GraphObject) (map[string]GraphObject, error) {
	out := make(map[string]GraphObject)
	for _, group := range groups {
		for _, object := range group {
			if prior, exists := out[object.GraphObjectID]; exists {
				equal, err := canonicalMaterialEqual(canonicalObjectMaterial(prior), canonicalObjectMaterial(object))
				if err != nil {
					return nil, fmt.Errorf("carry-forward graph_object_id collision %q: %w", object.GraphObjectID, err)
				}
				if !equal {
					return nil, fmt.Errorf("carry-forward graph_object_id collision %q has divergent canonical material fields", object.GraphObjectID)
				}
				continue
			}
			out[object.GraphObjectID] = object
		}
	}
	return out, nil
}

func mergeGraphSymbolsByID(groups ...[]GraphSymbol) (map[string]GraphSymbol, error) {
	out := make(map[string]GraphSymbol)
	for _, group := range groups {
		for _, symbol := range group {
			if prior, exists := out[symbol.SymbolID]; exists {
				equal, err := canonicalMaterialEqual(canonicalSymbolMaterial(prior), canonicalSymbolMaterial(symbol))
				if err != nil {
					return nil, fmt.Errorf("carry-forward symbol_id collision %q: %w", symbol.SymbolID, err)
				}
				if !equal {
					return nil, fmt.Errorf("carry-forward symbol_id collision %q has divergent canonical material fields", symbol.SymbolID)
				}
				continue
			}
			out[symbol.SymbolID] = symbol
		}
	}
	return out, nil
}

func mergeGraphEdgesByID(groups ...[]GraphEdge) (map[string]GraphEdge, error) {
	out := make(map[string]GraphEdge)
	for _, group := range groups {
		for _, edge := range group {
			if prior, exists := out[edge.GraphEdgeID]; exists {
				equal, err := canonicalMaterialEqual(canonicalEdgeMaterial(prior), canonicalEdgeMaterial(edge))
				if err != nil {
					return nil, fmt.Errorf("carry-forward graph_edge_id collision %q: %w", edge.GraphEdgeID, err)
				}
				if !equal {
					return nil, fmt.Errorf("carry-forward graph_edge_id collision %q has divergent canonical material fields", edge.GraphEdgeID)
				}
				continue
			}
			out[edge.GraphEdgeID] = edge
		}
	}
	return out, nil
}

func normalizeKnownLegacyReciprocityStates(edges []GraphEdge, legacySnapshotIDs map[string]bool) error {
	for i := range edges {
		if edges[i].ReciprocityState != "mirror_committed" {
			continue
		}
		if !legacySnapshotIDs[edges[i].GraphSnapshotID] {
			return fmt.Errorf("current-profile edge %q uses retired reciprocity_state mirror_committed", edges[i].GraphEdgeID)
		}
		// mirror_committed was the known pre-profile/8 writer literal for a
		// pair committed atomically. Reciprocity state is graph-derived row
		// metadata, so a complete successor may re-render that exact legacy
		// meaning as the v1 protocol literal `complete` without mutating the
		// prior sealed snapshot.
		edges[i].ReciprocityState = "complete"
	}
	return nil
}

func sourceEvidenceKey(authority, reference, version, digest string) string {
	return authority + "\x00" + reference + "\x00" + version + "\x00" + digest
}

func externalStableIdentityKey(object GraphObject) string {
	return object.ObjectClass + "\x00" + object.SourceAuthorityID + "\x00" + object.SourceRefKind + "\x00" + object.SourceStableReference + "\x00" + object.SectionPath
}

func rejectUnrepresentableExternalVersionRefresh(carried, delta []GraphObject) error {
	carriedByStable := make(map[string]GraphObject)
	for _, object := range carried {
		if _, external := externalReferenceObjectClasses[object.ObjectClass]; external {
			key := externalStableIdentityKey(object)
			if prior, duplicate := carriedByStable[key]; duplicate && !sameExternalVersionEvidence(prior, object) {
				return fmt.Errorf("%w: carried snapshots already contain external stable identity %q with conflicting version/digest/trust evidence", ErrOODGraphExternalVersionTransitionUnrepresentable, object.SourceStableReference)
			}
			carriedByStable[key] = object
		}
	}
	seenDelta := make(map[string]GraphObject)
	for _, object := range delta {
		if _, external := externalReferenceObjectClasses[object.ObjectClass]; !external {
			continue
		}
		key := externalStableIdentityKey(object)
		if prior, duplicate := seenDelta[key]; duplicate && !sameExternalVersionEvidence(prior, object) {
			return fmt.Errorf("%w: one batch supplies external stable identity %q with conflicting version/digest/trust evidence", ErrOODGraphExternalVersionTransitionUnrepresentable, object.SourceStableReference)
		}
		seenDelta[key] = object
		if prior, exists := carriedByStable[key]; exists && !sameExternalVersionEvidence(prior, object) {
			return fmt.Errorf("%w: external stable identity %q changes version/digest/trust evidence (%q/%q -> %q/%q); OOD §8/§9 requires temporal evidence but §6 currently forbids supersedes/superseded_by endpoints for external classes", ErrOODGraphExternalVersionTransitionUnrepresentable, object.SourceStableReference, prior.VersionCoordinate, prior.SourceContentHash, object.VersionCoordinate, object.SourceContentHash)
		}
	}
	return nil
}

func sameExternalVersionEvidence(a, b GraphObject) bool {
	return a.VersionCoordinate == b.VersionCoordinate &&
		a.SourceContentHash == b.SourceContentHash &&
		a.SourceContentHashOwner == b.SourceContentHashOwner &&
		a.SourceArtifactClass == b.SourceArtifactClass
}

func loadEligibleActiveCandidateSeeds(ctx context.Context, queryer spannerStatementQueryer, snapshotT, runT, orgID string) ([]eligibleSnapshotSeed, error) {
	stmt := spanner.Statement{
		SQL: fmt.Sprintf(`SELECT s.graph_snapshot_id, s.graph_version, s.source_set
FROM %s s
JOIN %s r
  ON r.organization_id=s.organization_id
 AND r.materialization_run_id=s.materialization_run_id
WHERE s.organization_id=@org
  AND s.snapshot_kind='active_candidate'
  AND s.snapshot_state='sealed'
  AND s.status='active'
  AND s.sealed_at IS NOT NULL
  AND r.target_graph_snapshot_id=s.graph_snapshot_id
  AND r.state='sealed'
  AND r.input_source_set_hash=s.source_set_hash
  AND r.finished_at IS NOT NULL
ORDER BY s.graph_version, s.graph_snapshot_id`, snapshotT, runT),
		Params: map[string]interface{}{"org": orgID},
	}
	iter := queryer.Query(ctx, stmt)
	defer iter.Stop()
	var out []eligibleSnapshotSeed
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("load eligible snapshot seeds: %w", err)
		}
		var seed eligibleSnapshotSeed
		var sourceSet spanner.NullJSON
		if err := row.Columns(&seed.SnapshotID, &seed.GraphVersion, &sourceSet); err != nil {
			return nil, fmt.Errorf("decode eligible snapshot seed: %w", err)
		}
		if sourceSet.Valid {
			if m := jsonValueToMap(sourceSet.Value); m != nil {
				seed.SourceSet = m
				seed.Profile, _ = m["materialization_profile_version"].(string)
			}
		}
		out = append(out, seed)
	}
	return out, nil
}

func latestOrganizationGraphVersion(ctx context.Context, queryer spannerStatementQueryer, snapshotT, orgID string) (int64, error) {
	iter := queryer.Query(ctx, spanner.Statement{
		SQL:    fmt.Sprintf("SELECT COALESCE(MAX(graph_version), 0) FROM %s WHERE organization_id=@org", snapshotT),
		Params: map[string]interface{}{"org": orgID},
	})
	defer iter.Stop()
	row, err := iter.Next()
	if err != nil {
		return 0, fmt.Errorf("read organization graph-version fence: %w", err)
	}
	var version int64
	if err := row.Columns(&version); err != nil {
		return 0, fmt.Errorf("decode organization graph-version fence: %w", err)
	}
	return version, nil
}

func selectCarryForwardSeeds(seeds []eligibleSnapshotSeed) []eligibleSnapshotSeed {
	latestComplete := -1
	for i, seed := range seeds {
		if seed.Profile == MaterializationProfileVersion {
			latestComplete = i
		}
	}
	if latestComplete < 0 {
		return append([]eligibleSnapshotSeed(nil), seeds...)
	}
	out := []eligibleSnapshotSeed{seeds[latestComplete]}
	for i := latestComplete + 1; i < len(seeds); i++ {
		out = append(out, seeds[i])
	}
	return out
}

func loadCarryForwardObjects(ctx context.Context, client spannerStatementQueryer, snapshotT, objectT, orgID string, snapshotIDs []string) ([]GraphObject, error) {
	if len(snapshotIDs) == 0 {
		return nil, nil
	}
	stmt := spanner.Statement{SQL: fmt.Sprintf(`SELECT s.graph_version,
o.organization_id, o.graph_snapshot_id, o.graph_object_id, o.object_class,
	o.api_element_role, o.api_element_role_locator_manifest_hash,
o.source_authority_id, o.source_artifact_class, o.source_ref_kind,
o.source_stable_reference, o.version_coordinate, o.section_path, o.graph_address,
o.source_content_hash, o.source_content_hash_owner, o.materialization_run_id,
o.projection_role, o.validation_state, o.status, o.visibility_scope,
o.search_text, o.search_payload, o.embedding, o.embedding_model
FROM %s o JOIN %s s
  ON s.organization_id=o.organization_id AND s.graph_snapshot_id=o.graph_snapshot_id
WHERE o.organization_id=@org AND o.graph_snapshot_id IN UNNEST(@snapshots)
  AND o.status='active'
ORDER BY s.graph_version, s.graph_snapshot_id, o.graph_object_id`, objectT, snapshotT), Params: map[string]interface{}{"org": orgID, "snapshots": snapshotIDs}}
	iter := client.Query(ctx, stmt)
	defer iter.Stop()
	byID := map[string]GraphObject{}
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("load carry-forward objects: %w", err)
		}
		var version int64
		var o GraphObject
		var apiRole, apiLocator, contentHash, contentOwner, searchText spanner.NullString
		var searchPayload spanner.NullJSON
		if err := row.Columns(&version, &o.OrganizationID, &o.GraphSnapshotID, &o.GraphObjectID, &o.ObjectClass, &apiRole, &apiLocator,
			&o.SourceAuthorityID, &o.SourceArtifactClass, &o.SourceRefKind, &o.SourceStableReference,
			&o.VersionCoordinate, &o.SectionPath, &o.GraphAddress, &contentHash, &contentOwner,
			&o.MaterializationRunID, &o.ProjectionRole, &o.ValidationState, &o.Status,
			&o.VisibilityScope, &searchText, &searchPayload, &o.Embedding, &o.EmbeddingModel); err != nil {
			return nil, fmt.Errorf("decode carry-forward object: %w", err)
		}
		o.SourceContentHash = contentHash.StringVal
		o.APIElementRole = apiRole.StringVal
		o.APIElementRoleLocatorManifestHash = apiLocator.StringVal
		o.SourceContentHashOwner = contentOwner.StringVal
		o.SearchText = searchText.StringVal
		if searchPayload.Valid {
			o.SearchPayload = jsonValueToMap(searchPayload.Value)
		}
		if prior, duplicate := byID[o.GraphObjectID]; duplicate {
			equal, compareErr := canonicalMaterialEqual(canonicalObjectMaterial(prior), canonicalObjectMaterial(o))
			if compareErr != nil {
				return nil, fmt.Errorf("carry-forward graph_object_id collision %q: %w", o.GraphObjectID, compareErr)
			}
			if !equal {
				return nil, fmt.Errorf("carry-forward graph_object_id collision %q has divergent canonical material fields across selected snapshots", o.GraphObjectID)
			}
			continue
		}
		byID[o.GraphObjectID] = o
	}
	out := make([]GraphObject, 0, len(byID))
	for _, o := range byID {
		out = append(out, o)
	}
	return out, nil
}

func loadCarryForwardSymbols(ctx context.Context, client spannerStatementQueryer, snapshotT, symbolT, orgID string, snapshotIDs []string) ([]GraphSymbol, error) {
	if len(snapshotIDs) == 0 {
		return nil, nil
	}
	stmt := spanner.Statement{SQL: fmt.Sprintf(`SELECT s.graph_version,
y.organization_id, y.graph_snapshot_id, y.symbol_id, y.graph_object_id,
y.object_class, y.symbol_kind, y.symbol_name, y.source_authority_id,
y.source_stable_reference, y.version_coordinate, y.section_path, y.graph_address,
y.materialization_run_id, y.validation_state, y.status, y.visibility_scope,
y.search_text, y.search_payload, y.embedding, y.embedding_model
FROM %s y JOIN %s s
  ON s.organization_id=y.organization_id AND s.graph_snapshot_id=y.graph_snapshot_id
WHERE y.organization_id=@org AND y.graph_snapshot_id IN UNNEST(@snapshots)
  AND y.status='active'
ORDER BY s.graph_version, s.graph_snapshot_id, y.symbol_id`, symbolT, snapshotT), Params: map[string]interface{}{"org": orgID, "snapshots": snapshotIDs}}
	iter := client.Query(ctx, stmt)
	defer iter.Stop()
	byID := map[string]GraphSymbol{}
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("load carry-forward symbols: %w", err)
		}
		var version int64
		var s GraphSymbol
		var searchText spanner.NullString
		var searchPayload spanner.NullJSON
		if err := row.Columns(&version, &s.OrganizationID, &s.GraphSnapshotID, &s.SymbolID, &s.GraphObjectID,
			&s.ObjectClass, &s.SymbolKind, &s.SymbolName, &s.SourceAuthorityID,
			&s.SourceStableReference, &s.VersionCoordinate, &s.SectionPath, &s.GraphAddress,
			&s.MaterializationRunID, &s.ValidationState, &s.Status, &s.VisibilityScope,
			&searchText, &searchPayload, &s.Embedding, &s.EmbeddingModel); err != nil {
			return nil, fmt.Errorf("decode carry-forward symbol: %w", err)
		}
		s.SearchText = searchText.StringVal
		if searchPayload.Valid {
			s.SearchPayload = jsonValueToMap(searchPayload.Value)
		}
		if prior, duplicate := byID[s.SymbolID]; duplicate {
			equal, compareErr := canonicalMaterialEqual(canonicalSymbolMaterial(prior), canonicalSymbolMaterial(s))
			if compareErr != nil {
				return nil, fmt.Errorf("carry-forward symbol_id collision %q: %w", s.SymbolID, compareErr)
			}
			if !equal {
				return nil, fmt.Errorf("carry-forward symbol_id collision %q has divergent canonical material fields across selected snapshots", s.SymbolID)
			}
			continue
		}
		byID[s.SymbolID] = s
	}
	out := make([]GraphSymbol, 0, len(byID))
	for _, s := range byID {
		out = append(out, s)
	}
	return out, nil
}

func loadCarryForwardEdges(ctx context.Context, client spannerStatementQueryer, snapshotT, edgeT, orgID string, snapshotIDs []string) ([]GraphEdge, error) {
	if len(snapshotIDs) == 0 {
		return nil, nil
	}
	stmt := spanner.Statement{SQL: fmt.Sprintf(`SELECT s.graph_version,
e.organization_id, e.graph_snapshot_id, e.graph_edge_id,
e.source_endpoint_kind, e.source_endpoint_id, e.source_endpoint_class,
e.target_endpoint_kind, e.target_endpoint_id, e.target_endpoint_class,
e.edge_label, e.edge_family, e.source_version_coordinate, e.target_version_coordinate,
e.authoring_source_path, e.source_authority_id, e.source_stable_reference,
e.source_content_hash, e.valid_from, e.valid_until, e.diagnostic_only,
e.reciprocity_state, e.inverse_edge_id, e.edge_confidence,
e.materialization_run_id, e.validation_state, e.status, e.visibility_scope,
e.search_text, e.search_payload, e.embedding, e.embedding_model
FROM %s e JOIN %s s
  ON s.organization_id=e.organization_id AND s.graph_snapshot_id=e.graph_snapshot_id
WHERE e.organization_id=@org AND e.graph_snapshot_id IN UNNEST(@snapshots)
  AND e.status='active'
ORDER BY s.graph_version, s.graph_snapshot_id, e.graph_edge_id`, edgeT, snapshotT), Params: map[string]interface{}{"org": orgID, "snapshots": snapshotIDs}}
	iter := client.Query(ctx, stmt)
	defer iter.Stop()
	byID := map[string]GraphEdge{}
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("load carry-forward edges: %w", err)
		}
		var version int64
		var e GraphEdge
		var contentHash, inverseID, searchText spanner.NullString
		var validFrom, validUntil spanner.NullTime
		var confidence spanner.NullFloat32
		var searchPayload spanner.NullJSON
		if err := row.Columns(&version, &e.OrganizationID, &e.GraphSnapshotID, &e.GraphEdgeID,
			&e.SourceEndpointKind, &e.SourceEndpointID, &e.SourceEndpointClass,
			&e.TargetEndpointKind, &e.TargetEndpointID, &e.TargetEndpointClass,
			&e.EdgeLabel, &e.EdgeFamily, &e.SourceVersionCoordinate, &e.TargetVersionCoordinate,
			&e.AuthoringSourcePath, &e.SourceAuthorityID, &e.SourceStableReference,
			&contentHash, &validFrom, &validUntil, &e.DiagnosticOnly, &e.ReciprocityState,
			&inverseID, &confidence, &e.MaterializationRunID, &e.ValidationState, &e.Status,
			&e.VisibilityScope, &searchText, &searchPayload, &e.Embedding, &e.EmbeddingModel); err != nil {
			return nil, fmt.Errorf("decode carry-forward edge: %w", err)
		}
		e.SourceContentHash = contentHash.StringVal
		if validFrom.Valid {
			t := validFrom.Time
			e.ValidFrom = &t
		}
		if validUntil.Valid {
			t := validUntil.Time
			e.ValidUntil = &t
		}
		e.InverseEdgeID = inverseID.StringVal
		if confidence.Valid {
			v := confidence.Float32
			e.EdgeConfidence = &v
		}
		e.SearchText = searchText.StringVal
		if searchPayload.Valid {
			e.SearchPayload = jsonValueToMap(searchPayload.Value)
		}
		if prior, duplicate := byID[e.GraphEdgeID]; duplicate {
			equal, compareErr := canonicalMaterialEqual(canonicalEdgeMaterial(prior), canonicalEdgeMaterial(e))
			if compareErr != nil {
				return nil, fmt.Errorf("carry-forward graph_edge_id collision %q: %w", e.GraphEdgeID, compareErr)
			}
			if !equal {
				return nil, fmt.Errorf("carry-forward graph_edge_id collision %q has divergent canonical material fields across selected snapshots", e.GraphEdgeID)
			}
			continue
		}
		byID[e.GraphEdgeID] = e
	}
	out := make([]GraphEdge, 0, len(byID))
	for _, e := range byID {
		out = append(out, e)
	}
	return out, nil
}

func validateCompleteMaterializationClosure(batch MaterializationBatch) error {
	objects := make(map[string]GraphObject, len(batch.Objects))
	addresses := make(map[string]string, len(batch.Objects))
	for _, object := range batch.Objects {
		if object.OrganizationID != batch.Run.OrganizationID || object.GraphSnapshotID != batch.Snapshot.GraphSnapshotID || object.MaterializationRunID != batch.Run.MaterializationRunID || object.Status != "active" {
			return fmt.Errorf("complete snapshot object %q has inconsistent organization/snapshot/run/status", object.GraphObjectID)
		}
		if prior, duplicate := addresses[object.GraphAddress]; duplicate && prior != object.GraphObjectID {
			return fmt.Errorf("complete snapshot graph_address %q maps to both %q and %q", object.GraphAddress, prior, object.GraphObjectID)
		}
		addresses[object.GraphAddress] = object.GraphObjectID
		objects[object.GraphObjectID] = object
	}
	for _, symbol := range batch.Symbols {
		owner, ok := objects[symbol.GraphObjectID]
		if !ok || owner.ObjectClass != symbol.ObjectClass {
			return fmt.Errorf("complete snapshot symbol %q has missing or class-mismatched owner %q", symbol.SymbolID, symbol.GraphObjectID)
		}
		if symbol.OrganizationID != batch.Run.OrganizationID || symbol.GraphSnapshotID != batch.Snapshot.GraphSnapshotID || symbol.MaterializationRunID != batch.Run.MaterializationRunID || symbol.Status != "active" {
			return fmt.Errorf("complete snapshot symbol %q has inconsistent organization/snapshot/run/status", symbol.SymbolID)
		}
	}
	edges := make(map[string]GraphEdge, len(batch.Edges))
	for _, edge := range batch.Edges {
		edges[edge.GraphEdgeID] = edge
		source, sourceOK := objects[edge.SourceEndpointID]
		target, targetOK := objects[edge.TargetEndpointID]
		if edge.SourceEndpointKind != "graph_object" || edge.TargetEndpointKind != "graph_object" || !sourceOK || !targetOK {
			return fmt.Errorf("complete snapshot edge %q has unresolved non-object endpoint", edge.GraphEdgeID)
		}
		if source.ObjectClass != edge.SourceEndpointClass || target.ObjectClass != edge.TargetEndpointClass || source.VersionCoordinate != edge.SourceVersionCoordinate || target.VersionCoordinate != edge.TargetVersionCoordinate {
			return fmt.Errorf("complete snapshot edge %q endpoint class/version evidence mismatch", edge.GraphEdgeID)
		}
		if edge.SourceAuthorityID != source.SourceAuthorityID || edge.SourceStableReference != source.SourceStableReference || edge.SourceContentHash != source.SourceContentHash {
			return fmt.Errorf("complete snapshot edge %q source evidence mismatch", edge.GraphEdgeID)
		}
		if edge.OrganizationID != batch.Run.OrganizationID || edge.GraphSnapshotID != batch.Snapshot.GraphSnapshotID || edge.MaterializationRunID != batch.Run.MaterializationRunID || edge.Status != "active" {
			return fmt.Errorf("complete snapshot edge %q has inconsistent organization/snapshot/run/status", edge.GraphEdgeID)
		}
	}
	for _, edge := range batch.Edges {
		if edge.InverseEdgeID != "" {
			inverse, ok := edges[edge.InverseEdgeID]
			if !ok || inverse.InverseEdgeID != edge.GraphEdgeID {
				return fmt.Errorf("complete snapshot edge %q has missing or asymmetric inverse %q", edge.GraphEdgeID, edge.InverseEdgeID)
			}
		}
	}
	return nil
}
