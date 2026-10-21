package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/vertexai"
	"github.com/wI2L/jsondiff"
)

// Env carries dependencies for every handler. Constructed in cmdMCP and
// passed by pointer.
type embeddingClient interface {
	Embed(context.Context, string, string) ([]float32, error)
}

const maxConcurrentExternalEmbeddings = 8

// One external item currently expands to object + metadata symbol + commonly
// an edge, each with a 3072-float vector, and complete snapshots clone that
// closure. Keep the bootstrap writer far below Spanner's 100 MiB commit cap.
// Exhaustive integration corpora stay fail-closed until the protocol admits
// immutable content rows, normalized snapshot membership/receipt manifests,
// and a compact publication-head CAS.
// The pre-I/O delta gate must never advertise a larger envelope than the
// final complete-snapshot gate. An external object always emits an object and
// metadata-symbol row, so this also refuses a 129-object delta before any
// future permission-evidence/source retrieval or embedding work can begin.
const maxExternalObjectsPerBootstrapMaterialization = maxCompleteExternalBootstrapVectorRows / 2
const maxVectorRowsPerExternalBootstrapMaterialization = maxCompleteExternalBootstrapVectorRows

func buildCompletePublisherSourceSet(orgID string, coordinates []SourceCoordinate, batch MaterializationBatch) (map[string]interface{}, error) {
	return BuildSourceSetWithExternalReceipts(orgID, coordinates, batch.ExternalVerificationReceipts)
}

func validateExternalBootstrapPublicationEnvelope(submissions []ArtifactSubmission, policies []ExternalSourceDescriptor, relationshipCount int) error {
	if len(submissions) != len(policies) || relationshipCount < 0 {
		return fmt.Errorf("external bootstrap publication envelope cardinality mismatch")
	}
	externalCount := 0
	vectorRows := len(submissions) + relationshipCount // one object + one edge vector per row
	for i, policy := range policies {
		if policy.ID != "" {
			externalCount++
			vectorRows++ // one metadata symbol per external object
			continue
		}
		vectorRows += estimatedExtractedSymbolCount(submissions[i].Contract)
		vectorRows += estimatedExtractedSymbolCount(submissions[i].Payload)
	}
	if externalCount == 0 {
		return nil
	}
	if externalCount > maxExternalObjectsPerBootstrapMaterialization {
		return fmt.Errorf("%w: external objects=%d exceeds bootstrap ceiling=%d; exhaustive corpora require normalized immutable publication", ErrOODGraphMaterializationScaleUnrepresentable, externalCount, maxExternalObjectsPerBootstrapMaterialization)
	}
	if vectorRows > maxVectorRowsPerExternalBootstrapMaterialization {
		return fmt.Errorf("%w: estimated object+symbol+relationship vector rows=%d exceeds external-bootstrap ceiling=%d", ErrOODGraphMaterializationScaleUnrepresentable, vectorRows, maxVectorRowsPerExternalBootstrapMaterialization)
	}
	return nil
}

func estimatedExtractedSymbolCount(value interface{}) int {
	switch typed := value.(type) {
	case nil:
		return 0
	case map[string]interface{}:
		count := 1 // nested_object marker
		for _, child := range typed {
			count += estimatedExtractedSymbolCount(child)
			if count > maxVectorRowsPerExternalBootstrapMaterialization {
				return count
			}
		}
		return count
	case []interface{}:
		count := 0
		for _, child := range typed {
			count += estimatedExtractedSymbolCount(child)
			if count > maxVectorRowsPerExternalBootstrapMaterialization {
				return count
			}
		}
		return count
	case string, float64, bool:
		return 1
	default:
		// Programmatic callers can construct values JSON decoding never emits.
		// Treat an unknown value as over-limit rather than undercounting it.
		return maxVectorRowsPerExternalBootstrapMaterialization + 1
	}
}

func embedExternalObjectsBounded(ctx context.Context, env *Env, objects []GraphObject, canonicalNames []string, policies []ExternalSourceDescriptor) error {
	if len(objects) != len(canonicalNames) || len(objects) != len(policies) {
		return fmt.Errorf("external embedding input cardinality mismatch")
	}
	indices := make([]int, 0, len(objects))
	for i, policy := range policies {
		if policy.ID != "" {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		return nil
	}
	if env == nil || env.Embed == nil {
		return fmt.Errorf("external-reference ingestion requires a configured embedding client")
	}
	limit := maxConcurrentExternalEmbeddings
	if len(indices) < limit {
		limit = len(indices)
	}
	jobs := make(chan int)
	errs := make([]error, len(objects))
	var wg sync.WaitGroup
	for worker := 0; worker < limit; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				vec, err := env.Embed.Embed(ctx, objects[i].SearchText, vertexai.TaskTypeRetrievalDocument)
				if err != nil {
					errs[i] = fmt.Errorf("embed external object %q: %w", canonicalNames[i], err)
					continue
				}
				if len(vec) != externalReferenceEmbeddingDimensions {
					errs[i] = fmt.Errorf("embed external object %q: got %d dimensions, want %d", canonicalNames[i], len(vec), externalReferenceEmbeddingDimensions)
					continue
				}
				objects[i].Embedding = vec
			}
		}()
	}
	for _, i := range indices {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	// Arrival order is irrelevant; report the lowest submission index so the
	// same inputs produce the same failure even when RPC completion reorders.
	for _, i := range indices {
		if errs[i] != nil {
			return errs[i]
		}
	}
	return nil
}

type Env struct {
	Config            SpecGraphConfig
	Kinds             NodeKindRegistry
	Edges             EdgeLabelRegistry
	Projections       ProjectionRegistry
	Substrates        SubstrateRouter
	Embed             embeddingClient // nil when Config.Embedding is unset
	ExternalFetch     externalReferenceFetcher
	ExternalAuthorize externalSourceAuthorizationResolver
	ExternalArchive   externalEvidenceArchive
	Now               func() time.Time
}

// ---------------- typed inputs (one per verb) ----------------

type useInput struct {
	SnapshotID string `json:"snapshot_id,omitempty" jsonschema:"retired compatibility argument; pass graph_snapshot_id directly on each typed historical read"`
}

type createInput struct {
	NodeKind string `json:"node_kind" jsonschema:"projection-axis kind: section | symbol | sentinel | invariant | assumption | config | circuit | doc_object | decision | ..."`
	StableID string `json:"stable_id,omitempty" jsonschema:"omit to mint a new id; provide to re-admit at v_N+1 under the same id"`
	// Contract / Payload are typed as map[string]interface{} so the MCP
	// inputSchema reflects to {"type":"object","additionalProperties":true}
	// — the canonical "any JSON object" shape Claude Code accepts.
	// Plain interface{} reflects to bare boolean `true`, which strict MCP
	// clients reject.
	Contract      map[string]interface{} `json:"contract" jsonschema:"the stable surface this node promises"`
	Payload       map[string]interface{} `json:"payload" jsonschema:"kind-specific body"`
	ParentRef     string                 `json:"parent_ref,omitempty"`
	GoverningSpec string                 `json:"governing_spec,omitempty"`
	SpecSection   string                 `json:"spec_section,omitempty"`

	// AcknowledgeDistinctFrom carries node_ids the caller has examined and
	// confirmed are NOT duplicates of the proposed node. Used to override
	// Layer-3 (embedding-similarity) dedup when the proposed node really
	// is a distinct concept that happens to be semantically close to an
	// existing one. On the first create call the caller leaves this empty;
	// if the gate refuses with ErrPossibleDuplicate, the caller inspects
	// the returned candidates (via spec_graph_get), confirms distinctness,
	// re-submits with each candidate node_id added here. Layer-1 (definition
	// hash) and Layer-2 (canonical_name) cannot be acknowledged — those are
	// hard collisions that require update / rename / different design.
	AcknowledgeDistinctFrom []string `json:"acknowledge_distinct_from,omitempty" jsonschema:"node_ids the caller has examined and confirmed are not duplicates of the proposed node — bypasses Layer-3 similarity dedup for those specific candidates"`
}

type updateInput struct {
	NodeID   string                 `json:"node_id" jsonschema:"stable id of the node to re-admit"`
	Contract map[string]interface{} `json:"contract" jsonschema:"the stable surface this node promises — MUST be byte-equivalent to the prior version per node_version_chain_axiom"`
	Payload  map[string]interface{} `json:"payload" jsonschema:"kind-specific body"`
}

type archiveInput struct {
	NodeID string `json:"node_id"`
}

type linkInput struct {
	SourceID  string `json:"source_id"`
	TargetID  string `json:"target_id"`
	EdgeLabel string `json:"edge_label" jsonschema:"closed-registry edge label"`
}

type unlinkInput struct {
	EdgeID string `json:"edge_id"`
}

// archiveEdgeInput is the typed input for spec_graph_edge_archive.
// EdgeID accepts either the primary edge's graph_edge_id or its mirror's
// — when the edge declares reciprocity, the resolver finds both endpoints
// from either end and archives the pair atomically.
type archiveEdgeInput struct {
	EdgeID string `json:"edge_id" jsonschema:"graph_edge_id (UUIDv5 from edge identity tuple) to archive; either end of a reciprocal pair is accepted — the mirror is archived in the same transaction"`
}

// archiveNodeInput is the typed input for spec_graph_node_archive.
// graph_object_id names the OODGraphObjects row to flip to status='archived'.
type archiveNodeInput struct {
	GraphObjectID string `json:"graph_object_id" jsonschema:"OODGraphObjects.graph_object_id to archive; verb refuses if active incoming edges exist (caller must spec_graph_edge_archive those first)"`
}

type getInput struct {
	NodeID  string `json:"node_id"`
	Version string `json:"version,omitempty"`
}

type listInput struct {
	NodeKind string `json:"node_kind,omitempty"`
	Status   string `json:"status,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type searchInput struct {
	Query    string `json:"query"`
	NodeKind string `json:"node_kind,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type neighborsInput struct {
	NodeID     string   `json:"node_id"`
	Depth      int      `json:"depth,omitempty"`
	EdgeLabels []string `json:"edge_labels,omitempty"`
	Direction  string   `json:"direction,omitempty"`
}

type closureInput struct {
	NodeID         string `json:"node_id"`
	ClosureProfile string `json:"closure_profile"`
	MaxDepth       int    `json:"max_depth"`
	ResultCap      int    `json:"result_cap"`
}

type impactInput struct {
	NodeID    string `json:"node_id"`
	MaxDepth  int    `json:"max_depth"`
	ResultCap int    `json:"result_cap"`
}

type historyInput struct {
	NodeID string `json:"node_id"`
}

type diffInput struct {
	NodeID   string `json:"node_id"`
	VersionA string `json:"version_a"`
	VersionB string `json:"version_b"`
}

type projectInput struct {
	NodeID     string `json:"node_id"`
	Projection string `json:"projection"`
}

type queryInput struct {
	SQL    string                 `json:"sql" jsonschema:"GoogleSQL or GQL query — READ-ONLY; SELECT/GRAPH_TABLE/MATCH only"`
	Params map[string]interface{} `json:"params,omitempty"`
}

type importInput struct {
	Submissions      []ArtifactSubmission   `json:"submissions,omitempty"`
	Relationships    []ExternalRelationship `json:"relationships,omitempty" jsonschema:"typed external-reference edges resolved only against submissions in this same materialization batch"`
	FilePath         string                 `json:"file_path,omitempty" jsonschema:"alternative to submissions: path to a JSON file containing the submissions array, OR a directory whose *.json files are loaded in name order. Leading-underscore filenames (e.g. _edges.json, _findings.json) are skipped — they are author/validator artifacts, not submissions."`
	StagingPromotion *stagingPromotionPlan  `json:"-"`
}

type stagingPromotionPlan struct {
	IngestionRunID    string
	ConceptStagingIDs []string
	EdgeStagingIDs    []string
	ExternalReceipts  []*stagedExternalVerificationReceipt
}

type healthInput struct{}

// ---------------- handler bodies ----------------

func handleUse(_ context.Context, _ *Env, in useInput) (Snapshot, error) {
	return Snapshot{}, fmt.Errorf("spec_graph_use cannot create an implicit pin on stateless HTTP; pass graph_snapshot_id=%q explicitly on every historical read, or omit it to derive the current eligible snapshot", in.SnapshotID)
}

func handleCreate(ctx context.Context, env *Env, in createInput) (AdmissionRecord, error) {
	if in.NodeKind == "" {
		return AdmissionRecord{}, fmt.Errorf("node_kind required")
	}
	desc, err := env.Kinds.Resolve(ctx, in.NodeKind)
	if err != nil {
		return AdmissionRecord{}, err
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return AdmissionRecord{}, err
	}
	sub := ArtifactSubmission{
		ArtifactType:   desc.ArtifactType(),
		OrganizationID: orgID,
		NodeKind:       in.NodeKind,
		StableID:       in.StableID,
		Contract:       in.Contract,
		Payload:        in.Payload,
		GoverningSpec:  in.GoverningSpec,
		SpecSection:    in.SpecSection,
	}
	// Pre-admission dedup gate. Runs Layer 1 (definition_hash) →
	// Layer 2 (canonical_name) → Layer 3 (embedding similarity) BEFORE
	// the ceremony writes any row. Skipped entirely when env.Config.Dedup
	// is nil. See dedup.go for the layer design.
	if idempotent, err := runDedupGate(ctx, env, sub, in.AcknowledgeDistinctFrom); err != nil {
		return AdmissionRecord{}, err
	} else if idempotent != nil {
		return *idempotent, nil
	}
	return AdmitArtifact(ctx, env, sub)
}

func handleUpdate(ctx context.Context, env *Env, in updateInput) (AdmissionRecord, error) {
	if in.NodeID == "" {
		return AdmissionRecord{}, fmt.Errorf("node_id required")
	}
	prior, err := readNodeAcrossSubstrates(ctx, env, in.NodeID, "", "")
	if err != nil {
		return AdmissionRecord{}, fmt.Errorf("read prior version: %w", err)
	}
	// Contract monotonicity is universal per node_version_chain_axiom — every
	// re-admission's contract must be byte-equivalent to the prior version's
	// (only payload may change). Enforced in every mode, including
	// experimental_bootstrap.
	if err := validateContractMonotonicity(prior.CurrentVersion.Contract, in.Contract); err != nil {
		return AdmissionRecord{}, err
	}
	desc, err := env.Kinds.Resolve(ctx, prior.NodeKind)
	if err != nil {
		return AdmissionRecord{}, err
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return AdmissionRecord{}, err
	}
	sub := ArtifactSubmission{
		ArtifactType:   desc.ArtifactType(),
		OrganizationID: orgID,
		NodeKind:       prior.NodeKind,
		StableID:       in.NodeID,
		Contract:       in.Contract,
		Payload:        in.Payload,
		PriorVersion:   &prior.CurrentVersion,
	}
	return AdmitArtifact(ctx, env, sub)
}

func handleArchive(ctx context.Context, env *Env, in archiveInput) (AdmissionRecord, error) {
	if in.NodeID == "" {
		return AdmissionRecord{}, fmt.Errorf("node_id required")
	}
	prior, err := readNodeAcrossSubstrates(ctx, env, in.NodeID, "", "")
	if err != nil {
		return AdmissionRecord{}, err
	}
	// Dangling-closure check: refuse to archive a node with active dependents.
	if err := checkDanglingClosure(ctx, env, in.NodeID); err != nil {
		return AdmissionRecord{}, err
	}
	desc, err := env.Kinds.Resolve(ctx, prior.NodeKind)
	if err != nil {
		return AdmissionRecord{}, err
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return AdmissionRecord{}, err
	}
	sub := ArtifactSubmission{
		ArtifactType:   desc.ArtifactType(),
		OrganizationID: orgID,
		NodeKind:       prior.NodeKind,
		StableID:       in.NodeID,
		PriorVersion:   &prior.CurrentVersion,
		IsRetirement:   true,
	}
	return AdmitArtifact(ctx, env, sub)
}

// handleLink publishes one typed edge (and its reciprocal mirror, when
// required) as a complete immutable successor snapshot. Endpoints resolve
// only from the rows carried into that same successor.
func handleLink(ctx context.Context, env *Env, in linkInput) (AdmissionRecord, error) {
	if in.SourceID == "" || in.TargetID == "" || in.EdgeLabel == "" {
		return AdmissionRecord{}, fmt.Errorf("source_id, target_id, edge_label required")
	}
	desc, err := env.Edges.Resolve(ctx, in.EdgeLabel)
	if err != nil {
		return AdmissionRecord{}, err
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return AdmissionRecord{}, err
	}
	all, err := env.Substrates.All(ctx)
	if err != nil {
		return AdmissionRecord{}, err
	}
	if len(all) == 0 {
		return AdmissionRecord{}, fmt.Errorf("no substrates registered")
	}

	now := env.Now().UTC()
	runID := uuid.NewString()
	snapshotID := uuid.NewString()
	visibility := "organization"
	delta := MaterializationBatch{
		Run: MaterializationRun{
			OrganizationID:       orgID,
			MaterializationRunID: runID,
			RunKind:              "corpus_refresh",
			State:                "running",
			StartedAt:            now,
			Status:               "active",
			VisibilityScope:      visibility,
		},
		Snapshot: GraphSnapshot{
			OrganizationID:  orgID,
			GraphSnapshotID: snapshotID,
			SnapshotKind:    "active_candidate",
			SnapshotState:   "building",
			Status:          "active",
			VisibilityScope: visibility,
		},
	}

	// Edge-only active_candidate snapshots are forbidden. Find the unique
	// OOD adapter whose complete carry-forward contains both endpoints.
	var adapter SubstrateAdapter
	var batch MaterializationBatch
	var coords []SourceCoordinate
	var checked []string
	for _, candidate := range all {
		preparer, ok := candidate.(CompleteMaterializationPreparer)
		if !ok {
			continue
		}
		if err := candidate.CheckOODGraphSchema(ctx); err != nil {
			checked = append(checked, fmt.Sprintf("%s: %v", candidate.ID(), err))
			continue
		}
		prepared, preparedCoords, err := preparer.PrepareCompleteMaterialization(ctx, delta, nil, materializationValidationAuthority(env))
		if err != nil {
			checked = append(checked, fmt.Sprintf("%s: %v", candidate.ID(), err))
			continue
		}
		hasSource, hasTarget := false, false
		for _, object := range prepared.Objects {
			hasSource = hasSource || object.GraphObjectID == in.SourceID
			hasTarget = hasTarget || object.GraphObjectID == in.TargetID
		}
		if !hasSource || !hasTarget {
			checked = append(checked, fmt.Sprintf("%s: endpoint absent", candidate.ID()))
			continue
		}
		if adapter != nil {
			return AdmissionRecord{}, fmt.Errorf("link endpoints resolve in more than one complete OOD substrate")
		}
		adapter, batch, coords = candidate, prepared, preparedCoords
	}
	if adapter == nil {
		return AdmissionRecord{}, fmt.Errorf("link endpoints do not resolve together in a complete OOD snapshot (checked=%v)", checked)
	}

	pending := PendingEdge{
		SourceEndpointID:    in.SourceID,
		TargetEndpointID:    in.TargetID,
		Label:               desc,
		AuthoringSourcePath: "$",
		VisibilityScope:     visibility,
	}
	if mirrorLabel := desc.ReciprocalLabel(); mirrorLabel != "" {
		mirrorDesc, err := env.Edges.Resolve(ctx, mirrorLabel)
		if err != nil {
			return AdmissionRecord{}, fmt.Errorf("resolve reciprocal label %q: %w", mirrorLabel, err)
		}
		pending.MirrorLabel = mirrorDesc
		pending.HasMirror = true
	}
	newEdges, violations := ResolveEdgeEndpointsInBatch(orgID, runID, snapshotID, batch.Objects, []PendingEdge{pending})
	if len(violations) != 0 || len(newEdges) == 0 {
		return AdmissionRecord{}, fmt.Errorf("link endpoint/registry validation rejected %d fact(s)", len(violations))
	}

	// A repeated link call reuses the stable edge identity already carried
	// into the successor; it never appends a duplicate row inside one snapshot.
	existingEdges := make(map[string]struct{}, len(batch.Edges))
	for _, edge := range batch.Edges {
		existingEdges[edge.GraphEdgeID] = struct{}{}
	}
	for _, edge := range newEdges {
		if _, exists := existingEdges[edge.GraphEdgeID]; exists {
			continue
		}
		batch.Edges = append(batch.Edges, edge)
		existingEdges[edge.GraphEdgeID] = struct{}{}
	}
	sort.Slice(batch.Edges, func(i, j int) bool { return batch.Edges[i].GraphEdgeID < batch.Edges[j].GraphEdgeID })
	authority := materializationValidationAuthority(env)
	if err := ensureChangedRowEmbeddings(ctx, &batch, MaterializationBatch{Edges: newEdges}, authority); err != nil {
		return AdmissionRecord{}, err
	}
	edgeCoords, err := SourceCoordinatesFromRows(batch.Objects, nil, newEdges)
	if err != nil {
		return AdmissionRecord{}, err
	}
	coords = MergeSourceCoordinates(coords, edgeCoords)
	if err := validateCompleteMaterializationRows(ctx, batch, authority); err != nil {
		return AdmissionRecord{}, fmt.Errorf("validate complete link successor: %w", err)
	}
	sourceSetHash, err := ComputeSourceSetHash(orgID, coords)
	if err != nil {
		return AdmissionRecord{}, err
	}
	sourceSet, err := buildCompletePublisherSourceSet(orgID, coords, batch)
	if err != nil {
		return AdmissionRecord{}, err
	}
	batch.Snapshot.SourceSetHash = sourceSetHash
	batch.Snapshot.SourceSet = sourceSet
	batch.Run.InputSourceSetHash = sourceSetHash
	batch.Run.InputSourceSet = sourceSet
	if err := validateCompleteExternalBootstrapPublicationEnvelope(batch); err != nil {
		return AdmissionRecord{}, err
	}

	if err := adapter.OpenMaterializationRun(ctx, batch.Run); err != nil {
		return AdmissionRecord{}, err
	}
	if err := adapter.CommitMaterializationRun(ctx, batch); err != nil {
		if fErr := adapter.FailMaterializationRun(ctx, orgID, runID); fErr != nil {
			return AdmissionRecord{}, fmt.Errorf("commit edge admission: %w (and marking run failed: %v)", err, fErr)
		}
		return AdmissionRecord{}, fmt.Errorf("commit edge admission: %w", err)
	}

	return AdmissionRecord{
		RunID:          runID,
		ArtifactType:   "edge",
		OrganizationID: orgID,
		ArtifactID:     newEdges[0].GraphEdgeID,
		AdmittedAt:     now,
		AdmittedBy:     env.Config.ExperimentalAdmitter,
	}, nil
}

// validateEdgeEndpointClasses checks the edge label's source/target class
// restrictions + self-loop policy. Mirrors validateEdgeEndpoints (which
// took the legacy Node struct) but works against object_class strings
// from OODGraphObjects.
func validateEdgeEndpointClasses(desc EdgeLabelDescriptor, srcID, srcClass, tgtID, tgtClass string) error {
	if srcKinds := desc.SourceKinds(); len(srcKinds) == 0 || !containsString(srcKinds, srcClass) {
		return fmt.Errorf("%w: edge_label=%q source_id=%q has object_class=%q, allowed source_kinds=%v",
			ErrEdgeKindMismatch, desc.Name(), srcID, srcClass, srcKinds)
	}
	if tgtKinds := desc.TargetKinds(); len(tgtKinds) == 0 || !containsString(tgtKinds, tgtClass) {
		return fmt.Errorf("%w: edge_label=%q target_id=%q has object_class=%q, allowed target_kinds=%v",
			ErrEdgeKindMismatch, desc.Name(), tgtID, tgtClass, tgtKinds)
	}
	if desc.ForbidSelfLoops() && srcID == tgtID {
		return fmt.Errorf("%w: edge_label=%q source_id=target_id=%q",
			ErrEdgeSelfLoopForbidden, desc.Name(), srcID)
	}
	return nil
}

// handleArchiveEdge is a compatibility surface that fails closed. OOD v1
// requires retirement to publish a later complete immutable snapshot, while
// its current closed edge/class grammar cannot yet express that successor
// for every row class. The substrate therefore refuses before database I/O;
// prior sealed snapshots are never rewritten.
func handleArchiveEdge(ctx context.Context, env *Env, in archiveEdgeInput) (EdgeArchiveResult, error) {
	if in.EdgeID == "" {
		return EdgeArchiveResult{}, fmt.Errorf("edge_id required")
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return EdgeArchiveResult{}, err
	}
	admitter := env.Config.ExperimentalAdmitter
	if admitter == "" {
		admitter = env.Config.GenesisAdmitter
	}
	if admitter == "" {
		return EdgeArchiveResult{}, fmt.Errorf("experimental_admitter or genesis_admitter required for audit_record.principal_stable_id")
	}
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		return EdgeArchiveResult{}, err
	}
	if len(adapters) == 0 {
		return EdgeArchiveResult{}, fmt.Errorf("no substrates registered")
	}
	return adapters[0].ArchiveEdge(ctx, orgID, in.EdgeID, admitter)
}

// handleArchiveNode has the same immutable fail-closed contract as
// handleArchiveEdge. It remains registered so callers receive the typed
// protocol sentinel rather than falling back to an unsafe mutation path.
// It emits no row and performs no database access.
func handleArchiveNode(ctx context.Context, env *Env, in archiveNodeInput) (NodeArchiveResult, error) {
	if in.GraphObjectID == "" {
		return NodeArchiveResult{}, fmt.Errorf("graph_object_id required")
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return NodeArchiveResult{}, err
	}
	admitter := env.Config.ExperimentalAdmitter
	if admitter == "" {
		admitter = env.Config.GenesisAdmitter
	}
	if admitter == "" {
		return NodeArchiveResult{}, fmt.Errorf("experimental_admitter or genesis_admitter required for audit_record.principal_stable_id")
	}
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		return NodeArchiveResult{}, err
	}
	if len(adapters) == 0 {
		return NodeArchiveResult{}, fmt.Errorf("no substrates registered")
	}
	return adapters[0].ArchiveNode(ctx, orgID, in.GraphObjectID, admitter)
}

func handleUnlink(ctx context.Context, env *Env, in unlinkInput) (AdmissionRecord, error) {
	if in.EdgeID == "" {
		return AdmissionRecord{}, fmt.Errorf("edge_id required")
	}
	// Read the existing edge first so the retirement submission carries the
	// edge_label + endpoints + versions the ceremony needs to route and audit.
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		return AdmissionRecord{}, err
	}
	var existing Edge
	var found bool
	for _, a := range adapters {
		e, err := a.ReadEdge(ctx, in.EdgeID, "")
		if err == nil {
			existing = e
			found = true
			break
		}
	}
	if !found {
		return AdmissionRecord{}, fmt.Errorf("edge %q not found in any substrate", in.EdgeID)
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return AdmissionRecord{}, err
	}
	sub := ArtifactSubmission{
		ArtifactType:      "edge",
		OrganizationID:    orgID,
		EdgeLabel:         existing.EdgeLabel,
		EdgeSourceID:      existing.SourceID,
		EdgeSourceVersion: existing.SourceVersion,
		EdgeTargetID:      existing.TargetID,
		EdgeTargetVersion: existing.TargetVersion,
		StableID:          in.EdgeID,
		IsRetirement:      true,
	}
	return AdmitArtifact(ctx, env, sub)
}

func handleGet(ctx context.Context, env *Env, in getInput, snapshotID string) (Node, error) {
	return readNodeAcrossSubstrates(ctx, env, in.NodeID, in.Version, snapshotID)
}

func handleList(ctx context.Context, env *Env, in listInput, snapshotID string) (NodeListResult, error) {
	if in.Status == "" {
		in.Status = "active"
	}
	if in.Limit <= 0 {
		in.Limit = 50
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return NodeListResult{}, err
	}
	filter := ListFilter{
		NodeKind:       in.NodeKind,
		Status:         in.Status,
		OrganizationID: orgID,
		SnapshotID:     snapshotID,
		Limit:          in.Limit,
	}
	if in.NodeKind != "" {
		desc, err := env.Kinds.Resolve(ctx, in.NodeKind)
		if err != nil {
			return NodeListResult{}, err
		}
		adapter, err := env.Substrates.Adapter(ctx, desc)
		if err != nil {
			return NodeListResult{}, err
		}
		ns, err := adapter.ListNodes(ctx, filter)
		return NodeListResult{Nodes: ns}, err
	}
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		return NodeListResult{}, err
	}
	out := NodeListResult{}
	for _, a := range adapters {
		ns, err := a.ListNodes(ctx, filter)
		if err != nil {
			return out, fmt.Errorf("substrate %q list: %w", a.ID(), err)
		}
		out.Nodes = append(out.Nodes, ns...)
	}
	return out, nil
}

func handleSearch(ctx context.Context, env *Env, in searchInput) (NodeListResult, error) {
	if in.Query == "" {
		return NodeListResult{}, fmt.Errorf("query required")
	}
	if env.Embed == nil {
		return NodeListResult{}, fmt.Errorf("embedding not configured — set Config.Embedding in spec-graph.config.json to enable spec_graph_search")
	}
	vec, err := env.Embed.Embed(ctx, in.Query, vertexai.TaskTypeRetrievalQuery)
	if err != nil {
		return NodeListResult{}, fmt.Errorf("embed query: %w", err)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 15
	}
	// Bootstrap routes all reads to the single substrate.
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		return NodeListResult{}, err
	}
	if len(adapters) == 0 {
		return NodeListResult{}, fmt.Errorf("no substrates registered")
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return NodeListResult{}, err
	}
	nodes, err := adapters[0].SearchByEmbedding(ctx, vec, in.NodeKind, limit, orgID)
	if err != nil {
		return NodeListResult{}, err
	}
	return NodeListResult{Nodes: nodes}, nil
}

func handleNeighbors(ctx context.Context, env *Env, in neighborsInput, snapshotID string) (EdgeListResult, error) {
	if in.NodeID == "" {
		return EdgeListResult{}, fmt.Errorf("node_id required")
	}
	if in.Direction == "" {
		in.Direction = "both"
	}
	if in.Depth <= 0 {
		in.Depth = 1
	}
	prior, err := readNodeAcrossSubstrates(ctx, env, in.NodeID, "", snapshotID)
	if err != nil {
		return EdgeListResult{}, err
	}
	desc, err := env.Kinds.Resolve(ctx, prior.NodeKind)
	if err != nil {
		return EdgeListResult{}, err
	}
	adapter, err := env.Substrates.Adapter(ctx, desc)
	if err != nil {
		return EdgeListResult{}, err
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return EdgeListResult{}, err
	}
	edges, err := adapter.Neighbors(ctx, in.NodeID, NeighborOpts{
		Direction:      in.Direction,
		EdgeLabels:     in.EdgeLabels,
		Depth:          in.Depth,
		SnapshotID:     snapshotID,
		OrganizationID: orgID,
	})
	return EdgeListResult{Edges: edges}, err
}

func handleClosure(ctx context.Context, env *Env, in closureInput) (NodeListResult, error) {
	if in.NodeID == "" {
		return NodeListResult{}, fmt.Errorf("node_id required")
	}
	if in.MaxDepth <= 0 {
		in.MaxDepth = 3
	}
	if in.ResultCap <= 0 {
		in.ResultCap = 100
	}
	labels, err := resolveClosureProfile(ctx, env, in.ClosureProfile)
	if err != nil {
		return NodeListResult{}, err
	}
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		return NodeListResult{}, err
	}
	if len(adapters) == 0 {
		return NodeListResult{}, fmt.Errorf("no substrates registered")
	}
	nodes, err := adapters[0].TraverseClosure(ctx, in.NodeID, labels, in.MaxDepth, in.ResultCap, "forward")
	return NodeListResult{Nodes: nodes}, err
}

func handleImpact(ctx context.Context, env *Env, in impactInput) (NodeListResult, error) {
	if in.NodeID == "" {
		return NodeListResult{}, fmt.Errorf("node_id required")
	}
	if in.MaxDepth <= 0 {
		in.MaxDepth = 3
	}
	if in.ResultCap <= 0 {
		in.ResultCap = 100
	}
	// Impact = all edge labels, reverse direction.
	all, err := env.Edges.All(ctx)
	if err != nil {
		return NodeListResult{}, err
	}
	labels := make([]string, 0, len(all))
	for _, l := range all {
		labels = append(labels, l.Name())
	}
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		return NodeListResult{}, err
	}
	if len(adapters) == 0 {
		return NodeListResult{}, fmt.Errorf("no substrates registered")
	}
	nodes, err := adapters[0].TraverseClosure(ctx, in.NodeID, labels, in.MaxDepth, in.ResultCap, "reverse")
	return NodeListResult{Nodes: nodes}, err
}

// resolveClosureProfile maps a closure_profile name to the set of edge_labels
// whose edge_family equals the profile string. The profile string IS the
// edge_family — no Go-resident aliases. Callers pick whichever edge_family
// values they declared in spec-graph.config.json edge_labels and pass that
// literal as closure_profile.
func resolveClosureProfile(ctx context.Context, env *Env, profile string) ([]string, error) {
	if profile == "" {
		return nil, fmt.Errorf("closure_profile required (use the edge_family value declared in spec-graph.config.json edge_labels)")
	}
	all, err := env.Edges.All(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range all {
		if l.EdgeFamily() == profile {
			out = append(out, l.Name())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("closure_profile %q matched zero edge_labels (no edge_label has edge_family=%q in config)", profile, profile)
	}
	return out, nil
}

func handleHistory(ctx context.Context, env *Env, in historyInput) (VersionListResult, error) {
	if in.NodeID == "" {
		return VersionListResult{}, fmt.Errorf("node_id required")
	}
	// Walk every registered substrate; first one with history wins (bootstrap
	// has one substrate, so this is trivial).
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		return VersionListResult{}, err
	}
	for _, a := range adapters {
		vs, err := a.History(ctx, in.NodeID)
		if err == nil && len(vs) > 0 {
			return VersionListResult{Versions: vs}, nil
		}
	}
	return VersionListResult{}, fmt.Errorf("node %q has no history in any registered substrate", in.NodeID)
}

func handleDiff(ctx context.Context, env *Env, in diffInput) (DiffResult, error) {
	if in.NodeID == "" || in.VersionA == "" || in.VersionB == "" {
		return DiffResult{}, fmt.Errorf("node_id, version_a, version_b all required")
	}
	a, err := readNodeAcrossSubstrates(ctx, env, in.NodeID, in.VersionA, "")
	if err != nil {
		return DiffResult{}, fmt.Errorf("read version_a: %w", err)
	}
	b, err := readNodeAcrossSubstrates(ctx, env, in.NodeID, in.VersionB, "")
	if err != nil {
		return DiffResult{}, fmt.Errorf("read version_b: %w", err)
	}
	// Per REQUIREMENTS.md §12.2: structural diff is RFC 6902 over the
	// (contract + payload) tree of both versions. Operations are paths
	// rooted at "/contract/..." and "/payload/...".
	srcTree := map[string]interface{}{
		"contract": a.CurrentVersion.Contract,
		"payload":  a.CurrentVersion.Payload,
	}
	dstTree := map[string]interface{}{
		"contract": b.CurrentVersion.Contract,
		"payload":  b.CurrentVersion.Payload,
	}
	patch, err := jsondiff.Compare(srcTree, dstTree, jsondiff.Invertible())
	if err != nil {
		return DiffResult{}, fmt.Errorf("compute diff: %w", err)
	}
	ops := make([]DiffOp, 0, len(patch))
	for _, p := range patch {
		op := DiffOp{Op: string(p.Type), Path: p.Path, Value: p.Value, OldValue: p.OldValue}
		ops = append(ops, op)
	}
	out := DiffResult{
		NodeID:     in.NodeID,
		VersionA:   a.CurrentVersion.Version,
		VersionB:   b.CurrentVersion.Version,
		Operations: ops,
	}
	if a.Status != b.Status {
		out.StatusChange = a.Status + "->" + b.Status
	}
	if a.NodeKind != b.NodeKind {
		out.KindChange = a.NodeKind + "->" + b.NodeKind
	}
	out.Identical = len(ops) == 0 && out.StatusChange == "" && out.KindChange == ""
	return out, nil
}

func handleProject(ctx context.Context, env *Env, in projectInput, snapshotID string) (ProjectResult, error) {
	if in.NodeID == "" || in.Projection == "" {
		return ProjectResult{}, fmt.Errorf("node_id and projection required")
	}
	proj, err := env.Projections.Resolve(ctx, in.Projection)
	if err != nil {
		return ProjectResult{}, err
	}
	root, err := readNodeAcrossSubstrates(ctx, env, in.NodeID, "", snapshotID)
	if err != nil {
		return ProjectResult{}, err
	}
	b, err := proj.Render(ctx, root, nil)
	if err != nil {
		return ProjectResult{}, err
	}
	return ProjectResult{
		Projection:  in.Projection,
		ContentType: "application/json",
		Body:        string(b),
	}, nil
}

// ---------------- new handlers per REQUIREMENTS.md §3.4 - §3.7 ----------------

func handleQuery(ctx context.Context, env *Env, in queryInput) (QueryResult, error) {
	if err := validateReadOnlyQueryInput(env, in); err != nil {
		return QueryResult{}, err
	}
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		return QueryResult{}, err
	}
	if len(adapters) == 0 {
		return QueryResult{}, fmt.Errorf("no substrates registered")
	}
	// The untyped experimental SQL peephole retains its historical
	// single-substrate behavior. Typed OOD/staging reads must instead call
	// handleQueryOnSubstrate with the config-resolved table owner.
	return adapters[0].ExecuteReadOnlyQuery(ctx, in.SQL, in.Params)
}

func validateReadOnlyQueryInput(env *Env, in queryInput) error {
	if env == nil {
		return fmt.Errorf("no environment configured")
	}
	if env.Config.Mode != ModeExperimentalBootstrap || !env.Config.ExperimentalQueryEnabled {
		return fmt.Errorf("%w: spec_graph_query requires mode=experimental_bootstrap and experimental_query_enabled=true", ErrModeMismatch)
	}
	if in.SQL == "" {
		return fmt.Errorf("sql required")
	}
	if !isReadOnlySQL(in.SQL) {
		return fmt.Errorf("query must be READ-ONLY (SELECT, GRAPH, or MATCH); got: %s", strings.SplitN(strings.TrimSpace(in.SQL), " ", 2)[0])
	}
	return nil
}

func handleQueryOnSubstrate(ctx context.Context, env *Env, in queryInput, substrateID string) (QueryResult, error) {
	if in.SQL == "" {
		return QueryResult{}, fmt.Errorf("sql required")
	}
	if !isReadOnlySQL(in.SQL) {
		return QueryResult{}, fmt.Errorf("query must be READ-ONLY (SELECT, GRAPH, or MATCH); got: %s", strings.SplitN(strings.TrimSpace(in.SQL), " ", 2)[0])
	}
	if env == nil {
		return QueryResult{}, fmt.Errorf("no environment configured")
	}
	if substrateID == "" {
		return QueryResult{}, fmt.Errorf("substrate id required for typed read")
	}
	if env.Substrates == nil {
		return QueryResult{}, fmt.Errorf("no substrates registered")
	}
	adapter, err := env.Substrates.ByID(substrateID)
	if err != nil {
		return QueryResult{}, err
	}
	return adapter.ExecuteReadOnlyQuery(ctx, in.SQL, in.Params)
}

// handleImport admits per-node JSON files (the bootstrap/seed_nodes/
// shape — each file is { node_kind, contract, payload }) into the
// OODGraph substrate. Each file becomes ONE OODGraphObjects row with
// object_class = the file's node_kind; top-level scalar keys in
// contract/payload become OODGraphSymbols rows with the scalar value
// in search_text. The whole batch is written atomically via
// CommitMaterializationRun.
// validateSubmissionKinds is handleImport's fail-closed pre-pass over a
// batch's node_kind values. Every submission's kind must be non-empty and
// present in the closed NodeKindRegistry; the first offender aborts the
// whole batch, naming its index and the offending kind.
//
// Why this exists as its own pass: handleImport writes
// OODGraphObjects.object_class verbatim from node_kind, so the node_kind
// registry IS the closed registry governing object_class. Validating only
// at the point of row construction leaves the check downstream of live
// substrate I/O, which both costs a round-trip on a doomed batch and puts
// the gate out of reach of the emulator-free unit suite.
func validateSubmissionKinds(ctx context.Context, kinds NodeKindRegistry, subs []ArtifactSubmission) error {
	for i, sub := range subs {
		if sub.NodeKind == "" {
			return fmt.Errorf("submission[%d]: node_kind required", i)
		}
		if _, err := kinds.Resolve(ctx, sub.NodeKind); err != nil {
			return fmt.Errorf("submission[%d] node_kind=%q: %w", i, sub.NodeKind, err)
		}
	}
	return nil
}

func handleImport(ctx context.Context, env *Env, in importInput) (ImportResult, error) {
	subs := in.Submissions
	if len(subs) == 0 && in.FilePath != "" {
		loaded, err := loadSubmissionsFromPath(in.FilePath)
		if err != nil {
			return ImportResult{}, err
		}
		subs = loaded
	}
	if len(subs) == 0 {
		return ImportResult{}, fmt.Errorf("no submissions provided")
	}
	if promotion := in.StagingPromotion; promotion != nil && len(promotion.ExternalReceipts) != len(subs) {
		return ImportResult{}, fmt.Errorf("staging promotion receipt cardinality mismatch: receipts=%d submissions=%d", len(promotion.ExternalReceipts), len(subs))
	}

	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return ImportResult{}, err
	}
	ctx = withExternalVerificationSession(ctx, orgID)

	// Fail-closed node_kind gate over the WHOLE batch, before any substrate
	// or embedding I/O. object_class is written verbatim from node_kind
	// (see the GraphObject construction below), so the node_kind registry is
	// the closed set that governs object_class — and a closed registry is
	// only closed where the WRITE validates against it.
	//
	// This runs here rather than only inside the write loop for three
	// reasons: an out-of-registry kind costs no Spanner round-trip and no
	// per-object embedding call; a bad kind at submission[N] no longer
	// wastes N embeddings before it is caught; and the gate stays reachable
	// from `make test-unit`, which needs no emulator. The in-loop Resolve
	// below is retained — it returns the descriptor the loop consumes.
	if err := validateSubmissionKinds(ctx, env.Kinds, subs); err != nil {
		return ImportResult{}, err
	}

	// Resolve every canonical name + source coordinate and the descriptor-owned
	// external policy before touching the network or substrate. This first pass
	// is intentionally static: relationship/topology and unsupported adapter
	// dependencies must be rejected before any vendor request is consumed.
	canonicalNames := make([]string, len(subs))
	sourceCoordinates := make([]ArtifactSourceCoordinate, len(subs))
	kindDescriptors := make([]NodeKindDescriptor, len(subs))
	externalPolicies := make([]ExternalSourceDescriptor, len(subs))
	externalReceipts := make([]*stagedExternalVerificationReceipt, len(subs))
	for i, sub := range subs {
		if sub.NodeKind == "" {
			return ImportResult{}, fmt.Errorf("submission[%d]: node_kind required", i)
		}
		desc, err := env.Kinds.Resolve(ctx, sub.NodeKind)
		if err != nil {
			return ImportResult{}, fmt.Errorf("submission[%d] node_kind=%q: %w", i, sub.NodeKind, err)
		}
		canonicalName, err := resolveSubmissionCanonicalName(sub)
		if err != nil {
			return ImportResult{}, fmt.Errorf("submission[%d] node_kind=%q: %w", i, sub.NodeKind, err)
		}
		coord, err := resolveArtifactSourceCoordinate(sub.NodeKind, canonicalName, desc, sub.SourceCoordinate)
		if err != nil {
			return ImportResult{}, fmt.Errorf("submission[%d] node_kind=%q canonical_name=%q: %w", i, sub.NodeKind, canonicalName, err)
		}
		var policy ExternalSourceDescriptor
		if desc.ExternalReferenceRequired() {
			if in.StagingPromotion == nil {
				policy, err = preflightExternalReferenceSubmissionShape(env, sub, canonicalName, desc, coord)
			} else {
				policy, err = resolveExternalSourcePolicy(env.Config, sub.NodeKind, canonicalName, coord)
				if err == nil && (len(sub.Contract) != 0 || len(sub.Payload) != 0) {
					err = fmt.Errorf("external-reference submissions are stable-reference-only: contract and payload must be empty")
				}
			}
		}
		if err != nil {
			return ImportResult{}, fmt.Errorf("submission[%d] node_kind=%q canonical_name=%q: %w", i, sub.NodeKind, canonicalName, err)
		}
		canonicalNames[i] = canonicalName
		sourceCoordinates[i] = coord
		kindDescriptors[i] = desc
		externalPolicies[i] = policy
	}
	if err := validateExternalBootstrapPublicationEnvelope(subs, externalPolicies, len(in.Relationships)); err != nil {
		return ImportResult{}, err
	}
	relationshipPlans, err := planExternalRelationships(ctx, env, canonicalNames, kindDescriptors, externalPolicies, in.Relationships)
	if err != nil {
		return ImportResult{}, err
	}

	targetSubstrateID := kindDescriptors[0].SubstrateID()
	for i := 1; i < len(kindDescriptors); i++ {
		if kindDescriptors[i].SubstrateID() != targetSubstrateID {
			return ImportResult{}, fmt.Errorf("spec_graph_import batch spans substrates %q and %q; materialization runs are single-substrate", targetSubstrateID, kindDescriptors[i].SubstrateID())
		}
	}
	for i, policy := range externalPolicies {
		if policy.ID == "" {
			continue
		}
		if err := preflightExternalLocatorAdmission(subs[i].NodeKind, sourceCoordinates[i], policy); err != nil {
			return ImportResult{}, fmt.Errorf("submission[%d] node_kind=%q canonical_name=%q: %w", i, subs[i].NodeKind, canonicalNames[i], err)
		}
	}

	// Only after every batch-wide static refusal is clear may the trusted
	// fetch path run (or a staging receipt be revalidated).
	for i, sub := range subs {
		coord := sourceCoordinates[i]
		var policy ExternalSourceDescriptor
		if in.StagingPromotion != nil && kindDescriptors[i].ExternalReferenceRequired() {
			if in.StagingPromotion.ExternalReceipts[i] == nil || in.StagingPromotion.ExternalReceipts[i].Authorization.OrganizationID != orgID {
				err = fmt.Errorf("staged external verification receipt organization does not match kernel-resolved organization")
			} else {
				coord, policy, err = validateStagedExternalReferenceSubmission(env, sub, canonicalNames[i], kindDescriptors[i], coord, in.StagingPromotion.ExternalReceipts[i])
			}
			externalReceipts[i] = in.StagingPromotion.ExternalReceipts[i]
		} else if in.StagingPromotion == nil {
			var receipt *stagedExternalVerificationReceipt
			coord, policy, receipt, err = validateExternalReferenceSubmissionForStaging(ctx, env, sub, canonicalNames[i], kindDescriptors[i], coord)
			externalReceipts[i] = receipt
			if err == nil && policy.ID != "" {
				err = requireArchivedExternalEvidence(receipt)
			}
		}
		if err != nil {
			return ImportResult{}, fmt.Errorf("submission[%d] node_kind=%q canonical_name=%q: %w", i, sub.NodeKind, canonicalNames[i], err)
		}
		sourceCoordinates[i] = coord
		externalPolicies[i] = policy
	}

	adapter, err := env.Substrates.ByID(targetSubstrateID)
	if err != nil {
		return ImportResult{}, fmt.Errorf("resolve import substrate %q: %w", targetSubstrateID, err)
	}
	if err := adapter.CheckOODGraphSchema(ctx); err != nil {
		return ImportResult{}, fmt.Errorf("OODGraph schema not applied: %w", err)
	}

	runID := uuid.NewString()
	snapshotID := uuid.NewString()
	now := env.Now().UTC()
	visibility := "organization"

	// Deterministic id namespace per §8.idempotency_and_replay_safety:
	// same identity tuple → same graph_object_id / symbol_id on replay.
	idNS := uuid.MustParse("767c2399-87f9-4859-ac64-afb575bdb263")
	objects := make([]GraphObject, 0, len(subs))
	symbols := make([]GraphSymbol, 0)

	for i, sub := range subs {
		// Each submission's NodeKind drives object_class. Contract+Payload
		// hold the seed_node's content; the StableID may name the
		// canonical name (filename-derived per loadSubmissionsFromPath).
		kind := sub.NodeKind
		if kind == "" {
			return ImportResult{}, fmt.Errorf("submission[%d]: node_kind required", i)
		}
		desc := kindDescriptors[i]
		canonicalName := canonicalNames[i]
		coord := sourceCoordinates[i]
		externalPolicy := externalPolicies[i]
		ga := GraphAddress{
			ObjectClass:       kind,
			SourceAuthorityID: coord.SourceAuthorityID,
			SourceRefKind:     coord.SourceRefKind,
			SourceRef:         coord.SourceStableReference,
			VersionCoordinate: coord.VersionCoordinate,
			SectionPath:       coord.SectionPath,
		}
		objectIDName := fmt.Sprintf("object|%s|%s|%s|%s|%s|%s|%s",
			orgID, kind, coord.SourceAuthorityID, coord.SourceRefKind,
			coord.SourceStableReference, coord.VersionCoordinate, coord.SectionPath)
		graphObjectID := uuid.NewSHA1(idNS, []byte(objectIDName)).String()

		searchPayload := graphOwnedObjectSearchPayload(kind, ga.String(), coord)
		if externalPolicy.ID != "" {
			searchPayload = externalReferenceSearchPayload(kind, ga.String(), coord, externalPolicy)
		}
		// Retrieval text is a graph-owned projection of identity and
		// classification coordinates only. OOD §6/§8 forbids copying
		// source contract/payload bodies into search columns or embeddings.
		searchText := graphOwnedObjectSearchText(kind, ga.String(), coord)
		if externalPolicy.ID != "" {
			searchText = externalReferenceSearchText(kind, coord, externalPolicy)
		}

		projectionRole := desc.ProjectionRole()

		obj := GraphObject{
			OrganizationID:         orgID,
			GraphSnapshotID:        snapshotID,
			GraphObjectID:          graphObjectID,
			ObjectClass:            kind,
			SourceAuthorityID:      coord.SourceAuthorityID,
			SourceArtifactClass:    coord.SourceArtifactClass,
			SourceRefKind:          coord.SourceRefKind,
			SourceStableReference:  coord.SourceStableReference,
			VersionCoordinate:      coord.VersionCoordinate,
			SectionPath:            coord.SectionPath,
			GraphAddress:           ga.String(),
			SourceContentHash:      coord.SourceContentHash,
			SourceContentHashOwner: coord.SourceContentHashOwner,
			MaterializationRunID:   runID,
			ProjectionRole:         projectionRole,
			ValidationState:        "valid",
			Status:                 "active",
			VisibilityScope:        visibility,
			SearchText:             searchText,
			SearchPayload:          searchPayload,
			EmbeddingModel:         embeddingModelOrEmpty(env),
		}
		if externalPolicy.ID == "" && env.Embed != nil && searchText != "" {
			vec, eErr := env.Embed.Embed(ctx, searchText, vertexai.TaskTypeRetrievalDocument)
			if eErr != nil {
				return ImportResult{}, fmt.Errorf("embed object %q: %w", canonicalName, eErr)
			}
			obj.Embedding = vec
		}
		objects = append(objects, obj)

		// Decompose contract + payload into Symbols (recursive — nested
		// objects become section-path-addressable Symbol rows too).
		if externalPolicy.ID != "" {
			continue
		}
		contractPath, err := composeSourceSectionPath(coord.SectionPath, "$.contract")
		if err != nil {
			return ImportResult{}, fmt.Errorf("submission[%d] contract symbol path: %w", i, err)
		}
		payloadPath, err := composeSourceSectionPath(coord.SectionPath, "$.payload")
		if err != nil {
			return ImportResult{}, fmt.Errorf("submission[%d] payload symbol path: %w", i, err)
		}
		if err := extractSymbolsRecursive(ctx, sub.Contract, contractPath, "contract", graphObjectID, kind, coord, orgID, snapshotID, runID, visibility, env, idNS, &symbols); err != nil {
			return ImportResult{}, fmt.Errorf("submission[%d] contract symbols: %w", i, err)
		}
		if err := extractSymbolsRecursive(ctx, sub.Payload, payloadPath, "payload", graphObjectID, kind, coord, orgID, snapshotID, runID, visibility, env, idNS, &symbols); err != nil {
			return ImportResult{}, fmt.Errorf("submission[%d] payload symbols: %w", i, err)
		}
	}
	// External projections are independent derived work. Bound their
	// concurrency and finish them before opening a materialization run so
	// thousands of symbols do not serialize model RPC latency or hold graph
	// transaction/run state while waiting on Vertex.
	if err := embedExternalObjectsBounded(ctx, env, objects, canonicalNames, externalPolicies); err != nil {
		return ImportResult{}, err
	}
	for i, policy := range externalPolicies {
		if policy.ID == "" {
			continue
		}
		sym, err := externalReferenceSymbol(objects[i], canonicalNames[i], sourceCoordinates[i], idNS)
		if err != nil {
			return ImportResult{}, fmt.Errorf("submission[%d] external symbol: %w", i, err)
		}
		symbols = append(symbols, sym)
	}
	edges, err := materializeExternalRelationships(ctx, env, orgID, runID, snapshotID, visibility, objects, relationshipPlans)
	if err != nil {
		return ImportResult{}, err
	}

	// Source set + hash per §8.canonical_source_intake.source_set_contract.
	// The stored source_set now names the coordinates this run consumed
	// rather than {object_count, symbol_count}: two counts cannot satisfy
	// §8.snapshot_production_contract.historical_reproducibility, which
	// requires a sealed snapshot to remain reproducible from its source_set.
	// graph_version is left zero — CommitMaterializationRun assigns it.
	snapshot := GraphSnapshot{
		OrganizationID:  orgID,
		GraphSnapshotID: snapshotID,
		SnapshotKind:    "active_candidate",
		SnapshotState:   "building",
		Status:          "active",
		VisibilityScope: visibility,
	}
	run := MaterializationRun{
		OrganizationID:       orgID,
		MaterializationRunID: runID,
		RunKind:              "corpus_refresh",
		State:                "running",
		StartedAt:            now,
		Status:               "active",
		VisibilityScope:      visibility,
	}
	batch := MaterializationBatch{
		Run:                          run,
		Snapshot:                     snapshot,
		Objects:                      objects,
		Symbols:                      symbols,
		Edges:                        edges,
		ExternalVerificationReceipts: compactExternalVerificationReceipts(externalReceipts),
	}
	if promotion := in.StagingPromotion; promotion != nil {
		if promotion.IngestionRunID == "" || len(promotion.ConceptStagingIDs) != len(objects) || len(promotion.EdgeStagingIDs) != len(edges) {
			return ImportResult{}, fmt.Errorf("staging promotion binding cardinality mismatch: concepts=%d/%d edges=%d/%d", len(promotion.ConceptStagingIDs), len(objects), len(promotion.EdgeStagingIDs), len(edges))
		}
		for i, stagingID := range promotion.ConceptStagingIDs {
			if stagingID == "" {
				return ImportResult{}, fmt.Errorf("staging promotion concept[%d] missing staging_id", i)
			}
			batch.StagingConceptPromotions = append(batch.StagingConceptPromotions, StagingConceptPromotion{
				IngestionRunID: promotion.IngestionRunID,
				StagingID:      stagingID,
				GraphObjectID:  objects[i].GraphObjectID,
			})
		}
		for i, stagingEdgeID := range promotion.EdgeStagingIDs {
			if stagingEdgeID == "" {
				return ImportResult{}, fmt.Errorf("staging promotion edge[%d] missing staging_edge_id", i)
			}
			batch.StagingEdgePromotions = append(batch.StagingEdgePromotions, StagingEdgePromotion{
				IngestionRunID: promotion.IngestionRunID,
				StagingEdgeID:  stagingEdgeID,
				GraphEdgeID:    edges[i].GraphEdgeID,
			})
		}
	}
	coords := SourceCoordinatesFromArtifacts(orgID, sourceCoordinates)
	if preparer, ok := adapter.(CompleteMaterializationPreparer); ok {
		batch, coords, err = preparer.PrepareCompleteMaterialization(ctx, batch, coords, materializationValidationAuthority(env))
		if err != nil {
			return ImportResult{}, fmt.Errorf("prepare complete materialization: %w", err)
		}
	}
	sourceSetHash, err := ComputeSourceSetHash(orgID, coords)
	if err != nil {
		return ImportResult{}, err
	}
	sourceSet, err := buildCompletePublisherSourceSet(orgID, coords, batch)
	if err != nil {
		return ImportResult{}, err
	}
	batch.Snapshot.SourceSetHash = sourceSetHash
	batch.Snapshot.SourceSet = sourceSet
	batch.Run.InputSourceSetHash = sourceSetHash
	batch.Run.InputSourceSet = sourceSet
	if err := validateCompleteExternalBootstrapPublicationEnvelope(batch); err != nil {
		return ImportResult{}, err
	}
	// Stage 1 open_materialization_run, committed before the batch so a
	// failure below leaves a failed run row rather than no evidence at all.
	if err := adapter.OpenMaterializationRun(ctx, batch.Run); err != nil {
		return ImportResult{}, err
	}
	if err := adapter.CommitMaterializationRun(ctx, batch); err != nil {
		if fErr := adapter.FailMaterializationRun(ctx, orgID, runID); fErr != nil {
			return ImportResult{}, fmt.Errorf("commit materialization run: %w (and marking run failed: %v)", err, fErr)
		}
		return ImportResult{}, fmt.Errorf("commit materialization run: %w", err)
	}

	result := ImportResult{
		Total:                 len(subs),
		Admitted:              len(objects),
		RelationshipsAdmitted: len(edges),
		GraphSnapshotID:       snapshotID,
	}
	for _, o := range objects {
		result.OrderedIDs = append(result.OrderedIDs, o.GraphObjectID)
	}
	for _, edge := range edges {
		result.OrderedEdgeIDs = append(result.OrderedEdgeIDs, edge.GraphEdgeID)
	}
	return result, nil
}

// extractSymbolsRecursive walks the contract/payload tree and emits a
// Symbol per addressable unit:
//   - scalar string → symbol with search_text = the value
//   - nested keyed object → recurse, emitting a section-marker symbol for
//     the key itself and walking children
//   - array of strings → one symbol per element (index in symbol_name)
//   - array of objects → recurse into each, with array-index in section_path
//   - numbers / bools → symbol with stringified value as search_text
//
// Every Symbol row carries its full section_path so the graph_address
// uniquely identifies it within the parent Object's identity space.
// Embeddings populated when env.Embed is configured.
func extractSymbolsRecursive(ctx context.Context, val interface{}, sectionPath, fieldName, ownerObjectID, ownerClass string, source ArtifactSourceCoordinate, orgID, snapshotID, runID, visibility string, env *Env, idNS uuid.UUID, out *[]GraphSymbol) error {
	if val == nil {
		return nil
	}
	switch vv := val.(type) {
	case string:
		return emitSymbol(ctx, fieldName, "scalar_string", vv, sectionPath, ownerObjectID, ownerClass, source, orgID, snapshotID, runID, visibility, env, idNS, out)
	case float64:
		return emitSymbol(ctx, fieldName, "scalar_number", fmt.Sprintf("%v", vv), sectionPath, ownerObjectID, ownerClass, source, orgID, snapshotID, runID, visibility, env, idNS, out)
	case bool:
		return emitSymbol(ctx, fieldName, "scalar_bool", fmt.Sprintf("%v", vv), sectionPath, ownerObjectID, ownerClass, source, orgID, snapshotID, runID, visibility, env, idNS, out)
	case []interface{}:
		for i, elem := range vv {
			childPath := fmt.Sprintf("%s[%d]", sectionPath, i)
			childField := fmt.Sprintf("%s_%d", fieldName, i)
			if err := extractSymbolsRecursive(ctx, elem, childPath, childField, ownerObjectID, ownerClass, source, orgID, snapshotID, runID, visibility, env, idNS, out); err != nil {
				return err
			}
		}
	case map[string]interface{}:
		// Emit a marker symbol for the keyed object itself so the
		// parent path is addressable.
		if err := emitSymbol(ctx, fieldName, "nested_object", fmt.Sprintf("object{%d keys}", len(vv)), sectionPath, ownerObjectID, ownerClass, source, orgID, snapshotID, runID, visibility, env, idNS, out); err != nil {
			return err
		}
		keys := make([]string, 0, len(vv))
		for k := range vv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			childPath := sectionPath + "." + k
			if err := extractSymbolsRecursive(ctx, vv[k], childPath, k, ownerObjectID, ownerClass, source, orgID, snapshotID, runID, visibility, env, idNS, out); err != nil {
				return err
			}
		}
	}
	return nil
}

func emitSymbol(ctx context.Context, fieldName, symbolKind, _ string, sectionPath, ownerObjectID, ownerClass string, source ArtifactSourceCoordinate, orgID, snapshotID, runID, visibility string, env *Env, idNS uuid.UUID, out *[]GraphSymbol) error {
	if err := ValidateSectionPath(sectionPath); err != nil {
		return err
	}
	if len(sectionPath) > 2048 {
		return fmt.Errorf("section_path exceeds OODGraphSymbols STRING(2048)")
	}
	if fieldName == "" || !utf8.ValidString(fieldName) || len(fieldName) > 1024 {
		return fmt.Errorf("symbol_name must be non-empty valid UTF-8 within OODGraphSymbols STRING(1024)")
	}
	ga := GraphAddress{
		ObjectClass:       "symbol",
		SourceAuthorityID: source.SourceAuthorityID,
		SourceRefKind:     source.SourceRefKind,
		SourceRef:         source.SourceStableReference,
		VersionCoordinate: source.VersionCoordinate,
		SectionPath:       sectionPath,
	}
	address := ga.String()
	if len(address) > 4096 {
		return fmt.Errorf("symbol graph_address exceeds OODGraphSymbols STRING(4096) after canonical percent encoding")
	}
	parsed, err := ParseGraphAddress(address)
	if err != nil || parsed.String() != address {
		return fmt.Errorf("symbol graph_address is not canonical: %w", err)
	}
	symbolIDName := fmt.Sprintf("symbol|%s|%s|%s|%s|%s|%s|%s|%s:%s",
		orgID, ownerClass, source.SourceAuthorityID, source.SourceRefKind,
		source.SourceStableReference, source.VersionCoordinate, sectionPath, symbolKind, fieldName)
	symbolID := uuid.NewSHA1(idNS, []byte(symbolIDName)).String()
	sym := GraphSymbol{
		OrganizationID:        orgID,
		GraphSnapshotID:       snapshotID,
		SymbolID:              symbolID,
		GraphObjectID:         ownerObjectID,
		ObjectClass:           ownerClass,
		SymbolKind:            symbolKind,
		SymbolName:            fieldName,
		SourceAuthorityID:     source.SourceAuthorityID,
		SourceStableReference: source.SourceStableReference,
		VersionCoordinate:     source.VersionCoordinate,
		SectionPath:           sectionPath,
		GraphAddress:          address,
		MaterializationRunID:  runID,
		ValidationState:       "valid",
		Status:                "active",
		VisibilityScope:       visibility,
		EmbeddingModel:        embeddingModelOrEmpty(env),
	}
	sym.SearchText = graphOwnedSymbolSearchText(sym)
	sym.SearchPayload = graphOwnedSymbolSearchPayload(sym)
	if env != nil && env.Embed != nil && sym.SearchText != "" {
		vec, err := env.Embed.Embed(ctx, sym.SearchText, vertexai.TaskTypeRetrievalDocument)
		if err == nil {
			sym.Embedding = vec
		}
		// On embed error, we still admit the symbol; embedding stays empty.
		// Search will skip rows with NULL embedding via "WHERE embedding IS NOT NULL".
	}
	*out = append(*out, sym)
	return nil
}

func embeddingModelOrEmpty(env *Env) string {
	if env != nil && env.Config.Embedding != nil {
		return env.Config.Embedding.Model
	}
	return ""
}

// resolveAdapterForSubmission picks the substrate adapter that will own this
// submission's row. Mirrors the routing inside AdmitArtifact but exposes it
// to batch callers (handleImport) so they can group plans by adapter before
// calling the variadic CommitAdmission. Nodes route by node_kind via the
// kind registry; edges route to the first registered substrate (bootstrap
// has one; the multi-substrate routing for edges is a cutover concern).
func resolveAdapterForSubmission(ctx context.Context, env *Env, sub ArtifactSubmission) (SubstrateAdapter, error) {
	if sub.NodeKind != "" {
		desc, err := env.Kinds.Resolve(ctx, sub.NodeKind)
		if err != nil {
			return nil, err
		}
		return env.Substrates.Adapter(ctx, desc)
	}
	if sub.EdgeLabel != "" {
		all, err := env.Substrates.All(ctx)
		if err != nil {
			return nil, err
		}
		if len(all) == 0 {
			return nil, fmt.Errorf("no substrates registered")
		}
		return all[0], nil
	}
	return nil, fmt.Errorf("submission must have either node_kind or edge_label")
}

// loadSubmissionsFromPath accepts either a single JSON file (containing an
// array OR a single object) OR a directory whose *.json files are loaded in
// filename order. Matches bootstrap/seed_nodes/ layout (one file per node,
// admitted in name order per the README).
func loadSubmissionsFromPath(path string) ([]ArtifactSubmission, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if !info.IsDir() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", path, err)
		}
		return parseSubmissionsJSON(data, path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read dir %q: %w", path, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		// Underscore-prefixed files are author/validator artifacts
		// (_edges.json carries the parent admission driver's edge list,
		// _findings.json carries the validator's verdict). They are not
		// submissions and the directory scan skips them per
		// AUTHORING_GUIDE.md §11.
		if strings.HasPrefix(e.Name(), "_") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var out []ArtifactSubmission
	for _, name := range names {
		full := filepath.Join(path, name)
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", full, err)
		}
		got, err := parseSubmissionsJSON(data, full)
		if err != nil {
			return nil, err
		}
		// Seed_node filenames are "NNN_<canonical_name>.json". When the
		// file body doesn't carry an explicit stable_id, derive it from
		// the filename: strip the NNN_ prefix and the .json suffix.
		canonicalName := canonicalNameFromFilename(name)
		for i := range got {
			if got[i].StableID == "" {
				got[i].StableID = canonicalName
			}
		}
		out = append(out, got...)
	}
	return out, nil
}

// resolveSubmissionCanonicalName extracts the canonical_name component of
// the OOD_GRAPH_PROTOCOL_v1 §3 identity tuple from an ArtifactSubmission.
// Precedence:
//
//  1. sub.StableID (explicit caller-set name; e.g. CLI / single-file
//     admission paths that derive name from filename)
//  2. sub.Contract["canonical_name"] (the typical inline-submission path —
//     the canonical_name lives in the contract per the authoring guide)
//  3. sub.Contract["canonical_err_name"] (sentinel-specific; sentinels use
//     PascalCase Err-prefixed names)
//
// Returns an error if none of the three resolve. Falling back to a kind-only
// name (e.g. "section") collapses every same-kind submission to the same
// UUIDv5 — the canonical_name component of the identity tuple MUST be
// distinct per node.
func resolveSubmissionCanonicalName(sub ArtifactSubmission) (string, error) {
	if sub.StableID != "" {
		return sub.StableID, nil
	}
	if sub.Contract != nil {
		if v, ok := sub.Contract["canonical_name"].(string); ok && v != "" {
			return v, nil
		}
		if v, ok := sub.Contract["canonical_err_name"].(string); ok && v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("identity required — set stable_id OR contract.canonical_name (sentinels: contract.canonical_err_name); cannot derive UUIDv5 from kind alone")
}

// canonicalNameFromFilename strips the leading "NNN_" admission-order
// prefix and the ".json" suffix from a seed_node filename, leaving the
// canonical name. "001_origin.json" → "origin";
// "002_node_identity_axiom.json" → "node_identity_axiom".
func canonicalNameFromFilename(name string) string {
	base := strings.TrimSuffix(name, ".json")
	// Strip leading "NNN_" if present (3+ digits then underscore).
	for i, r := range base {
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '_' && i > 0 {
			return base[i+1:]
		}
		break
	}
	return base
}

// parseSubmissionsJSON accepts either a top-level array of submissions OR a
// single submission object, returning a slice either way.
func parseSubmissionsJSON(data []byte, source string) ([]ArtifactSubmission, error) {
	// File/directory ingress does not pass through the MCP raw-Arguments
	// duplicate-key guard. Scan the untouched bytes here before generic
	// contract/payload maps can collapse nested duplicate members last-wins.
	if err := rejectDuplicateJSONKeysRecursive(data, source); err != nil {
		return nil, fmt.Errorf("parse %q: %w", source, err)
	}
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var arr []ArtifactSubmission
		if err := json.Unmarshal(data, &arr); err != nil {
			return nil, fmt.Errorf("parse %q as array: %w", source, err)
		}
		return arr, nil
	}
	var one ArtifactSubmission
	if err := json.Unmarshal(data, &one); err != nil {
		return nil, fmt.Errorf("parse %q as object: %w", source, err)
	}
	return []ArtifactSubmission{one}, nil
}

func handleHealth(ctx context.Context, env *Env, _ healthInput) (HealthResult, error) {
	out := HealthResult{
		Mode: env.Config.Mode,
		RegistrySizes: map[string]int{
			"substrates":  len(env.Config.Substrates),
			"node_kinds":  len(env.Config.NodeKinds),
			"edge_labels": len(env.Config.EdgeLabels),
			"projections": len(env.Config.Projections),
		},
		OverallReady: true,
	}
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		out.OverallReady = false
		out.BlockingIssues = append(out.BlockingIssues, err.Error())
		return out, nil
	}
	for _, a := range adapters {
		h := SubstrateHealth{ID: a.ID(), Database: a.Database()}
		if err := a.CheckOODGraphSchema(ctx); err != nil {
			h.Reachable = true
			h.SchemaApplied = false
			h.Error = err.Error()
			out.OverallReady = false
			out.BlockingIssues = append(out.BlockingIssues, fmt.Sprintf("substrate %q: %s", a.ID(), err.Error()))
		} else {
			h.Reachable = true
			h.SchemaApplied = true
		}
		out.Substrates = append(out.Substrates, h)
	}
	// Mode is required by Validate(); if we got here, mode is set. No
	// "unset" branch — the binary would have refused to boot.
	return out, nil
}

// ---------------- shared helpers ----------------

func readNodeAcrossSubstrates(ctx context.Context, env *Env, nodeID, version, snapshotID string) (Node, error) {
	if nodeID == "" {
		return Node{}, fmt.Errorf("node_id required")
	}
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		return Node{}, err
	}
	var lastErr error
	for _, a := range adapters {
		n, err := a.ReadNode(ctx, nodeID, version, snapshotID)
		if err == nil {
			return n, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("node %q not found in any substrate", nodeID)
	}
	return Node{}, lastErr
}

// checkDanglingClosure refuses to archive a node that has active incoming
// edges (other nodes depend on it). Queries Edges where target_node_id =
// the archive candidate AND status = 'active'; any match returns
// ErrClosureWouldDangle with the dependent-edge inventory.
func checkDanglingClosure(ctx context.Context, env *Env, nodeID string) error {
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		return err
	}
	var depEdges []Edge
	for _, a := range adapters {
		edges, err := a.Neighbors(ctx, nodeID, NeighborOpts{Direction: "in"})
		if err != nil {
			return fmt.Errorf("substrate %q dangling-closure probe: %w", a.ID(), err)
		}
		for _, e := range edges {
			if e.Status == "active" {
				depEdges = append(depEdges, e)
			}
		}
	}
	if len(depEdges) == 0 {
		return nil
	}
	var summary []string
	for _, e := range depEdges {
		summary = append(summary, fmt.Sprintf("%s --%s--> %s", e.SourceID, e.EdgeLabel, e.TargetID))
	}
	return fmt.Errorf("%w: %d active incoming edge(s) — retire them first (unlink) before archiving: %s",
		ErrClosureWouldDangle, len(depEdges), strings.Join(summary, "; "))
}

// validateContractMonotonicity enforces node_version_chain_axiom's
// "contract is byte-equivalent across versions" rule. Compares canonical-JSON
// serializations of the prior and proposed contracts; any difference returns
// ErrContractDrift. Universal — not mode-gated.
func validateContractMonotonicity(prior, proposed interface{}) error {
	priorBytes, err := canonicalJSON(prior)
	if err != nil {
		return fmt.Errorf("canonical prior contract: %w", err)
	}
	proposedBytes, err := canonicalJSON(proposed)
	if err != nil {
		return fmt.Errorf("canonical proposed contract: %w", err)
	}
	if !bytes.Equal(priorBytes, proposedBytes) {
		return fmt.Errorf("%w: contract is byte-equivalent invariant per node_version_chain_axiom — re-admission may refine payload but never alter contract", ErrContractDrift)
	}
	return nil
}

func isReadOnlySQL(s string) bool {
	t := strings.ToUpper(strings.TrimLeft(s, " \t\r\n"))
	return strings.HasPrefix(t, "SELECT") ||
		strings.HasPrefix(t, "WITH") ||
		strings.HasPrefix(t, "GRAPH") ||
		strings.HasPrefix(t, "MATCH")
}

// topologicallyOrder returns the submissions in dependency order: a node
// whose payload references another node-id appearing in the same import
// must come AFTER its referent. References are detected by scanning the
// payload JSON for "$ref" strings naming other submissions' stable ids.
//
// This is a simple Kahn-style topological sort. Cycles or unresolved
// referents return ErrImportDependencyUnresolved.
func topologicallyOrder(subs []ArtifactSubmission) ([]ArtifactSubmission, error) {
	knownIDs := map[string]int{}
	for i, s := range subs {
		if s.StableID == "" {
			continue // anonymous nodes are leaves
		}
		if _, dup := knownIDs[s.StableID]; dup {
			return nil, fmt.Errorf("%w: duplicate stable_id %q in submissions", ErrImportDependencyUnresolved, s.StableID)
		}
		knownIDs[s.StableID] = i
	}

	// Build the dependency edges: from submission i, find all $ref strings in
	// its contract+payload that reference other submission stable_ids.
	deps := make([][]int, len(subs))
	for i, s := range subs {
		refs := scanRefs(s.Contract, s.Payload)
		for _, r := range refs {
			if j, ok := knownIDs[r]; ok && j != i {
				deps[i] = append(deps[i], j)
			}
		}
	}

	// Kahn's algorithm: indegree is incoming dep count.
	indegree := make([]int, len(subs))
	for _, ds := range deps {
		for _, d := range ds {
			indegree[d]++
		}
	}
	// Actually we want dependents to come AFTER referents. Reverse:
	// edge i → j means "i references j" so j must come before i.
	// So the result order is: all nodes with no outgoing deps first.
	out := make([]ArtifactSubmission, 0, len(subs))
	queue := []int{}
	outdegree := make([]int, len(subs))
	for i := range deps {
		outdegree[i] = len(deps[i])
		if outdegree[i] == 0 {
			queue = append(queue, i)
		}
	}
	// Sort queue for stable output
	sort.Ints(queue)
	processed := map[int]bool{}
	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		if processed[i] {
			continue
		}
		processed[i] = true
		out = append(out, subs[i])
		// Anyone who depended on i can have their outdegree decremented.
		for j, ds := range deps {
			for _, d := range ds {
				if d == i {
					outdegree[j]--
					if outdegree[j] == 0 && !processed[j] {
						queue = append(queue, j)
						sort.Ints(queue)
					}
				}
			}
		}
	}
	if len(out) != len(subs) {
		return nil, fmt.Errorf("%w: cycle or unresolved referent (%d of %d submissions could not be ordered)", ErrImportDependencyUnresolved, len(subs)-len(out), len(subs))
	}
	return out, nil
}

// scanRefs walks already-parsed JSON values for any string of the form
// "$ref:<id>" or a key named "$ref" pointing at a string id. Inputs are
// interface{} (the form Contract/Payload arrive in post-deserialization).
func scanRefs(values ...interface{}) []string {
	var out []string
	for _, v := range values {
		if v == nil {
			continue
		}
		collectRefs(v, &out)
	}
	return out
}

func collectRefs(v interface{}, out *[]string) {
	switch t := v.(type) {
	case json.RawMessage:
		var parsed interface{}
		if err := json.Unmarshal(t, &parsed); err == nil {
			collectRefs(parsed, out)
		}
	case []byte:
		var parsed interface{}
		if err := json.Unmarshal(t, &parsed); err == nil {
			collectRefs(parsed, out)
		}
	case map[string]interface{}:
		for k, vv := range t {
			if k == "$ref" {
				if s, ok := vv.(string); ok {
					*out = append(*out, s)
				}
			}
			collectRefs(vv, out)
		}
	case []interface{}:
		for _, e := range t {
			collectRefs(e, out)
		}
	case string:
		if strings.HasPrefix(t, "$ref:") {
			*out = append(*out, strings.TrimPrefix(t, "$ref:"))
		}
	}
}
