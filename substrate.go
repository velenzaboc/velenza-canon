package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/structpb"
)

// SubstrateRouter dispatches verb operations to the substrate that owns a
// given node_kind. The framework owns no storage; the router is the
// indirection between the universal verb API and the per-substrate Spanner
// tables.
//
// PRINCIPLE 7 CONFORMANCE: every behavioral value loads from
// spec-graph.config.json. ONE generic adapter (SpannerSubstrateAdapter)
// handles every substrate; per-substrate table identity is the
// SubstrateDescriptor's named table fields, not a role-key map with code-
// resident keys.
type SubstrateRouter interface {
	Adapter(ctx context.Context, kind NodeKindDescriptor) (SubstrateAdapter, error)
	All(ctx context.Context) ([]SubstrateAdapter, error)
	ByID(id string) (SubstrateAdapter, error)
	Close() error
}

// SubstrateAdapter is the per-substrate operational interface.
type SubstrateAdapter interface {
	ID() string
	Description() string
	Database() string

	// CommitAdmission runs steps 7-10 atomically: read prior signature_chain
	// (for re-admission), write the new typed row(s), mark prior version
	// superseded (if re-admission), append the ArtifactAdmissionLog row(s).
	// Variadic: passing two plans commits both in ONE Spanner RW transaction
	// (used for reciprocal edge pairs — atomic per REQUIREMENTS.md §2).
	CommitAdmission(ctx context.Context, plans ...AdmissionPlan) ([]AdmissionRecord, error)

	ReadNode(ctx context.Context, nodeID, version, snapshotID string) (Node, error)
	ReadEdge(ctx context.Context, edgeID, snapshotID string) (Edge, error)
	ListNodes(ctx context.Context, filter ListFilter) ([]Node, error)
	Neighbors(ctx context.Context, nodeID string, opts NeighborOpts) ([]Edge, error)
	History(ctx context.Context, nodeID string) ([]NodeVersion, error)

	ExecuteReadOnlyQuery(ctx context.Context, sql string, params map[string]interface{}) (QueryResult, error)

	// SearchByEmbedding runs APPROX_COSINE_DISTANCE against Nodes.embedding_v2
	// and returns the top-K nearest nodes ordered by distance. nodeKind
	// optionally restricts to one kind; "" = any kind.
	SearchByEmbedding(ctx context.Context, query []float32, nodeKind string, limit int, orgID string) ([]Node, error)

	// FindByDefinitionHash returns the (at most one) active node whose
	// definition_hash exactly matches the given hex string within the
	// organization. Found=false (no error) signals no hit. Used by
	// Layer-1 pre-admission dedup to short-circuit re-creates of byte-
	// identical contracts into an idempotent return.
	FindByDefinitionHash(ctx context.Context, orgID, definitionHash string) (Node, bool, error)

	// FindByCanonicalName returns the (at most one) active node within
	// (org, node_kind) whose contract.canonical_name equals the given
	// string. Found=false (no error) signals no hit. Used by Layer-2
	// pre-admission dedup to refuse collisions on the logical primary
	// key per AUTHORING_GUIDE §2.
	FindByCanonicalName(ctx context.Context, orgID, nodeKind, canonicalName string) (Node, bool, error)

	// FindSimilarByEmbedding runs APPROX_COSINE_DISTANCE filtered by
	// maxDistance and returns the top-N hits as SimilarNode (Node +
	// distance). Used by Layer-3 pre-admission dedup. Differs from
	// SearchByEmbedding in two ways: (a) carries the distance back so the
	// caller can populate PossibleDuplicateCandidate, (b) WHERE-clauses
	// by distance threshold so callers don't have to post-filter.
	FindSimilarByEmbedding(ctx context.Context, orgID string, query []float32, maxDistance float64, limit int) ([]SimilarNode, error)

	// ArchiveEdge is intentionally fail-closed until the protocol can express
	// retirement as a later complete immutable snapshot. It never mutates a
	// prior sealed row or emits a bespoke archive snapshot.
	ArchiveEdge(ctx context.Context, orgID, edgeID, admitterLiteral string) (EdgeArchiveResult, error)

	// ArchiveNode has the same immutable fail-closed contract as ArchiveEdge.
	ArchiveNode(ctx context.Context, orgID, nodeID, admitterLiteral string) (NodeArchiveResult, error)

	// TraverseClosure runs a quantified-path GRAPH_TABLE query starting at
	// the given node, following edges whose edge_label is in the allowed set,
	// up to max_depth hops. direction is "forward" (closure) or "reverse"
	// (impact). Returns end nodes.
	TraverseClosure(ctx context.Context, startNodeID string, edgeLabels []string, maxDepth, resultCap int, direction string) ([]Node, error)

	CheckSchema(ctx context.Context) error

	// VerifyExperimentalSchema queries the database's information_schema and
	// returns nil ONLY if the DB carries EXACTLY the spec-graph experimental
	// base tables (NodeTable + EdgeTable + AdmissionLogTable from the
	// descriptor) — no more, no less. Used by `spec-graph reset` before
	// DropDatabase to refuse on any database that doesn't fingerprint as a
	// spec-graph experimental DB. Production-tier databases carry many
	// other base tables and fail the exclusivity check; empty databases
	// (zero base tables) pass since there's nothing to lose by dropping.
	VerifyExperimentalSchema(ctx context.Context) error

	// ---------------- schema_v2 OODGraph substrate (Phase 4 addition) ----------------

	// OpenMaterializationRun performs stage 1 of the §8 pipeline
	// (open_materialization_run): inserts the run row at state="running"
	// with a NULL target_graph_snapshot_id, committed on its own BEFORE any
	// row construction. It is what makes a run that never seals leave audit
	// evidence, which §8.idempotency_and_replay_safety.abandoned_run_rule
	// and §9.active_snapshot_selection.failed_and_abandoned_run_rule both
	// presuppose. Callers pair it with FailMaterializationRun on every
	// error path and CommitMaterializationRun on success.
	OpenMaterializationRun(ctx context.Context, run MaterializationRun) error

	// FailMaterializationRun moves an open run row to state="failed" per
	// §8.materialization_pipeline.seal_materialization_run.failure_state,
	// leaving target_graph_snapshot_id NULL. Idempotent — it only matches
	// rows still in state="running".
	FailMaterializationRun(ctx context.Context, orgID, runID string) error

	// CommitMaterializationRun wraps stage-15 through stage-19 of the
	// §8.materialization_pipeline (write_graph_rows → write_projection_artifacts
	// → write_snapshot_row → seal_materialization_run) in ONE Spanner
	// ReadWriteTransaction. Earlier validation/parsing stages run in-memory
	// in ceremony.go (Phase 5). The batch carries the materialization run
	// record + all graph rows to write + all violations + projection
	// artifacts; the snapshot row is sealed in the same transaction.
	//
	// The run row must already have been opened by OpenMaterializationRun:
	// stage 19 UPDATEs it rather than inserting, and fails loudly if no open
	// row exists. batch.Snapshot.GraphVersion is IGNORED — the version is
	// assigned inside the transaction after every row write succeeds.
	CommitMaterializationRun(ctx context.Context, batch MaterializationBatch) error

	// CheckOODGraphSchema verifies the 7 OODGraph tables exist in the
	// configured database. Analogous to CheckSchema for the schema_v2 substrate.
	CheckOODGraphSchema(ctx context.Context) error

	Close() error
}

// CompleteMaterializationPreparer is the optional schema-v2 capability used
// by the Spanner adapter before a run opens. It converts an import delta into
// a complete immutable snapshot by carrying forward the current active corpus
// (or, on the first corrected run, consolidating every eligible legacy
// partial snapshot). Adapters that do not implement it retain the in-memory
// unit-test behavior of committing the supplied batch unchanged.
type CompleteMaterializationPreparer interface {
	PrepareCompleteMaterialization(context.Context, MaterializationBatch, []SourceCoordinate, MaterializationValidationAuthority) (MaterializationBatch, []SourceCoordinate, error)
}

// MaterializationValidationAuthority supplies the config-resident closed
// registries used to revalidate every carried row before a complete successor
// can seal. Carry-forward is not an exemption from the current protocol.
type MaterializationValidationAuthority struct {
	Kinds           NodeKindRegistry
	Edges           EdgeLabelRegistry
	Projections     ProjectionRegistry
	ExternalSources []ExternalSourceDescriptor
	Embed           embeddingClient
	EmbeddingModel  string
	EmbeddingDims   int
}

func materializationValidationAuthority(env *Env) MaterializationValidationAuthority {
	if env == nil {
		return MaterializationValidationAuthority{}
	}
	authority := MaterializationValidationAuthority{
		Kinds: env.Kinds, Edges: env.Edges, Projections: env.Projections,
		ExternalSources: env.Config.ExternalSources, Embed: env.Embed,
	}
	if env.Config.Embedding != nil {
		authority.EmbeddingModel = env.Config.Embedding.Model
		authority.EmbeddingDims = env.Config.Embedding.Dimensions
	}
	return authority
}

// AdmissionPlan is the substrate-side input to CommitAdmission.
type AdmissionPlan struct {
	OrganizationID string
	IsEdge         bool
	IsRetirement   bool

	Node *NodeVersion
	Edge *Edge

	PriorVersion *NodeVersion
	Record       AdmissionRecord
}

// ListFilter is the universal filter passed to ListNodes.
type ListFilter struct {
	NodeKind       string
	Status         string
	OrganizationID string
	SnapshotID     string
	AuthorityID    string
	Limit          int
}

// NeighborOpts is the universal neighbor-traversal options struct.
type NeighborOpts struct {
	Direction      string
	EdgeLabels     []string
	Depth          int
	SnapshotID     string
	OrganizationID string
}

// -------------------- descriptor --------------------

// SubstrateDescriptor is one registered substrate. Every table name is a
// named config field — no role-key registry, no Go-resident keys.
//
// The schema_v1 fields (NodeTable / EdgeTable / AdmissionLogTable) remain
// load-bearing for the legacy CommitAdmission path. The schema_v2 fields
// (Snapshot / Object / Symbol / GraphEdge / MaterializationRun /
// Violation / ProjectionArtifact) are required only when callers invoke
// CommitMaterializationRun / CheckOODGraphSchema; the (C) substrate
// rebuild lands these incrementally per phase. Phase 6 deletes the
// schema_v1 fields once handlers migrate fully.
type SubstrateDescriptor struct {
	ID              string `json:"id"`
	Description     string `json:"description"`
	SpannerDatabase string `json:"spanner_database,omitempty"`
	// Legacy parser sentinels. The process-level selector owns Google
	// credentials; stale per-substrate fields fail config validation.
	CredentialsFile   string `json:"credentials_file,omitempty"`
	CredentialsSource string `json:"credentials_source,omitempty"`
	ReadOnly          bool   `json:"read_only,omitempty"`

	// schema_v1 (legacy — still serving handlers.go / ceremony.go until Phase 5/6).
	NodeTable         string `json:"node_table,omitempty"`
	EdgeTable         string `json:"edge_table,omitempty"`
	AdmissionLogTable string `json:"admission_log_table,omitempty"`

	// schema_v2 — OODGraph 7-table substrate per OOD_GRAPH_PROTOCOL_v1 §6.
	// Consumed by CommitMaterializationRun and CheckOODGraphSchema.
	SnapshotTable           string `json:"snapshot_table,omitempty"`
	ObjectTable             string `json:"object_table,omitempty"`
	SymbolTable             string `json:"symbol_table,omitempty"`
	GraphEdgeTable          string `json:"graph_edge_table,omitempty"`
	MaterializationRunTable string `json:"materialization_run_table,omitempty"`
	ViolationTable          string `json:"violation_table,omitempty"`
	ProjectionArtifactTable string `json:"projection_artifact_table,omitempty"`
}

// -------------------- adapter --------------------

type SpannerSubstrateAdapter struct {
	Descriptor    SubstrateDescriptor
	Credentials   gcpauth.Selector
	AllowEmulator bool
	mu            sync.Mutex
	client        *spanner.Client

	// Integration fixtures use this private switch to seed historical partial
	// snapshots through the same emulator tables before exercising the first
	// corrected complete snapshot. No runtime constructor enables it: a live
	// writer may open and seal only the current materialization profile.
	allowLegacyMaterializationProfilesForTesting bool
}

func (a *SpannerSubstrateAdapter) ID() string          { return a.Descriptor.ID }
func (a *SpannerSubstrateAdapter) Description() string { return a.Descriptor.Description }
func (a *SpannerSubstrateAdapter) Database() string    { return a.Descriptor.SpannerDatabase }

func (a *SpannerSubstrateAdapter) getClient(ctx context.Context) (*spanner.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client != nil {
		return a.client, nil
	}
	var clientOptions []option.ClientOption
	useEmulator, err := gcpauth.ValidateSpannerEmulatorHost(os.Getenv("SPANNER_EMULATOR_HOST"), a.AllowEmulator)
	if err != nil {
		return nil, fmt.Errorf("substrate %q: %w", a.Descriptor.ID, err)
	}
	if useEmulator {
		clientOptions = append(clientOptions, option.WithoutAuthentication())
	} else {
		tokenSource, err := a.Credentials.TokenSource(ctx, gcpauth.CloudPlatformScope)
		if err != nil {
			return nil, fmt.Errorf("substrate %q: google credentials: %w", a.Descriptor.ID, err)
		}
		clientOptions = append(clientOptions, option.WithTokenSource(tokenSource))
	}
	c, err := spanner.NewClient(ctx, a.Descriptor.SpannerDatabase, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("substrate %q: spanner client: %w", a.Descriptor.ID, err)
	}
	a.client = c
	return c, nil
}

func (a *SpannerSubstrateAdapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client != nil {
		a.client.Close()
		a.client = nil
	}
	return nil
}

func (a *SpannerSubstrateAdapter) requireWriteTables() (string, string, string, error) {
	if a.Descriptor.ReadOnly {
		return "", "", "", fmt.Errorf("substrate %q is read-only", a.Descriptor.ID)
	}
	if a.Descriptor.NodeTable == "" || a.Descriptor.EdgeTable == "" || a.Descriptor.AdmissionLogTable == "" {
		return "", "", "", fmt.Errorf("substrate %q: node_table / edge_table / admission_log_table all required for writes", a.Descriptor.ID)
	}
	return a.Descriptor.NodeTable, a.Descriptor.EdgeTable, a.Descriptor.AdmissionLogTable, nil
}

// -------------------- CheckSchema --------------------

func (a *SpannerSubstrateAdapter) CheckSchema(ctx context.Context) error {
	nodeT, edgeT, logT, err := a.requireWriteTables()
	if err != nil {
		return err
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return err
	}
	stmt := spanner.Statement{
		SQL: `SELECT table_name FROM information_schema.tables WHERE table_schema = '' AND table_name IN UNNEST(@names)`,
		Params: map[string]interface{}{
			"names": []string{nodeT, edgeT, logT},
		},
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	found := map[string]bool{}
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("check_schema query: %w", err)
		}
		var name string
		if err := row.Columns(&name); err != nil {
			return fmt.Errorf("check_schema decode: %w", err)
		}
		found[name] = true
	}
	for _, want := range []string{nodeT, edgeT, logT} {
		if !found[want] {
			return fmt.Errorf("%w: missing table %q", ErrSchemaNotApplied, want)
		}
	}
	return nil
}

// VerifyExperimentalSchema enumerates the database's base tables via
// information_schema and refuses with ErrSchemaFingerprintMismatch if the
// table set is anything other than EXACTLY {NodeTable, EdgeTable,
// AdmissionLogTable}. Empty databases (zero base tables — e.g. freshly
// created via gcloud, schema not yet applied) pass: nothing to lose by
// dropping.
//
// This is the pre-drop fingerprint gate behind spec-graph reset. The
// init_database_allowlist is config-driven (a config edit can defeat it);
// this check is structural — the DB's own schema is the fingerprint. A
// production DB like a production database carries DocObjects + many other tables
// and fails the exclusivity check.
func (a *SpannerSubstrateAdapter) VerifyExperimentalSchema(ctx context.Context) error {
	// (C) substrate rebuild: the fingerprint accepts EITHER schema_v1
	// (legacy 3 tables) OR schema_v2 (7 OODGraph tables) OR BOTH (during
	// the Phase 4-6 transition window). Empty DB also passes — nothing
	// to fingerprint.
	expected := map[string]bool{}
	for _, t := range []string{a.Descriptor.NodeTable, a.Descriptor.EdgeTable, a.Descriptor.AdmissionLogTable,
		a.Descriptor.SnapshotTable, a.Descriptor.ObjectTable, a.Descriptor.SymbolTable,
		a.Descriptor.GraphEdgeTable, a.Descriptor.MaterializationRunTable,
		a.Descriptor.ViolationTable, a.Descriptor.ProjectionArtifactTable} {
		if t != "" {
			expected[t] = true
		}
	}
	if len(expected) == 0 {
		return fmt.Errorf("substrate %q: cannot verify schema — no table fields configured (legacy or OODGraph)", a.Descriptor.ID)
	}

	client, err := a.getClient(ctx)
	if err != nil {
		return err
	}
	stmt := spanner.Statement{
		SQL: `SELECT table_name FROM information_schema.tables
		      WHERE table_schema = '' AND table_type = 'BASE TABLE'`,
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	found := map[string]bool{}
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("verify schema query: %w", err)
		}
		var name string
		if err := row.Columns(&name); err != nil {
			return fmt.Errorf("verify schema decode: %w", err)
		}
		found[name] = true
	}

	// Empty DB → safe to drop. Nothing to fingerprint.
	if len(found) == 0 {
		return nil
	}

	// The fingerprint passes if EVERY found table is one the descriptor
	// expected. "Missing" expected tables are fine (substrate may be at
	// schema_v1 with only 3 tables present, and the descriptor lists both
	// schema_v1 + schema_v2 fields). "Extra" unexpected tables fail —
	// that's the production-DB-mistake guard.
	var extra []string
	for f := range found {
		if !expected[f] {
			extra = append(extra, f)
		}
	}
	if len(extra) == 0 {
		return nil
	}
	sort.Strings(extra)
	expectedList := []string{}
	for e := range expected {
		expectedList = append(expectedList, e)
	}
	sort.Strings(expectedList)
	return fmt.Errorf("%w: substrate=%q expected_base_tables=%v unexpected=%v",
		ErrSchemaFingerprintMismatch, a.Descriptor.ID, expectedList, extra)
}

// -------------------- CommitAdmission --------------------

func (a *SpannerSubstrateAdapter) CommitAdmission(ctx context.Context, plans ...AdmissionPlan) ([]AdmissionRecord, error) {
	if len(plans) == 0 {
		return nil, fmt.Errorf("CommitAdmission: no plans supplied")
	}
	nodeT, edgeT, logT, err := a.requireWriteTables()
	if err != nil {
		return nil, err
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}

	// Copy records out so we can mutate signature_chain inside the closure
	// without re-reading the plans slice.
	recs := make([]AdmissionRecord, len(plans))
	for i, p := range plans {
		recs[i] = p.Record
	}

	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
		for i, plan := range plans {
			fullChain := append([]string{}, recs[i].SignatureChain...)
			if plan.PriorVersion != nil && !plan.IsEdge {
				prior, err := readPriorSignatureChainInTx(ctx, tx, nodeT, plan.OrganizationID, plan.Node.NodeID, plan.PriorVersion.Version)
				if err != nil {
					return fmt.Errorf("plan[%d] step 7 read prior chain: %w", i, err)
				}
				fullChain = append(prior, fullChain...)
			}
			recs[i].SignatureChain = fullChain

			if plan.IsEdge {
				if plan.IsRetirement {
					if err := retireEdgeInTx(ctx, tx, edgeT, plan); err != nil {
						return fmt.Errorf("plan[%d] step 9 retire edge: %w", i, err)
					}
				} else {
					if err := writeEdgeInTx(ctx, tx, edgeT, plan); err != nil {
						return fmt.Errorf("plan[%d] step 9 write edge: %w", i, err)
					}
				}
			} else {
				if err := writeNodeInTx(ctx, tx, nodeT, plan, fullChain); err != nil {
					return fmt.Errorf("plan[%d] step 9 write node: %w", i, err)
				}
				if plan.PriorVersion != nil {
					if err := supersedePriorInTx(ctx, tx, nodeT, plan.OrganizationID, plan.Node.NodeID, plan.PriorVersion.Version, plan.Node.Version); err != nil {
						return fmt.Errorf("plan[%d] step 9 supersede prior: %w", i, err)
					}
				}
			}

			if err := writeAdmissionLogInTx(ctx, tx, logT, recs[i]); err != nil {
				return fmt.Errorf("plan[%d] step 10 admission log: %w", i, err)
			}
		}
		return nil
	})
	if err != nil {
		return recs, fmt.Errorf("%w: %v", ErrCeremonyAtomicityBroken, err)
	}
	now := time.Now().UTC()
	for i := range recs {
		recs[i].AdmittedAt = now
	}
	return recs, nil
}

func readPriorSignatureChainInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, nodeT, orgID, nodeID string, version int) ([]string, error) {
	row, err := tx.ReadRow(ctx, nodeT, spanner.Key{orgID, nodeID, int64(version)}, []string{"signature_chain"})
	if err != nil {
		if spanner.ErrCode(err) == 5 {
			return nil, nil
		}
		return nil, err
	}
	var chain []string
	if err := row.Columns(&chain); err != nil {
		return nil, err
	}
	return chain, nil
}

func writeNodeInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, nodeT string, plan AdmissionPlan, chain []string) error {
	nv := plan.Node
	contractNullable := spanner.NullJSON{Valid: false}
	if nv.Contract != nil {
		contractNullable = spanner.NullJSON{Value: nv.Contract, Valid: true}
	}
	contentNullable := spanner.NullJSON{Valid: false}
	if nv.Payload != nil {
		contentNullable = spanner.NullJSON{Value: nv.Payload, Valid: true}
	}
	cols := []string{
		"organization_id", "node_id", "version", "node_kind", "status",
		"contract", "content", "definition_hash", "manifest_hash", "signature_chain",
		"admitted_by", "admitted_at",
		"governing_spec_ref", "source_spec_lineage_refs",
		"spec_section_ref", "spec_symbol_ref", "node_creation_contract_ref",
		"embedding_v2",
	}
	var embeddingVal interface{} = []float32(nil)
	if len(nv.EmbeddingV2) > 0 {
		embeddingVal = nv.EmbeddingV2
	}
	vals := []interface{}{
		plan.OrganizationID, nv.NodeID, int64(nv.Version), plan.Record.ArtifactType, nv.Status,
		contractNullable, contentNullable, nv.DefinitionHash, nv.ManifestHash, chain,
		plan.Record.AdmittedBy, spanner.CommitTimestamp,
		nullableString(nv.GoverningSpecRef), nv.SourceSpecLineageRefs,
		nullableString(nv.SpecSectionRef), nullableString(nv.SpecSymbolRef), nullableString(nv.NodeCreationContractRef),
		embeddingVal,
	}
	return tx.BufferWrite([]*spanner.Mutation{spanner.Insert(nodeT, cols, vals)})
}

func writeEdgeInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, edgeT string, plan AdmissionPlan) error {
	e := plan.Edge
	if e.SourceVersion == 0 || e.TargetVersion == 0 {
		return fmt.Errorf("edge %q: source_version (%d) and target_version (%d) must both be set (property-graph KEY uniqueness)", e.EdgeID, e.SourceVersion, e.TargetVersion)
	}
	cols := []string{
		"organization_id", "edge_id", "source_node_id", "source_version",
		"target_node_id", "target_version", "edge_label", "status", "admitted_at",
		"reciprocal_edge_id",
	}
	vals := []interface{}{
		plan.OrganizationID, e.EdgeID, e.SourceID, int64(e.SourceVersion),
		e.TargetID, int64(e.TargetVersion), e.EdgeLabel, e.Status, spanner.CommitTimestamp,
		nullableString(e.ReciprocalEdgeID),
	}
	return tx.BufferWrite([]*spanner.Mutation{spanner.Insert(edgeT, cols, vals)})
}

// retireEdgeInTx updates the existing edge row's status to 'retired'. Edges
// don't carry versions (their PK is org+edge_id), so retirement is an UPDATE
// rather than an INSERT-new-version like nodes.
func retireEdgeInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, edgeT string, plan AdmissionPlan) error {
	e := plan.Edge
	return tx.BufferWrite([]*spanner.Mutation{
		spanner.Update(edgeT,
			[]string{"organization_id", "edge_id", "status"},
			[]interface{}{plan.OrganizationID, e.EdgeID, "retired"},
		),
	})
}

func supersedePriorInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, nodeT, orgID, nodeID string, priorVersion, newVersion int) error {
	return tx.BufferWrite([]*spanner.Mutation{
		spanner.Update(nodeT,
			[]string{"organization_id", "node_id", "version", "status", "superseded_by_version"},
			[]interface{}{orgID, nodeID, int64(priorVersion), "superseded", int64(newVersion)},
		),
	})
}

func writeAdmissionLogInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, logT string, rec AdmissionRecord) error {
	passReport, _ := json.Marshal(rec.PassReport)
	cols := []string{
		"organization_id", "admission_id", "artifact_id", "artifact_type", "artifact_version",
		"artifact_hash", "manifest_hash", "admitted_by", "admitted_at",
		"signature", "dual_control_approver", "is_non_genesis", "pass_report",
	}
	signature := ""
	if len(rec.SignatureChain) > 0 {
		signature = rec.SignatureChain[len(rec.SignatureChain)-1]
	}
	vals := []interface{}{
		rec.OrganizationID, rec.RunID, rec.ArtifactID, rec.ArtifactType, int64(rec.ArtifactVersion),
		rec.DefinitionHash, rec.ManifestHash, rec.AdmittedBy, spanner.CommitTimestamp,
		signature, nullableString(""), rec.IsNonGenesis, spanner.NullJSON{Value: json.RawMessage(passReport), Valid: len(passReport) > 0},
	}
	return tx.BufferWrite([]*spanner.Mutation{spanner.Insert(logT, cols, vals)})
}

// -------------------- read paths --------------------

func (a *SpannerSubstrateAdapter) ReadNode(ctx context.Context, nodeID, version, _snapshotID string) (Node, error) {
	if a.Descriptor.NodeTable == "" {
		return Node{}, fmt.Errorf("substrate %q: node_table not configured", a.Descriptor.ID)
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return Node{}, err
	}
	var stmt spanner.Statement
	if version != "" {
		// Spanner's version column is INT64; the input may be a string from
		// the MCP layer. Parse and reject malformed.
		v, perr := strconv.ParseInt(version, 10, 64)
		if perr != nil {
			return Node{}, fmt.Errorf("read node: version %q is not an integer: %w", version, perr)
		}
		stmt = spanner.Statement{
			SQL: fmt.Sprintf(`SELECT organization_id, node_id, version, node_kind, status,
				TO_JSON_STRING(contract) AS contract_json,
				TO_JSON_STRING(content) AS content_json,
				definition_hash, manifest_hash, signature_chain,
				admitted_by, admitted_at
				FROM %s WHERE node_id = @node_id AND version = @version LIMIT 1`, a.Descriptor.NodeTable),
			Params: map[string]interface{}{"node_id": nodeID, "version": v},
		}
	} else {
		stmt = spanner.Statement{
			SQL: fmt.Sprintf(`SELECT organization_id, node_id, version, node_kind, status,
				TO_JSON_STRING(contract) AS contract_json,
				TO_JSON_STRING(content) AS content_json,
				definition_hash, manifest_hash, signature_chain,
				admitted_by, admitted_at
				FROM %s WHERE node_id = @node_id AND status = 'active' LIMIT 1`, a.Descriptor.NodeTable),
			Params: map[string]interface{}{"node_id": nodeID},
		}
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	row, err := iter.Next()
	if err == iterator.Done {
		return Node{}, fmt.Errorf("node %q not found in substrate %q", nodeID, a.Descriptor.ID)
	}
	if err != nil {
		return Node{}, fmt.Errorf("read node: %w", err)
	}
	return decodeNodeRow(row)
}

func (a *SpannerSubstrateAdapter) ReadEdge(ctx context.Context, edgeID, _snapshotID string) (Edge, error) {
	if a.Descriptor.EdgeTable == "" {
		return Edge{}, fmt.Errorf("substrate %q: edge_table not configured", a.Descriptor.ID)
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return Edge{}, err
	}
	stmt := spanner.Statement{
		SQL: fmt.Sprintf(`SELECT organization_id, edge_id, source_node_id, source_version,
			target_node_id, target_version, edge_label, status, admitted_at, reciprocal_edge_id
			FROM %s WHERE edge_id = @edge_id LIMIT 1`, a.Descriptor.EdgeTable),
		Params: map[string]interface{}{"edge_id": edgeID},
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	row, err := iter.Next()
	if err == iterator.Done {
		return Edge{}, fmt.Errorf("edge %q not found in substrate %q", edgeID, a.Descriptor.ID)
	}
	if err != nil {
		return Edge{}, fmt.Errorf("read edge: %w", err)
	}
	return decodeEdgeRow(row)
}

func (a *SpannerSubstrateAdapter) ListNodes(ctx context.Context, f ListFilter) ([]Node, error) {
	if a.Descriptor.NodeTable == "" {
		return nil, fmt.Errorf("substrate %q: node_table not configured", a.Descriptor.ID)
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}
	sql := fmt.Sprintf(`SELECT organization_id, node_id, version, node_kind, status,
		TO_JSON_STRING(contract) AS contract_json,
		TO_JSON_STRING(content) AS content_json,
		definition_hash, manifest_hash, signature_chain,
		admitted_by, admitted_at
		FROM %s WHERE 1=1`, a.Descriptor.NodeTable)
	params := map[string]interface{}{}
	if f.NodeKind != "" {
		sql += ` AND node_kind = @kind`
		params["kind"] = f.NodeKind
	}
	if f.Status != "" {
		sql += ` AND status = @status`
		params["status"] = f.Status
	}
	if f.OrganizationID != "" {
		sql += ` AND organization_id = @org`
		params["org"] = f.OrganizationID
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	sql += fmt.Sprintf(` LIMIT %d`, limit)

	iter := client.Single().Query(ctx, spanner.Statement{SQL: sql, Params: params})
	defer iter.Stop()
	var out []Node
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list nodes: %w", err)
		}
		n, err := decodeNodeRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func (a *SpannerSubstrateAdapter) Neighbors(ctx context.Context, nodeID string, opts NeighborOpts) ([]Edge, error) {
	if a.Descriptor.EdgeTable == "" {
		return nil, fmt.Errorf("substrate %q: edge_table not configured", a.Descriptor.ID)
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}
	var where string
	switch opts.Direction {
	case "in":
		where = `target_node_id = @id`
	case "out":
		where = `source_node_id = @id`
	default:
		where = `(source_node_id = @id OR target_node_id = @id)`
	}
	params := map[string]interface{}{"id": nodeID}
	sql := fmt.Sprintf(`SELECT organization_id, edge_id, source_node_id, source_version,
		target_node_id, target_version, edge_label, status, admitted_at, reciprocal_edge_id
		FROM %s WHERE %s`, a.Descriptor.EdgeTable, where)
	if len(opts.EdgeLabels) > 0 {
		sql += ` AND edge_label IN UNNEST(@labels)`
		params["labels"] = opts.EdgeLabels
	}
	sql += ` LIMIT 200`
	iter := client.Single().Query(ctx, spanner.Statement{SQL: sql, Params: params})
	defer iter.Stop()
	var out []Edge
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("neighbors: %w", err)
		}
		e, err := decodeEdgeRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (a *SpannerSubstrateAdapter) History(ctx context.Context, nodeID string) ([]NodeVersion, error) {
	if a.Descriptor.NodeTable == "" {
		return nil, fmt.Errorf("substrate %q: node_table not configured", a.Descriptor.ID)
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}
	sql := fmt.Sprintf(`SELECT organization_id, node_id, version, node_kind, status,
		TO_JSON_STRING(contract) AS contract_json,
		TO_JSON_STRING(content) AS content_json,
		definition_hash, manifest_hash, signature_chain,
		admitted_by, admitted_at
		FROM %s WHERE node_id = @id ORDER BY version ASC`, a.Descriptor.NodeTable)
	iter := client.Single().Query(ctx, spanner.Statement{SQL: sql, Params: map[string]interface{}{"id": nodeID}})
	defer iter.Stop()
	var out []NodeVersion
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("history: %w", err)
		}
		n, err := decodeNodeRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, n.CurrentVersion)
	}
	return out, nil
}

func (a *SpannerSubstrateAdapter) SearchByEmbedding(ctx context.Context, query []float32, nodeKind string, limit int, orgID string) ([]Node, error) {
	if a.Descriptor.NodeTable == "" {
		return nil, fmt.Errorf("substrate %q: node_table not configured", a.Descriptor.ID)
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}
	sql := fmt.Sprintf(`
		SELECT organization_id, node_id, version, node_kind, status,
			TO_JSON_STRING(contract) AS contract_json,
			TO_JSON_STRING(content) AS content_json,
			definition_hash, manifest_hash, signature_chain,
			admitted_by, admitted_at,
			APPROX_COSINE_DISTANCE(embedding_v2, @query_vec, options => JSON '{"num_leaves_to_search": 10}') AS distance
		FROM %s
		WHERE embedding_v2 IS NOT NULL
		  AND status = 'active'
		  %s
		  %s
		ORDER BY distance
		LIMIT %d
	`, a.Descriptor.NodeTable,
		condIf(nodeKind != "", "AND node_kind = @kind"),
		condIf(orgID != "", "AND organization_id = @org"),
		limit,
	)
	params := map[string]interface{}{"query_vec": query}
	if nodeKind != "" {
		params["kind"] = nodeKind
	}
	if orgID != "" {
		params["org"] = orgID
	}
	iter := client.Single().Query(ctx, spanner.Statement{SQL: sql, Params: params})
	defer iter.Stop()
	var out []Node
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("search query: %w", err)
		}
		n, err := decodeNodeRowWithDistance(row)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func condIf(b bool, s string) string {
	if b {
		return s
	}
	return ""
}

// FindByDefinitionHash — Layer-1 pre-admission dedup lookup. Selects at most
// one active row whose definition_hash matches exactly. (definition_hash is
// SHA-256 hex over canonical(contract+payload+identity fields) per
// stepDefinitionHash — collisions are cryptographically negligible.)
func (a *SpannerSubstrateAdapter) FindByDefinitionHash(ctx context.Context, orgID, definitionHash string) (Node, bool, error) {
	if a.Descriptor.NodeTable == "" {
		return Node{}, false, fmt.Errorf("substrate %q: node_table not configured", a.Descriptor.ID)
	}
	if definitionHash == "" {
		return Node{}, false, fmt.Errorf("FindByDefinitionHash: empty definition_hash")
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return Node{}, false, err
	}
	stmt := spanner.Statement{
		SQL: fmt.Sprintf(`SELECT organization_id, node_id, version, node_kind, status,
			TO_JSON_STRING(contract) AS contract_json,
			TO_JSON_STRING(content) AS content_json,
			definition_hash, manifest_hash, signature_chain,
			admitted_by, admitted_at
			FROM %s
			WHERE organization_id = @org AND definition_hash = @h AND status = 'active'
			LIMIT 1`, a.Descriptor.NodeTable),
		Params: map[string]interface{}{"org": orgID, "h": definitionHash},
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	row, err := iter.Next()
	if err == iterator.Done {
		return Node{}, false, nil
	}
	if err != nil {
		return Node{}, false, fmt.Errorf("find by definition_hash: %w", err)
	}
	n, err := decodeNodeRow(row)
	if err != nil {
		return Node{}, false, err
	}
	return n, true, nil
}

// FindByCanonicalName — Layer-2 pre-admission dedup lookup. Selects at most
// one active row in (org, node_kind) whose contract.canonical_name equals the
// given string. JSON_VALUE on the contract column extracts the field; the
// match is case-sensitive and exact (canonical_names are snake_case literals
// per AUTHORING_GUIDE).
func (a *SpannerSubstrateAdapter) FindByCanonicalName(ctx context.Context, orgID, nodeKind, canonicalName string) (Node, bool, error) {
	if a.Descriptor.NodeTable == "" {
		return Node{}, false, fmt.Errorf("substrate %q: node_table not configured", a.Descriptor.ID)
	}
	if canonicalName == "" {
		return Node{}, false, nil
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return Node{}, false, err
	}
	stmt := spanner.Statement{
		SQL: fmt.Sprintf(`SELECT organization_id, node_id, version, node_kind, status,
			TO_JSON_STRING(contract) AS contract_json,
			TO_JSON_STRING(content) AS content_json,
			definition_hash, manifest_hash, signature_chain,
			admitted_by, admitted_at
			FROM %s
			WHERE organization_id = @org
			  AND node_kind = @kind
			  AND status = 'active'
			  AND JSON_VALUE(contract, '$.canonical_name') = @name
			LIMIT 1`, a.Descriptor.NodeTable),
		Params: map[string]interface{}{"org": orgID, "kind": nodeKind, "name": canonicalName},
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	row, err := iter.Next()
	if err == iterator.Done {
		return Node{}, false, nil
	}
	if err != nil {
		return Node{}, false, fmt.Errorf("find by canonical_name: %w", err)
	}
	n, err := decodeNodeRow(row)
	if err != nil {
		return Node{}, false, err
	}
	return n, true, nil
}

// FindSimilarByEmbedding — Layer-3 pre-admission dedup lookup. Runs
// APPROX_COSINE_DISTANCE filtered by maxDistance (cosine distance < threshold)
// and returns the top-N hits with their distances. Differs from
// SearchByEmbedding by carrying the distance back so the caller can populate
// PossibleDuplicateCandidate.
func (a *SpannerSubstrateAdapter) FindSimilarByEmbedding(ctx context.Context, orgID string, query []float32, maxDistance float64, limit int) ([]SimilarNode, error) {
	if a.Descriptor.NodeTable == "" {
		return nil, fmt.Errorf("substrate %q: node_table not configured", a.Descriptor.ID)
	}
	if limit <= 0 {
		return nil, fmt.Errorf("FindSimilarByEmbedding: limit must be > 0")
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}
	sql := fmt.Sprintf(`
		SELECT organization_id, node_id, version, node_kind, status,
			TO_JSON_STRING(contract) AS contract_json,
			TO_JSON_STRING(content) AS content_json,
			definition_hash, manifest_hash, signature_chain,
			admitted_by, admitted_at,
			APPROX_COSINE_DISTANCE(embedding_v2, @query_vec, options => JSON '{"num_leaves_to_search": 10}') AS distance
		FROM %s
		WHERE embedding_v2 IS NOT NULL
		  AND status = 'active'
		  AND organization_id = @org
		  AND APPROX_COSINE_DISTANCE(embedding_v2, @query_vec, options => JSON '{"num_leaves_to_search": 10}') < @max_d
		ORDER BY distance
		LIMIT %d
	`, a.Descriptor.NodeTable, limit)
	params := map[string]interface{}{
		"query_vec": query,
		"org":       orgID,
		"max_d":     maxDistance,
	}
	iter := client.Single().Query(ctx, spanner.Statement{SQL: sql, Params: params})
	defer iter.Stop()
	var out []SimilarNode
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("find similar by embedding: %w", err)
		}
		n, dist, err := decodeNodeRowWithDistanceValue(row)
		if err != nil {
			return nil, err
		}
		out = append(out, SimilarNode{Node: n, Distance: dist})
	}
	return out, nil
}

// decodeNodeRowWithDistanceValue is decodeNodeRowWithDistance's twin but
// returns the distance instead of discarding it. Same column order.
func decodeNodeRowWithDistanceValue(row *spanner.Row) (Node, float64, error) {
	var (
		orgID, nodeID, kind, status, defHash, manHash, admittedBy string
		version                                                   int64
		contractJSON                                              spanner.NullString
		contentJSON                                               spanner.NullString
		chain                                                     []string
		admittedAt                                                time.Time
		distance                                                  float64
	)
	if err := row.Columns(&orgID, &nodeID, &version, &kind, &status, &contractJSON, &contentJSON, &defHash, &manHash, &chain, &admittedBy, &admittedAt, &distance); err != nil {
		return Node{}, 0, fmt.Errorf("decode similar-search row: %w", err)
	}
	var contract map[string]interface{}
	if contractJSON.Valid {
		_ = json.Unmarshal([]byte(contractJSON.StringVal), &contract)
	}
	var payload map[string]interface{}
	if contentJSON.Valid {
		_ = json.Unmarshal([]byte(contentJSON.StringVal), &payload)
	}
	nv := NodeVersion{
		NodeID: nodeID, Version: int(version), Status: status,
		Contract: contract, Payload: payload,
		DefinitionHash: defHash, ManifestHash: manHash, SignatureChain: chain,
		AdmittedAt: admittedAt, AdmittedBy: admittedBy,
	}
	return Node{
		NodeID: nodeID, NodeKind: kind, OrganizationID: orgID, Status: status,
		CreatedAt: admittedAt, UpdatedAt: admittedAt, CurrentVersion: nv,
	}, distance, nil
}

// decodeNodeRowWithDistance is the same shape as decodeNodeRow but with an
// extra trailing FLOAT64 distance column (which we discard — the order in the
// result IS the distance ranking).
func decodeNodeRowWithDistance(row *spanner.Row) (Node, error) {
	var (
		orgID, nodeID, kind, status, defHash, manHash, admittedBy string
		version                                                   int64
		contractJSON                                              spanner.NullString
		contentJSON                                               spanner.NullString
		chain                                                     []string
		admittedAt                                                time.Time
		distance                                                  float64
	)
	if err := row.Columns(&orgID, &nodeID, &version, &kind, &status, &contractJSON, &contentJSON, &defHash, &manHash, &chain, &admittedBy, &admittedAt, &distance); err != nil {
		return Node{}, fmt.Errorf("decode search row: %w", err)
	}
	var contract map[string]interface{}
	if contractJSON.Valid {
		_ = json.Unmarshal([]byte(contractJSON.StringVal), &contract)
	}
	var payload map[string]interface{}
	if contentJSON.Valid {
		_ = json.Unmarshal([]byte(contentJSON.StringVal), &payload)
	}
	nv := NodeVersion{
		NodeID: nodeID, Version: int(version), Status: status,
		Contract: contract, Payload: payload,
		DefinitionHash: defHash, ManifestHash: manHash, SignatureChain: chain,
		AdmittedAt: admittedAt, AdmittedBy: admittedBy,
	}
	return Node{
		NodeID: nodeID, NodeKind: kind, OrganizationID: orgID, Status: status,
		CreatedAt: admittedAt, UpdatedAt: admittedAt, CurrentVersion: nv,
	}, nil
}

func (a *SpannerSubstrateAdapter) TraverseClosure(ctx context.Context, startNodeID string, edgeLabels []string, maxDepth, resultCap int, direction string) ([]Node, error) {
	if a.Descriptor.NodeTable == "" {
		return nil, fmt.Errorf("substrate %q: node_table not configured", a.Descriptor.ID)
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}
	// Bounded quantified-path traversal over CorpusGraph with edge-property
	// filtering inside the path pattern.
	//
	// Spanner GQL syntax: the WHERE clause goes INSIDE the parenthesized
	// edge pattern — e.g. `[e WHERE e.edge_label IN UNNEST(@labels)]->{1,N}`.
	// (Per https://docs.cloud.google.com/spanner/docs/reference/standard-sql/graph-patterns
	// — "where_clause: A WHERE clause, which filters the nodes or edges that
	// were matched.")
	//
	// The property graph uses DYNAMIC LABEL on nodes (from node_kind) and
	// edges (from edge_label), so untyped patterns `(n)` and `[e]` match
	// regardless of dynamic label, then the inline WHERE narrows by label.
	// 'end' is a GQL reserved keyword — use 'dst'.
	leftArrow, rightArrow := "-", "->"
	if direction == "reverse" {
		leftArrow, rightArrow = "<-", "-"
	}
	edgeFilter := "e.status = 'active'"
	if len(edgeLabels) > 0 {
		edgeFilter = "e.edge_label IN UNNEST(@labels) AND " + edgeFilter
	}
	sql := fmt.Sprintf(`
		GRAPH CorpusGraph
		MATCH (start {node_id: @start})%s[e WHERE %s]%s{1,%d}(dst)
		RETURN DISTINCT dst.node_id AS node_id, dst.node_kind AS node_kind, dst.status AS status,
			dst.organization_id AS organization_id, dst.admitted_at AS admitted_at
		LIMIT %d
	`, leftArrow, edgeFilter, rightArrow, maxDepth, resultCap)
	params := map[string]interface{}{"start": startNodeID, "labels": edgeLabels}
	iter := client.Single().Query(ctx, spanner.Statement{SQL: sql, Params: params})
	defer iter.Stop()
	var out []Node
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("closure traversal: %w", err)
		}
		var (
			nodeID, kind, status, orgID string
			admittedAt                  time.Time
		)
		if err := row.Columns(&nodeID, &kind, &status, &orgID, &admittedAt); err != nil {
			return nil, fmt.Errorf("decode closure row: %w", err)
		}
		out = append(out, Node{
			NodeID:         nodeID,
			NodeKind:       kind,
			OrganizationID: orgID,
			Status:         status,
			CreatedAt:      admittedAt,
			UpdatedAt:      admittedAt,
			CurrentVersion: NodeVersion{NodeID: nodeID, Status: status, AdmittedAt: admittedAt},
		})
	}
	return out, nil
}

func (a *SpannerSubstrateAdapter) ExecuteReadOnlyQuery(ctx context.Context, sql string, params map[string]interface{}) (QueryResult, error) {
	client, err := a.getClient(ctx)
	if err != nil {
		return QueryResult{}, err
	}
	iter := client.Single().Query(ctx, spanner.Statement{SQL: sql, Params: params})
	defer iter.Stop()
	out := QueryResult{}
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return out, fmt.Errorf("query: %w", err)
		}
		if out.Columns == nil {
			out.Columns = row.ColumnNames()
		}
		m := map[string]interface{}{}
		for i, name := range row.ColumnNames() {
			var gc spanner.GenericColumnValue
			if err := row.Column(i, &gc); err != nil {
				m[name] = nil
				continue
			}
			m[name] = decodeStructpbValue(gc.Value)
		}
		out.Rows = append(out.Rows, m)
	}
	return out, nil
}

// decodeStructpbValue converts a Spanner GenericColumnValue's underlying
// google.protobuf.Value into a Go-native interface{} so callers don't
// have to know about protobuf wrappers. Strings → string, numbers →
// float64, bools → bool, null → nil, structs → map[string]interface{},
// lists → []interface{}. JSON marshaling produces the same shape either
// way; in-process Go consumers (like type-asserting handlers) get the
// native types they expect.
func decodeStructpbValue(v *structpb.Value) interface{} {
	if v == nil {
		return nil
	}
	switch k := v.Kind.(type) {
	case *structpb.Value_NullValue:
		return nil
	case *structpb.Value_NumberValue:
		return k.NumberValue
	case *structpb.Value_StringValue:
		return k.StringValue
	case *structpb.Value_BoolValue:
		return k.BoolValue
	case *structpb.Value_StructValue:
		out := map[string]interface{}{}
		for fname, fval := range k.StructValue.GetFields() {
			out[fname] = decodeStructpbValue(fval)
		}
		return out
	case *structpb.Value_ListValue:
		vals := k.ListValue.GetValues()
		out := make([]interface{}, len(vals))
		for i, e := range vals {
			out[i] = decodeStructpbValue(e)
		}
		return out
	}
	return nil
}

// -------------------- decoding helpers --------------------

func decodeNodeRow(row *spanner.Row) (Node, error) {
	var (
		orgID, nodeID, kind, status, defHash, manHash, admittedBy string
		version                                                   int64
		contractJSON                                              spanner.NullString
		contentJSON                                               spanner.NullString
		chain                                                     []string
		admittedAt                                                time.Time
	)
	if err := row.Columns(&orgID, &nodeID, &version, &kind, &status, &contractJSON, &contentJSON, &defHash, &manHash, &chain, &admittedBy, &admittedAt); err != nil {
		return Node{}, fmt.Errorf("decode node row: %w", err)
	}
	var contract map[string]interface{}
	if contractJSON.Valid {
		_ = json.Unmarshal([]byte(contractJSON.StringVal), &contract)
	}
	var payload map[string]interface{}
	if contentJSON.Valid {
		_ = json.Unmarshal([]byte(contentJSON.StringVal), &payload)
	}
	nv := NodeVersion{
		NodeID:         nodeID,
		Version:        int(version),
		Status:         status,
		Contract:       contract,
		Payload:        payload,
		DefinitionHash: defHash,
		ManifestHash:   manHash,
		SignatureChain: chain,
		AdmittedAt:     admittedAt,
		AdmittedBy:     admittedBy,
	}
	return Node{
		NodeID:         nodeID,
		NodeKind:       kind,
		OrganizationID: orgID,
		Status:         status,
		CreatedAt:      admittedAt,
		UpdatedAt:      admittedAt,
		CurrentVersion: nv,
	}, nil
}

func decodeEdgeRow(row *spanner.Row) (Edge, error) {
	var (
		orgID, edgeID, sourceID, targetID, label, status string
		sourceVer, targetVer                             spanner.NullInt64
		admittedAt                                       time.Time
		recipID                                          spanner.NullString
	)
	if err := row.Columns(&orgID, &edgeID, &sourceID, &sourceVer, &targetID, &targetVer, &label, &status, &admittedAt, &recipID); err != nil {
		return Edge{}, fmt.Errorf("decode edge row: %w", err)
	}
	e := Edge{
		EdgeID:         edgeID,
		OrganizationID: orgID,
		SourceID:       sourceID,
		TargetID:       targetID,
		EdgeLabel:      label,
		Status:         status,
		AdmittedAt:     admittedAt,
	}
	if sourceVer.Valid {
		e.SourceVersion = int(sourceVer.Int64)
	}
	if targetVer.Valid {
		e.TargetVersion = int(targetVer.Int64)
	}
	if recipID.Valid {
		e.ReciprocalEdgeID = recipID.StringVal
	}
	return e, nil
}

func nullableString(s string) interface{} {
	if s == "" {
		return spanner.NullString{Valid: false}
	}
	return s
}

// nullableTime is the TIMESTAMP twin of nullableString: it renders a nil
// *time.Time as a TYPED Spanner null rather than as a bare untyped nil.
//
// The distinction matters on a nullable TIMESTAMP column. A bare `nil` in a
// mutation value slice carries no type for the client to encode, where
// spanner.NullTime{} is unambiguous — and the codebase already settled on
// the typed form for strings (nullableString above) and JSON
// (spanner.NullJSON{Valid: false}), so a bare nil is also an inconsistency
// with the convention every other nullable column here follows.
func nullableTime(t *time.Time) interface{} {
	if t == nil {
		return spanner.NullTime{}
	}
	return *t
}

func nullableInt64(v int) interface{} {
	if v == 0 {
		return spanner.NullInt64{Valid: false}
	}
	return int64(v)
}

// -------------------- router --------------------

type configRouter struct {
	byID map[string]*SpannerSubstrateAdapter
}

func newRouter(credentials gcpauth.Selector, allowEmulator bool, substrates []SubstrateDescriptor) SubstrateRouter {
	r := &configRouter{byID: make(map[string]*SpannerSubstrateAdapter, len(substrates))}
	for _, d := range substrates {
		r.byID[d.ID] = &SpannerSubstrateAdapter{Descriptor: d, Credentials: credentials, AllowEmulator: allowEmulator}
	}
	return r
}

func (r *configRouter) Adapter(_ context.Context, kind NodeKindDescriptor) (SubstrateAdapter, error) {
	a, ok := r.byID[kind.SubstrateID()]
	if !ok {
		return nil, fmt.Errorf("no substrate registered for id %q (kind=%q): %w", kind.SubstrateID(), kind.Name(), ErrSubstrateNotProvisioned)
	}
	return a, nil
}

func (r *configRouter) All(_ context.Context) ([]SubstrateAdapter, error) {
	out := make([]SubstrateAdapter, 0, len(r.byID))
	for _, a := range r.byID {
		out = append(out, a)
	}
	return out, nil
}

func (r *configRouter) ByID(id string) (SubstrateAdapter, error) {
	a, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("no substrate %q registered", id)
	}
	return a, nil
}

func (r *configRouter) Close() error {
	for _, a := range r.byID {
		_ = a.Close()
	}
	return nil
}
