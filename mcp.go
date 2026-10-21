package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

func cmdMCP(ctx context.Context, _ []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := validateMCPRuntimeComposition(cfg); err != nil {
		return err
	}

	env := &Env{
		Config:      cfg,
		Kinds:       newKindRegistry(cfg.NodeKinds),
		Edges:       newEdgeRegistry(cfg.EdgeLabels),
		Projections: newProjectionRegistry(cfg.Projections),
		Substrates:  newRouter(cfg.GoogleCredentials, cfg.AllowSpannerEmulator, cfg.Substrates),
		Now:         time.Now,
	}
	// The direct HTTP adapter is a bootstrap-only ingress adapter. OOD Graph
	// §8 requires production fetch/materialization to execute through admitted
	// circuit nodes over Ring-1 drivers; installing this Go adapter in
	// production would create a second, non-canonical execution path. A
	// production process therefore remains fail-closed until its outer
	// composition supplies the admitted fetch adapter.
	if cfg.Mode == ModeExperimentalBootstrap {
		env.ExternalFetch = newHTTPExternalReferenceFetcher(newBootstrapExternalHTTPClient(), maxExternalReferenceBytes, env.Now)
	}
	defer env.Substrates.Close()

	if cfg.Embedding != nil {
		auth, err := vertexai.NewAuth(ctx, cfg.GoogleCredentials.RequestTokenSourceFactory(gcpauth.CloudPlatformScope))
		if err != nil {
			return fmt.Errorf("build vertex auth: %w", err)
		}
		env.Embed, err = vertexai.NewEmbedClient(auth, vertexai.EmbedConfig{
			Project:      cfg.Embedding.Project,
			Location:     cfg.Embedding.Location,
			Model:        cfg.Embedding.Model,
			Dimensions:   cfg.Embedding.Dimensions,
			MaxTextBytes: cfg.Embedding.MaxTextBytes,
		})
		if err != nil {
			return fmt.Errorf("build vertex embedding client: %w", err)
		}
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "spec-graph",
		Version: "v0.1.0",
	}, nil)
	server.AddReceivingMiddleware(productionCallerContextMiddleware(cfg))

	// ---------------- state ----------------

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_use",
			Description: `Compatibility refusal for the retired implicit-pin API. Streamable HTTP is stateless, so callers must pass graph_snapshot_id explicitly on every historical read; omit it to derive the current eligible snapshot for that request. This tool never mutates process or tenant state.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in useInput) (*mcp.CallToolResult, Snapshot, error) {
			out, err := handleUse(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	// ---------------- edges (write) ----------------

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_link",
			Description: `Admit a typed edge between two graph objects. source_id and target_id are OODGraphObjects.graph_object_id values from a prior admission. edge_label validated against spec-graph.config.json edge_labels; endpoint classes validated against the label's allowed source_kinds/target_kinds; self-loop policy enforced. Reciprocity (when declared) creates the mirror edge in the same Spanner ReadWriteTransaction with cross-linked inverse_edge_ids. Writes to OODGraphEdges per OOD_GRAPH_PROTOCOL_v1 §4.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in linkInput) (*mcp.CallToolResult, AdmissionRecord, error) {
			out, err := handleLink(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_edge_archive",
			Description: `Fail-closed compatibility surface. OOD Graph v1 retirement must publish a later complete immutable snapshot and preserve every prior sealed row; the current registry cannot represent that transition for every class. This verb performs no database access and returns ErrOODGraphImmutableRetirementUnavailable.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in archiveEdgeInput) (*mcp.CallToolResult, EdgeArchiveResult, error) {
			out, err := handleArchiveEdge(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_node_archive",
			Description: `Fail-closed compatibility surface. OOD Graph v1 retirement must publish a later complete immutable snapshot and preserve every prior sealed row; the current registry cannot represent that transition for every class. This verb performs no database access and returns ErrOODGraphImmutableRetirementUnavailable.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in archiveNodeInput) (*mcp.CallToolResult, NodeArchiveResult, error) {
			out, err := handleArchiveNode(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	// ---------------- schema_v2 OODGraph typed read verbs ----------------

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_get",
			Description: `Fetch one OODGraphObjects row by graph_object_id. Retrieval columns contain only graph-owned identity/classification metadata; source contract/payload content remains with its source authority.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in oodGetInput) (*mcp.CallToolResult, QueryResult, error) {
			out, err := handleOODGet(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_list",
			Description: `List OODGraphObjects rows. Filter by object_class / status / graph_snapshot_id. Default status filter is 'active'.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in oodListInput) (*mcp.CallToolResult, QueryResult, error) {
			out, err := handleOODList(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_search",
			Description: `Vector + retrieval search over OODGraphObjects.embedding. Embeds the query via gemini-embedding-001 (3072d) and runs APPROX_COSINE_DISTANCE. Returns top-K rows ordered by distance.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in oodSearchInput) (*mcp.CallToolResult, QueryResult, error) {
			out, err := handleOODSearch(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_neighbors",
			Description: `List OODGraphEdges incident to a graph_object_id. direction=out|in|both (default both); optionally filter by edge_labels.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in oodNeighborsInput) (*mcp.CallToolResult, QueryResult, error) {
			out, err := handleOODNeighbors(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_closure",
			Description: `Forward transitive closure from a graph_object_id. closure_profile is the closed literal dependency_closure_profile and walks only complete reciprocal depends_on/load_bearing_for pairs inside one active, fresh, eligible snapshot. max_depth and result_cap are required; capped results return typed non-authoritative cap evidence.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in oodClosureInput) (*mcp.CallToolResult, oodTraversalResult, error) {
			out, err := handleOODClosure(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_impact",
			Description: `Typed impact traversal from a graph_object_id. closure_profile is the closed literal load_bearing_impact_profile and walks only complete reciprocal load_bearing_for/depends_on pairs inside one active, fresh, eligible snapshot. max_depth and result_cap are required; capped results return typed non-authoritative cap evidence.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in oodImpactInput) (*mcp.CallToolResult, oodTraversalResult, error) {
			out, err := handleOODImpact(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_query",
			Description: `Ad-hoc read-only GoogleSQL / GQL query. Gated by experimental_bootstrap mode with experimental_query_enabled=true. SELECT, GRAPH, MATCH, or WITH queries only.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in queryInput) (*mcp.CallToolResult, QueryResult, error) {
			out, err := handleQuery(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	addImportTool(server, env)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_health",
			Description: `Readiness + schema state + registry sizes + mode. Snapshot selection is request-local: pass graph_snapshot_id explicitly for history or omit it to derive current. Run at session start to surface immediate blockers.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in healthInput) (*mcp.CallToolResult, HealthResult, error) {
			out, err := handleHealth(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	// ---------------- schema_v2 OODGraph read verbs ----------------

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_list_runs",
			Description: `List OODGraphMaterializationRuns rows. Filter by state (pending|running|sealed|failed|abandoned) and/or run_kind.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in listRunsInput) (*mcp.CallToolResult, QueryResult, error) {
			out, err := handleListRuns(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_list_violations",
			Description: `List OODGraphViolations rows. Filter by graph_snapshot_id / severity / violation_code.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in listViolationsInput) (*mcp.CallToolResult, QueryResult, error) {
			out, err := handleListViolations(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_list_snapshots",
			Description: `List OODGraphSnapshots rows. Filter by snapshot_state (building|sealed) / snapshot_kind / status.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in listSnapshotsInput) (*mcp.CallToolResult, QueryResult, error) {
			out, err := handleListSnapshots(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	// ---------------- staging substrate (pre-admission pipeline) ----------------
	//
	// Five tools drive the in-Spanner pre-admission pipeline against the
	// staging_concepts + staging_edges tables (schema_v2.sql). The shape
	// replaces the prior per-stage Go-binary pipeline (spec-extract →
	// spec-cluster → spec-dedup-verify → spec-lint → spec-admit) with
	// MCP tools that run substrate-side: ML.PREDICT for Flash work,
	// SQL for structural R-rules, INSERT…SELECT for promotion. See
	// staging.go for the full architectural rationale.

	addStagingLoadTool(server, env)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_reembed_admitted",
			Description: `Retired fail-closed compatibility endpoint. In-place re-embedding would mutate prior sealed snapshots; the current materialization profile refreshes graph-owned retrieval embeddings only while publishing a complete immutable successor.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in reembedAdmittedInput) (*mcp.CallToolResult, reembedAdmittedResult, error) {
			out, err := handleReembedAdmitted(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_staging_extract_ood",
			Description: `Generic .ood.json → staging-concepts extraction. Reads one spec from source_file (absolute path), walks its top-level .sections.* keys, stages one concept per section with canonical_name = '<spec_prefix>__<section_key>' (spec_prefix = basename minus .ood.json, lowercased). Payload is the section body verbatim. node_kind defaults to 'section' (override for invariant catalogs / sentinel catalogs / etc.). Works on every spec in specs-local/ without requiring a per-spec recipe under bootstrap/recipes/. Downstream staging tools (cluster, dedup_verify, lint, promote) operate on these the same way they operate on recipe-extracted ConceptTables.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in stagingExtractOODInput) (*mcp.CallToolResult, stagingExtractOODResult, error) {
			out, err := handleStagingExtractOOD(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_staging_list",
			Description: `List staging_concepts rows for one ingestion_run_id. Filter by pipeline_state (extracted | embedded | clustered | dedup_verified | linted | promoted | rejected) and/or node_kind. Default limit 200.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in stagingListInput) (*mcp.CallToolResult, QueryResult, error) {
			out, err := handleStagingList(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_staging_get",
			Description: `Fetch one staging_concepts row by (ingestion_run_id, staging_id). Returns the full row including contract + payload + lint_findings + dedup_decision.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in stagingGetInput) (*mcp.CallToolResult, QueryResult, error) {
			out, err := handleStagingGet(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_staging_lint",
			Description: `Run every applicable R-rule against the staged concepts + edges of one ingestion_run_id. Structural rules (R3 kind_in_registry, R7 canonical_name_pattern, R8 no_duplicate, R10 edge_endpoint_kinds, R12 self_loop, R13 no_source_reference, R15 no_admission_artifacts) run as SQL. R6 no_prose runs via ML.PREDICT against the r6_flash registered model (Spanner-side parallelism via @{remote_udf_max_outstanding_rpcs=64}) when include_r6_flash=true; ~2 min for 5k rows. Updates lint_status on every staging_concepts row to 'pass' or 'fail' and lint_findings to the JSON-encoded findings; advances pipeline_state to 'linted'. Returns combined findings grouped by rule.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in stagingLintInput) (*mcp.CallToolResult, stagingLintResult, error) {
			out, err := handleStagingLint(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_staging_cluster",
			Description: `Identity replay gate for one staged ingestion_run_id. Every new staging row must carry a resolved source_coordinate and is compared only with the one eligible current materialization-profile snapshot. Ordinary graph identities match the canonical identity tuple; external references additionally require the exact authority-owned content digest. Semantic payload comparison is fail-closed until a sanctioned source-authority resolver exists.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in stagingClusterInput) (*mcp.CallToolResult, stagingClusterResult, error) {
			out, err := handleStagingCluster(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_staging_dedup_verify",
			Description: `Fail-closed compatibility endpoint for legacy verify_needed rows. OOD retrieval metadata cannot substitute for source contract/payload content; semantic comparison requires a sanctioned resolver for the owning source authority.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in stagingDedupVerifyInput) (*mcp.CallToolResult, stagingDedupVerifyResult, error) {
			out, err := handleStagingDedupVerify(ctx, env, in)
			return textResult(out, err), out, err
		},
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_staging_promote",
			Description: `Atomically promote one complete staged ingestion_run_id through the OODGraph-v2 materialization path. Every non-duplicate concept and every edge must have pipeline_state='linted' and lint_status='pass'; one failed or unlinted row rejects the whole run. External rows consume the trusted load-time byte/locator receipt and freshness policy without a second fetch. Confirmed admitted duplicates are skipped and counted.`,
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, in stagingPromoteInput) (*mcp.CallToolResult, stagingPromoteResult, error) {
			out, err := handleStagingPromote(ctx, env, in)
			return textResult(out, err), out, err
		},
	)
	addTraceCodeTool(server)

	// Streamable HTTP transport per the MCP 2025-11-25 spec. The SDK's
	// StreamableHTTPHandler is an http.Handler; we serve it from a plain
	// net/http.Server bound to cfg.ListenAddress.
	//
	// Stateless=true: spec-graph holds no per-session state. Historical
	// snapshot selection is an explicit graph_snapshot_id in each typed read;
	// omitted means derive current for that request. Stateless mode skips
	// Mcp-Session-Id validation and
	// closes the temporary session after each request — simpler, and lets the
	// process be restarted under the client without breaking sessions.
	//
	// DNS-rebinding protection is on by default (any request arriving via a
	// localhost address with a non-localhost Host header is 403'd). The
	// localhost bind (127.0.0.1) is also enforced by net.Listen on the address
	// the config supplies — we recommend 127.0.0.1:<port> in
	// spec-graph.config.json. Production requests fail closed in
	// productionCallerContextMiddleware unless an in-process verified-bearer
	// adapter supplies TokenInfo with an organization_id claim. Raw HTTP
	// headers are never treated as identity. validateMCPRuntimeComposition
	// prevents the bare handler from booting in production until that adapter
	// and the admitted external-ingestion circuit adapter are wired.
	httpHandler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			Stateless: true,
		},
	)
	srv := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           httpHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown on context cancellation. ctx is cancelled by main's
	// signal handler on SIGINT / SIGTERM, which lets in-flight tool calls
	// finish before the process exits.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(os.Stderr, "spec-graph: listening on %s (Streamable HTTP MCP)\n", cfg.ListenAddress)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}

func validateMCPRuntimeComposition(cfg SpecGraphConfig) error {
	if cfg.Mode == ModeProduction {
		return ErrProductionRuntimeCompositionUnavailable
	}
	return nil
}

func productionCallerContextMiddleware(cfg SpecGraphConfig) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if cfg.Mode != ModeProduction {
				return next(ctx, method, req)
			}
			if req == nil || req.GetExtra() == nil || req.GetExtra().TokenInfo == nil {
				return nil, fmt.Errorf("production CallerContext requires verified bearer TokenInfo")
			}
			organizationID, ok := req.GetExtra().TokenInfo.Extra["organization_id"].(string)
			if !ok {
				return nil, fmt.Errorf("production CallerContext verified bearer TokenInfo requires string organization_id claim")
			}
			if err := validateCallerOrganizationID(organizationID); err != nil {
				return nil, fmt.Errorf("production CallerContext organization_id invalid: %w", err)
			}
			return next(withCallerOrganizationID(ctx, organizationID), method, req)
		}
	}
}

func addImportTool(server *mcp.Server, env *Env) {
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_import",
			Description: `Bulk materialization of multiple submissions and typed relationships into one OODGraph-v2 snapshot. Pass submissions inline or as a JSON file path; relationships resolve source_canonical_name and target_canonical_name only against submissions in this same batch. External-reference kinds require caller identity fields in source_coordinate; source_content_hash is an optional expectation, while digest owner, observed_at, and version_coordinate are trusted outputs. Before any external I/O, the injected authorization resolver must bind the kernel-resolved organization, exact source/representation locator, principal, affirmative grant, policy version, decision, method, content/trust classes, ceilings, validity window, and body-custody disposition. Canonical identity hashes transport-decoded representation bytes, while raw transfer hash/length remain separate occurrence evidence. Exact authorized bytes archive through the protected SOURCE RECORD/AGFS source-carrier boundary before parsing; OODGraph stores only the v4 receipt's authority-bound coordinates/digests and promotion refuses receipt-only custody. External relationships are restricted to the OOD protocol's eight labels and the complete batch is all-or-none.`,
		},
		func(ctx context.Context, req *mcp.CallToolRequest, in importInput) (*mcp.CallToolResult, ImportResult, error) {
			// The SDK applies JSON Schema by decoding Arguments to map[string]any
			// and re-marshalling before it decodes importInput. That normalization
			// necessarily collapses duplicate JSON members. Inspect the untouched
			// wire Arguments retained on CallToolRequest before trusting the typed
			// value, or duplicate identity/relationship keys remain last-wins at
			// the live MCP surface despite strict struct decoders.
			if req == nil || req.Params == nil {
				err := fmt.Errorf("spec_graph_import request arguments unavailable")
				return textResult(ImportResult{}, err), ImportResult{}, err
			}
			if err := rejectDuplicateJSONKeysRecursive(req.Params.Arguments, "spec_graph_import.arguments"); err != nil {
				return textResult(ImportResult{}, err), ImportResult{}, err
			}
			out, err := handleImport(ctx, env, in)
			return textResult(out, err), out, err
		},
	)
}

func addStagingLoadTool(server *mcp.Server, env *Env) {
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_staging_load",
			Description: `Bulk INSERT concepts + edges into staging_concepts / staging_edges. Mints an ingestion_run_id when absent and sets loaded ordinary concepts to pipeline_state='embedded'. Every concept embedding uses only graph-owned identity/classification coordinates; source contract/payload bodies are excluded. External-reference callers provide authority/class/ref/section identity and omit trusted digest owner, observed_at, and version_coordinate. A typed authorization decision must resolve before external I/O. The v4 body-free receipt binds raw transfer evidence, canonical transport-decoded evidence identity, representation and authority declarations, grant/policy/decision coordinates, tenant, custody disposition, and—when storage is authorized—an immutable AGFS file-version/archive digest. Receipt-only no_local_body_custody may stage for audit but cannot promote; exact AGFS custody archives before locator parsing and later hydrates byte ranges only through the protected SOURCE RECORD/AGFS external-carrier resolver, never ordinary fs.file.read.`,
		},
		func(ctx context.Context, req *mcp.CallToolRequest, in stagingLoadInput) (*mcp.CallToolResult, stagingLoadResult, error) {
			// The SDK's typed decode normalizes through map[string]any. Inspect
			// untouched wire Arguments before trusting the typed staging batch,
			// exactly as import does, or nested duplicate identity keys become
			// last-wins at the live MCP surface.
			if req == nil || req.Params == nil {
				err := fmt.Errorf("spec_graph_staging_load request arguments unavailable")
				return textResult(stagingLoadResult{}, err), stagingLoadResult{}, err
			}
			if err := rejectDuplicateJSONKeysRecursive(req.Params.Arguments, "spec_graph_staging_load.arguments"); err != nil {
				return textResult(stagingLoadResult{}, err), stagingLoadResult{}, err
			}
			out, err := handleStagingLoad(ctx, env, in)
			return textResult(out, err), out, err
		},
	)
}

func textResult(v interface{}, err error) *mcp.CallToolResult {
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		}
	}
	b, mErr := json.MarshalIndent(v, "", "  ")
	if mErr != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: mErr.Error()}},
		}
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}
}
