package providerplan

// This is deliberately an integration boundary test, not a boot-nil check:
// the protected launcher is connected to a real local gRPC Spanner endpoint.
// The complete positive fixture is assembled below this same server shape so
// hostile cases cannot replace the source verifier with a caller callback.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/apiv1/spannerpb"
	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type sourceProofIntegrationSpanner struct {
	spannerpb.UnimplementedSpannerServer
	serveCurrentHead bool
	rows             []oodpublication.SpannerRow
	fixture          *oodtestfixture.Fixture
}

func (sourceProofIntegrationSpanner) CreateSession(context.Context, *spannerpb.CreateSessionRequest) (*spannerpb.Session, error) {
	return &spannerpb.Session{Name: "projects/p/instances/i/databases/d/sessions/source-proof"}, nil
}
func (sourceProofIntegrationSpanner) BatchCreateSessions(context.Context, *spannerpb.BatchCreateSessionsRequest) (*spannerpb.BatchCreateSessionsResponse, error) {
	return &spannerpb.BatchCreateSessionsResponse{Session: []*spannerpb.Session{{Name: "projects/p/instances/i/databases/d/sessions/source-proof"}}}, nil
}
func (sourceProofIntegrationSpanner) BeginTransaction(context.Context, *spannerpb.BeginTransactionRequest) (*spannerpb.Transaction, error) {
	return &spannerpb.Transaction{Id: []byte("source-proof-ro")}, nil
}
func sourceProofSendRow(columns []string, values map[string]interface{}, send func(*spannerpb.PartialResultSet) error) error {
	fields := make([]*spannerpb.StructType_Field, len(columns))
	row := make([]*structpb.Value, len(columns))
	for i, name := range columns {
		v, present := values[name]
		if !present {
			return status.Errorf(codes.InvalidArgument, "fixture lacks column %s", name)
		}
		code, value := sourceProofValue(name, v)
		fields[i] = &spannerpb.StructType_Field{Name: name, Type: &spannerpb.Type{Code: code}}
		if code == spannerpb.TypeCode_ARRAY {
			fields[i].Type.ArrayElementType = &spannerpb.Type{Code: spannerpb.TypeCode_STRING}
		}
		row[i] = value
	}
	return send(&spannerpb.PartialResultSet{Metadata: &spannerpb.ResultSetMetadata{RowType: &spannerpb.StructType{Fields: fields}}, Values: row})
}
func sourceProofValue(column string, v interface{}) (spannerpb.TypeCode, *structpb.Value) {
	if v == nil {
		if strings.HasSuffix(column, "_at") || column == "valid_from" || column == "valid_until" {
			return spannerpb.TypeCode_TIMESTAMP, structpb.NewNullValue()
		}
		return spannerpb.TypeCode_STRING, structpb.NewNullValue()
	}
	switch x := v.(type) {
	case int64:
		return spannerpb.TypeCode_INT64, structpb.NewStringValue(fmt.Sprintf("%d", x))
	case bool:
		return spannerpb.TypeCode_BOOL, structpb.NewBoolValue(x)
	case []string:
		items := make([]*structpb.Value, len(x))
		for i := range x {
			items[i] = structpb.NewStringValue(x[i])
		}
		return spannerpb.TypeCode_ARRAY, &structpb.Value{Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: items}}}
	case time.Time:
		return spannerpb.TypeCode_TIMESTAMP, structpb.NewStringValue(x.Format(time.RFC3339Nano))
	case oodpublication.CanonicalJSON:
		return spannerpb.TypeCode_JSON, structpb.NewStringValue(string(x))
	case []byte:
		return spannerpb.TypeCode_BYTES, structpb.NewStringValue(base64.StdEncoding.EncodeToString(x))
	default:
		return spannerpb.TypeCode_STRING, structpb.NewStringValue(fmt.Sprint(v))
	}
}
func (s sourceProofIntegrationSpanner) StreamingRead(req *spannerpb.ReadRequest, stream spannerpb.Spanner_StreamingReadServer) error {
	for _, row := range s.rows {
		if row.Table != req.Table || !sourceProofReadKeyMatches(req, row) {
			continue
		}
		return sourceProofSendRow(req.Columns, row.Columns, stream.Send)
	}
	return status.Error(codes.NotFound, "fixture row absent")
}
func sourceProofReadKeyMatches(req *spannerpb.ReadRequest, row oodpublication.SpannerRow) bool {
	if req.KeySet == nil || len(req.KeySet.Keys) == 0 {
		return true
	}
	key := req.KeySet.Keys[0].Values
	if len(key) != len(row.KeyColumns) {
		return false
	}
	for i, name := range row.KeyColumns {
		if fmt.Sprint(row.Columns[name]) != key[i].GetStringValue() {
			return false
		}
	}
	return true
}
func (s sourceProofIntegrationSpanner) ExecuteStreamingSql(req *spannerpb.ExecuteSqlRequest, stream spannerpb.Spanner_ExecuteStreamingSqlServer) error {
	// A missing head is an authentic Spanner query result.  In particular, this
	// must not be converted into an attestation-authority result.
	if strings.Contains(req.Sql, "OODGraphSnapshotHeads") {
		if s.serveCurrentHead {
			columns := []string{"graph_snapshot_id", "graph_version", "head_generation", "closure_hash", "verification_certificate_id", "verification_certificate_hash", "snapshot_envelope_hash", "materialization_run_id", "materialization_profile_id", "materialization_profile_version", "materialization_profile_digest", "snapshot_state", "status", "run_state", "certificate_hash"}
			values := []string{"123e4567-e89b-12d3-a456-426614174001", "1", "1", strings.Repeat("a", 64), "123e4567-e89b-12d3-a456-426614174002", strings.Repeat("b", 64), strings.Repeat("c", 64), "123e4567-e89b-12d3-a456-426614174003", "123e4567-e89b-12d3-a456-426614174004", "v1", strings.Repeat("d", 64), "sealed", "active", "sealed", strings.Repeat("b", 64)}
			if s.fixture != nil {
				f := s.fixture
				values = []string{fmt.Sprint(f.Plan.Snapshot.Columns["graph_snapshot_id"]), "1", "1", f.Certificate.ClosureHash, f.Certificate.VerificationCertificateID, f.Certificate.VerificationCertificateHash, strings.Repeat("e", 64), f.Certificate.MaterializationRunID, f.Certificate.MaterializationProfileID, f.Certificate.MaterializationProfileVersion, f.Certificate.MaterializationProfileDigest, "sealed", "active", "sealed", f.Certificate.VerificationCertificateHash}
			}
			fields := make([]*spannerpb.StructType_Field, len(columns))
			row := make([]*structpb.Value, len(columns))
			for i := range columns {
				code := spannerpb.TypeCode_STRING
				if columns[i] == "graph_version" || columns[i] == "head_generation" {
					code = spannerpb.TypeCode_INT64
				}
				fields[i] = &spannerpb.StructType_Field{Name: columns[i], Type: &spannerpb.Type{Code: code}}
				row[i] = structpb.NewStringValue(values[i])
			}
			return stream.Send(&spannerpb.PartialResultSet{Metadata: &spannerpb.ResultSetMetadata{RowType: &spannerpb.StructType{Fields: fields}}, Values: row})
		}
		return nil
	}
	if table, columns, ok := sourceProofQueryShape(req.Sql); ok {
		emitted := false
		for _, row := range s.rows {
			if row.Table != table || !sourceProofQueryMatches(req, row) {
				continue
			}
			if err := sourceProofSendRow(columns, row.Columns, stream.Send); err != nil {
				return err
			}
			emitted = true
		}
		if !emitted {
			if _, selected := req.Params.GetFields()["id"]; selected {
				return status.Errorf(codes.NotFound, "fixture lookup absent: %s", req.Sql)
			}
		}
		return nil
	}
	return status.Errorf(codes.InvalidArgument, "unexpected query before current-head selection: %s", req.Sql)
}
func sourceProofQueryShape(sql string) (string, []string, bool) {
	sql = strings.ReplaceAll(sql, "\n", " ")
	start, from := strings.Index(sql, "SELECT "), strings.Index(sql, " FROM ")
	if start != 0 || from < 7 {
		return "", nil, false
	}
	columns := strings.Split(strings.ReplaceAll(sql[7:from], " ", ""), ",")
	rest := strings.Fields(sql[from+6:])
	if len(rest) == 0 {
		return "", nil, false
	}
	return rest[0], columns, true
}
func sourceProofQueryMatches(req *spannerpb.ExecuteSqlRequest, row oodpublication.SpannerRow) bool {
	params := req.Params.GetFields()
	if org, ok := params["org"]; ok && fmt.Sprint(row.Columns["organization_id"]) != org.GetStringValue() {
		return false
	}
	idColumn := sourceProofPrimaryIDColumn(row.Table)
	for parameter, column := range map[string]string{"id": idColumn, "hash": "manifest_node_hash", "node": "manifest_node_hash"} {
		if v, ok := params[parameter]; ok && fmt.Sprint(row.Columns[column]) != v.GetStringValue() {
			return false
		}
	}
	return true
}

func sourceProofPrimaryIDColumn(table string) string {
	switch table {
	case "OODGraphClosureVerificationCertificates":
		return "verification_certificate_id"
	case "OODGraphManifestNodes", "OODGraphManifestEntries":
		return "manifest_node_hash"
	case "OODGraphObjects":
		return "graph_object_id"
	case "OODGraphSymbols":
		return "symbol_id"
	case "OODGraphEdges":
		return "graph_edge_id"
	case "OODGraphExternalFetchBatches":
		return "fetch_batch_id"
	case "OODGraphRelationshipEvidence":
		return "relationship_evidence_hash"
	case "OODGraphAPIPropertyFacts":
		return "api_property_fact_hash"
	case "OODGraphGraphFactEvidenceLocators":
		return "graph_fact_locator_hash"
	case "OODGraphProjectionArtifacts":
		return "projection_artifact_id"
	default:
		return "receipt_id"
	}
}

// sourceProofIntegrationAuthority has no proof shortcut: it merely supplies
// the narrow owner capabilities required to construct the real proof
// authority. The positive fixture asserts these methods only after local
// closure and batch verification have completed.
type sourceProofIntegrationAuthority struct {
	productionSourceOODFixtureAuthority
}

type sourceProofFixtureAuthority struct{ fixture oodtestfixture.Fixture }

func (a sourceProofFixtureAuthority) VerifyClosureAttestation(ctx context.Context, c oodevidence.ClosureCertificateV8) error {
	return a.fixture.Attestor.VerifyClosureAttestation(ctx, c)
}
func (sourceProofFixtureAuthority) AdmittedNoncomponentRoleCounts(context.Context, oodevidence.BatchV8) (map[string]int64, error) {
	return map[string]int64{}, nil
}
func (sourceProofFixtureAuthority) ResolveCanonicalComponentManifest(context.Context, oodevidence.BatchV8) ([]oodevidence.ComponentManifestTuple, error) {
	return nil, nil
}
func (a sourceProofFixtureAuthority) ResolveAPIPropertyPayloadSchema(_ context.Context, id, v, d, p string) (oodpublication.AdmittedAPIPropertyPayloadSchema, error) {
	s := a.fixture.PropertySchema
	if s.ArtifactID != id || s.Version != v || s.Digest != d || s.Profile != p {
		return s, fmt.Errorf("schema")
	}
	return s, nil
}
func (a sourceProofFixtureAuthority) AttestCurrentProviderDocumentationEvidence(_ context.Context, c oodpublication.CurrentSealedClosure, r DocumentationFactoryProductionSourceOODReadRequest, _ oodevidence.VerifiedClosureV8, _ []oodevidence.VerifiedBatchV8, m []DocumentationFactoryProductionSourceOODSpannerMembershipRow) (DocumentationFactoryProductionSourceOODProofAttestation, error) {
	if len(m) != 1 {
		return DocumentationFactoryProductionSourceOODProofAttestation{}, fmt.Errorf("membership")
	}
	g := productionSourceOwnerObservation(r.Request)
	g.OrganizationID = r.Expected.OrganizationID
	b := DocumentationFactoryProductionSourceOODEvidenceBindingRow{Identity: r.Request.EvidenceIdentities[0], EvidenceIdentitySHA256: m[0].EvidenceIdentitySHA256, ReceiptID: m[0].ReceiptID, ReceiptSHA256: m[0].ReceiptSHA256, FetchBatchID: m[0].FetchBatchID, FetchBatchCertificateID: c.CertificateID, FetchBatchCertificateSHA256: c.CertificateHash, ArchiveBindingSHA256: m[0].ArchiveBindingSHA256, RelationshipEvidenceSHA256: strings.Repeat("a", 64), LocatorManifestSHA256: strings.Repeat("b", 64), ExternalCurrentValidityReference: "fixture-current", ExternalCurrentValiditySHA256: strings.Repeat("c", 64)}
	return DocumentationFactoryProductionSourceOODProofAttestation{CurrentGeneration: g, ExternalCurrentValidityReference: "fixture-current", ExternalCurrentValiditySHA256: strings.Repeat("c", 64), Bindings: []DocumentationFactoryProductionSourceOODEvidenceBindingRow{b}}, nil
}

// sourceProofFixtureRequest derives the caller's body-free identity from the
// same archived receipt used by the physical closure.  It is deliberately
// shared by the positive and hostile cases below: a hostile case is allowed
// to correlate a package identity with a substituted physical receipt, but it
// is never allowed to select a different closure or bypass reconciliation.
func sourceProofFixtureRequest(t *testing.T, f oodtestfixture.Fixture) (DocumentationFactoryProductionSourceOwnerBindingExpectation, DocumentationFactoryProductionSourceVerificationRequest) {
	t.Helper()
	expected := productionSourceOwnerBindingExpectation()
	expected.OrganizationID = f.Certificate.OrganizationID
	r := productionSourceOwnerRequestFixture(t)
	r.EvidenceIdentities[0].SourceContentSHA256 = f.Receipt.SourceContentHash
	r.EvidenceIdentities[0].SourceContentByteCount = f.Receipt.EvidenceArchiveByteCount
	root, err := documentationFactoryProviderEvidenceIdentitySetRoot(r.EvidenceIdentities)
	if err != nil {
		t.Fatal(err)
	}
	r.EvidenceIdentitySetRootSHA256 = root
	return expected, r
}

func sourceProofFixtureRowsWithReceiptMutation(t *testing.T, f oodtestfixture.Fixture, mutate func(map[string]interface{})) []oodpublication.SpannerRow {
	t.Helper()
	rows := sourceProofFixtureRows(t, f)
	for i := range rows {
		if rows[i].Table != "OODGraphExternalFetchReceipts" {
			continue
		}
		columns := make(map[string]interface{}, len(rows[i].Columns))
		for k, v := range rows[i].Columns {
			columns[k] = v
		}
		mutate(columns)
		rows[i].Columns = columns
		return rows
	}
	t.Fatal("fixture has no immutable external-fetch receipt")
	return nil
}

// The per-batch receipt tree is immutable evidence addressed from the sealed
// batch, but is not one of the nine snapshot-root trees.  Production reads it
// after reconciling the nine roots; model that physical database shape here
// without smuggling it into the closure roster.
func sourceProofFixtureRows(t *testing.T, f oodtestfixture.Fixture) []oodpublication.SpannerRow {
	t.Helper()
	entryBytes, nodeBytes := sourceProofFixtureBatchManifestByteCounts(t, f)
	rows := append([]oodpublication.SpannerRow(nil), f.ImmutableRows...)
	var node, entry oodpublication.SpannerRow
	root := ""
	for _, row := range f.ImmutableRows {
		switch row.Table {
		case "OODGraphManifestNodes":
			if node.Table == "" {
				node = row
			}
		case "OODGraphManifestEntries":
			if entry.Table == "" {
				entry = row
			}
		case "OODGraphExternalFetchBatches":
			root, _ = row.Columns["batch_receipt_manifest_root_hash"].(string)
		}
	}
	if node.Table == "" || entry.Table == "" || root == "" {
		t.Fatal("fixture lacks manifest row templates")
	}
	clone := func(row oodpublication.SpannerRow) oodpublication.SpannerRow {
		out := row
		out.Columns = make(map[string]interface{}, len(row.Columns))
		for k, v := range row.Columns {
			out.Columns[k] = v
		}
		return out
	}
	node = clone(node)
	node.Columns["manifest_node_hash"] = root
	node.Columns["manifest_kind"] = "fetch_batch_receipt"
	node.Columns["node_kind"] = "leaf"
	node.Columns["node_level"] = int64(0)
	node.Columns["entry_count"] = int64(1)
	node.Columns["transitive_member_count"] = int64(1)
	node.Columns["canonical_byte_count"] = nodeBytes
	entry = clone(entry)
	entry.Columns["manifest_node_hash"] = root
	entry.Columns["entry_ordinal"] = int64(0)
	entry.Columns["entry_kind"] = "receipt"
	entry.Columns["member_id"] = f.Receipt.ReceiptID
	entry.Columns["member_hash"] = f.Receipt.RedactedTransportEvidenceDigest
	entry.Columns["child_manifest_node_hash"] = nil
	entry.Columns["canonical_entry_byte_count"] = entryBytes
	rows = append(rows, node, entry)
	return rows
}

// The batch receipt tree is evidence outside the snapshot's nine roots, but
// its physical manifest rows still use the same self-describing byte counts
// as its sealed typed manifest.  Derive those counts from the exact receipt
// rather than inheriting arbitrary values from a snapshot-manifest template.
func sourceProofFixtureBatchManifestByteCounts(t *testing.T, f oodtestfixture.Fixture) (int64, int64) {
	t.Helper()
	digest, err := oodcanon.DigestHex(f.Receipt.RedactedTransportEvidenceDigest)
	if err != nil {
		t.Fatal(err)
	}
	fields := []oodcanon.NamedValue{
		{Name: "entry_ordinal", Value: oodcanon.I64(0)},
		{Name: "entry_kind", Value: oodcanon.String("receipt")},
		{Name: "member_id", Value: oodcanon.String(f.Receipt.ReceiptID)},
		{Name: "member_hash", Value: digest},
		{Name: "child_manifest_node_hash", Value: oodcanon.NullValue(oodcanon.SHA256)},
		{Name: "canonical_entry_byte_count", Value: oodcanon.I64(0)},
	}
	entry, err := oodcanon.EncodeNestedRecord(oodcanon.ManifestLeafV1().Fields[7].Element.Nested, fields)
	if err != nil {
		t.Fatal(err)
	}
	entryBytes := int64(len(entry))
	fields[len(fields)-1].Value = oodcanon.I64(entryBytes)
	record := oodcanon.RecordValue{
		"manifest_kind":           oodcanon.String("fetch_batch_receipt"),
		"entry_count":             oodcanon.I64(1),
		"transitive_member_count": oodcanon.I64(1),
		"canonical_byte_count":    oodcanon.I64(0),
		"ordered_entry_tuples":    {Type: oodcanon.Array, Presence: oodcanon.Present, Elements: []oodcanon.Value{{Type: oodcanon.Record, Presence: oodcanon.Present, Fields: fields}}},
	}
	node, err := oodcanon.Encode(oodcanon.ManifestLeafV1(), record)
	if err != nil {
		t.Fatal(err)
	}
	return entryBytes, int64(len(node))
}

func sourceProofFixtureRowsWithBatchManifestEntryMutation(t *testing.T, f oodtestfixture.Fixture, mutate func(map[string]interface{})) []oodpublication.SpannerRow {
	t.Helper()
	rows := sourceProofFixtureRows(t, f)
	batchRoot := ""
	for _, row := range f.ImmutableRows {
		if row.Table == "OODGraphExternalFetchBatches" {
			batchRoot, _ = row.Columns["batch_receipt_manifest_root_hash"].(string)
			break
		}
	}
	for i := range rows {
		if rows[i].Table != "OODGraphManifestEntries" || rows[i].Columns["manifest_node_hash"] != batchRoot {
			continue
		}
		columns := make(map[string]interface{}, len(rows[i].Columns))
		for k, v := range rows[i].Columns {
			columns[k] = v
		}
		mutate(columns)
		rows[i].Columns = columns
		return rows
	}
	t.Fatal("fixture has no physical batch receipt manifest entry")
	return nil
}

func (sourceProofIntegrationAuthority) ResolveAPIPropertyPayloadSchema(context.Context, string, string, string, string) (oodpublication.AdmittedAPIPropertyPayloadSchema, error) {
	return oodpublication.AdmittedAPIPropertyPayloadSchema{Fields: []oodpublication.APIPropertyPayloadField{{Name: "name", Type: oodcanon.UTF8}}}, status.Error(codes.FailedPrecondition, "property schema requested before fixture row was installed")
}
func (sourceProofIntegrationAuthority) AttestCurrentProviderDocumentationEvidence(context.Context, oodpublication.CurrentSealedClosure, DocumentationFactoryProductionSourceOODReadRequest, oodevidence.VerifiedClosureV8, []oodevidence.VerifiedBatchV8, []DocumentationFactoryProductionSourceOODSpannerMembershipRow) (DocumentationFactoryProductionSourceOODProofAttestation, error) {
	return DocumentationFactoryProductionSourceOODProofAttestation{}, status.Error(codes.FailedPrecondition, "attestation requested before local proof fixture was installed")
}

func newSourceProofIntegrationClient(t *testing.T, server sourceProofIntegrationSpanner) (*spanner.Client, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	spannerpb.RegisterSpannerServer(g, server)
	go g.Serve(l)
	c, err := spanner.NewClient(context.Background(), "projects/p/instances/i/databases/d", option.WithEndpoint(l.Addr().String()), option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())), option.WithoutAuthentication())
	if err != nil {
		g.Stop()
		l.Close()
		t.Fatal(err)
	}
	return c, func() { c.Close(); g.Stop(); l.Close() }
}

func TestProductionSourceQualificationUsesProtectedLauncherAndRealSpannerCurrentHead(t *testing.T) {
	client, done := newSourceProofIntegrationClient(t, sourceProofIntegrationSpanner{})
	defer done()
	launcher, err := NewDocumentationFactoryProductionSourceProtectedLauncher(client, productionSourceOwnerBindingExpectation(), sourceProofIntegrationAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := launcher.ResolveDocumentationFactoryProductionSourceVerifier(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), productionSourceOwnerRequestFixture(t))
	if err == nil || !strings.Contains(err.Error(), "current head absent") {
		t.Fatalf("protected real-Spanner qualification error=%v, want current-head refusal", err)
	}
}

func TestProductionSourceQualificationReadsEligibleCurrentHeadBeforeMembership(t *testing.T) {
	client, done := newSourceProofIntegrationClient(t, sourceProofIntegrationSpanner{serveCurrentHead: true})
	defer done()
	launcher, err := NewDocumentationFactoryProductionSourceProtectedLauncher(client, productionSourceOwnerBindingExpectation(), sourceProofIntegrationAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := launcher.ResolveDocumentationFactoryProductionSourceVerifier(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), productionSourceOwnerRequestFixture(t))
	if err == nil || !strings.Contains(err.Error(), "fixture row absent") {
		t.Fatalf("eligible current head did not advance to the protected membership read: %v", err)
	}
}

// The full physical closure used by the next test stages is built by the
// shared support package through real receipt, batch, locator, manifest and
// closure verifiers. Keeping this assertion here prevents the Spanner bridge
// from silently drifting back to hand-authored opaque proof values.
func TestProductionSourceQualificationFixtureHasVerifiedAllRootsClosure(t *testing.T) {
	fixture := oodtestfixture.Build(context.Background(), t)
	if err := oodevidence.ValidateVerifiedClosureV8(fixture.Proof); err != nil {
		t.Fatalf("shared physical OOD fixture proof: %v", err)
	}
	if len(fixture.ImmutableRows) == 0 || len(fixture.Certificate.Roots) != 9 || len(fixture.Closure.Nodes) < 9 {
		t.Fatalf("shared fixture is not a complete nine-root physical closure")
	}
	for _, kind := range []string{"source", "object", "symbol", "edge", "api_property", "graph_fact_locator", "receipt", "structural_projection", "violation"} {
		if root := fixture.Certificate.Roots[kind]; root.Hash == "" || root.Count < 0 {
			t.Fatalf("shared fixture is missing fixed closure root %q", kind)
		}
	}
	auxRoots := map[string]bool{}
	for _, row := range fixture.ImmutableRows {
		switch row.Table {
		case "OODGraphObjects":
			if row.Columns["object_class"] == "api_symbol" {
				if root, _ := row.Columns["api_element_role_locator_manifest_hash"].(string); root != "" {
					auxRoots[root] = true
				}
			}
		case "OODGraphRelationshipEvidence":
			if row.Columns["evidence_source_kind"] == "external_document_evidence" && row.Columns["edge_label"] == "documents" {
				if root, _ := row.Columns["graph_fact_locator_manifest_hash"].(string); root != "" {
					auxRoots[root] = true
				}
			}
		}
	}
	if len(auxRoots) < 2 {
		t.Fatalf("shared fixture lacks distinct retained role/documentation claim roots: %v", auxRoots)
	}
	for root := range auxRoots {
		members, err := oodpublication.ResolveGraphFactLocatorManifestMembers(fixture.ImmutableRows, fixture.Proof.OrganizationID(), root)
		if err != nil || len(members) == 0 {
			t.Fatalf("shared fixture auxiliary locator root %q is not physically resolvable: members=%v err=%v", root, members, err)
		}
	}
}

func TestProductionSourceQualificationAcceptsRealAllRootsSpannerClosure(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	expected, r := sourceProofFixtureRequest(t, f)
	client, done := newSourceProofIntegrationClient(t, sourceProofIntegrationSpanner{serveCurrentHead: true, rows: sourceProofFixtureRows(t, f), fixture: &f})
	defer done()
	launcher, err := NewDocumentationFactoryProductionSourceProtectedLauncher(client, expected, sourceProofFixtureAuthority{fixture: f})
	if err != nil {
		t.Fatal(err)
	}
	v, err := launcher.ResolveDocumentationFactoryProductionSourceVerifier(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), r); err != nil {
		t.Fatalf("real all-roots qualification: %v", err)
	}
}

func TestProductionSourceQualificationHydratesClaimLocatorRoots(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	client, done := newSourceProofIntegrationClient(t, sourceProofIntegrationSpanner{rows: sourceProofFixtureRows(t, f), fixture: &f})
	defer done()
	tx := client.ReadOnlyTransaction()
	defer tx.Close()
	closure, err := readDocumentationFactoryOODManifestClosure(context.Background(), tx, f.Certificate)
	if err != nil {
		t.Fatalf("hydrate claim locator closure: %v", err)
	}
	root := *f.Relationship.GraphFactLocatorManifestHash
	found := false
	for _, n := range closure.Input.Nodes {
		if n.Hash == root {
			found = true
		}
	}
	if !found {
		t.Fatalf("claim locator root %q was not hydrated", root)
	}
	if _, err := oodpublication.ResolveGraphFactLocatorManifestMembers(closure.Input.ImmutableRows, f.Certificate.OrganizationID, root); err != nil {
		t.Fatalf("hydrated claim locator root does not resolve: %v", err)
	}
	globalLocatorMembers := 0
	for _, m := range closure.Input.Members {
		if m.ManifestKind == "graph_fact_locator" && m.Row != nil && m.Row.Table == "OODGraphGraphFactEvidenceLocators" && m.MemberID == f.Locator.LocatorHash {
			globalLocatorMembers++
		}
	}
	if globalLocatorMembers != 1 {
		t.Fatalf("claim locator hydration global member count=%d, want 1", globalLocatorMembers)
	}
}

func TestProductionSourceQualificationRejectsMissingOrForeignClaimLocatorRoot(t *testing.T) {
	for name, mutate := range map[string]func([]oodpublication.SpannerRow, oodtestfixture.Fixture){
		"missing root": func(rows []oodpublication.SpannerRow, _ oodtestfixture.Fixture) {
			for i := range rows {
				if rows[i].Table == "OODGraphObjects" && rows[i].Columns["api_element_role_locator_manifest_hash"] != nil {
					rows[i].Columns["api_element_role_locator_manifest_hash"] = strings.Repeat("f", 64)
					return
				}
			}
		},
		"foreign locator": func(rows []oodpublication.SpannerRow, f oodtestfixture.Fixture) {
			root := *f.Relationship.GraphFactLocatorManifestHash
			for i := range rows {
				if rows[i].Table == "OODGraphManifestEntries" && rows[i].Columns["manifest_node_hash"] == root {
					rows[i].Columns["member_id"] = strings.Repeat("f", 64)
					rows[i].Columns["member_hash"] = strings.Repeat("f", 64)
					return
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := oodtestfixture.Build(context.Background(), t)
			rows := sourceProofFixtureRows(t, f)
			for i := range rows {
				columns := make(map[string]interface{}, len(rows[i].Columns))
				for k, v := range rows[i].Columns {
					columns[k] = v
				}
				rows[i].Columns = columns
			}
			mutate(rows, f)
			client, done := newSourceProofIntegrationClient(t, sourceProofIntegrationSpanner{rows: rows, fixture: &f})
			defer done()
			tx := client.ReadOnlyTransaction()
			defer tx.Close()
			if _, err := readDocumentationFactoryOODManifestClosure(context.Background(), tx, f.Certificate); err == nil {
				t.Fatal("foreign or missing claim locator root accepted")
			}
		})
	}
}

func TestProductionSourceQualificationRejectsCorrelatedReceiptContentSubstitution(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	expected, r := sourceProofFixtureRequest(t, f)
	// Correlate the caller's requested identity to the replacement row.  The
	// active receipt manifest still commits to the original immutable row, so
	// the proof must fail during physical closure reconciliation rather than
	// accepting a matching content lookup.
	badContent := strings.Repeat("f", 64)
	r.EvidenceIdentities[0].SourceContentSHA256 = badContent
	root, err := documentationFactoryProviderEvidenceIdentitySetRoot(r.EvidenceIdentities)
	if err != nil {
		t.Fatal(err)
	}
	r.EvidenceIdentitySetRootSHA256 = root
	rows := sourceProofFixtureRowsWithReceiptMutation(t, f, func(columns map[string]interface{}) {
		columns["source_content_hash"] = badContent
	})
	client, done := newSourceProofIntegrationClient(t, sourceProofIntegrationSpanner{serveCurrentHead: true, rows: rows, fixture: &f})
	defer done()
	launcher, err := NewDocumentationFactoryProductionSourceProtectedLauncher(client, expected, sourceProofFixtureAuthority{fixture: f})
	if err != nil {
		t.Fatal(err)
	}
	v, err := launcher.ResolveDocumentationFactoryProductionSourceVerifier(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), r); err == nil || !strings.Contains(err.Error(), "hydrate manifest closure") {
		t.Fatalf("correlated receipt substitution error=%v, want closure rejection", err)
	}
}

func TestProductionSourceQualificationRejectsArchiveBindingSubstitution(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	expected, r := sourceProofFixtureRequest(t, f)
	rows := sourceProofFixtureRowsWithReceiptMutation(t, f, func(columns map[string]interface{}) {
		columns["evidence_archive_record_digest"] = strings.Repeat("e", 64)
	})
	client, done := newSourceProofIntegrationClient(t, sourceProofIntegrationSpanner{serveCurrentHead: true, rows: rows, fixture: &f})
	defer done()
	launcher, err := NewDocumentationFactoryProductionSourceProtectedLauncher(client, expected, sourceProofFixtureAuthority{fixture: f})
	if err != nil {
		t.Fatal(err)
	}
	v, err := launcher.ResolveDocumentationFactoryProductionSourceVerifier(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), r); err == nil || !strings.Contains(err.Error(), "verify closure") {
		t.Fatalf("archive-binding substitution error=%v, want closure rejection", err)
	}
}

func TestProductionSourceQualificationRejectsBatchManifestEntrySubstitution(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	expected, r := sourceProofFixtureRequest(t, f)
	rows := sourceProofFixtureRowsWithBatchManifestEntryMutation(t, f, func(columns map[string]interface{}) {
		columns["member_hash"] = strings.Repeat("0", 64)
	})
	client, done := newSourceProofIntegrationClient(t, sourceProofIntegrationSpanner{serveCurrentHead: true, rows: rows, fixture: &f})
	defer done()
	launcher, err := NewDocumentationFactoryProductionSourceProtectedLauncher(client, expected, sourceProofFixtureAuthority{fixture: f})
	if err != nil {
		t.Fatal(err)
	}
	v, err := launcher.ResolveDocumentationFactoryProductionSourceVerifier(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), r); err == nil || !strings.Contains(err.Error(), "batch receipt manifest node hash mismatch") {
		t.Fatalf("batch manifest entry substitution error=%v, want canonical-node rejection", err)
	}
}

func TestProductionSourceQualificationRejectsBatchManifestEntryByteCountSubstitution(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	expected, r := sourceProofFixtureRequest(t, f)
	rows := sourceProofFixtureRowsWithBatchManifestEntryMutation(t, f, func(columns map[string]interface{}) {
		columns["canonical_entry_byte_count"] = int64(2)
	})
	client, done := newSourceProofIntegrationClient(t, sourceProofIntegrationSpanner{serveCurrentHead: true, rows: rows, fixture: &f})
	defer done()
	launcher, err := NewDocumentationFactoryProductionSourceProtectedLauncher(client, expected, sourceProofFixtureAuthority{fixture: f})
	if err != nil {
		t.Fatal(err)
	}
	v, err := launcher.ResolveDocumentationFactoryProductionSourceVerifier(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), r); err == nil || !strings.Contains(err.Error(), "receipt manifest entry byte count") {
		t.Fatalf("batch manifest entry byte-count substitution error=%v, want canonical entry-byte-count rejection", err)
	}
}
