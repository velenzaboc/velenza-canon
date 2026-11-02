package providerplan

import (
	"context"
	"net"
	"strings"
	"testing"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/apiv1/spannerpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// hydrationSpanner is intentionally a real gRPC Spanner boundary: ReadRow
// uses StreamingRead and manifest entries use ExecuteStreamingSql.
type hydrationSpanner struct {
	spannerpb.UnimplementedSpannerServer
	badType, wrongTenant, missing, malformed bool
	entryKind                                string
}

func (s *hydrationSpanner) CreateSession(context.Context, *spannerpb.CreateSessionRequest) (*spannerpb.Session, error) {
	return &spannerpb.Session{Name: "projects/p/instances/i/databases/d/sessions/s"}, nil
}
func (s *hydrationSpanner) BatchCreateSessions(context.Context, *spannerpb.BatchCreateSessionsRequest) (*spannerpb.BatchCreateSessionsResponse, error) {
	return &spannerpb.BatchCreateSessionsResponse{Session: []*spannerpb.Session{{Name: "projects/p/instances/i/databases/d/sessions/s"}}}, nil
}

func (s *hydrationSpanner) BeginTransaction(context.Context, *spannerpb.BeginTransactionRequest) (*spannerpb.Transaction, error) {
	return &spannerpb.Transaction{Id: []byte("tx")}, nil
}
func (s *hydrationSpanner) StreamingRead(req *spannerpb.ReadRequest, stream spannerpb.Spanner_StreamingReadServer) error {
	if s.missing {
		return status.Error(codes.NotFound, "missing")
	}
	cols := req.Columns
	vals := make([]*structpb.Value, len(cols))
	fields := make([]*spannerpb.StructType_Field, len(cols))
	for i, c := range cols {
		typ, val := hydrationValue(c, s.badType && c == "fetch_component_ordinal")
		fields[i] = &spannerpb.StructType_Field{Name: c, Type: typ}
		vals[i] = val
	}
	if s.wrongTenant {
		for i, c := range cols {
			if c == "organization_id" {
				vals[i] = structpb.NewStringValue("other-org")
			}
		}
	}
	return stream.Send(&spannerpb.PartialResultSet{Metadata: &spannerpb.ResultSetMetadata{RowType: &spannerpb.StructType{Fields: fields}}, Values: vals})
}
func (s *hydrationSpanner) ExecuteStreamingSql(req *spannerpb.ExecuteSqlRequest, stream spannerpb.Spanner_ExecuteStreamingSqlServer) error {
	cols := []string{"entry_ordinal", "entry_kind", "member_id", "member_hash", "child_manifest_node_hash"}
	types := []*spannerpb.Type{{Code: spannerpb.TypeCode_INT64}, {Code: spannerpb.TypeCode_STRING}, {Code: spannerpb.TypeCode_STRING}, {Code: spannerpb.TypeCode_STRING}, {Code: spannerpb.TypeCode_STRING}}
	fields := make([]*spannerpb.StructType_Field, len(cols))
	for i := range cols {
		fields[i] = &spannerpb.StructType_Field{Name: cols[i], Type: types[i]}
	}
	ord := "0"
	if s.malformed {
		ord = "1"
	}
	kind := s.entryKind
	if kind == "" {
		kind = "receipt"
	}
	values := []*structpb.Value{structpb.NewStringValue(ord), structpb.NewStringValue(kind), structpb.NewStringValue("receipt"), structpb.NewStringValue(strings.Repeat("a", 64)), structpb.NewNullValue()}
	return stream.Send(&spannerpb.PartialResultSet{Metadata: &spannerpb.ResultSetMetadata{RowType: &spannerpb.StructType{Fields: fields}}, Values: values})
}
func hydrationValue(c string, bad bool) (*spannerpb.Type, *structpb.Value) {
	if bad {
		return &spannerpb.Type{Code: spannerpb.TypeCode_STRING}, structpb.NewStringValue("wrong")
	}
	ints := map[string]bool{"fetch_component_ordinal": true, "permission_byte_ceiling": true, "permission_depth_ceiling": true, "transport_raw_byte_count": true, "transport_decoded_byte_count": true, "evidence_archive_byte_count": true, "total_receipt_count": true, "component_receipt_count": true, "completeness_evidence_receipt_count": true, "noncomponent_receipt_count": true, "expected_component_count": true, "source_artifact_count": true, "relationship_evidence_count": true, "object_count": true, "symbol_count": true, "edge_count": true, "api_property_count": true, "graph_fact_locator_count": true, "receipt_count": true, "structural_projection_count": true, "violation_count": true, "source_authority_identity_count": true, "completeness_identity_count": true, "permission_policy_identity_count": true, "archive_binding_identity_count": true, "profile_identity_count": true, "external_source_receipt_eligibility_count": true, "node_level": true, "entry_count": true, "transitive_member_count": true, "canonical_byte_count": true}
	if ints[c] {
		return &spannerpb.Type{Code: spannerpb.TypeCode_INT64}, structpb.NewStringValue("1")
	}
	if c == "sealed" {
		return &spannerpb.Type{Code: spannerpb.TypeCode_BOOL}, structpb.NewBoolValue(true)
	}
	if c == "permission_effective_at" || c == "observed_at" || c == "sealed_at" || c == "permission_expires_at" {
		return &spannerpb.Type{Code: spannerpb.TypeCode_TIMESTAMP}, structpb.NewStringValue("2026-01-01T00:00:00Z")
	}
	if c == "receipt_roles" {
		return &spannerpb.Type{Code: spannerpb.TypeCode_ARRAY, ArrayElementType: &spannerpb.Type{Code: spannerpb.TypeCode_STRING}}, &structpb.Value{Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{structpb.NewStringValue("component")}}}}
	}
	return &spannerpb.Type{Code: spannerpb.TypeCode_STRING}, structpb.NewStringValue(hydrationString(c))
}
func hydrationString(c string) string {
	if c == "organization_id" {
		return "org"
	}
	if c == "fetch_batch_id" {
		return "batch"
	}
	if c == "receipt_id" {
		return "receipt"
	}
	if c == "verification_certificate_id" {
		return "cert"
	}
	if strings.Contains(c, "hash") || strings.Contains(c, "digest") {
		return strings.Repeat("a", 64)
	}
	if strings.HasSuffix(c, "_id") {
		return "00000000-0000-4000-8000-000000000001"
	}
	if c == "manifest_kind" {
		return "fetch_batch_receipt"
	}
	if c == "node_kind" {
		return "leaf"
	}
	return "value"
}
func newHydrationTransaction(t *testing.T, s *hydrationSpanner) (*spanner.ReadOnlyTransaction, func()) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	g := grpc.NewServer()
	spannerpb.RegisterSpannerServer(g, s)
	go g.Serve(l)
	c, e := spanner.NewClient(context.Background(), "projects/p/instances/i/databases/d", option.WithEndpoint(l.Addr().String()), option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())), option.WithoutAuthentication())
	if e != nil {
		t.Fatal(e)
	}
	tx := c.ReadOnlyTransaction()
	return tx, func() { tx.Close(); c.Close(); g.Stop(); l.Close() }
}
func TestOODHydrationRealSpannerRows(t *testing.T) {
	tx, done := newHydrationTransaction(t, &hydrationSpanner{})
	defer done()
	ctx := context.Background()
	if r, e := readDocumentationFactoryOODReceipt(ctx, tx, "org", "receipt"); e != nil || r.FetchComponentOrdinal == nil {
		t.Fatalf("receipt=%+v err=%v", r, e)
	}
	if _, e := readDocumentationFactoryOODBatch(ctx, tx, "org", "batch"); e != nil {
		t.Fatal(e)
	}
	if c, e := readDocumentationFactoryOODClosureCertificate(ctx, tx, "org", "cert"); e != nil || len(c.Roots) != 9 {
		t.Fatalf("certificate=%+v err=%v", c, e)
	}
	if n, e := readDocumentationFactoryOODReceiptManifestNode(ctx, tx, "org", strings.Repeat("a", 64)); e != nil || len(n.Entries) != 1 {
		t.Fatalf("node=%+v err=%v", n, e)
	}
}
func TestOODHydrationRejectsBadRows(t *testing.T) {
	for name, s := range map[string]*hydrationSpanner{"wrong type": {badType: true}, "wrong tenant": {wrongTenant: true}, "missing": {missing: true}, "malformed manifest": {malformed: true}, "legacy member literal": {entryKind: "member"}, "certificate in batch tree": {entryKind: "fetch_batch_certificate"}} {
		t.Run(name, func(t *testing.T) {
			tx, done := newHydrationTransaction(t, s)
			defer done()
			ctx := context.Background()
			if s.malformed || s.entryKind != "" {
				_, e := readDocumentationFactoryOODReceiptManifestNode(ctx, tx, "org", strings.Repeat("a", 64))
				if e == nil {
					t.Fatal("malformed manifest accepted")
				}
				return
			}
			_, e := readDocumentationFactoryOODReceipt(ctx, tx, "org", "receipt")
			if e == nil {
				t.Fatal("bad row accepted")
			}
		})
	}
}
func TestOODHydrationNullableBindings(t *testing.T) {
	if int64Ptr(spanner.NullInt64{}) != nil || !sameNullBinding(spanner.NullString{}, spanner.NullString{}, spanner.NullString{}) || sameNullBinding(spanner.NullString{Valid: true}, spanner.NullString{}, spanner.NullString{Valid: true}) {
		t.Fatal("nullable hydration binding invariant failed")
	}
}
