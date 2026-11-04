package oodpublication

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"google.golang.org/grpc/codes"
)

// SpannerRow carries one complete, schema-closed OOD v8 row. The writer never
// adds defaults or substitutes a partial payload for a physical row.
type SpannerRow struct {
	Table      string
	KeyColumns []string
	Columns    map[string]interface{}
}

type SpannerWritePlan struct {
	OrganizationID, SnapshotKind, SnapshotID, RunID, ClosureHash string
	ImmutableRows                                                []SpannerRow
	Snapshot, Run, Head, Publication                             SpannerRow
}

type SpannerPublicationWriter struct{ Client *spanner.Client }

// SpannerPublicationOutcome distinguishes a successful exact replay from a
// new head advance. Replays deliberately name the already-current immutable
// snapshot; they do not allocate or overwrite a caller-supplied identity.
type SpannerPublicationOutcome struct {
	SnapshotID                   string
	RunID                        string
	GraphVersion, HeadGeneration int64
	Replay                       bool
}

func (w SpannerPublicationWriter) Publish(ctx context.Context, p SpannerWritePlan) error {
	return errors.New("raw OOD8 Spanner publication is forbidden; use PublishVerifiedOutcome")
}

// PublishVerifiedOutcome is the production admission boundary. The opaque
// proof can only be produced by oodevidence after protected closure traversal
// and attestation verification; caller-owned plan hashes are never authority.
func (w SpannerPublicationWriter) PublishVerifiedOutcome(ctx context.Context, proof oodevidence.VerifiedClosureV8, p SpannerWritePlan) (SpannerPublicationOutcome, error) {
	if err := oodevidence.ValidateVerifiedClosureV8(proof); err != nil {
		return SpannerPublicationOutcome{}, fmt.Errorf("verified OOD closure required: %w", err)
	}
	if p.OrganizationID != proof.OrganizationID() || p.Snapshot.Columns["verification_certificate_id"] != proof.CertificateID() || p.Snapshot.Columns["verification_certificate_hash"] != proof.CertificateHash() || p.Run.Columns["candidate_verification_certificate_id"] != proof.CertificateID() || p.Run.Columns["candidate_verification_certificate_hash"] != proof.CertificateHash() {
		return SpannerPublicationOutcome{}, errors.New("write plan does not bind the verified closure proof")
	}
	return w.publishOutcome(ctx, p)
}

func (w SpannerPublicationWriter) publishOutcome(ctx context.Context, p SpannerWritePlan) (SpannerPublicationOutcome, error) {
	if ctx == nil || w.Client == nil {
		return SpannerPublicationOutcome{}, errors.New("OOD8 writer requires protected client and context")
	}
	if err := validateSpannerWritePlan(p); err != nil {
		return SpannerPublicationOutcome{}, err
	}
	for _, row := range p.ImmutableRows {
		if err := immutableInsertOrCompare(ctx, w.Client, row); err != nil {
			return SpannerPublicationOutcome{}, err
		}
	}
	var outcome SpannerPublicationOutcome
	_, err := w.Client.ReadWriteTransaction(ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
		// These precise reads lock only the publication coordinate, candidate
		// identities and selected certificate. No corpus enumeration or scan-max
		// allocation occurs in the RWT.
		current, replay, err := lockPublicationFence(ctx, tx, p)
		if err != nil {
			return err
		}
		if replay {
			replayRun, err := exactReplayRun(p, current.SnapshotID)
			if err != nil {
				return err
			}
			if err := assertRowAbsent(ctx, tx, replayRun); err != nil {
				return err
			}
			if err := bufferInsert(tx, replayRun); err != nil {
				return err
			}
			outcome = current
			return nil
		}
		if err := bufferInsert(tx, p.Snapshot); err != nil {
			return err
		}
		if err := bufferInsert(tx, p.Run); err != nil {
			return err
		}
		for _, row := range []SpannerRow{p.Head, p.Publication} {
			if err := bufferRow(tx, row); err != nil {
				return err
			}
		}
		outcome = SpannerPublicationOutcome{SnapshotID: p.SnapshotID, RunID: p.RunID, GraphVersion: p.Snapshot.Columns["graph_version"].(int64), HeadGeneration: p.Head.Columns["head_generation"].(int64)}
		return nil
	})
	return outcome, err
}

func exactReplayRun(p SpannerWritePlan, currentSnapshotID string) (SpannerRow, error) {
	r := SpannerRow{Table: p.Run.Table, KeyColumns: append([]string(nil), p.Run.KeyColumns...), Columns: map[string]interface{}{}}
	for k, v := range p.Run.Columns {
		r.Columns[k] = v
	}
	r.Columns["target_graph_snapshot_id"] = currentSnapshotID
	r.Columns["state"] = "exact_replay_noop"
	if r.Columns["candidate_closure_hash"] != p.ClosureHash || r.Columns["candidate_verification_certificate_id"] != p.Snapshot.Columns["verification_certificate_id"] || r.Columns["candidate_verification_certificate_hash"] != p.Snapshot.Columns["verification_certificate_hash"] {
		return SpannerRow{}, errors.New("exact replay run does not bind candidate closure")
	}
	return r, nil
}

func validateSpannerWritePlan(p SpannerWritePlan) error {
	if p.OrganizationID == "" || p.SnapshotKind == "" || p.SnapshotID == "" || p.RunID == "" || p.ClosureHash == "" || len(p.ImmutableRows) == 0 {
		return errors.New("OOD8 write plan incomplete")
	}
	if err := exactRow(p.Snapshot, TableSnapshots, snapshotColumns); err != nil {
		return err
	}
	if err := exactRow(p.Run, TableRuns, runColumns); err != nil {
		return err
	}
	if err := exactRow(p.Head, TableSnapshotHeads, snapshotHeadColumns); err != nil {
		return err
	}
	if err := exactRow(p.Publication, TablePublicationState, publicationStateColumns); err != nil {
		return err
	}
	for _, row := range p.ImmutableRows {
		if err := validRow(row); err != nil {
			return err
		}
	}
	cert, err := certificateRow(p)
	if err != nil {
		return err
	}
	if err := verifyCertificateHash(cert.Columns); err != nil {
		return err
	}
	for _, binding := range []struct {
		row          SpannerRow
		column, want string
	}{{p.Snapshot, "organization_id", p.OrganizationID}, {p.Snapshot, "graph_snapshot_id", p.SnapshotID}, {p.Snapshot, "snapshot_kind", p.SnapshotKind}, {p.Snapshot, "materialization_run_id", p.RunID}, {p.Snapshot, "closure_hash", p.ClosureHash}, {p.Run, "organization_id", p.OrganizationID}, {p.Run, "materialization_run_id", p.RunID}, {p.Run, "target_graph_snapshot_id", p.SnapshotID}, {p.Run, "candidate_closure_hash", p.ClosureHash}, {p.Head, "organization_id", p.OrganizationID}, {p.Head, "snapshot_kind", p.SnapshotKind}, {p.Head, "graph_snapshot_id", p.SnapshotID}, {p.Head, "closure_hash", p.ClosureHash}, {p.Publication, "organization_id", p.OrganizationID}} {
		if v, ok := binding.row.Columns[binding.column]; !ok || v != binding.want {
			return fmt.Errorf("write-plan binding %s is not exact", binding.column)
		}
	}
	return nil
}
func exactRow(row SpannerRow, table string, want []string) error {
	if row.Table != table {
		return fmt.Errorf("expected %s", table)
	}
	if err := validRow(row); err != nil {
		return err
	}
	got := keys(row.Columns)
	want = append([]string(nil), want...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("%s lacks exact OOD8 column roster", table)
	}
	if wantKeys := mutableTableKeys(table); !reflect.DeepEqual(row.KeyColumns, wantKeys) {
		return fmt.Errorf("%s lacks exact OOD8 primary key roster", table)
	}
	return nil
}

func mutableTableKeys(table string) []string {
	switch table {
	case TableSnapshots:
		return []string{"organization_id", "graph_snapshot_id"}
	case TableRuns:
		return []string{"organization_id", "materialization_run_id"}
	case TableSnapshotHeads:
		return []string{"organization_id", "snapshot_kind"}
	case TablePublicationState:
		return []string{"organization_id"}
	default:
		return nil
	}
}
func validRow(row SpannerRow) error {
	if row.Table == "" || len(row.KeyColumns) == 0 || len(row.Columns) == 0 {
		return errors.New("incomplete Spanner row")
	}
	for _, k := range row.KeyColumns {
		if _, ok := row.Columns[k]; !ok {
			return fmt.Errorf("key column %s absent", k)
		}
	}
	return nil
}
func keys(m map[string]interface{}) []string {
	r := make([]string, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
func values(row SpannerRow, cols []string) []interface{} {
	r := make([]interface{}, len(cols))
	for i, k := range cols {
		r[i] = row.Columns[k]
	}
	return r
}
func immutableInsertOrCompare(ctx context.Context, c *spanner.Client, row SpannerRow) error {
	cols := keys(row.Columns)
	key := make(spanner.Key, 0, len(row.KeyColumns))
	for _, k := range row.KeyColumns {
		key = append(key, row.Columns[k])
	}
	r, err := c.Single().ReadRow(ctx, row.Table, key, cols)
	if err != nil {
		if spanner.ErrCode(err) != codes.NotFound {
			return err
		}
		_, err = c.Apply(ctx, []*spanner.Mutation{spanner.Insert(row.Table, cols, values(row, cols))})
		// A concurrent identical immutable insert is success only after the
		// winner's bytes are strongly re-read and compared below. Never turn an
		// AlreadyExists response into a blind success.
		if err != nil && spanner.ErrCode(err) != codes.AlreadyExists {
			return err
		}
		r, err = c.Single().ReadRow(ctx, row.Table, key, cols)
		if err != nil {
			return err
		}
	}
	got := make([]interface{}, len(cols))
	if err := r.Columns(got...); err != nil {
		return err
	}
	if err := immutableRowMatches(row, cols, got); err != nil {
		return err
	}
	return nil
}

func immutableRowMatches(row SpannerRow, cols []string, got []interface{}) error {
	for i, k := range cols {
		// The only value that Spanner may replace during an immutable insert is
		// an explicit server commit timestamp. Logical sealing, finishing and
		// caller-supplied timestamps are closure material and compare exactly.
		if immutableServerGeneratedTimestamp(k, row.Columns[k]) {
			continue
		}
		if !reflect.DeepEqual(got[i], row.Columns[k]) {
			return fmt.Errorf("immutable collision %s.%s", row.Table, k)
		}
	}
	return nil
}

func immutableServerGeneratedTimestamp(column string, value interface{}) bool {
	if column != "created_at" && column != "updated_at" {
		return false
	}
	t, ok := value.(time.Time)
	return ok && t.Equal(spanner.CommitTimestamp)
}
func bufferRow(tx *spanner.ReadWriteTransaction, row SpannerRow) error {
	cols := keys(row.Columns)
	return tx.BufferWrite([]*spanner.Mutation{spanner.InsertOrUpdate(row.Table, cols, values(row, cols))})
}
func bufferInsert(tx *spanner.ReadWriteTransaction, row SpannerRow) error {
	cols := keys(row.Columns)
	return tx.BufferWrite([]*spanner.Mutation{spanner.Insert(row.Table, cols, values(row, cols))})
}
func lockPublicationFence(ctx context.Context, tx *spanner.ReadWriteTransaction, p SpannerWritePlan) (SpannerPublicationOutcome, bool, error) {
	var priorSnapshot, priorClosure, priorEnvelope string
	var priorHead int64
	row, err := tx.ReadRow(ctx, TableSnapshotHeads, spanner.Key{p.OrganizationID, p.SnapshotKind}, []string{"graph_snapshot_id", "head_generation", "closure_hash", "snapshot_envelope_hash"})
	if err == nil {
		err = row.Columns(&priorSnapshot, &priorHead, &priorClosure, &priorEnvelope)
	}
	headMissing := spanner.ErrCode(err).String() == "NotFound"
	if err != nil && !headMissing {
		return SpannerPublicationOutcome{}, false, err
	}
	var priorGraph, priorPublication int64
	var stateHash string
	row, err = tx.ReadRow(ctx, TablePublicationState, spanner.Key{p.OrganizationID}, []string{"current_graph_version", "publication_generation", "publication_state_hash"})
	if err == nil {
		err = row.Columns(&priorGraph, &priorPublication, &stateHash)
	}
	stateMissing := spanner.ErrCode(err).String() == "NotFound"
	if err != nil && !stateMissing {
		return SpannerPublicationOutcome{}, false, err
	}
	if !headMissing && priorClosure == p.ClosureHash {
		if err := verifyCurrentReplay(ctx, tx, p.OrganizationID, priorSnapshot, priorClosure); err != nil {
			return SpannerPublicationOutcome{}, false, err
		}
		return SpannerPublicationOutcome{SnapshotID: priorSnapshot, RunID: p.RunID, GraphVersion: priorGraph, HeadGeneration: priorHead, Replay: true}, true, nil
	}
	// A plan must never convert an old sealed identity into a current one.
	// ReadRow in the RWT locks both existing rows and absence before the
	// immutable Insert mutations are buffered.
	if err := assertRowAbsent(ctx, tx, p.Snapshot); err != nil {
		return SpannerPublicationOutcome{}, false, err
	}
	if err := assertRowAbsent(ctx, tx, p.Run); err != nil {
		return SpannerPublicationOutcome{}, false, err
	}
	s := p.Snapshot.Columns
	h := p.Head.Columns
	ps := p.Publication.Columns
	if headMissing {
		if s["predecessor_graph_snapshot_id"] != nil || s["predecessor_head_generation"] != nil || s["predecessor_snapshot_envelope_hash"] != nil || s["published_head_generation"] != int64(1) || h["head_generation"] != int64(1) {
			return SpannerPublicationOutcome{}, false, errors.New("first kind publication predecessor/generation invalid")
		}
	} else {
		if s["predecessor_graph_snapshot_id"] != priorSnapshot || s["predecessor_head_generation"] != priorHead || s["predecessor_snapshot_envelope_hash"] != priorEnvelope || s["published_head_generation"] != priorHead+1 || h["head_generation"] != priorHead+1 {
			return SpannerPublicationOutcome{}, false, errors.New("successor kind head fence stale")
		}
	}
	if stateMissing {
		if s["graph_version"] != int64(1) || s["published_org_publication_generation"] != int64(1) || s["predecessor_org_publication_state_hash"] != nil || ps["current_graph_version"] != int64(1) || ps["publication_generation"] != int64(1) {
			return SpannerPublicationOutcome{}, false, errors.New("first organization publication invalid")
		}
	} else {
		if s["graph_version"] != priorGraph+1 || s["published_org_publication_generation"] != priorPublication+1 || s["predecessor_org_publication_state_hash"] != stateHash || ps["current_graph_version"] != priorGraph+1 || ps["publication_generation"] != priorPublication+1 {
			return SpannerPublicationOutcome{}, false, errors.New("organization publication fence stale")
		}
	}
	if h["graph_version"] != s["graph_version"] || h["closure_hash"] != s["closure_hash"] || h["snapshot_envelope_hash"] != s["snapshot_envelope_hash"] || p.Run.Columns["candidate_closure_hash"] != s["closure_hash"] || p.Run.Columns["target_graph_snapshot_id"] != s["graph_snapshot_id"] {
		return SpannerPublicationOutcome{}, false, errors.New("snapshot/run/head envelope cross-binding invalid")
	}
	if err := verifySnapshotEnvelope(s); err != nil {
		return SpannerPublicationOutcome{}, false, err
	}
	if err := lockAndVerifyCertificate(ctx, tx, p); err != nil {
		return SpannerPublicationOutcome{}, false, err
	}
	return SpannerPublicationOutcome{}, false, nil
}

func verifyCurrentReplay(ctx context.Context, tx *spanner.ReadWriteTransaction, organizationID, snapshotID, closureHash string) error {
	row, err := tx.ReadRow(ctx, TableSnapshots, spanner.Key{organizationID, snapshotID}, []string{"closure_hash", "snapshot_state", "status"})
	if err != nil {
		return fmt.Errorf("read current replay snapshot: %w", err)
	}
	var gotClosure, state, status string
	if err := row.Columns(&gotClosure, &state, &status); err != nil {
		return err
	}
	if gotClosure != closureHash || state != "sealed" || status != "active" {
		return errors.New("current replay head does not resolve to active sealed snapshot")
	}
	return nil
}

func assertRowAbsent(ctx context.Context, tx *spanner.ReadWriteTransaction, row SpannerRow) error {
	key := make(spanner.Key, 0, len(row.KeyColumns))
	for _, k := range row.KeyColumns {
		key = append(key, row.Columns[k])
	}
	_, err := tx.ReadRow(ctx, row.Table, key, []string{row.KeyColumns[0]})
	if spanner.ErrCode(err) == codes.NotFound {
		return nil
	}
	if err == nil {
		return fmt.Errorf("immutable %s identity already exists", row.Table)
	}
	return err
}

func certificateRow(p SpannerWritePlan) (SpannerRow, error) {
	var found *SpannerRow
	for i := range p.ImmutableRows {
		r := &p.ImmutableRows[i]
		if r.Table != TableCertificates {
			continue
		}
		if found != nil {
			return SpannerRow{}, errors.New("write plan has duplicate closure certificates")
		}
		found = r
	}
	if found == nil {
		return SpannerRow{}, errors.New("write plan lacks immutable closure certificate")
	}
	if !reflect.DeepEqual(found.KeyColumns, []string{"organization_id", "verification_certificate_id"}) {
		return SpannerRow{}, errors.New("closure certificate lacks exact OOD8 primary key roster")
	}
	for _, k := range []string{"organization_id", "verification_certificate_id", "verification_certificate_hash", "materialization_run_id", "snapshot_kind", "closure_hash"} {
		if _, ok := found.Columns[k]; !ok {
			return SpannerRow{}, fmt.Errorf("closure certificate lacks %s", k)
		}
	}
	return *found, nil
}

// lockAndVerifyCertificate verifies the persisted immutable certificate while
// it is locked by the same RWT that selects the head. This closes the gap
// between an earlier immutable write and the snapshot/root references.
func lockAndVerifyCertificate(ctx context.Context, tx *spanner.ReadWriteTransaction, p SpannerWritePlan) error {
	cert, err := certificateRow(p)
	if err != nil {
		return err
	}
	cols := certificateFenceColumns()
	row, err := tx.ReadRow(ctx, TableCertificates, spanner.Key{p.OrganizationID, p.Snapshot.Columns["verification_certificate_id"]}, cols)
	if err != nil {
		return fmt.Errorf("read locked closure certificate: %w", err)
	}
	persisted := map[string]interface{}{}
	ptrs := make([]interface{}, len(cols))
	for i, k := range cols {
		if certificateIntColumn(k) {
			ptrs[i] = new(int64)
		} else {
			ptrs[i] = new(string)
		}
	}
	if err := row.Columns(ptrs...); err != nil {
		return err
	}
	for i, k := range cols {
		if certificateIntColumn(k) {
			persisted[k] = *(ptrs[i].(*int64))
		} else {
			persisted[k] = *(ptrs[i].(*string))
		}
		if want, ok := cert.Columns[k]; !ok || !reflect.DeepEqual(persisted[k], want) {
			return fmt.Errorf("persisted closure certificate differs at %s", k)
		}
	}
	if err := certificateBindsSnapshot(p.Snapshot.Columns, p.Run.Columns, persisted); err != nil {
		return err
	}
	return nil
}

func certificateFenceColumns() []string {
	return []string{"verification_certificate_id", "verification_certificate_hash", "materialization_run_id", "snapshot_kind", "closure_hash", "source_set_hash", "source_manifest_root_hash", "source_artifact_count", "relationship_evidence_count", "object_manifest_root_hash", "object_count", "symbol_manifest_root_hash", "symbol_count", "edge_manifest_root_hash", "edge_count", "api_property_manifest_root_hash", "api_property_count", "graph_fact_locator_manifest_root_hash", "graph_fact_locator_count", "receipt_manifest_root_hash", "receipt_count", "structural_projection_manifest_root_hash", "structural_projection_count", "violation_manifest_root_hash", "violation_count", "materialization_profile_id", "materialization_profile_version", "materialization_profile_digest"}
}

func certificateIntColumn(k string) bool {
	switch k {
	case "source_artifact_count", "relationship_evidence_count", "object_count", "symbol_count", "edge_count", "api_property_count", "graph_fact_locator_count", "receipt_count", "structural_projection_count", "violation_count":
		return true
	default:
		return false
	}
}

func certificateBindsSnapshot(snapshot, run, cert map[string]interface{}) error {
	for _, b := range []struct{ from, to string }{
		{"verification_certificate_id", "verification_certificate_id"}, {"verification_certificate_hash", "verification_certificate_hash"}, {"materialization_run_id", "materialization_run_id"}, {"snapshot_kind", "snapshot_kind"}, {"closure_hash", "closure_hash"},
		{"source_set_hash", "source_set_hash"}, {"source_manifest_root_hash", "source_manifest_root_hash"}, {"source_artifact_count", "source_artifact_count"}, {"relationship_evidence_count", "relationship_evidence_count"},
		{"object_manifest_root_hash", "object_manifest_root_hash"}, {"object_count", "object_count"}, {"symbol_manifest_root_hash", "symbol_manifest_root_hash"}, {"symbol_count", "symbol_count"}, {"edge_manifest_root_hash", "edge_manifest_root_hash"}, {"edge_count", "edge_count"}, {"api_property_manifest_root_hash", "api_property_manifest_root_hash"}, {"api_property_count", "api_property_count"}, {"graph_fact_locator_manifest_root_hash", "graph_fact_locator_manifest_root_hash"}, {"graph_fact_locator_count", "graph_fact_locator_count"}, {"receipt_manifest_root_hash", "receipt_manifest_root_hash"}, {"receipt_count", "receipt_count"}, {"structural_projection_manifest_root_hash", "structural_projection_manifest_root_hash"}, {"structural_projection_count", "structural_projection_count"}, {"violation_manifest_root_hash", "violation_manifest_root_hash"}, {"violation_count", "violation_count"}, {"materialization_profile_id", "materialization_profile_id"}, {"materialization_profile_version", "materialization_profile_version"}, {"materialization_profile_digest", "materialization_profile_digest"},
	} {
		if snapshot[b.from] != cert[b.to] {
			return fmt.Errorf("snapshot/certificate binding differs at %s", b.from)
		}
	}
	if run["candidate_verification_certificate_id"] != cert["verification_certificate_id"] || run["candidate_verification_certificate_hash"] != cert["verification_certificate_hash"] || run["candidate_closure_hash"] != cert["closure_hash"] || run["materialization_run_id"] != cert["materialization_run_id"] {
		return errors.New("run/certificate binding invalid")
	}
	return nil
}

func verifyCertificateHash(cert map[string]interface{}) error {
	profile := oodcanon.ClosureVerificationCertificateV1()
	record := oodcanon.RecordValue{}
	for _, f := range profile.Fields {
		if f.Literal != nil {
			continue
		}
		x, ok := cert[f.Name]
		if !ok {
			return fmt.Errorf("closure certificate lacks canonical field %s", f.Name)
		}
		v, err := canonicalScalarValue(f, x)
		if err != nil {
			return fmt.Errorf("closure certificate %s: %w", f.Name, err)
		}
		record[f.Name] = v
	}
	digest, err := oodcanon.DigestHexOf(profile, record)
	if err != nil {
		return fmt.Errorf("recompute closure certificate: %w", err)
	}
	if cert["verification_certificate_hash"] != digest {
		return errors.New("closure certificate hash is not owner-canonical")
	}
	return nil
}

func verifySnapshotEnvelope(snapshot map[string]interface{}) error {
	profile := oodcanon.SnapshotEnvelopeV1()
	record := oodcanon.RecordValue{}
	for _, f := range profile.Fields {
		if f.Literal != nil {
			continue
		}
		v, ok := snapshot[f.Name]
		if !ok {
			return fmt.Errorf("snapshot envelope lacks %s", f.Name)
		}
		cv, err := snapshotEnvelopeValue(f, v)
		if err != nil {
			return fmt.Errorf("snapshot envelope %s: %w", f.Name, err)
		}
		record[f.Name] = cv
	}
	digest, err := oodcanon.DigestHexOf(profile, record)
	if err != nil {
		return fmt.Errorf("recompute snapshot envelope: %w", err)
	}
	if snapshot["snapshot_envelope_hash"] != digest {
		return errors.New("snapshot envelope hash is not owner-canonical")
	}
	return nil
}

func snapshotEnvelopeValue(f oodcanon.Field, x interface{}) (oodcanon.Value, error) {
	return canonicalScalarValue(f, x)
}

func canonicalScalarValue(f oodcanon.Field, x interface{}) (oodcanon.Value, error) {
	if x == nil {
		if f.Policy == oodcanon.Nullable {
			return oodcanon.NullValue(f.Type), nil
		}
		return oodcanon.Value{}, errors.New("required value is null")
	}
	switch f.Type {
	case oodcanon.UTF8:
		v, ok := x.(string)
		if !ok {
			return oodcanon.Value{}, errors.New("not string")
		}
		return oodcanon.String(v), nil
	case oodcanon.UUID:
		v, ok := x.(string)
		if !ok {
			return oodcanon.Value{}, errors.New("not UUID text")
		}
		return oodcanon.UUIDText(v)
	case oodcanon.SHA256:
		v, ok := x.(string)
		if !ok {
			return oodcanon.Value{}, errors.New("not digest text")
		}
		return oodcanon.DigestHex(v)
	case oodcanon.Int64:
		v, ok := x.(int64)
		if !ok {
			return oodcanon.Value{}, errors.New("not int64")
		}
		return oodcanon.I64(v), nil
	case oodcanon.TimestampMicroseconds:
		v, ok := x.(time.Time)
		if !ok || v.IsZero() || v.Location() != time.UTC || v.Nanosecond()%1000 != 0 {
			return oodcanon.Value{}, errors.New("not UTC microsecond timestamp")
		}
		return oodcanon.Value{Type: oodcanon.TimestampMicroseconds, Presence: oodcanon.Present, Bytes: i64bytes(v.UnixMicro())}, nil
	default:
		return oodcanon.Value{}, errors.New("unsupported envelope field type")
	}
}

func i64bytes(x int64) []byte {
	return []byte{byte(uint64(x) >> 56), byte(uint64(x) >> 48), byte(uint64(x) >> 40), byte(uint64(x) >> 32), byte(uint64(x) >> 24), byte(uint64(x) >> 16), byte(uint64(x) >> 8), byte(x)}
}
