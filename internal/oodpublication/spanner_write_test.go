package oodpublication

import (
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
)

const (
	testSnapshotID = "11111111-1111-4111-8111-111111111111"
	testRunID      = "22222222-2222-4222-8222-222222222222"
	testCertID     = "33333333-3333-4333-8333-333333333333"
)

func row(table string, columns []string) SpannerRow {
	m := map[string]interface{}{}
	for _, c := range columns {
		m[c] = c
	}
	return SpannerRow{Table: table, KeyColumns: mutableTableKeys(table), Columns: m}
}
func TestSpannerWritePlanRequiresExactOOD8MutableRosters(t *testing.T) {
	cert := canonicalCertificate(t)
	p := SpannerWritePlan{OrganizationID: "org", SnapshotKind: "kind", SnapshotID: testSnapshotID, RunID: testRunID, ClosureHash: cert.Columns["closure_hash"].(string), ImmutableRows: []SpannerRow{cert}, Snapshot: row(TableSnapshots, snapshotColumns), Run: row(TableRuns, runColumns), Head: row(TableSnapshotHeads, snapshotHeadColumns), Publication: row(TablePublicationState, publicationStateColumns)}
	for _, x := range []SpannerRow{p.Snapshot, p.Run, p.Head, p.Publication} {
		_ = x
	}
	p.Snapshot.Columns["organization_id"], p.Snapshot.Columns["graph_snapshot_id"], p.Snapshot.Columns["snapshot_kind"], p.Snapshot.Columns["materialization_run_id"], p.Snapshot.Columns["closure_hash"] = "org", testSnapshotID, "kind", testRunID, p.ClosureHash
	p.Run.Columns["organization_id"], p.Run.Columns["materialization_run_id"], p.Run.Columns["target_graph_snapshot_id"], p.Run.Columns["candidate_closure_hash"] = "org", testRunID, testSnapshotID, p.ClosureHash
	p.Head.Columns["organization_id"], p.Head.Columns["snapshot_kind"], p.Head.Columns["graph_snapshot_id"], p.Head.Columns["closure_hash"] = "org", "kind", testSnapshotID, p.ClosureHash
	p.Publication.Columns["organization_id"] = "org"
	if err := validateSpannerWritePlan(p); err != nil {
		t.Fatal(err)
	}
	delete(p.Head.Columns, "closure_hash")
	if err := validateSpannerWritePlan(p); err == nil {
		t.Fatal("partial head roster accepted")
	}
}

func TestVerifyCertificateHashRejectsSubstitution(t *testing.T) {
	cert := canonicalCertificate(t)
	if err := verifyCertificateHash(cert.Columns); err != nil {
		t.Fatal(err)
	}
	cert.Columns["receipt_manifest_root_hash"] = strings.Repeat("f", 64)
	if err := verifyCertificateHash(cert.Columns); err == nil {
		t.Fatal("certificate root substitution accepted")
	}
}

func TestVerifySnapshotEnvelopeRejectsForgedOrStaleFence(t *testing.T) {
	s := canonicalEnvelopeSnapshot(t)
	if err := verifySnapshotEnvelope(s); err != nil {
		t.Fatal(err)
	}
	s["published_head_generation"] = int64(2)
	if err := verifySnapshotEnvelope(s); err == nil {
		t.Fatal("stale allocation accepted by envelope verifier")
	}
	s = canonicalEnvelopeSnapshot(t)
	s["snapshot_envelope_hash"] = strings.Repeat("f", 64)
	if err := verifySnapshotEnvelope(s); err == nil {
		t.Fatal("forged envelope accepted")
	}
}

func TestCertificateBindsEveryPersistedSnapshotRootAndRun(t *testing.T) {
	s := map[string]interface{}{}
	cert := map[string]interface{}{}
	for _, k := range certificateFenceColumns() {
		v := interface{}("x-" + k)
		if certificateIntColumn(k) {
			v = int64(7)
		}
		cert[k], s[k] = v, v
	}
	s["verification_certificate_id"], s["verification_certificate_hash"] = testCertID, strings.Repeat("a", 64)
	cert["verification_certificate_id"], cert["verification_certificate_hash"] = s["verification_certificate_id"], s["verification_certificate_hash"]
	s["materialization_run_id"], cert["materialization_run_id"] = testRunID, testRunID
	run := map[string]interface{}{"candidate_verification_certificate_id": testCertID, "candidate_verification_certificate_hash": strings.Repeat("a", 64), "candidate_closure_hash": cert["closure_hash"], "materialization_run_id": testRunID}
	if err := certificateBindsSnapshot(s, run, cert); err != nil {
		t.Fatal(err)
	}
	cert["receipt_manifest_root_hash"] = strings.Repeat("b", 64)
	if err := certificateBindsSnapshot(s, run, cert); err == nil {
		t.Fatal("certificate root substitution accepted")
	}
}

func TestCertificateRowIsMandatoryAndUnique(t *testing.T) {
	p := SpannerWritePlan{ImmutableRows: []SpannerRow{{Table: "OODGraphManifestNodes", KeyColumns: []string{"k"}, Columns: map[string]interface{}{"k": "v"}}}}
	if _, err := certificateRow(p); err == nil {
		t.Fatal("missing certificate accepted")
	}
	p.ImmutableRows = append(p.ImmutableRows, SpannerRow{Table: TableCertificates, KeyColumns: []string{"organization_id", "verification_certificate_id"}, Columns: map[string]interface{}{"organization_id": "o", "verification_certificate_id": testCertID, "verification_certificate_hash": strings.Repeat("a", 64), "materialization_run_id": testRunID, "snapshot_kind": "kind", "closure_hash": strings.Repeat("b", 64)}})
	if _, err := certificateRow(p); err != nil {
		t.Fatal(err)
	}
	p.ImmutableRows = append(p.ImmutableRows, p.ImmutableRows[1])
	if _, err := certificateRow(p); err == nil {
		t.Fatal("duplicate certificate accepted")
	}
}

func TestImmutableComparisonOnlySkipsExplicitServerCreatedTimestamp(t *testing.T) {
	row := SpannerRow{Table: "OODGraphObjects", KeyColumns: []string{"organization_id"}, Columns: map[string]interface{}{"organization_id": "org", "sealed_at": time.Date(2026, 11, 2, 17, 0, 0, 0, time.UTC), "created_at": spanner.CommitTimestamp}}
	cols := keys(row.Columns)
	got := []interface{}{time.Date(2026, 11, 2, 18, 0, 0, 0, time.UTC), "org", time.Date(2026, 11, 2, 17, 0, 0, 1, time.UTC)}
	if err := immutableRowMatches(row, cols, got); err == nil {
		t.Fatal("different logical sealing timestamp accepted")
	}
	row.Columns["sealed_at"] = got[2]
	if err := immutableRowMatches(row, cols, got); err != nil {
		t.Fatal(err)
	}
}

func TestExactReplayRunTargetsCurrentSnapshotAndIsNoopOnly(t *testing.T) {
	p := SpannerWritePlan{ClosureHash: strings.Repeat("a", 64), Run: SpannerRow{Table: TableRuns, KeyColumns: []string{"organization_id", "materialization_run_id"}, Columns: map[string]interface{}{"candidate_closure_hash": strings.Repeat("a", 64), "candidate_verification_certificate_id": testCertID, "candidate_verification_certificate_hash": strings.Repeat("b", 64), "target_graph_snapshot_id": testSnapshotID, "state": "sealed"}}, Snapshot: SpannerRow{Columns: map[string]interface{}{"verification_certificate_id": testCertID, "verification_certificate_hash": strings.Repeat("b", 64)}}}
	r, err := exactReplayRun(p, "55555555-5555-4555-8555-555555555555")
	if err != nil {
		t.Fatal(err)
	}
	if r.Columns["state"] != "exact_replay_noop" || r.Columns["target_graph_snapshot_id"] != "55555555-5555-4555-8555-555555555555" {
		t.Fatal("replay run did not persist the current no-op audit coordinate")
	}
}

func canonicalEnvelopeSnapshot(t *testing.T) map[string]interface{} {
	t.Helper()
	s := map[string]interface{}{"organization_id": "org", "snapshot_kind": "provider_documentation", "graph_snapshot_id": testSnapshotID, "graph_version": int64(1), "materialization_run_id": testRunID, "sealed_at": time.Date(2026, 11, 2, 17, 0, 0, 123000000, time.UTC), "closure_hash": strings.Repeat("a", 64), "verification_certificate_id": testCertID, "verification_certificate_hash": strings.Repeat("b", 64), "predecessor_graph_snapshot_id": nil, "predecessor_head_generation": nil, "predecessor_snapshot_envelope_hash": nil, "published_head_generation": int64(1), "predecessor_org_publication_state_hash": nil, "published_org_publication_generation": int64(1)}
	profile := oodcanon.SnapshotEnvelopeV1()
	record := oodcanon.RecordValue{}
	for _, f := range profile.Fields {
		if f.Literal != nil {
			continue
		}
		v, err := snapshotEnvelopeValue(f, s[f.Name])
		if err != nil {
			t.Fatal(err)
		}
		record[f.Name] = v
	}
	digest, err := oodcanon.DigestHexOf(profile, record)
	if err != nil {
		t.Fatal(err)
	}
	s["snapshot_envelope_hash"] = digest
	return s
}

func canonicalCertificate(t *testing.T) SpannerRow {
	t.Helper()
	profile := oodcanon.ClosureVerificationCertificateV1()
	columns := map[string]interface{}{"organization_id": "org", "verification_certificate_id": testCertID}
	for _, f := range profile.Fields {
		if f.Literal != nil {
			continue
		}
		switch f.Type {
		case oodcanon.UTF8:
			columns[f.Name] = "x-" + f.Name
		case oodcanon.UUID:
			columns[f.Name] = "44444444-4444-4444-8444-444444444444"
		case oodcanon.SHA256:
			columns[f.Name] = strings.Repeat("a", 64)
		case oodcanon.Int64:
			columns[f.Name] = int64(1)
		default:
			t.Fatalf("unsupported certificate fixture type %v", f.Type)
		}
	}
	columns["organization_id"] = "org"
	columns["materialization_run_id"] = testRunID
	columns["snapshot_kind"] = "kind"
	record := oodcanon.RecordValue{}
	for _, f := range profile.Fields {
		if f.Literal != nil {
			continue
		}
		v, err := canonicalScalarValue(f, columns[f.Name])
		if err != nil {
			t.Fatal(err)
		}
		record[f.Name] = v
	}
	digest, err := oodcanon.DigestHexOf(profile, record)
	if err != nil {
		t.Fatal(err)
	}
	columns["verification_certificate_hash"] = digest
	return SpannerRow{Table: TableCertificates, KeyColumns: []string{"organization_id", "verification_certificate_id"}, Columns: columns}
}
