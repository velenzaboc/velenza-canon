package providerplan

import "testing"

func TestAuditCloudModelRevisionReportsDeterministicLeafDrift(t *testing.T) {
	a, err := AuditCloudModelRevision([]byte(`{"revision":"1","schema":{"x":true}}`), []byte(`{"revision":"2","schema":{"x":false},"new":null}`))
	if err != nil || a.OldSHA256 == a.NewSHA256 || len(a.Changes) != 3 {
		t.Fatalf("audit=%+v err=%v", a, err)
	}
	if a.Changes[0].Pointer != "/new" || a.Changes[1].Pointer != "/revision" || a.Changes[2].Pointer != "/schema/x" {
		t.Fatalf("noncanonical changes: %+v", a.Changes)
	}
}

func TestAuditCloudModelRevisionPreservesAdversarialStructure(t *testing.T) {
	a, err := AuditCloudModelRevision([]byte(`{"n":9007199254740992,"a":"","x":{},"k/a":{"~":[]}}`), []byte(`{"n":9007199254740993,"x":[],"k/a":{"~":null}}`))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range a.Changes {
		seen[c.Pointer] = true
	}
	for _, p := range []string{"/a", "/n", "/x", "/k~1a/~0"} {
		if !seen[p] {
			t.Fatalf("missing %s: %+v", p, a.Changes)
		}
	}
	if _, err := AuditCloudModelRevision([]byte(`{"x":1,"x":2}`), []byte(`{}`)); err == nil {
		t.Fatal("duplicate keys accepted")
	}
	container, err := AuditCloudModelRevision([]byte(`{"0":1}`), []byte(`[1]`))
	if err != nil || len(container.Changes) != 1 || container.Changes[0].Pointer != "" {
		t.Fatal("object and array with identical leaf coordinates collapsed")
	}
}
