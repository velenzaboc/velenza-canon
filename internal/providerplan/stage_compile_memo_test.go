package providerplan

import (
	"crypto/sha256"
	"encoding/json"
	"sync"
)

// CompileStageReceipt and ValidateStageReceipt are pure functions of their
// exact byte inputs. Compilation reads only the request bytes and the
// StageCompileInputs, and validation reads only the receipt bytes; no clock,
// randomness, environment variable or filesystem state reaches either. (The
// package's only clock is the injected production source-package clock, and its
// only randomness names a private --out staging file; neither is on this path.)
//
// Dozens of source-package fixtures rebuild the identical four-stage factory
// lineage, and each full compile runs the closure scanner and every JSON
// structural bound. On the Windows coverage runner that repetition alone pushed
// internal/providerplan past its 600s test timeout. The test helpers
// mustCompileStage and mustValidateStage therefore memoize by a SHA-256 digest
// of the complete input:
//
//   - The compile key encodes the request bytes together with every exported
//     field of StageCompileInputs, so a different byte, field value, ordering
//     or nil-versus-empty slice is a different key. Two distinct inputs never
//     share a result.
//   - Each key is computed exactly once (sync.Once), so the parallel tests that
//     build the same lineage at the same moment wait for one computation
//     instead of all missing the cache together.
//   - Because both functions are pure, a cached result, including a cached
//     error, is the result the caller would have computed itself. Callers
//     receive copies, so no test can mutate another test's result.
//
// Tests that assert on CompileStageReceipt or ValidateStageReceipt directly do
// not go through these helpers and are unaffected.

type stageCompileMemoEntry struct {
	once    sync.Once
	receipt []byte
	err     error
}

type stageValidateMemoEntry struct {
	once    sync.Once
	summary StageReceiptSummary
	err     error
}

var (
	stageCompileMemo  sync.Map // [sha256.Size]byte -> *stageCompileMemoEntry
	stageValidateMemo sync.Map // [sha256.Size]byte -> *stageValidateMemoEntry
)

func memoizedCompileStageReceipt(request []byte, inputs StageCompileInputs) ([]byte, error) {
	encoded, err := json.Marshal(struct {
		Request []byte
		Inputs  StageCompileInputs
	}{Request: request, Inputs: inputs})
	if err != nil {
		return CompileStageReceipt(request, inputs)
	}
	value, _ := stageCompileMemo.LoadOrStore(sha256.Sum256(encoded), &stageCompileMemoEntry{})
	entry := value.(*stageCompileMemoEntry)
	entry.once.Do(func() {
		entry.receipt, entry.err = CompileStageReceipt(request, inputs)
	})
	if entry.err != nil {
		return nil, entry.err
	}
	return append([]byte(nil), entry.receipt...), nil
}

func memoizedValidateStageReceipt(raw []byte) (StageReceiptSummary, error) {
	value, _ := stageValidateMemo.LoadOrStore(sha256.Sum256(raw), &stageValidateMemoEntry{})
	entry := value.(*stageValidateMemoEntry)
	entry.once.Do(func() {
		entry.summary, entry.err = ValidateStageReceipt(raw)
	})
	if entry.err != nil {
		return StageReceiptSummary{}, entry.err
	}
	summary := entry.summary
	if entry.summary.Predecessors != nil {
		summary.Predecessors = make([]StageReceiptReference, len(entry.summary.Predecessors))
		copy(summary.Predecessors, entry.summary.Predecessors)
	}
	if entry.summary.EvidenceCommitments != nil {
		summary.EvidenceCommitments = make([]StageEvidenceCommitment, len(entry.summary.EvidenceCommitments))
		copy(summary.EvidenceCommitments, entry.summary.EvidenceCommitments)
	}
	return summary, nil
}
