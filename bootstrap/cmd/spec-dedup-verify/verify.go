package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Generator is the FlashClient surface verify.go needs. Defined as an
// interface so tests can supply a mock without touching Vertex AI.
type Generator interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

// recordIdentityKey is the full triple that uniquely identifies a
// ConceptRecord within a pipeline run. The skip predicate that decides
// "is this member the representative we already use as A in the pair?"
// MUST compare on this triple, not on source_path alone — two records
// can legitimately share a source_path with different leaf_names (e.g.
// a section with multiple concept-bearing subkeys). Comparing source_path
// alone wrongly skips sibling concepts and they never reach Flash.
func recordIdentityKey(r ConceptRecord) string {
	return r.SourceFile + "#" + r.SourcePath + "#" + r.LeafName
}

// VerifyAll runs the dedup-verify pass over a ClusterBuckets input:
//   - For every auto_merge cluster: Flash picks the canonical name.
//   - For every verify_required cluster: Flash classifies each pair
//     (representative vs each member) as same-concept / different /
//     uncertain.
//   - no_match records pass straight through.
// Every Flash call is recorded to the ledger.
func VerifyAll(
	ctx context.Context,
	buckets *ClusterBuckets,
	gen Generator,
	cfg *FlashConfig,
) (*DedupDecisions, *FlashLedger, error) {
	decisions := &DedupDecisions{
		ConceptDomain: buckets.ConceptDomain,
		NoMatch:       buckets.NoMatch,
	}
	ledger := &FlashLedger{ConceptDomain: buckets.ConceptDomain}

	// Auto-merge clusters: pick canonical name via Flash.
	for _, cl := range buckets.AutoMerge {
		am, entry, err := pickCanonicalName(ctx, gen, cfg, buckets.ConceptDomain, cl)
		if err != nil {
			// Record the error in the ledger; promote the cluster to
			// escalations (treat as if Flash returned uncertain on every
			// member pair).
			ledger.Entries = append(ledger.Entries, entry)
			for _, m := range cl.Members {
				if recordIdentityKey(m.Record) == recordIdentityKey(cl.Representative) {
					continue
				}
				decisions.Escalations = append(decisions.Escalations, EscalatedPair{
					A: cl.Representative, B: m.Record,
					Reason: "flash_error", RawFlash: err.Error(),
				})
			}
			continue
		}
		ledger.Entries = append(ledger.Entries, entry)
		decisions.AutoMerge = append(decisions.AutoMerge, am)
	}

	// Verify_required clusters: pair-by-pair same-concept check.
	for _, cl := range buckets.VerifyRequired {
		for _, m := range cl.Members {
			if recordIdentityKey(m.Record) == recordIdentityKey(cl.Representative) {
				continue
			}
			vd, escal, entry := verifyPair(ctx, gen, cfg, buckets.ConceptDomain, cl.Representative, m.Record)
			ledger.Entries = append(ledger.Entries, entry)
			if escal != nil {
				decisions.Escalations = append(decisions.Escalations, *escal)
			}
			if vd != nil {
				decisions.Verified = append(decisions.Verified, *vd)
			}
		}
	}

	return decisions, ledger, nil
}

// pickCanonicalName renders the canonical-name template, calls Flash,
// parses the response, and assembles an AutoMergeDecision + ledger
// entry.
func pickCanonicalName(
	ctx context.Context,
	gen Generator,
	cfg *FlashConfig,
	conceptDomain string,
	cl Cluster,
) (AutoMergeDecision, FlashLedgerEntry, error) {
	candidates := make([]string, 0, len(cl.Members))
	seen := map[string]bool{}
	for _, m := range cl.Members {
		// Use source_path as the candidate name surface — recipes
		// commonly populate source_path with the local id. If a record
		// later carries an explicit canonical_name proposal, that
		// surface can extend.
		name := m.Record.SourcePath
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		candidates = append(candidates, name)
	}
	data := CanonicalNameSelectionData{
		Statement:  cl.Representative.RawValue,
		Candidates: candidates,
	}
	prompt, err := LoadAndRender(cfg.Prompts.CanonicalNameSelectionPath, data)
	if err != nil {
		return AutoMergeDecision{}, FlashLedgerEntry{
			CallID:         callID("canon", cl.Representative),
			ConceptDomain:  conceptDomain,
			PromptTemplate: cfg.Prompts.CanonicalNameSelectionPath,
			Model:          cfg.Model,
			Statement:      cl.Representative.RawValue,
			Candidates:     candidates,
			Error:          err.Error(),
		}, err
	}
	raw, err := gen.Generate(ctx, prompt)
	entry := FlashLedgerEntry{
		CallID:         callID("canon", cl.Representative),
		ConceptDomain:  conceptDomain,
		PromptTemplate: cfg.Prompts.CanonicalNameSelectionPath,
		Model:          cfg.Model,
		Statement:      cl.Representative.RawValue,
		Candidates:     candidates,
		RenderedPrompt: prompt,
		RawResponse:    raw,
	}
	if err != nil {
		entry.Error = err.Error()
		return AutoMergeDecision{}, entry, err
	}
	name, rationale, proposed, parseErr := ParseCanonicalNameResponse(raw)
	if parseErr != nil {
		entry.Error = parseErr.Error()
		return AutoMergeDecision{}, entry, parseErr
	}
	entry.ParsedName = name
	entry.Rationale = rationale
	source := "flash_selected"
	if proposed {
		source = "flash_proposed"
	}
	entry.DecisionApplied = source
	members := make([]ConceptRecord, 0, len(cl.Members))
	for _, m := range cl.Members {
		members = append(members, m.Record)
	}
	return AutoMergeDecision{
		ChosenName:        name,
		ChosenNameSource:  source,
		RepresentativeRaw: cl.Representative.RawValue,
		Members:           members,
	}, entry, nil
}

// verifyPair runs the same-concept Flash call on one pair. Returns
// (verified, nil, entry) if Flash answered yes/no, (nil, escalation,
// entry) if Flash returned uncertain or the response was malformed.
func verifyPair(
	ctx context.Context,
	gen Generator,
	cfg *FlashConfig,
	conceptDomain string,
	a, b ConceptRecord,
) (*VerifyDecision, *EscalatedPair, FlashLedgerEntry) {
	data := SameConceptQueryData{
		StatementA: a.RawValue,
		StatementB: b.RawValue,
		SourceA:    a.SourceFile + "#" + a.SourcePath,
		SourceB:    b.SourceFile + "#" + b.SourcePath,
	}
	prompt, err := LoadAndRender(cfg.Prompts.SameConceptQueryPath, data)
	entry := FlashLedgerEntry{
		CallID:         callID("verify", a),
		ConceptDomain:  conceptDomain,
		PromptTemplate: cfg.Prompts.SameConceptQueryPath,
		Model:          cfg.Model,
		A:              a,
		B:              b,
	}
	if err != nil {
		entry.Error = err.Error()
		return nil, &EscalatedPair{A: a, B: b, Reason: "flash_error", RawFlash: err.Error()}, entry
	}
	entry.RenderedPrompt = prompt
	raw, err := gen.Generate(ctx, prompt)
	if err != nil {
		entry.Error = err.Error()
		return nil, &EscalatedPair{A: a, B: b, Reason: "flash_error", RawFlash: err.Error()}, entry
	}
	entry.RawResponse = raw
	verdict, rationale, parseErr := ParseSameConceptResponse(raw)
	if parseErr != nil {
		entry.Error = parseErr.Error()
		return nil, &EscalatedPair{A: a, B: b, Reason: "flash_unparseable", RawFlash: raw}, entry
	}
	entry.ParsedVerdict = verdict
	entry.Rationale = rationale
	switch verdict {
	case "yes":
		entry.DecisionApplied = "merge"
		return &VerifyDecision{A: a, B: b, Verdict: "merge", Rationale: rationale}, nil, entry
	case "no":
		entry.DecisionApplied = "split"
		return &VerifyDecision{A: a, B: b, Verdict: "split", Rationale: rationale}, nil, entry
	case "uncertain":
		entry.DecisionApplied = "escalate"
		return nil, &EscalatedPair{A: a, B: b, Reason: "flash_uncertain", RawFlash: raw}, entry
	}
	// Should not reach here — parse guarantees one of the three.
	entry.Error = fmt.Sprintf("unexpected verdict %q", verdict)
	return nil, &EscalatedPair{A: a, B: b, Reason: "flash_unparseable", RawFlash: raw}, entry
}

// callID produces a stable identifier per Flash call for ledger
// correlation. Hashes the kind + a deterministic record fingerprint.
func callID(kind string, r ConceptRecord) string {
	h := sha256.Sum256([]byte(kind + ":" + r.SourceFile + ":" + r.SourcePath + ":" + r.LeafName + ":" + r.RawValue))
	return kind + "-" + hex.EncodeToString(h[:8])
}
