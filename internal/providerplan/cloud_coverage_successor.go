package providerplan

import (
	"bytes"
	"fmt"
	"strings"
)

// A predecessor occurrence may be divided into multiple model-declared
// leaves. Store their complete evidence coordinates for field-level review.
type CloudCoverageResolution struct {
	Predecessor CloudCoverageEntry   `json:"predecessor"`
	Successors  []CloudCoverageEntry `json:"successors"`
}

type CloudCoverageSuccessorAudit struct {
	PredecessorSHA256 string                    `json:"predecessor_sha256"`
	SuccessorSHA256   string                    `json:"successor_sha256"`
	Preserved         int                       `json:"preserved_occurrences"`
	Resolutions       []CloudCoverageResolution `json:"resolutions"`
}

// Compare a mapping generation on the same retained models. Preparation
// validates the successor's complete source/schema closure before this audit
// assigns each occurrence back to exactly one previously selected field.
func AuditCloudCoverageSuccessor(previous []byte, expectedSHA256 string, next CloudCoverageBacklog) (CloudCoverageSuccessorAudit, error) {
	var empty CloudCoverageSuccessorAudit
	if !isLowerSHA256(expectedSHA256) || sha256Hex(previous) != expectedSHA256 {
		return empty, fmt.Errorf("predecessor coverage digest mismatch")
	}
	var prior CloudCoverageBacklog
	if err := strictUnmarshal(previous, &prior); err != nil {
		return empty, fmt.Errorf("predecessor coverage: %w", err)
	}
	if len(prior.Entries) == 0 || prior.Status != cloudCoverageStatus || prior.Version != cloudCoverageVersion || !isLowerSHA256(prior.ScopeSHA256) {
		return empty, fmt.Errorf("invalid predecessor coverage")
	}
	totals, err := cloudCoverageTotals(prior.Entries)
	if err != nil || totals != prior.DispositionTotals {
		return empty, fmt.Errorf("invalid predecessor occurrence roster or totals")
	}
	raw, err := canonicalCloudCoverageDocument(prior)
	if err != nil || !bytes.Equal(raw, previous) {
		return empty, fmt.Errorf("predecessor is not a canonical coverage document")
	}
	raw, err = canonicalCloudCoverageDocument(next)
	if err != nil || !bytes.Equal(raw, next.Document) || sha256Hex(raw) != next.DocumentSHA256 ||
		next.publicationSeal != cloudCoveragePublicationSeal(next.DocumentSHA256, next.ScopeSHA256) {
		return empty, fmt.Errorf("successor differs from its prepared coverage")
	}
	parents := make(map[string]int, len(prior.Entries))
	children := make([][]CloudCoverageEntry, len(prior.Entries))
	for i, e := range prior.Entries {
		parents[cloudCoverageEntryKey(e)] = i
	}
	for _, e := range next.Entries {
		key := e
		for {
			index, exists := parents[cloudCoverageEntryKey(key)]
			if exists {
				old := prior.Entries[index]
				if old.ModelSHA256 != e.ModelSHA256 || old.ModelSourceID != e.ModelSourceID || old.RecordClassSymbol != e.RecordClassSymbol {
					return empty, fmt.Errorf("model or record class changed for %s %s", e.OperationID, e.SourcePointer)
				}
				if old.SourcePointer == e.SourcePointer && (old.SourceFieldID != e.SourceFieldID || old.SelectedRangeSHA256 != e.SelectedRangeSHA256 ||
					old.EvidenceLocator == nil || e.EvidenceLocator == nil || *old.EvidenceLocator != *e.EvidenceLocator) {
					return empty, fmt.Errorf("source coordinate changed for %s %s", e.OperationID, e.SourcePointer)
				}
				children[index] = append(children[index], e)
				break
			}
			slash := strings.LastIndex(key.SourcePointer, "/")
			if slash <= 0 {
				return empty, fmt.Errorf("no predecessor for %s %s", e.OperationID, e.SourcePointer)
			}
			key.SourcePointer = key.SourcePointer[:slash]
		}
	}
	audit := CloudCoverageSuccessorAudit{PredecessorSHA256: expectedSHA256, SuccessorSHA256: next.DocumentSHA256}
	for i, old := range prior.Entries {
		group := children[i]
		if len(group) == 0 {
			return empty, fmt.Errorf("missing successor for %s %s", old.OperationID, old.SourcePointer)
		}
		if old.Disposition != CloudSourceUnsupported {
			if len(group) != 1 || group[0].SourcePointer != old.SourcePointer || group[0].Disposition != old.Disposition {
				return empty, fmt.Errorf("previously accepted disposition changed for %s %s", old.OperationID, old.SourcePointer)
			}
			audit.Preserved++
			continue
		}
		for _, field := range group {
			switch field.Disposition {
			case CloudSourceMapsExactSourceFact, CloudSourceMapsExactLifecycleFact, CloudSourceMapsExactRelationshipFact:
				if field.TargetField == "" || field.SemanticOwnerRef == "" {
					return empty, fmt.Errorf("resolved occurrence %s %s lacks its neutral target", field.OperationID, field.SourcePointer)
				}
			case CloudSourcePrivateOnly:
				if !cloudSemanticPrivateReasons[field.PrivateReasonCode] || field.DispositionReason == "" {
					return empty, fmt.Errorf("private occurrence %s %s lacks its classification", field.OperationID, field.SourcePointer)
				}
			default:
				return empty, fmt.Errorf("unresolved successor disposition for %s %s", field.OperationID, field.SourcePointer)
			}
		}
		audit.Resolutions = append(audit.Resolutions, CloudCoverageResolution{Predecessor: old, Successors: group})
	}
	return audit, nil
}
