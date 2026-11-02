package providerplan

// Candidate-only model revision audit. It deliberately reports byte and JSON
// drift; it never selects, qualifies, or admits a refreshed source.
import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

type CloudModelRevisionChange struct {
	Pointer string `json:"pointer"`
	Old     string `json:"old"`
	New     string `json:"new"`
}
type CloudModelRevisionAudit struct {
	OldSHA256 string                     `json:"old_sha256"`
	NewSHA256 string                     `json:"new_sha256"`
	Changes   []CloudModelRevisionChange `json:"changes"`
}

func AuditCloudModelRevision(oldRaw, newRaw []byte) (CloudModelRevisionAudit, error) {
	var oldValue, newValue any
	if len(oldRaw) > 64<<20 || len(newRaw) > 64<<20 {
		return CloudModelRevisionAudit{}, fmt.Errorf("model exceeds audit bound")
	}
	if err := strictUnmarshal(oldRaw, &oldValue); err != nil {
		return CloudModelRevisionAudit{}, fmt.Errorf("old model: %w", err)
	}
	if err := strictUnmarshal(newRaw, &newValue); err != nil {
		return CloudModelRevisionAudit{}, fmt.Errorf("new model: %w", err)
	}
	oldLeaves, newLeaves := map[string]string{}, map[string]string{}
	cloudModelRevisionLeaves(oldValue, "", oldLeaves)
	cloudModelRevisionLeaves(newValue, "", newLeaves)
	keys := map[string]bool{}
	for k := range oldLeaves {
		keys[k] = true
	}
	for k := range newLeaves {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	changes := make([]CloudModelRevisionChange, 0)
	for _, k := range ordered {
		if oldLeaves[k] != newLeaves[k] {
			changes = append(changes, CloudModelRevisionChange{k, oldLeaves[k], newLeaves[k]})
		}
	}
	a := sha256.Sum256(oldRaw)
	b := sha256.Sum256(newRaw)
	return CloudModelRevisionAudit{hex.EncodeToString(a[:]), hex.EncodeToString(b[:]), changes}, nil
}
func cloudModelRevisionLeaves(v any, p string, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		out[p] = "object"
		if len(x) == 0 {
			out[p] = "object:{}"
		}
		for k, v := range x {
			cloudModelRevisionLeaves(v, p+"/"+strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1"), out)
		}
	case []any:
		out[p] = "array"
		if len(x) == 0 {
			out[p] = "array:[]"
		}
		for i, v := range x {
			cloudModelRevisionLeaves(v, fmt.Sprintf("%s/%d", p, i), out)
		}
	default:
		out[p] = fmt.Sprintf("%T:%v", x, x)
	}
}
