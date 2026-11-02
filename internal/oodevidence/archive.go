package oodevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// VerifyArchivedCanonicalBytes proves the one fact that a locator range cannot
// prove by itself: that the hydrated archive record is exactly the canonical
// representation named by the immutable receipt.  It is deliberately local
// and side-effect-free; authority to hydrate remains with the archive owner.
func VerifyArchivedCanonicalBytes(receipt ReceiptV8, body []byte) error {
	if int64(len(body)) != receipt.EvidenceArchiveByteCount {
		return fmt.Errorf("archive body length %d does not match receipt %d", len(body), receipt.EvidenceArchiveByteCount)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != receipt.SourceContentHash {
		return fmt.Errorf("archive body SHA-256 does not match receipt")
	}
	return nil
}

// ValidateReceiptRoles implements OOD8's closed role grammar.  The caller
// supplies profile roles only after their admitted completeness profile has
// been resolved by its owning authority; this function does not authorize a
// profile or manufacture a role.
func ValidateReceiptRoles(roles []string, admittedNoncomponent map[string]int64) error {
	if len(roles) == 0 {
		return fmt.Errorf("receipt roles are empty")
	}
	if !sort.SliceIsSorted(roles, func(i, j int) bool { return roles[i] < roles[j] }) {
		return fmt.Errorf("receipt roles are not canonical byte sorted")
	}
	for i, role := range roles {
		if role == "" || (i > 0 && roles[i-1] == role) {
			return fmt.Errorf("receipt roles contain empty or duplicate role")
		}
		switch role {
		case "component", "completeness_evidence":
			continue
		}
		const prefix = "profile_noncomponent:"
		if !strings.HasPrefix(role, prefix) {
			return fmt.Errorf("unknown receipt role %q", role)
		}
		name := strings.TrimPrefix(role, prefix)
		if !validRoleName(name) || admittedNoncomponent == nil {
			return fmt.Errorf("invalid or unadmitted noncomponent role %q", role)
		}
		if _, ok := admittedNoncomponent[name]; !ok {
			return fmt.Errorf("unadmitted noncomponent role %q", role)
		}
	}
	return nil
}

func validRoleName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
		if i == 0 && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
