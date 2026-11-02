package oodevidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// PublicationRosterAuthority is the protected evidence owner for the exact
// immutable rows that witness a closure.  It receives canonical row bytes,
// not a caller assertion or a boolean; implementations must traverse the
// sealed manifest membership before returning success.
type PublicationRosterAuthority interface {
	VerifyCompletePublicationRoster(context.Context, VerifiedClosureV8, [][]byte) error
}

// VerifiedPublicationRosterV8 is an opaque binding of every immutable row,
// in order, to an already verified closure.  It prevents an API adapter from
// replacing a manifest/property/certificate row while preserving its own
// logical API rows.
type VerifiedPublicationRosterV8 struct {
	organizationID, closureHash, rosterHash string
	rowCount                                int
	verified                                bool
}

func (v VerifiedPublicationRosterV8) OrganizationID() string { return v.organizationID }
func (v VerifiedPublicationRosterV8) ClosureHash() string    { return v.closureHash }
func (v VerifiedPublicationRosterV8) RowCount() int          { return v.rowCount }

func ValidateVerifiedPublicationRosterV8(v VerifiedPublicationRosterV8) error {
	if !v.verified || v.organizationID == "" || v.closureHash == "" || v.rosterHash == "" || v.rowCount <= 0 {
		return errors.New("verified OOD8 publication roster absent")
	}
	return nil
}

func VerifyPublicationRosterV8(ctx context.Context, closure VerifiedClosureV8, canonicalRows [][]byte, authority PublicationRosterAuthority) (VerifiedPublicationRosterV8, error) {
	if authority == nil {
		return VerifiedPublicationRosterV8{}, errors.New("publication roster authority unavailable")
	}
	if err := ValidateVerifiedClosureV8(closure); err != nil {
		return VerifiedPublicationRosterV8{}, err
	}
	if len(canonicalRows) == 0 {
		return VerifiedPublicationRosterV8{}, errors.New("publication roster is empty")
	}
	for i, row := range canonicalRows {
		if len(row) == 0 {
			return VerifiedPublicationRosterV8{}, fmt.Errorf("publication roster row %d has no canonical bytes", i)
		}
	}
	if err := authority.VerifyCompletePublicationRoster(ctx, closure, clonePublicationRows(canonicalRows)); err != nil {
		return VerifiedPublicationRosterV8{}, fmt.Errorf("complete publication roster traversal: %w", err)
	}
	return VerifiedPublicationRosterV8{organizationID: closure.OrganizationID(), closureHash: closure.ClosureHash(), rosterHash: publicationRosterHash(canonicalRows), rowCount: len(canonicalRows), verified: true}, nil
}

// MatchesCanonicalRows is intentionally the only way a publication adapter
// can compare its rows to this proof.
func (v VerifiedPublicationRosterV8) MatchesCanonicalRows(rows [][]byte) bool {
	return v.verified && len(rows) == v.rowCount && publicationRosterHash(rows) == v.rosterHash
}

func publicationRosterHash(rows [][]byte) string {
	h := sha256.New()
	for _, row := range rows {
		var n [8]byte
		for i := uint(0); i < 8; i++ {
			n[7-i] = byte(uint64(len(row)) >> (i * 8))
		}
		_, _ = h.Write(n[:])
		_, _ = h.Write(row)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func clonePublicationRows(rows [][]byte) [][]byte {
	out := make([][]byte, len(rows))
	for i := range rows {
		out[i] = append([]byte(nil), rows[i]...)
	}
	return out
}
