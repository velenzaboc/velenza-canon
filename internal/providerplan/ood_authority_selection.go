package providerplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// decodeSelectedOODAuthority selects exact offline contract bytes, not an
// admitted document or a current production generation. OOD's authored status
// is metadata: the canonical protocol itself declares draft while remaining
// the forward contract owner. A local "locked" literal cannot create or veto
// that ownership. Expected pins, normalized contract checks and production
// source-owner authentication remain distinct requirements.
func decodeSelectedOODAuthority(item verificationAuthorityInputAdmissionItem, expected string) (oodContract, error) {
	var contract oodContract
	if item.Role != verificationAuthorityRoleOODGraph || sha256Hex(item.Raw) != item.Resource.ContentSHA256 {
		return contract, fmt.Errorf("selected OOD authority role or measured bytes mismatch")
	}
	if err := validateVerificationAuthorityExpectedPin(item, expected); err != nil {
		return contract, err
	}
	if err := requireValidUTF8("OOD spec", item.Raw); err != nil {
		return contract, err
	}
	if err := rejectDuplicateJSONKeys(item.Raw); err != nil {
		return contract, fmt.Errorf("OOD spec: %w", err)
	}
	if err := json.Unmarshal(item.Raw, &contract); err != nil {
		return contract, fmt.Errorf("decode OOD spec: %w", err)
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(item.Raw, &metadata); err != nil {
		return contract, fmt.Errorf("decode OOD metadata: %w", err)
	}
	versionJSON := bytes.TrimSpace(metadata["version"])
	if len(versionJSON) == 0 || versionJSON[0] < '0' || versionJSON[0] > '9' {
		return oodContract{}, fmt.Errorf("selected OOD authority version must be a positive JSON integer")
	}
	parsedID, uuidErr := uuid.Parse(contract.DocID)
	canonicalUUID := uuidErr == nil && parsedID.String() == contract.DocID
	version, err := strconv.ParseInt(contract.Version.String(), 10, 64)
	if err != nil || version <= 0 || strconv.FormatInt(version, 10) != contract.Version.String() ||
		!canonicalUUID || contract.DocID != strings.TrimSpace(contract.DocID) ||
		contract.Status == "" || contract.Status != strings.TrimSpace(contract.Status) {
		return oodContract{}, fmt.Errorf("selected OOD authority has no canonical doc_id/positive version/status metadata")
	}
	return contract, nil
}
