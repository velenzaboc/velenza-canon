//go:build externalfixture

package providerplan

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestExternalQBOWholeRunStageFirstGate(t *testing.T) {
	manifestPath := os.Getenv("VELENZA_QBO_WHOLE_RUN_STAGE_MANIFEST")
	if manifestPath == "" {
		t.Fatal("VELENZA_QBO_WHOLE_RUN_STAGE_MANIFEST is required")
	}
	requestRaw, inputs, err := LoadStageCompileFileManifest(manifestPath)
	if err != nil {
		t.Fatalf("load_gate_class=input_admission error_sha256=%x", sha256.Sum256([]byte(err.Error())))
	}
	if _, err := CompileStageReceipt(requestRaw, inputs); err != nil {
		t.Fatalf("compile_gate_class=%s body_free_scope=%s reconstruction_target=%s evidence_digest=%s error_sha256=%x", classifyExternalQBOWholeRunGate(err), externalQBOBodyFreeScope(err), externalQBOReconstructionTarget(err), externalQBOReconstructionDigest(err), sha256.Sum256([]byte(err.Error())))
	}
}

var externalQBOSelectedEvidenceDigestPattern = regexp.MustCompile(`selected evidence digest ([0-9a-f]{64})`)

func externalQBOReconstructionDigest(err error) string {
	match := externalQBOSelectedEvidenceDigestPattern.FindStringSubmatch(err.Error())
	if len(match) != 2 {
		return "not_applicable"
	}
	return match[1]
}

func externalQBOBodyFreeScope(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "complete request-lineage-material closure is not body-free"):
		return "complete_request_lineage_material_closure"
	case strings.Contains(message, "binding is not body-free"):
		return "binding"
	default:
		return "not_applicable"
	}
}

func externalQBOReconstructionTarget(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "complete decoded body"):
		return "decoded"
	case strings.Contains(message, "complete padded standard base64 body"):
		return "padded_standard_base64"
	case strings.Contains(message, "complete unpadded standard base64 body"):
		return "unpadded_standard_base64"
	case strings.Contains(message, "complete padded URL-safe base64 body"):
		return "padded_urlsafe_base64"
	case strings.Contains(message, "complete unpadded URL-safe base64 body"):
		return "unpadded_urlsafe_base64"
	case strings.Contains(message, "complete hexadecimal body"):
		return "hexadecimal"
	default:
		return "not_applicable"
	}
}

func classifyExternalQBOWholeRunGate(err error) string {
	message := err.Error()
	switch {
	case errors.Is(err, stageEvidenceStateBoundError):
		return "deterministic_state_bound"
	case errors.Is(err, stageEvidenceAggregateStateBoundError):
		return "deterministic_aggregate_state_bound"
	case strings.Contains(message, "exceeds fixed retained/decode storage limit"):
		return "body_free_retained_decode_storage_limit"
	case strings.Contains(message, "exceeds fixed retained storage limit"):
		return "body_free_retained_storage_limit"
	case strings.Contains(message, "exceeds fixed unique representation limit"):
		return "body_free_unique_representation_limit"
	case strings.Contains(message, "exceeds fixed occurrence-group limit"):
		return "body_free_occurrence_group_limit"
	case strings.Contains(message, "exceeds fixed chunk limit"):
		return "body_free_chunk_limit"
	case strings.Contains(message, "exceeds fixed auxiliary byte limit") || strings.Contains(message, "requires") && strings.Contains(message, "analyzer auxiliary bytes"):
		return "body_free_auxiliary_limit"
	case strings.Contains(message, "raw scalar index after") && strings.Contains(message, "exceeds fixed linear-work limit"):
		return "raw_scalar_index_linear_work_limit"
	case strings.Contains(message, "hex-folded scalar index after") && strings.Contains(message, "exceeds fixed linear-work limit"):
		return "hex_folded_scalar_index_linear_work_limit"
	case strings.Contains(message, "wrapped scalar target filter after") && strings.Contains(message, "exceeds fixed linear-work limit"):
		return "wrapped_target_filter_linear_work_limit"
	case strings.Contains(message, "wrapped scalar index after") && strings.Contains(message, "exceeds fixed linear-work limit"):
		return "wrapped_scalar_index_linear_work_limit"
	case strings.Contains(message, "unordered exact scalar carrier analysis") && strings.Contains(message, "exceeds fixed linear-work limit"):
		return "unordered_target_analysis_linear_work_limit"
	case strings.Contains(message, "wrapped exact scalar carrier analysis") && strings.Contains(message, "exceeds fixed linear-work limit"):
		phase := "other"
		switch {
		case strings.Contains(message, "wrapped upper-bound reachability gate"):
			phase = "upper_bound"
		case strings.Contains(message, "two-occurrence gate"):
			phase = "two_occurrence"
		case strings.Contains(message, "multi-occurrence gate"):
			phase = "multi_occurrence"
		}
		target := "other"
		switch {
		case strings.Contains(message, "complete decoded body"):
			target = "decoded"
		case strings.Contains(message, "complete padded standard base64 body"):
			target = "padded_standard_base64"
		case strings.Contains(message, "complete unpadded standard base64 body"):
			target = "unpadded_standard_base64"
		case strings.Contains(message, "complete padded URL-safe base64 body"):
			target = "padded_urlsafe_base64"
		case strings.Contains(message, "complete unpadded URL-safe base64 body"):
			target = "unpadded_urlsafe_base64"
		case strings.Contains(message, "complete hexadecimal body"):
			target = "hexadecimal"
		}
		return fmt.Sprintf("wrapped_target_%s_%s_linear_work_limit", phase, target)
	case strings.Contains(message, "exceeds fixed linear-work limit"):
		return "body_free_linear_work_limit"
	case strings.Contains(message, "body-free wrapped scalar index"):
		return "body_free_wrapped_index"
	case strings.Contains(message, "body-free scalar carrier"):
		return "body_free_scalar_carrier"
	case strings.Contains(message, "is not body-free") && strings.Contains(message, "unordered exact scalar carriers reconstruct"):
		return "body_free_unordered_exact_scalar_reconstruction"
	case strings.Contains(message, "is not body-free") && strings.Contains(message, "reconstructs"):
		return "body_free_ordered_reconstruction"
	case strings.Contains(message, "is not body-free"):
		return "body_free_closure"
	default:
		digest := sha256.Sum256([]byte(message))
		return fmt.Sprintf("other_%x", digest[:4])
	}
}
