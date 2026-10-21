package providerplan

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const (
	providerInputAdmissionKind                      = "provider_documentation_corpus_input_admission_v1"
	providerInputAdmissionVersion                   = "1"
	providerInputAdmissionStatusComplete            = "complete_exact_bounded_input_admission"
	providerInputAdmissionResourceKindManifest      = "evidence_manifest"
	providerInputAdmissionResourceKindCarrier       = "evidence_staged_base64_carrier"
	providerInputAdmissionResourceKindBody          = "evidence_decoded_body"
	providerInputAdmissionResourceKindArtifact      = "dependency_artifact"
	providerInputAdmissionResourceKindAuthority     = "verification_authority"
	providerInputAdmissionResourceKindStageManifest = "stage_input_manifest"
	providerInputAdmissionResourceKindStageFile     = "stage_input_file"
	exactWholeRunStageManifestCount                 = 4
	exactVerificationAuthorityCount                 = 3
	verificationAuthorityRoleOODGraph               = "ood_graph"
	verificationAuthorityRoleGrandVision            = "grand_vision"
	verificationAuthorityRoleSourceRecord           = "source_record"

	// These are one-process safety ceilings, not provider or tenant policy.
	// A larger corpus must be partitioned upstream into separately sealed work
	// units; this verifier never raises an untracked caller-selected limit.
	maxEvidenceManifestCount               int64 = 4_096
	maxEvidenceManifestBytesPerFile        int64 = 16 << 20
	maxEvidenceManifestBytesPerCorpus      int64 = 256 << 20
	maxEvidenceBodyCount                   int64 = 65_536
	maxEvidenceBodyBytesPerFile            int64 = 64 << 20
	maxEvidenceBodyBytesPerCorpus          int64 = 1 << 30
	maxEvidenceCarrierBytesPerFile         int64 = 86 << 20
	maxEvidenceCarrierBytesPerCorpus       int64 = 2 << 30
	maxEvidenceCarrierOuterWhitespace      int64 = 64 << 10
	maxDependencyArtifactCount             int64 = 16_384
	maxDependencyArtifactBytesPerFile      int64 = 64 << 20
	maxDependencyArtifactBytesPerCorpus    int64 = 512 << 20
	maxVerificationAuthorityCount          int64 = exactVerificationAuthorityCount
	maxVerificationAuthorityBytesPerFile   int64 = 64 << 20
	maxVerificationAuthorityBytesPerCorpus int64 = maxVerificationAuthorityCount * maxVerificationAuthorityBytesPerFile
	maxStageInputManifestCount             int64 = exactWholeRunStageManifestCount
	maxStageInputManifestBytesPerFile      int64 = 8 << 20
	maxStageInputManifestBytesPerCorpus    int64 = exactWholeRunStageManifestCount * maxStageInputManifestBytesPerFile
	maxStageInputFileCount                 int64 = 65_536
	maxStageInputFileBytesPerFile          int64 = 64 << 20
	maxStageInputFileBytesPerCorpus        int64 = 1 << 30
	// Encoded evidence carriers are consumed by the strict one-pass decoder and
	// retain metadata only. Every other accepted input class can reach its full
	// corpus ceiling at the same time without exceeding this bound. Factory
	// aliases share their already-retained stage bytes, and equal decoded bodies
	// share one content-index entry, so neither logical role reuse nor carrier
	// bytes add another resident corpus.
	maxProviderInputResidentSnapshotBytes int64 = maxStageInputManifestBytesPerCorpus +
		maxStageInputFileBytesPerCorpus +
		maxEvidenceManifestBytesPerCorpus +
		maxDependencyArtifactBytesPerCorpus +
		maxVerificationAuthorityBytesPerCorpus +
		maxEvidenceBodyBytesPerCorpus
	maxProviderInputAdmissionResourceCount int64 = maxEvidenceManifestCount + (2 * maxEvidenceBodyCount) + maxDependencyArtifactCount + maxVerificationAuthorityCount + maxStageInputManifestCount + maxStageInputFileCount
	maxProviderInputAdmissionResourceBytes int64 = 4 << 30
)

type providerInputAdmissionLimits struct {
	EvidenceManifestCount               int64 `json:"evidence_manifest_count"`
	EvidenceManifestBytesPerFile        int64 `json:"evidence_manifest_bytes_per_file"`
	EvidenceManifestBytesPerCorpus      int64 `json:"evidence_manifest_bytes_per_corpus"`
	EvidenceBodyCount                   int64 `json:"evidence_body_count"`
	EvidenceBodyBytesPerFile            int64 `json:"evidence_body_bytes_per_file"`
	EvidenceBodyBytesPerCorpus          int64 `json:"evidence_body_bytes_per_corpus"`
	EvidenceCarrierBytesPerFile         int64 `json:"evidence_carrier_bytes_per_file"`
	EvidenceCarrierBytesPerCorpus       int64 `json:"evidence_carrier_bytes_per_corpus"`
	EvidenceCarrierOuterWhitespace      int64 `json:"evidence_carrier_outer_whitespace"`
	DependencyArtifactCount             int64 `json:"dependency_artifact_count"`
	DependencyArtifactBytesPerFile      int64 `json:"dependency_artifact_bytes_per_file"`
	DependencyArtifactBytesPerCorpus    int64 `json:"dependency_artifact_bytes_per_corpus"`
	VerificationAuthorityCount          int64 `json:"verification_authority_count"`
	VerificationAuthorityBytesPerFile   int64 `json:"verification_authority_bytes_per_file"`
	VerificationAuthorityBytesPerCorpus int64 `json:"verification_authority_bytes_per_corpus"`
	StageInputManifestCount             int64 `json:"stage_input_manifest_count"`
	StageInputManifestBytesPerFile      int64 `json:"stage_input_manifest_bytes_per_file"`
	StageInputManifestBytesPerCorpus    int64 `json:"stage_input_manifest_bytes_per_corpus"`
	StageInputFileCount                 int64 `json:"stage_input_file_count"`
	StageInputFileBytesPerFile          int64 `json:"stage_input_file_bytes_per_file"`
	StageInputFileBytesPerCorpus        int64 `json:"stage_input_file_bytes_per_corpus"`
	StructuredJSONNestingDepth          int64 `json:"structured_json_nesting_depth"`
	StructuredJSONNodesPerValue         int64 `json:"structured_json_nodes_per_value"`
	StructuredJSONTokensPerValue        int64 `json:"structured_json_tokens_per_value"`
	StructuredJSONStringBytesPerValue   int64 `json:"structured_json_string_bytes_per_value"`
	StructuredJSONDecodedBytesPerValue  int64 `json:"structured_json_decoded_bytes_per_value"`
	StructuredJSONRowsPerArtifact       int64 `json:"structured_json_rows_per_artifact"`
	StructuredJSONRowsPerCorpus         int64 `json:"structured_json_rows_per_corpus"`
	StructuredJSONNodesPerArtifact      int64 `json:"structured_json_nodes_per_artifact"`
	StructuredJSONNodesPerCorpus        int64 `json:"structured_json_nodes_per_corpus"`
	StructuredJSONTokensPerArtifact     int64 `json:"structured_json_tokens_per_artifact"`
	StructuredJSONTokensPerCorpus       int64 `json:"structured_json_tokens_per_corpus"`
	StructuredJSONStringBytesArtifact   int64 `json:"structured_json_string_bytes_per_artifact"`
	StructuredJSONStringBytesCorpus     int64 `json:"structured_json_string_bytes_per_corpus"`
	StructuredJSONDecodedBytesArtifact  int64 `json:"structured_json_decoded_bytes_per_artifact"`
	StructuredJSONDecodedBytesCorpus    int64 `json:"structured_json_decoded_bytes_per_corpus"`
	ResidentSnapshotBytes               int64 `json:"resident_snapshot_bytes"`
	TotalResourceCount                  int64 `json:"total_resource_count"`
	TotalResourceBytes                  int64 `json:"total_resource_bytes"`
}

var canonicalProviderInputAdmissionLimits = providerInputAdmissionLimits{
	EvidenceManifestCount:               maxEvidenceManifestCount,
	EvidenceManifestBytesPerFile:        maxEvidenceManifestBytesPerFile,
	EvidenceManifestBytesPerCorpus:      maxEvidenceManifestBytesPerCorpus,
	EvidenceBodyCount:                   maxEvidenceBodyCount,
	EvidenceBodyBytesPerFile:            maxEvidenceBodyBytesPerFile,
	EvidenceBodyBytesPerCorpus:          maxEvidenceBodyBytesPerCorpus,
	EvidenceCarrierBytesPerFile:         maxEvidenceCarrierBytesPerFile,
	EvidenceCarrierBytesPerCorpus:       maxEvidenceCarrierBytesPerCorpus,
	EvidenceCarrierOuterWhitespace:      maxEvidenceCarrierOuterWhitespace,
	DependencyArtifactCount:             maxDependencyArtifactCount,
	DependencyArtifactBytesPerFile:      maxDependencyArtifactBytesPerFile,
	DependencyArtifactBytesPerCorpus:    maxDependencyArtifactBytesPerCorpus,
	VerificationAuthorityCount:          maxVerificationAuthorityCount,
	VerificationAuthorityBytesPerFile:   maxVerificationAuthorityBytesPerFile,
	VerificationAuthorityBytesPerCorpus: maxVerificationAuthorityBytesPerCorpus,
	StageInputManifestCount:             maxStageInputManifestCount,
	StageInputManifestBytesPerFile:      maxStageInputManifestBytesPerFile,
	StageInputManifestBytesPerCorpus:    maxStageInputManifestBytesPerCorpus,
	StageInputFileCount:                 maxStageInputFileCount,
	StageInputFileBytesPerFile:          maxStageInputFileBytesPerFile,
	StageInputFileBytesPerCorpus:        maxStageInputFileBytesPerCorpus,
	StructuredJSONNestingDepth:          maxProviderJSONNestingDepth,
	StructuredJSONNodesPerValue:         maxProviderJSONNodesPerValue,
	StructuredJSONTokensPerValue:        maxProviderJSONTokensPerValue,
	StructuredJSONStringBytesPerValue:   maxProviderJSONStringBytesPerValue,
	StructuredJSONDecodedBytesPerValue:  maxProviderJSONDecodedBytesPerValue,
	StructuredJSONRowsPerArtifact:       maxProviderJSONRowsPerArtifact,
	StructuredJSONRowsPerCorpus:         maxProviderJSONRowsPerCorpus,
	StructuredJSONNodesPerArtifact:      maxProviderJSONNodesPerArtifact,
	StructuredJSONNodesPerCorpus:        maxProviderJSONNodesPerCorpus,
	StructuredJSONTokensPerArtifact:     maxProviderJSONTokensPerArtifact,
	StructuredJSONTokensPerCorpus:       maxProviderJSONTokensPerCorpus,
	StructuredJSONStringBytesArtifact:   maxProviderJSONStringBytesArtifact,
	StructuredJSONStringBytesCorpus:     maxProviderJSONStringBytesCorpus,
	StructuredJSONDecodedBytesArtifact:  maxProviderJSONDecodedBytesArtifact,
	StructuredJSONDecodedBytesCorpus:    maxProviderJSONDecodedBytesCorpus,
	ResidentSnapshotBytes:               maxProviderInputResidentSnapshotBytes,
	TotalResourceCount:                  maxProviderInputAdmissionResourceCount,
	TotalResourceBytes:                  maxProviderInputAdmissionResourceBytes,
}

type providerInputAdmissionActuals struct {
	EvidenceManifestCount      int64 `json:"evidence_manifest_count"`
	EvidenceManifestBytes      int64 `json:"evidence_manifest_bytes"`
	EvidenceBodyCount          int64 `json:"evidence_body_count"`
	EvidenceBodyBytes          int64 `json:"evidence_body_bytes"`
	EvidenceCarrierCount       int64 `json:"evidence_carrier_count"`
	EvidenceCarrierBytes       int64 `json:"evidence_carrier_bytes"`
	DependencyArtifactCount    int64 `json:"dependency_artifact_count"`
	DependencyArtifactBytes    int64 `json:"dependency_artifact_bytes"`
	VerificationAuthorityCount int64 `json:"verification_authority_count"`
	VerificationAuthorityBytes int64 `json:"verification_authority_bytes"`
	StageInputManifestCount    int64 `json:"stage_input_manifest_count"`
	StageInputManifestBytes    int64 `json:"stage_input_manifest_bytes"`
	StageInputFileCount        int64 `json:"stage_input_file_count"`
	StageInputFileBytes        int64 `json:"stage_input_file_bytes"`
	StructuredJSONRowCount     int64 `json:"structured_json_row_count"`
	StructuredJSONNodeCount    int64 `json:"structured_json_node_count"`
	StructuredJSONTokenCount   int64 `json:"structured_json_token_count"`
	StructuredJSONStringBytes  int64 `json:"structured_json_string_bytes"`
	StructuredJSONDecodedBytes int64 `json:"structured_json_decoded_bytes"`
	ResidentSnapshotBytes      int64 `json:"resident_snapshot_bytes"`
	PeakResidentSnapshotBytes  int64 `json:"peak_resident_snapshot_bytes"`
	TotalResourceCount         int64 `json:"total_resource_count"`
	TotalResourceBytes         int64 `json:"total_resource_bytes"`
}

type providerInputAdmissionResourceReceipt struct {
	ResourceKind          string `json:"resource_kind"`
	StableCoordinate      string `json:"stable_coordinate"`
	ContentSHA256         string `json:"content_sha256"`
	ContentBytes          int64  `json:"content_bytes"`
	DecodedContentSHA256  string `json:"decoded_content_sha256,omitempty"`
	DecodedContentBytes   int64  `json:"decoded_content_bytes,omitempty"`
	ResourceReceiptSHA256 string `json:"resource_receipt_sha256"`
}

type providerInputAdmissionProof struct {
	Kind                  string                        `json:"kind"`
	Version               string                        `json:"version"`
	Limits                providerInputAdmissionLimits  `json:"limits"`
	Actuals               providerInputAdmissionActuals `json:"actuals"`
	ResourceSetRootSHA256 string                        `json:"resource_set_root_sha256"`
	Status                string                        `json:"status"`
	ProofSHA256           string                        `json:"proof_sha256"`
}

// providerInputPhysicalSnapshot is process-local evidence that every logical
// role in one factory run consumed the same immutable bytes from one initial
// retained or streamed admission traversal. Completion validation deliberately
// reopens and rehashes those exact bytes. Filesystem identity and mutation
// tokens never enter portable receipts; only the sealed content identity does.
type providerInputPhysicalSnapshot struct {
	path                  string
	pathKey               string
	bytes                 []byte
	digest                string
	size                  int64
	openedInfo            os.FileInfo
	fileIdentity          providerInputStableFileIdentity
	mutationToken         providerInputMutationToken
	retainsBytes          bool
	initialTraversalCount int
	initialTraversalBytes int64
}

type providerInputContentKey struct {
	digest string
	size   int64
}

type providerInputAdmissionAccumulator struct {
	limits              providerInputAdmissionLimits
	actuals             providerInputAdmissionActuals
	resources           []providerInputAdmissionResourceReceipt
	pathIdentities      []providerInputAdmissionPathIdentity
	pathKeys            map[string]struct{}
	fileIdentities      map[providerInputStableFileIdentity]struct{}
	resourceCoordinates map[string]struct{}
	resourceReceipts    map[string]struct{}
	physicalSnapshots   map[string]*providerInputPhysicalSnapshot
	residentContent     map[providerInputContentKey][]byte
	structuredJSONPaths map[string]struct{}
	residentInputBytes  int64
	residentInputPeak   int64
	factoryAliasMode    bool
	authorizedAliases   map[string]map[string]struct{}

	// Tests use these hooks to deterministically exercise mutation races on
	// retained snapshots. Production construction never installs them.
	beforeStableOpen    func(resourceKind, path string) error
	afterOpenBeforeStat func(resourceKind, path string) error
	afterOpenStat       func(resourceKind, path string) error
}

func newProviderInputAdmissionAccumulator(limits providerInputAdmissionLimits) (*providerInputAdmissionAccumulator, error) {
	if err := validateProviderInputAdmissionLimits(limits); err != nil {
		return nil, err
	}
	return &providerInputAdmissionAccumulator{
		limits:              limits,
		pathKeys:            map[string]struct{}{},
		fileIdentities:      map[providerInputStableFileIdentity]struct{}{},
		resourceCoordinates: map[string]struct{}{},
		resourceReceipts:    map[string]struct{}{},
		physicalSnapshots:   map[string]*providerInputPhysicalSnapshot{},
		residentContent:     map[providerInputContentKey][]byte{},
		structuredJSONPaths: map[string]struct{}{},
		authorizedAliases:   map[string]map[string]struct{}{},
	}, nil
}

func newCanonicalProviderInputAdmissionAccumulator() *providerInputAdmissionAccumulator {
	accumulator, err := newProviderInputAdmissionAccumulator(canonicalProviderInputAdmissionLimits)
	if err != nil {
		panic(err)
	}
	return accumulator
}

func validateProviderInputAdmissionLimits(limits providerInputAdmissionLimits) error {
	ceiling := canonicalProviderInputAdmissionLimits
	checks := []struct {
		name    string
		value   int64
		maximum int64
	}{
		{"evidence_manifest_count", limits.EvidenceManifestCount, ceiling.EvidenceManifestCount},
		{"evidence_manifest_bytes_per_file", limits.EvidenceManifestBytesPerFile, ceiling.EvidenceManifestBytesPerFile},
		{"evidence_manifest_bytes_per_corpus", limits.EvidenceManifestBytesPerCorpus, ceiling.EvidenceManifestBytesPerCorpus},
		{"evidence_body_count", limits.EvidenceBodyCount, ceiling.EvidenceBodyCount},
		{"evidence_body_bytes_per_file", limits.EvidenceBodyBytesPerFile, ceiling.EvidenceBodyBytesPerFile},
		{"evidence_body_bytes_per_corpus", limits.EvidenceBodyBytesPerCorpus, ceiling.EvidenceBodyBytesPerCorpus},
		{"evidence_carrier_bytes_per_file", limits.EvidenceCarrierBytesPerFile, ceiling.EvidenceCarrierBytesPerFile},
		{"evidence_carrier_bytes_per_corpus", limits.EvidenceCarrierBytesPerCorpus, ceiling.EvidenceCarrierBytesPerCorpus},
		{"evidence_carrier_outer_whitespace", limits.EvidenceCarrierOuterWhitespace, ceiling.EvidenceCarrierOuterWhitespace},
		{"dependency_artifact_count", limits.DependencyArtifactCount, ceiling.DependencyArtifactCount},
		{"dependency_artifact_bytes_per_file", limits.DependencyArtifactBytesPerFile, ceiling.DependencyArtifactBytesPerFile},
		{"dependency_artifact_bytes_per_corpus", limits.DependencyArtifactBytesPerCorpus, ceiling.DependencyArtifactBytesPerCorpus},
		{"verification_authority_count", limits.VerificationAuthorityCount, ceiling.VerificationAuthorityCount},
		{"verification_authority_bytes_per_file", limits.VerificationAuthorityBytesPerFile, ceiling.VerificationAuthorityBytesPerFile},
		{"verification_authority_bytes_per_corpus", limits.VerificationAuthorityBytesPerCorpus, ceiling.VerificationAuthorityBytesPerCorpus},
		{"stage_input_manifest_count", limits.StageInputManifestCount, ceiling.StageInputManifestCount},
		{"stage_input_manifest_bytes_per_file", limits.StageInputManifestBytesPerFile, ceiling.StageInputManifestBytesPerFile},
		{"stage_input_manifest_bytes_per_corpus", limits.StageInputManifestBytesPerCorpus, ceiling.StageInputManifestBytesPerCorpus},
		{"stage_input_file_count", limits.StageInputFileCount, ceiling.StageInputFileCount},
		{"stage_input_file_bytes_per_file", limits.StageInputFileBytesPerFile, ceiling.StageInputFileBytesPerFile},
		{"stage_input_file_bytes_per_corpus", limits.StageInputFileBytesPerCorpus, ceiling.StageInputFileBytesPerCorpus},
		{"structured_json_nesting_depth", limits.StructuredJSONNestingDepth, ceiling.StructuredJSONNestingDepth},
		{"structured_json_nodes_per_value", limits.StructuredJSONNodesPerValue, ceiling.StructuredJSONNodesPerValue},
		{"structured_json_tokens_per_value", limits.StructuredJSONTokensPerValue, ceiling.StructuredJSONTokensPerValue},
		{"structured_json_string_bytes_per_value", limits.StructuredJSONStringBytesPerValue, ceiling.StructuredJSONStringBytesPerValue},
		{"structured_json_decoded_bytes_per_value", limits.StructuredJSONDecodedBytesPerValue, ceiling.StructuredJSONDecodedBytesPerValue},
		{"structured_json_rows_per_artifact", limits.StructuredJSONRowsPerArtifact, ceiling.StructuredJSONRowsPerArtifact},
		{"structured_json_rows_per_corpus", limits.StructuredJSONRowsPerCorpus, ceiling.StructuredJSONRowsPerCorpus},
		{"structured_json_nodes_per_artifact", limits.StructuredJSONNodesPerArtifact, ceiling.StructuredJSONNodesPerArtifact},
		{"structured_json_nodes_per_corpus", limits.StructuredJSONNodesPerCorpus, ceiling.StructuredJSONNodesPerCorpus},
		{"structured_json_tokens_per_artifact", limits.StructuredJSONTokensPerArtifact, ceiling.StructuredJSONTokensPerArtifact},
		{"structured_json_tokens_per_corpus", limits.StructuredJSONTokensPerCorpus, ceiling.StructuredJSONTokensPerCorpus},
		{"structured_json_string_bytes_per_artifact", limits.StructuredJSONStringBytesArtifact, ceiling.StructuredJSONStringBytesArtifact},
		{"structured_json_string_bytes_per_corpus", limits.StructuredJSONStringBytesCorpus, ceiling.StructuredJSONStringBytesCorpus},
		{"structured_json_decoded_bytes_per_artifact", limits.StructuredJSONDecodedBytesArtifact, ceiling.StructuredJSONDecodedBytesArtifact},
		{"structured_json_decoded_bytes_per_corpus", limits.StructuredJSONDecodedBytesCorpus, ceiling.StructuredJSONDecodedBytesCorpus},
		{"resident_snapshot_bytes", limits.ResidentSnapshotBytes, ceiling.ResidentSnapshotBytes},
		{"total_resource_count", limits.TotalResourceCount, ceiling.TotalResourceCount},
		{"total_resource_bytes", limits.TotalResourceBytes, ceiling.TotalResourceBytes},
	}
	for _, check := range checks {
		if check.value <= 0 || check.value > check.maximum {
			return fmt.Errorf("provider input admission limit %s=%d is outside (0,%d]", check.name, check.value, check.maximum)
		}
	}
	if limits.StructuredJSONNestingDepth != ceiling.StructuredJSONNestingDepth ||
		limits.StructuredJSONNodesPerValue != ceiling.StructuredJSONNodesPerValue ||
		limits.StructuredJSONTokensPerValue != ceiling.StructuredJSONTokensPerValue ||
		limits.StructuredJSONStringBytesPerValue != ceiling.StructuredJSONStringBytesPerValue ||
		limits.StructuredJSONDecodedBytesPerValue != ceiling.StructuredJSONDecodedBytesPerValue {
		return fmt.Errorf("structured JSON per-value limits must equal the fixed canonical parser profile")
	}
	if limits.EvidenceManifestBytesPerFile > limits.EvidenceManifestBytesPerCorpus {
		return fmt.Errorf("evidence manifest per-file limit exceeds its corpus limit")
	}
	if limits.EvidenceBodyBytesPerFile > limits.EvidenceBodyBytesPerCorpus {
		return fmt.Errorf("evidence body per-file limit exceeds its corpus limit")
	}
	if limits.EvidenceCarrierBytesPerFile > limits.EvidenceCarrierBytesPerCorpus {
		return fmt.Errorf("evidence carrier per-file limit exceeds its corpus limit")
	}
	if limits.EvidenceCarrierOuterWhitespace >= limits.EvidenceCarrierBytesPerFile {
		return fmt.Errorf("evidence carrier outer-whitespace limit must be smaller than its per-file limit")
	}
	if limits.DependencyArtifactBytesPerFile > limits.DependencyArtifactBytesPerCorpus {
		return fmt.Errorf("dependency artifact per-file limit exceeds its corpus limit")
	}
	if limits.VerificationAuthorityBytesPerFile > limits.VerificationAuthorityBytesPerCorpus {
		return fmt.Errorf("verification authority per-file limit exceeds its corpus limit")
	}
	if limits.StageInputManifestBytesPerFile > limits.StageInputManifestBytesPerCorpus {
		return fmt.Errorf("stage input manifest per-file limit exceeds its corpus limit")
	}
	if limits.StageInputFileBytesPerFile > limits.StageInputFileBytesPerCorpus {
		return fmt.Errorf("stage input file per-file limit exceeds its corpus limit")
	}
	if limits.StructuredJSONRowsPerArtifact > limits.StructuredJSONRowsPerCorpus ||
		limits.StructuredJSONNodesPerValue > limits.StructuredJSONNodesPerArtifact || limits.StructuredJSONNodesPerArtifact > limits.StructuredJSONNodesPerCorpus ||
		limits.StructuredJSONTokensPerValue > limits.StructuredJSONTokensPerArtifact || limits.StructuredJSONTokensPerArtifact > limits.StructuredJSONTokensPerCorpus ||
		limits.StructuredJSONStringBytesPerValue > limits.StructuredJSONStringBytesArtifact || limits.StructuredJSONStringBytesArtifact > limits.StructuredJSONStringBytesCorpus ||
		limits.StructuredJSONDecodedBytesPerValue > limits.StructuredJSONDecodedBytesArtifact || limits.StructuredJSONDecodedBytesArtifact > limits.StructuredJSONDecodedBytesCorpus {
		return fmt.Errorf("structured JSON per-value/artifact/corpus limits are inconsistent")
	}
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) preflightPathCount(resourceKind string, count int) error {
	if count < 0 {
		return fmt.Errorf("%s path count is negative", resourceKind)
	}
	actual := int64(count)
	var limit int64
	var alreadyAdmitted int64
	switch resourceKind {
	case providerInputAdmissionResourceKindManifest:
		limit = accumulator.limits.EvidenceManifestCount
		alreadyAdmitted = accumulator.actuals.EvidenceManifestCount
	case providerInputAdmissionResourceKindArtifact:
		limit = accumulator.limits.DependencyArtifactCount
		alreadyAdmitted = accumulator.actuals.DependencyArtifactCount
	case providerInputAdmissionResourceKindAuthority:
		limit = accumulator.limits.VerificationAuthorityCount
		alreadyAdmitted = accumulator.actuals.VerificationAuthorityCount
	case providerInputAdmissionResourceKindStageManifest:
		limit = accumulator.limits.StageInputManifestCount
		alreadyAdmitted = accumulator.actuals.StageInputManifestCount
	case providerInputAdmissionResourceKindStageFile:
		limit = accumulator.limits.StageInputFileCount
		alreadyAdmitted = accumulator.actuals.StageInputFileCount
	default:
		return fmt.Errorf("unsupported provider input path-count resource kind %q", resourceKind)
	}
	if actual > limit-alreadyAdmitted {
		if alreadyAdmitted == 0 {
			return fmt.Errorf("%s path count %d exceeds limit %d", resourceKind, actual, limit)
		}
		return fmt.Errorf("%s path count %d plus admitted count %d exceeds limit %d", resourceKind, actual, alreadyAdmitted, limit)
	}
	if actual > accumulator.limits.TotalResourceCount-accumulator.actuals.TotalResourceCount {
		return fmt.Errorf("%s path count %d would exceed provider input total resource count limit %d", resourceKind, actual, accumulator.limits.TotalResourceCount)
	}
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) reserve(resourceKind string, size int64) error {
	if size < 0 {
		return fmt.Errorf("%s has negative byte length %d", resourceKind, size)
	}
	var count *int64
	var bytesActual *int64
	var countLimit int64
	var perFileLimit int64
	var corpusLimit int64
	switch resourceKind {
	case providerInputAdmissionResourceKindManifest:
		count = &accumulator.actuals.EvidenceManifestCount
		bytesActual = &accumulator.actuals.EvidenceManifestBytes
		countLimit = accumulator.limits.EvidenceManifestCount
		perFileLimit = accumulator.limits.EvidenceManifestBytesPerFile
		corpusLimit = accumulator.limits.EvidenceManifestBytesPerCorpus
	case providerInputAdmissionResourceKindBody:
		count = &accumulator.actuals.EvidenceBodyCount
		bytesActual = &accumulator.actuals.EvidenceBodyBytes
		countLimit = accumulator.limits.EvidenceBodyCount
		perFileLimit = accumulator.limits.EvidenceBodyBytesPerFile
		corpusLimit = accumulator.limits.EvidenceBodyBytesPerCorpus
	case providerInputAdmissionResourceKindCarrier:
		count = &accumulator.actuals.EvidenceCarrierCount
		bytesActual = &accumulator.actuals.EvidenceCarrierBytes
		countLimit = accumulator.limits.EvidenceBodyCount
		perFileLimit = accumulator.limits.EvidenceCarrierBytesPerFile
		corpusLimit = accumulator.limits.EvidenceCarrierBytesPerCorpus
	case providerInputAdmissionResourceKindArtifact:
		count = &accumulator.actuals.DependencyArtifactCount
		bytesActual = &accumulator.actuals.DependencyArtifactBytes
		countLimit = accumulator.limits.DependencyArtifactCount
		perFileLimit = accumulator.limits.DependencyArtifactBytesPerFile
		corpusLimit = accumulator.limits.DependencyArtifactBytesPerCorpus
	case providerInputAdmissionResourceKindAuthority:
		count = &accumulator.actuals.VerificationAuthorityCount
		bytesActual = &accumulator.actuals.VerificationAuthorityBytes
		countLimit = accumulator.limits.VerificationAuthorityCount
		perFileLimit = accumulator.limits.VerificationAuthorityBytesPerFile
		corpusLimit = accumulator.limits.VerificationAuthorityBytesPerCorpus
	case providerInputAdmissionResourceKindStageManifest:
		count = &accumulator.actuals.StageInputManifestCount
		bytesActual = &accumulator.actuals.StageInputManifestBytes
		countLimit = accumulator.limits.StageInputManifestCount
		perFileLimit = accumulator.limits.StageInputManifestBytesPerFile
		corpusLimit = accumulator.limits.StageInputManifestBytesPerCorpus
	case providerInputAdmissionResourceKindStageFile:
		count = &accumulator.actuals.StageInputFileCount
		bytesActual = &accumulator.actuals.StageInputFileBytes
		countLimit = accumulator.limits.StageInputFileCount
		perFileLimit = accumulator.limits.StageInputFileBytesPerFile
		corpusLimit = accumulator.limits.StageInputFileBytesPerCorpus
	default:
		return fmt.Errorf("unsupported provider input admission resource kind %q", resourceKind)
	}
	if size > perFileLimit {
		return fmt.Errorf("%s byte length %d exceeds per-file limit %d", resourceKind, size, perFileLimit)
	}
	if *count >= countLimit {
		return fmt.Errorf("%s count would exceed limit %d", resourceKind, countLimit)
	}
	if size > corpusLimit-*bytesActual {
		return fmt.Errorf("%s corpus bytes would exceed limit %d", resourceKind, corpusLimit)
	}
	if size > accumulator.limits.TotalResourceBytes-accumulator.actuals.TotalResourceBytes {
		return fmt.Errorf("provider input total resource bytes would exceed limit %d", accumulator.limits.TotalResourceBytes)
	}
	if accumulator.actuals.TotalResourceCount >= accumulator.limits.TotalResourceCount {
		return fmt.Errorf("provider input total resource count would exceed limit %d", accumulator.limits.TotalResourceCount)
	}
	(*count)++
	*bytesActual += size
	accumulator.actuals.TotalResourceCount++
	accumulator.actuals.TotalResourceBytes += size
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) checkReservation(resourceKind string, size int64) error {
	clone := *accumulator
	clone.resources = nil
	clone.pathIdentities = nil
	clone.physicalSnapshots = nil
	clone.beforeStableOpen = nil
	clone.afterOpenBeforeStat = nil
	clone.afterOpenStat = nil
	return clone.reserve(resourceKind, size)
}

func (accumulator *providerInputAdmissionAccumulator) addResource(resource providerInputAdmissionResourceReceipt) error {
	sealed, err := sealProviderInputAdmissionResource(resource)
	if err != nil {
		return err
	}
	accumulator.ensureDuplicateIndexes()
	coordinateKey := sealed.ResourceKind + "\x00" + sealed.StableCoordinate
	if _, duplicate := accumulator.resourceCoordinates[coordinateKey]; duplicate {
		return fmt.Errorf("provider input admission has duplicate resource identity %s %q", sealed.ResourceKind, sealed.StableCoordinate)
	}
	if _, duplicate := accumulator.resourceReceipts[sealed.ResourceReceiptSHA256]; duplicate {
		return fmt.Errorf("provider input admission duplicates resource receipt %s", sealed.ResourceReceiptSHA256)
	}
	accumulator.resources = append(accumulator.resources, sealed)
	accumulator.resourceCoordinates[coordinateKey] = struct{}{}
	accumulator.resourceReceipts[sealed.ResourceReceiptSHA256] = struct{}{}
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) ensureDuplicateIndexes() {
	if accumulator.resourceCoordinates == nil {
		accumulator.resourceCoordinates = make(map[string]struct{}, len(accumulator.resources))
		for _, resource := range accumulator.resources {
			accumulator.resourceCoordinates[resource.ResourceKind+"\x00"+resource.StableCoordinate] = struct{}{}
		}
	}
	if accumulator.resourceReceipts == nil {
		accumulator.resourceReceipts = make(map[string]struct{}, len(accumulator.resources))
		for _, resource := range accumulator.resources {
			accumulator.resourceReceipts[resource.ResourceReceiptSHA256] = struct{}{}
		}
	}
}

func sealProviderInputAdmissionResource(resource providerInputAdmissionResourceReceipt) (providerInputAdmissionResourceReceipt, error) {
	if resource.ResourceKind == "" || resource.StableCoordinate == "" || !isLowerSHA256(resource.ContentSHA256) || resource.ContentBytes < 0 {
		return providerInputAdmissionResourceReceipt{}, fmt.Errorf("provider input resource receipt is incomplete")
	}
	switch resource.ResourceKind {
	case providerInputAdmissionResourceKindCarrier:
		if !isLowerSHA256(resource.DecodedContentSHA256) || resource.DecodedContentBytes <= 0 {
			return providerInputAdmissionResourceReceipt{}, fmt.Errorf("provider input carrier resource decoded content tuple is incomplete")
		}
	case providerInputAdmissionResourceKindManifest, providerInputAdmissionResourceKindBody, providerInputAdmissionResourceKindArtifact, providerInputAdmissionResourceKindAuthority, providerInputAdmissionResourceKindStageManifest, providerInputAdmissionResourceKindStageFile:
		if resource.DecodedContentSHA256 != "" || resource.DecodedContentBytes != 0 {
			return providerInputAdmissionResourceReceipt{}, fmt.Errorf("provider input non-carrier resource carries a decoded content tuple")
		}
	default:
		return providerInputAdmissionResourceReceipt{}, fmt.Errorf("provider input resource receipt has unknown kind %q", resource.ResourceKind)
	}
	resource.ResourceReceiptSHA256 = ""
	identity, err := canonicalProviderInputAdmissionJSON(resource)
	if err != nil {
		return providerInputAdmissionResourceReceipt{}, err
	}
	resource.ResourceReceiptSHA256 = sha256Hex(identity)
	return resource, nil
}

func (accumulator *providerInputAdmissionAccumulator) seal() (providerInputAdmissionProof, error) {
	if int64(len(accumulator.resources)) != accumulator.actuals.TotalResourceCount {
		return providerInputAdmissionProof{}, fmt.Errorf("provider input admission has %d resource receipts, want %d reserved resources", len(accumulator.resources), accumulator.actuals.TotalResourceCount)
	}
	if accumulator.actuals.ResidentSnapshotBytes != accumulator.residentInputBytes || accumulator.actuals.PeakResidentSnapshotBytes != accumulator.residentInputPeak || accumulator.residentInputBytes > accumulator.residentInputPeak {
		return providerInputAdmissionProof{}, fmt.Errorf("provider input admission resident snapshot accounting differs from its observed current/peak state")
	}
	root, err := providerInputAdmissionResourceSetRoot(accumulator.resources)
	if err != nil {
		return providerInputAdmissionProof{}, err
	}
	proof := providerInputAdmissionProof{
		Kind:                  providerInputAdmissionKind,
		Version:               providerInputAdmissionVersion,
		Limits:                accumulator.limits,
		Actuals:               accumulator.actuals,
		ResourceSetRootSHA256: root,
		Status:                providerInputAdmissionStatusComplete,
	}
	identity, err := canonicalProviderInputAdmissionProofIdentity(proof)
	if err != nil {
		return providerInputAdmissionProof{}, err
	}
	proof.ProofSHA256 = sha256Hex(identity)
	if err := validateProviderInputAdmissionProof(proof, accumulator.resources); err != nil {
		return providerInputAdmissionProof{}, err
	}
	return proof, nil
}

func validateProviderInputAdmissionProof(proof providerInputAdmissionProof, resources []providerInputAdmissionResourceReceipt) error {
	if proof.Kind != providerInputAdmissionKind || proof.Version != providerInputAdmissionVersion || proof.Status != providerInputAdmissionStatusComplete || !isLowerSHA256(proof.ResourceSetRootSHA256) || !isLowerSHA256(proof.ProofSHA256) {
		return fmt.Errorf("provider input admission proof identity is incomplete")
	}
	if err := validateProviderInputAdmissionLimits(proof.Limits); err != nil {
		return err
	}
	for _, resource := range resources {
		if err := validateProviderInputAdmissionResourceAgainstLimits(resource, proof.Limits); err != nil {
			return err
		}
	}
	if err := validateProviderInputAdmissionEvidenceResourcePairs(resources); err != nil {
		return err
	}
	actuals, err := providerInputAdmissionActualsFromResources(resources)
	if err != nil {
		return err
	}
	if !equalProviderInputResourceActuals(actuals, proof.Actuals) {
		return fmt.Errorf("provider input admission actuals do not equal the exact resource receipt roster")
	}
	if err := validateProviderInputAdmissionActuals(proof.Actuals, proof.Limits); err != nil {
		return err
	}
	root, err := providerInputAdmissionResourceSetRoot(resources)
	if err != nil {
		return err
	}
	if root != proof.ResourceSetRootSHA256 {
		return fmt.Errorf("provider input admission resource root %s does not equal exact receipt roster root %s", proof.ResourceSetRootSHA256, root)
	}
	identity, err := canonicalProviderInputAdmissionProofIdentity(proof)
	if err != nil {
		return err
	}
	if sha256Hex(identity) != proof.ProofSHA256 {
		return fmt.Errorf("provider input admission proof digest does not equal its canonical identity")
	}
	return nil
}

func validateProviderInputAdmissionEvidenceResourcePairs(resources []providerInputAdmissionResourceReceipt) error {
	bodies := map[string]providerInputAdmissionResourceReceipt{}
	carriers := map[string]providerInputAdmissionResourceReceipt{}
	for _, resource := range resources {
		switch resource.ResourceKind {
		case providerInputAdmissionResourceKindBody:
			if _, duplicate := bodies[resource.StableCoordinate]; duplicate {
				return fmt.Errorf("provider input admission duplicates evidence body coordinate %q", resource.StableCoordinate)
			}
			bodies[resource.StableCoordinate] = resource
		case providerInputAdmissionResourceKindCarrier:
			if _, duplicate := carriers[resource.StableCoordinate]; duplicate {
				return fmt.Errorf("provider input admission duplicates evidence carrier coordinate %q", resource.StableCoordinate)
			}
			carriers[resource.StableCoordinate] = resource
		}
	}
	if len(bodies) != len(carriers) {
		return fmt.Errorf("provider input admission evidence body/carrier coordinate sets differ")
	}
	for _, coordinate := range sortedProviderStringMapKeys(bodies) {
		body := bodies[coordinate]
		carrier, ok := carriers[coordinate]
		if !ok || carrier.DecodedContentSHA256 != body.ContentSHA256 || carrier.DecodedContentBytes != body.ContentBytes {
			return fmt.Errorf("provider input admission carrier coordinate %q does not bind its exact decoded body", coordinate)
		}
	}
	return nil
}

func validateProviderInputAdmissionResourceAgainstLimits(resource providerInputAdmissionResourceReceipt, limits providerInputAdmissionLimits) error {
	var maximum int64
	switch resource.ResourceKind {
	case providerInputAdmissionResourceKindManifest:
		maximum = limits.EvidenceManifestBytesPerFile
	case providerInputAdmissionResourceKindBody:
		maximum = limits.EvidenceBodyBytesPerFile
	case providerInputAdmissionResourceKindCarrier:
		maximum = limits.EvidenceCarrierBytesPerFile
	case providerInputAdmissionResourceKindArtifact:
		maximum = limits.DependencyArtifactBytesPerFile
	case providerInputAdmissionResourceKindAuthority:
		maximum = limits.VerificationAuthorityBytesPerFile
	case providerInputAdmissionResourceKindStageManifest:
		maximum = limits.StageInputManifestBytesPerFile
	case providerInputAdmissionResourceKindStageFile:
		maximum = limits.StageInputFileBytesPerFile
	default:
		return fmt.Errorf("provider input resource receipt has unknown kind %q", resource.ResourceKind)
	}
	if resource.ContentBytes > maximum {
		return fmt.Errorf("provider input resource %q byte length %d exceeds bound limit %d", resource.StableCoordinate, resource.ContentBytes, maximum)
	}
	return nil
}

func validateProviderInputAdmissionActuals(actuals providerInputAdmissionActuals, limits providerInputAdmissionLimits) error {
	checks := []struct {
		name   string
		actual int64
		limit  int64
	}{
		{"evidence_manifest_count", actuals.EvidenceManifestCount, limits.EvidenceManifestCount},
		{"evidence_manifest_bytes", actuals.EvidenceManifestBytes, limits.EvidenceManifestBytesPerCorpus},
		{"evidence_body_count", actuals.EvidenceBodyCount, limits.EvidenceBodyCount},
		{"evidence_body_bytes", actuals.EvidenceBodyBytes, limits.EvidenceBodyBytesPerCorpus},
		{"evidence_carrier_count", actuals.EvidenceCarrierCount, limits.EvidenceBodyCount},
		{"evidence_carrier_bytes", actuals.EvidenceCarrierBytes, limits.EvidenceCarrierBytesPerCorpus},
		{"dependency_artifact_count", actuals.DependencyArtifactCount, limits.DependencyArtifactCount},
		{"dependency_artifact_bytes", actuals.DependencyArtifactBytes, limits.DependencyArtifactBytesPerCorpus},
		{"verification_authority_count", actuals.VerificationAuthorityCount, limits.VerificationAuthorityCount},
		{"verification_authority_bytes", actuals.VerificationAuthorityBytes, limits.VerificationAuthorityBytesPerCorpus},
		{"stage_input_manifest_count", actuals.StageInputManifestCount, limits.StageInputManifestCount},
		{"stage_input_manifest_bytes", actuals.StageInputManifestBytes, limits.StageInputManifestBytesPerCorpus},
		{"stage_input_file_count", actuals.StageInputFileCount, limits.StageInputFileCount},
		{"stage_input_file_bytes", actuals.StageInputFileBytes, limits.StageInputFileBytesPerCorpus},
		{"structured_json_row_count", actuals.StructuredJSONRowCount, limits.StructuredJSONRowsPerCorpus},
		{"structured_json_node_count", actuals.StructuredJSONNodeCount, limits.StructuredJSONNodesPerCorpus},
		{"structured_json_token_count", actuals.StructuredJSONTokenCount, limits.StructuredJSONTokensPerCorpus},
		{"structured_json_string_bytes", actuals.StructuredJSONStringBytes, limits.StructuredJSONStringBytesCorpus},
		{"structured_json_decoded_bytes", actuals.StructuredJSONDecodedBytes, limits.StructuredJSONDecodedBytesCorpus},
		{"resident_snapshot_bytes", actuals.ResidentSnapshotBytes, limits.ResidentSnapshotBytes},
		{"peak_resident_snapshot_bytes", actuals.PeakResidentSnapshotBytes, limits.ResidentSnapshotBytes},
		{"total_resource_count", actuals.TotalResourceCount, limits.TotalResourceCount},
		{"total_resource_bytes", actuals.TotalResourceBytes, limits.TotalResourceBytes},
	}
	for _, check := range checks {
		if check.actual < 0 || check.actual > check.limit {
			return fmt.Errorf("provider input admission actual %s=%d exceeds limit %d", check.name, check.actual, check.limit)
		}
	}
	if actuals.EvidenceBodyCount != actuals.EvidenceCarrierCount {
		return fmt.Errorf("provider input admission evidence body/carrier counts differ: bodies=%d carriers=%d", actuals.EvidenceBodyCount, actuals.EvidenceCarrierCount)
	}
	if actuals.TotalResourceCount != actuals.EvidenceManifestCount+actuals.EvidenceBodyCount+actuals.EvidenceCarrierCount+actuals.DependencyArtifactCount+actuals.VerificationAuthorityCount+actuals.StageInputManifestCount+actuals.StageInputFileCount {
		return fmt.Errorf("provider input admission total resource count does not equal its resource-kind partition")
	}
	if actuals.TotalResourceBytes != actuals.EvidenceManifestBytes+actuals.EvidenceBodyBytes+actuals.EvidenceCarrierBytes+actuals.DependencyArtifactBytes+actuals.VerificationAuthorityBytes+actuals.StageInputManifestBytes+actuals.StageInputFileBytes {
		return fmt.Errorf("provider input admission total resource bytes do not equal its resource-kind partition")
	}
	if actuals.ResidentSnapshotBytes > actuals.PeakResidentSnapshotBytes {
		return fmt.Errorf("provider input admission resident snapshot bytes exceed the observed peak")
	}
	return nil
}

func equalProviderInputResourceActuals(left, right providerInputAdmissionActuals) bool {
	return left.EvidenceManifestCount == right.EvidenceManifestCount &&
		left.EvidenceManifestBytes == right.EvidenceManifestBytes &&
		left.EvidenceBodyCount == right.EvidenceBodyCount &&
		left.EvidenceBodyBytes == right.EvidenceBodyBytes &&
		left.EvidenceCarrierCount == right.EvidenceCarrierCount &&
		left.EvidenceCarrierBytes == right.EvidenceCarrierBytes &&
		left.DependencyArtifactCount == right.DependencyArtifactCount &&
		left.DependencyArtifactBytes == right.DependencyArtifactBytes &&
		left.VerificationAuthorityCount == right.VerificationAuthorityCount &&
		left.VerificationAuthorityBytes == right.VerificationAuthorityBytes &&
		left.StageInputManifestCount == right.StageInputManifestCount &&
		left.StageInputManifestBytes == right.StageInputManifestBytes &&
		left.StageInputFileCount == right.StageInputFileCount &&
		left.StageInputFileBytes == right.StageInputFileBytes &&
		left.TotalResourceCount == right.TotalResourceCount &&
		left.TotalResourceBytes == right.TotalResourceBytes
}

func providerInputAdmissionActualsFromResources(resources []providerInputAdmissionResourceReceipt) (providerInputAdmissionActuals, error) {
	var actuals providerInputAdmissionActuals
	seenReceipts := map[string]struct{}{}
	seenIdentities := map[string]struct{}{}
	for _, resource := range resources {
		sealed, err := sealProviderInputAdmissionResource(resource)
		if err != nil {
			return providerInputAdmissionActuals{}, err
		}
		if sealed.ResourceReceiptSHA256 != resource.ResourceReceiptSHA256 {
			return providerInputAdmissionActuals{}, fmt.Errorf("provider input resource receipt %q has an invalid self digest", resource.StableCoordinate)
		}
		if _, duplicate := seenReceipts[resource.ResourceReceiptSHA256]; duplicate {
			return providerInputAdmissionActuals{}, fmt.Errorf("provider input resource receipt %s is duplicated", resource.ResourceReceiptSHA256)
		}
		seenReceipts[resource.ResourceReceiptSHA256] = struct{}{}
		identityKey := resource.ResourceKind + "\x00" + resource.StableCoordinate
		if _, duplicate := seenIdentities[identityKey]; duplicate {
			return providerInputAdmissionActuals{}, fmt.Errorf("provider input resource identity %s %q is duplicated", resource.ResourceKind, resource.StableCoordinate)
		}
		seenIdentities[identityKey] = struct{}{}
		if resource.ContentBytes > canonicalProviderInputAdmissionLimits.TotalResourceBytes {
			return providerInputAdmissionActuals{}, fmt.Errorf("provider input resource byte length %d exceeds the canonical accounting domain", resource.ContentBytes)
		}
		switch resource.ResourceKind {
		case providerInputAdmissionResourceKindManifest:
			if resource.ContentBytes > canonicalProviderInputAdmissionLimits.EvidenceManifestBytesPerCorpus-actuals.EvidenceManifestBytes {
				return providerInputAdmissionActuals{}, fmt.Errorf("evidence manifest resource bytes overflow the canonical accounting domain")
			}
			actuals.EvidenceManifestCount++
			actuals.EvidenceManifestBytes += resource.ContentBytes
		case providerInputAdmissionResourceKindBody:
			if resource.ContentBytes > canonicalProviderInputAdmissionLimits.EvidenceBodyBytesPerCorpus-actuals.EvidenceBodyBytes {
				return providerInputAdmissionActuals{}, fmt.Errorf("evidence body resource bytes overflow the canonical accounting domain")
			}
			actuals.EvidenceBodyCount++
			actuals.EvidenceBodyBytes += resource.ContentBytes
		case providerInputAdmissionResourceKindCarrier:
			if resource.ContentBytes > canonicalProviderInputAdmissionLimits.EvidenceCarrierBytesPerCorpus-actuals.EvidenceCarrierBytes {
				return providerInputAdmissionActuals{}, fmt.Errorf("evidence carrier resource bytes overflow the canonical accounting domain")
			}
			actuals.EvidenceCarrierCount++
			actuals.EvidenceCarrierBytes += resource.ContentBytes
		case providerInputAdmissionResourceKindArtifact:
			if resource.ContentBytes > canonicalProviderInputAdmissionLimits.DependencyArtifactBytesPerCorpus-actuals.DependencyArtifactBytes {
				return providerInputAdmissionActuals{}, fmt.Errorf("dependency artifact resource bytes overflow the canonical accounting domain")
			}
			actuals.DependencyArtifactCount++
			actuals.DependencyArtifactBytes += resource.ContentBytes
		case providerInputAdmissionResourceKindAuthority:
			if resource.ContentBytes > canonicalProviderInputAdmissionLimits.VerificationAuthorityBytesPerCorpus-actuals.VerificationAuthorityBytes {
				return providerInputAdmissionActuals{}, fmt.Errorf("verification authority resource bytes overflow the canonical accounting domain")
			}
			actuals.VerificationAuthorityCount++
			actuals.VerificationAuthorityBytes += resource.ContentBytes
		case providerInputAdmissionResourceKindStageManifest:
			if resource.ContentBytes > canonicalProviderInputAdmissionLimits.StageInputManifestBytesPerCorpus-actuals.StageInputManifestBytes {
				return providerInputAdmissionActuals{}, fmt.Errorf("stage input manifest resource bytes overflow the canonical accounting domain")
			}
			actuals.StageInputManifestCount++
			actuals.StageInputManifestBytes += resource.ContentBytes
		case providerInputAdmissionResourceKindStageFile:
			if resource.ContentBytes > canonicalProviderInputAdmissionLimits.StageInputFileBytesPerCorpus-actuals.StageInputFileBytes {
				return providerInputAdmissionActuals{}, fmt.Errorf("stage input file resource bytes overflow the canonical accounting domain")
			}
			actuals.StageInputFileCount++
			actuals.StageInputFileBytes += resource.ContentBytes
		default:
			return providerInputAdmissionActuals{}, fmt.Errorf("provider input resource receipt has unknown kind %q", resource.ResourceKind)
		}
		if resource.ContentBytes > canonicalProviderInputAdmissionLimits.TotalResourceBytes-actuals.TotalResourceBytes {
			return providerInputAdmissionActuals{}, fmt.Errorf("provider input resource byte total overflows its canonical domain")
		}
		actuals.TotalResourceCount++
		actuals.TotalResourceBytes += resource.ContentBytes
	}
	return actuals, nil
}

type verificationAuthorityInputAdmissionItem struct {
	Role     string
	Raw      []byte
	Resource providerInputAdmissionResourceReceipt
}

type verificationAuthorityInputAdmissionBinding struct {
	ProofSHA256           string
	ResourceSetRootSHA256 string
	Items                 []verificationAuthorityInputAdmissionItem
}

func (binding verificationAuthorityInputAdmissionBinding) resources() []providerInputAdmissionResourceReceipt {
	resources := make([]providerInputAdmissionResourceReceipt, 0, len(binding.Items))
	for _, item := range binding.Items {
		resources = append(resources, item.Resource)
	}
	return resources
}

func readVerificationAuthorityWithAdmission(path, role string, accumulator *providerInputAdmissionAccumulator) (verificationAuthorityInputAdmissionItem, error) {
	allowedRoles := map[string]struct{}{
		verificationAuthorityRoleOODGraph:     {},
		verificationAuthorityRoleGrandVision:  {},
		verificationAuthorityRoleSourceRecord: {},
	}
	if _, ok := allowedRoles[role]; !ok {
		return verificationAuthorityInputAdmissionItem{}, fmt.Errorf("verification authority role %q is not registered", role)
	}
	stableCoordinate := "verification_authority_input_v1|" + lengthPrefixedIdentityKey(role)
	file, err := readBoundedProviderInputFile(path, "verification authority "+role, providerInputAdmissionResourceKindAuthority, stableCoordinate, accumulator)
	if err != nil {
		return verificationAuthorityInputAdmissionItem{}, err
	}
	return verificationAuthorityInputAdmissionItem{Role: role, Raw: file.Bytes, Resource: file.Resource}, nil
}

func validateVerificationAuthorityExpectedPin(item verificationAuthorityInputAdmissionItem, expectedSHA256 string) error {
	if !isLowerSHA256(expectedSHA256) {
		return fmt.Errorf("verification authority %s expected digest is not lowercase SHA-256", item.Role)
	}
	if item.Resource.ContentSHA256 != expectedSHA256 {
		return fmt.Errorf("selected %s authority bytes hash %s does not equal independently expected authority hash %s", item.Role, item.Resource.ContentSHA256, expectedSHA256)
	}
	return nil
}

func bindAndValidateVerificationAuthorityInputAdmission(binding *verificationAuthorityInputAdmissionBinding, proof providerInputAdmissionProof, allResources []providerInputAdmissionResourceReceipt) error {
	if binding == nil {
		return fmt.Errorf("verification authority input binding has 0 items, want exactly %d", maxVerificationAuthorityCount)
	}
	if len(binding.Items) != int(maxVerificationAuthorityCount) {
		return fmt.Errorf("verification authority input binding has %d items, want exactly %d", len(binding.Items), maxVerificationAuthorityCount)
	}
	binding.ProofSHA256 = proof.ProofSHA256
	resources := binding.resources()
	root, err := providerInputAdmissionResourceSetRoot(resources)
	if err != nil {
		return err
	}
	binding.ResourceSetRootSHA256 = root
	resourceByReceipt := make(map[string]providerInputAdmissionResourceReceipt, len(allResources))
	authorityResourceCount := 0
	for _, resource := range allResources {
		resourceByReceipt[resource.ResourceReceiptSHA256] = resource
		if resource.ResourceKind == providerInputAdmissionResourceKindAuthority {
			authorityResourceCount++
		}
	}
	if authorityResourceCount != len(binding.Items) {
		return fmt.Errorf("verification authority sealed resource roster has %d items, want exactly %d", authorityResourceCount, len(binding.Items))
	}
	wantRoles := map[string]struct{}{
		verificationAuthorityRoleOODGraph:     {},
		verificationAuthorityRoleGrandVision:  {},
		verificationAuthorityRoleSourceRecord: {},
	}
	seenRoles := map[string]struct{}{}
	for _, item := range binding.Items {
		if _, ok := wantRoles[item.Role]; !ok {
			return fmt.Errorf("verification authority input binding has unregistered role %q", item.Role)
		}
		if _, duplicate := seenRoles[item.Role]; duplicate {
			return fmt.Errorf("verification authority input binding duplicates role %q", item.Role)
		}
		seenRoles[item.Role] = struct{}{}
		resource := item.Resource
		wantCoordinate := "verification_authority_input_v1|" + lengthPrefixedIdentityKey(item.Role)
		if resource.ResourceKind != providerInputAdmissionResourceKindAuthority || resource.StableCoordinate != wantCoordinate || resource.ContentBytes != int64(len(item.Raw)) || resource.ContentSHA256 != sha256Hex(item.Raw) {
			return fmt.Errorf("verification authority %q is not exactly bound to its admission resource", item.Role)
		}
		if resourceByReceipt[resource.ResourceReceiptSHA256].ResourceReceiptSHA256 != resource.ResourceReceiptSHA256 {
			return fmt.Errorf("verification authority %q is absent from the sealed provider input roster", item.Role)
		}
	}
	if len(seenRoles) != len(wantRoles) {
		return fmt.Errorf("verification authority input binding role set is incomplete")
	}
	return nil
}

func bindAndValidateProviderInputAdmission(evidence *loadedEvidence, dependencies map[string]artifactInput, authorityBinding *verificationAuthorityInputAdmissionBinding, stageBinding *stageCompileInputAdmissionBinding, priorResources []providerInputAdmissionResourceReceipt, proof providerInputAdmissionProof, resources []providerInputAdmissionResourceReceipt) error {
	if evidence == nil {
		return fmt.Errorf("provider input admission evidence binding target is nil")
	}
	evidence.InputAdmissionProof = proof
	for _, digest := range sortedProviderStringMapKeys(evidence.Artifacts) {
		artifact := evidence.Artifacts[digest]
		artifact.InputAdmissionProofSHA256 = proof.ProofSHA256
		evidence.Artifacts[digest] = artifact
	}
	for _, digest := range sortedProviderStringMapKeys(dependencies) {
		artifact := dependencies[digest]
		artifact.InputAdmissionProofSHA256 = proof.ProofSHA256
		dependencies[digest] = artifact
	}
	if err := validateProviderInputAdmissionProof(proof, resources); err != nil {
		return fmt.Errorf("validate provider input admission proof: %w", err)
	}
	if err := validateEvidenceInputAdmissionBinding(*evidence, proof); err != nil {
		return err
	}
	if err := validateDependencyInputAdmissionBinding(dependencies, proof, resources); err != nil {
		return err
	}
	combined := make([]providerInputAdmissionResourceReceipt, 0, len(resources))
	if authorityBinding != nil && len(authorityBinding.Items) != 0 {
		if err := bindAndValidateVerificationAuthorityInputAdmission(authorityBinding, proof, resources); err != nil {
			return err
		}
		combined = append(combined, authorityBinding.resources()...)
	}
	if stageBinding != nil && len(stageBinding.Items) != 0 {
		if err := bindAndValidateStageCompileInputAdmission(stageBinding, proof, resources); err != nil {
			return err
		}
		combined = append(combined, stageBinding.resources()...)
	}
	sealedResourceByReceipt := make(map[string]providerInputAdmissionResourceReceipt, len(resources))
	for _, resource := range resources {
		sealedResourceByReceipt[resource.ResourceReceiptSHA256] = resource
	}
	seenPriorReceipts := make(map[string]struct{}, len(priorResources))
	for _, resource := range priorResources {
		if resource.ResourceKind != providerInputAdmissionResourceKindStageManifest && resource.ResourceKind != providerInputAdmissionResourceKindStageFile {
			return fmt.Errorf("pre-verifier provider input roster contains non-stage resource kind %q", resource.ResourceKind)
		}
		if _, duplicate := seenPriorReceipts[resource.ResourceReceiptSHA256]; duplicate {
			return fmt.Errorf("pre-verifier provider input roster duplicates resource receipt %s", resource.ResourceReceiptSHA256)
		}
		seenPriorReceipts[resource.ResourceReceiptSHA256] = struct{}{}
		if sealedResourceByReceipt[resource.ResourceReceiptSHA256].ResourceReceiptSHA256 != resource.ResourceReceiptSHA256 {
			return fmt.Errorf("pre-verifier provider input resource %s is absent from the sealed whole-run roster", resource.ResourceReceiptSHA256)
		}
		combined = append(combined, resource)
	}
	combined = append(combined, evidence.InputAdmissionResources...)
	for _, digest := range sortedProviderStringMapKeys(dependencies) {
		artifact := dependencies[digest]
		combined = append(combined, artifact.InputAdmissionResource)
	}
	combinedRoot, err := providerInputAdmissionResourceSetRoot(combined)
	if err != nil {
		return err
	}
	if combinedRoot != proof.ResourceSetRootSHA256 || len(combined) != len(resources) {
		return fmt.Errorf("provider input admission downstream resource roster is not set-equal to the sealed resource roster")
	}
	return nil
}

func validateEvidenceInputAdmissionBinding(evidence loadedEvidence, proof providerInputAdmissionProof) error {
	if evidence.InputAdmissionProof.ProofSHA256 != proof.ProofSHA256 {
		return fmt.Errorf("loaded evidence does not carry the sealed provider input admission proof")
	}
	byKindAndCoordinate := map[string]providerInputAdmissionResourceReceipt{}
	manifestResourceCount := 0
	bodyResourceCount := 0
	carrierResourceCount := 0
	for _, resource := range evidence.InputAdmissionResources {
		switch resource.ResourceKind {
		case providerInputAdmissionResourceKindManifest:
			manifestResourceCount++
		case providerInputAdmissionResourceKindBody:
			bodyResourceCount++
		case providerInputAdmissionResourceKindCarrier:
			carrierResourceCount++
		default:
			return fmt.Errorf("loaded evidence carries non-evidence input resource kind %q", resource.ResourceKind)
		}
		key := resource.ResourceKind + "\x00" + resource.StableCoordinate
		if _, duplicate := byKindAndCoordinate[key]; duplicate {
			return fmt.Errorf("loaded evidence duplicates provider input resource coordinate %q", resource.StableCoordinate)
		}
		byKindAndCoordinate[key] = resource
	}
	if manifestResourceCount != len(evidence.Artifacts) || bodyResourceCount != evidence.BodyCoordinateRows || carrierResourceCount != evidence.BodyCoordinateRows || evidence.BodyCoordinateRows != len(evidence.MetadataByCoordinate) {
		return fmt.Errorf("loaded evidence resource roster is not set-equal to its manifest and body-coordinate rosters")
	}
	for _, digest := range sortedProviderStringMapKeys(evidence.Artifacts) {
		artifact := evidence.Artifacts[digest]
		if artifact.InputAdmissionProofSHA256 != proof.ProofSHA256 || artifact.InputAdmissionResource.ResourceKind != providerInputAdmissionResourceKindManifest || artifact.InputAdmissionResource.ContentSHA256 != digest || artifact.InputAdmissionResource.ContentBytes != int64(len(artifact.Raw)) || sha256Hex(artifact.Raw) != digest {
			return fmt.Errorf("evidence manifest %s is not exactly bound to its provider input admission resource", digest)
		}
		key := providerInputAdmissionResourceKindManifest + "\x00" + artifact.InputAdmissionResource.StableCoordinate
		if byKindAndCoordinate[key].ResourceReceiptSHA256 != artifact.InputAdmissionResource.ResourceReceiptSHA256 {
			return fmt.Errorf("evidence manifest %s admission resource is absent from the evidence resource roster", digest)
		}
	}
	for _, coordinate := range sortedEvidenceSourceCoordinates(evidence.MetadataByCoordinate) {
		metadata := evidence.MetadataByCoordinate[coordinate]
		stableCoordinate := "evidence_body_v1|" + lengthPrefixedIdentityKey(metadata.ManifestSHA256, coordinate.Ref, coordinate.URL)
		bodyResource, bodyOK := byKindAndCoordinate[providerInputAdmissionResourceKindBody+"\x00"+stableCoordinate]
		carrierResource, carrierOK := byKindAndCoordinate[providerInputAdmissionResourceKindCarrier+"\x00"+stableCoordinate]
		body, loadedBody := evidence.Bodies[metadata.ContentSHA256]
		if !bodyOK || !carrierOK || !loadedBody || bodyResource.ContentSHA256 != metadata.ContentSHA256 || bodyResource.ContentBytes != metadata.ContentBytes || int64(len(body.Bytes)) != metadata.ContentBytes || sha256Hex(body.Bytes) != metadata.ContentSHA256 {
			return fmt.Errorf("evidence coordinate ref=%q url=%q is not exactly bound to its decoded-body admission resource", coordinate.Ref, coordinate.URL)
		}
		if carrierResource.DecodedContentSHA256 != bodyResource.ContentSHA256 || carrierResource.DecodedContentBytes != bodyResource.ContentBytes {
			return fmt.Errorf("evidence coordinate ref=%q url=%q carrier admission does not bind the exact decoded body", coordinate.Ref, coordinate.URL)
		}
	}
	return nil
}

func validateDependencyInputAdmissionBinding(dependencies map[string]artifactInput, proof providerInputAdmissionProof, resources []providerInputAdmissionResourceReceipt) error {
	resourceByReceipt := map[string]providerInputAdmissionResourceReceipt{}
	dependencyResourceCount := 0
	for _, resource := range resources {
		resourceByReceipt[resource.ResourceReceiptSHA256] = resource
		if resource.ResourceKind == providerInputAdmissionResourceKindArtifact {
			dependencyResourceCount++
		}
	}
	if dependencyResourceCount != len(dependencies) {
		return fmt.Errorf("dependency input admission resource roster has %d resources, want exactly %d artifacts", dependencyResourceCount, len(dependencies))
	}
	for _, digest := range sortedProviderStringMapKeys(dependencies) {
		artifact := dependencies[digest]
		resource := artifact.InputAdmissionResource
		if artifact.InputAdmissionProofSHA256 != proof.ProofSHA256 || resource.ResourceKind != providerInputAdmissionResourceKindArtifact || resource.ContentSHA256 != digest || resource.ContentBytes != int64(len(artifact.Raw)) || sha256Hex(artifact.Raw) != digest {
			return fmt.Errorf("dependency artifact %s is not exactly bound to its provider input admission resource", digest)
		}
		if resourceByReceipt[resource.ResourceReceiptSHA256].ResourceReceiptSHA256 != resource.ResourceReceiptSHA256 {
			return fmt.Errorf("dependency artifact %s admission resource is absent from the sealed resource roster", digest)
		}
	}
	return nil
}

func providerInputAdmissionResourceSetRoot(resources []providerInputAdmissionResourceReceipt) (string, error) {
	digests := make([]string, 0, len(resources))
	for _, resource := range resources {
		sealed, err := sealProviderInputAdmissionResource(resource)
		if err != nil {
			return "", err
		}
		if resource.ResourceReceiptSHA256 != sealed.ResourceReceiptSHA256 {
			return "", fmt.Errorf("provider input resource %q has an invalid receipt digest", resource.StableCoordinate)
		}
		digests = append(digests, resource.ResourceReceiptSHA256)
	}
	sort.Strings(digests)
	identity := struct {
		Kind                  string   `json:"kind"`
		ResourceReceiptSHA256 []string `json:"resource_receipt_sha256"`
	}{Kind: "provider_documentation_corpus_input_resource_set_v1", ResourceReceiptSHA256: digests}
	canonical, err := canonicalProviderInputAdmissionJSON(identity)
	if err != nil {
		return "", err
	}
	return sha256Hex(canonical), nil
}

func canonicalProviderInputAdmissionProofIdentity(proof providerInputAdmissionProof) ([]byte, error) {
	proof.ProofSHA256 = ""
	return canonicalProviderInputAdmissionJSON(proof)
}

func canonicalProviderInputAdmissionJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalizeCandidateJSON(raw)
}

type boundedProviderInputFile struct {
	Bytes    []byte
	SHA256   string
	Size     int64
	Resource providerInputAdmissionResourceReceipt
}

func (accumulator *providerInputAdmissionAccumulator) ensurePhysicalSnapshotIndex() {
	if accumulator.physicalSnapshots == nil {
		accumulator.physicalSnapshots = map[string]*providerInputPhysicalSnapshot{}
	}
	if accumulator.residentContent == nil {
		accumulator.residentContent = map[providerInputContentKey][]byte{}
	}
}

func (accumulator *providerInputAdmissionAccumulator) enableFactorySnapshotAliases() {
	accumulator.factoryAliasMode = true
	if accumulator.authorizedAliases == nil {
		accumulator.authorizedAliases = map[string]map[string]struct{}{}
	}
}

func (accumulator *providerInputAdmissionAccumulator) authorizeFactorySnapshotAlias(path, label, resourceKind string) error {
	if accumulator == nil || !accumulator.factoryAliasMode {
		return fmt.Errorf("factory physical snapshot alias mode is not enabled")
	}
	inspectedPath, _, err := inspectPathWithoutLinks(path, label)
	if err != nil {
		return err
	}
	key := canonicalProviderInputPathKey(inspectedPath)
	if accumulator.physicalSnapshots[key] == nil {
		return fmt.Errorf("%s path %q has no admitted factory physical snapshot", label, path)
	}
	if accumulator.authorizedAliases[key] == nil {
		accumulator.authorizedAliases[key] = map[string]struct{}{}
	}
	accumulator.authorizedAliases[key][resourceKind] = struct{}{}
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) factorySnapshotAliasAuthorized(pathKey, resourceKind string) bool {
	if !accumulator.factoryAliasMode {
		return false
	}
	_, allowed := accumulator.authorizedAliases[pathKey][resourceKind]
	return allowed
}

func (accumulator *providerInputAdmissionAccumulator) checkResidentInputBytes(additional int64) error {
	if additional < 0 || accumulator.residentInputBytes < 0 || accumulator.residentInputBytes > accumulator.limits.ResidentSnapshotBytes || additional > accumulator.limits.ResidentSnapshotBytes-accumulator.residentInputBytes {
		return fmt.Errorf("provider input retained snapshot bytes would exceed limit %d", accumulator.limits.ResidentSnapshotBytes)
	}
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) retainResidentInputBytes(additional int64) error {
	if err := accumulator.checkResidentInputBytes(additional); err != nil {
		return err
	}
	accumulator.residentInputBytes += additional
	if accumulator.residentInputBytes > accumulator.residentInputPeak {
		accumulator.residentInputPeak = accumulator.residentInputBytes
	}
	accumulator.actuals.ResidentSnapshotBytes = accumulator.residentInputBytes
	accumulator.actuals.PeakResidentSnapshotBytes = accumulator.residentInputPeak
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) physicalSnapshot(
	path, label, hookResourceKind string,
	preRead func(int64) error,
) (*providerInputPhysicalSnapshot, error) {
	if accumulator == nil {
		return nil, fmt.Errorf("provider input admission accumulator is nil")
	}
	inspectedPath, inspectedInfo, err := inspectPathWithoutLinks(path, label)
	if err != nil {
		return nil, err
	}
	if !inspectedInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%s %q is not a regular file", label, path)
	}
	if preRead != nil {
		if err := preRead(inspectedInfo.Size()); err != nil {
			return nil, err
		}
	}
	key := canonicalProviderInputPathKey(inspectedPath)
	accumulator.ensurePhysicalSnapshotIndex()
	if snapshot := accumulator.physicalSnapshots[key]; snapshot != nil {
		if !accumulator.factorySnapshotAliasAuthorized(key, hookResourceKind) {
			return nil, fmt.Errorf("provider input admission rejects duplicate path or file identity %q", inspectedPath)
		}
		if !snapshot.retainsBytes {
			return nil, fmt.Errorf("provider input admission refuses a second payload read for streamed input %q", inspectedPath)
		}
		if err := validateProviderInputPhysicalSnapshotPath(snapshot, label, false); err != nil {
			return nil, err
		}
		return snapshot, nil
	}
	if err := accumulator.rejectDuplicatePathIdentity(inspectedPath, inspectedInfo); err != nil {
		return nil, err
	}
	if err := accumulator.checkResidentInputBytes(inspectedInfo.Size()); err != nil {
		return nil, fmt.Errorf("%s %q: %w", label, path, err)
	}
	if accumulator.beforeStableOpen != nil {
		if err := accumulator.beforeStableOpen(hookResourceKind, inspectedPath); err != nil {
			return nil, err
		}
	}
	file, err := openStableProviderInput(inspectedPath, label)
	if err != nil {
		return nil, fmt.Errorf("open %s %q: %w", label, path, err)
	}
	keepSnapshot := false
	defer func() {
		if !keepSnapshot {
			_ = file.Close()
		}
	}()
	if accumulator.afterOpenBeforeStat != nil {
		if err := accumulator.afterOpenBeforeStat(hookResourceKind, inspectedPath); err != nil {
			return nil, err
		}
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened %s %q: %w", label, path, err)
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%s %q is not a regular file", label, path)
	}
	// The opened handle is authoritative for allocation. The path-level size
	// check is only an early refusal; repeat every bound after the open/stat
	// window so same-inode growth cannot reach allocation or payload reads.
	if preRead != nil {
		if err := preRead(openedInfo.Size()); err != nil {
			return nil, err
		}
	}
	if err := accumulator.checkResidentInputBytes(openedInfo.Size()); err != nil {
		return nil, fmt.Errorf("%s %q: %w", label, path, err)
	}
	mutationToken, err := currentProviderInputMutationToken(file)
	if err != nil {
		return nil, fmt.Errorf("capture %s %q mutation token: %w", label, path, err)
	}
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return nil, fmt.Errorf("derive stable provider input file identity for %q: %w", inspectedPath, err)
	}
	if inspectedInfo.Size() != openedInfo.Size() || !inspectedInfo.ModTime().Equal(openedInfo.ModTime()) {
		return nil, fmt.Errorf("%s %q changed metadata before open", label, path)
	}
	if err := accumulator.rejectDuplicateOpenFileIdentity(inspectedPath, file); err != nil {
		return nil, err
	}
	if accumulator.afterOpenStat != nil {
		if err := accumulator.afterOpenStat(hookResourceKind, inspectedPath); err != nil {
			return nil, err
		}
	}
	currentIdentity, _, err := stableProviderInputPathIdentity(inspectedPath, label)
	if err != nil {
		return nil, fmt.Errorf("reinspect %s path %q after open: %w", label, path, err)
	}
	if currentIdentity != identity {
		return nil, fmt.Errorf("%s %q changed identity during validation", label, path)
	}
	length, err := safeProviderInputAllocationLength(openedInfo.Size())
	if err != nil {
		return nil, fmt.Errorf("%s %q: %w", label, path, err)
	}
	raw := make([]byte, length)
	observedRead := newHashingCountingReader(file)
	if _, err := io.ReadFull(observedRead, raw); err != nil {
		return nil, fmt.Errorf("read exact %s %q: %w", label, path, err)
	}
	var extra [1]byte
	if count, err := observedRead.Read(extra[:]); err != io.EOF || count != 0 {
		if err == nil {
			err = fmt.Errorf("file grew after its size was inspected")
		}
		return nil, fmt.Errorf("read exact %s %q: %w", label, path, err)
	}
	if err := validateStableOpenedFile(file, openedInfo, inspectedPath, label); err != nil {
		return nil, err
	}
	digest := observedRead.sha256()
	if observedRead.count != openedInfo.Size() || digest != sha256Hex(raw) {
		return nil, fmt.Errorf("%s %q physical payload observation differs from its retained exact bytes", label, path)
	}
	if err := validateProviderInputReadSnapshot(file, mutationToken, label); err != nil {
		return nil, err
	}
	if err := accumulator.addPathIdentity(inspectedPath, file); err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close exact %s %q snapshot: %w", label, path, err)
	}
	keepSnapshot = true
	snapshot := &providerInputPhysicalSnapshot{
		path:                  inspectedPath,
		pathKey:               key,
		bytes:                 raw,
		digest:                digest,
		size:                  openedInfo.Size(),
		openedInfo:            openedInfo,
		fileIdentity:          identity,
		mutationToken:         mutationToken,
		retainsBytes:          true,
		initialTraversalCount: observedRead.passes,
		initialTraversalBytes: observedRead.count,
	}
	contentKey := providerInputContentKey{digest: snapshot.digest, size: snapshot.size}
	if prior, exists := accumulator.residentContent[contentKey]; exists {
		if !equalProviderInputBytes(prior, snapshot.bytes) {
			return nil, fmt.Errorf("%s %q collides with an unequal retained content identity", label, path)
		}
	}
	if err := accumulator.retainResidentInputBytes(snapshot.size); err != nil {
		return nil, fmt.Errorf("retain exact %s %q snapshot: %w", label, path, err)
	}
	accumulator.physicalSnapshots[key] = snapshot
	if _, exists := accumulator.residentContent[contentKey]; !exists {
		accumulator.residentContent[contentKey] = snapshot.bytes
	}
	return snapshot, nil
}

func validateProviderInputPhysicalSnapshotPath(snapshot *providerInputPhysicalSnapshot, label string, withMutationToken bool) error {
	if snapshot == nil || snapshot.path == "" || snapshot.pathKey == "" || snapshot.openedInfo == nil || snapshot.initialTraversalCount != 1 || snapshot.initialTraversalBytes != snapshot.size || snapshot.size < 0 || !isLowerSHA256(snapshot.digest) || (snapshot.retainsBytes && (int64(len(snapshot.bytes)) != snapshot.size || sha256Hex(snapshot.bytes) != snapshot.digest)) || (!snapshot.retainsBytes && len(snapshot.bytes) != 0) {
		return fmt.Errorf("%s physical input snapshot is incomplete or was mutated in memory", label)
	}
	currentIdentity, currentInfo, err := stableProviderInputPathIdentity(snapshot.path, label)
	if err != nil {
		return fmt.Errorf("revalidate %s snapshot path %q: %w", label, snapshot.path, err)
	}
	if canonicalProviderInputPathKey(snapshot.path) != snapshot.pathKey || currentIdentity != snapshot.fileIdentity || currentInfo.Size() != snapshot.size || !currentInfo.ModTime().Equal(snapshot.openedInfo.ModTime()) {
		return fmt.Errorf("%s %q changed after its exact physical snapshot was read", label, snapshot.path)
	}
	if !withMutationToken {
		return nil
	}
	file, err := openStableProviderInput(snapshot.path, label)
	if err != nil {
		return fmt.Errorf("reopen %s %q for final snapshot validation: %w", label, snapshot.path, err)
	}
	defer file.Close()
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return fmt.Errorf("rederive %s %q stable file identity: %w", label, snapshot.path, err)
	}
	currentToken, err := currentProviderInputMutationToken(file)
	if err != nil {
		return fmt.Errorf("rederive %s %q mutation token: %w", label, snapshot.path, err)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("reinspect %s %q final snapshot handle: %w", label, snapshot.path, err)
	}
	if identity != snapshot.fileIdentity || currentToken != snapshot.mutationToken || openedInfo.Size() != snapshot.size || !openedInfo.ModTime().Equal(snapshot.openedInfo.ModTime()) {
		return fmt.Errorf("%s %q changed after its exact physical snapshot was read", label, snapshot.path)
	}
	observedRead := newHashingCountingReader(file)
	if _, err := io.CopyN(io.Discard, observedRead, snapshot.size); err != nil {
		return fmt.Errorf("%s %q changed after its exact physical snapshot was read: rehash exact bytes: %w", label, snapshot.path, err)
	}
	var extra [1]byte
	if count, err := observedRead.Read(extra[:]); err != io.EOF || count != 0 {
		if err == nil {
			err = fmt.Errorf("file grew after its exact physical snapshot was read")
		}
		return fmt.Errorf("%s %q changed after its exact physical snapshot was read: %w", label, snapshot.path, err)
	}
	if observedRead.count != snapshot.size || observedRead.sha256() != snapshot.digest {
		return fmt.Errorf("%s %q changed after its exact physical snapshot was read", label, snapshot.path)
	}
	if err := validateProviderInputReadSnapshot(file, currentToken, label); err != nil {
		return fmt.Errorf("%s %q changed after its exact physical snapshot was read: %w", label, snapshot.path, err)
	}
	if err := validateStableOpenedFile(file, openedInfo, snapshot.path, label); err != nil {
		return fmt.Errorf("%s %q changed after its exact physical snapshot was read: %w", label, snapshot.path, err)
	}
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) registerStreamedPhysicalSnapshot(path, label, digest string, size int64, openedInfo os.FileInfo, mutationToken providerInputMutationToken, file *os.File, initialTraversalCount int, initialTraversalBytes int64) error {
	key := canonicalProviderInputPathKey(path)
	accumulator.ensurePhysicalSnapshotIndex()
	if accumulator.physicalSnapshots[key] != nil {
		return fmt.Errorf("provider input admission rejects duplicate path or file identity %q", path)
	}
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return fmt.Errorf("derive stable streamed %s file identity for %q: %w", label, path, err)
	}
	if err := accumulator.addPathIdentity(path, file); err != nil {
		return err
	}
	accumulator.physicalSnapshots[key] = &providerInputPhysicalSnapshot{
		path:                  path,
		pathKey:               key,
		digest:                digest,
		size:                  size,
		openedInfo:            openedInfo,
		fileIdentity:          identity,
		mutationToken:         mutationToken,
		retainsBytes:          false,
		initialTraversalCount: initialTraversalCount,
		initialTraversalBytes: initialTraversalBytes,
	}
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) revalidatePhysicalSnapshots() error {
	if accumulator == nil {
		return fmt.Errorf("provider input admission accumulator is nil")
	}
	keys := make([]string, 0, len(accumulator.physicalSnapshots))
	for key := range accumulator.physicalSnapshots {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := validateProviderInputPhysicalSnapshotPath(accumulator.physicalSnapshots[key], "provider input", true); err != nil {
			return err
		}
	}
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) physicalSnapshotBytesByContent(digest string, size int64) []byte {
	return accumulator.residentContent[providerInputContentKey{digest: digest, size: size}]
}

func equalProviderInputBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (accumulator *providerInputAdmissionAccumulator) orderedResources() []providerInputAdmissionResourceReceipt {
	ordered := append([]providerInputAdmissionResourceReceipt(nil), accumulator.resources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ResourceReceiptSHA256 < ordered[j].ResourceReceiptSHA256 })
	return ordered
}

func readBoundedProviderInputFile(path, label, resourceKind, stableCoordinate string, accumulator *providerInputAdmissionAccumulator) (boundedProviderInputFile, error) {
	if accumulator == nil {
		return boundedProviderInputFile{}, fmt.Errorf("provider input admission accumulator is nil")
	}
	snapshot, err := accumulator.physicalSnapshot(path, label, resourceKind, func(size int64) error {
		if err := accumulator.checkReservation(resourceKind, size); err != nil {
			return fmt.Errorf("%s %q: %w", label, path, err)
		}
		return nil
	})
	if err != nil {
		return boundedProviderInputFile{}, err
	}
	if err := accumulator.reserve(resourceKind, snapshot.size); err != nil {
		return boundedProviderInputFile{}, fmt.Errorf("%s %q: %w", label, path, err)
	}
	if stableCoordinate == "" {
		stableCoordinate = resourceKind + "|sha256:" + snapshot.digest
	}
	resource, err := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{
		ResourceKind:     resourceKind,
		StableCoordinate: stableCoordinate,
		ContentSHA256:    snapshot.digest,
		ContentBytes:     snapshot.size,
	})
	if err != nil {
		return boundedProviderInputFile{}, err
	}
	if err := accumulator.addResource(resource); err != nil {
		return boundedProviderInputFile{}, err
	}
	return boundedProviderInputFile{Bytes: snapshot.bytes, SHA256: snapshot.digest, Size: snapshot.size, Resource: resource}, nil
}

func openStableRelativeEvidenceStagingFile(manifestPath, declared string, beforeOpen func(path string) error) (*os.File, os.FileInfo, providerInputMutationToken, string, error) {
	resolvedTarget, err := resolveRelativeEvidenceStagingPath(manifestPath, declared)
	if err != nil {
		return nil, nil, providerInputMutationToken{}, "", err
	}
	if beforeOpen != nil {
		if err := beforeOpen(resolvedTarget); err != nil {
			return nil, nil, providerInputMutationToken{}, "", err
		}
	}
	file, err := openStableProviderInput(resolvedTarget, "evidence staging_file")
	if err != nil {
		return nil, nil, providerInputMutationToken{}, "", fmt.Errorf("open exact staged body %q: %w", resolvedTarget, err)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, providerInputMutationToken{}, "", fmt.Errorf("inspect opened exact staged body %q: %w", resolvedTarget, err)
	}
	if !openedInfo.Mode().IsRegular() {
		file.Close()
		return nil, nil, providerInputMutationToken{}, "", fmt.Errorf("evidence manifest %q staging_file %q is not a regular file", manifestPath, declared)
	}
	mutationToken, err := currentProviderInputMutationToken(file)
	if err != nil {
		file.Close()
		return nil, nil, providerInputMutationToken{}, "", fmt.Errorf("capture exact staged body %q mutation token: %w", resolvedTarget, err)
	}
	openedIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		file.Close()
		return nil, nil, providerInputMutationToken{}, "", fmt.Errorf("derive exact staged body identity %q: %w", resolvedTarget, err)
	}
	pathIdentity, _, err := stableProviderInputPathIdentity(resolvedTarget, "evidence staging_file")
	if err != nil {
		file.Close()
		return nil, nil, providerInputMutationToken{}, "", err
	}
	if openedIdentity != pathIdentity {
		file.Close()
		return nil, nil, providerInputMutationToken{}, "", fmt.Errorf("evidence manifest %q staging_file %q changed identity before open", manifestPath, declared)
	}
	if err := validateRelativeEvidenceStagingPathIdentity(manifestPath, declared, file, openedInfo, false); err != nil {
		file.Close()
		return nil, nil, providerInputMutationToken{}, "", err
	}
	return file, openedInfo, mutationToken, resolvedTarget, nil
}

func validateRelativeEvidenceStagingPathIdentity(manifestPath, declared string, file *os.File, openedInfo os.FileInfo, afterRead bool) error {
	manifestAbs, err := filepath.Abs(manifestPath)
	if err != nil {
		return fmt.Errorf("resolve evidence manifest path %q: %w", manifestPath, err)
	}
	root := filepath.Dir(manifestAbs)
	if _, rootInfo, err := inspectPathWithoutLinks(root, "evidence manifest directory"); err != nil {
		return err
	} else if !rootInfo.IsDir() {
		return fmt.Errorf("evidence manifest directory %q is not a directory", root)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve evidence manifest directory %q after open: %w", root, err)
	}
	declaredTarget := filepath.Clean(filepath.Join(root, filepath.FromSlash(declared)))
	if _, _, err := inspectPathWithoutLinks(declaredTarget, "evidence staging_file"); err != nil {
		return err
	}
	currentTarget, err := filepath.EvalSymlinks(declaredTarget)
	if err != nil {
		return fmt.Errorf("re-resolve evidence staging_file %q after open: %w", declared, err)
	}
	if err := requirePathWithinRoot(resolvedRoot, currentTarget); err != nil {
		return fmt.Errorf("evidence manifest %q staging_file %q was redirected outside its manifest directory after open: %w", manifestPath, declared, err)
	}
	openedIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return fmt.Errorf("derive opened evidence staging_file identity %q: %w", currentTarget, err)
	}
	currentIdentity, _, err := stableProviderInputPathIdentity(currentTarget, "evidence staging_file")
	if err != nil {
		return fmt.Errorf("inspect re-resolved evidence staging_file %q: %w", currentTarget, err)
	}
	if openedIdentity != currentIdentity {
		return fmt.Errorf("evidence manifest %q staging_file %q changed identity during validation", manifestPath, declared)
	}
	if !afterRead {
		return nil
	}
	closedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("reinspect opened exact staged body %q: %w", currentTarget, err)
	}
	closedIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return fmt.Errorf("rederive opened evidence staging_file identity %q: %w", currentTarget, err)
	}
	if openedIdentity != closedIdentity || openedInfo.Size() != closedInfo.Size() || !openedInfo.ModTime().Equal(closedInfo.ModTime()) {
		return fmt.Errorf("evidence manifest %q staging_file %q changed while being read", manifestPath, declared)
	}
	return nil
}

func readBoundedRelativeEvidenceStagingCarrier(manifestPath, declared string, accumulator *providerInputAdmissionAccumulator) ([]byte, string, error) {
	if accumulator == nil {
		return nil, "", fmt.Errorf("provider input admission accumulator is nil")
	}
	resolvedTarget, err := resolveRelativeEvidenceStagingPath(manifestPath, declared)
	if err != nil {
		return nil, "", err
	}
	snapshot, err := accumulator.physicalSnapshot(resolvedTarget, "evidence staging_file", providerInputAdmissionResourceKindCarrier, func(size int64) error {
		if size > accumulator.limits.EvidenceCarrierBytesPerFile {
			return fmt.Errorf("exact staged body %q byte length %d exceeds per-file limit %d", resolvedTarget, size, accumulator.limits.EvidenceCarrierBytesPerFile)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	resolvedAfter, err := resolveRelativeEvidenceStagingPath(manifestPath, declared)
	if err != nil || canonicalProviderInputPathKey(resolvedAfter) != snapshot.pathKey {
		return nil, "", fmt.Errorf("evidence staging_file %q changed identity while being read", declared)
	}
	return snapshot.bytes, resolvedTarget, nil
}

func decodeBoundedRelativeEvidenceStagingFile(manifestPath, manifestSHA256, declared string, sourceCoordinate evidenceSourceCoordinate, expectedDecodedBytes int64, expectedDecodedSHA256 string, accumulator *providerInputAdmissionAccumulator) ([]byte, string, error) {
	if expectedDecodedBytes <= 0 || !isLowerSHA256(expectedDecodedSHA256) {
		return nil, "", fmt.Errorf("exact staged evidence body has an invalid declared byte count/hash tuple")
	}
	if accumulator == nil {
		return nil, "", fmt.Errorf("provider input admission accumulator is nil")
	}
	if !isLowerSHA256(manifestSHA256) || !canonicalEvidenceSourceRef(sourceCoordinate.Ref) || !canonicalEvidenceSourceURL(sourceCoordinate.URL) {
		return nil, "", fmt.Errorf("exact staged evidence body has an invalid manifest/source coordinate")
	}
	if err := accumulator.checkReservation(providerInputAdmissionResourceKindBody, expectedDecodedBytes); err != nil {
		return nil, "", fmt.Errorf("declared decoded staged evidence body: %w", err)
	}
	encodedPayloadBytes, err := expectedPaddedBase64Bytes(expectedDecodedBytes)
	if err != nil {
		return nil, "", err
	}
	if encodedPayloadBytes > accumulator.limits.EvidenceCarrierBytesPerFile-accumulator.limits.EvidenceCarrierOuterWhitespace {
		return nil, "", fmt.Errorf("declared evidence body byte length %d cannot fit the bounded canonical base64 carrier", expectedDecodedBytes)
	}
	resolvedTarget, err := resolveRelativeEvidenceStagingPath(manifestPath, declared)
	if err != nil {
		return nil, "", err
	}
	file, openedInfo, mutationToken, openedPath, err := openStableRelativeEvidenceStagingFile(manifestPath, declared, func(path string) error {
		if accumulator.beforeStableOpen == nil {
			return nil
		}
		return accumulator.beforeStableOpen(providerInputAdmissionResourceKindCarrier, path)
	})
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	if canonicalProviderInputPathKey(openedPath) != canonicalProviderInputPathKey(resolvedTarget) {
		return nil, "", fmt.Errorf("evidence staging_file %q changed identity before streaming", declared)
	}
	if err := accumulator.rejectDuplicatePathIdentity(openedPath, openedInfo); err != nil {
		return nil, "", err
	}
	if err := accumulator.rejectDuplicateOpenFileIdentity(openedPath, file); err != nil {
		return nil, "", err
	}
	if openedInfo.Size() > encodedPayloadBytes+accumulator.limits.EvidenceCarrierOuterWhitespace {
		return nil, "", fmt.Errorf("base64 staged evidence carrier %q byte length %d exceeds exact payload length %d plus outer-whitespace limit %d", openedPath, openedInfo.Size(), encodedPayloadBytes, accumulator.limits.EvidenceCarrierOuterWhitespace)
	}
	if err := accumulator.checkReservation(providerInputAdmissionResourceKindCarrier, openedInfo.Size()); err != nil {
		return nil, "", fmt.Errorf("base64 staged evidence carrier %q: %w", openedPath, err)
	}
	if accumulator.afterOpenStat != nil {
		if err := accumulator.afterOpenStat(providerInputAdmissionResourceKindCarrier, openedPath); err != nil {
			return nil, "", err
		}
	}
	if err := validateRelativeEvidenceStagingPathIdentity(manifestPath, declared, file, openedInfo, false); err != nil {
		return nil, "", err
	}
	if err := accumulator.reserve(providerInputAdmissionResourceKindCarrier, openedInfo.Size()); err != nil {
		return nil, "", fmt.Errorf("base64 staged evidence carrier %q: %w", openedPath, err)
	}
	if err := accumulator.reserve(providerInputAdmissionResourceKindBody, expectedDecodedBytes); err != nil {
		return nil, "", fmt.Errorf("decoded staged evidence body %q: %w", resolvedTarget, err)
	}
	// The opened size is the hard physical-read boundary. A same-inode append
	// after the authoritative fstat may contribute at most one diagnostic byte;
	// it can never turn the trailing-whitespace drain into an unbounded read.
	encodedReader := newHashingCountingReader(io.LimitReader(file, openedInfo.Size()+1))
	trimmedReader := newStrictTrimmedBase64Reader(encodedReader)
	decodedHasher := sha256.New()
	decoder := base64.NewDecoder(base64.StdEncoding.Strict(), trimmedReader)
	decodedReader := io.TeeReader(decoder, decodedHasher)
	body := accumulator.physicalSnapshotBytesByContent(expectedDecodedSHA256, expectedDecodedBytes)
	retainsDerivedBody := false
	if body == nil {
		if err := accumulator.checkResidentInputBytes(expectedDecodedBytes); err != nil {
			return nil, "", fmt.Errorf("decoded staged evidence body %q: %w", resolvedTarget, err)
		}
		decodedLength, err := safeProviderInputAllocationLength(expectedDecodedBytes)
		if err != nil {
			return nil, "", err
		}
		body = make([]byte, decodedLength)
		if _, err := io.ReadFull(decodedReader, body); err != nil {
			return nil, "", fmt.Errorf("decode exact staged body %q: %w", resolvedTarget, err)
		}
		retainsDerivedBody = true
	} else {
		written, err := io.CopyN(io.Discard, decodedReader, expectedDecodedBytes)
		if err != nil || written != expectedDecodedBytes {
			return nil, "", fmt.Errorf("decode exact staged body %q: copied %d of %d: %w", resolvedTarget, written, expectedDecodedBytes, err)
		}
	}
	var extraDecoded [1]byte
	if count, err := decodedReader.Read(extraDecoded[:]); err != io.EOF || count != 0 {
		if err == nil {
			err = fmt.Errorf("decoded body exceeds declared byte length %d", expectedDecodedBytes)
		}
		return nil, "", fmt.Errorf("decode exact staged body %q: %w", resolvedTarget, err)
	}
	// A base64 decoder may finish at padding before requesting trailing bytes.
	// Drain the validating filter so trailing whitespace is bounded and any
	// non-whitespace byte after padding is rejected rather than ignored.
	if _, err := io.Copy(io.Discard, trimmedReader); err != nil {
		return nil, "", fmt.Errorf("validate exact staged body carrier %q: %w", resolvedTarget, err)
	}
	if encodedReader.count != openedInfo.Size() {
		return nil, "", fmt.Errorf("base64 staged evidence carrier %q read %d bytes, want exact file size %d", openedPath, encodedReader.count, openedInfo.Size())
	}
	if err := validateRelativeEvidenceStagingPathIdentity(manifestPath, declared, file, openedInfo, true); err != nil {
		return nil, "", err
	}
	decodedDigest := hex.EncodeToString(decodedHasher.Sum(nil))
	if decodedDigest != expectedDecodedSHA256 {
		return nil, "", fmt.Errorf("exact staged body %q does not match manifest digest", resolvedTarget)
	}
	finalMutationToken, err := currentProviderInputMutationToken(file)
	if err != nil {
		return nil, "", fmt.Errorf("reinspect base64 evidence staging_file mutation token: %w", err)
	}
	if finalMutationToken != mutationToken {
		return nil, "", fmt.Errorf("base64 evidence staging_file changed during its one-pass physical snapshot read")
	}
	stableCoordinate := "evidence_body_v1|" + lengthPrefixedIdentityKey(manifestSHA256, sourceCoordinate.Ref, sourceCoordinate.URL)
	carrierResource := providerInputAdmissionResourceReceipt{
		ResourceKind:         providerInputAdmissionResourceKindCarrier,
		StableCoordinate:     stableCoordinate,
		ContentSHA256:        encodedReader.sha256(),
		ContentBytes:         encodedReader.count,
		DecodedContentSHA256: decodedDigest,
		DecodedContentBytes:  expectedDecodedBytes,
	}
	if err := accumulator.addResource(carrierResource); err != nil {
		return nil, "", err
	}
	if err := accumulator.addResource(providerInputAdmissionResourceReceipt{
		ResourceKind:     providerInputAdmissionResourceKindBody,
		StableCoordinate: stableCoordinate,
		ContentSHA256:    decodedDigest,
		ContentBytes:     expectedDecodedBytes,
	}); err != nil {
		return nil, "", err
	}
	if err := accumulator.registerStreamedPhysicalSnapshot(openedPath, "base64 evidence staging_file", encodedReader.sha256(), openedInfo.Size(), openedInfo, mutationToken, file, encodedReader.passes, encodedReader.count); err != nil {
		return nil, "", err
	}
	if retainsDerivedBody {
		contentKey := providerInputContentKey{digest: decodedDigest, size: expectedDecodedBytes}
		if prior, exists := accumulator.residentContent[contentKey]; exists {
			if !equalProviderInputBytes(prior, body) {
				return nil, "", fmt.Errorf("decoded staged evidence body collides with unequal retained bytes")
			}
		} else {
			if err := accumulator.retainResidentInputBytes(expectedDecodedBytes); err != nil {
				return nil, "", fmt.Errorf("retain decoded staged evidence body: %w", err)
			}
			accumulator.residentContent[contentKey] = body
		}
	}
	return body, openedPath, nil
}

func validateStableOpenedFile(file *os.File, openedInfo os.FileInfo, path, label string) error {
	openedIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return fmt.Errorf("derive opened %s identity %q: %w", label, path, err)
	}
	closedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("reinspect opened %s %q: %w", label, path, err)
	}
	closedIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return fmt.Errorf("rederive opened %s identity %q: %w", label, path, err)
	}
	if openedIdentity != closedIdentity || openedInfo.Size() != closedInfo.Size() || !openedInfo.ModTime().Equal(closedInfo.ModTime()) {
		return fmt.Errorf("%s %q changed while being read", label, path)
	}
	currentIdentity, currentInfo, err := stableProviderInputPathIdentity(path, label)
	if err != nil {
		return fmt.Errorf("reinspect %s path %q after read: %w", label, path, err)
	}
	if openedIdentity != currentIdentity || openedInfo.Size() != currentInfo.Size() || !openedInfo.ModTime().Equal(currentInfo.ModTime()) {
		return fmt.Errorf("%s %q changed identity while being read", label, path)
	}
	return nil
}

func openStableProviderInput(path, label string) (*os.File, error) {
	file, err := openProviderInputPathNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("open %s %q without following links or replacement parents: %w", label, path, err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || fileInfoHasReparsePoint(info) {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("inspect opened %s %q: %w", label, path, err)
		}
		return nil, fmt.Errorf("%s %q is not a stable regular file", label, path)
	}
	return file, nil
}

func validateProviderInputReadSnapshot(file *os.File, initial providerInputMutationToken, label string) error {
	afterRead, err := currentProviderInputMutationToken(file)
	if err != nil {
		return fmt.Errorf("reinspect %s mutation token: %w", label, err)
	}
	if afterRead != initial {
		return fmt.Errorf("%s changed while being read (mutation token)", label)
	}
	return nil
}

func safeProviderInputAllocationLength(size int64) (int, error) {
	if size < 0 || uint64(size) > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("byte length %d cannot be represented as an in-memory allocation", size)
	}
	return int(size), nil
}

type hashingCountingReader struct {
	reader io.Reader
	hash   hash.Hash
	count  int64
	passes int
}

func newHashingCountingReader(reader io.Reader) *hashingCountingReader {
	return &hashingCountingReader{reader: reader, hash: sha256.New()}
}

func (reader *hashingCountingReader) Read(target []byte) (int, error) {
	if reader.passes == 0 {
		reader.passes = 1
	}
	count, err := reader.reader.Read(target)
	if count > 0 {
		_, _ = reader.hash.Write(target[:count])
		reader.count += int64(count)
	}
	return count, err
}

func (reader *hashingCountingReader) sha256() string {
	return hex.EncodeToString(reader.hash.Sum(nil))
}

type strictTrimmedBase64Reader struct {
	reader   *bufio.Reader
	started  bool
	trailing bool
}

func newStrictTrimmedBase64Reader(reader io.Reader) *strictTrimmedBase64Reader {
	return &strictTrimmedBase64Reader{reader: bufio.NewReaderSize(reader, 64*1024)}
}

func (reader *strictTrimmedBase64Reader) Read(target []byte) (int, error) {
	if len(target) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(target) {
		value, err := reader.reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && written > 0 {
				return written, nil
			}
			return written, err
		}
		if isProviderInputASCIIWhitespace(value) {
			if reader.started {
				reader.trailing = true
			}
			continue
		}
		if value >= 0x80 {
			return written, fmt.Errorf("base64 carrier contains invalid UTF-8/non-ASCII byte 0x%02x", value)
		}
		if !isStandardBase64Byte(value) {
			return written, fmt.Errorf("base64 carrier contains noncanonical byte 0x%02x", value)
		}
		if reader.trailing {
			return written, fmt.Errorf("base64 carrier contains internal whitespace")
		}
		reader.started = true
		target[written] = value
		written++
	}
	return written, nil
}

func isProviderInputASCIIWhitespace(value byte) bool {
	switch value {
	case ' ', '\t', '\r', '\n', '\v', '\f':
		return true
	default:
		return false
	}
}

func isStandardBase64Byte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '+' || value == '/' || value == '='
}

func expectedPaddedBase64Bytes(decodedBytes int64) (int64, error) {
	length, err := safeProviderInputAllocationLength(decodedBytes)
	if err != nil {
		return 0, err
	}
	return int64(base64.StdEncoding.EncodedLen(length)), nil
}
