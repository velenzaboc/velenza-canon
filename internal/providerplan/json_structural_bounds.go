package providerplan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

func sortedProviderStringMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedEvidenceSourceCoordinates[T any](values map[evidenceSourceCoordinate]T) []evidenceSourceCoordinate {
	coordinates := make([]evidenceSourceCoordinate, 0, len(values))
	for coordinate := range values {
		coordinates = append(coordinates, coordinate)
	}
	sort.Slice(coordinates, func(i, j int) bool {
		if coordinates[i].Ref != coordinates[j].Ref {
			return coordinates[i].Ref < coordinates[j].Ref
		}
		return coordinates[i].URL < coordinates[j].URL
	})
	return coordinates
}

const (
	maxProviderJSONNestingDepth         = 64
	maxProviderJSONNodesPerValue        = 131_072
	maxProviderJSONTokensPerValue       = 262_144
	maxProviderJSONStringBytesPerValue  = int64(32 << 20)
	maxProviderJSONDecodedBytesPerValue = int64(64 << 20)
	maxProviderJSONRowsPerArtifact      = int64(262_144)
	maxProviderJSONRowsPerCorpus        = int64(1_048_576)
	maxProviderJSONNodesPerArtifact     = int64(1_048_576)
	maxProviderJSONNodesPerCorpus       = int64(4_194_304)
	maxProviderJSONTokensPerArtifact    = int64(2_097_152)
	maxProviderJSONTokensPerCorpus      = int64(8_388_608)
	maxProviderJSONStringBytesArtifact  = int64(64 << 20)
	maxProviderJSONStringBytesCorpus    = int64(512 << 20)
	maxProviderJSONDecodedBytesArtifact = int64(128 << 20)
	maxProviderJSONDecodedBytesCorpus   = int64(768 << 20)
)

type providerJSONStructure struct {
	Tokens       int64
	Nodes        int64
	StringBytes  int64
	DecodedBytes int64
}

type providerJSONArtifactStructure struct {
	Rows int64
	providerJSONStructure
}

func (accumulator *providerInputAdmissionAccumulator) beginStructuredJSONPhysicalInput(path, label string, raw []byte) (string, bool, error) {
	if accumulator == nil {
		return "", false, fmt.Errorf("provider structured JSON admission state is nil")
	}
	inspectedPath, _, err := inspectPathWithoutLinks(path, label)
	if err != nil {
		return "", false, err
	}
	key := canonicalProviderInputPathKey(inspectedPath)
	snapshot := accumulator.physicalSnapshots[key]
	if snapshot == nil || !snapshot.retainsBytes || snapshot.size != int64(len(raw)) || snapshot.digest != sha256Hex(raw) {
		return "", false, fmt.Errorf("%s does not bind one retained physical snapshot before structured JSON admission", label)
	}
	if accumulator.structuredJSONPaths == nil {
		accumulator.structuredJSONPaths = map[string]struct{}{}
	}
	if _, admitted := accumulator.structuredJSONPaths[key]; admitted {
		return key, false, nil
	}
	return key, true, nil
}

func (accumulator *providerInputAdmissionAccumulator) finishStructuredJSONPhysicalInput(key string) {
	accumulator.structuredJSONPaths[key] = struct{}{}
}

func (accumulator *providerInputAdmissionAccumulator) admitStructuredJSONDocument(path, label, resourceKind string, raw []byte) error {
	structure, err := validateProviderJSONStructure(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return accumulator.admitStructuredJSONDocumentStructure(path, label, resourceKind, raw, structure)
}

func (accumulator *providerInputAdmissionAccumulator) admitStructuredJSONDocumentStructure(path, label, resourceKind string, raw []byte, structure providerJSONStructure) error {
	key, charge, err := accumulator.beginStructuredJSONPhysicalInput(path, label, raw)
	if err != nil || !charge {
		return err
	}
	artifact := providerJSONArtifactStructure{}
	if err := accumulator.admitStructuredJSONRow(resourceKind, &artifact, structure); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	accumulator.finishStructuredJSONPhysicalInput(key)
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) admitStructuredJSONLines(path, label, resourceKind string, raw []byte) error {
	key, charge, err := accumulator.beginStructuredJSONPhysicalInput(path, label, raw)
	if err != nil || !charge {
		return err
	}
	artifact := providerJSONArtifactStructure{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	maximum, err := safeProviderInputAllocationLength(maxStageInputFileBytesPerFile)
	if err != nil {
		return err
	}
	scanner.Buffer(make([]byte, 64*1024), maximum)
	lineNumber := 0
	rowCount := 0
	for scanner.Scan() {
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		structure, err := validateProviderJSONStructure(line)
		if err != nil {
			return fmt.Errorf("%s line %d: %w", label, lineNumber, err)
		}
		if err := accumulator.admitStructuredJSONRow(resourceKind, &artifact, structure); err != nil {
			return fmt.Errorf("%s line %d: %w", label, lineNumber, err)
		}
		rowCount++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", label, err)
	}
	if rowCount == 0 {
		return fmt.Errorf("%s has no structured JSON rows", label)
	}
	accumulator.finishStructuredJSONPhysicalInput(key)
	return nil
}

func (accumulator *providerInputAdmissionAccumulator) admitStructuredJSONAuto(path, label, resourceKind string, raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	structure, structuralErr := validateProviderJSONStructure(trimmed)
	if structuralErr == nil {
		return accumulator.admitStructuredJSONDocumentStructure(path, label, resourceKind, raw, structure)
	}
	// A syntactically complete JSON scalar or container remains structured input
	// even when it exceeds the structural profile. It must fail closed rather
	// than falling through as an uncharged opaque file.
	if json.Valid(trimmed) {
		return fmt.Errorf("%s: %w", label, structuralErr)
	}
	// A complete roster of individually valid object rows is structured JSONL.
	// File names and extensions never participate in this classification or in
	// the portable actuals sealed by the admission receipt.
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	maximum, err := safeProviderInputAllocationLength(maxStageInputFileBytesPerFile)
	if err != nil {
		return err
	}
	scanner.Buffer(make([]byte, 64*1024), maximum)
	rows := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if len(line) == 0 || line[0] != '{' {
			return nil
		}
		if _, err := validateProviderJSONStructure(line); err != nil {
			return nil
		}
		rows++
	}
	if scanner.Err() != nil || rows == 0 {
		return nil
	}
	return accumulator.admitStructuredJSONLines(path, label, resourceKind, raw)
}

func (accumulator *providerInputAdmissionAccumulator) admitStructuredJSONRow(resourceKind string, artifact *providerJSONArtifactStructure, row providerJSONStructure) error {
	if accumulator == nil || artifact == nil {
		return fmt.Errorf("provider structured JSON admission state is nil")
	}
	if resourceKind != providerInputAdmissionResourceKindManifest && resourceKind != providerInputAdmissionResourceKindArtifact && resourceKind != providerInputAdmissionResourceKindAuthority && resourceKind != providerInputAdmissionResourceKindStageManifest && resourceKind != providerInputAdmissionResourceKindStageFile {
		return fmt.Errorf("provider structured JSON resource kind is unsupported")
	}
	if artifact.Rows < 0 || artifact.Nodes < 0 || artifact.Tokens < 0 || artifact.StringBytes < 0 || artifact.DecodedBytes < 0 ||
		accumulator.actuals.StructuredJSONRowCount < 0 || accumulator.actuals.StructuredJSONNodeCount < 0 || accumulator.actuals.StructuredJSONTokenCount < 0 || accumulator.actuals.StructuredJSONStringBytes < 0 || accumulator.actuals.StructuredJSONDecodedBytes < 0 ||
		row.Nodes < 0 || row.Tokens < 0 || row.StringBytes < 0 || row.DecodedBytes < 0 {
		return fmt.Errorf("provider structured JSON admission accounting is invalid")
	}
	if artifact.Rows >= accumulator.limits.StructuredJSONRowsPerArtifact || accumulator.actuals.StructuredJSONRowCount >= accumulator.limits.StructuredJSONRowsPerCorpus {
		return fmt.Errorf("provider structured JSON row count exceeds fixed artifact/corpus bound")
	}
	if row.Nodes > accumulator.limits.StructuredJSONNodesPerArtifact-artifact.Nodes || row.Nodes > accumulator.limits.StructuredJSONNodesPerCorpus-accumulator.actuals.StructuredJSONNodeCount {
		return fmt.Errorf("provider structured JSON node count exceeds fixed artifact/corpus bound")
	}
	if row.Tokens > accumulator.limits.StructuredJSONTokensPerArtifact-artifact.Tokens || row.Tokens > accumulator.limits.StructuredJSONTokensPerCorpus-accumulator.actuals.StructuredJSONTokenCount {
		return fmt.Errorf("provider structured JSON token count exceeds fixed artifact/corpus bound")
	}
	if row.StringBytes > accumulator.limits.StructuredJSONStringBytesArtifact-artifact.StringBytes || row.StringBytes > accumulator.limits.StructuredJSONStringBytesCorpus-accumulator.actuals.StructuredJSONStringBytes {
		return fmt.Errorf("provider structured JSON string bytes exceed fixed artifact/corpus bound")
	}
	if row.DecodedBytes > accumulator.limits.StructuredJSONDecodedBytesArtifact-artifact.DecodedBytes || row.DecodedBytes > accumulator.limits.StructuredJSONDecodedBytesCorpus-accumulator.actuals.StructuredJSONDecodedBytes {
		return fmt.Errorf("provider structured JSON decoded bytes exceed fixed artifact/corpus bound")
	}
	artifact.Rows++
	artifact.Nodes += row.Nodes
	artifact.Tokens += row.Tokens
	artifact.StringBytes += row.StringBytes
	artifact.DecodedBytes += row.DecodedBytes
	accumulator.actuals.StructuredJSONRowCount++
	accumulator.actuals.StructuredJSONNodeCount += row.Nodes
	accumulator.actuals.StructuredJSONTokenCount += row.Tokens
	accumulator.actuals.StructuredJSONStringBytes += row.StringBytes
	accumulator.actuals.StructuredJSONDecodedBytes += row.DecodedBytes
	return nil
}

type providerJSONContainerFrame struct {
	delimiter        json.Delim
	objectExpectsKey bool
	seenKeys         map[string]struct{}
}

// validateProviderJSONStructure is the common preflight for every recursive
// or materializing JSON consumer. It is iterative, rejects duplicate keys, and
// freezes depth/node/token bounds before json.Unmarshal or semantic recursion.
func validateProviderJSONStructure(raw []byte) (providerJSONStructure, error) {
	if err := rejectInvalidJSONUnicodeScalars(raw); err != nil {
		return providerJSONStructure{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	structure, err := consumeJSONValueBounded(decoder)
	if err != nil {
		return structure, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return structure, fmt.Errorf("trailing JSON token %v", token)
		}
		return structure, err
	}
	return structure, nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	_, err := consumeJSONValueBounded(decoder)
	return err
}

func consumeJSONValueBounded(decoder *json.Decoder) (providerJSONStructure, error) {
	frames := make([]providerJSONContainerFrame, 0, maxProviderJSONNestingDepth)
	structure := providerJSONStructure{}
	addDecoded := func(stringBytes, decodedBytes int64) error {
		if stringBytes < 0 || decodedBytes < 0 || stringBytes > maxProviderJSONStringBytesPerValue-structure.StringBytes {
			return fmt.Errorf("JSON value exceeds fixed decoded string-byte limit %d", maxProviderJSONStringBytesPerValue)
		}
		if decodedBytes > maxProviderJSONDecodedBytesPerValue-structure.DecodedBytes {
			return fmt.Errorf("JSON value exceeds fixed decoded scalar-byte limit %d", maxProviderJSONDecodedBytesPerValue)
		}
		structure.StringBytes += stringBytes
		structure.DecodedBytes += decodedBytes
		return nil
	}
	completeContainer := func() bool {
		if len(frames) == 0 {
			return true
		}
		parent := &frames[len(frames)-1]
		if parent.delimiter == '{' {
			parent.objectExpectsKey = true
		}
		return false
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return structure, err
		}
		structure.Tokens++
		if structure.Tokens > maxProviderJSONTokensPerValue {
			return structure, fmt.Errorf("JSON value exceeds fixed token limit %d", maxProviderJSONTokensPerValue)
		}
		switch typed := token.(type) {
		case string:
			if err := addDecoded(int64(len(typed)), int64(len(typed))); err != nil {
				return structure, err
			}
		case json.Number:
			if err := addDecoded(0, int64(len(typed.String()))); err != nil {
				return structure, err
			}
		case bool:
			if err := addDecoded(0, 1); err != nil {
				return structure, err
			}
		}

		if len(frames) != 0 {
			top := &frames[len(frames)-1]
			if top.delimiter == '{' && top.objectExpectsKey {
				if delim, ok := token.(json.Delim); ok && delim == '}' {
					frames = frames[:len(frames)-1]
					if completeContainer() {
						return structure, nil
					}
					continue
				}
				key, ok := token.(string)
				if !ok {
					return structure, fmt.Errorf("object key is not a string")
				}
				if _, duplicate := top.seenKeys[key]; duplicate {
					return structure, fmt.Errorf("duplicate JSON key %q", key)
				}
				top.seenKeys[key] = struct{}{}
				top.objectExpectsKey = false
				continue
			}
		}

		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				structure.Nodes++
				if structure.Nodes > maxProviderJSONNodesPerValue {
					return structure, fmt.Errorf("JSON value exceeds fixed node limit %d", maxProviderJSONNodesPerValue)
				}
				if len(frames) == maxProviderJSONNestingDepth {
					return structure, fmt.Errorf("JSON value exceeds fixed nesting depth %d", maxProviderJSONNestingDepth)
				}
				frame := providerJSONContainerFrame{delimiter: delim}
				if delim == '{' {
					frame.objectExpectsKey = true
					frame.seenKeys = map[string]struct{}{}
				}
				frames = append(frames, frame)
			case ']':
				if len(frames) == 0 || frames[len(frames)-1].delimiter != '[' {
					return structure, fmt.Errorf("array did not terminate")
				}
				frames = frames[:len(frames)-1]
				if completeContainer() {
					return structure, nil
				}
			case '}':
				return structure, fmt.Errorf("object terminated while awaiting a value")
			default:
				return structure, fmt.Errorf("unexpected JSON delimiter %q", delim)
			}
			continue
		}

		structure.Nodes++
		if structure.Nodes > maxProviderJSONNodesPerValue {
			return structure, fmt.Errorf("JSON value exceeds fixed node limit %d", maxProviderJSONNodesPerValue)
		}
		if len(frames) == 0 {
			return structure, nil
		}
		if frames[len(frames)-1].delimiter == '{' {
			frames[len(frames)-1].objectExpectsKey = true
		}
	}
}
