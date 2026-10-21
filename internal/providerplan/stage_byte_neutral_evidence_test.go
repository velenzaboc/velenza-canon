package providerplan

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestStageContractAcceptsByteNeutralExactEvidenceThroughEveryStage(t *testing.T) {
	body := invalidUTF8StageEvidenceBody()
	if utf8.Valid(body) {
		t.Fatal("test exact-evidence body unexpectedly contains valid UTF-8")
	}

	fixture := newStageContractFixtureWithBody(t, body)
	stages := []struct {
		name    string
		request []byte
		inputs  StageCompileInputs
	}{
		{name: "intake", request: fixture.evidenceRequest.raw, inputs: fixture.evidenceRequest.inputs},
		{name: "semantic", request: fixture.semanticRequest.raw, inputs: fixture.semanticRequest.inputs},
		{name: "graph", request: fixture.graphRequest.raw, inputs: fixture.graphRequest.inputs},
		{name: "full", request: fixture.fullRequest.raw, inputs: fixture.fullRequest.inputs},
	}

	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			receipt, err := CompileStageReceipt(stage.request, stage.inputs)
			if err != nil {
				t.Fatalf("compile stage with byte-neutral exact evidence: %v", err)
			}
			summary, err := ValidateStageReceipt(receipt)
			if err != nil {
				t.Fatalf("validate body-free stage receipt: %v", err)
			}
			if len(summary.EvidenceCommitments) != 1 {
				t.Fatalf("evidence commitments = %d, want 1", len(summary.EvidenceCommitments))
			}
			commitment := summary.EvidenceCommitments[0]
			if commitment.BodySHA256 != sha256Hex(body) || commitment.ByteCount != uint64(len(body)) {
				t.Fatalf("exact evidence commitment = %+v, want digest %s and byte count %d", commitment, sha256Hex(body), len(body))
			}
			if bytes.Contains(receipt, body) {
				t.Fatal("body-free receipt contains the exact evidence bytes")
			}
		})
	}
}

func TestStageContractRejectsTamperedByteNeutralExactEvidenceAtIntakeAndInheritance(t *testing.T) {
	body := invalidUTF8StageEvidenceBody()
	fixture := newStageContractFixtureWithBody(t, body)

	t.Run("empty_intake", func(t *testing.T) {
		inputs := fixture.evidenceRequest.inputs
		inputs.EvidenceBodies = cloneStageEvidenceBodies(inputs.EvidenceBodies)
		inputs.EvidenceBodies[0].Raw = nil
		if _, err := CompileStageReceipt(fixture.evidenceRequest.raw, inputs); err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Fatalf("empty intake exact evidence error = %v", err)
		}
	})

	t.Run("intake_digest_mismatch", func(t *testing.T) {
		inputs := fixture.evidenceRequest.inputs
		inputs.EvidenceBodies = cloneStageEvidenceBodies(inputs.EvidenceBodies)
		inputs.EvidenceBodies[0].Raw[0] ^= 0x01
		if _, err := CompileStageReceipt(fixture.evidenceRequest.raw, inputs); err == nil || !strings.Contains(err.Error(), "digest/byte claim does not match") {
			t.Fatalf("tampered intake exact evidence error = %v", err)
		}
	})

	t.Run("inherited_digest_mismatch", func(t *testing.T) {
		inputs := fixture.semanticRequest.inputs
		inputs.EvidenceBodies = cloneStageEvidenceBodies(inputs.EvidenceBodies)
		inputs.EvidenceBodies[0].Raw[len(inputs.EvidenceBodies[0].Raw)-1] ^= 0x01
		if _, err := CompileStageReceipt(fixture.semanticRequest.raw, inputs); err == nil || !strings.Contains(err.Error(), "immutable lineage digest/byte commitment") {
			t.Fatalf("tampered inherited exact evidence error = %v", err)
		}
	})
}

func invalidUTF8StageEvidenceBody() []byte {
	body := []byte("source-declared machine export exact bytes\n")
	body = append(body, 0xff, 0xfe, 0x80, 0xc0, 0xaf)
	body = append(body, []byte("\ntransport-decoded evidence remains byte authoritative before charset decoding\n")...)
	return body
}
