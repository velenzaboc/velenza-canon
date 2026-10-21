package providerplan

import "fmt"

const (
	documentationFactoryProductionSourceRunReceiptKind    = "provider_documentation_factory_production_source_run_receipt"
	documentationFactoryProductionSourceRunReceiptVersion = "1"
	documentationFactoryProductionSourceRunReceiptResult  = "authenticated_source_compiled_and_verified_candidate_only"
	documentationFactoryProductionSourceRunReceiptScope   = "sealed_source_package_exact_provider_evidence_identity_four_stage_candidate_compilation"
)

// DocumentationFactoryProductionSourceRunReceipt is the body-free release
// relay for one production-verified source compilation. It keeps the source
// owner's verification binding attached to the exact factory receipt without
// upgrading either receipt into admission, configuration, deployment, tenant,
// credential, source-materialization, or live-provider authority.
type DocumentationFactoryProductionSourceRunReceipt struct {
	ReceiptKind         string                                   `json:"receipt_kind"`
	ReceiptVersion      string                                   `json:"receipt_version"`
	Result              string                                   `json:"result"`
	Scope               string                                   `json:"scope"`
	SourceReceipt       DocumentationFactorySourceCompileReceipt `json:"source_receipt"`
	FactoryReceipt      FactoryRunReceipt                        `json:"factory_receipt"`
	BodyFree            bool                                     `json:"body_free"`
	AuthoritySelected   bool                                     `json:"authority_selected"`
	AdmissionAuthorized bool                                     `json:"admission_authorized"`
	FactoryComplete     bool                                     `json:"factory_complete"`
	ReceiptSHA256       string                                   `json:"receipt_sha256"`
}

// SealDocumentationFactoryProductionSourceRunReceipt closes the exact source
// and factory receipts produced by one compiler invocation into the only
// receipt shape accepted by the production-source release path.
func SealDocumentationFactoryProductionSourceRunReceipt(result DocumentationFactorySourceCompileResult) (DocumentationFactoryProductionSourceRunReceipt, error) {
	receipt := DocumentationFactoryProductionSourceRunReceipt{
		ReceiptKind:         documentationFactoryProductionSourceRunReceiptKind,
		ReceiptVersion:      documentationFactoryProductionSourceRunReceiptVersion,
		Result:              documentationFactoryProductionSourceRunReceiptResult,
		Scope:               documentationFactoryProductionSourceRunReceiptScope,
		SourceReceipt:       result.SourceReceipt,
		FactoryReceipt:      result.FactoryReceipt,
		BodyFree:            true,
		AuthoritySelected:   false,
		AdmissionAuthorized: false,
		FactoryComplete:     false,
	}
	raw, err := canonicalDocumentationFactoryProductionSourceRunReceiptIdentity(receipt)
	if err != nil {
		return DocumentationFactoryProductionSourceRunReceipt{}, err
	}
	receipt.ReceiptSHA256 = sha256Hex(raw)
	if err := ValidateDocumentationFactoryProductionSourceRunReceipt(receipt); err != nil {
		return DocumentationFactoryProductionSourceRunReceipt{}, err
	}
	return receipt, nil
}

// ValidateDocumentationFactoryProductionSourceRunReceipt verifies the closed
// source/factory relay. Producer authentication and currentness remain owned by
// the process-selected source verifier that created ProductionSourceVerification;
// this validator never infers either predicate from caller-authored JSON.
func ValidateDocumentationFactoryProductionSourceRunReceipt(receipt DocumentationFactoryProductionSourceRunReceipt) error {
	if receipt.ReceiptKind != documentationFactoryProductionSourceRunReceiptKind || receipt.ReceiptVersion != documentationFactoryProductionSourceRunReceiptVersion || receipt.Result != documentationFactoryProductionSourceRunReceiptResult || receipt.Scope != documentationFactoryProductionSourceRunReceiptScope || !receipt.BodyFree || receipt.AuthoritySelected || receipt.AdmissionAuthorized || receipt.FactoryComplete {
		return fmt.Errorf("production source run receipt identity or candidate-only posture is invalid")
	}
	if !isLowerSHA256(receipt.ReceiptSHA256) {
		return fmt.Errorf("production source run receipt digest is invalid")
	}
	if err := validateDocumentationFactorySourceReceipt(receipt.SourceReceipt); err != nil {
		return fmt.Errorf("production source run source receipt: %w", err)
	}
	verification := receipt.SourceReceipt.ProductionSourceVerification
	if verification == nil {
		return fmt.Errorf("production source run receipt lacks production source verification")
	}
	if err := validateFactoryRunReceipt(receipt.FactoryReceipt); err != nil {
		return fmt.Errorf("production source run factory receipt: %w", err)
	}
	if receipt.SourceReceipt.FactoryPortableReceiptSHA256 != receipt.FactoryReceipt.PortableReceiptSHA256 || receipt.SourceReceipt.FactoryReceiptSHA256 != receipt.FactoryReceipt.ReceiptSHA256 {
		return fmt.Errorf("production source run source receipt binds a different factory receipt")
	}
	factoryRaw, err := canonicalFactoryJSON(receipt.FactoryReceipt)
	if err != nil {
		return fmt.Errorf("serialize production source run factory receipt: %w", err)
	}
	factoryRaw = append(factoryRaw, '\n')
	if receipt.SourceReceipt.FactoryReceiptFileSHA256 != sha256Hex(factoryRaw) {
		return fmt.Errorf("production source run source receipt binds different factory receipt bytes")
	}
	if verification.Provider != receipt.FactoryReceipt.PreflightReceipt.Provider {
		return fmt.Errorf("production source run provider %q differs from compiled provider %q", verification.Provider, receipt.FactoryReceipt.PreflightReceipt.Provider)
	}
	if receipt.SourceReceipt.Completion != receipt.FactoryReceipt.Completion {
		return fmt.Errorf("production source run source and factory completion classifications differ")
	}
	raw, err := canonicalDocumentationFactoryProductionSourceRunReceiptIdentity(receipt)
	if err != nil {
		return err
	}
	if sha256Hex(raw) != receipt.ReceiptSHA256 {
		return fmt.Errorf("production source run receipt digest mismatch")
	}
	return nil
}

func canonicalDocumentationFactoryProductionSourceRunReceiptIdentity(receipt DocumentationFactoryProductionSourceRunReceipt) ([]byte, error) {
	receipt.ReceiptSHA256 = ""
	raw, err := canonicalFactoryJSON(receipt)
	if err != nil {
		return nil, fmt.Errorf("serialize production source run receipt: %w", err)
	}
	return raw, nil
}
