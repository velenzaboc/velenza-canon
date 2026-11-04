package providerplan

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/spanner"
)

// DocumentationFactoryProductionSourceProtectedLauncher is the boot-only
// composition boundary. Its caller supplies an already authorized client and
// an admitted owner binding; no CLI argument, source package, or receipt can
// select any of these dependencies.
type DocumentationFactoryProductionSourceProtectedLauncher struct {
	client      *spanner.Client
	expected    DocumentationFactoryProductionSourceOwnerBindingExpectation
	attestation DocumentationFactoryProductionSourceOODProofAttestationAuthority
}

// DocumentationFactoryProductionSourceQualifiedCompilation is an opaque,
// per-invocation compiler-to-preparation handoff. Its fields deliberately stay
// private so a caller cannot replace facts, receipts, or current OOD evidence.
type DocumentationFactoryProductionSourceQualifiedCompilation struct {
	compiled    DocumentationFactorySourceCompileResult
	preparation *documentationFactoryProductionSourceOODPreparationEvidence
	expected    DocumentationFactoryProductionSourceOwnerBindingExpectation
	request     DocumentationFactoryProductionSourceVerificationRequest
	current     DocumentationFactoryProductionSourceOODCurrentEvidenceRows
}

type documentationFactoryProductionSourcePreparationCapture struct {
	reader   DocumentationFactoryProductionSourceOODStrongReader
	pending  *DocumentationFactoryProductionSourceOODCurrentEvidenceRows
	request  DocumentationFactoryProductionSourceVerificationRequest
	expected DocumentationFactoryProductionSourceOwnerBindingExpectation
	rows     *DocumentationFactoryProductionSourceOODCurrentEvidenceRows
}

func (c *documentationFactoryProductionSourcePreparationCapture) ReadCurrentEligibleProviderEvidenceRows(ctx context.Context, request DocumentationFactoryProductionSourceOODReadRequest) (DocumentationFactoryProductionSourceOODCurrentEvidenceRows, error) {
	rows, err := c.reader.ReadCurrentEligibleProviderEvidenceRows(ctx, request)
	if err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, err
	}
	if rows.preparation == nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("protected OOD read omitted preparation evidence")
	}
	copyRows := cloneDocumentationFactoryProductionSourceOODCurrentEvidenceRows(rows)
	c.pending = &copyRows
	c.request = cloneDocumentationFactoryProductionSourceVerificationRequest(request.Request)
	c.expected = request.Expected
	return rows, nil
}

func (c *documentationFactoryProductionSourcePreparationCapture) observeValidatedPreparation(expected DocumentationFactoryProductionSourceOwnerBindingExpectation, request DocumentationFactoryProductionSourceVerificationRequest, rows DocumentationFactoryProductionSourceOODCurrentEvidenceRows) error {
	if c.pending == nil || c.expected != expected || c.request.ExpectedProvider != request.ExpectedProvider || c.request.SourcePackageSHA256 != request.SourcePackageSHA256 || c.request.SourcePackageByteCount != request.SourcePackageByteCount || c.request.VerificationReceiptSHA256 != request.VerificationReceiptSHA256 || c.request.VerificationReceiptByteCount != request.VerificationReceiptByteCount || c.request.EvidenceIdentitySetRootSHA256 != request.EvidenceIdentitySetRootSHA256 || c.request.ObservedAt != request.ObservedAt || !equalDocumentationFactoryProviderEvidenceIdentitySets(c.request.EvidenceIdentities, request.EvidenceIdentities) {
		return fmt.Errorf("validated preparation capture does not equal protected verification request")
	}
	if c.pending.preparation == nil || rows.preparation == nil {
		return fmt.Errorf("validated preparation capture lacks sealed evidence")
	}
	// Promote the private clone only after the normal current-evidence checks.
	c.rows = c.pending
	c.pending = nil
	return nil
}

func NewDocumentationFactoryProductionSourceProtectedLauncher(client *spanner.Client, expected DocumentationFactoryProductionSourceOwnerBindingExpectation, attestation DocumentationFactoryProductionSourceOODProofAttestationAuthority) (DocumentationFactoryProductionSourceProtectedLauncher, error) {
	if client == nil {
		return DocumentationFactoryProductionSourceProtectedLauncher{}, fmt.Errorf("protected source launcher requires selected Spanner client")
	}
	if err := validateDocumentationFactoryProductionSourceOwnerBindingExpectation(expected); err != nil {
		return DocumentationFactoryProductionSourceProtectedLauncher{}, err
	}
	if attestation == nil {
		return DocumentationFactoryProductionSourceProtectedLauncher{}, fmt.Errorf("protected source launcher requires OOD attestation authority")
	}
	return DocumentationFactoryProductionSourceProtectedLauncher{client: client, expected: expected, attestation: attestation}, nil
}

// ResolveDocumentationFactoryProductionSourceVerifier fulfills the protected
// boot resolver contract consumed by compilation. It composes the real typed
// proof authority and strong Spanner reader, rather than exposing a generic
// verification callback to source-package inputs.
func (l DocumentationFactoryProductionSourceProtectedLauncher) ResolveDocumentationFactoryProductionSourceVerifier(ctx context.Context) (DocumentationFactoryProductionSourceVerifier, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proof, err := NewDocumentationFactoryProductionSourceOODProofAuthority(l.attestation)
	if err != nil {
		return nil, err
	}
	reader, err := NewDocumentationFactoryProductionSourceOODSpannerReader(l.client, proof)
	if err != nil {
		return nil, err
	}
	return NewDocumentationFactoryProductionSourceOODCurrentVerifier(l.expected, reader)
}

// CompileDocumentationFactoryProductionSourcePackageProtected is the library
// launcher entrypoint for service boot code. It intentionally does not create
// clients, load ambient credentials, or add a command-line configuration path.
func (l DocumentationFactoryProductionSourceProtectedLauncher) CompileDocumentationFactoryProductionSourcePackageProtected(ctx context.Context, options DocumentationFactoryProductionSourceCompileOptions) (DocumentationFactorySourceCompileResult, error) {
	return CompileDocumentationFactoryProductionSourcePackageWithBoot(ctx, options, l)
}

// CompileDocumentationFactoryProductionSourcePackageForPreparation uses a
// fresh capture reader for this invocation only. It performs no write.
func (l DocumentationFactoryProductionSourceProtectedLauncher) CompileDocumentationFactoryProductionSourcePackageForPreparation(ctx context.Context, options DocumentationFactoryProductionSourceCompileOptions) (DocumentationFactoryProductionSourceQualifiedCompilation, error) {
	return l.compileDocumentationFactoryProductionSourcePackageForPreparationWithDependencies(ctx, options, documentationFactoryProductionSourceCompilerDependencies{
		SourceCompiler: defaultDocumentationFactorySourceCompilerDependencies(),
		Now:            time.Now,
	})
}

// compileDocumentationFactoryProductionSourcePackageForPreparationWithDependencies
// keeps the production protected-reader/capture path testable with the
// deterministic factory runner. It is package-private: boot callers always
// use CompileDocumentationFactoryProductionSourcePackageForPreparation and
// cannot select compiler dependencies, readers, or authorities.
func (l DocumentationFactoryProductionSourceProtectedLauncher) compileDocumentationFactoryProductionSourcePackageForPreparationWithDependencies(ctx context.Context, options DocumentationFactoryProductionSourceCompileOptions, dependencies documentationFactoryProductionSourceCompilerDependencies) (DocumentationFactoryProductionSourceQualifiedCompilation, error) {
	if ctx == nil {
		return DocumentationFactoryProductionSourceQualifiedCompilation{}, fmt.Errorf("production source preparation requires context")
	}
	proof, err := NewDocumentationFactoryProductionSourceOODProofAuthority(l.attestation)
	if err != nil {
		return DocumentationFactoryProductionSourceQualifiedCompilation{}, err
	}
	reader, err := NewDocumentationFactoryProductionSourceOODSpannerReader(l.client, proof)
	if err != nil {
		return DocumentationFactoryProductionSourceQualifiedCompilation{}, err
	}
	capture := &documentationFactoryProductionSourcePreparationCapture{reader: reader}
	verifier, err := NewDocumentationFactoryProductionSourceOODCurrentVerifier(l.expected, capture)
	if err != nil {
		return DocumentationFactoryProductionSourceQualifiedCompilation{}, err
	}
	compiled, err := compileDocumentationFactoryProductionSourcePackageWithDependencies(ctx, options, verifier, dependencies)
	if err != nil {
		return DocumentationFactoryProductionSourceQualifiedCompilation{}, err
	}
	if capture.rows == nil || capture.rows.preparation == nil {
		return DocumentationFactoryProductionSourceQualifiedCompilation{}, fmt.Errorf("protected compiler completed without current preparation evidence")
	}
	current := cloneDocumentationFactoryProductionSourceOODCurrentEvidenceRows(*capture.rows)
	// The qualified value owns one cloned evidence graph. Keep its private
	// preparation capability and current rows on that same graph; retaining the
	// capture's original pointer would make the successor's exact-closure check
	// fail after the defensive clone.
	return DocumentationFactoryProductionSourceQualifiedCompilation{compiled: compiled, preparation: current.preparation, expected: capture.expected, request: cloneDocumentationFactoryProductionSourceVerificationRequest(capture.request), current: current}, nil
}

var _ DocumentationFactoryProductionSourceBootResolver = DocumentationFactoryProductionSourceProtectedLauncher{}
