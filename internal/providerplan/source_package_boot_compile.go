package providerplan

import (
	"context"
	"fmt"
)

// CompileDocumentationFactoryProductionSourcePackageWithBoot is the protected
// launcher entrypoint. The independently composed resolver is selected before
// compilation and never comes from the package, receipt or CLI arguments.
func CompileDocumentationFactoryProductionSourcePackageWithBoot(ctx context.Context, options DocumentationFactoryProductionSourceCompileOptions, boot DocumentationFactoryProductionSourceBootResolver) (DocumentationFactorySourceCompileResult, error) {
	if ctx == nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("production source compilation requires context")
	}
	verifier, err := ResolveDocumentationFactoryProductionSourceVerifier(ctx, boot)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	return CompileDocumentationFactoryProductionSourcePackage(ctx, options, verifier)
}
