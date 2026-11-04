package providerplan

import (
	"context"
	"fmt"

	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

// DocumentationFactoryProductionSourceOODProtectedQueryClient is the narrow
// production service boundary for the OOD strong read. Its implementation is
// owned by the protected OOD service/Spanner adapter: it must authorize before
// reading and return rows from one coherent read timestamp. It has no SQL or
// caller-provided table/predicate surface.
type DocumentationFactoryProductionSourceOODProtectedQueryClient interface {
	ReadCurrentProviderDocumentationClosure(context.Context, DocumentationFactoryProductionSourceOODReadRequest) (DocumentationFactoryProductionSourceOODCurrentEvidenceRows, error)
}

// DocumentationFactoryProductionSourceOODProtectedQueryReader is the concrete
// providerplan adapter used at boot. It deliberately names the closed OOD8
// table contracts it consumes, so a generic alternate store cannot silently
// omit snapshot-head or materialization coordinates.
type DocumentationFactoryProductionSourceOODProtectedQueryReader struct {
	client DocumentationFactoryProductionSourceOODProtectedQueryClient
}

func NewDocumentationFactoryProductionSourceOODProtectedQueryReader(client DocumentationFactoryProductionSourceOODProtectedQueryClient) (DocumentationFactoryProductionSourceOODStrongReader, error) {
	if client == nil {
		return nil, fmt.Errorf("protected OOD current-query client is required")
	}
	// Force the concrete adapter to remain coupled to the generated closed
	// table/column contracts without opening a caller-selectable query API.
	if len(oodpublication.SnapshotColumns()) == 0 || len(oodpublication.SnapshotHeadColumns()) == 0 || len(oodpublication.PublicationStateColumns()) == 0 || len(oodpublication.MaterializationRunColumns()) == 0 {
		return nil, fmt.Errorf("OOD protected-query schema contract is unavailable")
	}
	return DocumentationFactoryProductionSourceOODProtectedQueryReader{client: client}, nil
}

func (r DocumentationFactoryProductionSourceOODProtectedQueryReader) ReadCurrentEligibleProviderEvidenceRows(ctx context.Context, request DocumentationFactoryProductionSourceOODReadRequest) (DocumentationFactoryProductionSourceOODCurrentEvidenceRows, error) {
	if err := ctx.Err(); err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, err
	}
	rows, err := r.client.ReadCurrentProviderDocumentationClosure(ctx, request)
	if err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("protected OOD current-query refused selection: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, err
	}
	return rows, nil
}

var _ DocumentationFactoryProductionSourceOODStrongReader = DocumentationFactoryProductionSourceOODProtectedQueryReader{}
