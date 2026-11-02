package oodpublication

import (
	"context"
	"testing"
)

func TestSpannerClosureReaderRefusesMissingProtectedClientOrCoordinates(t *testing.T) {
	for _, tc := range []struct{ org, kind string }{{"", "provider_documentation"}, {"org", ""}} {
		if _, err := (SpannerClosureReader{}).ReadCurrentSealedClosure(context.Background(), tc.org, tc.kind); err == nil {
			t.Fatal("reader accepted an unbound client or coordinate")
		}
	}
}
