package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestImmutableRetirementAdaptersFailBeforeDatabaseAccess(t *testing.T) {
	adapter := &SpannerSubstrateAdapter{}
	if _, err := adapter.ArchiveNode(context.Background(), "org", "node", "admitter"); !errors.Is(err, ErrOODGraphImmutableRetirementUnavailable) {
		t.Fatalf("ArchiveNode error=%v, want %v", err, ErrOODGraphImmutableRetirementUnavailable)
	}
	if _, err := adapter.ArchiveEdge(context.Background(), "org", "edge", "admitter"); !errors.Is(err, ErrOODGraphImmutableRetirementUnavailable) {
		t.Fatalf("ArchiveEdge error=%v, want %v", err, ErrOODGraphImmutableRetirementUnavailable)
	}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"node_id", func() error { _, err := adapter.ArchiveNode(context.Background(), "org", "", "admitter"); return err }},
		{"node_org", func() error { _, err := adapter.ArchiveNode(context.Background(), "", "node", "admitter"); return err }},
		{"edge_admitter", func() error { _, err := adapter.ArchiveEdge(context.Background(), "org", "edge", ""); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil || errors.Is(err, ErrOODGraphImmutableRetirementUnavailable) || !strings.Contains(err.Error(), "empty") {
				t.Fatalf("validation error=%v, want typed empty-input refusal before retirement sentinel", err)
			}
		})
	}
}
