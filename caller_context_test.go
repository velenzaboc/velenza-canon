package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestProductionMCPBootFailsClosedUntilVerifierAndCircuitAdaptersAreWired(t *testing.T) {
	if err := validateMCPRuntimeComposition(SpecGraphConfig{Mode: ModeExperimentalBootstrap}); err != nil {
		t.Fatalf("bootstrap composition rejected: %v", err)
	}
	if err := validateMCPRuntimeComposition(SpecGraphConfig{Mode: ModeProduction}); !errors.Is(err, ErrProductionRuntimeCompositionUnavailable) {
		t.Fatalf("production composition error=%v, want %v", err, ErrProductionRuntimeCompositionUnavailable)
	}
}

func TestResolveOrganizationIDIsBootstrapOnlyDefaultAndProductionOnlyCallerContext(t *testing.T) {
	bootstrap := &Env{Config: SpecGraphConfig{Mode: ModeExperimentalBootstrap, DefaultOrganizationID: "bootstrap-org"}}
	if got, err := resolveOrganizationID(context.Background(), bootstrap); err != nil || got != "bootstrap-org" {
		t.Fatalf("bootstrap organization=%q err=%v", got, err)
	}

	production := &Env{Config: SpecGraphConfig{Mode: ModeProduction}}
	if _, err := resolveOrganizationID(context.Background(), production); err == nil || !strings.Contains(err.Error(), "CallerContext") {
		t.Fatalf("production missing-context error=%v", err)
	}
	ctx := withCallerOrganizationID(context.Background(), "tenant-prod")
	if got, err := resolveOrganizationID(ctx, production); err != nil || got != "tenant-prod" {
		t.Fatalf("production organization=%q err=%v", got, err)
	}
}

func TestProductionCallerContextMiddlewareTrustsOnlyVerifiedTokenInfo(t *testing.T) {
	cfg := SpecGraphConfig{Mode: ModeProduction}
	called := false
	next := mcp.MethodHandler(func(ctx context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
		called = true
		got, err := resolveOrganizationID(ctx, &Env{Config: cfg})
		if err != nil || got != "tenant-verified" {
			t.Fatalf("resolved organization=%q err=%v", got, err)
		}
		return nil, nil
	})
	handler := productionCallerContextMiddleware(cfg)(next)

	rawHeaderOnly := &mcp.CallToolRequest{Extra: &mcp.RequestExtra{Header: http.Header{"X-Organization-Id": []string{"tenant-unverified"}}}}
	if _, err := handler(context.Background(), "tools/call", rawHeaderOnly); err == nil || !strings.Contains(err.Error(), "verified bearer TokenInfo") {
		t.Fatalf("raw-header-only error=%v", err)
	}
	if called {
		t.Fatal("raw organization header reached tool handler")
	}

	verified := &mcp.CallToolRequest{Extra: &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{Extra: map[string]any{"organization_id": "tenant-verified"}}}}
	if _, err := handler(context.Background(), "tools/call", verified); err != nil {
		t.Fatalf("verified CallerContext rejected: %v", err)
	}
	if !called {
		t.Fatal("verified CallerContext did not reach tool handler")
	}
}

func TestProductionCallerContextMiddlewareRejectsMalformedClaim(t *testing.T) {
	handler := productionCallerContextMiddleware(SpecGraphConfig{Mode: ModeProduction})(func(context.Context, string, mcp.Request) (mcp.Result, error) {
		t.Fatal("malformed claim reached tool handler")
		return nil, nil
	})
	for _, claim := range []any{nil, 42, " leading", strings.Repeat("x", 37)} {
		req := &mcp.CallToolRequest{Extra: &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{Extra: map[string]any{"organization_id": claim}}}}
		if _, err := handler(context.Background(), "tools/call", req); err == nil {
			t.Fatalf("claim %#v was accepted", claim)
		}
	}
}
