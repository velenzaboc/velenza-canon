package main

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type callerOrganizationIDContextKey struct{}

func withCallerOrganizationID(ctx context.Context, organizationID string) context.Context {
	return context.WithValue(ctx, callerOrganizationIDContextKey{}, organizationID)
}

func validateCallerOrganizationID(organizationID string) error {
	if organizationID == "" {
		return fmt.Errorf("organization_id is required")
	}
	if strings.TrimSpace(organizationID) != organizationID || !utf8.ValidString(organizationID) {
		return fmt.Errorf("organization_id must be canonical UTF-8 without surrounding whitespace")
	}
	if len(organizationID) > 36 {
		return fmt.Errorf("organization_id exceeds OODGraph STRING(36)")
	}
	if strings.IndexFunc(organizationID, unicode.IsControl) >= 0 {
		return fmt.Errorf("organization_id contains a control character")
	}
	return nil
}

// resolveOrganizationID is the single tenant-resolution gate used by graph
// reads and writes. Bootstrap retains its configured tenant. Production has
// no fallback: only the organization_id placed in context from a verified
// MCP bearer-token TokenInfo is accepted.
func resolveOrganizationID(ctx context.Context, env *Env) (string, error) {
	if env == nil {
		return "", fmt.Errorf("environment required")
	}
	var organizationID string
	switch env.Config.Mode {
	case ModeExperimentalBootstrap:
		organizationID = env.Config.DefaultOrganizationID
	case ModeProduction:
		organizationID, _ = ctx.Value(callerOrganizationIDContextKey{}).(string)
	default:
		return "", fmt.Errorf("invalid mode %q while resolving organization_id", env.Config.Mode)
	}
	if err := validateCallerOrganizationID(organizationID); err != nil {
		if env.Config.Mode == ModeProduction {
			return "", fmt.Errorf("production CallerContext organization_id invalid: %w", err)
		}
		return "", fmt.Errorf("bootstrap default_organization_id invalid: %w", err)
	}
	return organizationID, nil
}
