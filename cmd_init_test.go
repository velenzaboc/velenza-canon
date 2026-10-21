package main

import (
	"strings"
	"testing"
)

func TestValidateSchemaApplyArtifactRejectsNonAuthorizingRender(t *testing.T) {
	err := validateSchemaApplyArtifact([]byte("-- Rendering is not DDL-apply authorization; the sanctioned deployment gate remains mandatory.\nCREATE TABLE X (id INT64 NOT NULL) PRIMARY KEY (id);"))
	if err == nil || !strings.Contains(err.Error(), "verification input only") {
		t.Fatalf("got %v, want non-authorizing schema rejection", err)
	}
}

func TestValidateSchemaApplyArtifactAllowsCurrentRuntimeSchema(t *testing.T) {
	if err := validateSchemaApplyArtifact([]byte("CREATE TABLE X (id INT64 NOT NULL) PRIMARY KEY (id);")); err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
}
