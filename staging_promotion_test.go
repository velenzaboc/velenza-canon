package main

import (
	"strings"
	"testing"
)

func TestStagingPromotionFinalTransactionCASRequiresLintPass(t *testing.T) {
	concept := stagingConceptPromotionStatement("org", StagingConceptPromotion{
		IngestionRunID: "run", StagingID: "concept", GraphObjectID: "object",
	})
	edge := stagingEdgePromotionStatement("org", StagingEdgePromotion{
		IngestionRunID: "run", StagingEdgeID: "edge", GraphEdgeID: "graph-edge",
	})
	for name, sql := range map[string]string{"concept": concept.SQL, "edge": edge.SQL} {
		if !strings.Contains(sql, "pipeline_state='linted'") || !strings.Contains(sql, "lint_status='pass'") {
			t.Fatalf("%s final promotion CAS does not recheck both lint state and verdict: %s", name, sql)
		}
	}
}
