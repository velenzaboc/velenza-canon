package main

import (
	"strings"
	"testing"
)

func TestReplayViolationEvidenceCoordinateBounds(t *testing.T) {
	t.Run("nil evidence is explicit", func(t *testing.T) {
		coordinates, err := replayViolationEvidenceCoordinates(nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := coordinates["identity_tuple_field_names"]; len(got.([]string)) != 0 {
			t.Fatalf("identity tuple names = %#v, want empty", got)
		}
	})

	t.Run("missing and nil strings are empty", func(t *testing.T) {
		for name, evidence := range map[string]map[string]interface{}{
			"missing": {},
			"nil":     {"edge_label": nil},
		} {
			t.Run(name, func(t *testing.T) {
				got, err := replayViolationEvidenceString(evidence, "edge_label")
				if err != nil || got != "" {
					t.Fatalf("got %q, %v; want empty, nil", got, err)
				}
			})
		}
	})

	t.Run("identity tuple representations are normalized", func(t *testing.T) {
		for name, evidence := range map[string]map[string]interface{}{
			"missing":      {},
			"nil":          {"identity_tuple_field_names": nil},
			"string slice": {"identity_tuple_field_names": []string{"z", "a"}},
		} {
			t.Run(name, func(t *testing.T) {
				got, err := replayViolationIdentityTupleFieldNames(evidence)
				if err != nil {
					t.Fatal(err)
				}
				if name == "string slice" && strings.Join(got, ",") != "a,z" {
					t.Fatalf("names = %#v, want sorted", got)
				}
			})
		}
	})

	t.Run("identity tuple rejects malformed values", func(t *testing.T) {
		for name, raw := range map[string]interface{}{
			"non-array":  "graph_object_id",
			"non-string": []interface{}{"graph_object_id", 7},
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := replayViolationIdentityTupleFieldNames(map[string]interface{}{"identity_tuple_field_names": raw}); err == nil {
					t.Fatal("malformed identity tuple names were accepted")
				}
			})
		}
	})

	t.Run("graph address must be canonicalizable", func(t *testing.T) {
		if _, err := replayViolationEvidenceCoordinates(map[string]interface{}{"graph_address": "not-a-graph-address"}); err == nil {
			t.Fatal("malformed graph address was accepted")
		}
	})
}

func TestReplayManifestErrorPropagation(t *testing.T) {
	invalidBatch := func() MaterializationBatch {
		batch := replayTestBatch()
		batch.Violations[0].Evidence["identity_tuple_field_names"] = []interface{}{false}
		return batch
	}

	t.Run("digest", func(t *testing.T) {
		if _, err := replayManifestDigest(invalidBatch()); err == nil {
			t.Fatal("digest accepted malformed violation evidence")
		}
	})

	t.Run("equivalence left", func(t *testing.T) {
		if _, err := replayOutputsEquivalent(invalidBatch(), replayTestBatch()); err == nil {
			t.Fatal("equivalence accepted malformed left output")
		}
	})

	t.Run("equivalence right", func(t *testing.T) {
		if _, err := replayOutputsEquivalent(replayTestBatch(), invalidBatch()); err == nil {
			t.Fatal("equivalence accepted malformed right output")
		}
	})

	t.Run("structured set", func(t *testing.T) {
		if err := sortStructuredSet([]map[string]interface{}{{"unsupported": make(chan int)}}); err == nil {
			t.Fatal("structured set accepted a non-JSON value")
		}
	})
}
