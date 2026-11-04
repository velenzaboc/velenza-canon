# FeatureGraph evidence publisher

The operator runs through the existing root command, `spec-graph featuregraph-publish`, so Google client construction remains centralized in `substrate.go`. The implementation is `featuregraph_publish.go` and `internal/featuregraphprojection/`.

Build the root binary on an approved build worker, then run the native operator with its host-owned device selector. See `internal/featuregraphprojection/README.md` for plan/apply flags and the source-qualified, zero-runtime-authority contract. This directory is a source-discovery pointer, not a second client constructor.
