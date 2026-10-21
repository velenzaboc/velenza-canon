package main

import (
	"context"
	"encoding/json"
	"flag"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

// ---------------- CosineDistance ----------------

func TestCosineDistance_IdenticalVectorsZero(t *testing.T) {
	a := []float32{1, 0, 0, 0}
	d, err := CosineDistance(a, a)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(d) > 1e-9 {
		t.Errorf("identical vectors: distance = %v, want 0", d)
	}
}

func TestCosineDistance_OrthogonalIsOne(t *testing.T) {
	a := []float32{1, 0}
	b := []float32{0, 1}
	d, err := CosineDistance(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(d-1) > 1e-9 {
		t.Errorf("orthogonal: distance = %v, want 1", d)
	}
}

func TestCosineDistance_OppositeIsTwo(t *testing.T) {
	a := []float32{1, 0}
	b := []float32{-1, 0}
	d, err := CosineDistance(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(d-2) > 1e-9 {
		t.Errorf("opposite: distance = %v, want 2", d)
	}
}

func TestCosineDistance_LengthMismatchErrors(t *testing.T) {
	if _, err := CosineDistance([]float32{1, 0}, []float32{1, 0, 0}); err == nil {
		t.Error("expected length-mismatch error")
	}
}

func TestCosineDistance_EmptyErrors(t *testing.T) {
	if _, err := CosineDistance([]float32{}, []float32{}); err == nil {
		t.Error("expected empty-vector error")
	}
}

func TestCosineDistance_ZeroMagnitudeErrors(t *testing.T) {
	if _, err := CosineDistance([]float32{0, 0}, []float32{1, 0}); err == nil {
		t.Error("expected zero-magnitude error")
	}
}

// ---------------- BucketRecords ----------------

func validClusterConfig() ClusterConfig {
	return ClusterConfig{
		AutoMergeDistance:  0.10,
		ReviewDistance:     0.30,
		EmbeddingBatchSize: 10,
	}
}

func rec(path, value string) ConceptRecord {
	return ConceptRecord{
		SourceFile: "test.ood.json",
		SourcePath: path,
		LeafName:   "statement",
		RawValue:   value,
		NodeKind:   "invariant",
	}
}

func embed(r ConceptRecord, vec []float32) EmbeddedRecord {
	return EmbeddedRecord{Record: r, Embedding: vec}
}

func TestBucketRecords_EmptyInput(t *testing.T) {
	out, err := BucketRecords(nil, validClusterConfig(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if out.RecordsInspected != 0 {
		t.Errorf("expected 0 records inspected, got %d", out.RecordsInspected)
	}
	if len(out.AutoMerge) != 0 || len(out.VerifyRequired) != 0 || len(out.NoMatch) != 0 {
		t.Errorf("expected all buckets empty, got auto=%d verify=%d nm=%d",
			len(out.AutoMerge), len(out.VerifyRequired), len(out.NoMatch))
	}
}

func TestBucketRecords_TightPairAutoMerges(t *testing.T) {
	// Two vectors that are very close (distance ~ 0.001).
	a := embed(rec("s1", "the gate fires on deny"), []float32{1, 0.01, 0, 0})
	b := embed(rec("s2", "gate fires when deny verdict received"), []float32{0.99, 0.02, 0, 0})
	out, err := BucketRecords([]EmbeddedRecord{a, b}, validClusterConfig(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.AutoMerge) != 1 {
		t.Fatalf("expected 1 auto_merge cluster, got %d (verify=%d nm=%d)", len(out.AutoMerge), len(out.VerifyRequired), len(out.NoMatch))
	}
	if len(out.AutoMerge[0].Members) != 2 {
		t.Errorf("expected 2 members in cluster, got %d", len(out.AutoMerge[0].Members))
	}
}

func TestBucketRecords_GrayZoneVerifies(t *testing.T) {
	// Two vectors that are close but not super-close (distance ~0.2 — in
	// the [0.10, 0.30) gray zone).
	a := embed(rec("s1", "a"), []float32{1, 0, 0, 0})
	// Construct a vector with cos~0.8 → distance ~0.2.
	// cos(θ)=0.8 → use (0.8, 0.6, 0, 0); magnitude = 1.0; dot with (1,0,0,0) = 0.8.
	b := embed(rec("s2", "b"), []float32{0.8, 0.6, 0, 0})
	out, err := BucketRecords([]EmbeddedRecord{a, b}, validClusterConfig(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.VerifyRequired) != 1 {
		t.Fatalf("expected 1 verify_required cluster, got %d (auto=%d nm=%d)", len(out.VerifyRequired), len(out.AutoMerge), len(out.NoMatch))
	}
	if len(out.VerifyRequired[0].Members) != 2 {
		t.Errorf("expected 2 members, got %d", len(out.VerifyRequired[0].Members))
	}
}

func TestBucketRecords_FarApartNoMatch(t *testing.T) {
	a := embed(rec("s1", "a"), []float32{1, 0, 0, 0})
	b := embed(rec("s2", "b"), []float32{0, 1, 0, 0}) // orthogonal: distance 1.0 > 0.3
	out, err := BucketRecords([]EmbeddedRecord{a, b}, validClusterConfig(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.NoMatch) != 2 {
		t.Fatalf("expected 2 no_match, got %d (auto=%d verify=%d)", len(out.NoMatch), len(out.AutoMerge), len(out.VerifyRequired))
	}
}

func TestBucketRecords_RepresentativeHasLowestMeanDistance(t *testing.T) {
	// Three records, b in the middle of a and c by construction.
	// All within the review_distance threshold (we use a custom config
	// so all three land in one cluster).
	cfg := ClusterConfig{AutoMergeDistance: 0.5, ReviewDistance: 0.9, EmbeddingBatchSize: 10}
	a := embed(rec("s1", "a"), []float32{1, 0, 0, 0})                                                           // angle 0
	b := embed(rec("s2", "b"), []float32{float32(math.Cos(math.Pi / 8)), float32(math.Sin(math.Pi / 8)), 0, 0}) // angle pi/8
	c := embed(rec("s3", "c"), []float32{float32(math.Cos(math.Pi / 4)), float32(math.Sin(math.Pi / 4)), 0, 0}) // angle pi/4
	out, err := BucketRecords([]EmbeddedRecord{a, b, c}, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.AutoMerge)+len(out.VerifyRequired) != 1 {
		t.Fatalf("expected exactly 1 cluster across both buckets, got auto=%d verify=%d",
			len(out.AutoMerge), len(out.VerifyRequired))
	}
	var cluster Cluster
	if len(out.AutoMerge) == 1 {
		cluster = out.AutoMerge[0]
	} else {
		cluster = out.VerifyRequired[0]
	}
	// b should be the representative (lowest mean distance to the other two).
	if cluster.Representative.SourcePath != "s2" {
		t.Errorf("expected b (s2) as representative, got %q", cluster.Representative.SourcePath)
	}
}

func TestBucketRecords_DeterministicOrdering(t *testing.T) {
	a := embed(rec("z_path", "z"), []float32{0, 1, 0, 0})
	b := embed(rec("a_path", "a"), []float32{1, 0, 0, 0})
	// Two far-apart records → both in no_match. Ordering must be deterministic
	// (sorted by SourcePath ascending) so re-runs produce identical output.
	out, err := BucketRecords([]EmbeddedRecord{a, b}, validClusterConfig(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.NoMatch) != 2 {
		t.Fatalf("expected 2 no_match, got %d", len(out.NoMatch))
	}
	if out.NoMatch[0].SourcePath != "a_path" {
		t.Errorf("expected a_path first in no_match, got %q", out.NoMatch[0].SourcePath)
	}
}

func TestBucketRecords_ThresholdsRecordedInOutput(t *testing.T) {
	cfg := validClusterConfig()
	out, err := BucketRecords(nil, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	if out.Thresholds.AutoMergeDistance != cfg.AutoMergeDistance {
		t.Errorf("auto_merge_distance not recorded")
	}
	if out.Thresholds.ReviewDistance != cfg.ReviewDistance {
		t.Errorf("review_distance not recorded")
	}
}

func TestBucketRecords_InvalidConfigRejected(t *testing.T) {
	bad := ClusterConfig{AutoMergeDistance: 0.5, ReviewDistance: 0.4, EmbeddingBatchSize: 10}
	if _, err := BucketRecords(nil, bad, "test"); err == nil {
		t.Error("expected error on auto >= review")
	}
}

// ---------------- Config validation ----------------

func TestConfig_RequiresAllSections(t *testing.T) {
	missingEmbedding := validCredentialConfig()
	missingPipeline := validCredentialConfig()
	missingPipeline.Embedding = validEmbeddingConfig()
	missingCluster := validCredentialConfig()
	missingCluster.Embedding = validEmbeddingConfig()
	missingCluster.Pipeline = &PipelineConfig{}
	cases := []struct {
		name    string
		c       Config
		wantErr string
	}{
		{"missing_embedding", missingEmbedding, "embedding section required"},
		{"missing_pipeline", missingPipeline, "pipeline section required"},
		{"missing_cluster", missingCluster, "pipeline.cluster section required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", c.wantErr)
			}
		})
	}
}

func TestConfig_ValidPasses(t *testing.T) {
	c := validCredentialConfig()
	c.Embedding = validEmbeddingConfig()
	c.Pipeline = &PipelineConfig{
		Cluster: &ClusterConfig{
			AutoMergeDistance:  0.10,
			ReviewDistance:     0.30,
			EmbeddingBatchSize: 100,
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid config to pass, got %v", err)
	}
}

func TestLoadConfigAndDiskHelpersCloseMalformedInputs(t *testing.T) {
	dir := t.TempDir()
	cfg := validCredentialConfig()
	cfg.Embedding = validEmbeddingConfig()
	cfg.Pipeline = &PipelineConfig{Cluster: &ClusterConfig{AutoMergeDistance: 0.1, ReviewDistance: 0.3, EmbeddingBatchSize: 2}}
	configPath := filepath.Join(dir, "config.json")
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if _, err := LoadConfig(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("accepted missing config")
	}
	if err := os.WriteFile(configPath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath); err == nil {
		t.Fatal("accepted malformed config")
	}
	recordsPath := filepath.Join(dir, "records.json")
	if err := os.WriteFile(recordsPath, []byte(`[{"source_file":"s","source_path":"p","leaf_name":"n","raw_value":"v"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if records, err := loadRecords(recordsPath); err != nil || len(records) != 1 {
		t.Fatalf("records %#v, %v", records, err)
	}
	if err := os.WriteFile(recordsPath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRecords(recordsPath); err == nil {
		t.Fatal("accepted malformed records")
	}
	cachePath := filepath.Join(dir, "cache.json")
	if cache, err := loadCache(cachePath); err != nil || len(cache.Embedded) != 0 {
		t.Fatalf("missing cache %#v %v", cache, err)
	}
	if err := writeCache(cachePath, &EmbeddingCache{}); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCache(cachePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCache(cachePath); err == nil {
		t.Fatal("accepted malformed cache")
	}
}

func TestMainClustersEmptyInputWithInjectedLocalRuntime(t *testing.T) {
	dir := t.TempDir()
	cfg := validCredentialConfig()
	cfg.Embedding = validEmbeddingConfig()
	cfg.Pipeline = &PipelineConfig{Cluster: &ClusterConfig{AutoMergeDistance: .1, ReviewDistance: .3, EmbeddingBatchSize: 1}}
	config, records, output, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "records.json"), filepath.Join(dir, "out.json"), filepath.Join(dir, "cache.json")
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(records, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	oldArgs, oldFlags, oldAuth, oldEmbed := os.Args, flag.CommandLine, newVertexAuth, newEmbedClient
	t.Cleanup(func() {
		os.Args, flag.CommandLine, newVertexAuth, newEmbedClient = oldArgs, oldFlags, oldAuth, oldEmbed
	})
	flag.CommandLine = flag.NewFlagSet("spec-cluster", flag.ContinueOnError)
	os.Args = []string{"spec-cluster", "--config", config, "--records", records, "--output", output, "--cache", cache, "--concept-domain", "test"}
	newVertexAuth = func(context.Context, vertexai.TokenSourceFactory) (*vertexai.Auth, error) {
		return &vertexai.Auth{}, nil
	}
	newEmbedClient = func(auth *vertexai.Auth, cfg vertexai.EmbedConfig) (*vertexai.EmbedClient, error) {
		return vertexai.NewEmbedClient(auth, cfg)
	}
	main()
	if data, err := os.ReadFile(output); err != nil || !strings.Contains(string(data), "test") {
		t.Fatalf("output %q %v", data, err)
	}
}

func TestEmbedAllWithCacheUsesCacheAndClosesEmbedFailure(t *testing.T) {
	old := embedText
	t.Cleanup(func() { embedText = old })
	records := []ConceptRecord{{SourceFile: "s", SourcePath: "p", LeafName: "cached", RawValue: "cached"}, {SourceFile: "s", SourcePath: "p", LeafName: "fresh", RawValue: "fresh"}}
	cache := &EmbeddingCache{Embedded: []EmbeddedRecord{{Record: records[0], Embedding: []float32{1}}}}
	calls := 0
	embedText = func(_ context.Context, _ *vertexai.EmbedClient, text string) ([]float32, error) {
		calls++
		if text != "fresh" {
			t.Fatalf("embedded %q", text)
		}
		return []float32{2}, nil
	}
	out, err := embedAllWithCache(context.Background(), &vertexai.EmbedClient{}, records, cache)
	if err != nil || calls != 1 || len(out) != 2 || out[0].Embedding[0] != 1 || out[1].Embedding[0] != 2 {
		t.Fatalf("out %#v calls %d err %v", out, calls, err)
	}
	embedText = func(context.Context, *vertexai.EmbedClient, string) ([]float32, error) { return nil, os.ErrClosed }
	if _, err := embedAllWithCache(context.Background(), &vertexai.EmbedClient{}, []ConceptRecord{records[1]}, &EmbeddingCache{}); err == nil {
		t.Fatal("accepted embed error")
	}
}

func TestMainClosesMissingArguments(t *testing.T) {
	oldArgs, oldFlags, oldExit := os.Args, flag.CommandLine, exit
	t.Cleanup(func() { os.Args, flag.CommandLine, exit = oldArgs, oldFlags, oldExit })
	flag.CommandLine = flag.NewFlagSet("spec-cluster", flag.ContinueOnError)
	os.Args = []string{"spec-cluster"}
	code := -1
	exit = func(got int) { code = got; panic("exit") }
	defer func() {
		if recover() == nil || code != 2 {
			t.Fatalf("exit %d", code)
		}
	}()
	main()
}

func TestMainClosesUnreadableConfig(t *testing.T) {
	oldArgs, oldFlags, oldExit := os.Args, flag.CommandLine, exit
	t.Cleanup(func() { os.Args, flag.CommandLine, exit = oldArgs, oldFlags, oldExit })
	flag.CommandLine = flag.NewFlagSet("spec-cluster", flag.ContinueOnError)
	os.Args = []string{"spec-cluster", "--config", filepath.Join(t.TempDir(), "missing"), "--records", "r", "--output", "o", "--cache", "c", "--concept-domain", "d"}
	code := -1
	exit = func(got int) { code = got; panic("exit") }
	defer func() {
		if recover() == nil || code != 2 {
			t.Fatalf("exit %d", code)
		}
	}()
	main()
}

func TestMainClosesUnreadableRecords(t *testing.T) {
	dir := t.TempDir()
	cfg := validCredentialConfig()
	cfg.Embedding = validEmbeddingConfig()
	cfg.Pipeline = &PipelineConfig{Cluster: &ClusterConfig{AutoMergeDistance: .1, ReviewDistance: .3, EmbeddingBatchSize: 1}}
	config := filepath.Join(dir, "config.json")
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	oldArgs, oldFlags, oldExit := os.Args, flag.CommandLine, exit
	t.Cleanup(func() { os.Args, flag.CommandLine, exit = oldArgs, oldFlags, oldExit })
	flag.CommandLine = flag.NewFlagSet("spec-cluster", flag.ContinueOnError)
	os.Args = []string{"spec-cluster", "--config", config, "--records", filepath.Join(dir, "missing"), "--output", "o", "--cache", "c", "--concept-domain", "d"}
	code := -1
	exit = func(got int) { code = got; panic("exit") }
	defer func() {
		if recover() == nil || code != 2 {
			t.Fatalf("exit %d", code)
		}
	}()
	main()
}

func TestClusterConfig_RejectsOutOfRangeDistances(t *testing.T) {
	cases := []ClusterConfig{
		{AutoMergeDistance: 0, ReviewDistance: 0.5, EmbeddingBatchSize: 10},
		{AutoMergeDistance: 0.1, ReviewDistance: 0, EmbeddingBatchSize: 10},
		{AutoMergeDistance: 0.1, ReviewDistance: 2.1, EmbeddingBatchSize: 10},
		{AutoMergeDistance: 0.1, ReviewDistance: 0.3, EmbeddingBatchSize: 0},
	}
	for i, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d: expected error on %+v", i, c)
		}
	}
}

func validEmbeddingConfig() *EmbeddingConfig {
	return &EmbeddingConfig{
		Provider:     "vertex_ai",
		Project:      "test-project",
		Location:     "us-central1",
		Model:        "gemini-embedding-001",
		Dimensions:   4,
		MaxTextBytes: 8192,
	}
}

func validCredentialConfig() Config {
	return Config{
		Mode: "experimental_bootstrap",
		GoogleCredentials: gcpauth.Selector{
			CredentialsSource:   gcpauth.CredentialsSourceApplicationDefault,
			CredentialsProfile:  gcpauth.CredentialsProfileImpersonatedServiceAccount,
			CredentialsIdentity: "spec-graph-local@example-gcp-project.iam.gserviceaccount.com",
		},
	}
}
