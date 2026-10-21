package main

import (
	"fmt"
	"math"
	"sort"
)

// CosineDistance returns the cosine distance between two equal-length
// vectors: 1 − cos(θ). Range [0, 2]: identical vectors → 0, orthogonal → 1,
// opposite → 2. Matches the gemini-embedding-001 distance semantics
// spec-graph's APPROX_COSINE_DISTANCE assumes.
func CosineDistance(a, b []float32) (float64, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("vector length mismatch: %d vs %d", len(a), len(b))
	}
	if len(a) == 0 {
		return 0, fmt.Errorf("zero-length vectors")
	}
	var dot, na, nb float64
	for i := range a {
		x := float64(a[i])
		y := float64(b[i])
		dot += x * y
		na += x * x
		nb += y * y
	}
	if na == 0 || nb == 0 {
		return 0, fmt.Errorf("zero-magnitude vector")
	}
	cos := dot / (math.Sqrt(na) * math.Sqrt(nb))
	// Clamp tiny numerical excursions outside [-1, 1].
	if cos > 1 {
		cos = 1
	}
	if cos < -1 {
		cos = -1
	}
	return 1 - cos, nil
}

// BucketRecords groups EmbeddedRecords into three buckets per the
// configured thresholds:
//   - auto_merge: pairs whose distance is < AutoMergeDistance form clusters.
//   - verify_required: pairs whose distance is in [AutoMergeDistance,
//     ReviewDistance) form clusters whose members differ enough to need
//     LLM-tier confirmation (Stage 2b).
//   - no_match: records with no neighbor below ReviewDistance.
//
// Clustering uses single-linkage: any two records within ReviewDistance
// share a cluster. Inside a cluster, the bucket is auto_merge if EVERY
// pairwise distance is < AutoMergeDistance; otherwise verify_required.
//
// The representative of each cluster is the record with the lowest mean
// distance to other members — the anchor that downstream Stage 2b uses to
// frame Flash queries.
func BucketRecords(records []EmbeddedRecord, cfg ClusterConfig, conceptDomain string) (*ClusterBuckets, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("cluster config: %w", err)
	}
	out := &ClusterBuckets{
		ConceptDomain:    conceptDomain,
		RecordsInspected: len(records),
		Thresholds: ThresholdsUsed{
			AutoMergeDistance: cfg.AutoMergeDistance,
			ReviewDistance:    cfg.ReviewDistance,
		},
	}
	if len(records) == 0 {
		return out, nil
	}

	// Pairwise distances (upper triangle), needed for both linkage and
	// per-cluster mean-distance representative selection.
	n := len(records)
	dist := make([][]float64, n)
	for i := range dist {
		dist[i] = make([]float64, n)
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			d, err := CosineDistance(records[i].Embedding, records[j].Embedding)
			if err != nil {
				return nil, fmt.Errorf("distance %d/%d: %w", i, j, err)
			}
			dist[i][j] = d
			dist[j][i] = d
		}
	}

	// Single-linkage clustering at the ReviewDistance threshold via
	// union-find. Indices in [0, n) → cluster id.
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if dist[i][j] < cfg.ReviewDistance {
				union(i, j)
			}
		}
	}

	// Gather members per cluster root.
	clusters := map[int][]int{}
	for i := 0; i < n; i++ {
		r := find(i)
		clusters[r] = append(clusters[r], i)
	}

	// For each cluster, classify bucket + select representative.
	roots := make([]int, 0, len(clusters))
	for r := range clusters {
		roots = append(roots, r)
	}
	sort.Ints(roots) // deterministic output order

	for _, r := range roots {
		members := clusters[r]
		if len(members) == 1 {
			out.NoMatch = append(out.NoMatch, records[members[0]].Record)
			continue
		}
		// Determine bucket: if every pairwise distance among members is
		// < AutoMergeDistance, it's auto_merge; otherwise verify_required.
		auto := true
		for ii, i := range members {
			for jj := ii + 1; jj < len(members); jj++ {
				j := members[jj]
				if dist[i][j] >= cfg.AutoMergeDistance {
					auto = false
					break
				}
			}
			if !auto {
				break
			}
		}
		// Representative: member with lowest mean distance to other members.
		anchorIdx := representative(members, dist)
		anchor := records[anchorIdx].Record
		// Member list: sort by distance from anchor (ascending), anchor first
		// (distance 0).
		ms := make([]ClusterMember, 0, len(members))
		for _, i := range members {
			ms = append(ms, ClusterMember{
				Record:             records[i].Record,
				DistanceFromAnchor: dist[anchorIdx][i],
			})
		}
		sort.SliceStable(ms, func(a, b int) bool {
			return ms[a].DistanceFromAnchor < ms[b].DistanceFromAnchor
		})
		cl := Cluster{Representative: anchor, Members: ms}
		if auto {
			out.AutoMerge = append(out.AutoMerge, cl)
		} else {
			out.VerifyRequired = append(out.VerifyRequired, cl)
		}
	}

	// Sort no_match deterministically by source_path so re-runs produce
	// byte-identical output.
	sort.SliceStable(out.NoMatch, func(i, j int) bool {
		return out.NoMatch[i].SourcePath < out.NoMatch[j].SourcePath
	})
	return out, nil
}

// representative picks the cluster member with the lowest mean cosine
// distance to other members. Ties broken by ascending index for
// determinism.
func representative(members []int, dist [][]float64) int {
	bestIdx := members[0]
	bestMean := math.Inf(1)
	for _, i := range members {
		var sum float64
		var cnt int
		for _, j := range members {
			if j == i {
				continue
			}
			sum += dist[i][j]
			cnt++
		}
		var mean float64
		if cnt > 0 {
			mean = sum / float64(cnt)
		}
		if mean < bestMean {
			bestMean = mean
			bestIdx = i
		}
	}
	return bestIdx
}
