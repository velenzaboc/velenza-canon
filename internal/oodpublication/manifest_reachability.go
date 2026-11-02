package oodpublication

import (
	"errors"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
)

// A physical manifest row is eligible only when reached from a certificate
// root or an exact typed claim in that certificate's member closure.
func verifyManifestNodeReachability(c oodevidence.ClosureCertificateV8, members map[string]ManifestMemberV8, nodes map[string]ManifestNodeV8) error {
	roots := map[string]bool{}
	for _, root := range c.Roots {
		roots[root.Hash] = true
	}
	for _, member := range members {
		if member.Row == nil {
			continue
		}
		r := *member.Row
		var root string
		switch r.Table {
		case "OODGraphObjects":
			root = stringColumn(r, "api_element_role_locator_manifest_hash")
		case "OODGraphRelationshipEvidence", "OODGraphAPIPropertyFacts":
			root = stringColumn(r, "graph_fact_locator_manifest_hash")
		case "OODGraphViolations":
			claimRoots, err := ViolationGraphFactLocatorManifestRoots(r.Columns["evidence"].(CanonicalJSON))
			if err != nil {
				return err
			}
			for _, claimRoot := range claimRoots {
				roots[claimRoot] = true
			}
		}
		if root != "" {
			roots[root] = true
		}
	}
	seen, active := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(hash string) error {
		if active[hash] {
			return errors.New("manifest reachability cycle")
		}
		if seen[hash] {
			return nil
		}
		node, ok := nodes[hash]
		if !ok {
			return errors.New("referenced manifest node absent")
		}
		active[hash] = true
		for _, entry := range node.Entries {
			if entry.EntryKind == "child_manifest" {
				if err := visit(entry.ChildHash); err != nil {
					return err
				}
			}
		}
		delete(active, hash)
		seen[hash] = true
		return nil
	}
	for root := range roots {
		if err := visit(root); err != nil {
			return err
		}
	}
	if len(seen) != len(nodes) {
		return errors.New("unreferenced manifest node outside certificate and typed claim closure")
	}
	return nil
}
