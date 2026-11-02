package main

import (
	"errors"
	"fmt"
	"sort"

	"github.com/velenzaboc/velenza-canon/internal/oodapi"
)

// ErrAPIElementRoleEvidenceVerifierUnavailable is deliberate: the maintained
// v2 substrate has no graph-fact-locator, relationship-evidence, receipt, or
// completeness-certificate tables. A SHA-256-shaped value is not authority
// for an API role. Only the OOD8 verifier over those evidence rows may admit
// one; until that owner is available, API-role materialization is refused.
var ErrAPIElementRoleEvidenceVerifierUnavailable = errors.New("api element role evidence verifier is unavailable")

// apiRelationshipEdgeContracts is the closed, source-neutral OOD Graph v1
// API topology registry.  It intentionally describes roles rather than a
// provider's vocabulary: provider data is evidence for these graph facts, not
// an extension to the graph protocol.
//
// Keep this registry in lock-step with
// OOD_GRAPH_PROTOCOL_v1 §4.api_relationship_contract.
type apiRelationshipEdgeContract = oodapi.RelationshipContract

// The reusable verifier owns this closed registry. Keep a local copy only as
// a read-only compatibility surface for the established graph configuration
// validators; RelationshipContracts returns a defensive map.
var apiRelationshipEdgeContracts = oodapi.RelationshipContracts()

var apiElementRoles = func() map[string]struct{} {
	roles := make(map[string]struct{})
	for _, contract := range apiRelationshipEdgeContracts {
		roles[contract.SourceRole] = struct{}{}
		roles[contract.TargetRole] = struct{}{}
	}
	return roles
}()

func validateAPIRelationshipEdgeRegistry(labels []EdgeLabelDescriptor) error {
	byName := make(map[string]EdgeLabelDescriptor, len(labels))
	for i, label := range labels {
		name := label.Name()
		if _, duplicate := byName[name]; duplicate {
			return fmt.Errorf("edge_labels[%d].name %q is duplicated", i, name)
		}
		byName[name] = label
		if label.EdgeFamily() == "api_relationship" {
			contract, ok := apiRelationshipEdgeContracts[name]
			if !ok {
				return fmt.Errorf("edge_label %q is not in the closed OOD api_relationship registry", name)
			}
			if err := validateAPIRelationshipEdgeDescriptor(label, contract); err != nil {
				return err
			}
		}
	}

	names := make([]string, 0, len(apiRelationshipEdgeContracts))
	for name := range apiRelationshipEdgeContracts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		desc, ok := byName[name]
		if !ok {
			return fmt.Errorf("OOD api_relationship registry requires edge_label %q", name)
		}
		if err := validateAPIRelationshipEdgeDescriptor(desc, apiRelationshipEdgeContracts[name]); err != nil {
			return err
		}
	}
	return nil
}

func validateAPIRelationshipRegistryForConfig(c SpecGraphConfig) error {
	apiSymbolConfigured := false
	for _, kind := range c.NodeKinds {
		if kind.Name() == "api_symbol" {
			apiSymbolConfigured = true
			break
		}
	}
	if !apiSymbolConfigured {
		for _, source := range c.ExternalSources {
			if containsString(source.AllowedObjectClasses, "api_symbol") {
				apiSymbolConfigured = true
				break
			}
		}
	}
	if !apiSymbolConfigured {
		for _, label := range c.EdgeLabels {
			if label.EdgeFamily() == "api_relationship" {
				apiSymbolConfigured = true
				break
			}
		}
	}
	if !apiSymbolConfigured {
		return nil
	}
	return validateAPIRelationshipEdgeRegistry(c.EdgeLabels)
}

func validateAPIRelationshipEdgeDescriptor(desc EdgeLabelDescriptor, contract apiRelationshipEdgeContract) error {
	if desc.EdgeFamily() != "api_relationship" {
		return fmt.Errorf("edge_label %q edge_family=%q; want OOD protocol family api_relationship", desc.Name(), desc.EdgeFamily())
	}
	if desc.ReciprocalLabel() != "" || desc.DiagnosticOnly() {
		return fmt.Errorf("edge_label %q must be authoritative and must not declare reciprocal_label", desc.Name())
	}
	if !equalStringSets(desc.SourceKinds(), []string{"api_symbol"}) || !equalStringSets(desc.TargetKinds(), []string{"api_symbol"}) {
		return fmt.Errorf("edge_label %q must have exact api_symbol -> api_symbol endpoint classes", desc.Name())
	}
	return nil
}

func validateAPIElementRoleObject(object GraphObject) error {
	if err := validateAPIElementRoleShape(object); err != nil {
		return err
	}
	if object.ObjectClass == "api_symbol" {
		return fmt.Errorf("%w: api_symbol role %q cannot be qualified from a locator hash alone", ErrAPIElementRoleEvidenceVerifierUnavailable, object.APIElementRole)
	}
	return nil
}

// validateAPIElementRoleShape validates only the immutable row shape. It is
// intentionally not evidence verification and must never be used to admit an
// API-role row into a qualified graph snapshot.
func validateAPIElementRoleShape(object GraphObject) error {
	if object.ObjectClass != "api_symbol" {
		if object.APIElementRole != "" || object.APIElementRoleLocatorManifestHash != "" {
			return fmt.Errorf("api_element_role and api_element_role_locator_manifest_hash are only permitted on api_symbol")
		}
		return nil
	}
	return oodapi.ValidateRole(object.APIElementRole, object.APIElementRoleLocatorManifestHash)
}

func validateAPIRelationshipEndpoints(label EdgeLabelDescriptor, source, target GraphObject) error {
	contract, ok := apiRelationshipEdgeContracts[label.Name()]
	if !ok {
		return nil
	}
	if err := validateAPIElementRoleShape(source); err != nil {
		return fmt.Errorf("source endpoint: %w", err)
	}
	if err := validateAPIElementRoleShape(target); err != nil {
		return fmt.Errorf("target endpoint: %w", err)
	}
	if source.APIElementRole != contract.SourceRole || target.APIElementRole != contract.TargetRole {
		return fmt.Errorf("edge_label %q requires %s -> %s roles, got %s -> %s", label.Name(), contract.SourceRole, contract.TargetRole, source.APIElementRole, target.APIElementRole)
	}
	return fmt.Errorf("%w: api_relationship %q cannot be materialized before role-evidence verification", ErrAPIElementRoleEvidenceVerifierUnavailable, label.Name())
}
