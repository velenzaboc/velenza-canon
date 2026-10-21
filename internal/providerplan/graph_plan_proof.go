package providerplan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// graphPlanSchemaBindingProof is minted only by the existing graph_compile
// stage validator after its exact stage-profile pin, profile-bound target
// schemas, digest ledger, and JSON-Schema validation chain succeed. It has no
// serialization form.
type graphPlanSchemaBindingProof struct {
	seal                *graphPlanSchemaBindingSeal
	plan                stageArtifactIdentity
	profile             immutableStageArtifactPin
	profileSchema       immutableStageArtifactPin
	planSchema          stageArtifactIdentity
	dependencyArtifacts []stageArtifactIdentity
	dependencySchemas   map[stageMaterialCoordinate]stageArtifactIdentity
	setKindsByRowKind   map[string][]string
	derivedSets         map[string]compactStageSet
}

type graphPlanSchemaBindingSeal struct{}

var graphPlanSchemaBindingAuthority = &graphPlanSchemaBindingSeal{}

// graphPlanBodyFreeProof is distinct from structural schema validation. It is
// minted only after the graph stage's complete request, lineage, material, and
// evidence-nonescape scan succeeds for the exact plan digest.
type graphPlanBodyFreeProof struct {
	seal          *graphPlanBodyFreeSeal
	planSHA256    string
	requestSHA256 string
	receipt       StageReceiptReference
}

type graphPlanBodyFreeSeal struct{}

var graphPlanBodyFreeAuthority = &graphPlanBodyFreeSeal{}

type graphPlanParseProof struct {
	seal       *graphPlanParseSeal
	structural graphPlanSchemaBindingProof
	bodyFree   graphPlanBodyFreeProof
}

type graphPlanParseSeal struct{}

var graphPlanParseAuthority = &graphPlanParseSeal{}

func buildGraphPlanSchemaBindingProof(binding graphCompileStageBinding, profile stageValidationProfileDocument, materials map[stageMaterialCoordinate]StageMaterial) (graphPlanSchemaBindingProof, error) {
	planCoordinate := stageCoordinateForIdentity(binding.Plan)
	planMaterial, ok := materials[planCoordinate]
	if !ok {
		return graphPlanSchemaBindingProof{}, fmt.Errorf("graph plan exact material is absent")
	}
	var selected *stageValidationProfileArtifactBinding
	for index := range profile.BoundArtifactSchemas {
		candidate := &profile.BoundArtifactSchemas[index]
		if (stageMaterialCoordinate{Role: candidate.Role, ID: candidate.ArtifactID, Version: candidate.ArtifactVersion}) == planCoordinate {
			if selected != nil {
				return graphPlanSchemaBindingProof{}, fmt.Errorf("graph compile profile binds the exact plan coordinate more than once")
			}
			selected = candidate
		}
	}
	if selected == nil {
		return graphPlanSchemaBindingProof{}, fmt.Errorf("graph compile profile does not bind the exact plan coordinate")
	}
	if selected.ArtifactRawSHA256 != binding.Plan.RawSHA256 || sha256Hex(planMaterial.Raw) != binding.Plan.RawSHA256 {
		return graphPlanSchemaBindingProof{}, fmt.Errorf("graph compile profile/request/material plan digests differ")
	}
	planSchemaCoordinate := stageMaterialCoordinate{Role: selected.SchemaRole, ID: selected.SchemaID, Version: selected.SchemaVersion}
	planSchemaMaterial, ok := materials[planSchemaCoordinate]
	if !ok {
		return graphPlanSchemaBindingProof{}, fmt.Errorf("graph-plan target schema exact material is absent")
	}
	if selected.SchemaRawSHA256 != sha256Hex(planSchemaMaterial.Raw) {
		return graphPlanSchemaBindingProof{}, fmt.Errorf("graph compile profile target-schema digest differs from exact material")
	}
	planSchemaPin := stageArtifactIdentity{
		Role: selected.SchemaRole, ID: selected.SchemaID, Version: selected.SchemaVersion,
		RawSHA256: selected.SchemaRawSHA256,
	}

	_, discriminator, err := resolveValidationProfileSchema(planSchemaMaterial.Raw, validationProfileCoordinate{ID: selected.SchemaID, Version: selected.SchemaVersion})
	if err != nil {
		return graphPlanSchemaBindingProof{}, fmt.Errorf("resolve graph-plan target schema: %w", err)
	}
	if discriminator.property != "row_kind" {
		return graphPlanSchemaBindingProof{}, fmt.Errorf("graph-plan target schema discriminator %q is not the generic row_kind contract", discriminator.property)
	}
	setKindsByRowKind := make(map[string][]string, len(profile.GraphRowDispositions))
	for _, disposition := range profile.GraphRowDispositions {
		if _, duplicate := setKindsByRowKind[disposition.RowKind]; duplicate {
			return graphPlanSchemaBindingProof{}, fmt.Errorf("graph compile profile duplicates row disposition %q", disposition.RowKind)
		}
		setKindsByRowKind[disposition.RowKind] = slices.Clone(disposition.SetKinds)
	}
	for rowKind := range discriminator.values {
		if _, declared := setKindsByRowKind[rowKind]; !declared {
			return graphPlanSchemaBindingProof{}, fmt.Errorf("target-schema row kind %q has no graph profile disposition", rowKind)
		}
	}
	actualRowKinds, err := scanGraphPlanRowKinds(planMaterial.Raw)
	if err != nil {
		return graphPlanSchemaBindingProof{}, err
	}
	for rowKind := range actualRowKinds {
		if _, allowed := discriminator.values[rowKind]; !allowed {
			return graphPlanSchemaBindingProof{}, fmt.Errorf("exact plan row kind %q is absent from the target schema", rowKind)
		}
	}

	sets, err := deriveStageGraphSets(planMaterial.Raw, profile.GraphRowDispositions)
	if err != nil {
		return graphPlanSchemaBindingProof{}, err
	}
	dependencyCoordinates := make(map[stageMaterialCoordinate]struct{}, len(binding.DependencyArtifacts))
	for _, dependency := range binding.DependencyArtifacts {
		dependencyCoordinates[stageCoordinateForIdentity(dependency)] = struct{}{}
	}
	dependencySchemas := make(map[stageMaterialCoordinate]stageArtifactIdentity, len(dependencyCoordinates))
	for _, profileBinding := range profile.BoundArtifactSchemas {
		artifactCoordinate := stageMaterialCoordinate{Role: profileBinding.Role, ID: profileBinding.ArtifactID, Version: profileBinding.ArtifactVersion}
		if _, dependency := dependencyCoordinates[artifactCoordinate]; !dependency {
			continue
		}
		dependencySchemas[artifactCoordinate] = stageArtifactIdentity{
			Role: profileBinding.SchemaRole, ID: profileBinding.SchemaID, Version: profileBinding.SchemaVersion, RawSHA256: profileBinding.SchemaRawSHA256,
		}
	}
	if len(dependencySchemas) != len(dependencyCoordinates) {
		return graphPlanSchemaBindingProof{}, fmt.Errorf("graph compile profile does not bind every exact dependency artifact to one target schema")
	}
	return graphPlanSchemaBindingProof{
		seal:                graphPlanSchemaBindingAuthority,
		plan:                binding.Plan,
		profile:             binding.StageValidation.Profile,
		profileSchema:       binding.StageValidation.Schema,
		planSchema:          planSchemaPin,
		dependencyArtifacts: append([]stageArtifactIdentity(nil), binding.DependencyArtifacts...),
		dependencySchemas:   dependencySchemas,
		setKindsByRowKind:   cloneGraphRowSetKinds(setKindsByRowKind),
		derivedSets:         cloneCompactStageSets(sets),
	}, nil
}

func scanGraphPlanRowKinds(raw []byte) (map[string]struct{}, error) {
	rowKinds := map[string]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), maxValidationProfileRowBytes)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := rejectDuplicateJSONKeys(line); err != nil {
			return nil, fmt.Errorf("graph plan line %d: %w", lineNumber, err)
		}
		var envelope rowEnvelope
		if err := json.Unmarshal(line, &envelope); err != nil {
			return nil, fmt.Errorf("graph plan line %d row-kind envelope: %w", lineNumber, err)
		}
		if !isCanonicalValidationProfileIdentity(envelope.RowKind) {
			return nil, fmt.Errorf("graph plan line %d has no canonical row_kind", lineNumber)
		}
		rowKinds[envelope.RowKind] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan exact graph-plan row kinds: %w", err)
	}
	if len(rowKinds) == 0 {
		return nil, fmt.Errorf("graph plan has no rows")
	}
	return rowKinds, nil
}

func newGraphPlanParseProof(structural graphPlanSchemaBindingProof, requestSHA256 string, receipt StageReceiptReference) (graphPlanParseProof, error) {
	if structural.seal != graphPlanSchemaBindingAuthority || !isLowerSHA256(structural.plan.RawSHA256) {
		return graphPlanParseProof{}, fmt.Errorf("graph-plan body-free proof requires a sealed structural proof")
	}
	if !isLowerSHA256(requestSHA256) || receipt.StageKind != stageGraphCompile || !isLowerSHA256(receipt.ReceiptSHA256) || !isLowerSHA256(receipt.OutputRootSHA256) {
		return graphPlanParseProof{}, fmt.Errorf("graph-plan body-free proof requires exact graph request/receipt/root identities")
	}
	return graphPlanParseProof{
		seal:       graphPlanParseAuthority,
		structural: structural,
		bodyFree: graphPlanBodyFreeProof{
			seal: graphPlanBodyFreeAuthority, planSHA256: structural.plan.RawSHA256,
			requestSHA256: requestSHA256, receipt: receipt,
		},
	}, nil
}

func requireGraphPlanParseProof(proof graphPlanParseProof, planRaw []byte) error {
	if proof.seal != graphPlanParseAuthority || proof.structural.seal != graphPlanSchemaBindingAuthority || proof.bodyFree.seal != graphPlanBodyFreeAuthority {
		return fmt.Errorf("graph-plan parsing requires sealed structural and body-free stage proofs")
	}
	digest := sha256Hex(planRaw)
	if digest != proof.structural.plan.RawSHA256 || digest != proof.bodyFree.planSHA256 {
		return fmt.Errorf("graph-plan bytes do not equal the exact digest sealed by both stage proofs")
	}
	if len(proof.structural.setKindsByRowKind) == 0 {
		return fmt.Errorf("graph-plan structural proof has no closed row disposition roster")
	}
	return nil
}

func cloneCompactStageSets(input map[string]compactStageSet) map[string]compactStageSet {
	output := make(map[string]compactStageSet, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func graphPlanSetKinds(proof graphPlanParseProof, rowKind string) ([]string, bool) {
	if proof.seal != graphPlanParseAuthority || proof.structural.seal != graphPlanSchemaBindingAuthority {
		return nil, false
	}
	setKinds, ok := proof.structural.setKindsByRowKind[rowKind]
	return slices.Clone(setKinds), ok
}

func cloneGraphRowSetKinds(input map[string][]string) map[string][]string {
	output := make(map[string][]string, len(input))
	for key, value := range input {
		output[key] = slices.Clone(value)
	}
	return output
}
