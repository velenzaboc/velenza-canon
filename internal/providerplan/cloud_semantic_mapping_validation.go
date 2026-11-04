package providerplan

// Closed reason vocabularies are contract data, not projection behavior. They
// cover only source leaves intentionally excluded from neutral output.
var cloudSemanticPrivateReasons = map[string]bool{
	"credential": true, "secret": true, "personal_data": true,
	"security_sensitive": true, "provider_internal": true,
	"reserved_for_future_use": true,
}

var cloudSemanticUnsupportedReasons = map[string]bool{
	"no_neutral_owner": true, "no_exact_type": true,
	"no_safe_transform": true, "future_capability": true,
}

// cloudMappingContractAllFields includes private and unsupported leaves. They
// never become neutral output, but they remain part of the complete source
// roster which v3 owner validation must close.
func cloudMappingContractAllFields(contract CloudMappingContract) []CloudMappingContractField {
	fields := append([]CloudMappingContractField(nil), contract.Fields...)
	for _, nested := range contract.Nested {
		fields = append(fields, nested.Fields...)
	}
	return fields
}
