package providerplan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
)

// Binding follows model-format semantics, never provider/service name cases.
func validateCloudOperationModelBinding(profile CloudOperationAPIProfile, service CloudServiceAPIResidual, catalog CloudCatalog) error {
	op, ok := findCloudCatalogOperation(catalog, profile.OperationID)
	if !ok || profile.ModelEvidence.Locator != op.Locator || profile.ModelEvidence.SelectedRangeSHA256 != sha256Hex(op.RawJSON) {
		return fmt.Errorf("operation evidence is not the exact retained model range")
	}
	if catalog.Format == CloudCatalogFormatSmithyJSON {
		return validateCloudSmithyOperationProfile(profile, service, catalog, op)
	}
	if catalog.Format != CloudCatalogFormatGoogleDiscoveryREST {
		return fmt.Errorf("unsupported profile model format")
	}
	var raw struct {
		Method     string   `json:"httpMethod"`
		Path       string   `json:"path"`
		Scopes     []string `json:"scopes"`
		Parameters map[string]struct {
			Location string `json:"location"`
			Required bool   `json:"required"`
			Type     string `json:"type"`
		} `json:"parameters"`
		Response struct {
			Ref string `json:"$ref"`
		} `json:"response"`
	}
	if err := json.Unmarshal(op.RawJSON, &raw); err != nil {
		return err
	}
	base, err := url.Parse(service.Endpoint.BaseURL)
	if err != nil || base.Scheme != "https" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return fmt.Errorf("invalid discovery service base")
	}
	if profile.Route.Method != raw.Method || profile.Route.AuthorityTemplate != base.Host || profile.Route.PathTemplate != strings.TrimRight(base.Path, "/")+"/"+raw.Path {
		return fmt.Errorf("route differs from discovery method")
	}
	var selectors []string
	query := map[string]string{}
	for name, param := range raw.Parameters {
		if !param.Required {
			continue
		}
		if param.Type != "string" {
			return fmt.Errorf("unsupported required parameter type")
		}
		selectors = append(selectors, name)
		switch param.Location {
		case "query":
			query[name] = "{" + name + "}"
		case "path":
			if !strings.Contains(raw.Path, "{"+name+"}") {
				return fmt.Errorf("unbound path parameter")
			}
		default:
			return fmt.Errorf("unsupported required parameter location")
		}
	}
	sort.Strings(selectors)
	if !reflect.DeepEqual(selectors, profile.Route.RequiredSelectors) || !reflect.DeepEqual(query, profile.Route.QueryTemplates) {
		return fmt.Errorf("required discovery selectors differ")
	}
	sort.Strings(raw.Scopes)
	if !reflect.DeepEqual(raw.Scopes, profile.AcceptedScopes) {
		return fmt.Errorf("accepted scope alternatives differ from model")
	}
	if profile.Pagination.Required {
		p := profile.Pagination
		param, exists := raw.Parameters[p.RequestTokenField]
		if !exists || param.Location != "query" || param.Type != "string" || p.RequestTokenWireName != p.RequestTokenField || p.ResponseTokenWireName != p.ResponseTokenField {
			return fmt.Errorf("invalid discovery pagination request")
		}
		fields, err := cloudCatalogObjectFields(catalog, raw.Response.Ref)
		if err != nil {
			return err
		}
		field, exists := fields["/"+cloudCatalogEscapePointer(p.ResponseTokenField)]
		if !exists || field.ValueType != "string" {
			return fmt.Errorf("invalid discovery pagination response")
		}
	}
	return nil
}

func validateCloudSmithyOperationProfile(profile CloudOperationAPIProfile, service CloudServiceAPIResidual, catalog CloudCatalog, op CloudCatalogOperation) error {
	var raw struct {
		Input struct {
			Target string `json:"target"`
		} `json:"input"`
		Output struct {
			Target string `json:"target"`
		} `json:"output"`
		Traits map[string]json.RawMessage `json:"traits"`
	}
	if err := json.Unmarshal(op.RawJSON, &raw); err != nil {
		return err
	}
	var http struct {
		Method string `json:"method"`
		URI    string `json:"uri"`
	}
	if value, exists := raw.Traits["smithy.api#http"]; exists {
		if err := json.Unmarshal(value, &http); err != nil {
			return err
		}
		u, err := url.Parse(http.URI)
		if err != nil {
			return err
		}
		query := map[string]string{}
		for k, vs := range u.Query() {
			if len(vs) != 1 {
				return fmt.Errorf("duplicate model query")
			}
			query[k] = vs[0]
		}
		if profile.Route.Method != http.Method || profile.Route.PathTemplate != u.Path || !reflect.DeepEqual(query, profile.Route.QueryTemplates) {
			return fmt.Errorf("route differs from Smithy HTTP trait")
		}
	} else {
		queryProtocol := false
		for _, binding := range catalog.ProtocolBindings {
			if binding.ID == "aws.protocols#ec2Query" && binding.Status == cloudCatalogProtocolDocumentedSupported {
				queryProtocol = true
			}
		}
		if !queryProtocol {
			return fmt.Errorf("no supported Smithy route protocol")
		}
		parts := strings.Split(profile.OperationID, "#")
		if len(parts) != 2 {
			return fmt.Errorf("invalid query operation identity")
		}
		want := map[string]string{"Action": parts[1], "Version": catalog.APIVersion}
		if profile.Route.Method != "GET" || profile.Route.PathTemplate != "/" || !reflect.DeepEqual(want, profile.Route.QueryTemplates) {
			return fmt.Errorf("route differs from EC2 Query action/version")
		}
	}
	value, paginated := raw.Traits["smithy.api#paginated"]
	if paginated != profile.Pagination.Required {
		return fmt.Errorf("pagination differs from model trait")
	}
	if paginated {
		var p struct {
			Input  string `json:"inputToken"`
			Output string `json:"outputToken"`
		}
		if err := json.Unmarshal(value, &p); err != nil {
			return err
		}
		if profile.Pagination.RequestTokenField != p.Input || profile.Pagination.ResponseTokenField != p.Output {
			return fmt.Errorf("pagination member differs from model")
		}
		input, err := cloudSmithyMemberWireName(catalog, raw.Input.Target, p.Input, true)
		if err != nil {
			return err
		}
		output, err := cloudSmithyMemberWireName(catalog, raw.Output.Target, p.Output, false)
		if err != nil {
			return err
		}
		if input != profile.Pagination.RequestTokenWireName || output != profile.Pagination.ResponseTokenWireName {
			return fmt.Errorf("pagination wire name differs from model")
		}
	}
	return nil
}

func cloudSmithyMemberWireName(catalog CloudCatalog, shapeID, member string, input bool) (string, error) {
	shape, ok := cloudCatalogShape(catalog, shapeID)
	if !ok {
		return "", fmt.Errorf("pagination shape absent")
	}
	var raw struct {
		Members map[string]struct {
			Traits map[string]json.RawMessage `json:"traits"`
		} `json:"members"`
	}
	if err := json.Unmarshal(shape.RawJSON, &raw); err != nil {
		return "", err
	}
	field, exists := raw.Members[member]
	if !exists {
		return "", fmt.Errorf("pagination member absent")
	}
	traits := []string{"smithy.api#xmlName"}
	if input {
		traits = []string{"smithy.api#httpQuery", "aws.protocols#ec2QueryName", "smithy.api#xmlName"}
	}
	for _, name := range traits {
		if v, ok := field.Traits[name]; ok {
			var value string
			if err := json.Unmarshal(v, &value); err != nil {
				return "", err
			}
			return value, nil
		}
	}
	return member, nil
}
