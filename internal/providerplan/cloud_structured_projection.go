package providerplan

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

const cloudProjectionStructured CloudMappingProjection = "typed_structure"

// A closed recipe accounts for every member of a retained source object.
// Each list item is projected independently so associations survive missing
// optional members and repeated values. Source strings are never decoded as JSON.
type CloudStructuredRule struct {
	KeyKind           string                  `json:"key_kind,omitempty"`
	KeyMember         string                  `json:"key_member,omitempty"`
	ValueMember       string                  `json:"value_member,omitempty"`
	UnobservedMembers []string                `json:"unobserved_members,omitempty"`
	Kind              string                  `json:"kind"`
	Members           []CloudStructuredMember `json:"members,omitempty"`
	Item              *CloudStructuredRule    `json:"item,omitempty"`
	Values            map[string]string       `json:"values,omitempty"`
	ReasonCode        string                  `json:"reason_code,omitempty"`
	Rationale         string                  `json:"rationale,omitempty"`
	EvidenceRefs      []string                `json:"evidence_refs,omitempty"`
}

type CloudStructuredMember struct {
	OnAbsent string              `json:"on_absent,omitempty"`
	OnNull   string              `json:"on_null,omitempty"`
	Source   string              `json:"source"`
	Target   string              `json:"target,omitempty"`
	Rule     CloudStructuredRule `json:"rule"`
}

// A grouped relationship may preserve list/object association, but every
// emitted terminal value must come from the scoped identity resolver.
func (r *CloudStructuredRule) containsOnlyReferences() bool {
	if r == nil {
		return false
	}
	switch r.Kind {
	case "scoped_reference":
		return true
	case "list":
		return r.Item.containsOnlyReferences()
	case "object":
		found := false
		for _, member := range r.Members {
			if member.Rule.Kind == "private" {
				continue
			}
			if !member.Rule.containsOnlyReferences() {
				return false
			}
			found = true
		}
		return found
	default:
		return false
	}
}

type cloudStructuredMemberPlan struct {
	source, wire, target string
	onAbsent, onNull     string
	node                 *cloudStructuredPlan
}

type cloudStructuredPlan struct {
	keyIsReference                             bool
	keyMember, valueMember, keyWire, valueWire string
	unobserved                                 []string
	nestedLeafList                             bool
	kind, sourceType, format, itemWire         string
	members                                    []cloudStructuredMemberPlan
	item                                       *cloudStructuredPlan
	values                                     map[string]string
}

type cloudStructuredModelShape struct {
	Type       string                                 `json:"type"`
	Format     string                                 `json:"format"`
	Ref        string                                 `json:"$ref"`
	Properties map[string]json.RawMessage             `json:"properties"`
	Additional json.RawMessage                        `json:"additionalProperties"`
	Items      json.RawMessage                        `json:"items"`
	Members    map[string]cloudStructuredSmithyMember `json:"members"`
	Member     cloudStructuredSmithyMember            `json:"member"`
	Value      cloudStructuredSmithyMember            `json:"value"`
	Enum       []string                               `json:"enum"`
}

type cloudStructuredSmithyMember struct {
	Target string                     `json:"target"`
	Traits map[string]json.RawMessage `json:"traits"`
}

type cloudStructuredCompiler struct {
	catalog  CloudCatalog
	evidence map[string]bool
	nodes    int
}

func compileCloudStructuredFields(catalog CloudCatalog, contract CloudMappingContract, sources map[string]cloudResolvedField) (map[string]*cloudStructuredPlan, error) {
	plans := map[string]*cloudStructuredPlan{}
	nestedSources := map[string]cloudResolvedField{}
	for _, nested := range contract.Nested {
		for _, field := range nested.Fields {
			if field.StructuredRecipe != nil {
				parent, ok := sources[nested.ParentPointer]
				if !ok {
					return nil, fmt.Errorf("missing selected parent %s", nested.ParentPointer)
				}
				leaves, err := cloudDecompositionLeaves(catalog, parent)
				if err != nil {
					return nil, err
				}
				for key, v := range leaves {
					nestedSources[key] = v
				}
				break
			}
		}
	}
	for _, field := range cloudNeutralProjectionFields(contract) {
		if field.StructuredRecipe == nil {
			continue
		}
		source, ok := sources[field.SourcePointer]
		nestedSource, nested := nestedSources[field.SourcePointer]
		if nested {
			source, ok = nestedSource, true
		}
		if !ok || field.Projection != cloudProjectionStructured || field.StructuredRecipe.Kind == "private" || len(field.StructuredRecipe.EvidenceRefs) == 0 {
			return nil, fmt.Errorf("structured field %s lacks a matching source, projection or evidence", field.SourcePointer)
		}
		c := cloudStructuredCompiler{catalog: catalog, evidence: make(map[string]bool)}
		for _, e := range contract.EvidenceBindings {
			c.evidence[e.ID] = true
		}
		sourceRaw := source.InlineSchema
		// Discovery array properties may also name the item shape. Keep the
		// declared outer collection when its complete inline schema is present.
		if len(sourceRaw) == 0 && source.ShapeID != "" {
			shape, exists := cloudCatalogShape(catalog, source.ShapeID)
			if !exists {
				return nil, fmt.Errorf("structured field %s has no source shape", field.SourcePointer)
			}
			sourceRaw = shape.RawJSON
		}
		if nested {
			if !strings.HasSuffix(field.SourcePointer, "/*") || source.Cardinality != "many" || field.StructuredRecipe.Kind != "list" {
				return nil, fmt.Errorf("nested structured field must denote a retained terminal item collection")
			}
			if len(sourceRaw) == 0 {
				return nil, fmt.Errorf("missing retained leaf item schema")
			}
			var wrapErr error
			sourceRaw, wrapErr = json.Marshal(struct {
				Type  string          `json:"type"`
				Items json.RawMessage `json:"items"`
			}{"array", sourceRaw})
			if wrapErr != nil {
				return nil, fmt.Errorf("invalid retained item schema: %w", wrapErr)
			}
		}
		plan, err := c.compile(field.StructuredRecipe, sourceRaw, 0)
		if err != nil {
			return nil, fmt.Errorf("structured field %s: %w", field.SourcePointer, err)
		}
		if err := validateCloudStructuredOwner(contract.Neutral, field.TargetField, plan); err != nil {
			return nil, fmt.Errorf("structured target %s: %w", field.TargetField, err)
		}
		plan.nestedLeafList = nested
		plans[field.SourcePointer] = plan
	}
	return plans, nil
}

func (c *cloudStructuredCompiler) referenced(id string) (json.RawMessage, error) {
	s, ok := cloudCatalogShape(c.catalog, id)
	if !ok {
		return nil, fmt.Errorf("unknown structured source shape %q", id)
	}
	return s.RawJSON, nil
}

func (c *cloudStructuredCompiler) compile(r *CloudStructuredRule, raw json.RawMessage, depth int) (*cloudStructuredPlan, error) {
	c.nodes++
	if depth > 32 || c.nodes > 8192 || r == nil {
		return nil, fmt.Errorf("invalid or unbounded structured source recipe")
	}
	for _, ref := range r.EvidenceRefs {
		if !c.evidence[ref] {
			return nil, fmt.Errorf("unknown structured evidence reference %q", ref)
		}
	}
	var s cloudStructuredModelShape
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.Ref != "" {
		body, err := c.referenced(s.Ref)
		if err != nil {
			return nil, err
		}
		return c.compile(r, body, depth+1)
	}
	p := &cloudStructuredPlan{kind: r.Kind, sourceType: s.Type, format: s.Format}
	if r.KeyKind != "" {
		if r.Kind != "key_value_entries" || r.KeyKind != "scoped_reference" {
			return nil, fmt.Errorf("invalid dictionary key projection")
		}
		p.keyIsReference = true
	}
	if (len(r.Members) != 0 && r.Kind != "object") || (r.Item != nil && r.Kind != "list" && r.Kind != "key_value_entries") || (len(r.Values) != 0 && r.Kind != "enum") || ((r.ReasonCode != "" || r.Rationale != "") && r.Kind != "private") {
		return nil, fmt.Errorf("unrelated recipe options for %q", r.Kind)
	}
	if len(r.UnobservedMembers) > 0 && r.Kind != "object" {
		return nil, fmt.Errorf("unobserved members require a typed object")
	}
	if (r.KeyMember != "" || r.ValueMember != "") && (r.Kind != "key_value_entries" || s.Type != "list" || r.KeyMember == "" || r.ValueMember == "" || r.KeyMember == r.ValueMember) {
		return nil, fmt.Errorf("key/value members require a declared two-member pair list")
	}
	switch r.Kind {
	case "private":
		if !cloudSemanticPrivateReasons[r.ReasonCode] {
			return nil, fmt.Errorf("unknown private member reason")
		}
		if strings.TrimSpace(r.Rationale) == "" {
			return nil, fmt.Errorf("private member requires a rationale")
		}
	case "object":
		if (s.Type != "structure" && s.Type != "object") || len(s.Additional) > 0 {
			return nil, fmt.Errorf("named source object required")
		}
		if len(r.Members) == 0 || len(r.Members) != len(s.Properties)+len(s.Members) {
			return nil, fmt.Errorf("source object member roster is incomplete")
		}
		sources, targets := map[string]bool{}, map[string]bool{}
		for _, m := range r.Members {
			if m.Source == "" || sources[m.Source] || (m.Rule.Kind == "private") != (m.Target == "") || (m.Target != "" && targets[m.Target]) {
				return nil, fmt.Errorf("ambiguous structured member %q", m.Source)
			}
			sources[m.Source] = true
			if m.Target != "" {
				targets[m.Target] = true
			}
			childRaw := s.Properties[m.Source]
			wire := m.Source
			if sm, ok := s.Members[m.Source]; ok {
				var err error
				childRaw, err = c.referenced(sm.Target)
				if err != nil {
					return nil, err
				}
				wire = cloudSmithyWireMemberName(m.Source, sm.Traits)
			}
			if len(childRaw) == 0 {
				return nil, fmt.Errorf("unknown structured source member %q", m.Source)
			}
			node, err := c.compile(&m.Rule, childRaw, depth+1)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", m.Source, err)
			}
			if sm, ok := s.Members[m.Source]; ok && sm.Traits["smithy.api#xmlFlattened"] != nil {
				node.itemWire = ""
			}
			absent, null := m.OnAbsent, m.OnNull
			if absent == "" {
				absent = "not_observed"
			}
			if null == "" {
				null = "refuse"
			}
			switch absent {
			case "not_observed", "absent", "unknown", "refuse":
			default:
				return nil, fmt.Errorf("invalid missing-member policy for %s", m.Source)
			}
			switch null {
			case "refuse", "unknown", "absent", "null":
			default:
				return nil, fmt.Errorf("invalid null-member policy for %s", m.Source)
			}
			if m.Target == "" && (m.OnAbsent != "" || m.OnNull != "") {
				return nil, fmt.Errorf("private source member cannot declare output presence")
			}
			p.members = append(p.members, cloudStructuredMemberPlan{m.Source, wire, m.Target, absent, null, node})
		}
		for _, name := range r.UnobservedMembers {
			if name == "" || targets[name] {
				return nil, fmt.Errorf("ambiguous unobserved member %q", name)
			}
			targets[name] = true
			p.unobserved = append(p.unobserved, name)
		}
		if len(targets) == len(p.unobserved) {
			return nil, fmt.Errorf("structured object emits no neutral members")
		}
	case "list", "key_value_entries":
		item := s.Items
		if r.Kind == "list" {
			if s.Type != "list" && s.Type != "array" {
				return nil, fmt.Errorf("source list required")
			}
			if s.Member.Target != "" {
				var err error
				item, err = c.referenced(s.Member.Target)
				if err != nil {
					return nil, err
				}
				p.itemWire = cloudSmithyWireMemberName("item", s.Member.Traits)
			}
		} else if s.Type == "list" && r.KeyMember != "" {
			pairRaw, err := c.referenced(s.Member.Target)
			if err != nil {
				return nil, err
			}
			var pair cloudStructuredModelShape
			if err := json.Unmarshal(pairRaw, &pair); err != nil {
				return nil, err
			}
			key, hasKey := pair.Members[r.KeyMember]
			value, hasValue := pair.Members[r.ValueMember]
			if pair.Type != "structure" || len(pair.Members) != 2 || !hasKey || !hasValue {
				return nil, fmt.Errorf("source list lacks closed key/value pair")
			}
			k, err := c.referenced(key.Target)
			if err != nil {
				return nil, err
			}
			var keyShape cloudStructuredModelShape
			if json.Unmarshal(k, &keyShape) != nil || keyShape.Type != "string" {
				return nil, fmt.Errorf("dictionary key must be string")
			}
			item, err = c.referenced(value.Target)
			if err != nil {
				return nil, err
			}
			p.keyMember, p.valueMember = r.KeyMember, r.ValueMember
			p.itemWire = cloudSmithyWireMemberName("item", s.Member.Traits)
			p.keyWire, p.valueWire = cloudSmithyWireMemberName(r.KeyMember, key.Traits), cloudSmithyWireMemberName(r.ValueMember, value.Traits)
		} else {
			if s.Type != "object" || len(s.Additional) == 0 || len(s.Properties) != 0 {
				return nil, fmt.Errorf("typed Discovery dictionary required")
			}
			item = s.Additional
		}
		if r.Item == nil || r.Item.Kind == "private" {
			return nil, fmt.Errorf("typed public collection item required")
		}
		node, err := c.compile(r.Item, item, depth+1)
		if err != nil {
			return nil, err
		}
		p.item = node
	case "string", "utc_instant", "scoped_reference", "enum":
		if s.Type != "string" && s.Type != "timestamp" && s.Type != "enum" && !(r.Kind == "enum" && s.Type == "boolean") {
			return nil, fmt.Errorf("incompatible source type %q", s.Type)
		}
		if r.Kind == "enum" {
			if len(r.Values) == 0 {
				return nil, fmt.Errorf("missing closed enum mapping")
			}
			domain := s.Enum
			if s.Type == "enum" {
				domain = cloudSmithyEnumValues(raw)
			}
			if s.Type == "boolean" {
				domain = []string{"true", "false"}
			}
			if len(domain) != 0 {
				allowed := map[string]bool{}
				for _, key := range domain {
					allowed[key] = true
				}
				for key := range r.Values {
					if !allowed[key] {
						return nil, fmt.Errorf("enum includes non-model value %q", key)
					}
				}
			}
			p.values = r.Values
			for k, v := range r.Values {
				if k == "" || v == "" {
					return nil, fmt.Errorf("empty enum token")
				}
			}
		}
	case "boolean":
		if s.Type != "boolean" {
			return nil, fmt.Errorf("boolean source required")
		}
	case "integer_decimal":
		switch s.Type {
		case "byte", "short", "integer", "long", "bigInteger":
		case "string":
			if s.Format != "int64" && s.Format != "uint64" {
				return nil, fmt.Errorf("documented integer string required")
			}
		default:
			return nil, fmt.Errorf("integer source required")
		}
	default:
		return nil, fmt.Errorf("unrecognized structured mapping kind %q", r.Kind)
	}
	return p, nil
}

func (p *cloudStructuredPlan) project(v any, xml bool, scope string, bindings map[cloudNeutralBindingKey]string) (any, error) {
	switch p.kind {
	case "object":
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected structured source object")
		}
		out := map[string]any{}
		for _, name := range p.unobserved {
			out[name] = map[string]any{"state": "not_observed"}
		}
		known := map[string]bool{}
		for _, m := range p.members {
			key := m.source
			if xml {
				key = m.wire
			}
			known[key] = true
			if m.target == "" {
				continue
			}
			val, present := obj[key]
			if !present {
				if m.onAbsent == "refuse" {
					return nil, fmt.Errorf("required source member %s absent", key)
				}
				out[m.target] = map[string]any{"state": m.onAbsent}
				continue
			}
			if val == nil {
				if m.onNull == "refuse" {
					return nil, fmt.Errorf("source member %s cannot be null", key)
				}
				out[m.target] = map[string]any{"state": m.onNull}
				continue
			}
			projected, err := m.node.project(val, xml, scope, bindings)
			if err != nil {
				return nil, fmt.Errorf("source member %s: %w", key, err)
			}
			out[m.target] = map[string]any{"state": "present", "value": projected}
		}
		for key := range obj {
			if !known[key] {
				return nil, fmt.Errorf("unknown source member %q", key)
			}
		}
		return out, nil
	case "list":
		items, err := p.listItems(v, xml)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(items))
		for i, val := range items {
			t, err := p.item.project(val, xml, scope, bindings)
			if err != nil {
				return nil, fmt.Errorf("item %d: %w", i, err)
			}
			out = append(out, t)
		}
		return out, nil
	case "key_value_entries":
		dict, ok := v.(map[string]any)
		if p.keyMember != "" {
			items, err := p.listItems(v, xml)
			if err != nil {
				return nil, err
			}
			dict = make(map[string]any, len(items))
			k, vName := p.keyMember, p.valueMember
			if xml {
				k, vName = p.keyWire, p.valueWire
			}
			for _, item := range items {
				entry, ok := item.(map[string]any)
				if !ok || len(entry) != 2 {
					return nil, fmt.Errorf("expected a closed key/value entry")
				}
				name, ok := entry[k].(string)
				value, has := entry[vName]
				if !ok || !has {
					return nil, fmt.Errorf("malformed key/value entry")
				}
				if _, dupe := dict[name]; dupe {
					return nil, fmt.Errorf("duplicate dictionary key")
				}
				dict[name] = value
			}
		} else if !ok {
			return nil, fmt.Errorf("source dictionary required")
		}
		if p.keyIsReference {
			resolved := make(map[string]any, len(dict))
			for key, val := range dict {
				ref, exists := bindings[cloudNeutralBindingKey{scope, key}]
				if !exists || ref == "" {
					return nil, fmt.Errorf("missing scoped dictionary key binding")
				}
				if _, duplicate := resolved[ref]; duplicate {
					return nil, fmt.Errorf("ambiguous scoped dictionary key")
				}
				resolved[ref] = val
			}
			dict = resolved
		}
		keys := make([]string, 0, len(dict))
		for k := range dict {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]any, 0, len(keys))
		for _, k := range keys {
			t, err := p.item.project(dict[k], xml, scope, bindings)
			if err != nil {
				return nil, err
			}
			out = append(out, map[string]any{"key": k, "value": t})
		}
		return out, nil
	case "boolean":
		if b, ok := v.(bool); ok {
			return b, nil
		}
		if xml {
			if v == "true" {
				return true, nil
			}
			if v == "false" {
				return false, nil
			}
		}
		return nil, fmt.Errorf("invalid boolean")
	case "integer_decimal":
		var s string
		if xml || p.sourceType == "string" {
			var ok bool
			s, ok = v.(string)
			if !ok {
				return nil, fmt.Errorf("expected integer string")
			}
		} else {
			n, ok := v.(json.Number)
			if !ok {
				return nil, fmt.Errorf("expected integer number")
			}
			s = n.String()
		}
		var n big.Int
		if len(s) > 128 {
			return nil, fmt.Errorf("integer exceeds size bound")
		}
		if _, ok := n.SetString(s, 10); !ok || n.String() != s {
			return nil, fmt.Errorf("noncanonical integer")
		}
		if p.format == "uint64" && !n.IsUint64() || (p.format == "int64" || p.sourceType == "long") && !n.IsInt64() {
			return nil, fmt.Errorf("integer exceeds declared range")
		}
		return s, nil
	case "string", "utc_instant", "scoped_reference", "enum":
		s, ok := v.(string)
		if p.kind == "enum" && p.sourceType == "boolean" && !xml {
			if b, valid := v.(bool); valid {
				s, ok = fmt.Sprint(b), true
			} else {
				return nil, fmt.Errorf("expected boolean enum")
			}
		}
		if !ok {
			return nil, fmt.Errorf("invalid string")
		}
		switch p.kind {
		case "utc_instant":
			if err := validateCloudUTCInstant(s); err != nil {
				return nil, err
			}
		case "scoped_reference":
			ref, ok := bindings[cloudNeutralBindingKey{scope, s}]
			if !ok || ref == "" {
				return nil, fmt.Errorf("unresolved scoped reference")
			}
			return ref, nil
		case "enum":
			neutral, ok := p.values[s]
			if !ok {
				return nil, fmt.Errorf("unknown enum token")
			}
			return neutral, nil
		}
		return s, nil
	default:
		return nil, fmt.Errorf("non-emitting structured node")
	}
}

func (p *cloudStructuredPlan) listItems(v any, xml bool) ([]any, error) {
	if xml && p.itemWire != "" {
		if v == "" {
			return []any{}, nil
		}
		wrapper, ok := v.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return nil, fmt.Errorf("invalid XML list wrapper")
		}
		v, ok = wrapper[p.itemWire]
		if !ok {
			return nil, fmt.Errorf("wrong XML item name")
		}
	}
	if items, ok := v.([]any); ok {
		return items, nil
	}
	if xml && v != nil {
		return []any{v}, nil
	}
	return nil, fmt.Errorf("source list required")
}
