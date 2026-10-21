package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// verifyExternalObjectLocator proves that a granular external graph object
// resolves inside the exact canonical bytes whose digest is stored. The
// parser receives the verified in-memory copy after those same bytes have
// been durably archived; OODGraph rows retain only coordinates and digests.
func verifyExternalObjectLocator(objectClass, canonicalName string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor, receipt verifiedExternalSourceReceipt) error {
	locatorKind, ok := policy.LocatorKinds[objectClass]
	if !ok {
		return fmt.Errorf("external source %q has no locator policy for object class %q", policy.ID, objectClass)
	}
	if locatorKind == "code_graph_coordinate" {
		return fmt.Errorf("external object class %q requires a trusted code-graph coordinate resolver; an HTTP page digest cannot prove a code symbol", objectClass)
	}
	u, err := parseCanonicalHTTPSReference(coord.SourceStableReference)
	if err != nil {
		return fmt.Errorf("external locator reference: %w", err)
	}
	fragment := u.Fragment
	// Locator proof operates on the bounded, integrity-checked decoded view.
	// Body remains the exact raw wire representation used for the durable
	// content digest; parsing it would fail for a content-coded response and
	// would prove a different representation than the one the receipt names.
	locatorBody := receipt.LocatorBody
	if locatorBody == nil {
		if receipt.ContentCoding != "" {
			return fmt.Errorf("external locator receipt is missing its decoded locator view")
		}
		// Unit-level callers predating content-coding receipts provide only
		// Body. Production receipts always set LocatorBody.
		locatorBody = receipt.Body
	}
	switch locatorKind {
	case "resource_root":
		if fragment != "" {
			return fmt.Errorf("external object class %q uses resource_root locator policy and must not carry a URL fragment", objectClass)
		}
		if len(locatorBody) == 0 {
			return fmt.Errorf("external resource root is empty")
		}
		if receipt.Authorization.RepresentationDeclarationID == "" || receipt.Authorization.RepresentationDeclarationDigest == "" || receipt.Authorization.PermissionContentClass == "" || receipt.Authorization.SourceRepresentationKind == "" {
			return fmt.Errorf("%w: object_class=%q locator_kind=resource_root requires an admitted exact representation declaration and content class; a nonempty 2xx body is insufficient", ErrOODGraphExternalNonGranularProofUnavailable, objectClass)
		}
		wantName, err := canonicalExternalLocatorName(objectClass, coord, policy, policy.ID+"_resource_root")
		if err != nil {
			return err
		}
		if canonicalName != wantName {
			return fmt.Errorf("external canonical name %q does not match the authority-bound resource-root coordinate (want %q)", canonicalName, wantName)
		}
		return nil
	case "html_id_or_name":
		return verifyHTMLLocator(objectClass, canonicalName, coord, policy, fragment, locatorBody)
	case "json_pointer":
		return verifyJSONPointerLocator(objectClass, canonicalName, coord, policy, fragment, locatorBody)
	default:
		return fmt.Errorf("external source %q locator policy %q is unsupported", policy.ID, locatorKind)
	}
}

func granularExternalClass(class string) bool {
	switch class {
	case "api_symbol", "code_example", "release_note", "code_symbol_ref":
		return true
	default:
		return false
	}
}

// preflightExternalLocatorAdmission rejects locator dependencies that the
// current runtime/protocol cannot prove, before any upstream request occurs.
// It does not claim the referenced locator resolves; exact-byte resolution
// remains verifyExternalObjectLocator's job after a justified fetch.
func preflightExternalLocatorAdmission(objectClass string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor) error {
	locatorKind, ok := policy.LocatorKinds[objectClass]
	if !ok {
		return fmt.Errorf("external source %q has no locator policy for object class %q", policy.ID, objectClass)
	}
	u, err := parseCanonicalHTTPSReference(coord.SourceStableReference)
	if err != nil {
		return fmt.Errorf("external locator reference: %w", err)
	}
	switch locatorKind {
	case "resource_root":
		if u.Fragment != "" {
			return fmt.Errorf("external object class %q uses resource_root locator policy and must not carry a URL fragment", objectClass)
		}
		// The admitted authorization result later binds the representation
		// declaration, media/content class, and exact locator before I/O.
		return nil
	case "code_graph_coordinate":
		return fmt.Errorf("external object class %q requires a trusted code-graph coordinate resolver; HTTP retrieval cannot satisfy that adapter dependency", objectClass)
	case "html_id_or_name", "json_pointer":
		if u.Fragment == "" {
			if granularExternalClass(objectClass) {
				return fmt.Errorf("external object class %q requires an addressable %s fragment", objectClass, locatorKind)
			}
			return fmt.Errorf("%w: object_class=%q locator_kind=%s has no exact addressable locator or descriptor-owned content marker", ErrOODGraphExternalNonGranularProofUnavailable, objectClass, locatorKind)
		}
		return nil
	default:
		return fmt.Errorf("external source %q locator policy %q is unsupported", policy.ID, locatorKind)
	}
}

// HTML coordinates use one closed fragment grammar:
//   - api_symbol: #symbol=<exact id-or-name attribute>
//   - other addressable fragments: #anchor=<exact id-or-name attribute>
//
// Both spellings resolve only an upstream-addressable DOM id/name. Incidental
// text is not an authoritative locator and cannot mint a granular graph node.
func verifyHTMLLocator(objectClass, canonicalName string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor, fragment string, body []byte) error {
	if fragment == "" {
		if granularExternalClass(objectClass) {
			return fmt.Errorf("external object class %q requires an addressable HTML locator fragment", objectClass)
		}
		if len(body) == 0 {
			return fmt.Errorf("external HTML resource is empty")
		}
		return fmt.Errorf("%w: object_class=%q locator_kind=html_id_or_name has no exact addressable locator or descriptor-owned content marker", ErrOODGraphExternalNonGranularProofUnavailable, objectClass)
	}
	prefix := "anchor="
	if objectClass == "api_symbol" {
		prefix = "symbol="
	}
	if !strings.HasPrefix(fragment, prefix) || len(fragment) == len(prefix) {
		return fmt.Errorf("external %s locator fragment must use %q", objectClass, prefix+"<value>")
	}
	locator := fragment[len(prefix):]
	if !utf8.ValidString(locator) || len(locator) > 1024 || strings.TrimSpace(locator) != locator {
		return fmt.Errorf("external HTML locator must be canonical UTF-8 within 1024 bytes")
	}
	doc, err := parseBoundedHTMLDocument(body)
	if err != nil {
		return fmt.Errorf("parse exact external HTML bytes: %w", err)
	}
	matches := 0
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			matchedTarget := false
			for _, attr := range n.Attr {
				// HTML fragment targets are exact id attributes on any element,
				// plus the historical addressable <a name> form. A form/input
				// name is not a fragment target and cannot prove a graph symbol.
				if attr.Val == locator && (attr.Key == "id" || (attr.Key == "name" && n.DataAtom == atom.A)) {
					matchedTarget = true
				}
			}
			if matchedTarget {
				matches++
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if matches == 0 {
		return fmt.Errorf("external HTML locator %q does not resolve in the exact fetched bytes", locator)
	}
	if matches != 1 {
		return fmt.Errorf("external HTML locator %q is ambiguous in the exact fetched bytes: %d addressable targets", locator, matches)
	}
	// Every addressable external locator owns its name, including a
	// fragment-addressed reference_page. Otherwise two caller aliases for the
	// same exact page#fragment mint distinct version coordinates/object IDs.
	if err := verifyCanonicalNameMatchesLocatorCoordinate(objectClass, canonicalName, coord, policy, locator); err != nil {
		return err
	}
	return nil
}

func parseBoundedHTMLDocument(body []byte) (doc *html.Node, err error) {
	// x/net/html intentionally panics when an adversarial document drives its
	// open-element stack beyond the parser's fixed bound. Upstream bytes must
	// become a typed locator refusal, never crash the MCP process.
	defer func() {
		if recovered := recover(); recovered != nil {
			doc = nil
			err = fmt.Errorf("HTML parser safety bound exceeded: %v", recovered)
		}
	}()
	return html.Parse(bytes.NewReader(body))
}

func verifyJSONPointerLocator(objectClass, canonicalName string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor, fragment string, body []byte) error {
	if fragment == "" {
		if granularExternalClass(objectClass) {
			return fmt.Errorf("external object class %q requires a JSON Pointer URL fragment", objectClass)
		}
		var root interface{}
		if err := decodeSingleJSON(body, &root); err != nil {
			return fmt.Errorf("parse exact external JSON bytes: %w", err)
		}
		return fmt.Errorf("%w: object_class=%q locator_kind=json_pointer has no exact pointer or descriptor-owned content marker", ErrOODGraphExternalNonGranularProofUnavailable, objectClass)
	}
	if !strings.HasPrefix(fragment, "/") {
		return fmt.Errorf("external JSON locator fragment %q is not an RFC 6901 JSON Pointer", fragment)
	}
	var root interface{}
	if err := decodeSingleJSON(body, &root); err != nil {
		return fmt.Errorf("parse exact external JSON bytes: %w", err)
	}
	_, terminal, err := resolveJSONPointer(root, fragment)
	if err != nil {
		return fmt.Errorf("external JSON Pointer %q does not resolve: %w", fragment, err)
	}
	// The pointed value proves only that the address exists in these exact
	// bytes. Stable graph identity comes from the canonical RFC 6901 pointer,
	// never mutable readable fields inside the pointed value. The full pointer
	// is already hashed by canonicalExternalLocatorName; its terminal token is
	// only a readable prefix.
	if err := verifyCanonicalNameMatchesLocatorCoordinate(objectClass, canonicalName, coord, policy, terminal); err != nil {
		return err
	}
	return nil
}

func decodeSingleJSON(body []byte, out interface{}) error {
	if err := rejectDuplicateJSONKeysRecursive(body, "external_json"); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err == nil {
		return fmt.Errorf("multiple JSON values")
	} else if err != io.EOF {
		return err
	}
	return nil
}

func resolveJSONPointer(root interface{}, pointer string) (interface{}, string, error) {
	current := root
	terminal := ""
	for _, raw := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		token, err := decodeJSONPointerToken(raw)
		if err != nil {
			return nil, "", err
		}
		terminal = token
		switch node := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = node[token]
			if !ok {
				return nil, "", fmt.Errorf("object key %q absent", token)
			}
		case []interface{}:
			index, err := canonicalJSONArrayIndex(token)
			if err != nil || index >= len(node) {
				return nil, "", fmt.Errorf("array index %q invalid", token)
			}
			current = node[index]
		default:
			return nil, "", fmt.Errorf("cannot descend through %T", current)
		}
	}
	return current, terminal, nil
}

// canonicalJSONArrayIndex enforces RFC 6901 §4's exact array-index ABNF:
// "0" or a non-zero ASCII digit followed only by ASCII digits. strconv.Atoi
// alone accepts signed aliases such as +0 and -0, which would let multiple
// raw pointer fragments name the same array element and mint distinct graph
// identities for one locator target.
func canonicalJSONArrayIndex(token string) (int, error) {
	if token == "0" {
		return 0, nil
	}
	if token == "" || token[0] < '1' || token[0] > '9' {
		return 0, fmt.Errorf("not a canonical JSON Pointer array index")
	}
	for i := 1; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return 0, fmt.Errorf("not a canonical JSON Pointer array index")
		}
	}
	index, err := strconv.Atoi(token)
	if err != nil {
		return 0, fmt.Errorf("JSON Pointer array index overflows int: %w", err)
	}
	return index, nil
}

func decodeJSONPointerToken(raw string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '~' {
			b.WriteByte(raw[i])
			continue
		}
		if i+1 >= len(raw) {
			return "", fmt.Errorf("invalid JSON Pointer escape in %q", raw)
		}
		i++
		switch raw[i] {
		case '0':
			b.WriteByte('~')
		case '1':
			b.WriteByte('/')
		default:
			return "", fmt.Errorf("invalid JSON Pointer escape in %q", raw)
		}
	}
	return b.String(), nil
}

func verifyCanonicalNameMatchesLocatorCoordinate(objectClass, canonicalName string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor, locator string) error {
	want, err := canonicalExternalLocatorName(objectClass, coord, policy, locator)
	if err != nil {
		return err
	}
	if canonicalName != want {
		return fmt.Errorf("external canonical name %q does not match verified upstream locator coordinate for %q (want %q)", canonicalName, locator, want)
	}
	return nil
}

func canonicalExternalLocatorName(objectClass string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor, locator string) (string, error) {
	if !strings.HasPrefix(coord.SourceStableReference, policy.ReferencePrefix) {
		return "", fmt.Errorf("external locator reference %q does not use registered prefix %q", coord.SourceStableReference, policy.ReferencePrefix)
	}
	resource, err := externalResourceReference(coord.SourceStableReference, policy)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(resource, policy.ReferencePrefix) {
		return "", fmt.Errorf("external locator resource %q does not use registered prefix %q", resource, policy.ReferencePrefix)
	}
	relativeResource := strings.TrimPrefix(resource, policy.ReferencePrefix)
	if relativeResource == "" {
		relativeResource = "/"
	}
	rawFragment := ""
	if index := strings.IndexByte(coord.SourceStableReference, '#'); index >= 0 {
		rawFragment = coord.SourceStableReference[index+1:]
	}
	locatorKind := policy.LocatorKinds[objectClass]
	framed := fmt.Sprintf("%d:%s|%d:%s|%d:%s|%d:%s",
		len(objectClass), objectClass,
		len(locatorKind), locatorKind,
		len(relativeResource), relativeResource,
		len(rawFragment), rawFragment,
	)
	sum := sha256.Sum256([]byte(framed))
	readable := locatorSnakeCase(locator)
	if len(readable) > 128 {
		readable = strings.Trim(readable[:128], "_")
	}
	if readable == "" {
		readable = "locator"
	}
	name := policy.VersionStableNamePrefix + readable + "_at_sha256_" + hex.EncodeToString(sum[:])
	if len(name) > 1024 || !snakeCaseKeyPattern.MatchString(name) {
		return "", fmt.Errorf("external locator-derived canonical name is outside the 1024-byte lowercase snake_case boundary")
	}
	return name, nil
}

func locatorSnakeCase(value string) string {
	var out []rune
	var prior rune
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if unicode.IsUpper(r) && len(out) > 0 && (unicode.IsLower(prior) || unicode.IsDigit(prior)) && out[len(out)-1] != '_' {
				out = append(out, '_')
			}
			out = append(out, unicode.ToLower(r))
			prior = r
			continue
		}
		if len(out) > 0 && out[len(out)-1] != '_' {
			out = append(out, '_')
		}
		prior = r
	}
	return strings.Trim(string(out), "_")
}
