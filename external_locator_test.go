package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestHTMLLocatorRequiresOneAddressableTarget(t *testing.T) {
	policy := ExternalSourceDescriptor{
		ID: "official_articles", ReferenceKind: "https_url_prefix", ReferencePrefix: "https://example.com/docs",
		VersionStableNamePrefix: "official_article_", LocatorKinds: map[string]string{"api_symbol": "html_id_or_name"},
	}
	coord := ArtifactSourceCoordinate{SourceStableReference: "https://example.com/docs/page.html#symbol=Invoice"}
	name, err := canonicalExternalLocatorName("api_symbol", coord, policy, "Invoice")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "exact_id", body: `<div id="Invoice"></div>`},
		{name: "legacy_anchor_name", body: `<a name="Invoice"></a>`},
		{name: "non_anchor_name", body: `<input name="Invoice">`, want: "does not resolve"},
		{name: "duplicate_id", body: `<div id="Invoice"></div><span id="Invoice"></span>`, want: "ambiguous"},
		{name: "id_and_anchor_name", body: `<div id="Invoice"></div><a name="Invoice"></a>`, want: "ambiguous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyHTMLLocator("api_symbol", name, coord, policy, "symbol=Invoice", []byte(tc.body))
			if tc.want == "" && err != nil {
				t.Fatalf("valid target rejected: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestHTMLLocatorParserSafetyPanicBecomesTypedError(t *testing.T) {
	policy := ExternalSourceDescriptor{
		ID: "official_articles", ReferenceKind: "https_url_prefix", ReferencePrefix: "https://example.com/docs",
		VersionStableNamePrefix: "official_article_", LocatorKinds: map[string]string{"api_symbol": "html_id_or_name"},
	}
	coord := ArtifactSourceCoordinate{SourceStableReference: "https://example.com/docs/page.html#symbol=Invoice"}
	name, err := canonicalExternalLocatorName("api_symbol", coord, policy, "Invoice")
	if err != nil {
		t.Fatal(err)
	}
	// x/net/html panics after its bounded open-element stack is exhausted.
	// Upstream bytes must be a normal locator refusal, never a process crash.
	body := []byte(strings.Repeat("<div>", 513) + `<span id="Invoice"></span>`)
	err = verifyHTMLLocator("api_symbol", name, coord, policy, "symbol=Invoice", body)
	if err == nil || (!strings.Contains(err.Error(), "safety bound exceeded") && !strings.Contains(err.Error(), "exceeds 512")) {
		t.Fatalf("deep HTML error=%v, want contained parser-bound refusal", err)
	}
}

func TestLocatorProofUsesDecodedGzipView(t *testing.T) {
	policy := ExternalSourceDescriptor{
		ID: "official_schema", ReferenceKind: "https_url_prefix", ReferencePrefix: "https://example.com/schema",
		VersionStableNamePrefix: "official_schema_", LocatorKinds: map[string]string{"api_symbol": "json_pointer"},
	}
	decoded := []byte(`{"models":{"Invoice":{"name":"Invoice"}}}`)
	var encoded bytes.Buffer
	zw := gzip.NewWriter(&encoded)
	if _, err := zw.Write(decoded); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	coord := ArtifactSourceCoordinate{SourceStableReference: "https://example.com/schema/entities.json#/models/Invoice"}
	name, err := canonicalExternalLocatorName("api_symbol", coord, policy, "Invoice")
	if err != nil {
		t.Fatal(err)
	}
	receipt := verifiedExternalSourceReceipt{Body: encoded.Bytes(), LocatorBody: decoded, ContentCoding: "gzip"}
	if err := verifyExternalObjectLocator("api_symbol", name, coord, policy, receipt); err != nil {
		t.Fatalf("gzip decoded locator view rejected: %v", err)
	}
}

func TestAddressedReferencePageNameIsCoordinateDerived(t *testing.T) {
	policy := ExternalSourceDescriptor{
		ID: "official_docs", ReferenceKind: "https_url_prefix", ReferencePrefix: "https://example.com/docs",
		VersionStableNamePrefix: "official_docs_", LocatorKinds: map[string]string{"reference_page": "html_id_or_name"},
	}
	coord := ArtifactSourceCoordinate{SourceStableReference: "https://example.com/docs/invoice.html#anchor=overview"}
	want, err := canonicalExternalLocatorName("reference_page", coord, policy, "overview")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`<section id="overview"></section>`)
	if err := verifyHTMLLocator("reference_page", want, coord, policy, "anchor=overview", body); err != nil {
		t.Fatal(err)
	}
	if err := verifyHTMLLocator("reference_page", "official_docs_caller_alias", coord, policy, "anchor=overview", body); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("caller alias accepted: %v", err)
	}
}

func TestNonGranularExternalLocatorsFailClosedWithoutAuthenticityContract(t *testing.T) {
	cases := []struct {
		name   string
		kind   string
		body   []byte
		policy ExternalSourceDescriptor
	}{
		{name: "resource_root_soft_404", kind: "external_reference_doc", body: []byte("soft 404"), policy: ExternalSourceDescriptor{ID: "root", ReferenceKind: "https_url_prefix", ReferencePrefix: "https://docs.example/", LocatorKinds: map[string]string{"external_reference_doc": "resource_root"}}},
		{name: "html_login_shell", kind: "reference_page", body: []byte("<html><title>Sign in</title></html>"), policy: ExternalSourceDescriptor{ID: "html", ReferenceKind: "https_url_prefix", ReferencePrefix: "https://docs.example/", LocatorKinds: map[string]string{"reference_page": "html_id_or_name"}}},
		{name: "json_error_shell", kind: "reference_page", body: []byte(`{"error":"consent_required"}`), policy: ExternalSourceDescriptor{ID: "json", ReferenceKind: "https_url_prefix", ReferencePrefix: "https://docs.example/", LocatorKinds: map[string]string{"reference_page": "json_pointer"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coord := ArtifactSourceCoordinate{SourceStableReference: "https://docs.example/page"}
			receipt := verifiedExternalSourceReceipt{Body: tc.body, ByteLength: int64(len(tc.body))}
			err := verifyExternalObjectLocator(tc.kind, "caller_chosen_name", coord, tc.policy, receipt)
			if !errors.Is(err, ErrOODGraphExternalNonGranularProofUnavailable) {
				t.Fatalf("non-granular locator error=%v, want typed authenticity refusal", err)
			}
		})
	}
}

func TestJSONPointerLocatorBindsAPISymbolNameToExactBytes(t *testing.T) {
	policy := ExternalSourceDescriptor{
		ID:                      "quickbooks_online_static_api_corpus",
		ReferenceKind:           "https_url_prefix",
		ReferencePrefix:         "https://static.developer.intuit.com/JSONObjects",
		VersionStableNamePrefix: "quickbooks_online_api_",
		LocatorKinds:            map[string]string{"api_symbol": "json_pointer"},
	}
	body := []byte(`{"entities":{"Invoice":{"name":"Invoice"}}}`)
	receipt := verifiedExternalSourceReceipt{Body: body, ByteLength: int64(len(body))}
	coord := ArtifactSourceCoordinate{SourceStableReference: "https://static.developer.intuit.com/JSONObjects/EntityJsonObject_v1.json#/entities/Invoice"}
	canonicalName, err := canonicalExternalLocatorName("api_symbol", coord, policy, "Invoice")
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyExternalObjectLocator("api_symbol", canonicalName, coord, policy, receipt); err != nil {
		t.Fatalf("verified JSON symbol rejected: %v", err)
	}
	badPointer := coord
	badPointer.SourceStableReference = "https://static.developer.intuit.com/JSONObjects/EntityJsonObject_v1.json#/entities/Missing"
	if err := verifyExternalObjectLocator("api_symbol", "quickbooks_online_api_missing", badPointer, policy, receipt); err == nil || !strings.Contains(err.Error(), "does not resolve") {
		t.Fatalf("missing JSON symbol error=%v", err)
	}
	if err := verifyExternalObjectLocator("api_symbol", "quickbooks_online_api_customer", coord, policy, receipt); err == nil || !strings.Contains(err.Error(), "does not match verified upstream locator coordinate") {
		t.Fatalf("caller-authored symbol mismatch error=%v", err)
	}
}

func TestHTMLLocatorRequiresAddressableFragmentForGranularObject(t *testing.T) {
	policy := ExternalSourceDescriptor{
		ID:                      "quickbooks_online_static_articles",
		ReferenceKind:           "https_url_prefix",
		ReferencePrefix:         "https://static.developer.intuit.com/output_html/qbo",
		VersionStableNamePrefix: "quickbooks_online_article_",
		LocatorKinds:            map[string]string{"code_example": "html_id_or_name"},
	}
	body := []byte(`<html><body><pre id="create-invoice">...</pre></body></html>`)
	receipt := verifiedExternalSourceReceipt{Body: body, ByteLength: int64(len(body))}
	withoutFragment := ArtifactSourceCoordinate{SourceStableReference: "https://static.developer.intuit.com/output_html/qbo/invoice.html"}
	if err := verifyExternalObjectLocator("code_example", "quickbooks_online_article_create_invoice", withoutFragment, policy, receipt); err == nil || !strings.Contains(err.Error(), "requires an addressable HTML locator") {
		t.Fatalf("fragmentless code example error=%v", err)
	}
	withFragment := withoutFragment
	withFragment.SourceStableReference += "#anchor=create-invoice"
	canonicalName, err := canonicalExternalLocatorName("code_example", withFragment, policy, "create-invoice")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyExternalObjectLocator("code_example", canonicalName, withFragment, policy, receipt); err != nil {
		t.Fatalf("addressable code example rejected: %v", err)
	}
}

func TestJSONPointerLocatorIdentityDisambiguatesDuplicateLeafNamesByFullPointer(t *testing.T) {
	policy := ExternalSourceDescriptor{
		ID: "quickbooks_online_static_api_corpus", ReferenceKind: "https_url_prefix",
		ReferencePrefix: "https://static.developer.intuit.com/JSONObjects", VersionStableNamePrefix: "quickbooks_online_api_",
		LocatorKinds: map[string]string{"api_symbol": "json_pointer"},
	}
	body := []byte(`{"models":{"Invoice":{"properties":{"Id":{"type":"string"}}},"Customer":{"properties":{"Id":{"type":"string"}}}}}`)
	receipt := verifiedExternalSourceReceipt{Body: body, ByteLength: int64(len(body))}
	invoice := ArtifactSourceCoordinate{SourceStableReference: policy.ReferencePrefix + "/EntityJsonObject_v1.json#/models/Invoice/properties/Id"}
	customer := ArtifactSourceCoordinate{SourceStableReference: policy.ReferencePrefix + "/EntityJsonObject_v1.json#/models/Customer/properties/Id"}
	invoiceName, err := canonicalExternalLocatorName("api_symbol", invoice, policy, "Id")
	if err != nil {
		t.Fatal(err)
	}
	customerName, err := canonicalExternalLocatorName("api_symbol", customer, policy, "Id")
	if err != nil {
		t.Fatal(err)
	}
	if invoiceName == customerName {
		t.Fatalf("duplicate leaf Id collapsed across full JSON Pointers: %q", invoiceName)
	}
	if err := verifyExternalObjectLocator("api_symbol", invoiceName, invoice, policy, receipt); err != nil {
		t.Fatal(err)
	}
	if err := verifyExternalObjectLocator("api_symbol", customerName, customer, policy, receipt); err != nil {
		t.Fatal(err)
	}
}

func TestHTMLLocatorIdentityDisambiguatesSameAnchorAcrossResources(t *testing.T) {
	policy := ExternalSourceDescriptor{
		ID: "quickbooks_online_static_articles", ReferenceKind: "https_url_prefix",
		ReferencePrefix: "https://static.developer.intuit.com/output_html/qbo", VersionStableNamePrefix: "quickbooks_online_article_",
		LocatorKinds: map[string]string{"api_symbol": "html_id_or_name"},
	}
	body := []byte(`<html><body><span id="Id">Id</span></body></html>`)
	receipt := verifiedExternalSourceReceipt{Body: body, ByteLength: int64(len(body))}
	invoice := ArtifactSourceCoordinate{SourceStableReference: policy.ReferencePrefix + "/invoice.html#symbol=Id"}
	customer := ArtifactSourceCoordinate{SourceStableReference: policy.ReferencePrefix + "/customer.html#symbol=Id"}
	invoiceName, err := canonicalExternalLocatorName("api_symbol", invoice, policy, "Id")
	if err != nil {
		t.Fatal(err)
	}
	customerName, err := canonicalExternalLocatorName("api_symbol", customer, policy, "Id")
	if err != nil {
		t.Fatal(err)
	}
	if invoiceName == customerName {
		t.Fatalf("same HTML anchor collapsed across resource paths: %q", invoiceName)
	}
	if err := verifyExternalObjectLocator("api_symbol", invoiceName, invoice, policy, receipt); err != nil {
		t.Fatal(err)
	}
	if err := verifyExternalObjectLocator("api_symbol", customerName, customer, policy, receipt); err != nil {
		t.Fatal(err)
	}
	if err := verifyExternalObjectLocator("api_symbol", invoiceName, customer, policy, receipt); err == nil {
		t.Fatal("canonical name from one HTML resource was accepted for the same anchor on another page")
	}
}

func TestHTMLAPISymbolRejectsIncidentalTextWithoutAddressableAnchor(t *testing.T) {
	policy := ExternalSourceDescriptor{
		ID: "official_static_articles", ReferenceKind: "https_url_prefix",
		ReferencePrefix: "https://example.com/docs", VersionStableNamePrefix: "official_api_",
		LocatorKinds: map[string]string{"api_symbol": "html_id_or_name"},
	}
	coord := ArtifactSourceCoordinate{SourceStableReference: policy.ReferencePrefix + "/invoice.html#symbol=Invoice"}
	canonicalName, err := canonicalExternalLocatorName("api_symbol", coord, policy, "Invoice")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`<html><body><p>The Invoice symbol is discussed here.</p><span>Invoice</span></body></html>`)
	receipt := verifiedExternalSourceReceipt{Body: body, ByteLength: int64(len(body))}
	if err := verifyExternalObjectLocator("api_symbol", canonicalName, coord, policy, receipt); err == nil || !strings.Contains(err.Error(), "does not resolve") {
		t.Fatalf("incidental HTML text error=%v, want non-addressable locator refusal", err)
	}
}

func TestDecodeSingleJSONRejectsDuplicateObjectKeysAtEveryDepth(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "root", body: `{"models":{},"models":{"Invoice":{}}}`},
		{name: "nested", body: `{"models":{"Invoice":{"Id":1,"Id":2}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var decoded interface{}
			err := decodeSingleJSON([]byte(tc.body), &decoded)
			if err == nil || !strings.Contains(err.Error(), "duplicate field") {
				t.Fatalf("decodeSingleJSON error=%v, want duplicate-key refusal", err)
			}
		})
	}

	var decoded interface{}
	if err := decodeSingleJSON([]byte(`{"value":9007199254740993}`), &decoded); err != nil {
		t.Fatal(err)
	}
	number, ok := decoded.(map[string]interface{})["value"].(json.Number)
	if !ok || number.String() != "9007199254740993" {
		t.Fatalf("semantic decode did not preserve json.Number: %#v", decoded)
	}
}

func TestJSONPointerArrayIndexRejectsSignedAndLeadingZeroAliases(t *testing.T) {
	root := map[string]interface{}{"items": []interface{}{"zero", "one"}}
	for _, pointer := range []string{"/items/0", "/items/1"} {
		if _, _, err := resolveJSONPointer(root, pointer); err != nil {
			t.Fatalf("canonical pointer %q rejected: %v", pointer, err)
		}
	}
	for _, pointer := range []string{"/items/+0", "/items/-0", "/items/00", "/items/+1", "/items/01", "/items/1.0"} {
		if _, _, err := resolveJSONPointer(root, pointer); err == nil {
			t.Fatalf("noncanonical array-index alias %q resolved", pointer)
		}
	}

	policy := ExternalSourceDescriptor{
		ID: "official_static_api_corpus", ReferenceKind: "https_url_prefix",
		ReferencePrefix: "https://example.com/schema", VersionStableNamePrefix: "official_api_",
		LocatorKinds: map[string]string{"api_symbol": "json_pointer"},
	}
	body := []byte(`{"items":[{"name":"zero"}]}`)
	receipt := verifiedExternalSourceReceipt{Body: body, LocatorBody: body, ByteLength: int64(len(body)), DecodedByteLength: int64(len(body))}
	for _, alias := range []string{"+0", "-0", "00"} {
		coord := ArtifactSourceCoordinate{SourceStableReference: policy.ReferencePrefix + "/objects.json#/items/" + alias}
		if err := verifyExternalObjectLocator("api_symbol", "official_api_alias", coord, policy, receipt); err == nil || !strings.Contains(err.Error(), "does not resolve") {
			t.Fatalf("locator alias %q error=%v, want resolution refusal", alias, err)
		}
	}
}

func TestJSONPointerIdentityDoesNotChangeWithPointedReadableValue(t *testing.T) {
	policy := ExternalSourceDescriptor{
		ID: "official_static_api_corpus", ReferenceKind: "https_url_prefix",
		ReferencePrefix: "https://example.com/schema", VersionStableNamePrefix: "official_api_",
		LocatorKinds: map[string]string{"api_symbol": "json_pointer"},
	}
	coord := ArtifactSourceCoordinate{SourceStableReference: policy.ReferencePrefix + "/objects.json#/models/current"}
	stableName, err := canonicalExternalLocatorName("api_symbol", coord, policy, "current")
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{
		[]byte(`{"models":{"current":{"name":"Invoice"}}}`),
		[]byte(`{"models":{"current":{"name":"Bill"}}}`),
	} {
		receipt := verifiedExternalSourceReceipt{Body: body, LocatorBody: body, ByteLength: int64(len(body)), DecodedByteLength: int64(len(body))}
		if err := verifyExternalObjectLocator("api_symbol", stableName, coord, policy, receipt); err != nil {
			t.Fatalf("stable pointer identity changed with pointed value: %v", err)
		}
	}
	mutableValueName, err := canonicalExternalLocatorName("api_symbol", coord, policy, "Invoice")
	if err != nil {
		t.Fatal(err)
	}
	if mutableValueName == stableName {
		t.Fatal("test fixture failed to distinguish pointer token from mutable readable value")
	}
	if err := verifyExternalObjectLocator("api_symbol", mutableValueName, coord, policy, verifiedExternalSourceReceipt{Body: []byte(`{"models":{"current":{"name":"Invoice"}}}`)}); err == nil {
		t.Fatal("pointed readable value was accepted as stable locator identity")
	}
}
