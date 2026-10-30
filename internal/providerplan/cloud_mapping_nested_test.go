package providerplan

import "testing"

func TestCloudNestedLeavesDeriveSmithyXMLWirePointers(t *testing.T) {
	catalog := CloudCatalog{SchemaShapes: []CloudCatalogSchemaShape{
		{ID: "State", RawJSON: []byte(`{"type":"structure","members":{"Name":{"target":"Text","traits":{"smithy.api#xmlName":"name"}}}}`)},
		{ID: "Text", RawJSON: []byte(`{"type":"string"}`)},
	}}
	leaves, err := cloudNestedLeaves(catalog, "State", "/State", "/instanceState", "one", 0, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	leaf := leaves["/State/Name"]
	if leaf.WirePointer != "/instanceState/name" || leaf.ValueType != "string" {
		t.Fatalf("wrong retained XML pointer: %#v", leaf)
	}
}

func TestCloudNestedLeavesKeepListCardinalityAndXMLItemWrapper(t *testing.T) {
	catalog := CloudCatalog{SchemaShapes: []CloudCatalogSchemaShape{
		{ID: "Attachments", RawJSON: []byte(`{"type":"list","member":{"target":"Attachment","traits":{"smithy.api#xmlName":"item"}}}`)},
		{ID: "Attachment", RawJSON: []byte(`{"type":"structure","members":{"InstanceId":{"target":"Text","traits":{"smithy.api#xmlName":"instanceId"}}}}`)},
		{ID: "Text", RawJSON: []byte(`{"type":"string"}`)},
	}}
	leaves, err := cloudNestedLeaves(catalog, "Attachments", "/Attachments", "/attachmentSet", "many", 0, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	leaf := leaves["/Attachments/*/InstanceId"]
	if leaf.WirePointer != "/attachmentSet/item/instanceId" || leaf.Cardinality != "many" {
		t.Fatalf("wrong retained list leaf: %#v", leaf)
	}
}
