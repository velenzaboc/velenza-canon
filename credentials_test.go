package main

import (
	"reflect"
	"testing"
)

func TestGoogleCredentialSelectorIsProcessLevelOnly(t *testing.T) {
	typ := reflect.TypeOf(SpecGraphConfig{})
	field, ok := typ.FieldByName("GoogleCredentials")
	if !ok || field.Tag.Get("json") != "google_credentials" {
		t.Fatalf("SpecGraphConfig must expose exactly one google_credentials selector, got field=%+v present=%v", field, ok)
	}
	for _, forbidden := range []string{"CredentialsFile", "CredentialsSource", "CredentialsProfile", "CredentialsIdentity"} {
		if field, ok := typ.FieldByName(forbidden); ok {
			t.Fatalf("SpecGraphConfig must not expose legacy top-level %s selector field: %+v", forbidden, field)
		}
	}
}
