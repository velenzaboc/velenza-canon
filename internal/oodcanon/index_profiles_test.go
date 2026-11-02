package oodcanon

import "testing"

func TestSecondaryIndexProfilesAreTableDiscriminated(t *testing.T) {
	a, err := GraphAddressIndexHashV1("object", "org", "api://x")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GraphAddressIndexHashV1("symbol", "org", "api://x")
	if err != nil || a == b {
		t.Fatal("table discriminator was not bound")
	}
	if _, err := GraphAddressIndexHashV1("edge", "org", "api://x"); err == nil {
		t.Fatal("unsupported table accepted")
	}
}
