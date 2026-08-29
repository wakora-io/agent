package defs

import "testing"

func TestHypervVMGuid(t *testing.T) {
	got := hypervVMGuid(`Microsoft:2CE9F5F9-2E52-4B94-9E71-9D9A55A1F5BC\b637f346-6a0e-4dec-af52-bd70cb80a21d\0`)
	if got != "2ce9f5f9-2e52-4b94-9e71-9d9a55a1f5bc" {
		t.Fatalf("guid: %q", got)
	}
	if hypervVMGuid("Wrong:abc") != "" {
		t.Fatal("expected empty for foreign InstanceID")
	}
	if got := hypervVMGuid("Microsoft:AAAA"); got != "aaaa" {
		t.Fatalf("no-backslash form: %q", got)
	}
}

func TestHypervStateName(t *testing.T) {
	cases := map[uint16]string{2: "running", 3: "off", 6: "saved", 9: "paused", 42: "other"}
	for in, want := range cases {
		if got := hypervStateName(in); got != want {
			t.Fatalf("state %d: %q want %q", in, got, want)
		}
	}
}

func TestLooksLikeGuid(t *testing.T) {
	if !looksLikeGuid("2ce9f5f9-2e52-4b94-9e71-9d9a55a1f5bc") {
		t.Fatal("valid guid rejected")
	}
	for _, bad := range []string{"", "not-a-guid", "2CE9F5F92E524B949E719D9A55A1F5BCXX", "2ce9f5f9-2e52-4b94-9e71-9d9a55a1f5bg"} {
		if looksLikeGuid(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}
