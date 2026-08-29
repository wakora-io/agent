package agent

import "testing"

func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		have, min string
		want      bool
	}{
		{"r66", "r63", true},
		{"r63", "r66", false},
		{"r66", "r66", true},
		{"dev", "r99", true},
		{"r66", "weird", false},
		{"r66", "", true},
	}
	for _, c := range cases {
		if got := versionAtLeast(c.have, c.min); got != c.want {
			t.Errorf("versionAtLeast(%q,%q)=%v want %v", c.have, c.min, got, c.want)
		}
	}
}

func TestSanitizeCustomRejectsNonAppPrefix(t *testing.T) {
	for _, name := range []string{"host.cpu.used_pct", "svc.nginx.req", "orders", ""} {
		if _, ok := sanitizeCustom(customMetric{Name: name, Value: 1}); ok {
			t.Fatalf("accepted forbidden custom metric name %q", name)
		}
	}
}

func TestSanitizeCustomAcceptsAppPrefix(t *testing.T) {
	pt, ok := sanitizeCustom(customMetric{Name: "app.orders_processed", Value: 42})
	if !ok || pt.Name != "app.orders_processed" || pt.Value != 42 {
		t.Fatalf("valid app metric rejected: %+v ok=%v", pt, ok)
	}
}

func TestSanitizeCustomCapsTags(t *testing.T) {
	tags := map[string]string{}
	for i := 0; i < 20; i++ {
		tags[string(rune('a'+i))] = "v"
	}
	pt, ok := sanitizeCustom(customMetric{Name: "app.x", Value: 1, Tags: tags})
	if !ok {
		t.Fatal("rejected")
	}
	if len(pt.Tags) > customMaxTags {
		t.Fatalf("tag cardinality not capped: %d", len(pt.Tags))
	}
}

func TestSanitizeCustomTruncatesLongValues(t *testing.T) {
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'x'
	}
	pt, ok := sanitizeCustom(customMetric{Name: "app.x", Value: 1, Tags: map[string]string{"k": string(long)}})
	if !ok {
		t.Fatal("rejected")
	}
	if len(pt.Tags["k"]) > customMaxValueLen {
		t.Fatalf("long tag value not truncated: %d", len(pt.Tags["k"]))
	}
}
