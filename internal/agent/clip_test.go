package agent

import (
	"testing"
	"unicode/utf8"
)

func TestClipNeverSplitsARune(t *testing.T) {
	s := "abc" + "\u0101\u0101\u0101"
	for n := 0; n <= len(s)+1; n++ {
		got := clip(s, n)
		if len(got) > n || !utf8.ValidString(got) {
			t.Fatalf("clip(%q, %d) = %q", s, n, got)
		}
	}
	if got := clip("short", 64); got != "short" {
		t.Fatalf("clip touched a string under the cap: %q", got)
	}
}
