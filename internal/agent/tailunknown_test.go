package agent

import (
	"strings"
	"testing"
)

func TestTailPathUnknownNamesTheSource(t *testing.T) {
	got := tailPathUnknownError("slowLog")
	if !strings.Contains(got, "read from the service configuration") {
		t.Fatalf("got %q", got)
	}
	if !strings.Contains(got, "other failing checks") {
		t.Fatalf("the operator must be pointed at the real cause: %q", got)
	}
}

func TestTailPathUnknownStaysPlainWithoutASource(t *testing.T) {
	got := tailPathUnknownError("")
	if got != "log path unknown (not discovered yet)" {
		t.Fatalf("got %q", got)
	}
}
