package agent

import (
	"strings"
	"testing"

	"wakora.io/agent/internal/protocol"
)

func TestSanitizeFrustKeepsOnlyKnownSignals(t *testing.T) {
	out := sanitizeFrust([]protocol.RumFrust{
		{Name: "rage", Sel: "button#pay", Count: 4},
		{Name: "dead", Sel: "a.link", Count: 2},
		{Name: "error_click", Sel: "div:nth-child(2)", Count: 1},
	})
	if len(out) != 2 {
		t.Fatalf("want 2 signals, got %d", len(out))
	}
	if out[0].Name != "rage" || out[1].Name != "error_click" {
		t.Fatalf("unexpected signals: %+v", out)
	}
}

func TestSanitizeFrustCapsCountAndSelector(t *testing.T) {
	long := strings.Repeat("a", 400)
	out := sanitizeFrust([]protocol.RumFrust{{Name: "rage", Sel: long, Count: 0}})
	if len(out) != 1 {
		t.Fatalf("want the signal kept, got %d", len(out))
	}
	if len(out[0].Sel) != 120 {
		t.Fatalf("selector not capped: %d", len(out[0].Sel))
	}
	if out[0].Count != 1 {
		t.Fatalf("count floor not applied: %d", out[0].Count)
	}
	out = sanitizeFrust([]protocol.RumFrust{{Name: "rage", Count: 99999}})
	if out[0].Count != 1000 {
		t.Fatalf("count ceiling not applied: %d", out[0].Count)
	}
}

func TestSanitizeFrustCapsListLength(t *testing.T) {
	in := make([]protocol.RumFrust, 0, 9)
	for i := 0; i < 9; i++ {
		in = append(in, protocol.RumFrust{Name: "rage", Sel: "b", Count: 3})
	}
	if got := len(sanitizeFrust(in)); got != 5 {
		t.Fatalf("want 5 kept, got %d", got)
	}
	if sanitizeFrust(nil) != nil {
		t.Fatal("empty input must stay nil")
	}
	if sanitizeFrust([]protocol.RumFrust{{Name: "dead"}}) != nil {
		t.Fatal("a list of unknown signals must collapse to nil")
	}
}

func TestSanitizeCrumbsRejectsBrokenAndOversizedTrails(t *testing.T) {
	good := `[{"t":12,"k":"c","s":"button#pay"},{"t":40,"k":"f","s":"/api/pay","st":500,"d":230}]`
	if sanitizeCrumbs(good) != good {
		t.Fatal("a valid trail must survive")
	}
	if sanitizeCrumbs(`[{"t":12,"k":"c"`) != "" {
		t.Fatal("truncated json must be dropped")
	}
	if sanitizeCrumbs("["+strings.Repeat(`{"t":1,"k":"c","s":"a"},`, 200)+"]") != "" {
		t.Fatal("oversized trail must be dropped")
	}
	if sanitizeCrumbs("") != "" {
		t.Fatal("empty trail stays empty")
	}
}
