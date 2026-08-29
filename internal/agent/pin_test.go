package agent

import (
	"testing"

	"wakora.io/agent/internal/config"
)

func TestApplyPushedPinAdoptAndClear(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: cfg}
	a.pin.Store("")

	a.applyPushedPin("")
	if a.EffectivePin() != "" {
		t.Fatal("empty push with no prior pin must stay empty")
	}

	a.applyPushedPin("r227")
	if a.EffectivePin() != "r227" {
		t.Fatalf("console pin not adopted: %q", a.EffectivePin())
	}
	if !a.pinFromPush.Load() {
		t.Fatal("pinFromPush must be set after a console pin")
	}
	if back, _ := config.Load(dir); back.Pin != "r227" {
		t.Fatalf("pin not mirrored to wakora.conf: %q", back.Pin)
	}

	a.applyPushedPin("")
	if a.EffectivePin() != "" {
		t.Fatal("empty push must clear a console-sourced pin")
	}
	if back, _ := config.Load(dir); back.Pin != "" {
		t.Fatalf("unpin not mirrored to wakora.conf: %q", back.Pin)
	}
}

func TestLocalPinSurvivesEmptyPush(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Pin = "r225"
	a := &Agent{cfg: cfg}
	a.pin.Store("r225")

	a.applyPushedPin("")
	if a.EffectivePin() != "r225" {
		t.Fatalf("a local pin must survive an empty console push until it syncs up: %q", a.EffectivePin())
	}
}

func TestPushedPinBelowFloorIgnored(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: cfg}
	a.pin.Store("")

	a.applyPushedPin("r220")
	if a.EffectivePin() != "" {
		t.Fatalf("a pin below the pin-aware floor must be ignored: %q", a.EffectivePin())
	}
	if a.pinFromPush.Load() {
		t.Fatal("an ignored pin must not flip pinFromPush")
	}
	if back, _ := config.Load(dir); back.Pin != "" {
		t.Fatalf("an ignored pin must not reach wakora.conf: %q", back.Pin)
	}
}
