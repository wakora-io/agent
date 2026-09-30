package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wakora.io/agent/internal/config"
)

func identityAgent(t *testing.T) (*Agent, string, *int) {
	t.Helper()
	dir := t.TempDir()
	if err := config.SaveIdentity(dir, "uuid-original", "k-original"); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	restarts := 0
	a := &Agent{cfg: cfg}
	a.SetRestart(func() { restarts++ })
	return a, dir, &restarts
}

func TestReidentifySwapsIdentityAndMarks(t *testing.T) {
	a, dir, restarts := identityAgent(t)
	a.reidentify(`{"serverId":"uuid-copy","key":"k-new"}`)
	if *restarts != 1 {
		t.Fatalf("restart calls: %d", *restarts)
	}
	back, err := config.Load(dir)
	if err != nil || back.ServerID != "uuid-copy" || back.Key != "k-new" {
		t.Fatalf("identity after reidentify: err=%v id=%q key=%q", err, back.ServerID, back.Key)
	}
	prev, ok := config.TakeIdentityChanged(dir)
	if !ok || prev != "uuid-original" {
		t.Fatalf("marker: ok=%v prev=%q", ok, prev)
	}
}

func TestReidentifyIgnoresSameOrBrokenOrders(t *testing.T) {
	a, dir, restarts := identityAgent(t)
	for _, p := range []string{`{"serverId":"uuid-original","key":"k-x"}`, `{"serverId":"","key":"k-x"}`, `{"serverId":"uuid-copy"}`, `not json`} {
		a.reidentify(p)
	}
	if *restarts != 0 {
		t.Fatalf("restart calls: %d", *restarts)
	}
	if _, ok := config.TakeIdentityChanged(dir); ok {
		t.Fatal("no marker may be left by an ignored order")
	}
	back, _ := config.Load(dir)
	if back.ServerID != "uuid-original" || back.Key != "k-original" {
		t.Fatalf("identity changed: id=%q key=%q", back.ServerID, back.Key)
	}
}

func TestRefuseCopySetsIdentityAside(t *testing.T) {
	a, dir, restarts := identityAgent(t)
	a.refuseCopy("no free host slot\non the plan")
	if *restarts != 1 {
		t.Fatalf("restart calls: %d", *restarts)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity")); !os.IsNotExist(err) {
		t.Fatalf("identity must be moved aside, stat err=%v", err)
	}
	moved, _ := filepath.Glob(filepath.Join(dir, "identity.copy-*"))
	if len(moved) != 1 {
		t.Fatalf("set-aside copies: %v", moved)
	}
	r, ok := config.LoadCopyRefusal(dir)
	if !ok || r.Of != "uuid-original" || r.Reason != "no free host slot on the plan" || r.At == 0 {
		t.Fatalf("refusal: ok=%v %+v", ok, r)
	}
}

func TestCopyReasonIsBoundedAndNeverEmpty(t *testing.T) {
	if copyReason("  ") == "" {
		t.Fatal("empty reason must fall back to a default")
	}
	long := copyReason(strings.Repeat("ā", copyReasonMax+50))
	if n := len([]rune(long)); n != copyReasonMax {
		t.Fatalf("reason length %d", n)
	}
}

func TestInstanceIDsDiffer(t *testing.T) {
	a, b := newInstanceID(), newInstanceID()
	if len(a) != 16 || a == b {
		t.Fatalf("instance ids %q %q", a, b)
	}
}
