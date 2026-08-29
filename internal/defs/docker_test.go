package defs

import (
	"encoding/json"
	"os"
	"testing"

	"wakora.io/agent/internal/protocol"
)

func TestGroupContainers(t *testing.T) {
	cs := []dockerContainer{
		{ID: "1", Names: []string{"/web1"}, Image: "nginx:alpine", State: "running"},
		{ID: "2", Names: []string{"/web2"}, Image: "nginx:alpine", State: "running"},
		{ID: "3", Names: []string{"/web3"}, Image: "nginx:alpine", State: "exited"},
		{ID: "4", Names: []string{"/cache"}, Image: "redis:alpine", State: "running"},
	}
	groups := groupContainers(cs)
	if len(groups) != 2 {
		t.Fatalf("want 2 groups (billing: image = service unit), got %d", len(groups))
	}
	nginx := groups[0]
	if nginx.Image != "nginx:alpine" || nginx.Count != 3 || nginx.Running != 2 {
		t.Fatalf("nginx group wrong: %+v", nginx)
	}
	if len(nginx.Names) != 3 || nginx.Names[0] != "web1" {
		t.Fatalf("names wrong: %v", nginx.Names)
	}
	if groups[1].Image != "redis:alpine" || groups[1].Count != 1 {
		t.Fatalf("redis group wrong: %+v", groups[1])
	}
}

func TestImageKey(t *testing.T) {
	if imageKey("sha256:0123456789abcdef0123456789abcdef") != "sha256:0123456789ab"[:19] {
		t.Fatalf("sha256 image not shortened: %q", imageKey("sha256:0123456789abcdef0123456789abcdef"))
	}
	if imageKey("nginx:alpine") != "nginx:alpine" {
		t.Fatal("tagged image must stay as-is")
	}
	if imageKey("") != "unknown" {
		t.Fatal("empty image must map to unknown")
	}
}

func TestCPUPercentAndMem(t *testing.T) {
	raw := `{
		"cpu_stats": {"cpu_usage": {"total_usage": 2000000}, "system_cpu_usage": 100000000, "online_cpus": 2},
		"precpu_stats": {"cpu_usage": {"total_usage": 1000000}, "system_cpu_usage": 90000000},
		"memory_stats": {"usage": 1000000, "stats": {"inactive_file": 200000}}
	}`
	var s dockerStats
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatal(err)
	}
	pct, ok := cpuPercent(s)
	if !ok {
		t.Fatal("cpu percent should be computable")
	}
	want := 1000000.0 / 10000000.0 * 2 * 100
	if pct != want {
		t.Fatalf("cpu pct = %v, want %v", pct, want)
	}
	if got := memUsage(s); got != 800000 {
		t.Fatalf("mem = %v, want 800000 (usage - inactive_file)", got)
	}
}

func TestAddStatsNetAndBlkio(t *testing.T) {
	raw := `{
		"cpu_stats": {"cpu_usage": {"total_usage": 200}, "system_cpu_usage": 2000, "online_cpus": 1},
		"precpu_stats": {"cpu_usage": {"total_usage": 100}, "system_cpu_usage": 1000},
		"memory_stats": {"usage": 500},
		"networks": {"eth0": {"rx_bytes": 100, "tx_bytes": 30}, "eth1": {"rx_bytes": 50, "tx_bytes": 20}},
		"blkio_stats": {"io_service_bytes_recursive": [
			{"op": "read", "value": 4096}, {"op": "write", "value": 8192},
			{"op": "Read", "value": 1000}, {"op": "total", "value": 999999}
		]}
	}`
	var s dockerStats
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatal(err)
	}
	var g groupStats
	addStats(&g, s)
	if g.netRx != 150 || g.netTx != 50 {
		t.Fatalf("net rx/tx = %v/%v, want 150/50 (summed over interfaces)", g.netRx, g.netTx)
	}
	if g.blkRead != 5096 || g.blkWrite != 8192 {
		t.Fatalf("blkio read/write = %v/%v, want 5096/8192 (case-insensitive op, total ignored)", g.blkRead, g.blkWrite)
	}
	if !g.hasCPU || g.mem != 500 {
		t.Fatalf("cpu/mem aggregation broken: %+v", g)
	}
}

func TestCountRulesAptAndDnf(t *testing.T) {
	apt := []byte(`NOTE: This is only a simulation!
Inst libssl3 [3.0.11-1] (3.0.13-1 Debian-Security:12/stable-security [amd64])
Inst nginx [1.22.1-9] (1.22.1-9+deb12u1 Debian:12.5/stable [amd64])
Inst linux-image-amd64 [6.1.76-1] (6.1.90-1 Debian-Security:12/stable-security [amd64])
Conf libssl3 (3.0.13-1 Debian-Security:12/stable-security [amd64])`)
	if n := extractCount(apt, `(?m)^Inst `); n != 3 {
		t.Fatalf("apt updates count = %d, want 3", n)
	}
	if n := extractCount(apt, `(?m)^Inst .*[Ss]ecurity`); n != 2 {
		t.Fatalf("apt security count = %d, want 2", n)
	}

	dnf := []byte(`kernel.x86_64          5.14.0-427.el9   baseos
openssl.x86_64         3.0.7-27.el9     baseos
zsh.x86_64             5.8-9.el9        appstream

Obsoleting Packages
old.noarch             1.0              baseos`)
	if n := extractCount(dnf, `(?m)^\S+\.(noarch|x86_64|aarch64|i686)\s`); n != 4 {
		t.Fatalf("dnf updates count = %d, want 4", n)
	}

	sec := []byte(`RHSA-2026:1234 Critical/Sec.  openssl-3.0.7-28.el9.x86_64
RHSA-2026:5678 Moderate/Sec.  kernel-5.14.0-428.el9.x86_64`)
	if n := extractCount(sec, `(?m)^\S+\s+(Critical|Important|Moderate|Low)/Sec\.`); n != 2 {
		t.Fatalf("dnf security count = %d, want 2", n)
	}
}

func TestFileProbeExists(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/reboot-required"

	var o Outcome
	runFile(&o, "os", protocol.Probe{Name: "reboot", Path: path})
	if o.Check.Status != "ok" {
		t.Fatalf("missing file must not fail the check: %+v", o.Check)
	}
	if len(o.Metrics) != 1 || o.Metrics[0].Name != "svc.os.reboot.exists" || o.Metrics[0].Value != 0 {
		t.Fatalf("want exists=0 metric, got %+v", o.Metrics)
	}

	if err := os.WriteFile(path, []byte("*** System restart required ***\npkgs: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o = Outcome{}
	runFile(&o, "os", protocol.Probe{Name: "reboot", Path: path,
		Metrics: []protocol.ParseRule{{Name: "svc.os.reboot.pkgs", Regex: `pkgs: ([0-9]+)`}}})
	if len(o.Metrics) != 2 || o.Metrics[0].Value != 1 || o.Metrics[1].Value != 2 {
		t.Fatalf("want exists=1 + content metric, got %+v", o.Metrics)
	}
}

func TestInspectHealthAndRestarts(t *testing.T) {
	raw := `{"RestartCount": 7, "State": {"Health": {"Status": "unhealthy"}}}`
	var ins dockerInspect
	if err := json.Unmarshal([]byte(raw), &ins); err != nil {
		t.Fatal(err)
	}
	if ins.RestartCount != 7 || ins.State.Health.Status != "unhealthy" {
		t.Fatalf("inspect parse broken: %+v", ins)
	}
	var noHealth dockerInspect
	if err := json.Unmarshal([]byte(`{"RestartCount": 0, "State": {}}`), &noHealth); err != nil {
		t.Fatal(err)
	}
	if noHealth.State.Health.Status != "" {
		t.Fatal("container without healthcheck must have empty health status")
	}
}

func TestCPUPercentFirstSample(t *testing.T) {
	var s dockerStats
	s.CPU.Usage.Total = 500
	s.CPU.System = 1000
	if _, ok := cpuPercent(s); ok {
		t.Fatal("first sample (empty precpu) must not produce cpu percent")
	}
}
