//go:build linux

package metrics

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsePSITotal(t *testing.T) {
	got, ok := parsePSITotal("some avg10=2.85 avg60=2.94 avg300=3.08 total=12140538184\nfull avg10=2.47 avg60=2.66 avg300=2.78 total=11238566325\n")
	if !ok || got != 12140538184 {
		t.Fatalf("got %d ok=%v", got, ok)
	}
	if _, ok := parsePSITotal("full avg10=0.00 total=5\n"); ok {
		t.Fatal("a file without the some line must not read")
	}
}

func TestParseDiskstatsCountsWholePhysicalDisksOnly(t *testing.T) {
	stats := `   8       0 sda 100 0 2000 0 50 0 4000 0 0 700 0
   8       1 sda1 90 0 1800 0 40 0 3500 0 0 600 0
 253       0 dm-0 80 0 1600 0 30 0 3000 0 0 500 0
   7       0 loop0 10 0 200 0 0 0 0 0 0 10 0
 259       0 nvme0n1 10 0 100 0 5 0 300 0 0 90 0
`
	phys := map[string]bool{"sda": true, "nvme0n1": true}
	r, w, ticks := parseDiskstats(stats, func(n string) bool { return phys[n] })
	if r != (2000+100)*512 || w != (4000+300)*512 {
		t.Fatalf("read %d write %d", r, w)
	}
	if len(ticks) != 2 || ticks["sda"] != 700 || ticks["nvme0n1"] != 90 {
		t.Fatalf("ticks %v", ticks)
	}
	if _, _, none := parseDiskstats(stats, func(string) bool { return false }); none != nil {
		t.Fatal("no physical disk must read as no data")
	}
}

func TestParseIOStatStackedDevicesCountOnce(t *testing.T) {
	stat := `252:0 rbytes=0 wbytes=12288 rios=0 wios=3 dbytes=0 dios=0
259:0 rbytes=4761931776 wbytes=3628171264 rios=107066 wios=180831 dbytes=0 dios=0
252:3 rbytes=4761903104 wbytes=3628171264 rios=107063 wios=180831 dbytes=0 dios=0
252:6 rbytes=4761903104 wbytes=3628171264 rios=107063 wios=180831 dbytes=0 dios=0
`
	r, w, ok := parseIOStat(stat, func(d string) bool { return d == "259:0" })
	if !ok || r != 4761931776 || w != 3628171264 {
		t.Fatalf("physical sum: r=%d w=%d ok=%v", r, w, ok)
	}
	r, w, ok = parseIOStat(stat, func(string) bool { return false })
	if !ok || r != 4761931776 || w != 3628171264 {
		t.Fatalf("without sysfs the busiest device stands in, got r=%d w=%d", r, w)
	}
}

func TestDiskBusyPctTakesTheBusiestDisk(t *testing.T) {
	prev := map[string]uint64{"sda": 1000, "sdb": 5000}
	cur := map[string]uint64{"sda": 31000, "sdb": 5600, "sdc": 99}
	got, ok := diskBusyPct(prev, cur, time.Minute)
	if !ok || math.Abs(got-50) > 0.001 {
		t.Fatalf("got %.2f ok=%v, want 50", got, ok)
	}
	if _, ok := diskBusyPct(nil, cur, time.Minute); ok {
		t.Fatal("the first sample has nothing to compare against")
	}
}

func TestIOInContainer(t *testing.T) {
	host := t.TempDir()
	if inContainer(host) {
		t.Fatal("a bare root read as a container")
	}
	lxc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(lxc, "run/systemd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lxc, "run/systemd/container"), []byte("lxc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !inContainer(lxc) {
		t.Fatal("the systemd container marker was ignored")
	}
}

func TestIOPointsNeedTwoSamples(t *testing.T) {
	c := NewCollector()
	now := time.Now()
	if pts := c.ioPoints(now); len(pts) != 0 {
		t.Fatalf("first sample emitted %v", pts)
	}
	for _, p := range c.ioPoints(now.Add(2 * time.Second)) {
		if p.Value < 0 || (p.Name != "host.io.read_bytes_per_sec" && p.Name != "host.io.write_bytes_per_sec" && p.Value > 100) {
			t.Fatalf("out of range point %+v", p)
		}
	}
}
