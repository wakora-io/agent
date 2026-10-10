//go:build linux

package metrics

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAveragerFollowsTheKernelDecay(t *testing.T) {
	var l loadAverager
	if _, ok := l.value(); ok {
		t.Fatal("an averager without a sample reports a value")
	}
	l.observe(4)
	if v, _ := l.value(); v != [3]float64{4, 4, 4} {
		t.Fatalf("first sample primes all three, got %v", v)
	}
	for i := 0; i < 12; i++ {
		l.observe(0)
	}
	v, _ := l.value()
	want1 := 4 * math.Pow(loadDecay[0], 12)
	if math.Abs(v[0]-want1) > 1e-9 {
		t.Fatalf("load1 after a quiet minute %.4f, want %.4f", v[0], want1)
	}
	if !(v[0] < v[1] && v[1] < v[2]) {
		t.Fatalf("the short average must fall fastest, got %v", v)
	}
}

func TestCountActiveTasksReadsTaskStates(t *testing.T) {
	proc := t.TempDir()
	write := func(pid, tid, stat string) {
		dir := filepath.Join(proc, pid, "task", tid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("10", "10", "10 (nginx) S 1 10")
	write("10", "11", "11 (nginx: worker (x)) R 10 10")
	write("20", "20", "20 (mysqld) D 1 20")
	write("30", "30", "30 (wakora) R 1 30")
	write("40", "40", "40 (php-fpm) Z 1 40")
	if err := os.MkdirAll(filepath.Join(proc, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	if n := countActiveTasks(proc, 30); n != 2 {
		t.Fatalf("active tasks %d, want 2 (one R worker, one D, own process excluded)", n)
	}
}

func TestTaskStateSurvivesParensInTheName(t *testing.T) {
	if s := taskState("11 (nginx: worker (x)) R 10 10"); s != 'R' {
		t.Fatalf("state %q", s)
	}
	if s := taskState("garbage"); s != 0 {
		t.Fatalf("state %q", s)
	}
}
