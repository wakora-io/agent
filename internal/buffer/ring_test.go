package buffer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpoolRewritesLeaveNoPartialFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "buffer.jsonl")
	r := New(path, 512, time.Hour)
	for i := 0; i < 200; i++ {
		if err := r.Append([]byte(strings.Repeat("x", 40))); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "buffer.jsonl" {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("spool dir holds %v, want only the spool", names)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) > 512+64 {
		t.Fatalf("spool grew to %d bytes past its cap", len(data))
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" && !strings.HasSuffix(line, "x") {
			t.Fatalf("torn line in the spool: %q", line)
		}
	}
}

func TestAppendDrain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buf.jsonl")
	r := New(path, 1<<20, 0)
	if err := r.Append([]byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := r.Append([]byte(`{"b":2}`)); err != nil {
		t.Fatal(err)
	}

	var got []string
	if err := r.Drain(func(line []byte) error {
		got = append(got, string(line))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != `{"a":1}` || got[1] != `{"b":2}` {
		t.Fatalf("drained: %v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("spool not removed after successful drain")
	}
	if err := r.Drain(func([]byte) error { t.Fatal("empty spool delivered"); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestDrainAbortKeepsSpool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buf.jsonl")
	r := New(path, 1<<20, 0)
	_ = r.Append([]byte("one"))
	_ = r.Append([]byte("two"))

	boom := errors.New("send failed")
	err := r.Drain(func(line []byte) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("drain error lost: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("spool removed despite failed drain")
	}
}

func TestDrainAbortDropsSentPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buf.jsonl")
	r := New(path, 1<<20, 0)
	_ = r.Append([]byte("one"))
	_ = r.Append([]byte("two"))
	_ = r.Append([]byte("three"))

	boom := errors.New("send failed")
	n := 0
	err := r.Drain(func(line []byte) error {
		n++
		if n == 3 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) {
		t.Fatalf("drain error lost: %v", err)
	}
	var got []string
	if err := r.Drain(func(line []byte) error {
		got = append(got, string(line))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "three" {
		t.Fatalf("sent prefix must be dropped, remaining %v", got)
	}
}

func TestTrimDropsOldest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buf.jsonl")
	r := New(path, 60, 0)
	_ = r.Append([]byte("aaaaaaaaaa"))
	_ = r.Append([]byte("bbbbbbbbbb"))
	_ = r.Append([]byte("cccccccccc"))

	var got []string
	if err := r.Drain(func(line []byte) error {
		got = append(got, string(line))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || len(got) == 3 {
		t.Fatalf("size trim broken, drained %d entries", len(got))
	}
	if got[len(got)-1] != "cccccccccc" {
		t.Fatalf("newest entry must survive trim, got %v", got)
	}
}

func TestAgeLimitDropsStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buf.jsonl")
	r := New(path, 1<<20, time.Hour)

	past := time.Now().Add(-2 * time.Hour)
	r.now = func() time.Time { return past }
	_ = r.Append([]byte("stale"))

	r.now = time.Now
	_ = r.Append([]byte("fresh"))

	var got []string
	if err := r.Drain(func(line []byte) error {
		got = append(got, string(line))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "fresh" {
		t.Fatalf("age limit broken, drained %v", got)
	}
}

func TestDrainSkipsOversizedRecord(t *testing.T) {
	old := maxDrainRecord
	maxDrainRecord = 256
	defer func() { maxDrainRecord = old }()

	path := filepath.Join(t.TempDir(), "buf.jsonl")
	r := New(path, 1<<20, 0)
	_ = r.Append([]byte("small-a"))
	_ = r.Append([]byte(strings.Repeat("X", 4096)))
	_ = r.Append([]byte("small-b"))

	var got []string
	if err := r.Drain(func(line []byte) error {
		got = append(got, string(line))
		return nil
	}); err != nil {
		t.Fatalf("drain err: %v", err)
	}
	if len(got) != 2 || got[0] != "small-a" || got[1] != "small-b" {
		t.Fatalf("oversized record must be skipped without wiping the rest, got %v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("spool not removed after full drain")
	}
}

func TestDrainLargeRecordReplays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buf.jsonl")
	r := New(path, 8<<20, 0)
	big := strings.Repeat("Y", 3<<20)
	_ = r.Append([]byte("small-a"))
	_ = r.Append([]byte(big))
	_ = r.Append([]byte("small-b"))

	var got []string
	if err := r.Drain(func(line []byte) error {
		got = append(got, string(line))
		return nil
	}); err != nil {
		t.Fatalf("drain err: %v", err)
	}
	if len(got) != 3 || got[1] != big {
		t.Fatalf("multi-MB record must replay whole, got %d entries (mid len %d)", len(got), len(got[1]))
	}
}

func TestDrainLegacyUnstampedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buf.jsonl")
	if err := os.WriteFile(path, []byte("{\"legacy\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(path, 1<<20, time.Hour)
	var got []string
	if err := r.Drain(func(line []byte) error {
		got = append(got, string(line))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != `{"legacy":true}` {
		t.Fatalf("legacy line must replay as-is, got %v", got)
	}
}
