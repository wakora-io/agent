package defs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJournalCursorSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal-cursor.json")
	h := newTestHub()
	h.statePath = path
	h.subs["kernel"] = &journalSub{key: "kernel", set: map[string]bool{"kernel": true}, seeded: true}
	h.consume([]byte("-- cursor: s=one\n"), true, 0)
	h.save()

	now := time.Unix(1750001000, 0)
	r := newTestHub()
	r.load(path, now)
	if r.cursor != "s=one" {
		t.Fatalf("the cursor must come back from disk, got %q", r.cursor)
	}
	if ids := r.union(); len(ids) != 1 || ids[0] != "kernel" {
		t.Fatalf("the first read after a restart must cover the saved idents, got %v", ids)
	}
	old := now.Add(-20 * time.Minute).UnixMicro()
	fresh := now.Add(-2 * time.Minute).UnixMicro()
	out := []byte(`{"PRIORITY":"3","MESSAGE":"too old","SYSLOG_IDENTIFIER":"kernel","__REALTIME_TIMESTAMP":"` + itoa(old) + `"}
{"PRIORITY":"3","MESSAGE":"Out of memory: Killed process 4242 (wakora)","SYSLOG_IDENTIFIER":"kernel","__REALTIME_TIMESTAMP":"` + itoa(fresh) + `"}
-- cursor: s=two
`)
	r.consume(out, false, now.Unix())
	r.restored = time.Now()
	entries, err := r.drain("host/oom", []string{"kernel"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].msg != "Out of memory: Killed process 4242 (wakora)" {
		t.Fatalf("a subscriber born after the restart gets the backlog of the last 15 minutes, got %+v", entries)
	}
}

func TestJournalCursorIsSavedOnlyWhenItMoves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal-cursor.json")
	h := newTestHub()
	h.statePath = path
	h.cursor = "s=a"
	h.save()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st journalState
	if json.Unmarshal(raw, &st) != nil || st.Cursor != "s=a" {
		t.Fatalf("saved state: %s", raw)
	}
	_ = os.Remove(path)
	h.save()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("an unchanged cursor must not be rewritten")
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
