package defs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	journalUnionCap = 20000
	journalQueueCap = 5000
)

type journalEntry struct {
	ts    int64
	level string
	msg   string
}

type journalSub struct {
	key    string
	set    map[string]bool
	queue  []journalEntry
	seeded bool
}

type journalHub struct {
	mu      sync.Mutex
	subs    map[string]*journalSub
	cursor  string
	gen     uint64
	done    uint64
	lastErr error
	empty   bool
}

var journals = &journalHub{subs: map[string]*journalSub{}}

func JournalCycle() {
	journals.mu.Lock()
	journals.gen++
	journals.mu.Unlock()
}

func identSet(idents []string) map[string]bool {
	set := map[string]bool{}
	for _, id := range idents {
		if identRe.MatchString(id) {
			set[id] = true
		}
	}
	return set
}

func sameIdentSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func (h *journalHub) drain(key string, idents []string) ([]journalEntry, error) {
	set := identSet(idents)
	h.mu.Lock()
	defer h.mu.Unlock()
	sub := h.subs[key]
	if sub == nil || !sameIdentSet(sub.set, set) {
		sub = &journalSub{key: key, set: set}
		h.subs[key] = sub
	}
	if len(set) == 0 {
		return nil, nil
	}
	h.fetch()
	out := sub.queue
	sub.queue = nil
	if !sub.seeded {
		sub.seeded = true
		return nil, h.lastErr
	}
	return out, h.lastErr
}

func (h *journalHub) union() []string {
	seen := map[string]bool{}
	for _, s := range h.subs {
		for id := range s.set {
			seen[id] = true
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (h *journalHub) fetch() {
	if h.done == h.gen {
		return
	}
	h.done = h.gen
	ids := h.union()
	if len(ids) == 0 {
		return
	}
	args := []string{"--no-pager", "-o", "json", "--show-cursor"}
	for _, id := range ids {
		args = append(args, "SYSLOG_IDENTIFIER="+id)
	}
	first := h.cursor == ""
	if first {
		args = append(args, "-n", "1")
	} else {
		args = append(args, "--after-cursor", h.cursor, "-n", strconv.Itoa(journalUnionCap))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
	if err != nil {
		if journalNoEntries(err, out) {
			h.lastErr = nil
			if !h.empty {
				h.empty = true
				log.Printf("journal: nothing matches the %d watched identifiers - the journal is readable, it simply holds no entry for any of them", len(ids))
			}
			return
		}
		h.cursor = ""
		h.lastErr = journalErr(err, out, len(ids), !first)
		return
	}
	h.lastErr = nil
	h.empty = false
	h.consume(out, first, time.Now().Unix())
}

func journalNoEntries(err error, out []byte) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	return len(bytes.TrimSpace(out)) == 0 && len(bytes.TrimSpace(ee.Stderr)) == 0
}

func journalErr(err error, out []byte, idents int, cursor bool) error {
	msg := execErrText(err).Error()
	if msg == err.Error() {
		tail := firstOutputLine(out)
		if tail == "" {
			tail = "no output"
		}
		msg += ": " + tail
	}
	if cursor {
		msg += " (idents " + strconv.Itoa(idents) + ", resuming from a cursor)"
	} else {
		msg += " (idents " + strconv.Itoa(idents) + ", first read)"
	}
	return errors.New(msg)
}

func firstOutputLine(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			if len(line) > 120 {
				line = line[:120]
			}
			return line
		}
	}
	return ""
}

func (h *journalHub) consume(out []byte, first bool, now int64) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if bytes.HasPrefix(line, []byte("-- cursor: ")) {
			h.cursor = strings.TrimSpace(string(line[len("-- cursor: "):]))
			continue
		}
		if first {
			continue
		}
		var e struct {
			Priority string          `json:"PRIORITY"`
			Message  json.RawMessage `json:"MESSAGE"`
			Ident    json.RawMessage `json:"SYSLOG_IDENTIFIER"`
			Realtime string          `json:"__REALTIME_TIMESTAMP"`
		}
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		msg := decodeJournalMessage(e.Message)
		if msg == "" {
			continue
		}
		ident := decodeJournalMessage(e.Ident)
		if ident == "" {
			continue
		}
		ts := now
		if us, ok := parseMicros(e.Realtime); ok {
			ts = us / 1e6
		}
		ent := journalEntry{ts: ts, level: logPriorityLevel(e.Priority), msg: msg}
		for _, s := range h.subs {
			if !s.set[ident] || len(s.queue) >= journalQueueCap {
				continue
			}
			s.queue = append(s.queue, ent)
		}
	}
}

func decodeJournalMessage(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b []byte
	if json.Unmarshal(raw, &b) == nil {
		return string(b)
	}
	return ""
}

func parseMicros(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}

func logPriorityLevel(p string) string {
	switch p {
	case "0", "1", "2", "3":
		return "error"
	case "4":
		return "warn"
	case "5":
		return "notice"
	case "6":
		return "info"
	case "7":
		return "debug"
	}
	return "info"
}
