package defs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

var identRe = regexp.MustCompile(`^[A-Za-z0-9_.@-]+$`)

const srcCooldown = 30 * time.Minute

type JournalTailer struct {
	cursor  string
	lastAt  time.Time
	res     map[string]*regexp.Regexp
	srcLast map[string]time.Time
}

func NewJournalTailer() *JournalTailer {
	return &JournalTailer{res: map[string]*regexp.Regexp{}, srcLast: map[string]time.Time{}}
}

func (j *JournalTailer) compile(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	if re, ok := j.res[pattern]; ok {
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	j.res[pattern] = re
	return re
}

func (j *JournalTailer) Sample(idents []string, counters []protocol.Counter, now time.Time) ([]protocol.MetricPoint, []protocol.AgentEvent, error) {
	args := []string{"-q", "--no-pager", "-o", "cat", "--show-cursor"}
	for _, id := range idents {
		if !identRe.MatchString(id) {
			return nil, nil, fmt.Errorf("bad syslog identifier %q", id)
		}
		args = append(args, "SYSLOG_IDENTIFIER="+id)
	}
	first := j.cursor == ""
	if first {
		args = append(args, "-n", "1")
	} else {
		args = append(args, "--after-cursor", j.cursor, "-n", "20000")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "journalctl", args...).CombinedOutput()
	if err != nil {
		j.cursor = ""
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, nil, fmt.Errorf("journalctl: %s", msg)
	}
	counts := make([]int, len(counters))
	sources := make([]map[string]int, len(counters))
	if cur := j.consume(out, counters, counts, sources, first); cur != "" {
		j.cursor = cur
	}
	if first {
		j.lastAt = now
		return nil, nil, nil
	}
	elapsed := now.Sub(j.lastAt).Seconds()
	j.lastAt = now
	if elapsed <= 0 {
		return nil, nil, nil
	}
	pts := make([]protocol.MetricPoint, 0, len(counters))
	var events []protocol.AgentEvent
	for i, c := range counters {
		pts = append(pts, protocol.MetricPoint{Name: c.Name, Value: float64(counts[i]) / elapsed})
		if c.Event != "" {
			if ev, ok := foldSourceEvent(c, sources[i], now, j.srcLast); ok {
				events = append(events, ev)
			}
		}
	}
	return pts, events, nil
}

func foldSourceEvent(c protocol.Counter, src map[string]int, now time.Time, srcLast map[string]time.Time) (protocol.AgentEvent, bool) {
	if len(src) == 0 {
		return protocol.AgentEvent{}, false
	}
	min := c.Min
	if min <= 0 {
		min = 10
	}
	type kv struct {
		Source string `json:"source"`
		Count  int    `json:"count"`
	}
	top := make([]kv, 0, len(src))
	total := 0
	worst := 0
	for k, n := range src {
		top = append(top, kv{k, n})
		total += n
		if n > worst {
			worst = n
		}
	}
	if worst < min {
		return protocol.AgentEvent{}, false
	}
	if last, ok := srcLast[c.Event]; ok && now.Sub(last) < srcCooldown {
		return protocol.AgentEvent{}, false
	}
	srcLast[c.Event] = now
	sort.Slice(top, func(a, b int) bool { return top[a].Count > top[b].Count })
	if len(top) > 10 {
		top = top[:10]
	}
	detail, _ := json.Marshal(map[string]any{"sources": top, "total": total, "distinct": len(src)})
	return protocol.AgentEvent{Kind: c.Event, Detail: string(detail), Timestamp: now.Unix()}, true
}

func (j *JournalTailer) consume(out []byte, counters []protocol.Counter, counts []int, sources []map[string]int, skipLines bool) string {
	cursor := ""
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if bytes.HasPrefix(line, []byte("-- cursor: ")) {
			cursor = strings.TrimSpace(string(line[len("-- cursor: "):]))
			continue
		}
		if skipLines {
			continue
		}
		for i, c := range counters {
			re := j.compile(c.Regex)
			if re == nil || re.Match(line) {
				counts[i]++
				if c.Capture != "" {
					if cre := j.compile(c.Capture); cre != nil {
						if m := cre.FindSubmatch(line); len(m) >= 2 {
							if sources[i] == nil {
								sources[i] = map[string]int{}
							}
							sources[i][string(m[1])]++
						}
					}
				}
			}
		}
	}
	return cursor
}
