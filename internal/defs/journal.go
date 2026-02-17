package defs

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

var identRe = regexp.MustCompile(`^[A-Za-z0-9_.@-]+$`)

type JournalTailer struct {
	cursor string
	lastAt time.Time
	res    map[string]*regexp.Regexp
}

func NewJournalTailer() *JournalTailer {
	return &JournalTailer{res: map[string]*regexp.Regexp{}}
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

func (j *JournalTailer) Sample(idents []string, counters []protocol.Counter, now time.Time) ([]protocol.MetricPoint, error) {
	args := []string{"-q", "--no-pager", "-o", "cat", "--show-cursor"}
	for _, id := range idents {
		if !identRe.MatchString(id) {
			return nil, fmt.Errorf("bad syslog identifier %q", id)
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
		return nil, fmt.Errorf("journalctl: %s", msg)
	}
	counts := make([]int, len(counters))
	if cur := j.consume(out, counters, counts, first); cur != "" {
		j.cursor = cur
	}
	if first {
		j.lastAt = now
		return nil, nil
	}
	elapsed := now.Sub(j.lastAt).Seconds()
	j.lastAt = now
	if elapsed <= 0 {
		return nil, nil
	}
	pts := make([]protocol.MetricPoint, 0, len(counters))
	for i, c := range counters {
		pts = append(pts, protocol.MetricPoint{Name: c.Name, Value: float64(counts[i]) / elapsed})
	}
	return pts, nil
}

func (j *JournalTailer) consume(out []byte, counters []protocol.Counter, counts []int, skipLines bool) string {
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
			}
		}
	}
	return cursor
}
