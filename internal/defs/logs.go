package defs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

var logLevelRank = map[string]int{"error": 0, "warn": 1, "notice": 2, "info": 3, "debug": 4}

func LogRank(level string) int {
	if r, ok := logLevelRank[level]; ok {
		return r
	}
	return logLevelRank["info"]
}

var defaultRedact = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization:?\s*bearer\s+)\S+`),
	regexp.MustCompile(`(?i)((?:api[_-]?key|apikey|token|secret|password|passwd|pwd)["'\s:=]{1,3})\S+`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`://[^:/@\s]+:[^@/\s]+@`),
	regexp.MustCompile(`\b(?:\d[ -]?){13,16}\b`),
}

type LogTailer struct {
	cursor  string
	offsets map[string]int64
	seenF   map[string]bool
	res     map[string]*regexp.Regexp
	redact  []*regexp.Regexp
	pattern string
}

func NewLogTailer() *LogTailer {
	return &LogTailer{offsets: map[string]int64{}, seenF: map[string]bool{}, res: map[string]*regexp.Regexp{}}
}

func (l *LogTailer) compile(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	if re, ok := l.res[pattern]; ok {
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	l.res[pattern] = re
	return re
}

func (l *LogTailer) setRedact(extra []string) {
	key := strings.Join(extra, "\n")
	if key == l.pattern && l.redact != nil {
		return
	}
	l.pattern = key
	l.redact = append([]*regexp.Regexp{}, defaultRedact...)
	for _, p := range extra {
		if re, err := regexp.Compile(p); err == nil {
			l.redact = append(l.redact, re)
		}
	}
}

func (l *LogTailer) scrub(msg string) string {
	for _, re := range l.redact {
		msg = re.ReplaceAllString(msg, "***")
	}
	return msg
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

func (l *LogTailer) Collect(service string, p protocol.Probe, now time.Time) ([]protocol.LogLine, error) {
	l.setRedact(p.Redact)
	minRank, ok := logLevelRank[strings.ToLower(p.MinLevel)]
	if !ok {
		minRank = logLevelRank["notice"]
	}
	svc := service
	var out []protocol.LogLine
	var firstErr error
	if len(p.Idents) > 0 {
		lines, err := l.journal(p.Idents, now)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, ln := range lines {
			if logLevelRank[ln.Level] > minRank {
				continue
			}
			ln.Service = svc
			ln.Message = l.scrub(ln.Message)
			out = append(out, ln)
		}
	}
	paths := p.Paths
	if p.Path != "" {
		paths = append(paths, p.Path)
	}
	levelRe := l.compile(p.LevelRegex)
	forced := ""
	if p.ForceLevel != "" {
		forced = normalizeLevel(p.ForceLevel)
	}
	for _, path := range paths {
		lines, err := l.tailFile(path, now)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, raw := range lines {
			level := "info"
			if forced != "" {
				level = forced
			}
			if levelRe != nil {
				if m := levelRe.FindStringSubmatch(raw); len(m) >= 2 {
					level = normalizeLevel(m[1])
				}
			}
			if logLevelRank[level] > minRank {
				continue
			}
			out = append(out, protocol.LogLine{
				Ts: now.Unix(), Service: svc, Level: level, Message: l.scrub(raw),
			})
		}
	}
	return out, firstErr
}

func normalizeLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "emerg", "alert", "crit", "critical", "err", "error", "fatal":
		return "error"
	case "warn", "warning":
		return "warn"
	case "notice":
		return "notice"
	case "debug", "trace":
		return "debug"
	}
	return "info"
}

func (l *LogTailer) journal(idents []string, now time.Time) ([]protocol.LogLine, error) {
	args := []string{"-q", "--no-pager", "-o", "json", "--show-cursor"}
	for _, id := range idents {
		if !identRe.MatchString(id) {
			continue
		}
		args = append(args, "SYSLOG_IDENTIFIER="+id)
	}
	first := l.cursor == ""
	if first {
		args = append(args, "-n", "1")
	} else {
		args = append(args, "--after-cursor", l.cursor, "-n", "5000")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
	if err != nil {
		l.cursor = ""
		return nil, err
	}
	var lines []protocol.LogLine
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if bytes.HasPrefix(line, []byte("-- cursor: ")) {
			l.cursor = strings.TrimSpace(string(line[len("-- cursor: "):]))
			continue
		}
		if first {
			continue
		}
		var e struct {
			Priority string          `json:"PRIORITY"`
			Message  json.RawMessage `json:"MESSAGE"`
			Realtime string          `json:"__REALTIME_TIMESTAMP"`
		}
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		msg := decodeJournalMessage(e.Message)
		if msg == "" {
			continue
		}
		ts := now.Unix()
		if us, ok := parseMicros(e.Realtime); ok {
			ts = us / 1e6
		}
		lines = append(lines, protocol.LogLine{Ts: ts, Level: logPriorityLevel(e.Priority), Message: msg})
	}
	return lines, nil
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

func (l *LogTailer) tailFile(path string, now time.Time) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if !l.seenF[path] {
		l.offsets[path] = size
		l.seenF[path] = true
		return nil, nil
	}
	start := l.offsets[path]
	if size < start {
		start = 0
	}
	if size-start > maxTailRead {
		start = size - maxTailRead
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t != "" {
			lines = append(lines, t)
		}
	}
	l.offsets[path] = size
	return lines, nil
}
