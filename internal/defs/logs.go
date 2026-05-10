package defs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

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
	cursor   string
	offsets  map[string]int64
	seenF    map[string]bool
	res      map[string]*regexp.Regexp
	redact   []*regexp.Regexp
	pattern  string
	ctrSince map[string]int64
	winSince map[string]int64
	podSince map[string]string
	futSeen  map[uint64]bool
}

func NewLogTailer() *LogTailer {
	return &LogTailer{offsets: map[string]int64{}, seenF: map[string]bool{}, res: map[string]*regexp.Regexp{},
		ctrSince: map[string]int64{}, winSince: map[string]int64{}, podSince: map[string]string{}, futSeen: map[uint64]bool{}}
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

func ScrubDefault(msg string) string {
	for _, re := range defaultRedact {
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
			ln.Level = downgradeTransportError(ln.Level, ln.Message)
			if logLevelRank[ln.Level] > minRank {
				continue
			}
			ln.Service = svc
			ln.Message = l.scrub(ln.Message)
			out = append(out, ln)
		}
	}
	if p.Docker {
		lines, err := l.dockerLogs(p.Path, now)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, ln := range lines {
			if logLevelRank[ln.Level] > minRank {
				continue
			}
			ln.Message = l.scrub(ln.Message)
			out = append(out, ln)
		}
	}
	if len(p.Channels) > 0 {
		lines, err := l.winEventLines(p.Channels, now)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, ln := range lines {
			if logLevelRank[ln.Level] > minRank {
				continue
			}
			if l.futureDup(ln, now) {
				continue
			}
			ln.Service = svc
			ln.Message = l.scrub(ln.Message)
			out = append(out, ln)
		}
	}
	if p.K8s {
		lines, err := l.k8sPodLogs(p.Path, now)
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
	if forced != "" && levelRe == nil && logLevelRank[forced] > minRank {
		paths = nil
	}
	for _, path := range paths {
		path = strings.ReplaceAll(path, "%s", "main")
		if fi, err := os.Stat(path); err == nil && fi.IsDir() {
			path = newestLogIn(path)
			if path == "" {
				continue
			}
		}
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
			level = downgradeTransportError(level, raw)
			if logLevelRank[level] > minRank {
				continue
			}
			out = append(out, protocol.LogLine{
				Ts: parseLineTs(raw, now), Service: svc, Level: level, Message: l.scrub(raw),
			})
		}
	}
	return out, firstErr
}

func normalizeLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "emerg", "alert", "crit", "critical", "err", "error", "fatal", "panic", "e", "f", "#":
		return "error"
	case "warn", "warning", "w":
		return "warn"
	case "notice", "note", "log", "*":
		return "notice"
	case "debug", "trace", "d", ".":
		return "debug"
	}
	return "info"
}

func (l *LogTailer) journal(idents []string, now time.Time) ([]protocol.LogLine, error) {
	args := []string{"-q", "--no-pager", "-o", "json", "--show-cursor"}
	matched := 0
	for _, id := range idents {
		if !identRe.MatchString(id) {
			continue
		}
		args = append(args, "SYSLOG_IDENTIFIER="+id)
		matched++
	}
	if matched == 0 {
		return nil, nil
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

var dockerLevelRe = regexp.MustCompile(`(?i)\b(fatal|panic|critical|crit|error|err|warning|warn|notice|info|debug|trace)\b`)

var klogRe = regexp.MustCompile(`^([EWIF])\d{4} `)

func contentLevel(msg string) string {
	if m := klogRe.FindStringSubmatch(msg); len(m) == 2 {
		return normalizeLevel(m[1])
	}
	if m := dockerLevelRe.FindStringSubmatch(msg); len(m) >= 2 && len(msg) < 4096 {
		return normalizeLevel(m[1])
	}
	return ""
}

var embeddedLevelRes = []struct {
	re    *regexp.Regexp
	level string
}{
	{regexp.MustCompile(`PHP (Fatal error|Parse error|Recoverable fatal error):`), "error"},
	{regexp.MustCompile(`(?i)\blevel[=:]\s*"?(fatal|panic|crit(?:ical)?|err(?:or)?)\b`), "error"},
	{regexp.MustCompile(`(?i)"(?:level|severity|loglevel)"\s*:\s*"(?:fatal|panic|critical|error)"`), "error"},
	{regexp.MustCompile(`\[(?:ERROR|FATAL|CRIT)\]`), "error"},
	{regexp.MustCompile(`PHP Warning:`), "warn"},
	{regexp.MustCompile(`(?i)\blevel[=:]\s*"?warn(?:ing)?\b`), "warn"},
	{regexp.MustCompile(`(?i)"(?:level|severity|loglevel)"\s*:\s*"warn(?:ing)?"`), "warn"},
	{regexp.MustCompile(`\[(?:WARN|WARNING)\]`), "warn"},
	{regexp.MustCompile(`PHP (?:Notice|Deprecated):`), "notice"},
	{regexp.MustCompile(`(?i)\blevel[=:]\s*"?notice\b`), "notice"},
	{regexp.MustCompile(`\[NOTICE\]`), "notice"},
	{regexp.MustCompile(`(?i)\blevel[=:]\s*"?(?:info|debug|trace)\b`), "info"},
	{regexp.MustCompile(`(?i)"(?:level|severity|loglevel)"\s*:\s*"(?:info|debug|trace)"`), "info"},
	{regexp.MustCompile(`\[(?:INFO|DEBUG)\]`), "info"},
}

func downgradeTransportError(level, msg string) string {
	if level != "error" {
		return level
	}
	for _, m := range embeddedLevelRes {
		if m.re.MatchString(msg) {
			if logLevelRank[m.level] > logLevelRank["error"] {
				return m.level
			}
			return level
		}
	}
	return level
}

func dockerImageShort(image string) string {
	if i := strings.LastIndex(image, "/"); i >= 0 {
		image = image[i+1:]
	}
	if i := strings.IndexAny(image, ":@"); i >= 0 {
		image = image[:i]
	}
	if image == "" {
		return "docker"
	}
	return image
}

func (l *LogTailer) dockerLogs(sock string, now time.Time) ([]protocol.LogLine, error) {
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	resp, err := client.Get("http://docker/containers/json")
	if err != nil {
		return nil, err
	}
	var ctrs []dockerContainer
	err = json.NewDecoder(resp.Body).Decode(&ctrs)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(ctrs) > 50 {
		ctrs = ctrs[:50]
	}
	var out []protocol.LogLine
	live := map[string]bool{}
	for _, c := range ctrs {
		live[c.ID] = true
		since, seen := l.ctrSince[c.ID]
		if !seen {
			l.ctrSince[c.ID] = now.Unix()
			continue
		}
		svc := dockerImageShort(c.Image)
		r, err := client.Get("http://docker/containers/" + c.ID + "/logs?stdout=1&stderr=1&timestamps=1&since=" + strconv.FormatInt(since, 10))
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		r.Body.Close()
		last := since
		for _, ln := range demuxDockerLog(body) {
			ts, msg := splitDockerTimestamp(ln.text)
			if ts <= since {
				continue
			}
			if ts > last {
				last = ts
			}
			level := contentLevel(msg)
			if level == "" || level == "info" {
				if ln.stderr && !klogRe.MatchString(msg) {
					level = "notice"
				} else {
					level = "info"
				}
			}
			out = append(out, protocol.LogLine{Ts: ts, Service: svc, Level: level, Message: msg})
		}
		l.ctrSince[c.ID] = last
	}
	for id := range l.ctrSince {
		if !live[id] {
			delete(l.ctrSince, id)
		}
	}
	return out, nil
}

func (l *LogTailer) k8sPodLogs(kubeconfig string, now time.Time) ([]protocol.LogLine, error) {
	kc, _, err := connectKube(kubeconfig, 10*time.Second)
	if err != nil {
		return nil, err
	}
	pods, err := kc.pods()
	if err != nil {
		return nil, err
	}
	var out []protocol.LogLine
	live := map[string]bool{}
	taken := 0
	for _, pod := range pods {
		if taken >= 10 {
			break
		}
		if pod.phase == "Succeeded" || (pod.phase == "Running" && pod.restarts == 0 && !pod.crashloop) {
			continue
		}
		key := pod.namespace + "/" + pod.name
		live[key] = true
		taken++
		since, seen := l.podSince[key]
		if !seen {
			l.podSince[key] = now.UTC().Format(time.RFC3339)
			continue
		}
		raw, err := kc.getRaw("/api/v1/namespaces/" + pod.namespace + "/pods/" + pod.name +
			"/log?timestamps=true&tailLines=50&sinceTime=" + url.QueryEscape(since))
		if err != nil {
			continue
		}
		last := since
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			sp := strings.IndexByte(line, ' ')
			if sp <= 0 {
				continue
			}
			ts, err := time.Parse(time.RFC3339Nano, line[:sp])
			if err != nil {
				continue
			}
			stamp := ts.UTC().Format(time.RFC3339)
			if stamp <= since {
				continue
			}
			if stamp > last {
				last = stamp
			}
			msg := strings.TrimSpace(line[sp+1:])
			if msg == "" {
				continue
			}
			level := contentLevel(msg)
			if level == "" {
				level = "info"
			}
			out = append(out, protocol.LogLine{Ts: ts.Unix(), Level: level, Message: key + ": " + msg})
		}
		l.podSince[key] = last
	}
	for key := range l.podSince {
		if !live[key] {
			delete(l.podSince, key)
		}
	}
	return out, nil
}

type dockerLogLine struct {
	text   string
	stderr bool
}

func demuxDockerLog(body []byte) []dockerLogLine {
	var out []dockerLogLine
	if len(body) >= 8 && (body[0] == 1 || body[0] == 2) && body[1] == 0 && body[2] == 0 && body[3] == 0 {
		for len(body) >= 8 {
			stream := body[0]
			n := int(body[4])<<24 | int(body[5])<<16 | int(body[6])<<8 | int(body[7])
			body = body[8:]
			if n <= 0 || n > len(body) {
				break
			}
			chunk := body[:n]
			body = body[n:]
			for _, t := range strings.Split(string(chunk), "\n") {
				if t = strings.TrimSpace(t); t != "" {
					out = append(out, dockerLogLine{text: t, stderr: stream == 2})
				}
			}
		}
		return out
	}
	for _, t := range strings.Split(string(body), "\n") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, dockerLogLine{text: t})
		}
	}
	return out
}

func splitDockerTimestamp(line string) (int64, string) {
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return time.Now().Unix(), line
	}
	t, err := time.Parse(time.RFC3339Nano, line[:sp])
	if err != nil {
		return time.Now().Unix(), line
	}
	return t.Unix(), strings.TrimSpace(line[sp+1:])
}

func (l *LogTailer) futureDup(ln protocol.LogLine, now time.Time) bool {
	if ln.Ts <= now.Unix()+300 {
		return false
	}
	h := uint64(14695981039346656037)
	for _, b := range []byte(ln.Message) {
		h = (h ^ uint64(b)) * 1099511628211
	}
	h ^= uint64(ln.Ts)
	if l.futSeen[h] {
		return true
	}
	if len(l.futSeen) > 256 {
		l.futSeen = map[uint64]bool{}
	}
	l.futSeen[h] = true
	return false
}

var syslogTsRe = regexp.MustCompile(`^[A-Z][a-z]{2} [ 0-9]\d \d{2}:\d{2}:\d{2}`)

func parseLineTs(raw string, now time.Time) int64 {
	ts, ok := lineTime(raw, now)
	if !ok {
		return now.Unix()
	}
	u := ts.Unix()
	if u > now.Unix()+300 || u < now.Unix()-7*86400 {
		return now.Unix()
	}
	return u
}

func lineTime(raw string, now time.Time) (time.Time, bool) {
	head := raw
	if len(head) > 40 {
		head = head[:40]
	}
	if t, err := time.Parse(time.RFC3339Nano, firstField(head)); err == nil {
		return t, true
	}
	if len(head) >= 19 && head[4] == '-' && head[7] == '-' && head[10] == ' ' {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", head[:19], time.Local); err == nil {
			return t, true
		}
	}
	if len(head) >= 19 && head[4] == '/' && head[7] == '/' && head[10] == ' ' {
		if t, err := time.ParseInLocation("2006/01/02 15:04:05", head[:19], time.Local); err == nil {
			return t, true
		}
	}
	if i := strings.IndexByte(raw, '['); i >= 0 && i < 64 {
		rest := raw[i+1:]
		if j := strings.IndexByte(rest, ']'); j > 0 && j < 48 {
			in := rest[:j]
			if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", in); err == nil {
				return t, true
			}
			for _, layout := range []string{"Mon Jan 02 15:04:05.000000 2006", "Mon Jan _2 15:04:05.000000 2006", "Mon Jan 02 15:04:05 2006", "Mon Jan _2 15:04:05 2006"} {
				if t, err := time.ParseInLocation(layout, in, time.Local); err == nil {
					return t, true
				}
			}
		}
	}
	if m := syslogTsRe.FindString(head); m != "" {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", strings.ReplaceAll(m, "  ", " "), time.Local); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t, true
		}
	}
	return time.Time{}, false
}

func firstField(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}

func newestLogIn(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var best string
	var bestMod time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if best == "" || info.ModTime().After(bestMod) {
			best = dir + "/" + e.Name()
			bestMod = info.ModTime()
		}
	}
	return best
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
	data, err := io.ReadAll(io.LimitReader(f, maxTailRead))
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, t := range strings.Split(decodeMaybeUTF16(f, data), "\n") {
		if t = strings.TrimSpace(t); t != "" {
			lines = append(lines, t)
		}
	}
	l.offsets[path] = size
	return lines, nil
}

func decodeMaybeUTF16(f *os.File, data []byte) string {
	var bom [2]byte
	if n, err := f.ReadAt(bom[:], 0); err != nil || n < 2 || bom[0] != 0xFF || bom[1] != 0xFE {
		return string(data)
	}
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		data = data[2:]
	}
	if len(data)%2 == 1 {
		data = data[:len(data)-1]
	}
	u := make([]uint16, len(data)/2)
	for i := range u {
		u[i] = uint16(data[2*i]) | uint16(data[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}
