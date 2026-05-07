package defs

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"

	"wakora.io/agent/internal/protocol"
)

func timeNowUnix() int64 { return time.Now().Unix() }

type SyslogListener struct {
	port int

	mu       sync.Mutex
	total    uint64
	severe   uint64
	dropped  uint64
	matches  map[string]uint64
	patterns map[string]*regexp.Regexp
	allow    map[string]bool
	lastErr  error
	lines    []SyslogLine

	conn *net.UDPConn
}

type SyslogLine struct {
	Ts       int64
	Source   string
	Severity int
	Message  string
}

const syslogLineCap = 200

func NewSyslogListener(port int) *SyslogListener {
	if port <= 0 {
		port = 514
	}
	return &SyslogListener{
		port:     port,
		matches:  map[string]uint64{},
		patterns: map[string]*regexp.Regexp{},
		allow:    map[string]bool{},
	}
}

func (s *SyslogListener) Port() int { return s.port }

func (s *SyslogListener) Configure(counters []protocol.Counter, allowFrom []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range counters {
		if c.Regex == "" || s.patterns[c.Name] != nil {
			continue
		}
		if re, err := regexp.Compile(c.Regex); err == nil {
			s.patterns[c.Name] = re
		}
	}
	allow := make(map[string]bool, len(allowFrom))
	for _, ip := range allowFrom {
		if ip != "" {
			allow[ip] = true
		}
	}
	s.allow = allow
}

func (s *SyslogListener) Start() {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", s.port))
	if err != nil {
		s.mu.Lock()
		s.lastErr = err
		s.mu.Unlock()
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		s.mu.Lock()
		s.lastErr = err
		s.mu.Unlock()
		return
	}
	s.conn = conn
	go func() {
		buf := make([]byte, 8192)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			s.ingest(from.IP.String(), string(buf[:n]))
		}
	}()
}

func (s *SyslogListener) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *SyslogListener) ingest(source, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.allow) > 0 && !s.allow[source] {
		s.dropped++
		return
	}
	s.total++
	sev, sevOk := syslogSeverity(line)
	if sevOk && sev <= 3 {
		s.severe++
	}
	for name, re := range s.patterns {
		if re.MatchString(line) {
			s.matches[name]++
		}
	}
	if !sevOk {
		sev = 6
	}
	msg := line
	if i := indexAfterPri(line); i > 0 {
		msg = line[i:]
	}
	if len(s.lines) < syslogLineCap {
		s.lines = append(s.lines, SyslogLine{Ts: timeNowUnix(), Source: source, Severity: sev, Message: msg})
	}
}

func indexAfterPri(line string) int {
	if len(line) < 3 || line[0] != '<' {
		return 0
	}
	for i := 1; i < len(line) && i <= 4; i++ {
		if line[i] == '>' {
			return i + 1
		}
	}
	return 0
}

func (s *SyslogListener) DrainLines() []SyslogLine {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.lines
	s.lines = nil
	return out
}

func (s *SyslogListener) Snapshot() (total, severe, dropped uint64, matches map[string]uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.matches))
	for k, v := range s.matches {
		out[k] = v
	}
	return s.total, s.severe, s.dropped, out, s.lastErr
}

func syslogSeverity(line string) (int, bool) {
	if len(line) < 3 || line[0] != '<' {
		return 0, false
	}
	end := 1
	for end < len(line) && end <= 4 && line[end] != '>' {
		end++
	}
	if end >= len(line) || line[end] != '>' {
		return 0, false
	}
	pri, err := strconv.Atoi(line[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return 0, false
	}
	return pri % 8, true
}
