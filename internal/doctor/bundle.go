package doctor

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/discovery"
)

var bundleRedact = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization:?\s*bearer\s+)\S+`),
	regexp.MustCompile(`(?i)((?:api[_-]?key|apikey|token|secret|password|passwd|pwd)["'\s:=]{1,3})\S+`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`),
}

func redactLine(s string) string {
	for _, re := range bundleRedact {
		s = re.ReplaceAllString(s, "***")
	}
	return s
}

func WriteBundle(in Input, checks []Check) (string, error) {
	host, _ := os.Hostname()
	if host == "" {
		host = "host"
	}
	host = sanitize(host)
	path := filepath.Join(os.TempDir(), fmt.Sprintf("wakora-doctor-%s-%s.tar.gz", host, time.Now().Format("20060102-150405")))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	add := func(name string, body []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), ModTime: time.Now()})
		_, _ = tw.Write(body)
	}

	add("doctor.txt", []byte(Render(checks)))
	add("versions.txt", []byte(versionsText(in)))
	add("discovery.txt", []byte(discoveryCounts()))
	if st, err := os.ReadFile(filepath.Join(stateDirOr(in.StateDir), "status.json")); err == nil {
		add("status.json", st)
	}
	if tail := logTail(in.LogPath, 500); tail != "" {
		add("agent.log", []byte(tail))
	}
	return path, nil
}

func versionsText(in Input) string {
	var b strings.Builder
	fmt.Fprintf(&b, "version: %s\n", buildinfo.Version)
	fmt.Fprintf(&b, "os: %s\n", runtime.GOOS)
	fmt.Fprintf(&b, "arch: %s\n", runtime.GOARCH)
	fmt.Fprintf(&b, "endpoint: %s\n", in.Endpoint)
	if in.ConfPin != "" {
		fmt.Fprintf(&b, "pin: %s\n", in.ConfPin)
	}
	return b.String()
}

func discoveryCounts() string {
	facts := discovery.Collect()
	byKind := map[string]int{}
	for _, f := range facts {
		byKind[f.Kind]++
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var b strings.Builder
	b.WriteString("discovery snapshot (counts only, no content):\n")
	for _, k := range kinds {
		fmt.Fprintf(&b, "  %-12s %d\n", k, byKind[k])
	}
	return b.String()
}

func logTail(path string, n int) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var lines []string
	for sc.Scan() {
		lines = append(lines, redactLine(sc.Text()))
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n"
}

func stateDirOr(d string) string {
	if d == "" {
		return "/var/lib/wakora"
	}
	return d
}

func sanitize(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "host"
	}
	return b.String()
}
