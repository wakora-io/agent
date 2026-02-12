package config

import (
	"bufio"
	"io"
	"os"
	"sort"
	"strings"
)

func parseINI(r io.Reader) map[string]map[string]string {
	out := map[string]map[string]string{"": {}}
	section := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if out[section] == nil {
				out[section] = map[string]string{}
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		if k != "" {
			out[section][k] = v
		}
	}
	return out
}

func writeINI(path string, sections map[string]map[string]string) error {
	names := make([]string, 0, len(sections))
	for n := range sections {
		if len(sections[n]) > 0 {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		if n != "" {
			b.WriteString("[" + n + "]\n")
		}
		vals := sections[n]
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(k + " = " + vals[k] + "\n")
		}
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
