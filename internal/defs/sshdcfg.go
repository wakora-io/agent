package defs

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const sshdConfigPath = "/etc/ssh/sshd_config"

const sshdFallbackNote = "sshd has not started since boot, values read from sshd_config"

var sshdFallbackDefaults = [][2]string{
	{"permitrootlogin", "prohibit-password"},
	{"passwordauthentication", "yes"},
	{"port", "22"},
}

func sshdPrivsepMissing(out []byte) bool {
	return strings.Contains(strings.ToLower(string(out)), "privilege separation directory")
}

func sshdConfigEffective(path string) ([]byte, bool) {
	var pairs [][2]string
	if _, ok := sshdConfigRead(path, filepath.Dir(path), 0, &pairs); !ok {
		return nil, false
	}
	seen := map[string]bool{}
	var b strings.Builder
	for _, kv := range pairs {
		if kv[0] != "port" && seen[kv[0]] {
			continue
		}
		seen[kv[0]] = true
		b.WriteString(kv[0] + " " + kv[1] + "\n")
	}
	for _, d := range sshdFallbackDefaults {
		if !seen[d[0]] {
			b.WriteString(d[0] + " " + d[1] + "\n")
		}
	}
	return []byte(b.String()), true
}

func sshdConfigRead(path, base string, depth int, pairs *[][2]string) (bool, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	if len(data) > 1<<20 {
		data = data[:1<<20]
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexAny(line, " \t=")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(line[:idx])
		value := strings.TrimSpace(strings.TrimLeft(line[idx:], " \t="))
		if value == "" {
			continue
		}
		switch key {
		case "match":
			return true, true
		case "include":
			if depth >= 16 {
				continue
			}
			for _, pat := range strings.Fields(value) {
				if !filepath.IsAbs(pat) && !strings.HasPrefix(pat, "/") {
					pat = filepath.Join(base, pat)
				}
				matches, _ := filepath.Glob(pat)
				sort.Strings(matches)
				for _, m := range matches {
					if stopped, _ := sshdConfigRead(m, base, depth+1, pairs); stopped {
						return true, true
					}
				}
			}
			continue
		}
		*pairs = append(*pairs, [2]string{key, strings.ToLower(value)})
	}
	return false, true
}
