package defs

import (
	"regexp"
	"strings"
)

type iisSite struct {
	name  string
	state string
	hosts []string
}

var iisBindingRe = regexp.MustCompile(`[a-z]+/[^:,()]*:\d+:([^,)]*)`)

func parseIISSites(out string) []iisSite {
	var res []iisSite
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `SITE "`) {
			continue
		}
		rest := line[len(`SITE "`):]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			continue
		}
		st := iisSite{name: rest[:end]}
		if i := strings.Index(rest, "state:"); i >= 0 {
			s := rest[i+len("state:"):]
			if j := strings.IndexAny(s, ",)"); j >= 0 {
				s = s[:j]
			}
			st.state = strings.TrimSpace(s)
		}
		seen := map[string]bool{}
		for _, m := range iisBindingRe.FindAllStringSubmatch(rest, -1) {
			h := strings.ToLower(strings.TrimSpace(m[1]))
			if h == "" || h == "*" || seen[h] {
				continue
			}
			seen[h] = true
			st.hosts = append(st.hosts, h)
		}
		res = append(res, st)
	}
	return res
}

func parseAppcmd(out, kind string) map[string]string {
	res := map[string]string{}
	prefix := kind + " \""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := line[len(prefix):]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			continue
		}
		name := rest[:end]
		state := ""
		if i := strings.Index(rest, "state:"); i >= 0 {
			s := rest[i+len("state:"):]
			if j := strings.IndexAny(s, ",)"); j >= 0 {
				s = s[:j]
			}
			state = strings.TrimSpace(s)
		}
		res[name] = state
	}
	return res
}
