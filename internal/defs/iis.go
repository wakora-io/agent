package defs

import "strings"

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
