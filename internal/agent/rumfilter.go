package agent

import "strings"

func vhostSiteName(key string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	if i := strings.LastIndexByte(k, ':'); i > 0 {
		if port := k[i+1:]; port != "" && allDigits(port) {
			k = k[:i]
		}
	}
	return strings.TrimPrefix(k, "www.")
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func filterSitesByVhosts(sites, vhostKeys []string) []string {
	exact := make(map[string]bool, len(vhostKeys))
	var wild []string
	for _, k := range vhostKeys {
		n := vhostSiteName(k)
		if n == "" {
			continue
		}
		if strings.HasPrefix(n, "*.") {
			wild = append(wild, n[1:])
			continue
		}
		exact[n] = true
	}
	if len(exact) == 0 && len(wild) == 0 {
		return sites
	}
	out := make([]string, 0, len(sites))
	for _, s := range sites {
		if exact[s] {
			out = append(out, s)
			continue
		}
		for _, w := range wild {
			if strings.HasSuffix(s, w) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

func (a *Agent) vhostKeys() []string {
	a.mu.Lock()
	facts := a.facts
	a.mu.Unlock()
	var out []string
	for _, f := range facts {
		if f.Kind == "vhost" {
			out = append(out, f.Key)
		}
	}
	return out
}
