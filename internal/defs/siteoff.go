package defs

import (
	"strings"
	"sync/atomic"
)

var sitesOff atomic.Value

func SetSitesOff(list []string) {
	m := make(map[string]bool, len(list))
	for _, s := range list {
		if k := siteKey(s); k != "" {
			m[k] = true
		}
	}
	sitesOff.Store(m)
}

func siteOff(name string) bool {
	m, _ := sitesOff.Load().(map[string]bool)
	return len(m) > 0 && m[siteKey(name)]
}

func siteKey(s string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "www.")
}
