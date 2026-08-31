package agent

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"wakora.io/agent/internal/protocol"
)

var rumTraceRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
var rumSiteRe = regexp.MustCompile(`^[a-z0-9.-]+$`)
var rumFrustNames = map[string]bool{"rage": true, "error_click": true}

func sanitizeFrust(in []protocol.RumFrust) []protocol.RumFrust {
	if len(in) == 0 {
		return nil
	}
	out := make([]protocol.RumFrust, 0, len(in))
	for _, f := range in {
		if !rumFrustNames[f.Name] {
			continue
		}
		if len(f.Sel) > 120 {
			f.Sel = f.Sel[:120]
		}
		if f.Count < 1 {
			f.Count = 1
		}
		if f.Count > 1000 {
			f.Count = 1000
		}
		out = append(out, f)
		if len(out) >= 5 {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeCrumbs(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > 2048 {
		return ""
	}
	if !json.Valid([]byte(s)) {
		return ""
	}
	return s
}

func (a *Agent) setRumSites(sites []string) {
	norm := make([]string, 0, len(sites))
	seen := map[string]bool{}
	for _, s := range sites {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "www.")
		if s == "" || seen[s] {
			continue
		}
		if !rumSiteRe.MatchString(s) {
			log.Printf("rum sites: invalid site name dropped: %q", s)
			continue
		}
		seen[s] = true
		norm = append(norm, s)
	}
	sort.Strings(norm)
	prev, _ := a.rumAllowed.Load().(map[string]bool)
	same := len(prev) == len(seen)
	if same {
		for s := range seen {
			if !prev[s] {
				same = false
				break
			}
		}
	}
	a.rumAllowed.Store(seen)
	if same && prev != nil {
		return
	}
	if runtime.GOOS == "windows" {
		return
	}
	if len(norm) > 0 {
		log.Printf("rum sites: %v", norm)
	}
	a.writeRumSitesFile(norm)
}

func (a *Agent) writeRumSitesFile(sites []string) {
	writeRumSites(filepath.Join(a.cfg.StateDir(), "apm"), sites)
}

func writeRumSites(dir string, sites []string) {
	path := filepath.Join(dir, "rum-sites.php")
	if len(sites) == 0 {
		if _, err := os.Stat(path); err != nil {
			return
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("rum sites: mkdir: %v", err)
		return
	}
	var b strings.Builder
	b.WriteString("<?php return [")
	n := 0
	for _, s := range sites {
		if !rumSiteRe.MatchString(s) {
			continue
		}
		if n > 0 {
			b.WriteString(",")
		}
		b.WriteString("'" + s + "'=>1")
		n++
	}
	b.WriteString("];\n")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		log.Printf("rum sites: write: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("rum sites: rename: %v", err)
	}
}

func (a *Agent) handleRumBeacon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<10))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var it protocol.RumItem
	if err := json.Unmarshal(body, &it); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	it.Site = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(it.Site)), "www.")
	allowed, _ := a.rumAllowed.Load().(map[string]bool)
	if it.Site == "" || !allowed[it.Site] {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(it.Path) > 300 {
		it.Path = it.Path[:300]
	}
	if len(it.Dev) > 30 {
		it.Dev = it.Dev[:30]
	}
	if len(it.Browser) > 30 {
		it.Browser = it.Browser[:30]
	}
	if it.IP != "" && net.ParseIP(it.IP) == nil {
		it.IP = ""
	}
	if it.Trace != "" && !rumTraceRe.MatchString(it.Trace) {
		it.Trace = ""
	}
	if len(it.Errors) > 10 {
		it.Errors = it.Errors[:10]
	}
	it.Frust = sanitizeFrust(it.Frust)
	it.Crumbs = sanitizeCrumbs(it.Crumbs)
	select {
	case a.rum <- []protocol.RumItem{it}:
	default:
	}
	w.WriteHeader(http.StatusNoContent)
}
