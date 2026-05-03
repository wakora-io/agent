package agent

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"wakora.io/agent/internal/protocol"
)

func (a *Agent) setRumSites(sites []string) {
	norm := make([]string, 0, len(sites))
	seen := map[string]bool{}
	for _, s := range sites {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "www.")
		if s == "" || seen[s] {
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
	for i, s := range sites {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("'" + strings.ReplaceAll(s, "'", "") + "'=>1")
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
	if len(it.Errors) > 10 {
		it.Errors = it.Errors[:10]
	}
	select {
	case a.rum <- []protocol.RumItem{it}:
	default:
	}
	w.WriteHeader(http.StatusNoContent)
}
