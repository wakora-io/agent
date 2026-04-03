//go:build linux

package defs

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

func nginxBasedirPrepCommand(stateDir string, dirs []string) string {
	if len(dirs) == 0 || len(dirs) > 4 {
		return ""
	}
	apmDir := filepath.Join(stateDir, "apm")
	parts := []string{`B=` + filepath.Join(stateDir, "backups") + `/nginx-prep-$(date +%F-%H%M%S)`}
	globs := make([]string, len(dirs))
	for i, d := range dirs {
		sub := strings.ReplaceAll(strings.Trim(d, "/"), "/", "_")
		parts = append(parts,
			`mkdir -p $B/`+sub,
			`cp -a `+d+`/* $B/`+sub+`/`,
		)
		globs[i] = d + "/*"
	}
	parts = append(parts,
		`sed -i '/open_basedir/{\#`+apmDir+`#!s#\(open_basedir[[:space:]]*=[[:space:]]*\)\([^";\\ ]*\)#\1\2:`+apmDir+`#g}' `+strings.Join(globs, " "),
		`nginx -t`,
		`systemctl reload nginx`,
	)
	return strings.Join(parts, " && ")
}

type basedirScanResult struct {
	nginxFiles int
	userIni    int
	samples    []string
	nginxDirs  []string
	sampleLine string
}

type basedirScanCacheSet struct {
	mu   sync.Mutex
	sig  string
	when time.Time
	res  basedirScanResult
}

var basedirScanCache basedirScanCacheSet

var (
	basedirValRe  = regexp.MustCompile(`open_basedir\s*=\s*"?([^";\s]+)`)
	basedirLineRe = regexp.MustCompile(`(?m)^.*open_basedir.*$`)
	nginxRootRe   = regexp.MustCompile(`(?m)^\s*root\s+([^;\s]+)\s*;`)
)

func basedirOutsideScan(apmDir string) basedirScanResult {
	sig := configTreeSig("/etc/nginx")
	if sig == "" {
		return basedirScanResult{}
	}
	basedirScanCache.mu.Lock()
	if basedirScanCache.sig == sig && time.Since(basedirScanCache.when) < 30*time.Minute {
		res := basedirScanCache.res
		basedirScanCache.mu.Unlock()
		return res
	}
	basedirScanCache.mu.Unlock()

	res := scanNginxBasedir("/etc/nginx", apmDir)

	basedirScanCache.mu.Lock()
	basedirScanCache.sig = sig
	basedirScanCache.when = time.Now()
	basedirScanCache.res = res
	basedirScanCache.mu.Unlock()
	return res
}

func scanNginxBasedir(root, apmDir string) basedirScanResult {
	var res basedirScanResult
	docroots := map[string]bool{}
	dirs := map[string]bool{}
	seenReal := map[string]bool{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		real, err := filepath.EvalSymlinks(path)
		if err != nil || seenReal[real] {
			return nil
		}
		seenReal[real] = true
		if fi, err := os.Stat(real); err != nil || fi.Size() > 1<<20 {
			return nil
		}
		data, err := os.ReadFile(real)
		if err != nil {
			return nil
		}
		for _, m := range basedirValRe.FindAllSubmatch(data, -1) {
			if !basedirCovers(string(m[1]), apmDir) {
				res.nginxFiles++
				dirs[filepath.Dir(real)] = true
				if len(res.samples) < 3 {
					res.samples = append(res.samples, real)
				}
				if res.sampleLine == "" {
					if line := basedirLineRe.Find(data); line != nil {
						s := strings.TrimSpace(string(line))
						if len(s) > 160 {
							s = s[:160]
						}
						res.sampleLine = s
					}
				}
				break
			}
		}
		for _, m := range nginxRootRe.FindAllSubmatch(data, -1) {
			if len(docroots) < 500 {
				docroots[string(m[1])] = true
			}
		}
		return nil
	})
	for d := range dirs {
		res.nginxDirs = append(res.nginxDirs, d)
	}
	sort.Strings(res.nginxDirs)
	for dir := range docroots {
		ini := filepath.Join(dir, ".user.ini")
		fi, err := os.Stat(ini)
		if err != nil || fi.IsDir() || fi.Size() > 1<<20 {
			continue
		}
		data, err := os.ReadFile(ini)
		if err != nil {
			continue
		}
		for _, m := range basedirValRe.FindAllSubmatch(data, -1) {
			if !basedirCovers(string(m[1]), apmDir) {
				res.userIni++
				if len(res.samples) < 6 {
					res.samples = append(res.samples, ini)
				}
				break
			}
		}
	}
	return res
}
