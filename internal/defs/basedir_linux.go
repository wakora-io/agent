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

func nginxBasedirPrepCommand(apmDir string, dirs []string) string {
	if len(dirs) == 0 || len(dirs) > 4 {
		return ""
	}
	globs := make([]string, len(dirs))
	for i, d := range dirs {
		globs[i] = d + "/*"
	}
	return `sed -i.wakora-bak '/open_basedir/{\#` + apmDir + `#!s#\(open_basedir=[^";\\ ]*\)#\1:` + apmDir + `#g}' ` +
		strings.Join(globs, " ") + ` && nginx -t && systemctl reload nginx`
}

type basedirScanResult struct {
	nginxFiles int
	userIni    int
	samples    []string
	nginxDirs  []string
}

type basedirScanCacheSet struct {
	mu   sync.Mutex
	sig  string
	when time.Time
	res  basedirScanResult
}

var basedirScanCache basedirScanCacheSet

var (
	basedirValRe = regexp.MustCompile(`open_basedir\s*=\s*"?([^";\s]+)`)
	nginxRootRe  = regexp.MustCompile(`(?m)^\s*root\s+([^;\s]+)\s*;`)
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
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 1<<20 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, m := range basedirValRe.FindAllSubmatch(data, -1) {
			if !basedirCovers(string(m[1]), apmDir) {
				res.nginxFiles++
				dirs[filepath.Dir(path)] = true
				if len(res.samples) < 3 {
					res.samples = append(res.samples, path)
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
