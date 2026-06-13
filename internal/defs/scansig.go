package defs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const sigAbsent = "-"

func fileSig(path string) string {
	if path == "" {
		return sigAbsent
	}
	fi, err := os.Stat(path)
	if err != nil {
		return sigAbsent
	}
	return fmt.Sprintf("%d|%d", fi.Size(), fi.ModTime().UnixNano())
}

func hashItems(items []string) string {
	sort.Strings(items)
	h := sha256.New()
	for _, it := range items {
		h.Write([]byte(it))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func dirSig(dir, suffix string) string {
	if dir == "" {
		return sigAbsent
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return sigAbsent
	}
	items := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || (suffix != "" && !strings.HasSuffix(e.Name(), suffix)) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, fmt.Sprintf("%s|%d|%d", e.Name(), info.Size(), info.ModTime().UnixNano()))
	}
	return hashItems(items)
}

func globSig(patterns ...string) string {
	var items []string
	for _, g := range patterns {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			items = append(items, f+"|"+fileSig(f))
		}
	}
	return hashItems(items)
}
