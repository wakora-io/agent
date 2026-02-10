package discovery

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Facts struct {
	Processes []string
}

func Enumerate() Facts {
	var f Facts
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return f
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		f.Processes = append(f.Processes, strings.TrimSpace(string(comm)))
	}
	return f
}
