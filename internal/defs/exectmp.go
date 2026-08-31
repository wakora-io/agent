//go:build !windows

package defs

import (
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var execTmpDir atomic.Value

func SetExecTmpDir(dir string) { execTmpDir.Store(dir) }

var (
	tmpMu      sync.Mutex
	tmpChecked time.Time
	tmpFall    string
)

func execEnv() []string {
	dir := tmpFallbackDir()
	if dir == "" {
		return nil
	}
	return append(os.Environ(), "TMPDIR="+dir)
}

func tmpFallbackDir() string {
	tmpMu.Lock()
	defer tmpMu.Unlock()
	if time.Since(tmpChecked) < 5*time.Minute {
		return tmpFall
	}
	tmpChecked = time.Now()
	tmpFall = ""
	if tmpWritable() {
		return ""
	}
	base, _ := execTmpDir.Load().(string)
	if base == "" {
		return ""
	}
	if os.MkdirAll(base, 0o700) != nil {
		return ""
	}
	probe, err := os.CreateTemp(base, ".w")
	if err != nil {
		return ""
	}
	name := probe.Name()
	probe.Close()
	os.Remove(name)
	tmpFall = base
	return tmpFall
}

func tmpWritable() bool {
	f, err := os.CreateTemp(os.TempDir(), ".wakora")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}
