//go:build linux

package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/apm"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: phpsample <pid> <version> [seconds]")
		os.Exit(2)
	}
	pid, _ := strconv.Atoi(os.Args[1])
	version := os.Args[2]
	secs := 3
	if len(os.Args) > 3 {
		secs, _ = strconv.Atoi(os.Args[3])
	}
	s, err := apm.NewPHPSampler(pid, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "attach:", err)
		os.Exit(1)
	}
	folded := map[string]int{}
	total, hits := 0, 0
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	for time.Now().Before(deadline) {
		total++
		frames, _, err := s.Sample()
		if err == nil && len(frames) > 0 {
			hits++
			folded[strings.Join(frames, ";")]++
		}
		time.Sleep(5 * time.Millisecond)
	}
	fmt.Printf("php %s pid %d: samples=%d hits=%d (%.0f%%) uniqueStacks=%d\n",
		version, pid, total, hits, float64(hits)/float64(total)*100, len(folded))
	keys := make([]string, 0, len(folded))
	for k := range folded {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return folded[keys[i]] > folded[keys[j]] })
	for i, k := range keys {
		if i >= 5 {
			break
		}
		fmt.Printf("%6d  %s\n", folded[k], k)
	}
}
