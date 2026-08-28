package defs

import (
	"bufio"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

const maxTailRead = 8 << 20

func AnyPathExists(paths []string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

type Tailer struct {
	paths   []string
	offsets map[string]int64
	lastAt  time.Time
	res     map[string]*regexp.Regexp
	srcLast map[string]time.Time
	fds     *fdCache
}

func NewTailer(paths []string) *Tailer {
	return &Tailer{paths: paths, offsets: map[string]int64{}, res: map[string]*regexp.Regexp{}, srcLast: map[string]time.Time{}, fds: newFdCache()}
}

func (t *Tailer) Key() string {
	return strings.Join(t.paths, ",")
}

func (t *Tailer) CloseFDs() {
	t.fds.closeAll()
}

func (t *Tailer) compile(pattern string) *regexp.Regexp {
	re, _ := t.compileOK(pattern)
	return re
}

func (t *Tailer) compileOK(pattern string) (*regexp.Regexp, bool) {
	if pattern == "" {
		return nil, true
	}
	if re, ok := t.res[pattern]; ok {
		return re, re != nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		log.Printf("logtail: counter pattern %q does not compile (%v) - the counter is withheld, not defaulted to every line", pattern, err)
		re = nil
	}
	t.res[pattern] = re
	return re, err == nil
}

func (t *Tailer) Sample(counters []protocol.Counter, now time.Time) ([]protocol.MetricPoint, []protocol.AgentEvent, error) {
	first := t.lastAt.IsZero()
	counts := make([]int, len(counters))
	sources := make([]map[string]int, len(counters))
	var firstErr error
	for _, path := range t.paths {
		if err := t.sampleFile(path, counters, counts, sources, first); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if first {
		t.lastAt = now
		return nil, nil, firstErr
	}
	elapsed := now.Sub(t.lastAt).Seconds()
	t.lastAt = now
	if elapsed <= 0 {
		return nil, nil, firstErr
	}
	var pts []protocol.MetricPoint
	var events []protocol.AgentEvent
	for i, c := range counters {
		if _, ok := t.compileOK(c.Regex); !ok {
			continue
		}
		pts = append(pts, protocol.MetricPoint{Name: c.Name, Value: float64(counts[i]) / elapsed})
		if c.Event != "" {
			if ev, ok := foldSourceEvent(c, sources[i], now, t.srcLast); ok {
				events = append(events, ev)
			}
		}
	}
	return pts, events, firstErr
}

func (t *Tailer) sampleFile(path string, counters []protocol.Counter, counts []int, sources []map[string]int, first bool) error {
	h, err := t.fds.get(path)
	if err != nil {
		return err
	}
	defer h.done()
	size := h.st.Size()
	if first {
		t.offsets[path] = size
		return nil
	}
	if h.rotated {
		t.offsets[path] = 0
	}
	start := t.offsets[path]
	if size < start {
		start = 0
	}
	if size-start > maxTailRead {
		start = size - maxTailRead
	}
	if _, err := h.f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	sc := bufio.NewScanner(h.f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		for i, c := range counters {
			re, ok := t.compileOK(c.Regex)
			if !ok {
				continue
			}
			if re == nil || re.Match(line) {
				counts[i]++
				if c.Capture != "" {
					if cre := t.compile(c.Capture); cre != nil {
						if m := cre.FindSubmatch(line); len(m) >= 2 {
							if sources[i] == nil {
								sources[i] = map[string]int{}
							}
							sources[i][string(m[1])]++
						}
					}
				}
			}
		}
	}
	t.offsets[path] = size
	return nil
}
