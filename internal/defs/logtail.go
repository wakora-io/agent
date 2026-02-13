package defs

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"time"

	"wakora.io/agent/internal/protocol"
)

const maxTailRead = 8 << 20

type Tailer struct {
	path   string
	offset int64
	lastAt time.Time
	res    map[string]*regexp.Regexp
}

func NewTailer(path string) *Tailer {
	return &Tailer{path: path, res: map[string]*regexp.Regexp{}}
}

func (t *Tailer) compile(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	if re, ok := t.res[pattern]; ok {
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	t.res[pattern] = re
	return re
}

func (t *Tailer) Sample(counters []protocol.Counter, now time.Time) ([]protocol.MetricPoint, error) {
	f, err := os.Open(t.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()

	if t.lastAt.IsZero() {
		t.offset = size
		t.lastAt = now
		return nil, nil
	}
	if size < t.offset {
		t.offset = 0
	}
	start := t.offset
	if size-start > maxTailRead {
		start = size - maxTailRead
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}

	counts := make([]int, len(counters))
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		for i, c := range counters {
			re := t.compile(c.Regex)
			if re == nil || re.Match(line) {
				counts[i]++
			}
		}
	}
	elapsed := now.Sub(t.lastAt).Seconds()
	t.offset = size
	t.lastAt = now
	if elapsed <= 0 {
		return nil, nil
	}

	var pts []protocol.MetricPoint
	for i, c := range counters {
		pts = append(pts, protocol.MetricPoint{Name: c.Name, Value: float64(counts[i]) / elapsed})
	}
	return pts, nil
}
