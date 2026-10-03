package buffer

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"wakora.io/agent/internal/atomicfile"
)

var maxDrainRecord = 16 << 20

type Ring struct {
	path    string
	maxSize int64
	maxAge  time.Duration
	mu      sync.Mutex
	now     func() time.Time
}

func New(path string, maxSize int64, maxAge time.Duration) *Ring {
	return &Ring{path: path, maxSize: maxSize, maxAge: maxAge, now: time.Now}
}

func (r *Ring) Size() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	info, err := os.Stat(r.path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func (r *Ring) Append(line []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	stamped := strconv.FormatInt(r.now().UnixMilli(), 10) + "\t" + string(line) + "\n"
	if _, err := f.WriteString(stamped); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return r.trim()
}

func (r *Ring) trim() error {
	info, err := os.Stat(r.path)
	if err != nil {
		return nil
	}
	needSize := r.maxSize > 0 && info.Size() > r.maxSize
	needAge := r.maxAge > 0 && r.oldestStale()
	if !needSize && !needAge {
		return nil
	}
	var start int64
	if needSize {
		start = info.Size() - r.maxSize*9/10
	}
	return r.rewriteFrom(start, true)
}

func (r *Ring) rewriteFrom(start int64, dropStale bool) error {
	src, err := os.Open(r.path)
	if err != nil {
		return err
	}
	skipPartial := false
	if start > 0 {
		var prev [1]byte
		if _, err := src.ReadAt(prev[:], start-1); err == nil && prev[0] != '\n' {
			skipPartial = true
		}
		if _, err := src.Seek(start, io.SeekStart); err != nil {
			src.Close()
			return err
		}
	}
	br := bufio.NewReaderSize(src, 64<<10)
	defer src.Close()
	return atomicfile.WriteFunc(r.path, 0o600, func(w io.Writer) error {
		defer src.Close()
		first := true
		for {
			rec, n, oversized, rerr := readRecord(br, maxDrainRecord)
			if n > 0 && !(first && skipPartial) && !oversized {
				line := bytes.TrimSuffix(rec, []byte("\n"))
				if len(line) > 0 && !(dropStale && r.stale(line)) {
					if _, err := w.Write(line); err != nil {
						return err
					}
					if _, err := w.Write([]byte{'\n'}); err != nil {
						return err
					}
				}
			}
			first = false
			if rerr == io.EOF {
				return nil
			}
			if rerr != nil {
				return rerr
			}
		}
	})
}

func (r *Ring) oldestStale() bool {
	f, err := os.Open(r.path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	if !sc.Scan() {
		return false
	}
	return r.stale(sc.Bytes())
}

func (r *Ring) stale(line []byte) bool {
	if r.maxAge <= 0 {
		return false
	}
	ts, _, ok := splitStamp(line)
	if !ok {
		return false
	}
	return r.now().Sub(time.UnixMilli(ts)) > r.maxAge
}

func splitStamp(line []byte) (int64, []byte, bool) {
	i := bytes.IndexByte(line, '\t')
	if i <= 0 {
		return 0, line, false
	}
	ts, err := strconv.ParseInt(string(line[:i]), 10, 64)
	if err != nil {
		return 0, line, false
	}
	return ts, line[i+1:], true
}

func (r *Ring) Drain(fn func([]byte) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var sent int64
	br := bufio.NewReaderSize(f, 64<<10)
	for {
		rec, n, oversized, rerr := readRecord(br, maxDrainRecord)
		if n > 0 {
			line := bytes.TrimSuffix(rec, []byte("\n"))
			switch {
			case oversized:
				log.Printf("spool: dropping oversized record (%d bytes)", n)
				sent += int64(n)
			case r.stale(line):
				sent += int64(n)
			default:
				_, payload, _ := splitStamp(line)
				if ferr := fn(payload); ferr != nil {
					f.Close()
					r.dropPrefix(sent)
					return ferr
				}
				sent += int64(n)
			}
		}
		if rerr != nil {
			f.Close()
			if rerr == io.EOF {
				return os.Remove(r.path)
			}
			r.dropPrefix(sent)
			return rerr
		}
	}
}

func readRecord(br *bufio.Reader, cap int) (line []byte, n int, oversized bool, err error) {
	for {
		chunk, e := br.ReadSlice('\n')
		n += len(chunk)
		if !oversized {
			line = append(line, chunk...)
			if len(line) > cap {
				oversized = true
				line = nil
			}
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		return line, n, oversized, e
	}
}

func (r *Ring) dropPrefix(offset int64) {
	if offset <= 0 {
		return
	}
	info, err := os.Stat(r.path)
	if err != nil {
		return
	}
	if offset >= info.Size() {
		_ = os.Remove(r.path)
		return
	}
	if err := r.rewriteFrom(offset, false); err != nil {
		log.Printf("spool: cannot drop the replayed prefix: %v", err)
	}
}
