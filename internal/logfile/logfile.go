package logfile

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const maxSize = 10 << 20

type writer struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func Setup(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	w := &writer{path: path}
	if err := w.open(); err != nil {
		return err
	}
	log.SetOutput(io.MultiWriter(os.Stderr, w))
	return nil
}

func (w *writer) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f = f
	w.size = st.Size()
	return nil
}

func (w *writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size+int64(len(p)) > maxSize {
		w.f.Close()
		_ = os.Rename(w.path, w.path+".old")
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}
