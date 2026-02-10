package buffer

import (
	"bufio"
	"os"
	"sync"
)

type Ring struct {
	path    string
	maxSize int64
	mu      sync.Mutex
}

func New(path string, maxSize int64) *Ring {
	return &Ring{path: path, maxSize: maxSize}
}

func (r *Ring) Append(line []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return r.trim()
}

func (r *Ring) trim() error {
	info, err := os.Stat(r.path)
	if err != nil || r.maxSize <= 0 || info.Size() <= r.maxSize {
		return nil
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	if int64(len(data)) > r.maxSize {
		data = data[int64(len(data))-r.maxSize:]
	}
	return os.WriteFile(r.path, data, 0o600)
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
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if err := fn(sc.Bytes()); err != nil {
			f.Close()
			return err
		}
	}
	f.Close()
	return os.Remove(r.path)
}
