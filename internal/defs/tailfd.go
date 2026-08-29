package defs

import "os"

var (
	fdCacheCap = 512
	rotCheckN  = 10
)

type tailHandle struct {
	f       *os.File
	st      os.FileInfo
	keep    bool
	rotated bool
}

func (h *tailHandle) done() {
	if !h.keep {
		h.f.Close()
	}
}

type cachedFile struct {
	f    *os.File
	born os.FileInfo
	uses int
}

type fdCache struct {
	m map[string]*cachedFile
}

func newFdCache() *fdCache {
	return &fdCache{m: map[string]*cachedFile{}}
}

func (c *fdCache) get(path string) (*tailHandle, error) {
	cf, ok := c.m[path]
	if !ok {
		return c.open(path, false)
	}
	cf.uses++
	if cf.uses%rotCheckN == 0 {
		disk, err := os.Stat(path)
		if err != nil || !os.SameFile(cf.born, disk) {
			cf.f.Close()
			delete(c.m, path)
			if err != nil {
				return nil, err
			}
			return c.open(path, true)
		}
	}
	st, err := cf.f.Stat()
	if err != nil {
		cf.f.Close()
		delete(c.m, path)
		return nil, err
	}
	return &tailHandle{f: cf.f, st: st, keep: true}, nil
}

func (c *fdCache) open(path string, rotated bool) (*tailHandle, error) {
	f, err := openTail(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	tailAdvise(f)
	if len(c.m) < fdCacheCap {
		c.m[path] = &cachedFile{f: f, born: st}
		return &tailHandle{f: f, st: st, keep: true, rotated: rotated}, nil
	}
	return &tailHandle{f: f, st: st, rotated: rotated}, nil
}

func (c *fdCache) has(path string) bool {
	_, ok := c.m[path]
	return ok
}

func (c *fdCache) sweep(seen map[string]bool) {
	for path, cf := range c.m {
		if !seen[path] {
			cf.f.Close()
			delete(c.m, path)
		}
	}
}

func (c *fdCache) closeAll() {
	for path, cf := range c.m {
		cf.f.Close()
		delete(c.m, path)
	}
}
