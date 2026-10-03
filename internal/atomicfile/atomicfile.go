package atomicfile

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
)

func Write(path string, data []byte, perm os.FileMode) error {
	return WriteFunc(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

func WriteFunc(path string, perm os.FileMode, fill func(io.Writer) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	bw := bufio.NewWriterSize(tmp, 64<<10)
	if err := fill(bw); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := bw.Flush(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
