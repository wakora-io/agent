package apm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func bundleArchive(t *testing.T, dir, marker string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte(marker)
	if err := tw.WriteHeader(&tar.Header{Name: "wakora-otel.php", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, marker+".tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUnpackReplacesABundleWithoutLeavingLeftovers(t *testing.T) {
	dir := t.TempDir()
	p := &Provisioner{dir: dir}

	if err := p.unpackFile("sdk", bundleArchive(t, dir, "first")); err != nil {
		t.Fatal(err)
	}
	prepend := filepath.Join(dir, "sdk", "wakora-otel.php")
	if b, err := os.ReadFile(prepend); err != nil || string(b) != "first" {
		t.Fatalf("first unpack wrong: %q %v", b, err)
	}

	if err := p.unpackFile("sdk", bundleArchive(t, dir, "second")); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(prepend); err != nil || string(b) != "second" {
		t.Fatalf("refresh did not land: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".sdk.old")); !os.IsNotExist(err) {
		t.Fatal("the previous bundle was left behind - the swap must clean up after itself")
	}
	if _, err := os.Stat(filepath.Join(dir, ".tmp-sdk")); !os.IsNotExist(err) {
		t.Fatal("the staging dir was left behind")
	}
}

func TestUnpackKeepsTheOldBundleWhenTheArchiveIsBroken(t *testing.T) {
	dir := t.TempDir()
	p := &Provisioner{dir: dir}
	if err := p.unpackFile("sdk", bundleArchive(t, dir, "first")); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(dir, "broken.tar.gz")
	if err := os.WriteFile(broken, []byte("not a gzip stream"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.unpackFile("sdk", broken); err == nil {
		t.Fatal("a broken archive must fail")
	}
	b, err := os.ReadFile(filepath.Join(dir, "sdk", "wakora-otel.php"))
	if err != nil || string(b) != "first" {
		t.Fatalf("an applied bundle must survive a failed refresh - an active prepend reads it on every request: %q %v", b, err)
	}
}
