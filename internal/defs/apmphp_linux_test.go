//go:build linux

package defs

import "testing"

func TestParseModPhpMinor(t *testing.T) {
	load := []byte("# apache2 php module\nLoadModule php_module /usr/lib/apache2/modules/libphp8.3.so\n")
	if got := parseModPhpMinor(load); got != "8.3" {
		t.Fatalf("minor: %q", got)
	}
	if got := parseModPhpMinor([]byte("LoadModule mpm_prefork_module modules/mod_mpm_prefork.so")); got != "" {
		t.Fatalf("no libphp must yield empty, got %q", got)
	}
}
