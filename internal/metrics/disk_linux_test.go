//go:build linux

package metrics

import "testing"

func TestMountReadOnly(t *testing.T) {
	cases := map[string]bool{
		"rw,relatime,errors=remount-ro":            false,
		"ro,relatime,errors=remount-ro":            true,
		"rw,nosuid,nodev,noexec,relatime,ro":       true,
		"rw,relatime,data=ordered":                 false,
		"rw,relatime,discard,errors=remount-ro,ro": true,
		"": false,
	}
	for opts, want := range cases {
		if got := mountReadOnly(opts); got != want {
			t.Fatalf("%q: want %v got %v", opts, want, got)
		}
	}
}
