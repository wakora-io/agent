//go:build windows

package metrics

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestVolumeReadOnlyOnTheSystemDrive(t *testing.T) {
	root, err := windows.UTF16PtrFromString(os.Getenv("SystemDrive") + `\`)
	if err != nil {
		t.Fatal(err)
	}
	ro, ok := volumeReadOnly(root)
	if !ok {
		t.Fatal("the system drive gave no volume flags")
	}
	if ro {
		t.Fatal("the system drive read as read-only")
	}
}

func TestDiskPointsCarryTheReadOnlyFlag(t *testing.T) {
	seen := false
	for _, p := range diskPoints() {
		if p.Name == "host.disk.readonly" {
			seen = true
			if p.Value != 0 && p.Value != 1 {
				t.Fatalf("flag %v", p.Value)
			}
		}
	}
	if !seen {
		t.Fatal("no fixed drive reported host.disk.readonly")
	}
}
