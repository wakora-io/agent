//go:build linux

package agent

import "testing"

const mapsFixture = `00400000-02000000 r-xp 00000000 fd:01 393241 /usr/local/bin/wakora
02000000-02400000 r--p 01c00000 fd:01 393241 /usr/local/bin/wakora
02400000-02480000 rw-p 02000000 fd:01 393241 /usr/local/bin/wakora
02480000-024a0000 ---p 02080000 fd:01 393241 /usr/local/bin/wakora
7f1000000000-7f1000020000 rw-p 00000000 fd:01 393242 /usr/local/bin/wakora (deleted)
7f2000000000-7f2000100000 r-xp 00000000 fd:01 111 /lib/x86_64-linux-gnu/libc.so.6
7f3000000000-7f3000010000 rw-p 00000000 00:00 0
7f4000000000-7f4000010000 rw-p 00000000 00:00 0 [heap]
badline
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]`

func TestOwnExeRangesPicksOnlyOwnReadableMappings(t *testing.T) {
	got := ownExeRanges(mapsFixture, "/usr/local/bin/wakora")
	want := [][2]uint64{
		{0x00400000, 0x02000000},
		{0x02000000, 0x02400000},
		{0x02400000, 0x02480000},
		{0x7f1000000000, 0x7f1000020000},
	}
	if len(got) != len(want) {
		t.Fatalf("want %d ranges, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("range %d: want %x, got %x", i, want[i], got[i])
		}
	}
}

func TestOwnExeRangesIgnoresForeignPaths(t *testing.T) {
	if got := ownExeRanges(mapsFixture, "/usr/local/bin/other"); len(got) != 0 {
		t.Fatalf("want no ranges for a foreign path, got %v", got)
	}
}

func TestOwnExeRangesAcceptsDeletedExePath(t *testing.T) {
	got := ownExeRanges(mapsFixture, "/usr/local/bin/wakora (deleted)")
	if len(got) != 4 {
		t.Fatalf("want 4 ranges for the deleted-suffixed exe, got %v", got)
	}
}

func TestPinOwnMappingsDoesNotCrash(t *testing.T) {
	PinOwnMappings()
}
