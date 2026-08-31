package defs

import (
	"strings"
	"testing"

	"wakora.io/agent/internal/protocol"
)

func TestFoldRepeatsCollapsesStormWithVaryingNumbers(t *testing.T) {
	in := []protocol.LogLine{
		{Service: "system", Level: "notice", Message: `audit: type=1400 audit(1788198318.362:8761153): apparmor="DENIED" pid=32120`},
		{Service: "system", Level: "notice", Message: `audit: type=1400 audit(1788198318.706:8761154): apparmor="DENIED" pid=32120`},
		{Service: "system", Level: "notice", Message: `audit: type=1400 audit(1788198318.801:8761155): apparmor="DENIED" pid=32120`},
	}
	out := FoldRepeats(in)
	if len(out) != 1 {
		t.Fatalf("lines %d, want 1", len(out))
	}
	if !strings.HasSuffix(out[0].Message, "(repeated 3 times)") {
		t.Fatalf("message %q missing repeat marker", out[0].Message)
	}
	if !strings.Contains(out[0].Message, "audit(1788198318.362:8761153)") {
		t.Fatalf("message %q lost the raw text of the first line", out[0].Message)
	}
}

func TestFoldRepeatsLeavesInterleavedLinesAlone(t *testing.T) {
	in := []protocol.LogLine{
		{Service: "system", Level: "notice", Message: "first message 111111"},
		{Service: "system", Level: "notice", Message: "second message 222222"},
		{Service: "system", Level: "notice", Message: "first message 333333"},
	}
	out := FoldRepeats(in)
	if len(out) != 3 {
		t.Fatalf("lines %d, want 3", len(out))
	}
	for _, l := range out {
		if strings.Contains(l.Message, "repeated") {
			t.Fatalf("message %q folded, interleaved runs must survive", l.Message)
		}
	}
}

func TestFoldRepeatsKeepsDistinctSources(t *testing.T) {
	in := []protocol.LogLine{
		{Service: "system", Level: "error", Message: "Invalid user admin from 192.0.2.10 port 55001"},
		{Service: "system", Level: "error", Message: "Invalid user admin from 198.51.100.20 port 55002"},
		{Service: "system", Level: "error", Message: "Invalid user admin from 203.0.113.30 port 55003"},
	}
	out := FoldRepeats(in)
	if len(out) != 3 {
		t.Fatalf("lines %d, want 3, addresses must never fold into one", len(out))
	}
}

func TestFoldRepeatsKeepsShortNumbersDistinct(t *testing.T) {
	in := []protocol.LogLine{
		{Service: "system", Level: "warn", Message: "disk usage 85 percent"},
		{Service: "system", Level: "warn", Message: "disk usage 92 percent"},
	}
	out := FoldRepeats(in)
	if len(out) != 2 {
		t.Fatalf("lines %d, want 2", len(out))
	}
}

func TestFoldRepeatsSeparatesServiceAndLevel(t *testing.T) {
	in := []protocol.LogLine{
		{Service: "nginx", Level: "notice", Message: "same text 123456"},
		{Service: "postfix", Level: "notice", Message: "same text 123456"},
		{Service: "postfix", Level: "error", Message: "same text 123456"},
	}
	out := FoldRepeats(in)
	if len(out) != 3 {
		t.Fatalf("lines %d, want 3", len(out))
	}
}

func TestFoldRepeatsPassesSingleLine(t *testing.T) {
	in := []protocol.LogLine{{Service: "system", Level: "notice", Message: "only one 999999"}}
	out := FoldRepeats(in)
	if len(out) != 1 || strings.Contains(out[0].Message, "repeated") {
		t.Fatalf("single line altered: %+v", out)
	}
}

func TestFoldKeyMasksLongNumbersOnly(t *testing.T) {
	if foldKey("pid=32120 usage 85") != "pid=N usage 85" {
		t.Fatalf("key %q", foldKey("pid=32120 usage 85"))
	}
	if foldKey("from 192.0.2.10 port 55001") != "from 192.0.2.10 port N" {
		t.Fatalf("key %q", foldKey("from 192.0.2.10 port 55001"))
	}
}
