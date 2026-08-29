package defs

import "testing"

func TestChassisStringFormatsMacSubtype(t *testing.T) {
	mac := []byte{0xaa, 0x00, 0x11, 0x22, 0x33, 0xff}
	if got := chassisString(4, mac); got != "aa:00:11:22:33:ff" {
		t.Fatalf("mac chassis = %q", got)
	}
	if got := chassisString(7, []byte("bridge1")); got != "bridge1" {
		t.Fatalf("local chassis = %q", got)
	}
	if got := chassisString(7, []byte{0x01, 0x02}); got != "01:02" {
		t.Fatalf("binary chassis falls back to hex, got %q", got)
	}
}

func TestPortIdStringSubtypes(t *testing.T) {
	if got := portIdString(3, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}); got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("mac port = %q", got)
	}
	if got := portIdString(5, []byte("ether7")); got != "ether7" {
		t.Fatalf("ifName port = %q", got)
	}
}

func TestLldpRemPortExtractsMiddleComponent(t *testing.T) {
	if got := lldpRemPort("0.28.1"); got != "28" {
		t.Fatalf("rem index port = %q", got)
	}
	if got := lldpRemPort("7"); got != "7" {
		t.Fatalf("odd index passes through, got %q", got)
	}
}

func TestArpIPParsesTrailingFourComponents(t *testing.T) {
	if got := arpIP("2.203.0.113.23"); got != "203.0.113.23" {
		t.Fatalf("arp index with ifIndex prefix = %q", got)
	}
	if got := arpIP("10.0.0.9"); got != "10.0.0.9" {
		t.Fatalf("bare four components pass through, got %q", got)
	}
	if got := arpIP("1.2.3"); got != "" {
		t.Fatalf("short index must not parse, got %q", got)
	}
}

func TestFdbMacParsesTrailingSixComponents(t *testing.T) {
	if got := fdbMac("1.170.0.17.34.51.255"); got != "aa:00:11:22:33:ff" {
		t.Fatalf("dot1q fdb mac = %q", got)
	}
	if got := fdbMac("170.0.17.34.51.255"); got != "aa:00:11:22:33:ff" {
		t.Fatalf("dot1d fdb mac = %q", got)
	}
	if got := fdbMac("1.2.3"); got != "" {
		t.Fatalf("short index must not parse, got %q", got)
	}
	if got := fdbMac("1.170.0.17.34.51.999"); got != "" {
		t.Fatalf("octet over 255 must not parse, got %q", got)
	}
}
