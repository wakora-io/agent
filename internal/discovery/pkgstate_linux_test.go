package discovery

import (
	"reflect"
	"testing"
)

func TestParseAptLists(t *testing.T) {
	up := "Listing...\n" +
		"examplelib/stable-security 2.0-1+deb13u2 amd64 [upgradable from: 2.0-1+deb13u1]\n" +
		"demo-tool/stable 1:4.5-3 all [upgradable from: 1:4.5-2]\n"
	want := map[string]string{"examplelib": "2.0-1+deb13u2", "demo-tool": "1:4.5-3"}
	if got := parseAptUpgradable(up); !reflect.DeepEqual(got, want) {
		t.Fatalf("upgradable: %v", got)
	}
	inst := "Listing...\n" +
		"examplelib/stable,now 2.0-1+deb13u1 amd64 [installed]\n" +
		"oldlib1.1/now 1.1.1-9 amd64 [installed,local]\n"
	if got := parseAptLocal(inst); !reflect.DeepEqual(got, map[string]bool{"oldlib1.1": true}) {
		t.Fatalf("local: %v", got)
	}
}

func TestParseDnfOutput(t *testing.T) {
	up := "\n" +
		"demo-tool.x86_64                 1:1.2.3-5.el9_8           baseos\n" +
		"a-very-long-package-name-that-wraps.noarch\n" +
		"                                 4.5-1.el9                 appstream\n" +
		"Obsoleting Packages\n" +
		"other.x86_64                     2.0-1.el9                 baseos\n" +
		"    other-old.x86_64             1.0-1.el9                 @baseos\n"
	want := map[string]string{"demo-tool": "1:1.2.3-5.el9_8", "a-very-long-package-name-that-wraps": "4.5-1.el9"}
	if got := parseDnfCheckUpdate(up); !reflect.DeepEqual(got, want) {
		t.Fatalf("check-update: %v", got)
	}
	ex := "Extra Packages\n" +
		"vendor-agent.x86_64              3.1-1                     @System\n"
	if got := parseDnfExtras(ex); !reflect.DeepEqual(got, map[string]bool{"vendor-agent": true}) {
		t.Fatalf("extras: %v", got)
	}
	if got := parseDnfExtras(""); len(got) != 0 {
		t.Fatalf("no extras: %v", got)
	}
}

func TestParseZypperTables(t *testing.T) {
	up := "\nS  | Repository | Name      | Current Version | Available Version | Arch\n" +
		"---+------------+-----------+-----------------+-------------------+-------\n" +
		"v  | Update     | demo-tool | 1.0-150600.1.1  | 1.0-150600.2.1    | x86_64\n"
	if got := parseZypperUpdates(up); !reflect.DeepEqual(got, map[string]string{"demo-tool": "1.0-150600.2.1"}) {
		t.Fatalf("list-updates: %v", got)
	}
	or := "S | Repository | Name         | Version | Arch\n" +
		"--+------------+--------------+---------+-------\n" +
		"i | @System    | vendor-agent | 3.1-1   | x86_64\n"
	if got := parseZypperOrphans(or); !reflect.DeepEqual(got, map[string]bool{"vendor-agent": true}) {
		t.Fatalf("orphaned: %v", got)
	}
}

func TestParseApkOutput(t *testing.T) {
	up := "Installed:                                Available:\n" +
		"demo-base-3.20.0-r0                     < 3.20.5-r0 \n" +
		"lib-thing-1.2.3-r1                      < 1.2.4-r0 \n"
	want := map[string]string{"demo-base": "3.20.5-r0", "lib-thing": "1.2.4-r0"}
	if got := parseApkVersion(up); !reflect.DeepEqual(got, want) {
		t.Fatalf("version: %v", got)
	}
	or := "vendor-agent-3.1-r0 x86_64 {vendor-agent} (MIT) [installed]\n"
	if got := parseApkOrphans(or); !reflect.DeepEqual(got, map[string]bool{"vendor-agent": true}) {
		t.Fatalf("orphaned: %v", got)
	}
}

func TestWithPkgStateAnnotatesFacts(t *testing.T) {
	facts := []Fact{
		{Kind: "package", Key: "examplelib", Payload: `{"version":"2.0-1","source":"example"}`},
		{Kind: "package", Key: "oldlib", Payload: `{"version":"1.1-9"}`},
		{Kind: "package", Key: "same", Payload: `{"version":"3.0-1"}`},
		{Kind: "package", Key: "quiet", Payload: `{"version":"1.0"}`},
	}
	st := &pkgState{
		updates: map[string]string{"examplelib": "2.0-2", "same": "3.0-1"},
		orphans: map[string]bool{"oldlib": true},
	}
	got := withPkgState(facts, st)
	want := []string{
		`{"version":"2.0-1","source":"example","update":"2.0-2"}`,
		`{"version":"1.1-9","orphan":true}`,
		`{"version":"3.0-1"}`,
		`{"version":"1.0"}`,
	}
	for i, w := range want {
		if got[i].Payload != w {
			t.Fatalf("fact %d: %s", i, got[i].Payload)
		}
	}
	if out := withPkgState(facts, nil); len(out) != len(facts) {
		t.Fatal("no state leaves facts as they are")
	}
}
