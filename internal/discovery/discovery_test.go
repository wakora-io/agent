package discovery

import "testing"

func TestCountByKind(t *testing.T) {
	facts := []Fact{
		{Kind: "process", Key: "a"},
		{Kind: "process", Key: "b"},
		{Kind: "port", Key: "80/tcp"},
	}
	counts := CountByKind(facts)
	if counts["process"] != 2 || counts["port"] != 1 {
		t.Fatalf("counts: %v", counts)
	}
}

func TestContainerCgroup(t *testing.T) {
	inContainer := []string{
		"0::/system.slice/docker-0ce0e03103fe.scope",
		"12:cpu:/docker/abcdef",
		"0::/machine.slice/libpod-abc.scope",
		"0::/kubepods/burstable/pod1/abc",
		"0::/lxc/1082/ns/init.scope",
		"0::/lxc.payload.web1/init.scope",
	}
	for _, s := range inContainer {
		if !containerCgroup(s) {
			t.Fatalf("must detect container cgroup: %q", s)
		}
	}
	onHost := []string{
		"0::/system.slice/nginx.service",
		"0::/init.scope",
		"0::/system.slice/docker.service",
		"0::/user.slice/user-0.slice/session-1.scope",
	}
	for _, s := range onHost {
		if containerCgroup(s) {
			t.Fatalf("host cgroup misdetected as container: %q", s)
		}
	}
}

func TestSortedFactsDeterministic(t *testing.T) {
	agg := map[string]*packageInfo{
		"zsh":  {Version: "1"},
		"bash": {Version: "2"},
	}
	facts := sortedFacts("package", agg)
	if len(facts) != 2 || facts[0].Key != "bash" || facts[1].Key != "zsh" {
		t.Fatalf("order: %+v", facts)
	}
}
