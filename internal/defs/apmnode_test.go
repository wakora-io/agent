package defs

import (
	"strings"
	"testing"

	"wakora.io/agent/internal/apm"
)

func TestNodeLaunchOf(t *testing.T) {
	cases := []struct {
		cgroup string
		want   string
	}{
		{"0::/system.slice/nodeapp.service", "systemd:nodeapp.service"},
		{"0::/system.slice/pm2-root.service", "pm2:pm2-root.service"},
		{"0::/user.slice/user-0.slice/session-77.scope", "bare"},
		{"12:pids:/system.slice/myapi.service\n1:name=systemd:/system.slice/myapi.service", "systemd:myapi.service"},
		{"0::/init.scope", "bare"},
		{"", "bare"},
	}
	for _, c := range cases {
		if got := nodeLaunchOf(c.cgroup); got != c.want {
			t.Fatalf("nodeLaunchOf(%q) = %q, want %q", c.cgroup, got, c.want)
		}
	}
}

func TestNodeInContainer(t *testing.T) {
	if !nodeInContainer("0::/system.slice/docker-abc123.scope") {
		t.Fatal("docker cgroup not detected")
	}
	if !nodeInContainer("0::/lxc.payload.web/system.slice/app.service") {
		t.Fatal("lxc payload not detected")
	}
	if nodeInContainer("0::/system.slice/nodeapp.service") {
		t.Fatal("plain service flagged as container")
	}
}

func TestNodeVersionOK(t *testing.T) {
	cases := map[string]bool{
		"18.19.1":  true,
		"18.18.2":  false,
		"20.11.0":  true,
		"22.23.1":  true,
		"16.20.0":  false,
		"v18.19.0": true,
		"":         false,
		"garbage":  false,
	}
	for v, want := range cases {
		if got := nodeVersionOK(v); got != want {
			t.Fatalf("nodeVersionOK(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestNodeAppOf(t *testing.T) {
	join := func(args ...string) string { return strings.Join(args, "\x00") + "\x00" }
	if got := nodeAppOf(join("/usr/bin/node", "/opt/nodeapp/server.js")); got != "/opt/nodeapp/server.js" {
		t.Fatalf("app = %q", got)
	}
	if got := nodeAppOf(join("/usr/bin/node", "--max-old-space-size=512", "/srv/api/index.js", "--port", "3000")); got != "/srv/api/index.js" {
		t.Fatalf("app with flags = %q", got)
	}
	if got := nodeAppOf(join("node")); got != "" {
		t.Fatalf("bare node app = %q", got)
	}
	if got := nodeAppOf(join("node /opt/pm2app/app.js")); got != "/opt/pm2app/app.js" {
		t.Fatalf("pm2 title app = %q", got)
	}
	if got := nodeAppOf(""); got != "" {
		t.Fatalf("empty cmdline app = %q", got)
	}
}

func TestNodeDropin(t *testing.T) {
	env := apm.NodeEnv("/var/lib/wakora/apm/opentelemetry-node/wakora-register.js", "nodeapp", "http://127.0.0.1:4318", "", false)
	got := nodeDropin(env, "abc123")
	want := "[Service]\n" +
		"# wakora-artifact-sha abc123\n" +
		"Environment=\"NODE_OPTIONS=--require /var/lib/wakora/apm/opentelemetry-node/wakora-register.js\"\n" +
		"Environment=\"OTEL_SERVICE_NAME=nodeapp\"\n" +
		"Environment=\"OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318\"\n" +
		"Environment=\"OTEL_TRACES_EXPORTER=otlp\"\n" +
		"Environment=\"OTEL_METRICS_EXPORTER=otlp\"\n"
	if got != want {
		t.Fatalf("dropin:\n%s\nwant:\n%s", got, want)
	}
	if !strings.HasPrefix(nodeDropin(env, ""), "[Service]\nEnvironment=") {
		t.Fatal("empty sha must skip the marker line")
	}
	merged := apm.NodeEnv("/reg.js", "app", "http://127.0.0.1:4318", "--max-old-space-size=512", false)
	if merged["NODE_OPTIONS"] != "--max-old-space-size=512 --require /reg.js" {
		t.Fatalf("merge = %q", merged["NODE_OPTIONS"])
	}
	perf := apm.NodeEnv("/reg.js", "app", "http://127.0.0.1:4318", "", true)
	if perf["NODE_OPTIONS"] != "--require /reg.js --perf-basic-prof-only-functions" {
		t.Fatalf("perf opts = %q", perf["NODE_OPTIONS"])
	}
	perApp := apm.NodeEnv("/reg.js", "", "http://127.0.0.1:4318", "", false)
	if _, ok := perApp["OTEL_SERVICE_NAME"]; ok {
		t.Fatal("empty service name must not emit OTEL_SERVICE_NAME (pm2 per-app naming)")
	}
	if strings.Contains(nodeDropin(perApp, ""), "OTEL_SERVICE_NAME") {
		t.Fatal("dropin must skip absent service name")
	}
	envFile := nodeEnvFile(perApp, "sha1")
	want2 := "# wakora-artifact-sha sha1\n" +
		"NODE_OPTIONS=\"--require /reg.js\"\n" +
		"OTEL_EXPORTER_OTLP_ENDPOINT=\"http://127.0.0.1:4318\"\n" +
		"OTEL_TRACES_EXPORTER=\"otlp\"\n" +
		"OTEL_METRICS_EXPORTER=\"otlp\"\n"
	if envFile != want2 {
		t.Fatalf("env file:\n%s\nwant:\n%s", envFile, want2)
	}
}

func TestNodeTargets(t *testing.T) {
	ms := []nodeMaster{
		{pid: 1, launch: "systemd:nodeapp.service"},
		{pid: 2, launch: "pm2:pm2-root.service"},
		{pid: 3, launch: "pm2:pm2-root.service"},
		{pid: 4, launch: "bare"},
		{pid: 5, launch: "systemd:api.service"},
	}
	ts := nodeTargets(ms)
	if len(ts) != 4 {
		t.Fatalf("targets = %d, want 4", len(ts))
	}
	byLabel := map[string]nodeTarget{}
	for _, x := range ts {
		byLabel[x.label] = x
	}
	if byLabel["nodeapp"].unit != "nodeapp.service" || len(byLabel["nodeapp"].masters) != 1 {
		t.Fatalf("nodeapp target wrong: %+v", byLabel["nodeapp"])
	}
	if !byLabel["pm2"].perApp || byLabel["pm2"].unit != "pm2-root.service" || len(byLabel["pm2"].masters) != 2 {
		t.Fatalf("pm2 target wrong: %+v", byLabel["pm2"])
	}
	if byLabel["bare"].unit != "" {
		t.Fatalf("bare target has a unit: %+v", byLabel["bare"])
	}
	if byLabel["api"].unit != "api.service" {
		t.Fatalf("api target wrong: %+v", byLabel["api"])
	}
}

func TestNodeRestartsSeen(t *testing.T) {
	tgt := nodeTarget{label: "rs-test", masters: []nodeMaster{{pid: 100}, {pid: 200}}}
	if got := nodeRestartsSeen(tgt); got != 0 {
		t.Fatalf("first sight = %v, want 0", got)
	}
	if got := nodeRestartsSeen(tgt); got != 0 {
		t.Fatalf("stable pids = %v, want 0", got)
	}
	tgt.masters[1].pid = 201
	if got := nodeRestartsSeen(tgt); got != 1 {
		t.Fatalf("pid change = %v, want 1", got)
	}
	if got := nodeRestartsSeen(tgt); got != 1 {
		t.Fatalf("stable after change = %v, want 1", got)
	}
}

func TestNodeExistingOptions(t *testing.T) {
	env := "PATH=/usr/bin\x00NODE_OPTIONS=--max-old-space-size=512\x00HOME=/root"
	if got := nodeExistingOptions(env); got != "--max-old-space-size=512" {
		t.Fatalf("existing = %q", got)
	}
	ours := "NODE_OPTIONS=--require /var/lib/wakora/apm/opentelemetry-node/wakora-register.js\x00"
	if got := nodeExistingOptions(ours); got != "" {
		t.Fatalf("our own options must not count as existing: %q", got)
	}
	if got := nodeExistingOptions("PATH=/usr/bin\x00"); got != "" {
		t.Fatalf("no NODE_OPTIONS must be empty: %q", got)
	}
}
