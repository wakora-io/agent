//go:build linux

package defs

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wakora.io/agent/internal/apm"
)

func TestScanNginxBasedirFindsRestrictions(t *testing.T) {
	apmDir := "/var/lib/wakora/apm"
	nginx := t.TempDir()
	docroot := t.TempDir()
	openroot := t.TempDir()

	write := func(path, content string) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(nginx, "sites", "restricted.conf"),
		"server {\n\troot "+docroot+";\n\tfastcgi_param PHP_ADMIN_VALUE \"open_basedir=/www/a:/tmp/\";\n}\n")
	write(filepath.Join(nginx, "sites", "allowed.conf"),
		"server {\n\troot "+openroot+";\n\tfastcgi_param PHP_ADMIN_VALUE \"open_basedir=/www/b:/tmp/:"+apmDir+"\";\n}\n")
	write(filepath.Join(nginx, "sites", "plain.conf"),
		"server {\n\tlisten 80;\n}\n")
	write(filepath.Join(nginx, "sites", "commented.conf"),
		"server {\n\t# fastcgi_param PHP_ADMIN_VALUE \"open_basedir=/www/x:/tmp/\";\n\tlisten 81;\n}\n")
	write(filepath.Join(docroot, ".user.ini"), "open_basedir=/www/a:/tmp/\n")
	write(filepath.Join(openroot, ".user.ini"), "memory_limit=256M\n; open_basedir=/www/y:/tmp/\n")

	enabled := filepath.Join(nginx, "enabled")
	if err := os.MkdirAll(enabled, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(nginx, "sites", "restricted.conf"), filepath.Join(enabled, "restricted.conf")); err != nil {
		t.Fatal(err)
	}

	res := scanNginxBasedir(nginx, apmDir)
	if res.nginxFiles != 1 {
		t.Fatalf("nginxFiles = %d, want 1 (allowed, plain, commented-out and the symlink duplicate must not count)", res.nginxFiles)
	}
	if !strings.Contains(res.sampleLine, "open_basedir=/www/a:/tmp/") {
		t.Fatalf("sampleLine must carry the raw matched line, got %q", res.sampleLine)
	}
	if res.userIni != 1 {
		t.Fatalf("userIni = %d, want 1", res.userIni)
	}
	if len(res.samples) == 0 {
		t.Fatal("samples must name the restricted files")
	}
	realSites, _ := filepath.EvalSymlinks(filepath.Join(nginx, "sites"))
	if len(res.nginxDirs) != 1 || res.nginxDirs[0] != realSites {
		t.Fatalf("nginxDirs = %v, want only the REAL file's dir (sed -i through a symlink would replace it with a plain copy)", res.nginxDirs)
	}
}

func TestNginxBasedirPrepCommand(t *testing.T) {
	stateDir := "/var/lib/wakora"
	cmd := nginxBasedirPrepCommand(stateDir, []string{"/etc/nginx/sites-available"})
	if cmd == "" {
		t.Fatal("command must be generated for one dir")
	}
	for _, want := range []string{
		"B=/var/lib/wakora/backups/nginx-prep-$(date",
		"mkdir -p $B/etc_nginx_sites-available",
		"cp -a /etc/nginx/sites-available/* $B/etc_nginx_sites-available/",
		"sed -i '/open_basedir/",
		"/etc/nginx/sites-available/*",
		"nginx -t && systemctl reload nginx || { cp -a $B/etc_nginx_sites-available/* /etc/nginx/sites-available/",
		"originals restored from $B",
		"/var/lib/wakora/apm",
	} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("command %q missing %q", cmd, want)
		}
	}
	if strings.Contains(cmd, "exit ") {
		t.Fatal("the command is pasted into an interactive shell - exit would kill the admin session, use false")
	}
	if strings.Contains(cmd, ".wakora-bak") {
		t.Fatal("backups must live outside the config tree, not as sed suffix files (an include glob could pick those up)")
	}
	if nginxBasedirPrepCommand(stateDir, nil) != "" {
		t.Fatal("no dirs must yield no command")
	}
	if nginxBasedirPrepCommand(stateDir, []string{"a", "b", "c", "d", "e"}) != "" {
		t.Fatal("too many dirs must yield no command (find variant is a future tail)")
	}
}

func TestNginxBasedirPrepSedBehaves(t *testing.T) {
	if _, err := exec.LookPath("sed"); err != nil {
		t.Skip("sed not available")
	}
	stateDir := t.TempDir()
	apmDir := filepath.Join(stateDir, "apm")
	dir := t.TempDir()
	simple := filepath.Join(dir, "simple.conf")
	multi := filepath.Join(dir, "multi.conf")
	done := filepath.Join(dir, "done.conf")
	spaced := filepath.Join(dir, "spaced.conf")
	commented := filepath.Join(dir, "commented.conf")
	os.WriteFile(simple, []byte("fastcgi_param PHP_ADMIN_VALUE \"open_basedir=/www/a:/tmp/\";\n"), 0o644)
	os.WriteFile(multi, []byte("fastcgi_param PHP_ADMIN_VALUE \"open_basedir=/www/b:/tmp/\\nerror_log=/www/b/log/php.log\";\n"), 0o644)
	os.WriteFile(done, []byte("fastcgi_param PHP_ADMIN_VALUE \"open_basedir=/www/c:/tmp/:"+apmDir+"\";\n"), 0o644)
	os.WriteFile(spaced, []byte("fastcgi_param PHP_ADMIN_VALUE \"open_basedir = /www/d:/tmp/\";\n"), 0o644)
	os.WriteFile(commented, []byte("\t# fastcgi_param PHP_ADMIN_VALUE \"open_basedir=/www/e:/tmp/\";\n"), 0o644)

	cmd := nginxBasedirPrepCommand(stateDir, []string{dir})
	cmd = strings.Replace(cmd, "nginx -t && systemctl reload nginx", "true", 1)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("prep failed: %v: %s", err, out)
	}

	got, _ := os.ReadFile(simple)
	if !strings.Contains(string(got), "open_basedir=/www/a:/tmp/:"+apmDir+"\"") {
		t.Fatalf("simple: %s", got)
	}
	got, _ = os.ReadFile(multi)
	if !strings.Contains(string(got), "open_basedir=/www/b:/tmp/:"+apmDir+"\\nerror_log=/www/b/log/php.log") {
		t.Fatalf("multi: apm dir must land before the escaped newline, got: %s", got)
	}
	got, _ = os.ReadFile(done)
	if strings.Count(string(got), apmDir) != 1 {
		t.Fatalf("done: already-amended line must stay untouched, got: %s", got)
	}
	got, _ = os.ReadFile(spaced)
	if !strings.Contains(string(got), "open_basedir = /www/d:/tmp/:"+apmDir+"\"") {
		t.Fatalf("spaced: whitespace around = must be amended too (scan tolerates it, sed must match), got: %s", got)
	}
	got, _ = os.ReadFile(commented)
	if strings.Contains(string(got), apmDir) {
		t.Fatalf("commented: a commented-out line must stay untouched, got: %s", got)
	}

	if leftovers, _ := filepath.Glob(dir + "/*.wakora-bak"); len(leftovers) != 0 {
		t.Fatalf("no backup files may land next to the configs, got %v", leftovers)
	}
	backups, _ := filepath.Glob(filepath.Join(stateDir, "backups", "nginx-prep-*", "*", "*.conf"))
	if len(backups) != 5 {
		t.Fatalf("want 5 pristine copies in the backup dir, got %v", backups)
	}
	simpleBak, _ := filepath.Glob(filepath.Join(stateDir, "backups", "nginx-prep-*", "*", "simple.conf"))
	if len(simpleBak) != 1 {
		t.Fatalf("simple.conf backup missing: %v", backups)
	}
	raw, _ := os.ReadFile(simpleBak[0])
	if strings.Contains(string(raw), apmDir) {
		t.Fatal("backups must hold the PRE-amendment content")
	}
}

func TestNginxBasedirPrepRollsBack(t *testing.T) {
	if _, err := exec.LookPath("sed"); err != nil {
		t.Skip("sed not available")
	}
	stateDir := t.TempDir()
	apmDir := filepath.Join(stateDir, "apm")
	dir := t.TempDir()
	conf := filepath.Join(dir, "site.conf")
	original := "fastcgi_param PHP_ADMIN_VALUE \"open_basedir=/www/a:/tmp/\";\n"
	os.WriteFile(conf, []byte(original), 0o644)

	cmd := nginxBasedirPrepCommand(stateDir, []string{dir})
	cmd = strings.Replace(cmd, "nginx -t && systemctl reload nginx", "false", 1)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err == nil {
		t.Fatal("a failed config test must surface as a non-zero exit")
	}
	if !strings.Contains(string(out), "originals restored") {
		t.Fatalf("rollback must announce itself, got: %s", out)
	}
	got, _ := os.ReadFile(conf)
	if string(got) != original {
		t.Fatalf("config must be byte-identical after rollback, got: %s", got)
	}
	if strings.Contains(string(got), apmDir) {
		t.Fatal("rollback left the amendment in place")
	}
}

func TestStageCleanupFindsStalePrepend(t *testing.T) {
	stateDir := t.TempDir()
	scanDir := t.TempDir()
	poolDir := t.TempDir()
	os.WriteFile(filepath.Join(scanDir, "90-wakora-otel.ini"),
		[]byte("auto_prepend_file=/var/lib/wakora/apm/opentelemetry-php-sdk81/wakora-otel.php\n"), 0o644)
	os.WriteFile(filepath.Join(scanDir, "10-opcache.ini"), []byte("zend_extension=opcache.so\n"), 0o644)
	os.WriteFile(filepath.Join(poolDir, "site.conf"),
		[]byte("[site]\nphp_admin_value[auto_prepend_file] = /var/lib/wakora/apm/opentelemetry-php-sdk81/wakora-otel.php\n"), 0o644)
	os.WriteFile(filepath.Join(poolDir, "commented.conf"),
		[]byte("[c]\n; php_admin_value[auto_prepend_file] = /var/lib/wakora/apm/x/wakora-otel.php\n"), 0o644)

	st := &sapiTarget{
		rt:        apm.PHPRuntime{VersionShort: "8.1", Prepend: "/var/lib/wakora/apm/opentelemetry-php-sdk81/wakora-otel.php"},
		iniDir:    scanDir,
		poolDir:   poolDir,
		testCmd:   "php-fpm8.1 -t",
		reloadCmd: "systemctl reload php8.1-fpm",
		unit:      "php8.1-fpm",
	}
	o := &Outcome{Facts: map[string]string{}}
	stageCleanup(o, "apm-php", stateDir, st, "apmphp-apm-php-8.1", "8.1")

	if len(o.Events) != 1 {
		t.Fatalf("want one action_required, got %d", len(o.Events))
	}
	var det map[string]string
	if err := json.Unmarshal([]byte(o.Events[0].Detail), &det); err != nil {
		t.Fatal(err)
	}
	cmd := det["command"]
	for _, want := range []string{
		"rm " + filepath.Join(scanDir, "90-wakora-otel.ini"),
		"sed -i.wakora-bak",
		filepath.Join(poolDir, "site.conf"),
		"php-fpm8.1 -t && systemctl reload php8.1-fpm",
	} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("command %q missing %q", cmd, want)
		}
	}
	if strings.Contains(cmd, "10-opcache.ini") || strings.Contains(cmd, "commented.conf") {
		t.Fatalf("clean files must stay out of the command: %q", cmd)
	}
	if det["change"] != "otel-cleanup" {
		t.Fatalf("change: %q", det["change"])
	}

	o2 := &Outcome{Facts: map[string]string{}}
	stageCleanup(o2, "apm-php", stateDir, st, "apmphp-apm-php-8.1", "8.1")
	if len(o2.Events) != 0 {
		t.Fatal("same content must not re-raise the event (content-sha dedup)")
	}
}

func TestOpenBasedirPoolsFollowsIncludes(t *testing.T) {
	apmDir := "/var/lib/wakora/apm"
	confDir := t.TempDir()
	extra := filepath.Join(confDir, "vhosts.d")
	if err := os.MkdirAll(extra, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "php-fpm.conf"),
		[]byte("[global]\ninclude="+extra+"/*.conf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extra, "site1.conf"),
		[]byte("[site1]\nphp_admin_value[open_basedir] = /www/site1:/tmp/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extra, "site2.conf"),
		[]byte("[site2]\nphp_admin_value[open_basedir] = /www/site2:/tmp/:"+apmDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	restricted, total := openBasedirPools("", confDir, apmDir)
	if total != 2 {
		t.Fatalf("total = %d, want 2 pool files via include glob", total)
	}
	if restricted != 1 {
		t.Fatalf("restricted = %d, want 1", restricted)
	}
}
