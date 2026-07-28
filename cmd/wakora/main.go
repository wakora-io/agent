package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"wakora.io/agent/internal/agent"
	"wakora.io/agent/internal/apm"
	"wakora.io/agent/internal/bootstrap"
	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/defs"
	"wakora.io/agent/internal/logfile"
	"wakora.io/agent/internal/secret"
	"wakora.io/agent/internal/transport"
	"wakora.io/agent/internal/update"
)

func main() {
	configDir := flag.String("config", defaultConfigDir, "config directory")
	endpoint := flag.String("endpoint", "", "override built-in gateway endpoint (dev)")
	certPin := flag.String("cert-pin", "", "override built-in gateway certificate pin (dev)")
	publisherKey := flag.String("publisher-key", "", "override built-in definitions publisher key (dev)")
	key := flag.String("key", "", "team key: register this host and exit")
	overrides := map[string]map[string]string{}
	flag.Func("set", "service location override svc.key=value (repeatable), writes wakora.conf and exits", func(v string) error {
		svc, k, val, err := parseOverride(v)
		if err != nil {
			return err
		}
		if overrides[svc] == nil {
			overrides[svc] = map[string]string{}
		}
		overrides[svc][k] = val
		return nil
	})
	updateURL := flag.String("update-url", "", "override release base url (dev)")
	updateEvery := flag.Duration("update-interval", 24*time.Hour, "auto-update check interval")
	doUpd := flag.Bool("update", false, "update to the latest release and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	test := flag.Bool("test", false, "dry run: collect and print, do not connect")
	interval := flag.Duration("interval", time.Minute, "collection interval")
	heartbeat := flag.Duration("heartbeat", 30*time.Second, "heartbeat interval")
	discoveryEvery := flag.Duration("discovery-interval", 30*time.Minute, "full discovery resync interval")
	discoveryCheck := flag.Duration("discovery-check", 30*time.Second, "cheap change-detection interval (dpkg + listening ports)")
	logPath := flag.String("log-file", defaultLogFile, "own log file (service mode), empty = stderr only")
	spoolAge := flag.Duration("spool-age", 24*time.Hour, "offline spool age limit (oldest entries dropped)")
	baseline := flag.Bool("baseline", false, "safe baseline (Speed 1): metrics/discovery/heartbeat only, pushed definitions are not executed")
	customPort := flag.Int("custom-metrics-port", 0, "loopback port for app custom-metric ingest (app.* only), 0 = off")
	otlpPort := flag.Int("otlp-port", 0, "loopback port for OTLP/HTTP JSON span ingest (APM layer-2), 0 = off")
	otlpBind := flag.String("otlp-bind", "", "extra OTLP bind addresses beyond loopback (comma-separated, e.g. a docker bridge gateway for container apps)")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.Version)
		return
	}

	secret.InitSeed(*configDir)

	if args := flag.Args(); len(args) > 0 && args[0] == "secret" {
		runSecret(*configDir, args[1:])
		return
	}

	if args := flag.Args(); len(args) > 0 && args[0] == "service" {
		runServiceCmd(args[1:])
		return
	}

	if args := flag.Args(); len(args) > 0 && args[0] == "uninstall" {
		runUninstall(*configDir, args[1:])
		return
	}

	if args := flag.Args(); len(args) > 0 && args[0] == "doctor" {
		runDoctor(*configDir, args[1:])
		return
	}

	cfg, err := config.Load(*configDir)
	if err != nil {
		if !underServiceManager() {
			log.Fatal(err)
		}
		log.Printf("%v - idle until re-registered", err)
	}
	if *baseline {
		cfg.Baseline = true
	}
	if *customPort > 0 {
		cfg.CustomMetricsPort = *customPort
	}
	if *otlpPort > 0 {
		cfg.OTLPPort = *otlpPort
	}
	if *otlpBind != "" {
		cfg.OTLPBind = append(cfg.OTLPBind, strings.Split(*otlpBind, ",")...)
	}
	if *endpoint != "" {
		cfg.Endpoint = *endpoint
	}
	pin := buildinfo.CertPin
	if *certPin != "" {
		pin = *certPin
	}
	pubKey := buildinfo.PublisherKey
	if *publisherKey != "" {
		pubKey = *publisherKey
	}
	httpc := transport.PinnedClient(pin)

	if *key != "" || len(overrides) > 0 {
		if *key != "" {
			regURL := deriveURL(cfg.Endpoint, "/register")
			if regURL == "" {
				log.Fatal("register: no endpoint built in; use --endpoint (dev)")
			}
			serverID, serverKey, err := bootstrap.Register(httpc, regURL, *key, secret.MachineID(), cfg.Hostname)
			if err != nil {
				if saveErr := config.SavePendingKey(*configDir, *key); saveErr != nil {
					log.Fatalf("register failed (%v) and pending key not stored: %v", err, saveErr)
				}
				log.Printf("register failed: %v", err)
				log.Print("team key stored encrypted on this machine; the service retries registration until the gateway accepts (survives restarts)")
			} else {
				if err := config.SaveIdentity(*configDir, serverID, serverKey); err != nil {
					log.Fatal(err)
				}
				config.ClearPendingKey(*configDir)
				log.Printf("registered, server uuid %s", serverID)
			}
		}
		for svc, kv := range overrides {
			for k, v := range kv {
				if err := config.WriteOverride(*configDir, svc, k, v); err != nil {
					log.Fatal(err)
				}
			}
		}
		if len(overrides) > 0 {
			log.Print("wakora.conf updated")
		}
		return
	}

	relURL := *updateURL
	if relURL == "" {
		relURL = deriveURL(cfg.Endpoint, "/release")
	}

	manifestState := filepath.Join(cfg.StateDir(), "update-manifest")

	if *doUpd {
		runUpdateOnce(relURL, httpc, pubKey, manifestState, cfg.Pin)
		return
	}

	_ = os.MkdirAll(cfg.StateDir(), 0o755)
	_ = os.Chmod(cfg.StateDir(), 0o755)
	if cfg.Pin != "" && !update.PinSupported(cfg.Pin) {
		log.Printf("clearing pin %s: below the pin-aware floor r%d (agents that old ignore their own pin and loop)", cfg.Pin, update.PinFloor)
		_ = config.WriteOverride(*configDir, "agent", "pin", "")
		cfg.Pin = ""
	}
	defs.Provision = apm.NewProvisioner(relURL, httpc, pubKey, cfg.StateDir())
	a := agent.New(cfg, buffer.New(cfg.RingPath(), 64<<20, *spoolAge), pubKey)

	if *test {
		a.DryRun()
		return
	}

	if cfg.Endpoint == "" {
		log.Fatal("no gateway endpoint built into this binary; use --endpoint (dev)")
	}
	if cfg.Key == "" && config.LoadPendingKey(*configDir) == "" && !underServiceManager() && term.IsTerminal(int(os.Stderr.Fd())) {
		log.Fatal("no identity; register with: wakora --key <TEAMKEY>")
	}

	if *logPath != "" {
		if err := logfile.Setup(*logPath); err != nil {
			log.Printf("log file unavailable (%v), continuing with stderr", err)
		}
	}

	debug.SetMemoryLimit(128 << 20)
	if runtime.NumCPU() > 2 {
		runtime.GOMAXPROCS(2)
	}
	agent.EnsureCgroupHeadroom()
	agent.PinOwnMappings()

	if cfg.Baseline {
		log.Print("safe baseline (Speed 1): pushed definitions will not execute; enable with wakora --set agent.baseline=false")
	}

	client := &transport.Client{Endpoint: cfg.Endpoint, Dialer: transport.NewWSDialer(a.Key, pin), OnDialError: a.RecordDialError}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	run := func(ctx context.Context) error {
		if relURL != "" {
			updateKick := make(chan struct{}, 1)
			a.SetUpdateKick(updateKick)
			go autoUpdate(ctx, relURL, httpc, pubKey, manifestState, *updateEvery, updateKick, a.EffectivePin)
			if cfg.Pin != "" && cfg.Pin != buildinfo.Version {
				select {
				case updateKick <- struct{}{}:
				default:
				}
			}
		}
		if cfg.Key == "" {
			if config.LoadPendingKey(*configDir) != "" {
				log.Print("no identity yet - retrying registration with the stored team key")
			} else {
				log.Print("no identity yet - idle until registered; run: wakora --key <TEAMKEY>")
			}
			if !waitForIdentity(ctx, cfg, httpc, *configDir) {
				return nil
			}
			a.RefreshIdentity()
			log.Print("identity registered, starting")
		}
		return a.Run(ctx, client, *interval, *heartbeat, *discoveryEvery, *discoveryCheck)
	}

	if underServiceManager() {
		if err := runUnderServiceManager(ctx, run); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := run(ctx); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintln(out, "Wakora monitoring agent "+buildinfo.Version)
	fmt.Fprintln(out, "\nUsage:")
	fmt.Fprintln(out, "  wakora [flags]                                 run the agent (service mode)")
	fmt.Fprintln(out, "  wakora --key <TEAMKEY>                         register this host and exit")
	fmt.Fprintln(out, "  wakora doctor [--bundle]                       self-diagnostics; --bundle writes a redacted support tar to /tmp")
	fmt.Fprintln(out, "  wakora uninstall [--force]                     deregister and remove the agent from this host")
	fmt.Fprintln(out, "  wakora service <install|uninstall|start|stop>  manage the OS service")
	fmt.Fprintln(out, "  wakora secret <set NAME|list|rm NAME>          manage local service credentials")
	fmt.Fprintln(out, "  wakora --set svc.key=value                     write a wakora.conf location override and exit")
	fmt.Fprintln(out, "  wakora --update                                update to the latest release and exit")
	fmt.Fprintln(out, "  wakora --version                               print version and exit")
	fmt.Fprintln(out, "\nFlags:")
	flag.VisitAll(func(f *flag.Flag) {
		name, help := flag.UnquoteUsage(f)
		line := "  --" + f.Name
		if name != "" {
			line += " " + name
		}
		fmt.Fprintln(out, line)
		indent := "        "
		fmt.Fprintln(out, indent+strings.ReplaceAll(help, "\n", "\n"+indent))
		if f.DefValue != "" && f.DefValue != "0" && f.DefValue != "false" {
			fmt.Fprintf(out, "%s(default %q)\n", indent, f.DefValue)
		}
	})
}

func runSecret(dir string, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: wakora secret <set NAME [--user U] | list | rm NAME>")
		os.Exit(2)
	}
	switch args[0] {
	case "set":
		if len(args) < 2 {
			log.Fatal("usage: wakora secret set NAME [--user U] [--priv]")
		}
		name := args[1]
		user := ""
		withPriv := false
		for i := 2; i < len(args); i++ {
			switch {
			case args[i] == "--user" && i+1 < len(args):
				user = args[i+1]
			case args[i] == "--priv":
				withPriv = true
			}
		}
		if user == "" {
			fmt.Fprint(os.Stderr, "user: ")
			user = readLine()
		}
		pass := readSecret("password: ")
		priv := ""
		if withPriv {
			priv = readSecret("privacy passphrase: ")
		}
		if err := secret.SetCred(dir, name, secret.Cred{User: user, Pass: pass, Priv: priv}); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "secret %q stored (encrypted, stays on this host)\n", name)
	case "list":
		for _, n := range secret.ListCreds(dir) {
			fmt.Println(n)
		}
	case "rm":
		if len(args) < 2 {
			log.Fatal("usage: wakora secret rm NAME")
		}
		removed, err := secret.RemoveCred(dir, args[1])
		if err != nil {
			log.Fatal(err)
		}
		if !removed {
			log.Fatalf("no secret named %q", args[1])
		}
		fmt.Fprintf(os.Stderr, "secret %q removed\n", args[1])
	default:
		log.Fatalf("unknown secret command %q", args[0])
	}
}

var stdinReader = bufio.NewReader(os.Stdin)

func readLine() string {
	line, _ := stdinReader.ReadString('\n')
	return strings.TrimSpace(line)
}

func readSecret(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return readLine()
}

func parseOverride(v string) (svc, key, val string, err error) {
	eq := strings.IndexByte(v, '=')
	if eq <= 0 {
		return "", "", "", errors.New("want svc.key=value")
	}
	left := strings.TrimSpace(v[:eq])
	val = strings.TrimSpace(v[eq+1:])
	dot := strings.IndexByte(left, '.')
	if dot <= 0 || dot >= len(left)-1 {
		return "", "", "", errors.New("want svc.key=value")
	}
	return left[:dot], left[dot+1:], val, nil
}

func deriveURL(endpoint, path string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := "http"
	if u.Scheme == "wss" || u.Scheme == "https" {
		scheme = "https"
	}
	return scheme + "://" + u.Host + path
}

func waitForIdentity(ctx context.Context, cfg *config.Config, httpc *http.Client, configDir string) bool {
	regURL := deriveURL(cfg.Endpoint, "/register")
	backoff := 2 * time.Second
	next := time.Now()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			if err := cfg.ReloadIdentity(); err == nil && cfg.Key != "" {
				config.ClearPendingKey(configDir)
				return true
			}
			if regURL == "" || time.Now().Before(next) {
				continue
			}
			pending := config.LoadPendingKey(configDir)
			if pending == "" {
				continue
			}
			serverID, serverKey, err := bootstrap.Register(httpc, regURL, pending, secret.MachineID(), cfg.Hostname)
			if err != nil {
				log.Printf("pending registration: %v (next try in %s)", err, backoff)
				next = time.Now().Add(backoff)
				if backoff *= 2; backoff > time.Minute {
					backoff = time.Minute
				}
				continue
			}
			if err := config.SaveIdentity(configDir, serverID, serverKey); err != nil {
				log.Printf("pending registration: identity save failed: %v", err)
				continue
			}
			config.ClearPendingKey(configDir)
			_ = cfg.ReloadIdentity()
			log.Printf("registered, server uuid %s", serverID)
			return true
		}
	}
}

func runUpdateOnce(relURL string, httpc *http.Client, pubKey, statePath, pin string) {
	if relURL == "" {
		log.Fatal("update: no release url; use --update-url or --endpoint")
	}
	u := update.New(relURL, httpc, pubKey, statePath)
	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	if pin != "" {
		if pin == buildinfo.Version {
			log.Printf("already on pinned %s", buildinfo.Version)
			return
		}
		if err := u.ApplyPinned(exe, pin); err != nil {
			log.Fatal(err)
		}
		log.Printf("converged to pinned %s from %s", pin, buildinfo.Version)
		restartService()
		return
	}
	latest, err := u.LatestVersion()
	if err != nil {
		log.Fatal(err)
	}
	if latest == buildinfo.Version {
		log.Printf("already up to date (%s)", buildinfo.Version)
		return
	}
	if !update.Newer(latest, buildinfo.Version) {
		log.Printf("release %s is not newer than %s, skipping (no downgrade)", latest, buildinfo.Version)
		return
	}
	if err := u.Apply(exe); err != nil {
		log.Fatal(err)
	}
	log.Printf("updated %s -> %s", buildinfo.Version, latest)
	restartService()
}

func autoUpdate(ctx context.Context, relURL string, httpc *http.Client, pubKey, statePath string, every time.Duration, kick <-chan struct{}, pinOf func() string) {
	u := update.New(relURL, httpc, pubKey, statePath)
	exe, err := os.Executable()
	if err != nil {
		return
	}
	check := func() {
		if pinOf != nil {
			if pin := pinOf(); pin != "" {
				if pin == buildinfo.Version {
					return
				}
				if err := u.ApplyPinned(exe, pin); err != nil {
					log.Printf("pinned update to %s failed: %v", pin, err)
					return
				}
				log.Printf("converged to pinned %s from %s, restarting", pin, buildinfo.Version)
				exitForRestart()
				return
			}
		}
		latest, err := u.LatestVersion()
		if err != nil {
			log.Printf("update check failed: %v", err)
			return
		}
		if !update.Newer(latest, buildinfo.Version) {
			return
		}
		if err := u.Apply(exe); err != nil {
			log.Printf("auto-update failed: %v", err)
			return
		}
		log.Printf("auto-updated %s -> %s, restarting", buildinfo.Version, latest)
		exitForRestart()
	}
	select {
	case <-ctx.Done():
		return
	case <-kick:
		check()
	case <-time.After(90 * time.Second):
		check()
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			check()
		case <-t.C:
			check()
		}
	}
}
