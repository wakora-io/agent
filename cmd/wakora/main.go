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
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"wakora.io/agent/internal/agent"
	"wakora.io/agent/internal/bootstrap"
	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/config"
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
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.Version)
		return
	}

	if args := flag.Args(); len(args) > 0 && args[0] == "secret" {
		runSecret(*configDir, args[1:])
		return
	}

	if args := flag.Args(); len(args) > 0 && args[0] == "service" {
		runServiceCmd(args[1:])
		return
	}

	cfg, err := config.Load(*configDir)
	if err != nil {
		log.Fatal(err)
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
				log.Fatal(err)
			}
			if err := config.SaveIdentity(*configDir, serverID, serverKey); err != nil {
				log.Fatal(err)
			}
			log.Printf("registered, server uuid %s", serverID)
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

	if *doUpd {
		runUpdateOnce(relURL, httpc)
		return
	}

	a := agent.New(cfg, buffer.New(cfg.RingPath(), 64<<20, *spoolAge), pubKey)

	if *test {
		a.DryRun()
		return
	}

	if cfg.Endpoint == "" {
		log.Fatal("no gateway endpoint built into this binary; use --endpoint (dev)")
	}
	if cfg.Key == "" {
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

	client := &transport.Client{Endpoint: cfg.Endpoint, Dialer: transport.NewWSDialer(a.Key, pin)}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	run := func(ctx context.Context) error {
		if relURL != "" {
			go autoUpdate(ctx, relURL, httpc, *updateEvery)
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

func runUpdateOnce(relURL string, httpc *http.Client) {
	if relURL == "" {
		log.Fatal("update: no release url; use --update-url or --endpoint")
	}
	u := update.New(relURL, httpc)
	latest, err := u.LatestVersion()
	if err != nil {
		log.Fatal(err)
	}
	if latest == buildinfo.Version {
		log.Printf("already up to date (%s)", buildinfo.Version)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	if err := u.Apply(exe); err != nil {
		log.Fatal(err)
	}
	log.Printf("updated %s -> %s", buildinfo.Version, latest)
	restartService()
}

func autoUpdate(ctx context.Context, relURL string, httpc *http.Client, every time.Duration) {
	u := update.New(relURL, httpc)
	exe, err := os.Executable()
	if err != nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			latest, err := u.LatestVersion()
			if err != nil || latest == buildinfo.Version {
				continue
			}
			if err := u.Apply(exe); err != nil {
				log.Printf("auto-update failed: %v", err)
				continue
			}
			log.Printf("auto-updated %s -> %s, restarting", buildinfo.Version, latest)
			exitForRestart()
		}
	}
}
