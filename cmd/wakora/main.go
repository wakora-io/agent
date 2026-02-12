package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"wakora.io/agent/internal/agent"
	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/transport"
	"wakora.io/agent/internal/update"
)

func main() {
	configDir := flag.String("config", "/etc/wakora", "config directory")
	endpoint := flag.String("endpoint", "", "override built-in gateway endpoint (dev)")
	key := flag.String("key", "", "store per-server key into identity and exit")
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
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.Version)
		return
	}

	if *key != "" || len(overrides) > 0 {
		if *key != "" {
			uuid, err := config.SetKey(*configDir, *key)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("identity stored, server uuid %s", uuid)
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

	cfg, err := config.Load(*configDir)
	if err != nil {
		log.Fatal(err)
	}
	if *endpoint != "" {
		cfg.Endpoint = *endpoint
	}

	relURL := *updateURL
	if relURL == "" {
		relURL = releaseURL(cfg.Endpoint)
	}

	if *doUpd {
		runUpdateOnce(relURL)
		return
	}

	a := agent.New(cfg, &transport.Client{Endpoint: cfg.Endpoint, Dialer: transport.NewWSDialer(cfg.Key)}, buffer.New(cfg.RingPath(), 64<<20))

	if *test {
		a.DryRun()
		return
	}

	if cfg.Endpoint == "" {
		log.Fatal("no gateway endpoint built into this binary; use --endpoint (dev)")
	}
	if cfg.Key == "" {
		log.Fatal("no identity; run: wakora --key <KEY>")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if relURL != "" {
		go autoUpdate(ctx, relURL, *updateEvery)
	}

	if err := a.Run(ctx, *interval); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
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

func releaseURL(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := "http"
	if u.Scheme == "wss" || u.Scheme == "https" {
		scheme = "https"
	}
	return scheme + "://" + u.Host + "/release"
}

func runUpdateOnce(relURL string) {
	if relURL == "" {
		log.Fatal("update: no release url; use --update-url or --endpoint")
	}
	u := update.New(relURL)
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
	_ = exec.Command("systemctl", "restart", "wakora-agent").Run()
}

func autoUpdate(ctx context.Context, relURL string, every time.Duration) {
	u := update.New(relURL)
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
			os.Exit(0)
		}
	}
}
