package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
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
	endpoint := flag.String("endpoint", "", "gateway endpoint")
	key := flag.String("key", "", "per-server key")
	updateURL := flag.String("update-url", "", "release base url")
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

	cfg, err := config.Load(*configDir)
	if err != nil {
		log.Fatal(err)
	}
	if *endpoint != "" {
		cfg.Endpoint = *endpoint
	}
	if *key != "" {
		cfg.Key = *key
	}
	if *updateURL != "" {
		cfg.UpdateURL = *updateURL
	}

	if *doUpd {
		runUpdateOnce(cfg.UpdateURL)
		return
	}

	client := &transport.Client{Endpoint: cfg.Endpoint, Dialer: transport.NewWSDialer(cfg.Key)}
	a := agent.New(cfg, client, buffer.New(cfg.RingPath(), 64<<20))

	if *test {
		a.DryRun()
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.UpdateURL != "" {
		go autoUpdate(ctx, cfg.UpdateURL, *updateEvery)
	}

	if err := a.Run(ctx, *interval); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

func runUpdateOnce(url string) {
	if url == "" {
		log.Fatal("update: no update url configured")
	}
	u := update.New(url)
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

func autoUpdate(ctx context.Context, url string, every time.Duration) {
	u := update.New(url)
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
