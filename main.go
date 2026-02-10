package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"
	"time"

	"wakora.io/agent/internal/agent"
	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/transport"
)

func main() {
	configDir := flag.String("config", "/etc/wakora", "config directory")
	endpoint := flag.String("endpoint", "", "gateway endpoint")
	test := flag.Bool("test", false, "dry run: collect and print, do not connect")
	interval := flag.Duration("interval", time.Minute, "collection interval")
	flag.Parse()

	cfg, err := config.Load(*configDir)
	if err != nil {
		log.Fatal(err)
	}
	if *endpoint != "" {
		cfg.Endpoint = *endpoint
	}

	a := agent.New(cfg, &transport.Client{Endpoint: cfg.Endpoint}, buffer.New(cfg.RingPath(), 64<<20))

	if *test {
		a.DryRun()
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx, *interval); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
