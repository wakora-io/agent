package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"wakora.io/agent/internal/bootstrap"
	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/transport"
)

func runUninstall(configDir string, args []string) {
	force, alreadyDereg := false, false
	for _, a := range args {
		switch a {
		case "--force", "-force", "--yes", "-yes":
			force = true
		case "--deregistered", "-deregistered":
			alreadyDereg = true
			force = true
		}
	}

	cfg, _ := config.Load(configDir)
	logDir := filepath.Dir(defaultLogFile)

	if !force {
		fmt.Fprintf(os.Stderr, "This removes the Wakora agent from this host:\n")
		fmt.Fprintf(os.Stderr, "  - stops and deletes the service\n")
		fmt.Fprintf(os.Stderr, "  - wipes %s, %s and %s\n", cfg.Dir(), cfg.StateDir(), logDir)
		fmt.Fprintf(os.Stderr, "  - deletes the binary\n")
		fmt.Fprintf(os.Stderr, "  - deregisters the host from the console\n\n")
		fmt.Fprintf(os.Stderr, "Type the hostname (%s) to confirm: ", cfg.Hostname)
		if readLine() != cfg.Hostname {
			fmt.Fprintln(os.Stderr, "cancelled - nothing was changed")
			os.Exit(1)
		}
	}

	if !alreadyDereg && cfg.Key != "" && cfg.ServerID != "" {
		if url := deriveURL(cfg.Endpoint, "/deregister"); url != "" {
			httpc := transport.PinnedClient(buildinfo.CertPin)
			if err := bootstrap.Deregister(httpc, url, cfg.ServerID, cfg.Key); err != nil {
				log.Printf("gateway deregister failed (%v) - cleaning up locally; remove the host in the console too", err)
			} else {
				log.Print("deregistered from the gateway (key revoked, telemetry purged)")
			}
		}
	}

	apmDir := filepath.Join(cfg.StateDir(), "apm")
	keepApm := apmApplied(apmDir)

	removePlatformService()

	wipeAgentFiles(cfg.Dir(), cfg.StateDir(), logDir, apmDir, keepApm)

	if exe, err := os.Executable(); err == nil {
		if err := selfDeleteBinary(exe); err != nil {
			log.Printf("binary self-delete failed (%v) - remove %s by hand", err, exe)
		}
	}

	fmt.Fprintln(os.Stderr, "wakora removed from this host")
	if keepApm {
		fmt.Fprintf(os.Stderr, "note: APM is still active - detach it from the console (a php reload), then delete %s\n", apmDir)
	}
}

func wipeAgentFiles(configDir, stateDir, logDir, apmDir string, keepApm bool) {
	apmParent := filepath.Dir(apmDir)
	done := map[string]bool{}
	for _, d := range []string{configDir, stateDir, logDir} {
		if d == "" || done[d] {
			continue
		}
		done[d] = true
		if keepApm && d == apmParent {
			ents, err := os.ReadDir(d)
			if err != nil {
				continue
			}
			for _, e := range ents {
				if e.Name() == "apm" {
					continue
				}
				_ = os.RemoveAll(filepath.Join(d, e.Name()))
			}
			continue
		}
		_ = os.RemoveAll(d)
	}
}
