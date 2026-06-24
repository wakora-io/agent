package main

import (
	"fmt"
	"os"

	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/doctor"
	"wakora.io/agent/internal/transport"
)

func runDoctor(configDir string, args []string) {
	bundle := false
	for _, a := range args {
		if a == "--bundle" || a == "bundle" {
			bundle = true
		}
	}

	cfg, idErr := config.Load(configDir)
	pin := buildinfo.CertPin
	in := doctor.Input{
		ConfigDir:   configDir,
		StateDir:    cfg.StateDir(),
		LogPath:     defaultLogFile,
		Endpoint:    cfg.Endpoint,
		Pin:         pin,
		ConfPin:     cfg.Pin,
		ServerID:    cfg.ServerID,
		Key:         cfg.Key,
		IdentityErr: idErr,
		HTTP:        transport.PinnedClient(pin),
	}

	checks := doctor.Run(in)
	fmt.Println("Wakora agent " + buildinfo.Version)
	fmt.Print(doctor.Render(checks))

	if bundle {
		path, err := doctor.WriteBundle(in, checks)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bundle failed: "+err.Error())
		} else {
			fmt.Println("\nsupport bundle written to " + path)
			fmt.Println("it contains no secrets or log content - only statuses, sizes and counts")
		}
	}

	if doctor.Worst(checks) == doctor.Fail {
		os.Exit(2)
	}
}
