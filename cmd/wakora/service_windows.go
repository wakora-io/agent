//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"wakora.io/agent/internal/update"
)

const serviceName = "wakora"

func init() { update.CleanupOld() }

func underServiceManager() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

type wakoraService struct {
	run func(context.Context) error
}

func (w *wakoraService) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = w.run(ctx)
		close(done)
	}()
	s <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		case <-done:
			return false, 0
		}
	}
}

func runUnderServiceManager(ctx context.Context, run func(context.Context) error) error {
	return svc.Run(serviceName, &wakoraService{run: run})
}

func runServiceCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: wakora service <install|uninstall|start|stop>")
		os.Exit(2)
	}
	switch args[0] {
	case "install":
		if err := installService(); err != nil {
			log.Fatalf("install: %v", err)
		}
		fmt.Fprintln(os.Stderr, "wakora service installed and started")
	case "uninstall":
		if err := uninstallService(); err != nil {
			log.Fatalf("uninstall: %v", err)
		}
		fmt.Fprintln(os.Stderr, "wakora service removed")
	case "start", "stop":
		if err := controlService(args[0]); err != nil {
			log.Fatalf("%s: %v", args[0], err)
		}
	default:
		log.Fatalf("unknown service command %q", args[0])
	}
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists", serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  "Wakora Agent",
		Description:  "Wakora monitoring agent",
		StartType:    mgr.StartAutomatic,
		DelayedAutoStart: true,
	})
	if err != nil {
		return err
	}
	defer s.Close()

	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 3 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 3 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}, 86400)

	return s.Start()
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	return s.Delete()
}

func controlService(action string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if action == "start" {
		return s.Start()
	}
	_, err = s.Control(svc.Stop)
	return err
}
