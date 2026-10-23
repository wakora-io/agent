package agent

import (
	"context"
	"log"
	"time"

	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/pause"
)

var pauseLogEvery = time.Hour

var pauseStateDir = func(c *config.Config) string { return c.StateDir() }

func (a *Agent) Paused() string {
	v, _ := a.paused.Load().(string)
	return v
}

func (a *Agent) setPaused(reason string, dkick chan struct{}) {
	reason = pause.Normalize(reason)
	prev := a.Paused()
	if reason == prev {
		return
	}
	a.paused.Store(reason)
	if err := pause.Write(pauseStateDir(a.cfg), reason); err != nil {
		log.Printf("pause state not saved: %v", err)
	}
	if reason != "" {
		if prev == "" {
			a.mu.Lock()
			a.lastRun = map[string]time.Time{}
			a.probeSeen = map[string]bool{}
			a.mu.Unlock()
		}
		log.Print(pause.Message(reason))
		return
	}
	log.Print("this host is monitored again: collection resumes")
	if dkick != nil {
		select {
		case dkick <- struct{}{}:
		default:
		}
	}
}

func (a *Agent) pauseLog(ctx context.Context) {
	if r := a.Paused(); r != "" {
		log.Print(pause.Message(r))
	}
	t := time.NewTicker(pauseLogEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if r := a.Paused(); r != "" {
				log.Print(pause.Message(r))
			}
		}
	}
}

func (a *Agent) quietWhilePaused() {
	a.closeUnusedListeners()
	a.stopEBPF("this host is not monitored on its workspace plan")
	for _, t := range a.tailers {
		t.CloseFDs()
	}
	for _, lt := range a.logTailers {
		lt.CloseFDs()
	}
}
