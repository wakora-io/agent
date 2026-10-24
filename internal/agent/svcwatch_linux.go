//go:build linux

package agent

import (
	"context"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"time"

	"wakora.io/agent/internal/discovery"
	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/transport"
)

const svcWatchEvery = time.Minute

func (a *Agent) watchedUnits() map[string]string {
	a.mu.Lock()
	active := a.active
	facts := a.facts
	a.mu.Unlock()
	units := map[string]string{}
	live := map[string]bool{}
	for _, d := range active {
		if a.serviceDenied(d.Service) {
			continue
		}
		live[d.Service] = true
		if d.Match.Unit != "" {
			units[d.Match.Unit] = d.Service
			continue
		}
		for _, pid := range defPids(d, facts) {
			raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
			if err != nil {
				continue
			}
			if u := cgroupUnit(string(raw)); u != "" && u != "wakora-agent.service" {
				if _, taken := units[u]; !taken {
					units[u] = d.Service
				}
			}
		}
	}
	if a.unitSeen != nil {
		keepWatching(units, a.unitSeen, live)
	}
	return units
}

func (a *Agent) runServiceWatch(conn transport.Conn) (bool, error) {
	now := time.Now()
	if !a.svcWatchAt.IsZero() && now.Sub(a.svcWatchAt) < svcWatchEvery {
		return false, nil
	}
	a.svcWatchAt = now
	a.mu.Lock()
	all := a.defs
	facts := a.facts
	a.mu.Unlock()
	if len(facts) == 0 {
		return false, nil
	}
	moved := !sameKeys(defProcessKeys(all, facts), defProcessKeys(all, discovery.Processes()))
	restarts, err := a.unitRestarts(conn, now)
	if err != nil {
		return false, err
	}
	if !moved && restarts == 0 {
		return false, nil
	}
	log.Print("a watched service process changed, refreshing processes and ports")
	return true, a.refreshFacts(conn)
}

func (a *Agent) unitRestarts(conn transport.Conn, now time.Time) (int, error) {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return 0, nil
	}
	units := a.watchedUnits()
	if len(units) == 0 {
		return 0, nil
	}
	names := make([]string, 0, len(units))
	for u := range units {
		names = append(names, u)
	}
	sort.Strings(names)
	args := append([]string{"show", "-p", "Id", "-p", "NRestarts", "-p", "Result", "-p", "ExecMainStartTimestampMonotonic", "--"}, names...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).Output()
	if err != nil && len(out) == 0 {
		return 0, nil
	}
	if a.unitSeen == nil {
		a.unitSeen = map[string]unitState{}
	}
	restarts := unitRestarts(a.unitSeen, parseUnitShow(string(out)), units)
	for _, r := range restarts {
		ev := restartEvent(r, now.Unix())
		ev.ServerID = a.cfg.ServerID
		ev.Hostname = a.cfg.Hostname
		log.Printf("%s: %s", ev.Kind, ev.Detail)
		msg, err := protocol.Encode(protocol.TypeEvent, a.seq.Add(1), ev)
		if err != nil {
			continue
		}
		if err := conn.Send(msg); err != nil {
			return 0, err
		}
	}
	return len(restarts), nil
}

func (a *Agent) refreshFacts(conn transport.Conn) error {
	a.mu.Lock()
	prev := a.facts
	a.mu.Unlock()
	return a.applyFacts(conn, discovery.Refresh(prev))
}
