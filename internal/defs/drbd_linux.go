//go:build linux

package defs

import (
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wakora.io/agent/internal/protocol"
)

type drbdPeerDev struct {
	Volume     int     `json:"volume"`
	Repl       string  `json:"replication-state"`
	PeerDisk   string  `json:"peer-disk-state"`
	PeerClient bool    `json:"peer-client"`
	ResyncSusp string  `json:"resync-suspended"`
	OutOfSync  float64 `json:"out-of-sync"`
	Percent    float64 `json:"percent-in-sync"`
	EtaSec     float64 `json:"estimated-seconds-to-finish"`
}

type drbdConn struct {
	Name      string        `json:"name"`
	State     string        `json:"connection-state"`
	Congested bool          `json:"congested"`
	PeerRole  string        `json:"peer-role"`
	PeerDevs  []drbdPeerDev `json:"peer_devices"`
}

type drbdDev struct {
	Volume       int     `json:"volume"`
	DiskState    string  `json:"disk-state"`
	Client       bool    `json:"client"`
	Quorum       bool    `json:"quorum"`
	UpperPending float64 `json:"upper-pending"`
	LowerPending float64 `json:"lower-pending"`
}

type drbdRes struct {
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	Suspended bool       `json:"suspended"`
	ForceIO   bool       `json:"force-io-failures"`
	Devices   []drbdDev  `json:"devices"`
	Conns     []drbdConn `json:"connections"`
}

type drbdLinkMem struct {
	oos     float64
	pct     float64
	stuckAt time.Time
	up      bool
	upKnown bool
	flaps   []time.Time
}

var (
	drbdMu  sync.Mutex
	drbdMem = map[string]*drbdLinkMem{}
)

var drbdSyncStates = map[string]bool{
	"StartingSyncS": true, "StartingSyncT": true, "WFBitMapS": true, "WFBitMapT": true,
	"WFSyncUUID": true, "SyncSource": true, "SyncTarget": true,
}

func runDRBD(o *Outcome, service string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "drbdsetup", "status", "--json").Output()
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "drbdsetup status: " + err.Error()
		return
	}
	var resources []drbdRes
	if err := json.Unmarshal(out, &resources); err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "drbdsetup json: " + err.Error()
		return
	}
	drbdEmit(o, service, resources, time.Now())
}

func drbdEmit(o *Outcome, service string, resources []drbdRes, now time.Time) {
	o.Check.Status = "ok"
	prefix := "svc." + service + "."
	add := func(name string, v float64, tags map[string]string) {
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + name, Value: v, Tags: tags})
	}
	add("resources", float64(len(resources)), nil)
	if len(resources) == 0 {
		o.Check.Error = "no drbd resources configured"
		return
	}
	if len(resources) > 100 {
		resources = resources[:100]
	}

	drbdMu.Lock()
	defer drbdMu.Unlock()
	live := map[string]bool{}
	var degraded []string
	links := 0

	for _, r := range resources {
		rt := map[string]string{"res": r.Name}
		primary := 0.0
		if r.Role == "Primary" {
			primary = 1
		}
		susp := 0.0
		if r.Suspended || r.ForceIO {
			susp = 1
		}
		upToDate := 1.0
		quorum := 1.0
		lowerPending := 0.0
		diskful := false
		for _, d := range r.Devices {
			if !d.Quorum {
				quorum = 0
			}
			lowerPending += d.LowerPending
			if d.Client {
				continue
			}
			diskful = true
			if d.DiskState != "UpToDate" {
				upToDate = 0
				if len(degraded) < 8 {
					degraded = append(degraded, r.Name+": "+d.DiskState)
				}
			}
		}
		replicas := 0.0
		if diskful && upToDate == 1 {
			replicas = 1
		}
		add("resource.primary", primary, rt)
		add("resource.suspended", susp, rt)
		add("device.quorum", quorum, rt)
		if diskful {
			add("device.uptodate", upToDate, rt)
		}
		if lowerPending > 0 {
			add("device.lower_pending", lowerPending, rt)
		}

		for _, c := range r.Conns {
			if links >= 300 {
				break
			}
			links++
			link := r.Name + ":" + strings.ToLower(c.Name)
			lt := map[string]string{"link": link}
			up := c.State == "Connected"
			est := 0.0
			if up {
				est = 1
			}
			cong := 0.0
			if c.Congested {
				cong = 1
			}
			oosSum, lingering, pctMin, etaMax := 0.0, 0.0, 100.0, 0.0
			syncing := false
			peerDiskful, peerAllUpToDate := false, true
			for _, pd := range c.PeerDevs {
				oosSum += pd.OutOfSync
				if pd.Repl == "Established" {
					lingering += pd.OutOfSync
				}
				if drbdSyncStates[pd.Repl] {
					syncing = true
					if pd.Percent < pctMin {
						pctMin = pd.Percent
					}
				}
				if pd.EtaSec > etaMax {
					etaMax = pd.EtaSec
				}
				if !pd.PeerClient {
					peerDiskful = true
					if pd.PeerDisk != "UpToDate" {
						peerAllUpToDate = false
					}
				}
			}
			if peerDiskful && peerAllUpToDate {
				replicas++
			}

			m, ok := drbdMem[link]
			if !ok {
				m = &drbdLinkMem{}
				drbdMem[link] = m
			}
			live[link] = true

			stalled := 0.0
			if syncing && oosSum > 0 {
				if !m.stuckAt.IsZero() && m.oos == oosSum && m.pct == pctMin {
					if now.Sub(m.stuckAt) >= 10*time.Minute {
						stalled = 1
					}
				} else {
					m.stuckAt = now
				}
			} else {
				m.stuckAt = time.Time{}
			}
			m.oos = oosSum
			m.pct = pctMin

			if m.upKnown && m.up != up {
				m.flaps = append(m.flaps, now)
			}
			m.up = up
			m.upKnown = true
			cut := now.Add(-time.Hour)
			for len(m.flaps) > 0 && m.flaps[0].Before(cut) {
				m.flaps = m.flaps[1:]
			}

			add("connection.established", est, lt)
			add("connection.congested", cong, lt)
			add("connection.flaps_hour", float64(len(m.flaps)), lt)
			add("peer.oos_kib", oosSum, lt)
			add("peer.oos_lingering_kib", lingering, lt)
			add("peer.resync_stalled", stalled, lt)
			if syncing {
				add("peer.resync_percent", pctMin, lt)
			}
			if etaMax > 0 {
				add("peer.eta_sec", etaMax, lt)
			}
		}
		add("resource.replicas_uptodate", replicas, rt)
	}

	for k := range drbdMem {
		if !live[k] {
			delete(drbdMem, k)
		}
	}

	sort.Strings(degraded)
	facts := map[string]string{"resources": strconv.Itoa(len(resources))}
	if len(degraded) > 0 {
		facts["degraded"] = strings.Join(degraded, ", ")
	}
	o.Facts = facts
}
