//go:build linux

package defs

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

type linstorNetIf struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	IsActive bool   `json:"is_active"`
}

type linstorNode struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Status string         `json:"connection_status"`
	NetIfs []linstorNetIf `json:"net_interfaces"`
}

type linstorPool struct {
	Name     string `json:"storage_pool_name"`
	Node     string `json:"node_name"`
	Provider string `json:"provider_kind"`
	FreeKib  int64  `json:"free_capacity"`
	TotalKib int64  `json:"total_capacity"`
}

type linstorSnapNode struct {
	NodeName  string `json:"node_name"`
	CreatedMs int64  `json:"create_timestamp"`
}

type linstorSnap struct {
	Name     string            `json:"name"`
	Resource string            `json:"resource_name"`
	Nodes    []linstorSnapNode `json:"snapshots"`
}

type linstorReport struct {
	NodeName string `json:"node_name"`
	TimeMs   int64  `json:"error_time"`
}

func linstorClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func linstorGet(client *http.Client, base, path, token string, out any) error {
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fmt.Errorf("auth%d", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

func runLinstor(o *Outcome, service string, p protocol.Probe, resolve CredResolver) {
	secretName := p.Secret
	if secretName == "" {
		secretName = "linstor-controller"
	}
	token := ""
	if cred, ok := resolve(secretName); ok {
		token = cred.Pass
	}
	bases := p.URLs
	if len(bases) == 0 {
		bases = []string{"https://127.0.0.1:3371", "http://127.0.0.1:3370"}
	}
	client := linstorClient()

	var nodes []linstorNode
	base := ""
	var lastErr error
	for _, b := range bases {
		err := linstorGet(client, b, "/v1/nodes", token, &nodes)
		if err == nil {
			base = b
			break
		}
		lastErr = err
	}
	if base == "" {
		o.Check.Status = "fail"
		if lastErr != nil && strings.HasPrefix(lastErr.Error(), "auth") {
			o.Check.Error = "the controller api rejected the request (" + strings.TrimPrefix(lastErr.Error(), "auth") + ") - create an api token and store it: wakora secret set " + secretName
		} else {
			o.Check.Error = "controller api unreachable: " + lastErr.Error()
		}
		return
	}
	o.Check.Status = "ok"
	prefix := "svc." + service + "."
	add := func(name string, v float64, tags map[string]string) {
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + name, Value: v, Tags: tags})
	}

	onlineN := 0
	var offline []string
	var failover []string
	if len(nodes) > 50 {
		nodes = nodes[:50]
	}
	for _, n := range nodes {
		online := 0.0
		if n.Status == "ONLINE" {
			online = 1
			onlineN++
		} else if len(offline) < 8 {
			offline = append(offline, n.Name+": "+strings.ToLower(n.Status))
		}
		add("node.online", online, map[string]string{"node": n.Name})
		if n.Type == "Controller" {
			continue
		}
		active := ""
		for _, ni := range n.NetIfs {
			if ni.IsActive {
				active = ni.Name
				break
			}
		}
		if active != "" {
			onDefault := 0.0
			if active == "default" {
				onDefault = 1
			} else if len(failover) < 8 {
				failover = append(failover, n.Name+" via "+active)
			}
			add("netif.on_default", onDefault, map[string]string{"node": n.Name})
		}
	}
	add("nodes", float64(len(nodes)), nil)
	add("nodes_online", float64(onlineN), nil)

	var pools []linstorPool
	if err := linstorGet(client, base, "/v1/view/storage-pools", token, &pools); err == nil {
		if len(pools) > 200 {
			pools = pools[:200]
		}
		for _, sp := range pools {
			if sp.Provider == "DISKLESS" || sp.TotalKib <= 0 {
				continue
			}
			pct := float64(sp.FreeKib) / float64(sp.TotalKib) * 100
			add("pool.free_pct", pct, map[string]string{"pool": sp.Name + "@" + sp.Node})
		}
	}

	sinceMs := (time.Now().Unix() - 3600) * 1000
	var reports []linstorReport
	if err := linstorGet(client, base, "/v1/error-reports?since="+strconv.FormatInt(sinceMs, 10), token, &reports); err == nil {
		add("error_reports_hour", float64(len(reports)), nil)
	}

	var snaps []linstorSnap
	if err := linstorGet(client, base, "/v1/view/snapshots?limit=500", token, &snaps); err == nil {
		stale := 0
		var staleNames []string
		cutMs := (time.Now().Unix() - 86400) * 1000
		for _, s := range snaps {
			if !strings.Contains(strings.ToLower(s.Name), "vzdump") {
				continue
			}
			newest := int64(0)
			for _, sn := range s.Nodes {
				if sn.CreatedMs > newest {
					newest = sn.CreatedMs
				}
			}
			if newest > 0 && newest < cutMs {
				stale++
				if len(staleNames) < 5 {
					staleNames = append(staleNames, s.Resource+"/"+s.Name)
				}
			}
		}
		add("stale_snapshots", float64(stale), nil)
		if stale > 0 {
			sort.Strings(staleNames)
			if o.Facts == nil {
				o.Facts = map[string]string{}
			}
			o.Facts["staleSnaps"] = strings.Join(staleNames, ", ")
		}
	}

	if o.Facts == nil {
		o.Facts = map[string]string{}
	}
	o.Facts["nodes"] = strconv.Itoa(onlineN) + " of " + strconv.Itoa(len(nodes)) + " online"
	if len(offline) > 0 {
		o.Facts["offline"] = strings.Join(offline, ", ")
	}
	if len(failover) > 0 {
		o.Facts["failover"] = strings.Join(failover, ", ")
	}
}
