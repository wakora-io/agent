package defs

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"wakora.io/agent/internal/protocol"
)

type dockerContainer struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	State string   `json:"State"`
}

type dockerStats struct {
	CPU struct {
		Usage struct {
			Total float64 `json:"total_usage"`
		} `json:"cpu_usage"`
		System     float64 `json:"system_cpu_usage"`
		OnlineCPUs float64 `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPU struct {
		Usage struct {
			Total float64 `json:"total_usage"`
		} `json:"cpu_usage"`
		System float64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	Memory struct {
		Usage float64            `json:"usage"`
		Stats map[string]float64 `json:"stats"`
	} `json:"memory_stats"`
}

type dockerGroup struct {
	Image   string
	Count   int
	Running int
	Names   []string
}

func runDocker(o *Outcome, service string, p protocol.Probe, timeout time.Duration) {
	sock := p.Path
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	o.Check.Target = "unix://" + sock
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}

	var containers []dockerContainer
	if err := dockerGet(client, "/containers/json?all=1", &containers); err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	o.Check.Status = "ok"

	var ver struct {
		Version string `json:"Version"`
	}
	if err := dockerGet(client, "/version", &ver); err == nil && ver.Version != "" {
		o.Facts = map[string]string{"version": ver.Version}
	}

	groups := groupContainers(containers)
	total, running := 0, 0
	for _, g := range groups {
		total += g.Count
		running += g.Running
	}
	prefix := "svc." + service + "."
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: prefix + "containers", Value: float64(total)},
		protocol.MetricPoint{Name: prefix + "containers_running", Value: float64(running)},
		protocol.MetricPoint{Name: prefix + "services", Value: float64(len(groups))},
	)

	cpuByImage, memByImage := collectStats(client, containers, timeout)
	for _, g := range groups {
		tags := map[string]string{"image": g.Image}
		o.Metrics = append(o.Metrics,
			protocol.MetricPoint{Name: prefix + "group.containers", Value: float64(g.Count), Tags: tags},
			protocol.MetricPoint{Name: prefix + "group.running", Value: float64(g.Running), Tags: tags},
		)
		if cpu, ok := cpuByImage[g.Image]; ok {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "group.cpu_pct", Value: cpu, Tags: tags})
		}
		if mem, ok := memByImage[g.Image]; ok {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "group.mem_bytes", Value: mem, Tags: tags})
		}

		names := g.Names
		if len(names) > 20 {
			names = names[:20]
		}
		payload, err := json.Marshal(map[string]any{
			"count": g.Count, "running": g.Running, "containers": strings.Join(names, ","),
		})
		if err == nil {
			o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "docker", Key: g.Image, Payload: string(payload)})
		}
	}
}

func collectStats(client *http.Client, containers []dockerContainer, timeout time.Duration) (cpu, mem map[string]float64) {
	cpu = map[string]float64{}
	mem = map[string]float64{}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, c := range containers {
		if c.State != "running" {
			continue
		}
		wg.Add(1)
		go func(c dockerContainer) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var s dockerStats
			if err := dockerGetCtx(ctx, client, "/containers/"+c.ID+"/stats?stream=false", &s); err != nil {
				return
			}
			img := imageKey(c.Image)
			mu.Lock()
			defer mu.Unlock()
			if pct, ok := cpuPercent(s); ok {
				cpu[img] += pct
			}
			mem[img] += memUsage(s)
		}(c)
	}
	wg.Wait()
	return cpu, mem
}

func groupContainers(cs []dockerContainer) []dockerGroup {
	byImage := map[string]*dockerGroup{}
	for _, c := range cs {
		img := imageKey(c.Image)
		g := byImage[img]
		if g == nil {
			g = &dockerGroup{Image: img}
			byImage[img] = g
		}
		g.Count++
		if c.State == "running" {
			g.Running++
		}
		if len(c.Names) > 0 {
			if name := strings.TrimPrefix(c.Names[0], "/"); name != "" {
				g.Names = append(g.Names, name)
			}
		}
	}
	out := make([]dockerGroup, 0, len(byImage))
	for _, g := range byImage {
		sort.Strings(g.Names)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Image < out[j].Image })
	return out
}

func imageKey(img string) string {
	if img == "" {
		return "unknown"
	}
	if strings.HasPrefix(img, "sha256:") && len(img) > 19 {
		return img[:19]
	}
	return img
}

func cpuPercent(s dockerStats) (float64, bool) {
	cpuDelta := s.CPU.Usage.Total - s.PreCPU.Usage.Total
	sysDelta := s.CPU.System - s.PreCPU.System
	if sysDelta <= 0 || cpuDelta < 0 || s.PreCPU.System == 0 {
		return 0, false
	}
	n := s.CPU.OnlineCPUs
	if n <= 0 {
		n = 1
	}
	return cpuDelta / sysDelta * n * 100, true
}

func memUsage(s dockerStats) float64 {
	u := s.Memory.Usage
	if v, ok := s.Memory.Stats["inactive_file"]; ok && v < u {
		u -= v
	}
	return u
}

func dockerGet(client *http.Client, path string, v any) error {
	return dockerGetCtx(context.Background(), client, path, v)
}

func dockerGetCtx(ctx context.Context, client *http.Client, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker api %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
