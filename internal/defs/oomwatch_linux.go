//go:build linux

package defs

import (
	"context"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"wakora.io/agent/internal/protocol"
)

func (w *OOMWatch) Run(now time.Time) ([]protocol.MetricPoint, []protocol.AgentEvent) {
	container := cisInContainer(w.root)
	var entries []journalEntry
	if _, err := os.Stat(w.root + "run/systemd/journal"); err == nil {
		idents := []string{"kernel", "systemd"}
		if container {
			idents = []string{"systemd"}
		}
		entries, _ = journals.drain("host/oom", idents)
	}
	w.lines = w.lines[:0]
	for _, e := range entries {
		w.lines = append(w.lines, e.msg)
	}
	return w.collect(now, container, entries)
}

var (
	dockerImagesMu sync.Mutex
	dockerImages   = map[string]string{}
)

func DockerImageOf(id string) string {
	dockerImagesMu.Lock()
	img, ok := dockerImages[id]
	dockerImagesMu.Unlock()
	if ok {
		return img
	}
	sock := "/var/run/docker.sock"
	if _, err := os.Stat(sock); err != nil {
		return ""
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	defer client.CloseIdleConnections()
	var c struct {
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
	}
	if dockerGet(client, "/containers/"+id+"/json", &c) != nil || c.Config.Image == "" {
		return ""
	}
	img = imageKey(c.Config.Image)
	dockerImagesMu.Lock()
	if len(dockerImages) > 512 {
		dockerImages = map[string]string{}
	}
	dockerImages[id] = img
	dockerImagesMu.Unlock()
	return img
}
