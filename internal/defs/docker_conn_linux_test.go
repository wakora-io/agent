package defs

import (
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func TestDockerProbeLeavesNoOpenConnections(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var open int64
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"Id":"a1","Names":["/web"],"Image":"nginx:alpine","State":"running"},{"Id":"b2","Names":["/db"],"Image":"redis:7","State":"running"}]`))
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"27.0.0"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})
	srv := &http.Server{
		Handler: mux,
		ConnState: func(_ net.Conn, s http.ConnState) {
			switch s {
			case http.StateNew:
				atomic.AddInt64(&open, 1)
			case http.StateClosed, http.StateHijacked:
				atomic.AddInt64(&open, -1)
			}
		},
	}
	go srv.Serve(ln)
	defer srv.Close()

	for i := 0; i < 3; i++ {
		var o Outcome
		runDocker(&o, "docker", protocol.Probe{Path: sock}, 5*time.Second)
		if o.Check.Status != "ok" {
			t.Fatalf("probe failed: %s", o.Check.Error)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt64(&open) != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := atomic.LoadInt64(&open); n != 0 {
		t.Fatalf("%d connections to the docker socket stayed open after the probe returned", n)
	}
}
