package agent

import (
	"context"
	"log"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"
)

type otlpVerdictKey struct{}

type otlpSenders struct {
	mu     sync.Mutex
	uids   map[uint32]bool
	at     time.Time
	missAt time.Time
	warnAt map[uint32]time.Time
	scan   func() map[uint32]bool
	now    func() time.Time
	noDiag sync.Once
}

func (a *Agent) otlpConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, otlpVerdictKey{}, a.otlpSenderOK(c))
}

func (a *Agent) otlpSenderOK(c net.Conn) bool {
	if runtime.GOOS != "linux" {
		return true
	}
	srv, ok := c.LocalAddr().(*net.TCPAddr)
	cli, ok2 := c.RemoteAddr().(*net.TCPAddr)
	if !ok || !ok2 || !srv.IP.IsLoopback() {
		return true
	}
	uid, ok := loopbackPeerUID(srv, cli)
	if !ok {
		a.senders.noDiag.Do(func() {
			log.Print("otlp: the kernel did not name the process behind a loopback connection, so the sender check is skipped and data is accepted")
		})
		return true
	}
	return a.senders.allowed(uid)
}

func (s *otlpSenders) allowed(uid uint32) bool {
	if uid == 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	scan := s.scan
	if scan == nil {
		scan = scanOTLPSenders
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	t := now()
	if s.uids == nil || t.Sub(s.at) > time.Minute {
		s.uids, s.at = scan(), t
	}
	if s.uids[uid] {
		return true
	}
	if t.Sub(s.missAt) > 10*time.Second {
		s.missAt = t
		s.uids, s.at = scan(), t
		if s.uids[uid] {
			return true
		}
	}
	if s.warnAt == nil {
		s.warnAt = map[uint32]time.Time{}
	}
	if t.Sub(s.warnAt[uid]) > 10*time.Minute {
		s.warnAt[uid] = t
		log.Printf("otlp: refused data from uid %d - no process running as it carries the OpenTelemetry instrumentation the agent installs", uid)
	}
	return false
}

func otlpGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := r.Context().Value(otlpVerdictKey{}).(bool); !ok {
			http.Error(w, "sender is not an instrumented runtime on this host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
