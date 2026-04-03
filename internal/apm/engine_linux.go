//go:build linux

package apm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var bucketBoundsMs = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

type portAgg struct {
	count   uint64
	err5xx  uint64
	err4xx  uint64
	maxNs   uint64
	buckets [14]uint64
}

type PortStats struct {
	Count   uint64
	Err5xx  uint64
	Err4xx  uint64
	MaxMs   float64
	P50Ms   float64
	P95Ms   float64
	Elapsed time.Duration
}

type Snapshot struct {
	HTTP       map[uint16]PortStats
	Downstream map[string]PortStats
	Elapsed    time.Duration
}

type Engine struct {
	mu        sync.Mutex
	objs      httpredObjects
	links     []link.Link
	rb        *ringbuf.Reader
	httpAgg   map[uint16]*portAgg
	dsAgg     map[string]*portAgg
	dsByPort  map[uint16]string
	lastDrain time.Time
	lastErr   error
	started   bool
}

func NewEngine() *Engine {
	return &Engine{httpAgg: map[uint16]*portAgg{}, dsAgg: map[string]*portAgg{}, dsByPort: map[uint16]string{}}
}

func Supported() (bool, string) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return false, "no kernel BTF (/sys/kernel/btf/vmlinux)"
	}
	if err := features.HaveProgramType(ebpf.Kprobe); err != nil {
		return false, "kprobe programs unavailable: " + err.Error()
	}
	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		return false, "ringbuf maps unavailable: " + err.Error()
	}
	return true, ""
}

func (e *Engine) Start(ports []int, downstream map[string][]int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started {
		return nil
	}
	if ok, reason := Supported(); !ok {
		return errors.New(reason)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("memlock: %w", err)
	}
	if err := loadHttpredObjects(&e.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("bpf verifier: %+v", ve)
		}
		return fmt.Errorf("bpf load: %w", err)
	}
	one := uint8(1)
	for _, p := range ports {
		if p > 0 && p < 65536 {
			if err := e.objs.WatchedPorts.Put(uint16(p), one); err != nil {
				e.closeLocked()
				return err
			}
		}
	}
	for comp, dports := range downstream {
		for _, p := range dports {
			if p > 0 && p < 65536 {
				if err := e.objs.DownstreamPorts.Put(uint16(p), one); err != nil {
					e.closeLocked()
					return err
				}
				e.dsByPort[uint16(p)] = comp
			}
		}
	}
	attach := []struct {
		name string
		prog *ebpf.Program
		ret  bool
	}{
		{"tcp_recvmsg", e.objs.TcpRecvEnter, false},
		{"tcp_recvmsg", e.objs.TcpRecvExit, true},
		{"tcp_sendmsg", e.objs.TcpSendEnter, false},
	}
	for _, a := range attach {
		var l link.Link
		var err error
		if a.ret {
			l, err = link.Kretprobe(a.name, a.prog, nil)
		} else {
			l, err = link.Kprobe(a.name, a.prog, nil)
		}
		if err != nil {
			e.closeLocked()
			return fmt.Errorf("attach %s: %w", a.name, err)
		}
		e.links = append(e.links, l)
	}
	rb, err := ringbuf.NewReader(e.objs.Events)
	if err != nil {
		e.closeLocked()
		return err
	}
	e.rb = rb
	e.started = true
	e.lastDrain = time.Now()
	go e.readLoop()
	return nil
}

func (e *Engine) readLoop() {
	for {
		rec, err := e.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			e.mu.Lock()
			e.lastErr = err
			e.mu.Unlock()
			continue
		}
		if len(rec.RawSample) < 13 {
			continue
		}
		durNs := binary.LittleEndian.Uint64(rec.RawSample[0:8])
		port := binary.LittleEndian.Uint16(rec.RawSample[8:10])
		status := binary.LittleEndian.Uint16(rec.RawSample[10:12])
		kind := rec.RawSample[12]
		if durNs > 30_000_000_000 {
			continue
		}
		e.mu.Lock()
		var a *portAgg
		if kind == 1 {
			comp := e.dsByPort[port]
			if comp == "" {
				e.mu.Unlock()
				continue
			}
			a = e.dsAgg[comp]
			if a == nil {
				a = &portAgg{}
				e.dsAgg[comp] = a
			}
		} else {
			a = e.httpAgg[port]
			if a == nil {
				a = &portAgg{}
				e.httpAgg[port] = a
			}
			if status >= 500 {
				a.err5xx++
			} else if status >= 400 {
				a.err4xx++
			}
		}
		a.count++
		if durNs > a.maxNs {
			a.maxNs = durNs
		}
		ms := float64(durNs) / 1e6
		idx := len(bucketBoundsMs)
		for i, b := range bucketBoundsMs {
			if ms <= b {
				idx = i
				break
			}
		}
		a.buckets[idx]++
		e.mu.Unlock()
	}
}

func (e *Engine) Drain() (Snapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started {
		return Snapshot{}, errors.New("engine not started")
	}
	elapsed := time.Since(e.lastDrain)
	e.lastDrain = time.Now()
	snap := Snapshot{
		HTTP:       make(map[uint16]PortStats, len(e.httpAgg)),
		Downstream: make(map[string]PortStats, len(e.dsAgg)),
		Elapsed:    elapsed,
	}
	for port, a := range e.httpAgg {
		snap.HTTP[port] = statsFrom(a, elapsed)
		e.httpAgg[port] = &portAgg{}
	}
	for comp, a := range e.dsAgg {
		snap.Downstream[comp] = statsFrom(a, elapsed)
		e.dsAgg[comp] = &portAgg{}
	}
	err := e.lastErr
	e.lastErr = nil
	return snap, err
}

func statsFrom(a *portAgg, elapsed time.Duration) PortStats {
	return PortStats{
		Count:   a.count,
		Err5xx:  a.err5xx,
		Err4xx:  a.err4xx,
		MaxMs:   float64(a.maxNs) / 1e6,
		P50Ms:   percentile(a, 0.50),
		P95Ms:   percentile(a, 0.95),
		Elapsed: elapsed,
	}
}

func percentile(a *portAgg, q float64) float64 {
	if a.count == 0 {
		return 0
	}
	maxMs := float64(a.maxNs) / 1e6
	target := uint64(float64(a.count)*q + 0.5)
	if target < 1 {
		target = 1
	}
	var cum uint64
	lower := 0.0
	for i, n := range a.buckets {
		upper := maxMs
		if i < len(bucketBoundsMs) {
			upper = bucketBoundsMs[i]
		}
		if n > 0 && cum+n >= target {
			frac := float64(target-cum) / float64(n)
			v := lower + (upper-lower)*frac
			if v > maxMs {
				v = maxMs
			}
			return v
		}
		cum += n
		lower = upper
	}
	return maxMs
}

func (e *Engine) closeLocked() {
	for _, l := range e.links {
		l.Close()
	}
	e.links = nil
	if e.rb != nil {
		e.rb.Close()
		e.rb = nil
	}
	e.objs.Close()
	e.started = false
}

func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closeLocked()
}
