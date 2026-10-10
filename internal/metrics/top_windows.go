//go:build windows

package metrics

import (
	"sort"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const topN = 5

var (
	procK32GetProcessMemoryInfo = kernel32.NewProc("K32GetProcessMemoryInfo")
	procGetProcessIoCounters    = kernel32.NewProc("GetProcessIoCounters")
)

type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

type ioCounters struct {
	readOperationCount  uint64
	writeOperationCount uint64
	otherOperationCount uint64
	readTransferCount   uint64
	writeTransferCount  uint64
	otherTransferCount  uint64
}

type topAgg struct {
	ticks uint64
	rss   uint64
	io    uint64
}

type procSample struct {
	name  string
	cpu   uint64
	rss   uint64
	io    uint64
	valid bool
}

func (c *Collector) topPoints(now time.Time) []Point {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var samples []procSample
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID == 0 {
			continue
		}
		if s := sampleProcess(e.ProcessID, windows.UTF16ToString(e.ExeFile[:])); s.valid {
			samples = append(samples, s)
		}
	}
	return c.topFrom(aggregateTop(samples), now)
}

func sampleProcess(pid uint32, name string) procSample {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return procSample{}
	}
	defer windows.CloseHandle(h)
	s := procSample{name: name}
	var created, exited, kernelT, userT windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernelT, &userT) == nil {
		s.cpu = filetimeToUint64(kernelT) + filetimeToUint64(userT)
		s.valid = true
	}
	var mem processMemoryCounters
	mem.cb = uint32(unsafe.Sizeof(mem))
	if r, _, _ := procK32GetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mem)), uintptr(mem.cb)); r != 0 {
		s.rss = uint64(mem.workingSetSize)
		s.valid = true
	}
	var io ioCounters
	if r, _, _ := procGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&io))); r != 0 {
		s.io = io.readTransferCount + io.writeTransferCount
	}
	return s
}

func aggregateTop(samples []procSample) map[string]*topAgg {
	cur := map[string]*topAgg{}
	for _, s := range samples {
		a := cur[s.name]
		if a == nil {
			a = &topAgg{}
			cur[s.name] = a
		}
		a.ticks += s.cpu
		a.rss += s.rss
		a.io += s.io
	}
	return cur
}

func (c *Collector) topFrom(cur map[string]*topAgg, now time.Time) []Point {
	prev := c.prevTop
	prevAt := c.prevTopAt
	next := make(map[string]topSample, len(cur))
	for name, a := range cur {
		next[name] = topSample{ticks: a.ticks, io: a.io}
	}
	c.prevTop = next
	c.prevTopAt = now

	var pts []Point
	type row struct {
		name string
		v    float64
	}
	pick := func(rows []row, metric string) {
		sort.Slice(rows, func(i, j int) bool { return rows[i].v > rows[j].v })
		if len(rows) > topN {
			rows = rows[:topN]
		}
		for _, r := range rows {
			pts = append(pts, Point{Name: metric, Value: r.v, Tags: map[string]string{"proc": r.name}})
		}
	}

	var memRows []row
	for name, a := range cur {
		if a.rss > 0 {
			memRows = append(memRows, row{name, float64(a.rss)})
		}
	}
	pick(memRows, "host.top.mem_bytes")

	dt := now.Sub(prevAt).Seconds()
	if prev == nil || dt <= 0 {
		return pts
	}
	var cpuRows, ioRows []row
	for name, a := range cur {
		p, had := prev[name]
		if !had {
			continue
		}
		if a.ticks > p.ticks {
			pct := float64(a.ticks-p.ticks) / 1e7 / dt * 100
			cpuRows = append(cpuRows, row{name, float64(int(pct*10+0.5)) / 10})
		}
		if a.io > p.io {
			ioRows = append(ioRows, row{name, float64(int(float64(a.io-p.io)/dt + 0.5))})
		}
	}
	pick(cpuRows, "host.top.cpu_pct")
	pick(ioRows, "host.top.io_bps")
	return pts
}
