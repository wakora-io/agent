package metrics

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Host struct {
	Timestamp  int64
	Load1      float64
	MemTotalKB uint64
	MemFreeKB  uint64
	UptimeSec  float64
}

func Collect() Host {
	h := Host{Timestamp: time.Now().Unix()}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			h.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			h.UptimeSec, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseUint(f[1], 10, 64)
			switch f[0] {
			case "MemTotal:":
				h.MemTotalKB = v
			case "MemAvailable:":
				h.MemFreeKB = v
			}
		}
	}
	return h
}
