//go:build windows

package defs

import (
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"

	"wakora.io/agent/internal/protocol"
)

var (
	wevtapi      = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery = wevtapi.NewProc("EvtQuery")
	procEvtNext  = wevtapi.NewProc("EvtNext")
	procEvtClose = wevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	countCap                 = 20000
)

func runEventLog(o *Outcome, service string, p protocol.Probe) {
	channels := p.Channels
	if len(channels) == 0 {
		channels = []string{"System", "Application"}
	}
	windowMs := p.WindowSec * 1000
	if windowMs <= 0 {
		windowMs = 3600 * 1000
	}
	prefix := "svc." + service + "."

	metrics := []struct {
		name   string
		levels string
	}{
		{"errors", "(Level=1 or Level=2) and "},
		{"warnings", "(Level=3) and "},
		{"events", ""},
	}
	var lastErr error
	ok := false
	for _, ch := range channels {
		tags := map[string]string{"channel": ch}
		for _, m := range metrics {
			q := "*[System[" + m.levels + "TimeCreated[timediff(@SystemTime) <= " + strconv.Itoa(windowMs) + "]]]"
			n, err := eventCount(ch, q)
			if err != nil {
				lastErr = err
				continue
			}
			ok = true
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + m.name, Value: float64(n), Tags: tags})
		}
	}
	if !ok {
		o.Check.Status = "fail"
		if lastErr != nil {
			o.Check.Error = lastErr.Error()
		} else {
			o.Check.Error = "no event log channels readable"
		}
		return
	}
	o.Check.Status = "ok"
}

func eventCount(channel, query string) (int, error) {
	chPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	qPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return 0, err
	}
	h, _, callErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(chPtr)),
		uintptr(unsafe.Pointer(qPtr)),
		uintptr(evtQueryChannelPath|evtQueryReverseDirection),
	)
	if h == 0 {
		return 0, callErr
	}
	defer procEvtClose.Call(h)

	const batch = 64
	events := make([]uintptr, batch)
	total := 0
	for total < countCap {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			h,
			uintptr(batch),
			uintptr(unsafe.Pointer(&events[0])),
			uintptr(5000),
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 {
			break
		}
		for i := 0; i < int(returned); i++ {
			procEvtClose.Call(events[i])
		}
		total += int(returned)
		if returned < batch {
			break
		}
	}
	return total, nil
}
