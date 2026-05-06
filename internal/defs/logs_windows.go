//go:build windows

package defs

import (
	"encoding/xml"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"wakora.io/agent/internal/protocol"
)

const winEventLineCap = 300

func winEventLevel(l string) string {
	switch l {
	case "1", "2":
		return "error"
	case "3":
		return "warn"
	case "5":
		return "debug"
	}
	return "info"
}

func (l *LogTailer) winEventLines(channels []string, now time.Time) ([]protocol.LogLine, error) {
	var out []protocol.LogLine
	var firstErr error
	for _, ch := range channels {
		since, seen := l.winSince[ch]
		if !seen {
			l.winSince[ch] = now.UnixMilli()
			continue
		}
		windowMs := now.UnixMilli() - since
		if windowMs <= 0 {
			continue
		}
		lines, err := winEventQueryLines(ch, windowMs)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		l.winSince[ch] = now.UnixMilli()
		out = append(out, lines...)
	}
	return out, firstErr
}

func winEventQueryLines(channel string, windowMs int64) ([]protocol.LogLine, error) {
	chPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, err
	}
	query := "*[System[TimeCreated[timediff(@SystemTime) <= " + strconv.FormatInt(windowMs, 10) + "]]]"
	qPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return nil, err
	}
	h, _, callErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(chPtr)),
		uintptr(unsafe.Pointer(qPtr)),
		uintptr(evtQueryChannelPath|evtQueryReverseDirection),
	)
	if h == 0 {
		return nil, callErr
	}
	defer procEvtClose.Call(h)

	const batch = 64
	events := make([]uintptr, batch)
	var out []protocol.LogLine
	for len(out) < winEventLineCap {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			h,
			uintptr(batch),
			uintptr(unsafe.Pointer(&events[0])),
			uintptr(5000),
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 || returned == 0 {
			break
		}
		for i := 0; i < int(returned); i++ {
			if ln, ok := winEventLine(events[i]); ok && len(out) < winEventLineCap {
				out = append(out, ln)
			}
			procEvtClose.Call(events[i])
		}
		if returned < batch {
			break
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func winEventLine(ev uintptr) (protocol.LogLine, bool) {
	raw := renderEventXML(ev)
	if raw == "" {
		return protocol.LogLine{}, false
	}
	var e evtXML
	if err := xml.Unmarshal([]byte(raw), &e); err != nil {
		return protocol.LogLine{}, false
	}
	msg := formatEventMessage(e.System.Provider.Name, ev)
	if msg == "" {
		msg = strings.Join(e.EventData.Data, " ")
	}
	msg = strings.Join(strings.Fields(msg), " ")
	if msg == "" {
		return protocol.LogLine{}, false
	}
	ts := time.Now().Unix()
	if t, err := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime); err == nil {
		ts = t.Unix()
	}
	return protocol.LogLine{
		Ts:      ts,
		Level:   winEventLevel(e.System.Level),
		Message: e.System.Provider.Name + "#" + e.System.EventID + ": " + msg,
	}, true
}
