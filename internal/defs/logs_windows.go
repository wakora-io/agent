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
		lines, maxNano, err := winEventQueryLines(ch, 15*60*1000, since)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if maxNano > since {
			l.winSince[ch] = maxNano
		}
		if !seen {
			continue
		}
		out = append(out, lines...)
	}
	return out, firstErr
}

func winEventQueryLines(channel string, windowMs, sinceNano int64) ([]protocol.LogLine, int64, error) {
	chPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, 0, err
	}
	query := "*[System[TimeCreated[timediff(@SystemTime) <= " + strconv.FormatInt(windowMs, 10) + "]]]"
	qPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return nil, 0, err
	}
	h, _, callErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(chPtr)),
		uintptr(unsafe.Pointer(qPtr)),
		uintptr(evtQueryChannelPath|evtQueryReverseDirection),
	)
	if h == 0 {
		return nil, 0, callErr
	}
	defer procEvtClose.Call(h)

	const batch = 64
	events := make([]uintptr, batch)
	var out []protocol.LogLine
	maxNano := sinceNano
	scanned := 0
	for scanned < 2000 && len(out) < winEventLineCap {
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
		stop := false
		for i := 0; i < int(returned); i++ {
			if ln, nano, ok := winEventLine(events[i]); ok {
				if nano > maxNano {
					maxNano = nano
				}
				if nano > sinceNano && len(out) < winEventLineCap {
					out = append(out, ln)
				}
				if nano <= sinceNano {
					stop = true
				}
			}
			procEvtClose.Call(events[i])
		}
		scanned += int(returned)
		if stop || returned < batch {
			break
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, maxNano, nil
}

func winEventLine(ev uintptr) (protocol.LogLine, int64, bool) {
	raw := renderEventXML(ev)
	if raw == "" {
		return protocol.LogLine{}, 0, false
	}
	var e evtXML
	if err := xml.Unmarshal([]byte(raw), &e); err != nil {
		return protocol.LogLine{}, 0, false
	}
	msg := formatEventMessage(e.System.Provider.Name, ev)
	if msg == "" {
		msg = strings.Join(e.EventData.Data, " ")
	}
	msg = strings.Join(strings.Fields(msg), " ")
	if msg == "" {
		return protocol.LogLine{}, 0, false
	}
	ts := time.Now().Unix()
	var nano int64
	if t, err := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime); err == nil {
		ts = t.Unix()
		nano = t.UnixNano()
	}
	return protocol.LogLine{
		Ts:      ts,
		Level:   winEventLevel(e.System.Level),
		Message: e.System.Provider.Name + "#" + e.System.EventID + ": " + msg,
	}, nano, true
}
