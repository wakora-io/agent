//go:build windows

package defs

import (
	"encoding/xml"
	"strconv"
	"strings"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"

	"wakora.io/agent/internal/protocol"
)

var (
	wevtapi                      = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery                 = wevtapi.NewProc("EvtQuery")
	procEvtNext                  = wevtapi.NewProc("EvtNext")
	procEvtClose                 = wevtapi.NewProc("EvtClose")
	procEvtRender                = wevtapi.NewProc("EvtRender")
	procEvtFormatMessage         = wevtapi.NewProc("EvtFormatMessage")
	procEvtOpenPublisherMetadata = wevtapi.NewProc("EvtOpenPublisherMetadata")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	countCap                 = 20000
	evtRenderEventXml        = 1
	evtFormatMessageEvent    = 1
	lastErrorsPerChannel     = 3
	errorMessageCap          = 240
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
	if o.Facts == nil {
		o.Facts = map[string]string{}
	}
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
			if m.name == "errors" && n > 0 {
				if samples := lastErrorEvents(ch, q); samples != "" {
					o.Facts["lastErrors."+ch] = samples
				}
			}
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

type evtXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []string `xml:"Data"`
	} `xml:"EventData"`
}

func lastErrorEvents(channel, query string) string {
	chPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return ""
	}
	qPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return ""
	}
	h, _, _ := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(chPtr)),
		uintptr(unsafe.Pointer(qPtr)),
		uintptr(evtQueryChannelPath|evtQueryReverseDirection),
	)
	if h == 0 {
		return ""
	}
	defer procEvtClose.Call(h)

	events := make([]uintptr, lastErrorsPerChannel)
	var returned uint32
	ret, _, _ := procEvtNext.Call(
		h,
		uintptr(lastErrorsPerChannel),
		uintptr(unsafe.Pointer(&events[0])),
		uintptr(5000),
		0,
		uintptr(unsafe.Pointer(&returned)),
	)
	if ret == 0 || returned == 0 {
		return ""
	}
	var lines []string
	for i := 0; i < int(returned); i++ {
		if s := describeEvent(events[i]); s != "" {
			lines = append(lines, s)
		}
		procEvtClose.Call(events[i])
	}
	return strings.Join(lines, " | ")
}

func describeEvent(ev uintptr) string {
	raw := renderEventXML(ev)
	if raw == "" {
		return ""
	}
	var e evtXML
	if err := xml.Unmarshal([]byte(raw), &e); err != nil {
		return ""
	}
	msg := formatEventMessage(e.System.Provider.Name, ev)
	if msg == "" {
		msg = strings.Join(e.EventData.Data, " ")
	}
	msg = strings.Join(strings.Fields(msg), " ")
	if len(msg) > errorMessageCap {
		cut := errorMessageCap
		for cut > 0 && !utf8.RuneStart(msg[cut]) {
			cut--
		}
		msg = msg[:cut] + "…"
	}
	out := e.System.Provider.Name + "#" + e.System.EventID
	if ts := e.System.TimeCreated.SystemTime; len(ts) >= 19 {
		out += " " + ts[:19] + "Z"
	}
	if msg != "" {
		out += ": " + msg
	}
	return out
}

func renderEventXML(ev uintptr) string {
	var used, props uint32
	buf := make([]uint16, 8192)
	ret, _, _ := procEvtRender.Call(
		0, ev, uintptr(evtRenderEventXml),
		uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)),
	)
	if ret == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

func formatEventMessage(provider string, ev uintptr) string {
	provPtr, err := windows.UTF16PtrFromString(provider)
	if err != nil {
		return ""
	}
	pm, _, _ := procEvtOpenPublisherMetadata.Call(0, uintptr(unsafe.Pointer(provPtr)), 0, 0, 0)
	if pm == 0 {
		return ""
	}
	defer procEvtClose.Call(pm)
	var used uint32
	buf := make([]uint16, 4096)
	ret, _, _ := procEvtFormatMessage.Call(
		pm, ev, 0, 0, 0, uintptr(evtFormatMessageEvent),
		uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)),
	)
	if ret == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
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
