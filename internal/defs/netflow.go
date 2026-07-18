package defs

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"wakora.io/agent/internal/protocol"
)

const (
	flowWindowSec  = 60
	flowAggCap     = 5000
	flowTopPerExp  = 100
	nfFieldBytes   = 1
	nfFieldPkts    = 2
	nfFieldProto   = 4
	nfFieldSrcPort = 7
	nfFieldSrcV4   = 8
	nfFieldDstPort = 11
	nfFieldDstV4   = 12
	nfFieldOutB    = 23
	nfFieldSrcV6   = 27
	nfFieldDstV6   = 28
)

type flowKey struct {
	exporter string
	src      string
	dst      string
	proto    uint8
	dstPort  uint16
}

type flowVal struct {
	bytes   uint64
	packets uint64
}

type tmplField struct {
	typ    uint16
	length uint16
}

type flowTemplate struct {
	fields []tmplField
	width  int
	fixed  bool
}

type FlowListener struct {
	port int

	mu          sync.Mutex
	allow       map[string]bool
	templates   map[string]map[uint16]flowTemplate
	agg         map[flowKey]*flowVal
	windowStart int64
	totalFlows  map[string]uint64
	totalBytes  map[string]uint64
	dropped     uint64
	lastErr     error

	conn *net.UDPConn
}

func NewFlowListener(port int) *FlowListener {
	if port <= 0 {
		port = 2055
	}
	return &FlowListener{
		port:        port,
		allow:       map[string]bool{},
		templates:   map[string]map[uint16]flowTemplate{},
		agg:         map[flowKey]*flowVal{},
		totalFlows:  map[string]uint64{},
		totalBytes:  map[string]uint64{},
		windowStart: time.Now().Unix(),
	}
}

func (f *FlowListener) Port() int { return f.port }

func (f *FlowListener) Configure(allowFrom []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	allow := make(map[string]bool, len(allowFrom))
	for _, ip := range allowFrom {
		if ip != "" {
			allow[ip] = true
		}
	}
	f.allow = allow
}

func (f *FlowListener) Start() {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", f.port))
	if err != nil {
		f.mu.Lock()
		f.lastErr = err
		f.mu.Unlock()
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		f.mu.Lock()
		f.lastErr = err
		f.mu.Unlock()
		return
	}
	f.conn = conn
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			f.Ingest(from.IP.String(), pkt)
		}
	}()
}

func (f *FlowListener) Close() {
	if f.conn != nil {
		f.conn.Close()
	}
}

func (f *FlowListener) Ingest(source string, pkt []byte) {
	if len(pkt) < 4 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.allow) > 0 && !f.allow[source] {
		f.dropped++
		return
	}
	switch binary.BigEndian.Uint16(pkt[0:2]) {
	case 5:
		f.ingestV5(source, pkt)
	case 9:
		f.ingestV9(source, pkt)
	case 10:
		f.ingestIPFIX(source, pkt)
	default:
		f.dropped++
	}
}

func (f *FlowListener) add(exporter, src, dst string, proto uint8, dstPort uint16, bytes, packets uint64) {
	f.totalFlows[exporter]++
	f.totalBytes[exporter] += bytes
	k := flowKey{exporter, src, dst, proto, dstPort}
	v, ok := f.agg[k]
	if !ok {
		if len(f.agg) >= flowAggCap {
			return
		}
		v = &flowVal{}
		f.agg[k] = v
	}
	v.bytes += bytes
	v.packets += packets
}

func (f *FlowListener) ingestV5(source string, pkt []byte) {
	if len(pkt) < 24 {
		return
	}
	count := int(binary.BigEndian.Uint16(pkt[2:4]))
	for i := 0; i < count; i++ {
		off := 24 + i*48
		if off+48 > len(pkt) {
			break
		}
		r := pkt[off : off+48]
		f.add(source,
			net.IP(r[0:4]).String(), net.IP(r[4:8]).String(),
			r[38], binary.BigEndian.Uint16(r[34:36]),
			uint64(binary.BigEndian.Uint32(r[20:24])), uint64(binary.BigEndian.Uint32(r[16:20])))
	}
}

func (f *FlowListener) tmplKey(source string, domain uint32) string {
	return fmt.Sprintf("%s|%d", source, domain)
}

func (f *FlowListener) storeTemplate(key string, id uint16, fields []tmplField) {
	t := flowTemplate{fields: fields, fixed: true}
	for _, fl := range fields {
		if fl.length == 0xffff {
			t.fixed = false
			break
		}
		t.width += int(fl.length)
	}
	m := f.templates[key]
	if m == nil {
		if len(f.templates) >= 64 {
			return
		}
		m = map[uint16]flowTemplate{}
		f.templates[key] = m
	}
	if len(m) < 128 {
		m[id] = t
	}
}

func readUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

func (f *FlowListener) parseDataSet(source, key string, id uint16, body []byte) {
	t, ok := f.templates[key][id]
	if !ok || !t.fixed || t.width == 0 {
		return
	}
	for off := 0; off+t.width <= len(body); off += t.width {
		rec := body[off : off+t.width]
		var src, dst string
		var proto uint8
		var dstPort uint16
		var bytesV, pktsV, outB uint64
		p := 0
		for _, fl := range t.fields {
			fb := rec[p : p+int(fl.length)]
			p += int(fl.length)
			switch fl.typ {
			case nfFieldBytes:
				bytesV = readUint(fb)
			case nfFieldOutB:
				outB = readUint(fb)
			case nfFieldPkts:
				pktsV = readUint(fb)
			case nfFieldProto:
				proto = uint8(readUint(fb))
			case nfFieldDstPort:
				dstPort = uint16(readUint(fb))
			case nfFieldSrcV4:
				if len(fb) == 4 {
					src = net.IP(fb).String()
				}
			case nfFieldDstV4:
				if len(fb) == 4 {
					dst = net.IP(fb).String()
				}
			case nfFieldSrcV6:
				if len(fb) == 16 && src == "" {
					src = net.IP(fb).String()
				}
			case nfFieldDstV6:
				if len(fb) == 16 && dst == "" {
					dst = net.IP(fb).String()
				}
			}
		}
		if bytesV == 0 {
			bytesV = outB
		}
		if src == "" && dst == "" {
			continue
		}
		f.add(source, src, dst, proto, dstPort, bytesV, pktsV)
	}
}

func (f *FlowListener) ingestV9(source string, pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	key := f.tmplKey(source, binary.BigEndian.Uint32(pkt[16:20]))
	off := 20
	for off+4 <= len(pkt) {
		setID := binary.BigEndian.Uint16(pkt[off : off+2])
		setLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if setLen < 4 || off+setLen > len(pkt) {
			return
		}
		body := pkt[off+4 : off+setLen]
		switch {
		case setID == 0:
			f.parseV9Templates(key, body)
		case setID >= 256:
			f.parseDataSet(source, key, setID, body)
		}
		off += setLen
	}
}

func (f *FlowListener) parseV9Templates(key string, body []byte) {
	off := 0
	for off+4 <= len(body) {
		id := binary.BigEndian.Uint16(body[off : off+2])
		n := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+n*4 > len(body) || id < 256 {
			return
		}
		fields := make([]tmplField, 0, n)
		for i := 0; i < n; i++ {
			fields = append(fields, tmplField{
				typ:    binary.BigEndian.Uint16(body[off : off+2]),
				length: binary.BigEndian.Uint16(body[off+2 : off+4]),
			})
			off += 4
		}
		f.storeTemplate(key, id, fields)
	}
}

func (f *FlowListener) ingestIPFIX(source string, pkt []byte) {
	if len(pkt) < 16 {
		return
	}
	key := f.tmplKey(source, binary.BigEndian.Uint32(pkt[12:16]))
	off := 16
	for off+4 <= len(pkt) {
		setID := binary.BigEndian.Uint16(pkt[off : off+2])
		setLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if setLen < 4 || off+setLen > len(pkt) {
			return
		}
		body := pkt[off+4 : off+setLen]
		switch {
		case setID == 2:
			f.parseIPFIXTemplates(key, body)
		case setID >= 256:
			f.parseDataSet(source, key, setID, body)
		}
		off += setLen
	}
}

func (f *FlowListener) parseIPFIXTemplates(key string, body []byte) {
	off := 0
	for off+4 <= len(body) {
		id := binary.BigEndian.Uint16(body[off : off+2])
		n := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if id < 256 {
			return
		}
		fields := make([]tmplField, 0, n)
		for i := 0; i < n; i++ {
			if off+4 > len(body) {
				return
			}
			typ := binary.BigEndian.Uint16(body[off : off+2])
			length := binary.BigEndian.Uint16(body[off+2 : off+4])
			off += 4
			if typ&0x8000 != 0 {
				if off+4 > len(body) {
					return
				}
				off += 4
				typ = 0
			}
			fields = append(fields, tmplField{typ: typ, length: length})
		}
		f.storeTemplate(key, id, fields)
	}
}

func (f *FlowListener) Drain(now int64) []protocol.FlowBatch {
	f.mu.Lock()
	defer f.mu.Unlock()
	if now-f.windowStart < flowWindowSec {
		return nil
	}
	winStart, winSec := f.windowStart, int(now-f.windowStart)
	byExp := map[string][]protocol.FlowRow{}
	for k, v := range f.agg {
		byExp[k.exporter] = append(byExp[k.exporter], protocol.FlowRow{
			Src: k.src, Dst: k.dst, Proto: k.proto, DstPort: k.dstPort,
			Bytes: v.bytes, Packets: v.packets,
		})
	}
	out := make([]protocol.FlowBatch, 0, len(byExp))
	for exp, rows := range byExp {
		sort.Slice(rows, func(i, j int) bool { return rows[i].Bytes > rows[j].Bytes })
		if len(rows) > flowTopPerExp {
			rows = rows[:flowTopPerExp]
		}
		out = append(out, protocol.FlowBatch{
			Exporter: exp, WindowStart: winStart, WindowSec: winSec,
			TotalFlows: f.totalFlows[exp], TotalBytes: f.totalBytes[exp], Rows: rows,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Exporter < out[j].Exporter })
	f.agg = map[flowKey]*flowVal{}
	f.totalFlows = map[string]uint64{}
	f.totalBytes = map[string]uint64{}
	f.windowStart = now
	return out
}

func (f *FlowListener) Snapshot() (dropped uint64, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dropped, f.lastErr
}
