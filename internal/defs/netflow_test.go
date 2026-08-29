package defs

import (
	"encoding/binary"
	"testing"
	"time"
)

func nfDrain(l *FlowListener) []struct {
	Exporter   string
	Rows       int
	TotalBytes uint64
} {
	out := []struct {
		Exporter   string
		Rows       int
		TotalBytes uint64
	}{}
	for _, b := range l.Drain(time.Now().Unix() + flowWindowSec + 1) {
		out = append(out, struct {
			Exporter   string
			Rows       int
			TotalBytes uint64
		}{b.Exporter, len(b.Rows), b.TotalBytes})
	}
	return out
}

func TestNetflowV5Parses(t *testing.T) {
	pkt := make([]byte, 24+48)
	binary.BigEndian.PutUint16(pkt[0:2], 5)
	binary.BigEndian.PutUint16(pkt[2:4], 1)
	r := pkt[24:]
	copy(r[0:4], []byte{10, 0, 0, 1})
	copy(r[4:8], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint32(r[16:20], 7)
	binary.BigEndian.PutUint32(r[20:24], 5000)
	binary.BigEndian.PutUint16(r[32:34], 1234)
	binary.BigEndian.PutUint16(r[34:36], 443)
	r[38] = 6

	l := NewFlowListener(0)
	l.Ingest("192.0.2.9", pkt)
	batches := l.Drain(time.Now().Unix() + flowWindowSec + 1)
	if len(batches) != 1 {
		t.Fatalf("one exporter batch expected, got %d", len(batches))
	}
	b := batches[0]
	if b.Exporter != "192.0.2.9" || b.TotalBytes != 5000 || b.TotalFlows != 1 || len(b.Rows) != 1 {
		t.Fatalf("v5 batch wrong: %+v", b)
	}
	row := b.Rows[0]
	if row.Src != "10.0.0.1" || row.Dst != "10.0.0.2" || row.Proto != 6 || row.DstPort != 443 || row.Bytes != 5000 || row.Packets != 7 {
		t.Fatalf("v5 row wrong: %+v", row)
	}
}

func v9Fields() []byte {
	f := make([]byte, 0, 20)
	for _, p := range [][2]uint16{{8, 4}, {12, 4}, {4, 1}, {11, 2}, {1, 4}} {
		b := make([]byte, 4)
		binary.BigEndian.PutUint16(b[0:2], p[0])
		binary.BigEndian.PutUint16(b[2:4], p[1])
		f = append(f, b...)
	}
	return f
}

func flowRecord() []byte {
	rec := make([]byte, 15)
	copy(rec[0:4], []byte{192, 0, 2, 1})
	copy(rec[4:8], []byte{198, 51, 100, 9})
	rec[8] = 17
	binary.BigEndian.PutUint16(rec[9:11], 53)
	binary.BigEndian.PutUint32(rec[11:15], 1500)
	return rec
}

func TestNetflowV9TemplateAndData(t *testing.T) {
	l := NewFlowListener(0)

	tpl := make([]byte, 20+4+4+20)
	binary.BigEndian.PutUint16(tpl[0:2], 9)
	binary.BigEndian.PutUint32(tpl[16:20], 1)
	binary.BigEndian.PutUint16(tpl[20:22], 0)
	binary.BigEndian.PutUint16(tpl[22:24], 28)
	binary.BigEndian.PutUint16(tpl[24:26], 256)
	binary.BigEndian.PutUint16(tpl[26:28], 5)
	copy(tpl[28:], v9Fields())
	l.Ingest("192.0.2.9", tpl)

	data := make([]byte, 20+4+15)
	binary.BigEndian.PutUint16(data[0:2], 9)
	binary.BigEndian.PutUint32(data[16:20], 1)
	binary.BigEndian.PutUint16(data[20:22], 256)
	binary.BigEndian.PutUint16(data[22:24], 19)
	copy(data[24:], flowRecord())
	l.Ingest("192.0.2.9", data)

	batches := l.Drain(time.Now().Unix() + flowWindowSec + 1)
	if len(batches) != 1 || len(batches[0].Rows) != 1 {
		t.Fatalf("v9 data must parse through the template, got %+v", batches)
	}
	row := batches[0].Rows[0]
	if row.Src != "192.0.2.1" || row.Dst != "198.51.100.9" || row.Proto != 17 || row.DstPort != 53 || row.Bytes != 1500 {
		t.Fatalf("v9 row wrong: %+v", row)
	}
}

func TestNetflowIPFIXTemplateAndData(t *testing.T) {
	l := NewFlowListener(0)

	tpl := make([]byte, 16+4+4+20)
	binary.BigEndian.PutUint16(tpl[0:2], 10)
	binary.BigEndian.PutUint32(tpl[12:16], 7)
	binary.BigEndian.PutUint16(tpl[16:18], 2)
	binary.BigEndian.PutUint16(tpl[18:20], 28)
	binary.BigEndian.PutUint16(tpl[20:22], 300)
	binary.BigEndian.PutUint16(tpl[22:24], 5)
	copy(tpl[24:], v9Fields())
	l.Ingest("203.0.113.5", tpl)

	data := make([]byte, 16+4+15)
	binary.BigEndian.PutUint16(data[0:2], 10)
	binary.BigEndian.PutUint32(data[12:16], 7)
	binary.BigEndian.PutUint16(data[16:18], 300)
	binary.BigEndian.PutUint16(data[18:20], 19)
	copy(data[20:], flowRecord())
	l.Ingest("203.0.113.5", data)

	batches := l.Drain(time.Now().Unix() + flowWindowSec + 1)
	if len(batches) != 1 || len(batches[0].Rows) != 1 {
		t.Fatalf("ipfix data must parse through the template, got %+v", batches)
	}
	if batches[0].Rows[0].Bytes != 1500 || batches[0].Rows[0].DstPort != 53 {
		t.Fatalf("ipfix row wrong: %+v", batches[0].Rows[0])
	}
}

func TestNetflowWindowAndAllowFrom(t *testing.T) {
	l := NewFlowListener(0)
	l.Configure([]string{"192.0.2.9"})

	pkt := make([]byte, 24+48)
	binary.BigEndian.PutUint16(pkt[0:2], 5)
	binary.BigEndian.PutUint16(pkt[2:4], 1)
	copy(pkt[24:28], []byte{10, 0, 0, 1})
	binary.BigEndian.PutUint32(pkt[44:48], 100)

	l.Ingest("198.51.100.7", pkt)
	if d, _ := l.Snapshot(); d != 1 {
		t.Fatalf("a stranger exporter must be dropped, dropped=%d", d)
	}
	l.Ingest("192.0.2.9", pkt)
	if got := l.Drain(time.Now().Unix()); got != nil {
		t.Fatalf("a young window must not drain, got %+v", got)
	}
	if got := l.Drain(time.Now().Unix() + flowWindowSec + 1); len(got) != 1 {
		t.Fatalf("the aged window must drain, got %+v", got)
	}
}
