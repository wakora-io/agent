//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func loopbackPeerUID(server, client *net.TCPAddr) (uint32, bool) {
	cip, sip := client.IP.To4(), server.IP.To4()
	if cip == nil || sip == nil {
		return 0, false
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, false
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})

	ne := binary.NativeEndian
	req := make([]byte, 72)
	ne.PutUint32(req[0:4], 72)
	ne.PutUint16(req[4:6], 20)
	ne.PutUint16(req[6:8], unix.NLM_F_REQUEST)
	ne.PutUint32(req[8:12], 1)
	req[16] = unix.AF_INET
	req[17] = unix.IPPROTO_TCP
	ne.PutUint32(req[20:24], 0xffffffff)
	binary.BigEndian.PutUint16(req[24:26], uint16(client.Port))
	binary.BigEndian.PutUint16(req[26:28], uint16(server.Port))
	copy(req[28:32], cip)
	copy(req[44:48], sip)
	ne.PutUint32(req[64:68], 0xffffffff)
	ne.PutUint32(req[68:72], 0xffffffff)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, false
	}
	buf := make([]byte, 8192)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil || n < 16 {
		return 0, false
	}
	return parseInetDiagUID(buf[:n])
}

func parseInetDiagUID(buf []byte) (uint32, bool) {
	ne := binary.NativeEndian
	if len(buf) < 16 {
		return 0, false
	}
	msgLen := int(ne.Uint32(buf[0:4]))
	if msgLen < 16 || msgLen > len(buf) || ne.Uint16(buf[4:6]) != 20 {
		return 0, false
	}
	payload := buf[16:msgLen]
	if len(payload) < 72 {
		return 0, false
	}
	return ne.Uint32(payload[64:68]), true
}

func scanOTLPSenders() map[uint32]bool {
	out := map[uint32]bool{0: true}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		fi, err := os.Stat("/proc/" + name)
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || out[st.Uid] {
			continue
		}
		if procEnvironHas(name, "wakora-register", "OTEL_DOTNET_AUTO_HOME") || procMapsHas(name, "opentelemetry") {
			out[st.Uid] = true
		}
	}
	return out
}

func procEnvironHas(pid string, needles ...string) bool {
	data, err := os.ReadFile("/proc/" + pid + "/environ")
	if err != nil {
		return false
	}
	for _, n := range needles {
		if bytes.Contains(data, []byte(n)) {
			return true
		}
	}
	return false
}

func procMapsHas(pid, needle string) bool {
	f, err := os.Open("/proc/" + pid + "/maps")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.Contains(strings.ToLower(sc.Text()), needle) {
			return true
		}
	}
	return false
}
