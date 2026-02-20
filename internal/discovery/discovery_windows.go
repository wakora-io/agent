//go:build windows

package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func Collect() []Fact {
	var facts []Fact
	facts = append(facts, processes()...)
	facts = append(facts, ports()...)
	facts = append(facts, services()...)
	facts = append(facts, packages()...)
	facts = append(facts, netFacts()...)
	return facts
}

func ChangeSignal() string {
	h := sha256.New()
	for _, f := range services() {
		fmt.Fprintf(h, "%s:%s;", f.Key, f.Payload)
	}
	for _, f := range ports() {
		fmt.Fprintf(h, "%s;", f.Key)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func processes() []Fact {
	agg := map[string]*procInfo{}
	for pid, name := range pidNames() {
		if p := agg[name]; p != nil {
			p.Count++
		} else {
			agg[name] = &procInfo{Count: 1, Pid: pid}
		}
	}
	return sortedFacts("process", agg)
}

func pidNames() map[int]string {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)

	out := map[int]string{}
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil
	}
	for {
		name := strings.TrimSuffix(windows.UTF16ToString(entry.ExeFile[:]), ".exe")
		if name != "" {
			out[int(entry.ProcessID)] = name
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return out
}

type portInfo struct {
	Addr    string `json:"addr,omitempty"`
	Pid     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPidListener = 3
	udpTableOwnerPid         = 1
)

type mibTCPRowOwnerPid struct {
	state      uint32
	localAddr  [4]byte
	localPort  [4]byte
	remoteAddr [4]byte
	remotePort [4]byte
	owningPid  uint32
}

type mibTCP6RowOwnerPid struct {
	localAddr     [16]byte
	localScopeID  uint32
	localPort     [4]byte
	remoteAddr    [16]byte
	remoteScopeID uint32
	remotePort    [4]byte
	state         uint32
	owningPid     uint32
}

type mibUDPRowOwnerPid struct {
	localAddr [4]byte
	localPort [4]byte
	owningPid uint32
}

type mibUDP6RowOwnerPid struct {
	localAddr    [16]byte
	localScopeID uint32
	localPort    [4]byte
	owningPid    uint32
}

func extendedTable(proc *windows.LazyProc, af, class uint32) []byte {
	var size uint32
	proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(class), 0)
	for i := 0; i < 4; i++ {
		if size == 0 {
			return nil
		}
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(class), 0)
		if r == 0 {
			return buf
		}
		if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil
		}
	}
	return nil
}

func netPort(b [4]byte) int {
	return int(b[0])<<8 | int(b[1])
}

func ports() []Fact {
	names := pidNames()
	agg := map[string]*portInfo{}
	add := func(proto string, port int, addr string, pid uint32) {
		if port == 0 {
			return
		}
		key := fmt.Sprintf("%d/%s", port, proto)
		if agg[key] != nil {
			return
		}
		agg[key] = &portInfo{Addr: addr, Pid: int(pid), Process: names[int(pid)]}
	}
	if buf := extendedTable(procGetExtendedTCPTable, windows.AF_INET, tcpTableOwnerPidListener); len(buf) >= 4 {
		n := int(*(*uint32)(unsafe.Pointer(&buf[0])))
		rowSize := int(unsafe.Sizeof(mibTCPRowOwnerPid{}))
		for i := 0; i < n && 4+(i+1)*rowSize <= len(buf); i++ {
			row := (*mibTCPRowOwnerPid)(unsafe.Pointer(&buf[4+i*rowSize]))
			add("tcp", netPort(row.localPort), net.IP(row.localAddr[:]).String(), row.owningPid)
		}
	}
	if buf := extendedTable(procGetExtendedTCPTable, windows.AF_INET6, tcpTableOwnerPidListener); len(buf) >= 4 {
		n := int(*(*uint32)(unsafe.Pointer(&buf[0])))
		rowSize := int(unsafe.Sizeof(mibTCP6RowOwnerPid{}))
		for i := 0; i < n && 4+(i+1)*rowSize <= len(buf); i++ {
			row := (*mibTCP6RowOwnerPid)(unsafe.Pointer(&buf[4+i*rowSize]))
			add("tcp", netPort(row.localPort), net.IP(row.localAddr[:]).String(), row.owningPid)
		}
	}
	if buf := extendedTable(procGetExtendedUDPTable, windows.AF_INET, udpTableOwnerPid); len(buf) >= 4 {
		n := int(*(*uint32)(unsafe.Pointer(&buf[0])))
		rowSize := int(unsafe.Sizeof(mibUDPRowOwnerPid{}))
		for i := 0; i < n && 4+(i+1)*rowSize <= len(buf); i++ {
			row := (*mibUDPRowOwnerPid)(unsafe.Pointer(&buf[4+i*rowSize]))
			add("udp", netPort(row.localPort), net.IP(row.localAddr[:]).String(), row.owningPid)
		}
	}
	if buf := extendedTable(procGetExtendedUDPTable, windows.AF_INET6, udpTableOwnerPid); len(buf) >= 4 {
		n := int(*(*uint32)(unsafe.Pointer(&buf[0])))
		rowSize := int(unsafe.Sizeof(mibUDP6RowOwnerPid{}))
		for i := 0; i < n && 4+(i+1)*rowSize <= len(buf); i++ {
			row := (*mibUDP6RowOwnerPid)(unsafe.Pointer(&buf[4+i*rowSize]))
			add("udp", netPort(row.localPort), net.IP(row.localAddr[:]).String(), row.owningPid)
		}
	}
	return sortedFacts("port", agg)
}

func services() []Fact {
	m, err := mgr.Connect()
	if err != nil {
		return nil
	}
	defer m.Disconnect()

	names, err := m.ListServices()
	if err != nil {
		return nil
	}
	agg := map[string]*unitInfo{}
	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		st, err := s.Query()
		if err != nil {
			s.Close()
			continue
		}
		startType := ""
		if cfg, err := s.Config(); err == nil {
			startType = startTypeName(cfg.StartType)
		}
		s.Close()
		agg[name] = &unitInfo{State: svcStateName(st.State), StartType: startType}
	}
	return sortedFacts("unit", agg)
}

type unitInfo struct {
	State     string `json:"state,omitempty"`
	StartType string `json:"startType,omitempty"`
}

func startTypeName(t uint32) string {
	switch t {
	case mgr.StartAutomatic:
		return "auto"
	case mgr.StartManual:
		return "manual"
	case mgr.StartDisabled:
		return "disabled"
	default:
		return "other"
	}
}

func svcStateName(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.Running:
		return "running"
	case svc.Paused:
		return "paused"
	default:
		return "pending"
	}
}

func packages() []Fact {
	agg := map[string]*packageInfo{}
	roots := []struct {
		key  registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	for _, r := range roots {
		k, err := registry.OpenKey(r.key, r.path, registry.READ)
		if err != nil {
			continue
		}
		subs, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}
		for _, sub := range subs {
			sk, err := registry.OpenKey(r.key, r.path+`\`+sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			version, _, _ := sk.GetStringValue("DisplayVersion")
			systemComp, _, _ := sk.GetIntegerValue("SystemComponent")
			sk.Close()
			name = strings.Trim(name, "\" ")
			if name == "" || systemComp == 1 || agg[name] != nil {
				continue
			}
			agg[name] = &packageInfo{Version: version}
		}
	}
	return sortedFacts("package", agg)
}
