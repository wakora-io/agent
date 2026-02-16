//go:build windows

package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	return hex.EncodeToString(h.Sum(nil))
}

func processes() []Fact {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)

	agg := map[string]*procInfo{}
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil
	}
	for {
		name := strings.TrimSuffix(windows.UTF16ToString(entry.ExeFile[:]), ".exe")
		if name != "" {
			if p := agg[name]; p != nil {
				p.Count++
			} else {
				agg[name] = &procInfo{Count: 1, Pid: int(entry.ProcessID)}
			}
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return sortedFacts("process", agg)
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
