//go:build windows

package doctor

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func checkService() Check {
	m, err := mgr.Connect()
	if err != nil {
		return Check{Name: "service", State: Warn, Detail: "cannot query the service manager", Next: "run as Administrator"}
	}
	defer m.Disconnect()
	s, err := m.OpenService("wakora-agent")
	if err != nil {
		return Check{Name: "service", State: Warn, Detail: "service not installed",
			Next: "install and start: wakora service install"}
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return Check{Name: "service", State: Warn, Detail: "cannot read service state"}
	}
	if st.State == svc.Running {
		return Check{Name: "service", State: Ok, Detail: "running (windows service)"}
	}
	return Check{Name: "service", State: Warn, Detail: "installed but not running",
		Next: "start it: wakora service start"}
}

func freeBytes(dir string) int64 {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0
	}
	return int64(free)
}
