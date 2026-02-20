//go:build windows

package metrics

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatus = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64     = kernel32.NewProc("GetTickCount64")
	procGetSystemTimes     = kernel32.NewProc("GetSystemTimes")
	procGetDiskFreeSpace   = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetLogicalDrives   = kernel32.NewProc("GetLogicalDrives")
	procGetDriveType       = kernel32.NewProc("GetDriveTypeW")

	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIfTable2  = iphlpapi.NewProc("GetIfTable2")
	procFreeMibTable = iphlpapi.NewProc("FreeMibTable")
)

type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

func loadPoints() []Point { return nil }

func memPoints() []Point {
	var m memoryStatusEx
	m.length = uint32(unsafe.Sizeof(m))
	ret, _, _ := procGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&m)))
	if ret == 0 {
		return nil
	}
	pts := []Point{
		{Name: "host.mem.total_kb", Value: float64(m.totalPhys) / 1024},
		{Name: "host.mem.available_kb", Value: float64(m.availPhys) / 1024},
		{Name: "host.mem.used_pct", Value: float64(m.memoryLoad)},
	}
	if m.totalPageFile > 0 {
		usedPage := m.totalPageFile - m.availPageFile
		pts = append(pts, Point{Name: "host.swap.used_pct", Value: float64(usedPage) / float64(m.totalPageFile) * 100})
	}
	return pts
}

func uptimePoints() []Point {
	ret, _, _ := procGetTickCount64.Call()
	if ret == 0 {
		return nil
	}
	return []Point{{Name: "host.uptime_sec", Value: float64(uint64(ret)) / 1000}}
}

func filetimeToUint64(ft windows.Filetime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

func (c *Collector) cpuPoints() []Point {
	var idleFt, kernelFt, userFt windows.Filetime
	ret, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleFt)),
		uintptr(unsafe.Pointer(&kernelFt)),
		uintptr(unsafe.Pointer(&userFt)),
	)
	if ret == 0 {
		return nil
	}
	idle := filetimeToUint64(idleFt)
	total := filetimeToUint64(kernelFt) + filetimeToUint64(userFt)

	prevTotal, prevIdle := c.prevCPUTotal, c.prevCPUIdle
	c.prevCPUTotal, c.prevCPUIdle = total, idle
	if !c.hasPrev {
		return nil
	}
	used, ok := cpuUsedPct(total, idle, prevTotal, prevIdle)
	if !ok {
		return nil
	}
	return []Point{{Name: "host.cpu.used_pct", Value: used}}
}

const driveFixed = 3

func diskPoints() []Point {
	mask, _, _ := procGetLogicalDrives.Call()
	if mask == 0 {
		return nil
	}
	var pts []Point
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + ":\\"
		rootPtr, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		dt, _, _ := procGetDriveType.Call(uintptr(unsafe.Pointer(rootPtr)))
		if dt != driveFixed {
			continue
		}
		var freeAvail, total, totalFree uint64
		ret, _, _ := procGetDiskFreeSpace.Call(
			uintptr(unsafe.Pointer(rootPtr)),
			uintptr(unsafe.Pointer(&freeAvail)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&totalFree)),
		)
		if ret == 0 || total == 0 {
			continue
		}
		used := total - totalFree
		tags := map[string]string{"mount": root}
		pts = append(pts,
			Point{Name: "host.disk.total_bytes", Value: float64(total), Tags: tags},
			Point{Name: "host.disk.used_bytes", Value: float64(used), Tags: tags},
			Point{Name: "host.disk.used_pct", Value: float64(total-freeAvail) / float64(total) * 100, Tags: tags},
		)
	}
	return pts
}

type mibIfRow2 struct {
	interfaceLuid               uint64
	interfaceIndex              uint32
	interfaceGuid               [16]byte
	alias                       [257]uint16
	description                 [257]uint16
	physicalAddressLength       uint32
	physicalAddress             [32]byte
	permanentPhysicalAddress    [32]byte
	mtu                         uint32
	ifType                      uint32
	tunnelType                  uint32
	mediaType                   uint32
	physicalMediumType          uint32
	accessType                  uint32
	directionType               uint32
	interfaceAndOperStatusFlags uint8
	operStatus                  uint32
	adminStatus                 uint32
	mediaConnectState           uint32
	networkGuid                 [16]byte
	connectionType              uint32
	transmitLinkSpeed           uint64
	receiveLinkSpeed            uint64
	inOctets                    uint64
	inUcastPkts                 uint64
	inNUcastPkts                uint64
	inDiscards                  uint64
	inErrors                    uint64
	inUnknownProtos             uint64
	inUcastOctets               uint64
	inMulticastOctets           uint64
	inBroadcastOctets           uint64
	outOctets                   uint64
	outUcastPkts                uint64
	outNUcastPkts               uint64
	outDiscards                 uint64
	outErrors                   uint64
	outUcastOctets              uint64
	outMulticastOctets          uint64
	outBroadcastOctets          uint64
	outQLen                     uint64
}

type mibIfTable2 struct {
	numEntries uint32
	_          [4]byte
	table      [1]mibIfRow2
}

const ifTypeSoftwareLoopback = 24

func (c *Collector) netPoints(now time.Time) []Point {
	var table *mibIfTable2
	ret, _, _ := procGetIfTable2.Call(uintptr(unsafe.Pointer(&table)))
	if ret != 0 || table == nil {
		return nil
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))

	rows := unsafe.Slice(&table.table[0], int(table.numEntries))
	var rx, tx uint64
	for i := range rows {
		r := &rows[i]
		if r.ifType == ifTypeSoftwareLoopback || r.operStatus != 1 {
			continue
		}
		rx += r.inOctets
		tx += r.outOctets
	}

	prevRx, prevTx, prevAt := c.prevNetRx, c.prevNetTx, c.prevNetAt
	c.prevNetRx, c.prevNetTx, c.prevNetAt = rx, tx, now
	if !c.hasPrev || prevAt.IsZero() {
		return nil
	}
	elapsed := now.Sub(prevAt).Seconds()
	if elapsed <= 0 || rx < prevRx || tx < prevTx {
		return nil
	}
	return []Point{
		{Name: "host.net.rx_bytes_per_sec", Value: float64(rx-prevRx) / elapsed},
		{Name: "host.net.tx_bytes_per_sec", Value: float64(tx-prevTx) / elapsed},
	}
}
