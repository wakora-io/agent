//go:build linux

package apm

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type phpOffsets struct {
	egCurrentExecuteData uint64
	edFunc               uint64
	edPrev               uint64
	funcType             uint64
	funcName             uint64
	funcScope            uint64
	funcFilename         uint64
	zstrLen              uint64
	zstrVal              uint64
	ceName               uint64
}

var phpOffsetTable = map[string]phpOffsets{
	"8.4": {egCurrentExecuteData: 488, edFunc: 24, edPrev: 48, funcType: 0, funcName: 8, funcScope: 16, funcFilename: 168, zstrLen: 16, zstrVal: 24, ceName: 8},
	"8.3": {egCurrentExecuteData: 488, edFunc: 24, edPrev: 48, funcType: 0, funcName: 8, funcScope: 16, funcFilename: 144, zstrLen: 16, zstrVal: 24, ceName: 8},
	"8.2": {egCurrentExecuteData: 488, edFunc: 24, edPrev: 48, funcType: 0, funcName: 8, funcScope: 16, funcFilename: 152, zstrLen: 16, zstrVal: 24, ceName: 8},
	"8.1": {egCurrentExecuteData: 488, edFunc: 24, edPrev: 48, funcType: 0, funcName: 8, funcScope: 16, funcFilename: 144, zstrLen: 16, zstrVal: 24, ceName: 8},
	"8.0": {egCurrentExecuteData: 488, edFunc: 24, edPrev: 48, funcType: 0, funcName: 8, funcScope: 16, funcFilename: 144, zstrLen: 16, zstrVal: 24, ceName: 8},
	"7.4": {egCurrentExecuteData: 488, edFunc: 24, edPrev: 48, funcType: 0, funcName: 8, funcScope: 16, funcFilename: 136, zstrLen: 16, zstrVal: 24, ceName: 8},
	"7.3": {egCurrentExecuteData: 488, edFunc: 24, edPrev: 48, funcType: 0, funcName: 8, funcScope: 16, funcFilename: 128, zstrLen: 16, zstrVal: 24, ceName: 8},
	"7.2": {egCurrentExecuteData: 480, edFunc: 24, edPrev: 48, funcType: 0, funcName: 8, funcScope: 16, funcFilename: 120, zstrLen: 16, zstrVal: 24, ceName: 8},
}

const (
	maxStackDepth   = 256
	zendUserFuncTag = 2
	ownerCacheCap   = 4096
)

type PHPSampler struct {
	pid    int
	eg     uint64
	off    phpOffsets
	owners map[uint64]string
}

func ProfileSupported() (bool, string) {
	if os.Geteuid() == 0 {
		return true, ""
	}
	data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err == nil && strings.TrimSpace(string(data)) == "0" {
		return true, ""
	}
	return false, "process_vm_readv needs root or CAP_SYS_PTRACE (ptrace_scope != 0)"
}

func NewPHPSampler(pid int, versionShort string) (*PHPSampler, error) {
	off, ok := phpOffsetTable[versionShort]
	if !ok {
		return nil, fmt.Errorf("no offset table for php %s", versionShort)
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, err
	}
	eg, err := executorGlobalsAddr(pid, exe)
	if err != nil {
		return nil, err
	}
	return &PHPSampler{pid: pid, eg: eg, off: off, owners: map[uint64]string{}}, nil
}

type egSym struct {
	stValue  uint64
	minVaddr uint64
	ok       bool
}

var (
	egSymMu    sync.Mutex
	egSymCache = map[string]egSym{}
)

func executorGlobalsAddr(pid int, exe string) (uint64, error) {
	procExe := fmt.Sprintf("/proc/%d/exe", pid)
	key := exe
	if st, err := os.Stat(procExe); err == nil {
		key = fmt.Sprintf("%s|%d|%d", exe, st.Size(), st.ModTime().UnixNano())
	}
	egSymMu.Lock()
	c, hit := egSymCache[key]
	egSymMu.Unlock()
	if !hit {
		c = readEGSym(procExe)
		egSymMu.Lock()
		if len(egSymCache) > 64 {
			egSymCache = map[string]egSym{}
		}
		egSymCache[key] = c
		egSymMu.Unlock()
	}
	if !c.ok {
		return 0, errors.New("executor_globals symbol not found")
	}
	base, err := exeBase(pid, exe)
	if err != nil {
		return 0, err
	}
	return base + (c.stValue - c.minVaddr), nil
}

func readEGSym(procExe string) egSym {
	f, err := elf.Open(procExe)
	if err != nil {
		return egSym{}
	}
	defer f.Close()

	var out egSym
	syms, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	for _, list := range [][]elf.Symbol{syms, dyn} {
		for _, s := range list {
			if s.Name == "executor_globals" {
				out.stValue = s.Value
				out.ok = true
				break
			}
		}
		if out.ok {
			break
		}
	}
	if !out.ok {
		return egSym{}
	}

	var minVaddr uint64 = ^uint64(0)
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Vaddr < minVaddr {
			minVaddr = p.Vaddr
		}
	}
	if minVaddr == ^uint64(0) {
		minVaddr = 0
	}
	out.minVaddr = minVaddr
	return out
}

func exeBase(pid int, exe string) (uint64, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasSuffix(line, exe) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[4] == "0" {
			continue
		}
		if fields[2] != "00000000" {
			continue
		}
		dash := strings.IndexByte(fields[0], '-')
		if dash < 0 {
			continue
		}
		return strconv.ParseUint(fields[0][:dash], 16, 64)
	}
	return 0, errors.New("exe base mapping not found")
}

func (s *PHPSampler) readMem(addr uint64, buf []byte) error {
	local := []unix.Iovec{{Base: &buf[0]}}
	local[0].SetLen(len(buf))
	remote := []unix.RemoteIovec{{Base: uintptr(addr), Len: len(buf)}}
	n, err := unix.ProcessVMReadv(s.pid, local, remote, 0)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return errors.New("short read")
	}
	return nil
}

func (s *PHPSampler) readPtr(addr uint64) (uint64, error) {
	var b [8]byte
	if err := s.readMem(addr, b[:]); err != nil {
		return 0, err
	}
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56, nil
}

func (s *PHPSampler) readZendString(addr uint64) string {
	if addr == 0 {
		return ""
	}
	var lb [8]byte
	if err := s.readMem(addr+s.off.zstrLen, lb[:]); err != nil {
		return ""
	}
	n := uint64(lb[0]) | uint64(lb[1])<<8 | uint64(lb[2])<<16 | uint64(lb[3])<<24
	if n == 0 || n > 512 {
		if n > 512 {
			n = 512
		} else {
			return ""
		}
	}
	buf := make([]byte, n)
	if err := s.readMem(addr+s.off.zstrVal, buf); err != nil {
		return ""
	}
	if !printableName(buf) {
		return ""
	}
	return string(buf)
}

func printableName(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func (s *PHPSampler) Sample() ([]string, string, error) {
	ed, err := s.readPtr(s.eg + s.off.egCurrentExecuteData)
	if err != nil {
		return nil, "", err
	}
	var frames []string
	firstUser, firstOwned := "", ""
	for depth := 0; ed != 0 && depth < maxStackDepth; depth++ {
		fn, err := s.readPtr(ed + s.off.edFunc)
		if err != nil {
			break
		}
		if fn != 0 {
			frames = append(frames, s.frameName(fn))
			if firstOwned == "" {
				if o := s.frameOwner(fn); o != "" {
					if firstUser == "" {
						firstUser = o
					}
					if OwnedFrame(o) {
						firstOwned = o
					}
				}
			}
		}
		prev, err := s.readPtr(ed + s.off.edPrev)
		if err != nil {
			break
		}
		ed = prev
	}
	if len(frames) == 0 {
		return nil, "", nil
	}
	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}
	owner := firstOwned
	if owner == "" {
		owner = firstUser
	}
	return frames, owner, nil
}

func OwnedFrame(owner string) bool {
	return strings.HasPrefix(owner, "plugin:") || strings.HasPrefix(owner, "theme:") ||
		strings.HasPrefix(owner, "mu-plugin:")
}

func (s *PHPSampler) frameName(fn uint64) string {
	namePtr, _ := s.readPtr(fn + s.off.funcName)
	name := s.readZendString(namePtr)
	if name == "" {
		name = "{main}"
	}
	scopePtr, _ := s.readPtr(fn + s.off.funcScope)
	if scopePtr != 0 {
		ceNamePtr, _ := s.readPtr(scopePtr + s.off.ceName)
		if cls := s.readZendString(ceNamePtr); cls != "" {
			return cls + "::" + name
		}
	}
	return name
}

func (s *PHPSampler) frameOwner(fn uint64) string {
	var tb [1]byte
	if err := s.readMem(fn+s.off.funcType, tb[:]); err != nil || tb[0] != zendUserFuncTag {
		return ""
	}
	filePtr, err := s.readPtr(fn + s.off.funcFilename)
	if err != nil || filePtr == 0 {
		return ""
	}
	if owner, ok := s.owners[filePtr]; ok {
		return owner
	}
	owner := ClassifyWPPath(s.readZendPath(filePtr))
	if len(s.owners) < ownerCacheCap {
		s.owners[filePtr] = owner
	}
	return owner
}

func (s *PHPSampler) readZendPath(addr uint64) string {
	var lb [8]byte
	if err := s.readMem(addr+s.off.zstrLen, lb[:]); err != nil {
		return ""
	}
	n := uint64(lb[0]) | uint64(lb[1])<<8 | uint64(lb[2])<<16 | uint64(lb[3])<<24
	if n == 0 || n > 4096 {
		return ""
	}
	buf := make([]byte, n)
	if err := s.readMem(addr+s.off.zstrVal, buf); err != nil {
		return ""
	}
	for _, c := range buf {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return string(buf)
}

func ClassifyWPPath(path string) string {
	if path == "" {
		return ""
	}
	for _, kind := range []string{"plugins", "themes", "mu-plugins"} {
		marker := "/wp-content/" + kind + "/"
		i := strings.Index(path, marker)
		if i < 0 {
			continue
		}
		rest := path[i+len(marker):]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			rest = rest[:j]
		}
		rest = strings.TrimSuffix(rest, ".php")
		if rest == "" {
			continue
		}
		label := "plugin"
		if kind == "themes" {
			label = "theme"
		} else if kind == "mu-plugins" {
			label = "mu-plugin"
		}
		return label + ":" + rest
	}
	if strings.Contains(path, "/wp-includes/") || strings.Contains(path, "/wp-admin/") ||
		strings.HasSuffix(path, "/wp-load.php") || strings.HasSuffix(path, "/wp-settings.php") ||
		strings.HasSuffix(path, "/wp-config.php") || strings.HasSuffix(path, "/index.php") ||
		strings.HasSuffix(path, "/wp-blog-header.php") {
		return "wp-core"
	}
	return "app"
}
