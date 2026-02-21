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

	"golang.org/x/sys/unix"
)

type phpOffsets struct {
	egCurrentExecuteData uint64
	edFunc               uint64
	edPrev               uint64
	funcType             uint64
	funcName             uint64
	funcScope            uint64
	zstrLen              uint64
	zstrVal              uint64
	ceName               uint64
}

var phpOffsetTable = map[string]phpOffsets{
	"8.3": {egCurrentExecuteData: 488, edFunc: 24, edPrev: 48, funcType: 0, funcName: 8, funcScope: 16, zstrLen: 16, zstrVal: 24, ceName: 8},
	"8.2": {egCurrentExecuteData: 488, edFunc: 24, edPrev: 48, funcType: 0, funcName: 8, funcScope: 16, zstrLen: 16, zstrVal: 24, ceName: 8},
}

const maxStackDepth = 256

type PHPSampler struct {
	pid int
	eg  uint64
	off phpOffsets
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
	return &PHPSampler{pid: pid, eg: eg, off: off}, nil
}

func executorGlobalsAddr(pid int, exe string) (uint64, error) {
	f, err := elf.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var stValue uint64
	found := false
	syms, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	for _, list := range [][]elf.Symbol{syms, dyn} {
		for _, s := range list {
			if s.Name == "executor_globals" {
				stValue = s.Value
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return 0, errors.New("executor_globals symbol not found")
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
	base, err := exeBase(pid, exe)
	if err != nil {
		return 0, err
	}
	return base + (stValue - minVaddr), nil
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

func (s *PHPSampler) Sample() ([]string, error) {
	ed, err := s.readPtr(s.eg + s.off.egCurrentExecuteData)
	if err != nil {
		return nil, err
	}
	var frames []string
	for depth := 0; ed != 0 && depth < maxStackDepth; depth++ {
		fn, err := s.readPtr(ed + s.off.edFunc)
		if err != nil {
			break
		}
		if fn != 0 {
			frames = append(frames, s.frameName(fn))
		}
		prev, err := s.readPtr(ed + s.off.edPrev)
		if err != nil {
			break
		}
		ed = prev
	}
	if len(frames) == 0 {
		return nil, nil
	}
	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}
	return frames, nil
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
