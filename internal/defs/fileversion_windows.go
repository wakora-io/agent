//go:build windows

package defs

import (
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

func fileVersion(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return ""
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return ""
	}
	var fixed *windows.VS_FIXEDFILEINFO
	var n uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&fixed), &n); err != nil || fixed == nil || n == 0 {
		return ""
	}
	return strconv.Itoa(int(fixed.FileVersionMS>>16)) + "." + strconv.Itoa(int(fixed.FileVersionMS&0xffff)) + "." + strconv.Itoa(int(fixed.FileVersionLS>>16))
}
