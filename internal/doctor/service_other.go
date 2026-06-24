//go:build !linux && !darwin && !windows

package doctor

func checkService() Check {
	return Check{Name: "service", State: Info, Detail: "service status not available on this platform"}
}

func freeBytes(dir string) int64 { return 0 }
