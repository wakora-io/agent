//go:build !linux

package metrics

import "time"

type ioState struct{}

func (c *Collector) ioPoints(now time.Time) []Point {
	return nil
}

func (c *Collector) cpuPressurePoints(now time.Time) []Point {
	return nil
}
