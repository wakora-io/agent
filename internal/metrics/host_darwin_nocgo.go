//go:build darwin && !cgo

package metrics

import "time"

// Without cgo these mach/route metrics are unavailable; load average + swap cover pressure.
func (c *Collector) cpuPoints() []Point          { return nil }
func (c *Collector) netPoints(time.Time) []Point { return nil }
func vmMemPoints(uint64) []Point                 { return nil }
