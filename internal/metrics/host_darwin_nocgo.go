//go:build darwin && !cgo

package metrics

import "time"

func (c *Collector) cpuPoints() []Point          { return nil }
func (c *Collector) netPoints(time.Time) []Point { return nil }
func vmMemPoints(uint64) []Point                 { return nil }
