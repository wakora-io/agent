//go:build !linux && !windows

package metrics

import "time"

func (c *Collector) topPoints(now time.Time) []Point {
	return nil
}
