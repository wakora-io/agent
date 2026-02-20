//go:build !linux

package apm

import (
	"errors"
	"time"
)

type PortStats struct {
	Count   uint64
	Err5xx  uint64
	Err4xx  uint64
	MaxMs   float64
	P50Ms   float64
	P95Ms   float64
	Elapsed time.Duration
}

type Engine struct{}

func NewEngine() *Engine { return &Engine{} }

func Supported() (bool, string) { return false, "ebpf is linux-only" }

func (e *Engine) Start(ports []int) error { return errors.New("ebpf is linux-only") }

func (e *Engine) Drain() (map[uint16]PortStats, error) { return nil, errors.New("ebpf is linux-only") }

func (e *Engine) Close() {}
