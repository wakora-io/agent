//go:build !linux

package apm

import "errors"

type PHPSampler struct{}

func NewPHPSampler(pid int, versionShort string) (*PHPSampler, error) {
	return nil, errors.New("php stack sampling is linux-only")
}

func (s *PHPSampler) Sample() ([]string, error) { return nil, errors.New("linux-only") }

func ProfileSupported() (bool, string) { return false, "php profiling is linux-only" }
