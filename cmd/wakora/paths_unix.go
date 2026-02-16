//go:build !windows

package main

const (
	defaultConfigDir = "/etc/wakora"
	defaultLogFile   = "/var/log/wakora/agent.log"
)
