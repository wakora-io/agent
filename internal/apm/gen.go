package apm

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64,arm64 -type http_event httpred bpf/httpred.c -- -Ibpf
