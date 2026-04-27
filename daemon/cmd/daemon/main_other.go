//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "agent-sandbox-daemon is Linux-only (cgroup v2 + eBPF). Build and run on Ubuntu.")
	os.Exit(1)
}
