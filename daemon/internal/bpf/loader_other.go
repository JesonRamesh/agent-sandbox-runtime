//go:build !linux

// Mac/Windows stub. The real loader is Linux-only because cilium/ebpf
// won't compile on other platforms. We expose the same surface so
// `go build ./...` works on a developer's Mac.

package bpf

import (
	"context"
	"errors"
	"log/slog"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/policy"
)

const (
	PinRoot       = "/sys/fs/bpf/agent-sandbox"
	DefaultBPFDir = "/usr/lib/agent-sandbox/bpf"
	MaxPolicies   = 32
)

var ErrCapacityExceeded = errors.New("bpf: max concurrent agents reached")

type Runtime struct{}

func LoadRuntime(_ string, _ *slog.Logger) (*Runtime, error) {
	return nil, errors.New("bpf.LoadRuntime: only supported on Linux")
}

func (rt *Runtime) Bind(_ string, _ uint64, _ policy.Compiled) (*Handle, error) {
	return nil, errors.New("bpf.Runtime.Bind: only supported on Linux")
}

func (rt *Runtime) Close() error { return nil }

type Handle struct{}

func (h *Handle) Events(_ context.Context) <-chan Event {
	ch := make(chan Event)
	close(ch)
	return ch
}

func (h *Handle) Cleanup() error  { return nil }
func (h *Handle) CgroupID() uint64 { return 0 }
func (h *Handle) PolicyID() uint32 { return 0 }
