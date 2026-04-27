//go:build linux

// Package bpf is the userspace half of the kernel-level guardrails. The
// kernel side lives in Mehul's `bpf/` (network/file/creds/exec.bpf.c)
// — see daemon/bpf/common.h.reference for the C-side contract this
// package is compiled against.
//
// Architecture:
//
//   - One Runtime per daemon process. LoadRuntime loads and attaches all
//     four .bpf.o objects once at startup, opens a single ringbuf reader
//     on the shared `events` map, and starts a fan-out goroutine that
//     dispatches each kernel event to the right per-agent channel by
//     cgroup_id.
//
//   - Per-agent state is just three things: a free policy_id from a
//     daemon-owned allocator, an entry in the `policies` BPF array map
//     holding the compiled rules, and an entry in the `cgroup_policy`
//     BPF hash map binding the agent's cgroup_id to that policy_id. The
//     LSM hooks in the kernel walk these maps on every syscall to decide
//     allow/deny/audit.
//
//   - A Handle is the per-agent receipt for a Bind() call. Cleanup()
//     reverses the Bind: clears both maps, returns the policy_id to the
//     allocator, and unsubscribes the per-agent event channel from the
//     fan-out.
//
// Pinning: maps are pinned under /sys/fs/bpf/agent-sandbox/, so the
// programs and policy survive a daemon restart. Re-attach on startup is
// not yet wired (see CAVEATS).
package bpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/policy"
)

const (
	// PinRoot is the bpffs directory the daemon owns.
	PinRoot = "/sys/fs/bpf/agent-sandbox"

	// DefaultBPFDir is where the daemon expects the four prebuilt
	// .bpf.o objects. Mehul's `bpf/Makefile` produces them; the
	// install script lands them here.
	DefaultBPFDir = "/usr/lib/agent-sandbox/bpf"

	// MaxPolicies bounds concurrent agents. Mirrors MAX_POLICIES in
	// bpf/common.h.reference. We allocate ids in [1, MaxPolicies] —
	// id 0 is reserved by the kernel side as "unmanaged" (no policy).
	MaxPolicies = 32
)

// objectName → expected ELF on disk. Mehul's Makefile produces these.
var bpfObjects = []string{"network", "file", "creds", "exec"}

// attachKind selects how each program in attachTable gets attached.
type attachKind int

const (
	attachLSM attachKind = iota
	attachTracepointSched
	attachTracepointSyscalls
)

type attachSpec struct {
	coll string
	prog string
	kind attachKind
	// For tracepoints, the (group, name) pair.
	tpGroup string
	tpName  string
}

// attachTable enumerates the eight programs the daemon attaches at
// startup. Names match Mehul's bpf/*.bpf.c SEC()/function names exactly
// — drift here means "program X missing from object" at startup.
var attachTable = []attachSpec{
	{coll: "network", prog: "asb_socket_connect", kind: attachLSM},
	{coll: "network", prog: "asb_sendto", kind: attachTracepointSyscalls, tpGroup: "syscalls", tpName: "sys_enter_sendto"},
	{coll: "file", prog: "asb_file_open", kind: attachLSM},
	{coll: "creds", prog: "asb_setuid", kind: attachLSM},
	{coll: "creds", prog: "asb_setgid", kind: attachLSM},
	{coll: "creds", prog: "asb_capset", kind: attachLSM},
	{coll: "exec", prog: "asb_sched_exec", kind: attachTracepointSched, tpGroup: "sched", tpName: "sched_process_exec"},
	{coll: "exec", prog: "asb_bprm_check", kind: attachLSM},
}

// Runtime owns daemon-wide BPF state. Constructed once in main() and
// shared across all RunAgent requests.
type Runtime struct {
	bpfDir string
	log    *slog.Logger

	colls map[string]*ebpf.Collection
	links []link.Link
	rb    *ringbuf.Reader

	// Shared maps. All four .bpf.o files declare the same `events`,
	// `cgroup_policy`, and `policies` maps with PinByName, so all
	// collections see the same kernel maps after Load.
	events       *ebpf.Map
	cgroupPolicy *ebpf.Map
	policies     *ebpf.Map

	// Allocator + binding bookkeeping. mu guards every field below.
	mu       sync.Mutex
	free     []uint32              // free policy_ids (FIFO)
	chans    map[uint64]chan Event // cgroup_id -> per-agent fan-out channel
	closed   bool
	cancelFn context.CancelFunc
}

// LoadRuntime is called exactly once per daemon startup. It loads each
// .bpf.o object, pins the shared maps, attaches all eight programs,
// opens the ringbuf reader, and starts the fan-out goroutine.
func LoadRuntime(bpfDir string, log *slog.Logger) (*Runtime, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing MEMLOCK rlimit (kernel <5.11 or missing CAP_SYS_RESOURCE?): %w", err)
	}
	if err := os.MkdirAll(PinRoot, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir pin root %s (is bpffs mounted?): %w", PinRoot, err)
	}

	rt := &Runtime{
		bpfDir: bpfDir,
		log:    log,
		colls:  make(map[string]*ebpf.Collection, len(bpfObjects)),
		chans:  make(map[uint64]chan Event),
	}

	// Free-list: ids 1..MaxPolicies, FIFO. id 0 is "unmanaged" per common.h.
	rt.free = make([]uint32, 0, MaxPolicies)
	for i := uint32(1); i <= MaxPolicies; i++ {
		rt.free = append(rt.free, i)
	}

	// Load + open each collection. The first one to declare `events`,
	// `cgroup_policy`, `policies` with PinByName creates the pinned
	// maps; subsequent collections reuse them via the same pin path.
	for _, name := range bpfObjects {
		path := filepath.Join(bpfDir, name+".bpf.o")
		spec, err := ebpf.LoadCollectionSpec(path)
		if err != nil {
			rt.unwindOnError()
			return nil, fmt.Errorf("load %s: %w", path, err)
		}
		for _, m := range []string{"events", "cgroup_policy", "policies"} {
			if ms, ok := spec.Maps[m]; ok {
				ms.Pinning = ebpf.PinByName
			}
		}
		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: PinRoot},
		})
		if err != nil {
			rt.unwindOnError()
			return nil, fmt.Errorf("instantiate %s: %w", name, err)
		}
		rt.colls[name] = coll
		// Resolve shared map handles from whichever collection has them.
		if rt.events == nil {
			rt.events = coll.Maps["events"]
			rt.cgroupPolicy = coll.Maps["cgroup_policy"]
			rt.policies = coll.Maps["policies"]
		}
	}
	if rt.events == nil || rt.cgroupPolicy == nil || rt.policies == nil {
		rt.unwindOnError()
		return nil, errors.New("required shared maps missing from BPF objects (events, cgroup_policy, policies)")
	}

	if err := rt.attachAll(); err != nil {
		rt.unwindOnError()
		return nil, err
	}

	rb, err := ringbuf.NewReader(rt.events)
	if err != nil {
		rt.unwindOnError()
		return nil, fmt.Errorf("open events ringbuf: %w", err)
	}
	rt.rb = rb

	// Fan-out goroutine. Owns the ringbuf reader; dispatches by cgroup_id.
	ctx, cancel := context.WithCancel(context.Background())
	rt.cancelFn = cancel
	go rt.fanOut(ctx)

	log.Info("bpf runtime loaded", "bpf_dir", bpfDir, "pin_root", PinRoot, "max_concurrent_agents", MaxPolicies)
	return rt, nil
}

func (rt *Runtime) attachAll() error {
	for _, s := range attachTable {
		coll, ok := rt.colls[s.coll]
		if !ok {
			return fmt.Errorf("collection %s not loaded", s.coll)
		}
		prog, ok := coll.Programs[s.prog]
		if !ok {
			return fmt.Errorf("program %s/%s missing from object", s.coll, s.prog)
		}
		var l link.Link
		var err error
		switch s.kind {
		case attachLSM:
			l, err = link.AttachLSM(link.LSMOptions{Program: prog})
		case attachTracepointSched, attachTracepointSyscalls:
			l, err = link.Tracepoint(s.tpGroup, s.tpName, prog, nil)
		default:
			return fmt.Errorf("unknown attach kind for %s/%s", s.coll, s.prog)
		}
		if err != nil {
			return fmt.Errorf("attach %s/%s: %w", s.coll, s.prog, err)
		}
		rt.links = append(rt.links, l)
	}
	return nil
}

// unwindOnError closes whatever has been allocated so far. Safe to call
// from any partial-init state.
func (rt *Runtime) unwindOnError() {
	if rt.rb != nil {
		_ = rt.rb.Close()
	}
	for _, l := range rt.links {
		_ = l.Close()
	}
	for _, c := range rt.colls {
		c.Close()
	}
}

// Bind allocates a policy_id, writes the compiled policy and the
// cgroup→policy_id binding into kernel maps, and returns a Handle that
// receives kernel events for this agent's cgroup. Cleanup() on the
// Handle reverses everything.
//
// If MaxPolicies agents are already running, returns ErrCapacityExceeded.
func (rt *Runtime) Bind(agentID string, cgroupID uint64, compiled policy.Compiled) (*Handle, error) {
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return nil, errors.New("bpf runtime is closed")
	}
	if len(rt.free) == 0 {
		rt.mu.Unlock()
		return nil, fmt.Errorf("%w (max %d concurrent agents — bump MAX_POLICIES in common.h)", ErrCapacityExceeded, MaxPolicies)
	}
	id := rt.free[0]
	rt.free = rt.free[1:]
	ch := make(chan Event, 64)
	rt.chans[cgroupID] = ch
	rt.mu.Unlock()

	// Write policy first, binding second. If the binding lands before
	// the policy slot has the right contents, the kernel's first lookup
	// could see a stale (or zero) struct policy.
	if err := rt.policies.Update(id, unsafe.Pointer(&compiled), ebpf.UpdateAny); err != nil {
		rt.releaseSlot(cgroupID, id)
		return nil, fmt.Errorf("write policies[%d]: %w", id, err)
	}
	if err := rt.cgroupPolicy.Update(cgroupID, id, ebpf.UpdateAny); err != nil {
		_ = rt.policies.Delete(id)
		rt.releaseSlot(cgroupID, id)
		return nil, fmt.Errorf("write cgroup_policy[%d→%d]: %w", cgroupID, id, err)
	}

	rt.log.Info("bpf bind", "agent_id", agentID, "cgroup_id", cgroupID, "policy_id", id)
	return &Handle{
		rt:       rt,
		agentID:  agentID,
		cgroupID: cgroupID,
		policyID: id,
		out:      ch,
	}, nil
}

// releaseSlot is the unwind for a partial Bind. Caller holds no lock.
func (rt *Runtime) releaseSlot(cgroupID uint64, id uint32) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if ch, ok := rt.chans[cgroupID]; ok {
		delete(rt.chans, cgroupID)
		close(ch)
	}
	rt.free = append(rt.free, id)
}

// fanOut owns the ringbuf reader. One goroutine for the lifetime of the
// runtime. Decode errors and missing-channel events are logged and the
// loop continues — a single bad record must not stall enforcement.
func (rt *Runtime) fanOut(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = rt.rb.Close()
	}()
	for {
		rec, err := rt.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				rt.closeAllChans()
				return
			}
			rt.log.Warn("ringbuf read", "err", err)
			continue
		}
		ev, err := decode(rec.RawSample)
		if err != nil {
			rt.log.Warn("decode event", "err", err, "len", len(rec.RawSample))
			continue
		}
		rt.mu.Lock()
		ch, ok := rt.chans[ev.CgroupID]
		rt.mu.Unlock()
		if !ok {
			// Event from a cgroup we don't manage. With pol_id=0 the
			// kernel programs early-return without emitting, so this
			// only fires on a Bind/Unbind race or kernel bug.
			continue
		}
		select {
		case ch <- ev:
		case <-ctx.Done():
			return
		default:
			rt.log.Warn("dropping event for slow consumer", "cgroup_id", ev.CgroupID)
		}
	}
}

func (rt *Runtime) closeAllChans() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for cg, ch := range rt.chans {
		close(ch)
		delete(rt.chans, cg)
	}
}

// Close detaches all programs, closes collections, closes the ringbuf,
// and closes all per-agent channels. Safe to call multiple times.
func (rt *Runtime) Close() error {
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return nil
	}
	rt.closed = true
	cancel := rt.cancelFn
	rt.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if rt.rb != nil {
		_ = rt.rb.Close()
	}
	for _, l := range rt.links {
		_ = l.Close()
	}
	for _, c := range rt.colls {
		c.Close()
	}
	return nil
}

// ErrCapacityExceeded is returned by Bind when MaxPolicies agents are
// already bound. Caller (cmd/daemon) should map this to a wire error.
var ErrCapacityExceeded = errors.New("bpf: max concurrent agents reached")

// Handle is the per-agent BPF receipt. The daemon stores it in the
// registry alongside the cgroup, and calls Cleanup when the agent exits.
type Handle struct {
	rt       *Runtime
	agentID  string
	cgroupID uint64
	policyID uint32
	out      chan Event

	cleanupOnce sync.Once
}

// Events returns the per-agent event channel. Closed when Cleanup is
// called or when the runtime shuts down.
func (h *Handle) Events(ctx context.Context) <-chan Event {
	if h == nil {
		ch := make(chan Event)
		close(ch)
		return ch
	}
	out := make(chan Event, 64)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-h.out:
				if !ok {
					return
				}
				ev.AgentID = h.agentID
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// Cleanup unbinds the agent: removes the cgroup_policy entry, clears
// (zeros) the policies slot, returns the policy_id to the allocator,
// and closes the per-agent channel. Idempotent.
func (h *Handle) Cleanup() error {
	if h == nil {
		return nil
	}
	var firstErr error
	h.cleanupOnce.Do(func() {
		// Order: clear cgroup_policy first so no further events fire,
		// then zero the policies slot, then return the id.
		if err := h.rt.cgroupPolicy.Delete(h.cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			firstErr = fmt.Errorf("delete cgroup_policy[%d]: %w", h.cgroupID, err)
		}
		var zero policy.Compiled
		if err := h.rt.policies.Update(h.policyID, unsafe.Pointer(&zero), ebpf.UpdateAny); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("zero policies[%d]: %w", h.policyID, err)
		}
		h.rt.releaseSlot(h.cgroupID, h.policyID)
	})
	return firstErr
}

// CgroupID returns the cgroup id this handle is bound to. Used by the
// daemon for orphan/registry reconciliation.
func (h *Handle) CgroupID() uint64 { return h.cgroupID }

// PolicyID returns the kernel-side policy id allocated to this agent.
func (h *Handle) PolicyID() uint32 { return h.policyID }
