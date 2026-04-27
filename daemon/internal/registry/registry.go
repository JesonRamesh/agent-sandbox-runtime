// Package registry holds in-memory state for all running and recently-exited
// agents. Brief §6 Phase 3 task 2 + §7 concurrency rules.
//
// Why a registry and not a map in main: the daemon needs to atomically add,
// look up, list, and reap agents from multiple goroutines (IPC handlers,
// cmd.Wait watchers, the periodic reaper). Centralizing the locking discipline
// here keeps it impossible for a caller to forget to take the lock or to hold
// it across I/O.
//
// Locking discipline (brief §7): one RWMutex per data structure.
// Registry.mu protects the agents map. Agent.mu protects the mutable
// status/exit fields on a single Agent. Public methods take the lock briefly
// and never hold it across I/O. List() copies pointer slices under the lock
// so iteration happens lock-free; per-Agent reads still take Agent.mu, which
// is fine because that lock is never held across syscalls or sends.
package registry

import (
	"fmt"
	"sync"
	"time"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/ipc"
)

// Status is the lifecycle state of an Agent. It is intentionally an int with
// a String() — the wire format (api/proto.md) uses lowercase strings, so we
// keep that conversion in one place rather than scattering string literals.
type Status int

const (
	StatusRunning Status = iota
	StatusExited
	StatusCrashed
)

// String matches the api/proto.md status vocabulary verbatim. Renaming any
// of these is a wire-breaking change — Phase 2's main_linux.go already emits
// these literals, so the registry has to agree.
func (s Status) String() string {
	switch s {
	case StatusRunning:
		return "running"
	case StatusExited:
		return "exited"
	case StatusCrashed:
		return "crashed"
	default:
		return "unknown"
	}
}

// Agent is everything the registry tracks for one sandboxed process.
//
// The kernel-side handles (cgroup, BPF objects, links, *exec.Cmd) deliberately
// do not appear as typed fields here — importing internal/cgroup or
// internal/bpf would create an import cycle once the daemon wires registry
// into its lifecycle code, and would also drag Linux-only types into a
// cross-platform package. Resources is `any` so the daemon can stash a
// *daemon.agentResources (or whatever shape it picks) without leaking that
// shape into the registry's API surface.
type Agent struct {
	ID         string
	Name       string
	Manifest   ipc.Manifest
	PID        int
	StartedAt  time.Time
	CgroupID   uint64
	CgroupPath string

	// Resources is opaque to the registry. The daemon owns its lifecycle —
	// the registry never inspects, closes, or copies it.
	Resources any

	// mu guards the fields below. Public methods take it briefly. Never held
	// across I/O. Field order: lock immediately above the fields it guards
	// (Go convention) so reviewers can spot un-locked access.
	mu       sync.Mutex
	status   Status
	exitCode int
	exitedAt time.Time
}

// Status returns the agent's current lifecycle state.
func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

// ExitCode returns the recorded exit code. Zero is meaningful when status is
// StatusExited; for a still-running agent the value is undefined and the
// caller should check Status() first.
func (a *Agent) ExitCode() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.exitCode
}

// MarkExited records a clean exit. Idempotent in the sense that calling it
// twice just overwrites the timestamp — the daemon should not, but if a
// crash watcher and a stop handler race, the last-writer-wins behaviour is
// acceptable because both paths agree the process is gone.
func (a *Agent) MarkExited(code int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status = StatusExited
	a.exitCode = code
	a.exitedAt = time.Now()
}

// MarkCrashed records an unclean exit. Brief §6 Phase 3 task 8 keeps crashed
// agents in the registry for --keep-crashed=60s so an operator can inspect
// them — Reap() honors that retention.
func (a *Agent) MarkCrashed(code int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status = StatusCrashed
	a.exitCode = code
	a.exitedAt = time.Now()
}

// ExitedAt returns the recorded exit time. The bool is false while the agent
// is still running so callers can distinguish "exited at the zero value"
// (impossible — clock is monotonic-ish) from "not exited yet".
func (a *Agent) ExitedAt() (time.Time, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.status == StatusRunning {
		return time.Time{}, false
	}
	return a.exitedAt, true
}

// Snapshot returns an ipc.AgentSummary suitable for JSON encoding by a caller
// that holds no locks. Returning a value (not a pointer) means the caller
// can serialize it without worrying about a concurrent MarkExited mutating
// the status string mid-marshal.
func (a *Agent) Snapshot() ipc.AgentSummary {
	a.mu.Lock()
	status := a.status.String()
	a.mu.Unlock()
	return ipc.AgentSummary{
		AgentID:   a.ID,
		Name:      a.Name,
		Status:    status,
		StartedAt: a.StartedAt,
		PID:       a.PID,
	}
}

// Registry is the daemon-wide map of agents.
type Registry struct {
	mu     sync.RWMutex
	agents map[string]*Agent
}

// New constructs an empty Registry.
func New() *Registry {
	return &Registry{agents: make(map[string]*Agent)}
}

// Add inserts a. Returns an error if an agent with the same ID is already
// present — collisions indicate a bug in the ID generator (crypto/rand
// exhaustion, clock fallback collision) and we'd rather surface it than
// silently clobber existing state.
func (r *Registry) Add(a *Agent) error {
	if a == nil {
		return fmt.Errorf("registry: cannot add nil agent")
	}
	if a.ID == "" {
		return fmt.Errorf("registry: agent ID is empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.agents[a.ID]; exists {
		return fmt.Errorf("registry: agent %q already exists", a.ID)
	}
	// Initialize status under Agent.mu so a concurrent Snapshot can't observe
	// the zero value mid-Add. Cheap because no other goroutine has a pointer
	// to a yet.
	a.mu.Lock()
	if a.status == 0 && a.exitedAt.IsZero() {
		a.status = StatusRunning
	}
	a.mu.Unlock()
	r.agents[a.ID] = a
	return nil
}

// Get returns the agent for id and whether it was found.
func (r *Registry) Get(id string) (*Agent, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.agents[id]
	return a, ok
}

// Remove deletes id from the registry and returns the removed agent. The
// caller is responsible for cleaning up the agent's resources (cgroup, BPF
// links, log files) — the registry has no Close hook because Resources is
// opaque to it.
func (r *Registry) Remove(id string) (*Agent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[id]
	if !ok {
		return nil, false
	}
	delete(r.agents, id)
	return a, true
}

// List returns a snapshot of the current agent pointers. The returned slice
// is owned by the caller and the registry's internal map is not aliased —
// the caller can iterate without holding r.mu, which is the whole point.
func (r *Registry) List() []*Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Agent, 0, len(r.agents))
	for _, a := range r.agents {
		out = append(out, a)
	}
	return out
}

// Summaries returns ipc.AgentSummary values for every agent. Each summary is
// taken via Agent.Snapshot, so callers can JSON-encode the result without
// any further locking — see api/proto.md ListAgents.
func (r *Registry) Summaries() []ipc.AgentSummary {
	agents := r.List()
	out := make([]ipc.AgentSummary, 0, len(agents))
	for _, a := range agents {
		out = append(out, a.Snapshot())
	}
	return out
}

// Reap removes agents whose status is Exited or Crashed AND whose exitedAt
// is older than retention. Returns the IDs removed so the caller can log
// or fan out further cleanup. Brief §6 Phase 3 task 8 documents the
// keep-crashed window — the daemon calls Reap on a ticker.
//
// We snapshot candidate IDs under the read lock, then take the write lock
// only for the deletes. This avoids holding the write lock across the
// per-agent status check, which itself takes Agent.mu — nesting Registry.mu
// (write) over Agent.mu would be fine in isolation but is a footgun for
// future code that might want to take them in the other order.
func (r *Registry) Reap(retention time.Duration) []string {
	cutoff := time.Now().Add(-retention)

	r.mu.RLock()
	candidates := make([]*Agent, 0, len(r.agents))
	for _, a := range r.agents {
		candidates = append(candidates, a)
	}
	r.mu.RUnlock()

	toRemove := make([]string, 0)
	for _, a := range candidates {
		a.mu.Lock()
		expired := a.status != StatusRunning && !a.exitedAt.IsZero() && a.exitedAt.Before(cutoff)
		a.mu.Unlock()
		if expired {
			toRemove = append(toRemove, a.ID)
		}
	}

	if len(toRemove) == 0 {
		return nil
	}

	removed := make([]string, 0, len(toRemove))
	r.mu.Lock()
	for _, id := range toRemove {
		// Re-check existence under the write lock — a concurrent Remove may
		// have beaten us here, in which case we must not double-report it.
		if _, ok := r.agents[id]; ok {
			delete(r.agents, id)
			removed = append(removed, id)
		}
	}
	r.mu.Unlock()
	return removed
}
