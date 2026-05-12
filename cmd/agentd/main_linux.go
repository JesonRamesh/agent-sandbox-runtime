//go:build linux

// agent-sandbox-daemon: Phase 3 multi-agent, manifest-driven, restart-safe.
//
// Each RunAgent request creates a per-agent cgroup, compiles the manifest
// allow-list into BPF map entries, loads connect4+connect6 programs into
// the cgroup with default-deny enforcement, and launches the agent inside
// via cgroup-aware fork. Events are fanned out to slog, per-agent log
// files, and a localhost WebSocket. Crashed agents are kept around for
// `--keep-crashed` before cleanup so an operator can post-mortem.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/agent-sandbox/runtime/internal/bpf"
	"github.com/agent-sandbox/runtime/internal/cgroup"
	"github.com/agent-sandbox/runtime/internal/events"
	"github.com/agent-sandbox/runtime/internal/ipc"
	"github.com/agent-sandbox/runtime/internal/policy"
	"github.com/agent-sandbox/runtime/internal/registry"
)

const daemonVersion = "0.1.0-phase3"
const maxAgentOutputChunkBytes = 8 * 1024

func main() {
	socketPath := flag.String("socket", ipc.DefaultSocketPath, "Unix socket path")
	logJSON := flag.Bool("log-json", false, "use JSON log handler instead of text")
	logDir := flag.String("log-dir", "/var/log/agent-sandbox", "per-agent log file directory")
	wsAddr := flag.String("ws-addr", "127.0.0.1:7443", "WebSocket bind address (must be loopback)")
	keepCrashed := flag.Duration("keep-crashed", 60*time.Second, "how long to retain crashed agents before cleanup")
	bpfDir := flag.String("bpf-dir", bpf.DefaultBPFDir, "directory containing prebuilt .bpf.o objects (network/file/creds/exec) — produced by Mehul's bpf/Makefile")
	flag.Parse()

	// We deliberately don't gate on euid==0. The systemd unit runs us as
	// the unprivileged `agent-sandbox` user with ambient capabilities
	// (CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_SYS_RESOURCE) — see
	// deploy/systemd/agent-sandbox.service. If those caps are missing,
	// the cgroup/BPF syscalls below fail with descriptive errors, which
	// is more informative than a euid check.

	var handler slog.Handler
	if *logJSON {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		handler = slog.NewTextHandler(os.Stderr, nil)
	}
	log := slog.New(handler)

	pipeline, err := events.NewPipeline(events.Config{LogDir: *logDir}, log)
	if err != nil {
		log.Error("events pipeline init", "err", err, "fix", "ensure --log-dir is writable")
		os.Exit(1)
	}

	// Load the daemon-wide BPF runtime once. Each subsequent RunAgent
	// call binds a per-agent policy_id into the shared maps; events
	// from all agents come in through one ringbuf and the runtime
	// fans them out to per-agent channels.
	bpfRuntime, err := bpf.LoadRuntime(*bpfDir, log)
	if err != nil {
		log.Error("bpf runtime load", "err", err, "bpf_dir", *bpfDir,
			"fix", "ensure the four .bpf.o files are at --bpf-dir, bpffs is mounted at /sys/fs/bpf, and the kernel cmdline contains lsm=...,bpf")
		os.Exit(1)
	}

	d := &daemon{
		startedAt:   time.Now(),
		log:         log,
		registry:    registry.New(),
		pipeline:    pipeline,
		bpfRuntime:  bpfRuntime,
		keepCrashed: *keepCrashed,
	}

	// Best-effort restart reconciliation: surface orphaned cgroups from a
	// prior daemon. v0.1 doesn't re-attach to them — see CAVEATS.
	d.reconcileStartup()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go pipeline.Run(ctx)

	wsServer := events.NewWSServer(*wsAddr, pipeline, log)
	if err := wsServer.Start(); err != nil {
		log.Error("websocket start", "err", err, "fix", "ensure --ws-addr is loopback (127.0.0.1 or ::1) and the port is free")
		os.Exit(1)
	}

	srv := ipc.NewServer(*socketPath, d, log)
	if err := srv.Start(); err != nil {
		log.Error("ipc server start", "err", err, "fix", "remove a stale socket file or ensure /run exists with the right permissions")
		os.Exit(1)
	}
	log.Info("daemon listening", "socket", *socketPath, "ws", *wsAddr, "version", daemonVersion)

	go d.reapLoop(ctx)

	if err := srv.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("ipc serve", "err", err)
	}

	log.Info("shutting down")
	d.shutdown()
	if err := srv.Stop(); err != nil {
		log.Error("ipc stop", "err", err)
	}
	if err := wsServer.Stop(context.Background()); err != nil {
		log.Error("websocket stop", "err", err)
	}
	if err := bpfRuntime.Close(); err != nil {
		log.Error("bpf runtime close", "err", err)
	}
	if err := pipeline.Close(); err != nil {
		log.Error("pipeline close", "err", err)
	}
}

// agentResources is what the registry stores in Agent.Resources. Defined
// here (not in registry/) so registry doesn't need to know about cgroup or
// bpf — keeping registry cross-platform.
type agentResources struct {
	cg         *cgroup.Cgroup
	bpfHandle  *bpf.Handle
	cmd        *exec.Cmd
	cancelEvts context.CancelFunc

	// cleanupMu serializes cleanup. Per-step bools below let a transient
	// failure (a flaky cgroup destroy, e.g.) be retried on the next call:
	// a successful step is marked done and skipped; a failed step stays
	// false and is retried. This replaces a sync.Once which would have
	// suppressed retries on the very steps that failed — leaving (for
	// example) the BPF map entry behind while the cgroup was already gone.
	cleanupMu     sync.Mutex
	evtsCancelled bool
	bpfFreed      bool
	cgDestroyed   bool

	// done is closed by waitAgent once cmd.Wait returns. Other code paths
	// (e.g. shutdown) wait on this instead of calling cmd.Wait themselves
	// — concurrent Wait calls on *exec.Cmd race on ProcessState and on
	// the underlying wait4(ECHILD) syscall.
	done chan struct{}
}

// cleanup tears down all resources for an agent. Idempotent at the per-step
// level: each component is attempted only if it hasn't yet succeeded. A
// transient failure on cgroup destroy doesn't block the BPF map clear, and
// a subsequent call (from the reaper, shutdown, or a retry path) re-attempts
// only the failed step.
func (r *agentResources) cleanup(log *slog.Logger, agentID string) {
	r.cleanupMu.Lock()
	defer r.cleanupMu.Unlock()

	if !r.evtsCancelled && r.cancelEvts != nil {
		r.cancelEvts()
		r.evtsCancelled = true
	}
	if !r.bpfFreed && r.bpfHandle != nil {
		if err := r.bpfHandle.Cleanup(); err != nil {
			log.Warn("bpf cleanup (will retry)", "agent_id", agentID, "err", err)
		} else {
			r.bpfFreed = true
		}
	} else if r.bpfHandle == nil {
		r.bpfFreed = true
	}
	if !r.cgDestroyed && r.cg != nil {
		if err := r.cg.Destroy(); err != nil {
			log.Warn("cgroup destroy (will retry)", "agent_id", agentID, "err", err, "fix", "manually rmdir /sys/fs/cgroup/agent-sandbox/<id> after killing leftover pids")
		} else {
			r.cgDestroyed = true
		}
	} else if r.cg == nil {
		r.cgDestroyed = true
	}
}

type daemon struct {
	startedAt   time.Time
	log         *slog.Logger
	registry    *registry.Registry
	pipeline    *events.Pipeline
	bpfRuntime  *bpf.Runtime
	keepCrashed time.Duration
}

// agentIDBytes is the entropy width for new agent IDs. 8 bytes pushes the
// 50% birthday-collision threshold to ~5 billion agents — enough that a
// CI/eval host running tens of thousands of agents per day no longer
// approaches collision territory.
const agentIDBytes = 8

func newAgentID() string {
	var b [agentIDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("agt_%x", time.Now().UnixNano())
	}
	return "agt_" + hex.EncodeToString(b[:])
}

func (d *daemon) RunAgent(_ context.Context, m ipc.Manifest) (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}

	compiled, err := policy.Compile(m)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ipc.ErrInvalidManifestErr, err)
	}

	// Generate an ID and pre-check the registry. With 8 bytes of entropy a
	// collision is astronomically unlikely, but if it ever happens (or if
	// crypto/rand fell back to the time-based ID), retry once with fresh
	// bytes before giving up.
	id := newAgentID()
	if _, exists := d.registry.Get(id); exists {
		id = newAgentID()
	}
	log := d.log.With("agent_id", id, "phase", "RunAgent")

	cg, err := cgroup.Create(id)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ipc.ErrCgroupFailedErr, err)
	}

	cgID, err := cg.ID()
	if err != nil {
		_ = cg.Destroy()
		return "", fmt.Errorf("%w: reading cgroup id: %v", ipc.ErrCgroupFailedErr, err)
	}

	bh, err := d.bpfRuntime.Bind(id, cgID, compiled)
	if err != nil {
		_ = cg.Destroy()
		return "", fmt.Errorf("%w: %v", ipc.ErrBPFLoadFailedErr, err)
	}

	cmd := exec.Command(m.Command[0], m.Command[1:]...) //nolint:gosec // operator-supplied command by design
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    cg.FD(),
	}
	cmd.Env = mergeEnv(os.Environ(), m.Env)
	if m.WorkingDir != "" {
		// Make sure the directory exists before exec.Cmd.Start() chdirs into it.
		// Without this, a manifest that supplies (or relies on the CLI's default
		// of) a non-existent path causes clone3 to fail with ENOENT — which Go
		// then renders as "fork/exec <cmd>: no such file or directory", a
		// confusing message that points at the binary, not the cwd.
		if err := os.MkdirAll(m.WorkingDir, 0o755); err != nil {
			_ = bh.Cleanup()
			_ = cg.Destroy()
			return "", fmt.Errorf("%w: create working_dir %q: %v", ipc.ErrLaunchFailedErr, m.WorkingDir, err)
		}
		cmd.Dir = m.WorkingDir
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = bh.Cleanup()
		_ = cg.Destroy()
		return "", fmt.Errorf("%w: capture stdout: %v", ipc.ErrLaunchFailedErr, err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = bh.Cleanup()
		_ = cg.Destroy()
		return "", fmt.Errorf("%w: capture stderr: %v", ipc.ErrLaunchFailedErr, err)
	}

	if err := cmd.Start(); err != nil {
		_ = bh.Cleanup()
		_ = cg.Destroy()
		return "", fmt.Errorf("%w: %v", ipc.ErrLaunchFailedErr, err)
	}

	evtCtx, cancelEvts := context.WithCancel(context.Background())
	res := &agentResources{
		cg:         cg,
		bpfHandle:  bh,
		cmd:        cmd,
		cancelEvts: cancelEvts,
		done:       make(chan struct{}),
	}

	a := &registry.Agent{
		ID:         id,
		Name:       m.Name,
		Manifest:   m,
		PID:        cmd.Process.Pid,
		StartedAt:  time.Now(),
		CgroupID:   cgID,
		CgroupPath: cg.Path(),
		Resources:  res,
	}
	if err := d.registry.Add(a); err != nil {
		// Should never happen — agent IDs are random — but be defensive.
		res.cleanup(d.log, id)
		// No sentinel for INTERNAL — CodeForError catches anything unmapped.
		return "", fmt.Errorf("registry add: %v", err)
	}

	log.Info("agent started",
		"name", m.Name,
		"pid", a.PID,
		"cgroup_id", cgID,
		"policy_id", bh.PolicyID(),
		"hosts", compiled.NHosts,
		"paths", compiled.NPaths,
		"bins", compiled.NBins,
		"mode", compiled.Mode)
	d.emitEvent(id, uint32(a.PID), "agent.started", map[string]any{ //nolint:gosec // Linux PIDs bounded by kernel.pid_max (≤ 2^22)
		"command":     m.Command,
		"cgroup_path": cg.Path(),
		"cgroup_id":   cgID,
		"policy_id":   bh.PolicyID(),
	})

	go d.streamAgentOutput(evtCtx, id, uint32(a.PID), "agent.stdout", stdoutPipe)
	go d.streamAgentOutput(evtCtx, id, uint32(a.PID), "agent.stderr", stderrPipe)
	go d.streamBPFEvents(evtCtx, id, bh)
	go d.waitAgent(a, res)

	return id, nil
}

// streamBPFEvents pumps the per-agent kernel event channel into the
// daemon's events.Pipeline. The Event.Kind field already carries the
// pillar+verb (e.g. "net.connect"); we forward it verbatim and stuff
// pillar-specific payload into the details object.
func (d *daemon) streamBPFEvents(ctx context.Context, agentID string, bh *bpf.Handle) {
	for ev := range bh.Events(ctx) {
		details := map[string]any{
			"verdict":   ev.Verdict,
			"comm":      ev.Comm,
			"tgid":      ev.TGID,
			"uid":       ev.UID,
			"gid":       ev.GID,
			"time_ns":   ev.TimeNs,
			"cgroup_id": ev.CgroupID,
		}
		if ev.Net != nil {
			details["family"] = ev.Net.Family
			details["dport"] = ev.Net.Dport
			details["daddr"] = ev.Net.Daddr
		}
		if ev.File != nil {
			details["flags"] = ev.File.Flags
			details["path"] = ev.File.Path
		}
		if ev.Creds != nil {
			details["old_id"] = ev.Creds.OldID
			details["new_id"] = ev.Creds.NewID
			details["cap_effective"] = ev.Creds.CapEff
		}
		if ev.Exec != nil {
			details["ppid"] = ev.Exec.PPID
			details["filename"] = ev.Exec.Filename
		}
		d.emitEvent(agentID, ev.PID, ev.Kind, details)
	}
}

func (d *daemon) streamAgentOutput(
	ctx context.Context,
	agentID string,
	pid uint32,
	eventType string,
	r io.Reader,
) {
	reader := bufio.NewReader(r)
	for {
		if ctx.Err() != nil {
			return
		}
		line, truncated, err := readOutputChunk(reader, maxAgentOutputChunkBytes)
		if !(errors.Is(err, io.EOF) && line == "" && !truncated) {
			d.emitEvent(agentID, pid, eventType, map[string]any{
				"line":      line,
				"truncated": truncated,
			})
		}
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return
			}
			d.log.Warn("agent output stream failed",
				"agent_id", agentID,
				"type", eventType,
				"err", err)
			return
		}
	}
}

func readOutputChunk(r *bufio.Reader, limit int) (string, bool, error) {
	if limit <= 0 {
		limit = maxAgentOutputChunkBytes
	}
	buf := make([]byte, 0, limit)
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(buf) == 0 {
					return "", false, io.EOF
				}
				return string(buf), false, io.EOF
			}
			if len(buf) > 0 {
				return string(buf), false, err
			}
			return "", false, err
		}

		if b == '\n' {
			return string(buf), false, nil
		}
		if b == '\r' {
			continue
		}

		buf = append(buf, b)
		if len(buf) < limit {
			continue
		}

		next, err := r.Peek(1)
		if err == nil && len(next) == 1 && next[0] == '\n' {
			_, _ = r.ReadByte()
			return string(buf), false, nil
		}
		if errors.Is(err, io.EOF) {
			return string(buf), false, io.EOF
		}
		return string(buf), true, nil
	}
}

func (d *daemon) waitAgent(a *registry.Agent, res *agentResources) {
	err := res.cmd.Wait()
	// Signal everyone waiting on this agent (notably shutdown) that Wait
	// has happened and ProcessState is now safe to read.
	close(res.done)

	exitCode := -1
	if res.cmd.ProcessState != nil {
		exitCode = res.cmd.ProcessState.ExitCode()
	}

	var status string
	if err != nil && exitCode != 0 {
		a.MarkCrashed(exitCode)
		status = "crashed"
	} else {
		a.MarkExited(exitCode)
		status = "exited"
	}

	d.emitEvent(a.ID, uint32(a.PID), "agent."+status, map[string]any{ //nolint:gosec // Linux PIDs bounded by kernel.pid_max (≤ 2^22)
		"exit_code":    exitCode,
		"duration_sec": time.Since(a.StartedAt).Seconds(),
	})

	// Crashed agents stay in the registry for keepCrashed before cleanup —
	// the reapLoop handles that. Exited (clean) agents clean up immediately.
	if status == "exited" {
		res.cleanup(d.log, a.ID)
		d.registry.Remove(a.ID)
	}
}

// reapLoop periodically removes crashed agents whose retention has expired.
// Exited (clean) agents are removed immediately by waitAgent; only crashed
// ones land here.
func (d *daemon) reapLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ids := d.registry.Reap(d.keepCrashed)
			for _, id := range ids {
				d.log.Info("reaping crashed agent", "agent_id", id)
				if a, ok := d.registry.Get(id); ok {
					if res, ok := a.Resources.(*agentResources); ok {
						res.cleanup(d.log, id)
					}
				}
				d.registry.Remove(id)
			}
		}
	}
}

func (d *daemon) emitEvent(agentID string, pid uint32, evtType string, details map[string]any) {
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		d.log.Error("marshal event details", "err", err)
		return
	}
	d.pipeline.Submit(ipc.Event{
		Ts:      time.Now(),
		AgentID: agentID,
		Type:    evtType,
		PID:     pid,
		Details: detailsJSON,
	})
}

// reconcileStartup scans the cgroup namespace for orphans from a prior
// daemon. v0.1 only logs them — full re-attach (re-loading pinned programs
// and re-opening pinned ringbufs) is tracked in CAVEATS.
func (d *daemon) reconcileStartup() {
	parent := filepath.Join(cgroup.Root, cgroup.Namespace)
	entries, err := os.ReadDir(parent)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			d.log.Warn("reconcile read cgroup parent", "path", parent, "err", err)
		}
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		d.log.Warn("orphan cgroup from prior daemon — leaving running, not adopted in v0.1",
			"agent_id", e.Name(),
			"path", filepath.Join(parent, e.Name()),
			"fix", "agentctl stop <id> after a future release supports adoption, or rmdir manually if no pids remain")
	}
}

func (d *daemon) shutdown() {
	for _, a := range d.registry.List() {
		res, ok := a.Resources.(*agentResources)
		if !ok {
			continue
		}
		if res.cmd != nil && res.cmd.Process != nil {
			_ = res.cmd.Process.Signal(syscall.SIGTERM)
		}
		// Wait for waitAgent's cmd.Wait to return — never call Wait here
		// concurrently. *exec.Cmd's Wait is not safe to call twice on the
		// same Cmd; the second call would race on ProcessState. If the
		// process doesn't honor SIGTERM in 2s, escalate to SIGKILL and
		// keep waiting (waitAgent will reap the result either way).
		if res.done == nil {
			// Defensive: an agent constructed by an older code path or by
			// a test fixture may not have a done chan. Skip rather than
			// nil-deref.
			res.cleanup(d.log, a.ID)
			d.registry.Remove(a.ID)
			continue
		}
		select {
		case <-res.done:
		case <-time.After(2 * time.Second):
			if res.cmd != nil && res.cmd.Process != nil {
				_ = res.cmd.Process.Kill()
			}
			select {
			case <-res.done:
			case <-time.After(2 * time.Second):
				d.log.Warn("waitAgent did not return after kill; proceeding with cleanup",
					"agent_id", a.ID)
			}
		}
		res.cleanup(d.log, a.ID)
		d.registry.Remove(a.ID)
	}
}

// --- Handler interface ---

func (d *daemon) StopAgent(_ context.Context, id string) error {
	a, ok := d.registry.Get(id)
	if !ok {
		// Idempotent per api/proto.md.
		return nil
	}
	res, ok := a.Resources.(*agentResources)
	if !ok {
		return nil
	}
	if res.cmd != nil && res.cmd.Process != nil {
		// SIGTERM first; waitAgent's Wait will return and run cleanup.
		_ = res.cmd.Process.Signal(syscall.SIGTERM)
	}
	return nil
}

func (d *daemon) ListAgents(_ context.Context) ([]ipc.AgentSummary, error) {
	return d.registry.Summaries(), nil
}

func (d *daemon) AgentLogs(_ context.Context, id string, tailN int) ([]ipc.Event, error) {
	if _, ok := d.registry.Get(id); !ok {
		return nil, fmt.Errorf("%w: %s", ipc.ErrAgentNotFoundErr, id)
	}
	if tailN <= 0 {
		tailN = 100
	}
	return d.pipeline.AgentLogTail(id, tailN)
}

func (d *daemon) StreamEvents(ctx context.Context, agentID string, sink func(ipc.Event) error) error {
	unsub := d.pipeline.Subscribe(agentID, sink)
	defer unsub()
	<-ctx.Done()
	return nil
}

func (d *daemon) IngestEvent(_ context.Context, agentID string, event ipc.IngestEvent) error {
	a, ok := d.registry.Get(agentID)
	if !ok {
		return fmt.Errorf("%w: %s", ipc.ErrAgentNotFoundErr, agentID)
	}
	if event.Type == "" || len(event.Type) < 5 || event.Type[:4] != "llm." {
		return fmt.Errorf("%w: event.type %q must be prefixed llm.", ipc.ErrInvalidManifestErr, event.Type)
	}
	ts := event.TS
	if ts.IsZero() {
		ts = time.Now()
	}
	details := event.Details
	if len(details) == 0 {
		details = json.RawMessage(`{}`)
	}
	d.pipeline.Submit(ipc.Event{
		Ts:      ts,
		AgentID: agentID,
		Type:    event.Type,
		PID:     uint32(a.PID),
		Details: details,
	})
	return nil
}

func (d *daemon) DaemonStatus(_ context.Context) (ipc.DaemonStatusResult, error) {
	return ipc.DaemonStatusResult{
		Version:       daemonVersion,
		UptimeSec:     int64(time.Since(d.startedAt).Seconds()),
		AgentCount:    len(d.registry.List()),
		EventsDropped: d.pipeline.DroppedCount(),
	}, nil
}

func mergeEnv(base []string, extra map[string]string) []string {
	out := append([]string(nil), base...)
	for k, v := range extra {
		out = append(out, fmt.Sprintf("%s=%s", k, v))
	}
	return out
}
