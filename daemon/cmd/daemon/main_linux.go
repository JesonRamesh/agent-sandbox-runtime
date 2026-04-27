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
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/bpf"
	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/cgroup"
	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/events"
	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/ipc"
	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/policy"
	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/registry"
)

const daemonVersion = "0.1.0-phase3"

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

	// closeOnce guards Close so the wait-then-cleanup goroutine and an
	// explicit StopAgent call don't both try to free the same resources.
	closeOnce sync.Once
}

func (r *agentResources) cleanup(log *slog.Logger, agentID string) {
	r.closeOnce.Do(func() {
		if r.cancelEvts != nil {
			r.cancelEvts()
		}
		if r.bpfHandle != nil {
			if err := r.bpfHandle.Cleanup(); err != nil {
				log.Warn("bpf cleanup", "agent_id", agentID, "err", err)
			}
		}
		if r.cg != nil {
			if err := r.cg.Destroy(); err != nil {
				log.Warn("cgroup destroy", "agent_id", agentID, "err", err, "fix", "manually rmdir /sys/fs/cgroup/agent-sandbox/<id> after killing leftover pids")
			}
		}
	})
}

type daemon struct {
	startedAt   time.Time
	log         *slog.Logger
	registry    *registry.Registry
	pipeline    *events.Pipeline
	bpfRuntime  *bpf.Runtime
	keepCrashed time.Duration
}

func newAgentID() string {
	var b [4]byte
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

	id := newAgentID()
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
		cmd.Dir = m.WorkingDir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

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
		return "", fmt.Errorf("%w: registry add: %v", ipc.ErrInternal, err)
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
	d.emitEvent(id, uint32(a.PID), "agent.started", map[string]any{
		"command":     m.Command,
		"cgroup_path": cg.Path(),
		"cgroup_id":   cgID,
		"policy_id":   bh.PolicyID(),
	})

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

func (d *daemon) waitAgent(a *registry.Agent, res *agentResources) {
	err := res.cmd.Wait()

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

	d.emitEvent(a.ID, uint32(a.PID), "agent."+status, map[string]any{
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
		// Give the process a moment to handle SIGTERM gracefully.
		done := make(chan struct{})
		go func() {
			res.cmd.Wait() //nolint:errcheck // Wait may already have happened in waitAgent
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = res.cmd.Process.Kill()
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

func (d *daemon) DaemonStatus(_ context.Context) (ipc.DaemonStatusResult, error) {
	return ipc.DaemonStatusResult{
		Version:    daemonVersion,
		UptimeSec:  int64(time.Since(d.startedAt).Seconds()),
		AgentCount: len(d.registry.List()),
	}, nil
}

func mergeEnv(base []string, extra map[string]string) []string {
	out := append([]string(nil), base...)
	for k, v := range extra {
		out = append(out, fmt.Sprintf("%s=%s", k, v))
	}
	return out
}
