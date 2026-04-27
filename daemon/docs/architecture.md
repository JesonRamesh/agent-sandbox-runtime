# Architecture

## At a glance

`agent-sandbox-daemon` is the userspace half of the Agent Sandbox Runtime. It accepts agent-launch requests from `agentctl` over a Unix socket, creates a per-agent cgroup v2 directory, binds it to a kernel-side BPF policy through Mehul's eBPF LSM programs, launches the agent inside via cgroup-aware fork, and fans out kernel-level events to slog, per-agent log files, and a localhost WebSocket. It is built for AI-agent operators who need an in-kernel kill-switch across four pillars — network, file, exec, creds — without containers, namespaces, or a separate sidecar.

The runtime is layered: cgroup v2 holds the agent process; eight BPF LSM/tracepoint programs (loaded once daemon-wide) walk a `cgroup_id → policy_id → struct policy` indirection on every relevant syscall and decide `allow | deny | audit`; the daemon owns the policy_id allocator, map writes, and event fan-out; IPC over Unix socket exposes a stable JSON contract to the CLI; the WebSocket exposes the same event stream to the UI. The eBPF C is owned by P1 (`bpf/` on `Mehul`) — see [`integration-with-mehul-ebpf.md`](integration-with-mehul-ebpf.md). v0 enforces AF_INET only (see [`../LIMITATIONS.md`](../LIMITATIONS.md)).

## Runtime diagram

```
                        ┌──────────────────────────────────────────────────┐
                        │                  user space                      │
                        │                                                  │
   agentctl run ───────▶│  /run/agent-sandbox.sock                         │
   (P3 CLI)             │   (length-prefixed JSON, mode 0600)              │
                        │              │                                   │
                        │              ▼                                   │
                        │   ┌──────────────────────────┐                   │
                        │   │   agent-sandbox-daemon   │                   │
                        │   │                          │                   │
                        │   │  ipc.Server ─▶ daemon ◀─ events.Pipeline    │
                        │   │                  │             │             │
                        │   │  registry.Registry           ws://127.0.0.1  │
                        │   │     │     │                  :7443/events    │
                        │   │     │     │                                  │
                        │   │  cgroup    bpf.Runtime ─▶ bpf.Handle (per agent)
                        │   │   .FD()       .Bind()       .Cleanup()       │
                        │   └────┬───────────┬───────────────────────────┬─┘
                        │        │           │                           │
                        ▼        ▼           ▼   pin maps                ▲
              ┌──────────────────────────────────────────┐               │
              │                kernel                    │               │
              │                                          │               │
              │  /sys/fs/cgroup/agent-sandbox/<id>/      │               │
              │     ├── cgroup.procs ◀── agent PID       │               │
              │     └── cgroup.kill                      │               │
              │                                          │               │
              │   8 BPF programs attached daemon-wide:    │               │
              │     network: lsm/socket_connect, tp/sys_enter_sendto      │
              │     file:    lsm.s/file_open                              │
              │     creds:   lsm/task_fix_setuid|setgid|capset            │
              │     exec:    tp/sched_process_exec, lsm/bprm_check_security
              │     │                                    │               │
              │     ├── cgroup_policy: cg_id → pol_id ─── /sys/fs/bpf/    │
              │     ├── policies:    pol_id → struct policy   agent-sandbox/
              │     └── events ringbuf ──────── ringbuf.Reader (one) ─────┘
              │                                                          │
              │  agent process: curl, python, ...                        │
              │   syscall → LSM hook → struct policy lookup → verdict   │
              │           → ringbuf event → daemon fans out by cg_id    │
              └──────────────────────────────────────────────────────────┘
```

Each agent gets its own cgroup and its own `policy_id` slot. The eight BPF programs are loaded **once** at daemon startup and stay attached for the daemon's lifetime; per-agent policy is just two map writes (`policies[id]` + `cgroup_policy[cg]→id`). One global ringbuf reader fans out events to per-agent channels keyed by `cgroup_id`.

## Per-package summary

### `internal/cgroup/`

Source: [`internal/cgroup/cgroup.go`](../internal/cgroup/cgroup.go).

Owns cgroup v2 lifecycle for one agent. `Create(name)` mkdir's `/sys/fs/cgroup/agent-sandbox/<name>/` and opens an `O_DIRECTORY|O_CLOEXEC` fd that lives for the duration of the `Cgroup` so it can be passed to `exec.Cmd` via `SysProcAttr.UseCgroupFD`. `ID()` `fstat`s that fd to expose the kernel's cgroup ID (the directory inode), which matches `bpf_get_current_cgroup_id()` on the BPF side. `Destroy()` writes `1` to `cgroup.kill` (kernel 5.14+) to atomically SIGKILL every pid in the cgroup, closes the fd, and rmdirs the directory. `List()` enumerates the namespace for startup reconciliation; `Adopt(name)` re-opens an existing one. `Manager` parameterizes the parent so integration tests can use `agent-sandbox-test/` without colliding with production. Linux-only — `cgroup_other.go` provides stubs so `go build` works on macOS.

Key invariants: the directory fd must be open before the cgroup is populated and before the BPF program attaches; the cgroup name is a single path segment (no slashes); `Destroy` is the only path that removes the directory.

### `internal/bpf/`

Source: [`internal/bpf/loader.go`](../internal/bpf/loader.go), [`internal/bpf/event.go`](../internal/bpf/event.go), [`bpf/common.h.reference`](../bpf/common.h.reference) (vendored read-only mirror of Mehul's contract).

`LoadRuntime(bpfDir)` is called once at daemon startup. It removes MEMLOCK, mkdir's `/sys/fs/bpf/agent-sandbox/`, loads four `.bpf.o` ELFs (`network`, `file`, `creds`, `exec`), pins the three shared maps (`events`, `cgroup_policy`, `policies`) by name under the pin root, attaches all eight programs (six LSM hooks + two tracepoints), opens a single `ringbuf.Reader` on `events`, and starts a fan-out goroutine. The fan-out decodes each record (header + per-pillar payload) and dispatches by `cgroup_id` to a per-agent buffered channel.

`Runtime.Bind(agentID, cgroupID, compiled)` does the per-agent work: allocates a free `policy_id ∈ [1, MaxPolicies]` from a daemon-owned free-list, writes `policies[id] = compiled`, then writes `cgroup_policy[cgroupID] = id`. Order matters — writing the binding before the policy slot is populated would let the kernel see a half-zero `struct policy` on the very next syscall. Returns a `*Handle` whose `Events(ctx)` exposes the per-agent stream and whose `Cleanup()` unbinds (deletes both map entries, returns the id to the free-list, closes the channel).

`event.go` mirrors `event_hdr` and the four payload structs from `bpf/common.h.reference` and decodes ringbuf records into a tagged `Event`. The Go layout MUST stay byte-identical with the C layout — there are tests in `event_test.go` that build synthetic kernel records and assert decode correctness.

Key invariants: every `LoadRuntime` either fully succeeds or fully unwinds the partial state; the policy_id allocator is recycled on every `Cleanup`; one bad ringbuf record never silences the rest (decode errors are logged and skipped); the runtime is responsible for closing all per-agent channels on shutdown.

### `internal/ipc/`

Source: [`internal/ipc/protocol.go`](../internal/ipc/protocol.go), [`internal/ipc/server.go`](../internal/ipc/server.go).

`protocol.go` is the machine-readable mirror of [`api/proto.md`](../api/proto.md): `Request` / `Response` envelopes, `Manifest`, `AgentSummary`, `Event`, per-method param/result structs, the stable error-code constants (`ErrInvalidManifest`, `ErrAgentNotFound`, `ErrCgroupFailed`, `ErrBPFLoadFailed`, `ErrLaunchFailed`, `ErrInternal`), and the `WriteFrame` / `ReadFrame` helpers that implement the 4-byte big-endian length prefix. A single `maxFrameBytes = 16 MiB` cap bounds the frame size. `server.go` runs the Unix-socket accept loop and dispatches one request per connection (except `StreamEvents`, which is persistent) to a `Handler` interface implemented by the daemon. `CodeForError` maps sentinel errors (`ErrInvalidManifestErr`, etc.) to wire codes — anything unmapped becomes `INTERNAL`.

Key invariants: the socket is mode `0600`; a stale socket file from a prior crash is logged and unlinked at `Start`; `Stop` waits for in-flight handlers via a `WaitGroup` so a slow `StreamEvents` cannot outlive shutdown.

### `internal/events/`

Source: [`internal/events/pipeline.go`](../internal/events/pipeline.go), [`internal/events/websocket.go`](../internal/events/websocket.go).

`Pipeline` is the daemon-wide event bus. `Submit(Event)` is non-blocking — a full input buffer drops the event with a warn log rather than back-pressuring the ringbuf reader. `Run(ctx)` fans each event out to (a) slog, (b) the per-agent log file at `<logDir>/<agent-id>.log` via a `rotatingWriter` (10 MiB × 3 by default), and (c) every active `Subscribe`r. `AgentLogTail(agentID, n)` reads the per-agent file and returns the last `n` decoded events. A subscriber whose `Sink` returns an error is removed in the same pass. `WSServer` exposes the same fan-out at `ws://127.0.0.1:7443/events?agent=<id>` and refuses to bind anything other than a loopback address.

Key invariants: one rotating writer per agent, serialized through `fileMu`; `Submit` recovers from a send-on-closed-channel panic so a Close vs Submit race during shutdown is safe; the websocket per-event write is bounded by a 1-second timeout so a stalled client cannot stall fan-out for everyone else.

### `internal/policy/`

Source: [`internal/policy/policy.go`](../internal/policy/policy.go).

Translates `ipc.Manifest` into a single `Compiled` value — a byte-for-byte mirror of `struct policy` from [`bpf/common.h.reference`](../bpf/common.h.reference). Fields:

- `Mode` — `audit` (0) or `enforce` (1).
- `Hosts[64]` of `HostRule{AddrV4 BE, PrefixLen, Port}` — for the network pillar's `host_allowed()` CIDR match.
- `Paths[64]` of `PathRule{Prefix[256]}` — for the file pillar's `path_allowed()` prefix match.
- `Bins[32]` of `BinaryRule{Path[256]}` — for the exec pillar's `binary_allowed()` exact-path match.
- `ForbiddenCaps` — bitmask consumed by the creds pillar's `caps_allowed()`.

`Compile(manifest)` does DNS resolution at launch time via `net.LookupHost`, expands one manifest host into one `HostRule` per A record, validates capability names against the cap-bit table, rejects oversized paths, and returns the packed struct. v0 is IPv4 only — IPv6 hosts in the manifest produce an error rather than silently being dropped. DNS rotation after launch is not handled — see [`../LIMITATIONS.md`](../LIMITATIONS.md).

Key invariants: addresses in `HostRule.AddrV4` use the same network-byte-order packing as `ctx->user_ip4` / `sin_addr.s_addr`; field order in `Compiled` matches `struct policy` exactly; the loader treats `Compiled` as opaque bytes via `unsafe.Pointer`.

### `internal/registry/`

Source: [`internal/registry/registry.go`](../internal/registry/registry.go).

In-memory map of `Agent` records. One `sync.RWMutex` on `Registry` guards the map; one `sync.Mutex` on each `Agent` guards its mutable status/exit fields. `Add`, `Get`, `Remove`, `List`, `Summaries`, and `Reap(retention)` are the public surface. `Reap` is what implements the `--keep-crashed` window — agents with `StatusExited`/`StatusCrashed` whose `exitedAt` is older than `retention` are removed. The kernel-side resources (cgroup, BPF handle, `*exec.Cmd`) are stored as `Agent.Resources any` to keep the registry import-cycle-free and cross-platform; the daemon in `cmd/daemon/main_linux.go` defines the concrete `agentResources` type and is responsible for cleanup.

Key invariants: locks are taken briefly and never held across I/O; the registry never inspects, closes, or copies `Agent.Resources`; status-string vocabulary (`running` / `exited` / `crashed`) is wire-stable per `api/proto.md`.

## Lifecycle of a request

When `agentctl run examples/curl-blocked.json` arrives at `/run/agent-sandbox.sock`:

1. `ipc.Server.Serve` accepts the connection and spawns a goroutine. `handleConn` reads one length-prefixed frame and dispatches by `req.Method` to `handleRunAgent`.
2. `handleRunAgent` JSON-decodes `RunAgentParams`, runs `Manifest.Validate()` (rejects empty `name` / empty `command` with `INVALID_MANIFEST`), and calls `daemon.RunAgent(ctx, manifest)` (see `cmd/daemon/main_linux.go`).
3. `daemon.RunAgent` calls `policy.Compile(manifest)` to pack the four pillar fields (allowed_hosts, allowed_paths, allowed_bins, forbidden_caps) into a single `Compiled` mirroring `struct policy`. DNS lookup of allowed_hosts happens here.
4. `cgroup.Create(id)` mkdir's `/sys/fs/cgroup/agent-sandbox/<id>/` and opens the directory fd. `Cgroup.ID()` `fstat`s that fd to obtain the kernel cgroup id.
5. `daemon.bpfRuntime.Bind(id, cgroupID, compiled)` allocates a free `policy_id`, writes `policies[id] = compiled` (the entire `struct policy`), then writes `cgroup_policy[cgroupID] = id`. The two writes are ordered so the kernel never sees a binding pointing at an uninitialized policy slot. Returns a `*bpf.Handle` whose Events channel is now subscribed for this cgroup_id.
6. The daemon builds an `*exec.Cmd` with `SysProcAttr.UseCgroupFD = true` and `CgroupFD = cg.FD()`, merges the manifest env onto the daemon env, and calls `cmd.Start()`. The kernel forks the agent directly into the cgroup — there is no race window where the agent runs outside enforcement.
7. The daemon assembles an `agentResources{cg, bpfHandle, cmd, cancelEvts}` and a `registry.Agent`, then `registry.Registry.Add` inserts it under `mu.Lock()`.
8. `daemon.streamBPFEvents` is launched in a goroutine: it ranges over `bh.Events(ctx)` and for each kernel event calls `daemon.emitEvent`, which `pipeline.Submit`s an `ipc.Event` whose `type` is one of `net.connect`, `net.sendto`, `file.open`, `exec`, `creds.setuid`, `creds.setgid`, `creds.capset`. The pipeline fans it out to slog, the per-agent log file, and every WebSocket / `StreamEvents` subscriber.
9. `daemon.waitAgent` is launched in a second goroutine: it blocks on `cmd.Wait()`, marks the agent `Exited` or `Crashed` based on the exit code, emits the corresponding `agent.exited` / `agent.crashed` event, and (for clean exits only) calls `agentResources.cleanup` and `Registry.Remove`. Crashed agents are left in place for `--keep-crashed`; `daemon.reapLoop` cleans them up on its 10-second tick.
10. `handleRunAgent` writes the `RunAgentResult{AgentID: id}` frame back to the client and closes the connection. The agent runs to completion independently; its events continue to flow through the pipeline until `cmd.Wait()` returns and the cleanup chain finishes.

## Process model

Each agent is a separate OS process spawned by `os/exec.Cmd.Start()` from inside the daemon. There are no namespaces (no `unshare`, no PID namespace, no mount namespace, no network namespace), no OCI runtime, no container image — the agent runs on the host's filesystem with the daemon's environment merged with the manifest's. The only isolation is the cgroup membership and the BPF LSM hooks that watch every relevant syscall the agent makes. The fork-into-cgroup is atomic: `SysProcAttr.UseCgroupFD = true` plus `CgroupFD = cg.FD()` causes the kernel to place the new process in the target cgroup before its first instruction runs (Linux 5.7+, requires Go 1.22+ for the `SysProcAttr` field). Multiple agents run concurrently; each has its own cgroup and its own `policy_id` slot in the shared kernel maps. The eight BPF programs themselves are loaded **once** at daemon startup and shared across every agent — the per-agent gate is the `cgroup_policy → policies[id]` lookup the kernel does on every syscall.

## What survives a daemon restart, and what doesn't

What survives:

- **The agent process.** It belongs to the kernel, not the daemon. SIGTERM'ing the daemon does not signal the agent.
- **The cgroup directory.** The kernel keeps it as long as it has members.
- **The attached BPF programs.** Each `link.AttachLSM` / `link.Tracepoint` link holds a kernel reference; programs stay attached even after the daemon process exits, as long as the bpffs pin directory persists.
- **The pinned maps.** `events`, `cgroup_policy`, `policies` are pinned under `/sys/fs/bpf/agent-sandbox/` (`PinByName`) and outlive the daemon. The kernel keeps the maps populated with whatever the daemon last wrote — so existing agents keep being enforced under the policy that was active when the daemon went down.

What does **not** survive:

- **The single ringbuf reader goroutine.** It lives in the daemon process; events emitted while the daemon is down are lost.
- **The in-memory registry.** All `*registry.Agent` records are gone after restart.
- **The `*exec.Cmd` handle and its `Wait` watcher.** The new daemon has no `pidfd` or `Wait` channel for the orphaned agent, so it cannot notice the process exiting.
- **The policy_id allocator state.** A fresh daemon doesn't know which ids are currently bound, so adoption (planned, not implemented) needs to walk `cgroup_policy` to rebuild the free-list.

What is **planned but not yet implemented** (CAVEATS §23): on startup the daemon should `LoadPinnedMap` the three shared maps, walk `cgroup_policy` to rebuild the free-list and per-agent records, re-attach the ringbuf reader, and let `agentctl stop <id>` target the orphaned agents. Today's `daemon.reconcileStartup` only logs orphan cgroup directories. Operators who restart the daemon while agents are running need to be aware: enforcement keeps working (the BPF programs are still attached and the policy maps still have valid entries), but events stop being recorded until the daemon is rebuilt with adoption, and `agentctl list` will not show the orphaned agents.
