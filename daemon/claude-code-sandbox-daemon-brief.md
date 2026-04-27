# Claude Code Brief — Sandbox Daemon (P2)

*Use this as the initial prompt to Claude Code, or save it as `CLAUDE.md` at the repo root and start the session with "Read CLAUDE.md and begin Phase 1."*

---

## 1. Mission

You are building **component P2 (the sandbox daemon)** of the Agent Sandbox Runtime project — a Linux-based sandbox that prevents AI agents from doing things they shouldn't, even when prompt-injected, by enforcing rules in the kernel via eBPF.

The sandbox daemon is the userspace service that:

1. Accepts agent-launch requests over a Unix socket from the `agentctl` CLI.
2. Creates a cgroup v2 directory for each agent.
3. Loads an eBPF program (sourced from teammate P1) into that cgroup.
4. Writes the agent's policy (allowed network destinations) into a BPF map.
5. Launches the agent process inside the cgroup using cgroup-aware fork.
6. Reads kernel-level security events from a ring buffer and streams them back to the CLI and to a WebSocket consumed by a web UI.
7. Manages the lifecycle of multiple concurrent agents and survives its own restarts.

You are not building the eBPF C code (P1's job), the CLI (P3's job), the orchestrator or demo (P4's job), or the web UI (P5's job). You are the glue that makes the kernel and userspace meet.

## 2. Operating environment and hard constraints

These are non-negotiable. Do not deviate without explicit approval.

- **Target OS:** Ubuntu 24.04 only. Kernel 6.8+. Do not write portability code for other distros or kernels.
- **Language:** Go 1.22 or newer (you need `SysProcAttr.UseCgroupFD`).
- **eBPF library:** `github.com/cilium/ebpf` with the `bpf2go` codegen tool. Do not use `libbpf-go`, `aya`, or any alternative.
- **cgroup version:** v2 unified hierarchy only. Do not write any v1 code paths.
- **License:** Apache 2.0 for everything you produce.
- **Vendoring:** All eBPF C programs come from Tetragon (Apache 2.0). Preserve copyright notices verbatim. Add `NOTICE` at repo root crediting Isovalent / the Tetragon project.
- **Privilege model:** The daemon runs with `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE`. Never write code that assumes UID 0.
- **No external services in v0.1:** No Kubernetes, no etcd, no databases, no message brokers. State lives in memory + pinned BPF maps + cgroup directories.

## 3. Repository layout

Create exactly this structure. Do not invent additional top-level directories without a documented reason.

```
agent-sandbox/
  cmd/
    daemon/main.go            # daemon entry point
    spike-cgroup/main.go      # Phase 1 throwaway, deleted after Phase 2
  internal/
    bpf/
      gen.go                  # //go:generate bpf2go ...
      vmlinux.h               # generated once, committed
      programs/               # vendored .c files from Tetragon
      loader.go               # thin wrapper around generated objects
    cgroup/
      cgroup.go               # cgroup v2 lifecycle
      cgroup_test.go
    registry/
      registry.go             # in-memory agent registry
      registry_test.go
    ipc/
      protocol.go             # Unix socket message types
      server.go               # accept loop + dispatcher
      server_test.go
    events/
      pipeline.go             # ringbuf -> log + websocket fan-out
      websocket.go
    policy/
      policy.go               # manifest -> BPF map translation
      policy_test.go
  api/
    proto.md                  # human-readable IPC contract
  deploy/
    systemd/agent-sandbox.service
    install.sh
  tests/
    e2e/                      # //go:build e2e
  docs/
    operations.md
    architecture.md
  Makefile
  .golangci.yml
  .github/workflows/ci.yml
  README.md
  NOTICE
  LICENSE
  CLAUDE.md                   # this brief
```

## 4. Public IPC contract (the only thing P3 and P4 see)

This is the surface area you commit to. It is the most important design decision you make this entire project. Keep it minimal.

Transport: Unix socket at `/run/agent-sandbox.sock`, length-prefixed JSON, one request per connection or persistent for `StreamEvents`.

Methods:

```
RunAgent(manifest: Manifest)       -> { agent_id: string }
StopAgent(agent_id: string)        -> { ok: bool }
ListAgents()                       -> { agents: []AgentSummary }
AgentLogs(agent_id, tail_n: int)   -> { lines: []EventJSON }
StreamEvents(agent_id?: string)    -> stream of EventJSON   (server-pushed)
DaemonStatus()                     -> { version, uptime, agent_count }
```

Manifest schema (P3 owns the YAML, sends you parsed JSON):

```json
{
  "name": "string",
  "command": ["string", ...],
  "allowed_hosts": ["string", ...],
  "allowed_paths": ["string", ...],
  "env": {"KEY": "VALUE"},
  "working_dir": "string"
}
```

Event schema (you produce, P5 consumes):

```json
{
  "ts": "RFC3339Nano",
  "agent_id": "string",
  "type": "network.block | network.allow | agent.started | agent.exited | agent.crashed",
  "pid": 1234,
  "details": { ... type-specific ... }
}
```

Document this in `api/proto.md` before writing the server. Treat that file as the contract — when in doubt, update the doc and tell the user.

## 5. Tetragon vendoring policy

Do **not** fork Tetragon. Do **not** import Tetragon as a Go module. Vendor specific files only.

For Phase 1 and 2, you will copy these (or whatever P1 actually delivers) into `internal/bpf/programs/`:

- A `cgroup/connect4` program for IPv4 outbound connection enforcement.
- A `cgroup/connect6` program for IPv6 (Phase 3).
- The `vmlinux.h` patterns and CO-RE helpers used by those programs.

Each vendored file keeps its original copyright header, and the top of each file gets a comment block: `// Vendored from github.com/cilium/tetragon at <commit-sha> on <date>. See NOTICE.` Do not edit vendored files unless absolutely necessary; if you must, add a second comment explaining the change.

## 6. Phased plan

You will work through four phases. Do not start Phase N+1 until Phase N's acceptance test passes.

### Phase 1 — Foundation

**Goal:** Toolchain works, repo skeleton exists, you can drive cgroups and load a trivial eBPF program.

Tasks, in order:

1. Run the four verification commands and report results to the user. If any fail, stop and ask:
   ```bash
   uname -r
   mount | grep cgroup2
   ls /sys/kernel/btf/vmlinux
   sudo bpftool feature probe | grep cgroup_sock
   ```
2. Initialize the repo (`git init`, Go module, `.gitignore`, Apache 2.0 LICENSE, NOTICE, empty README).
3. Install `bpf2go`: `go install github.com/cilium/ebpf/cmd/bpf2go@latest`.
4. Create the directory layout from section 3 with empty files.
5. Generate `vmlinux.h` and commit it.
6. Write `cmd/spike-cgroup/main.go`: ~50 lines that create `/sys/fs/cgroup/agent-sandbox-spike/`, move the current PID into `cgroup.procs`, spawn `sleep 3`, verify via `/proc/self/cgroup`, and clean up. Test with `sudo go run ./cmd/spike-cgroup`.
7. Write a minimal eBPF C program at `internal/bpf/programs/spike_connect4.c` that attaches to `cgroup/connect4` and `bpf_printk`s the destination IP. Wire `bpf2go` in `internal/bpf/gen.go`. Run `go generate ./...` then a small loader in `cmd/spike-cgroup` (rename if needed) that loads it. Verify with `sudo cat /sys/kernel/debug/tracing/trace_pipe` while running `curl example.com`.
8. Set up `Makefile` (`build`, `test`, `lint`, `generate`) and `.golangci.yml`.
9. Set up CI (`.github/workflows/ci.yml`) running `make build test lint`. CI does **not** run eBPF code (no kernel in GitHub runners by default) — only build + unit tests on non-privileged paths.

**Phase 1 acceptance:**

- [ ] All four verification commands pass.
- [ ] `make build && make test && make lint` is green.
- [ ] `sudo go run ./cmd/spike-cgroup` creates a cgroup, runs the program, cleans up.
- [ ] You can demonstrate trace_pipe output from the spike connect4 program when curling an external host.
- [ ] CI is green on a fresh push.

Commit at: `feat: phase 1 foundation — cgroup and ebpf spikes`. Then ask the user to confirm before proceeding to Phase 2.

### Phase 2 — Vertical Slice (Hardcoded MVP)

**Goal:** A real `RunAgent` request over Unix socket creates a cgroup, loads an eBPF program with one hardcoded blocked IP, launches the agent inside the cgroup with cgroup-aware fork, reads ring buffer events, and logs them. Hardcoded values are fine. One agent at a time is fine.

Tasks, in order:

1. Write `api/proto.md` documenting the IPC contract from section 4. Mark v0.1 fields in scope and v0.2 fields out of scope.
2. Implement `internal/cgroup/cgroup.go`:
   ```go
   type Cgroup struct { ... }
   func Create(name string) (*Cgroup, error)
   func (c *Cgroup) FD() int
   func (c *Cgroup) Path() string
   func (c *Cgroup) Destroy() error  // kill remaining pids, rmdir
   func List() ([]*Cgroup, error)    // for startup reconciliation
   ```
   Unit tests use a temp root under `/sys/fs/cgroup/agent-sandbox-test/` and require root — gate them with `//go:build linux && integration` and a sudo-aware test runner.
3. Implement `internal/bpf/loader.go`: load + attach generated programs to a specific cgroup fd. Critical first call: `rlimit.RemoveMemlock()`. Unit-test the parts that don't require BPF; everything else is integration.
4. Implement `internal/ipc/server.go`: Unix socket listener, JSON request decoding, dispatch to `RunAgent` only. Handle `SIGINT/SIGTERM` for clean shutdown.
5. Implement `RunAgent` end-to-end:
   - Parse manifest.
   - Create cgroup.
   - Load eBPF program; write hardcoded `1.1.1.1` (or another easily-curlable IP) into policy map as denied.
   - `exec.Cmd` with `SysProcAttr.UseCgroupFD = true` and `CgroupFD = cgroup.FD()`. Start the command.
   - Goroutine reads ring buffer; logs events as JSON to stderr.
   - On `cmd.Wait()`, detach programs, destroy cgroup.
6. Coordinate with P3 to wire their `agentctl run` into your socket. If P3 isn't ready, write a tiny `cmd/test-client/main.go` that sends a hardcoded `RunAgent` request.
7. Write a manual test script under `tests/manual/phase2.sh` documenting how to reproduce the demo.

**Phase 2 acceptance:**

- [ ] Run the daemon: `sudo ./bin/agent-sandbox-daemon` with no errors.
- [ ] From another terminal: `sudo ./bin/test-client run examples/curl-blocked.json` (or P3's CLI) launches a Python or shell agent that does `curl 1.1.1.1`.
- [ ] The curl fails with `Operation not permitted`.
- [ ] Daemon logs a `network.block` event for that connection in JSON form.
- [ ] Ctrl-C on the daemon leaves no `/sys/fs/cgroup/agent-sandbox/*` directories behind.
- [ ] Restart the daemon after a forced kill — startup reconciliation cleans up any leaked cgroups.

Commit at: `feat: phase 2 vertical slice — hardcoded sandbox MVP`. Pause for user confirmation.

### Phase 3 — Real Product

**Goal:** Hardcoded values gone. Multiple concurrent agents. Manifest drives policy. Events stream to a WebSocket. Daemon survives restart and adopts existing agents.

Tasks, in order:

1. Implement `internal/policy/policy.go`: translate `Manifest.allowed_hosts` to BPF map entries. Resolve hosts via `net.LookupHost` at agent launch (document DNS-rotation as out-of-scope in `LIMITATIONS.md`). Map schema:
   ```c
   struct policy_key   { __u64 cgroup_id; __u32 addr; __u16 port; __u8 proto; };
   struct policy_value { __u8 verdict; };
   ```
2. Implement `internal/registry/registry.go`:
   ```go
   type Agent struct {
       ID, Name string
       Cgroup *cgroup.Cgroup
       BPFObjs *bpfObjects
       Links []link.Link
       Cmd *exec.Cmd
       StartedAt time.Time
       Status AgentStatus
   }
   type Registry struct { mu sync.RWMutex; agents map[string]*Agent }
   ```
   All public methods take the lock briefly and never hold it across I/O.
3. Implement remaining IPC methods: `StopAgent`, `ListAgents`, `AgentLogs`, `DaemonStatus`.
4. Implement `internal/events/pipeline.go`: one central event channel; fan-out to (a) daemon log, (b) per-agent log files at `/var/log/agent-sandbox/<agent-id>.log` with size-rotation at 10MB keeping 3, (c) WebSocket subscribers.
5. Implement `internal/events/websocket.go` using `nhooyr.io/websocket`. Endpoint: `ws://127.0.0.1:7443/events?agent=<id>` (omit param to subscribe to all). Bind to localhost only.
6. Add `IPv6` support: vendor `cgroup/connect6` from P1 and load it alongside connect4.
7. Implement BPF map pinning under `/sys/fs/bpf/agent-sandbox/<agent-id>/`. On daemon startup, scan that directory plus `/sys/fs/cgroup/agent-sandbox/`, rebuild the registry, re-attach event readers. Running agents survive daemon restart — this is a feature, not a chore.
8. Implement crash handling: when `cmd.Wait()` returns an error, mark `Status = Crashed`, keep the cgroup for `--keep-crashed=60s` (configurable via daemon flag), then clean up.
9. Implement load-failure rollback: if `RunAgent` fails after the cgroup is created, destroy it and return a structured error to the caller.
10. Write integration tests in `tests/e2e/` covering: three concurrent agents with different policies, agent stop while others continue, daemon restart with running agents.

**Phase 3 acceptance:**

- [ ] Three `agentctl run` invocations with different manifests run concurrently. Each agent's blocks are visible in P5's UI tagged by `agent_id`.
- [ ] `agentctl list` shows three. `agentctl stop <id>` removes one. The other two keep running.
- [ ] `sudo systemctl restart agent-sandbox` (or kill + restart) leaves the agents running. After restart, `agentctl list` shows all three. Events resume streaming.
- [ ] An agent that calls `exit(1)` shows up as `Crashed`, then disappears from the registry within 60s.
- [ ] e2e test suite (`make test-e2e`) is green.

Commit at: `feat: phase 3 multi-agent, manifest-driven, restart-safe`. Pause for user confirmation.

### Phase 4 — Ship-ready

**Goal:** A stranger clones the repo and gets a working daemon in under ten minutes.

Tasks, in order:

1. Write `deploy/systemd/agent-sandbox.service` with the exact capability set from section 2. The unit must run as a non-root `agent-sandbox` user.
2. Write `deploy/install.sh`: creates the user, installs the binary to `/usr/local/bin`, installs the unit file, creates `/etc/agent-sandbox/`, `/var/log/agent-sandbox/`, mounts the BPF filesystem if missing, runs `systemctl daemon-reload && systemctl enable --now agent-sandbox`. Make it idempotent.
3. Add Makefile targets `install` and `uninstall` that wrap `install.sh`.
4. Write `docs/architecture.md` with an ASCII diagram and a section per internal package.
5. Write `docs/operations.md` covering log locations, common errors with named fixes, `bpftool prog list / map dump` recipes, recovery from a corrupted pinned-map state.
6. Add benchmarks in `internal/bpf/benchmarks_test.go`: agent startup overhead (sandboxed vs. unsandboxed) and per-connection cost. Targets: <100ms startup overhead, <1µs per connection.
7. Pass over every `fmt.Errorf` and `log.Error` — each must name the specific failure and the most likely fix.
8. Write the README's daemon section: quickstart, architecture summary, link to `docs/`.
9. Tag `v0.1.0`.

**Phase 4 acceptance:**

- [ ] On a fresh Ubuntu 24.04 VM with no prior setup: `git clone && sudo make install` completes successfully and `systemctl status agent-sandbox` shows active.
- [ ] `ps -o user= -C agent-sandbox-daemon` returns `agent-sandbox`, not `root`.
- [ ] Full e2e test suite green.
- [ ] Benchmarks meet the targets.
- [ ] `git tag v0.1.0` exists with a release commit.

## 7. Coding standards

- **Error handling:** Wrap with `fmt.Errorf("loading connect4 program: %w", err)`. Never return a bare error from a function the user sees.
- **Logging:** `log/slog` with JSON handler in production, text in dev. Log fields: `agent_id`, `cgroup_id`, `pid`, `phase`. No `fmt.Println` outside of CLI tools.
- **Concurrency:** One `sync.RWMutex` per data structure that needs it. Never hold a lock across a channel send or syscall. `context.Context` on every long-running goroutine.
- **Testing:** Unit tests for pure logic. Integration tests (`//go:build integration`) for cgroup and BPF — gate behind a Make target. e2e tests (`//go:build e2e`) spin up the real daemon.
- **No global state.** Pass dependencies explicitly. The only globals are flag values parsed in `main`.
- **Resource cleanup:** Every `Create` has a paired `Destroy`. Every loaded BPF object lives in a struct with a `Close()` method. Use `defer` aggressively.

## 8. Workflow rules

- After each numbered task in a phase, run `make build && make test`. If it's broken, fix before moving on.
- Commit at the end of each phase with the exact message in the phase spec.
- Use bash freely for verification — `bpftool prog list`, `cat /sys/fs/cgroup/...`, `journalctl`, etc. Don't ask permission for read-only commands.
- For commands that mutate the system (writing to `/sys/fs/cgroup/`, loading BPF programs, installing services), name what you're about to do in one line, then run.
- When you finish a phase, **stop** and ask the user to confirm before starting the next phase. Do not auto-advance.
- If you discover a constraint in section 2 is wrong (e.g., kernel doesn't have a feature you assumed), stop and ask. Do not silently work around it.

## 9. Out of scope (do not build)

These will look tempting. They are v0.2.

- Filesystem policy (LSM hooks, `openat` interception). Network policy only in v0.1.
- DNS-aware policy or DNS rebinding protection. Resolve at launch, accept the limitation.
- Multi-user / multi-tenant. Single daemon, single namespace.
- Remote API (HTTP/gRPC over the network). Unix socket only.
- Containerization (Docker, OCI). The daemon runs on the host directly.
- Kubernetes integration of any kind. Ever, in v0.1.
- A policy DSL beyond the manifest fields in section 4.
- Encryption of the Unix socket or WebSocket. Both are localhost-only.
- Metrics export (Prometheus, OTel). Add in v0.2.
- A `tetra`-style rich CLI of your own. P3 owns the CLI.

If the user asks for one of these mid-project, push back: "That's v0.2 by the brief. Do you want to change scope?"

## 10. Coordination assumptions and stubs

You are working in parallel with four teammates. You may not have their work when you need it.

- **P1 (eBPF):** You need their `cgroup/connect4` program by Phase 2. If it isn't ready, write a minimal stub yourself based on the Tetragon source — clearly mark it `STUB: replace with P1's program when ready`. Do not block.
- **P3 (CLI):** You need their `agentctl` to test end-to-end. If it isn't ready, the `cmd/test-client` you write in Phase 2 is your stand-in. The IPC contract in `api/proto.md` is the source of truth — they conform to you, not the other way around.
- **P4 (orchestrator):** You need to know whether they landed on AIOS or a custom orchestrator before Phase 3, because it affects whether agents are processes or threads. If unknown, assume processes (your design works either way as long as each agent is a process).
- **P5 (UI):** They subscribe to your WebSocket. Agree the event schema with them before Phase 3. Once agreed, do not change it without a heads-up.

## 11. When to escalate to the user

Stop and ask before:

- Modifying anything in `/etc/`, `/usr/local/`, or system-level configs outside what's documented in `deploy/install.sh`.
- Adding a Go dependency not already mentioned in this brief.
- Diverging from the IPC contract in section 4.
- Diverging from the directory layout in section 3.
- Skipping any acceptance-test bullet.
- Anything that would require the brief itself to change.

## 12. Definition of done

You are done when, on a fresh Ubuntu 24.04 VM:

```bash
git clone <repo>
cd agent-sandbox
sudo make install
sudo systemctl start agent-sandbox
agentctl run examples/blocked-curl.yaml
# observes: curl fails, network.block event in `agentctl logs`
```

…works on the first try, and `make test-e2e` is green, and `v0.1.0` is tagged.

Begin Phase 1 now. Start by running the four verification commands and reporting results.
