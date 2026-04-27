# Daemon model: per-agent (ours) vs. system-wide (Mehul's)

## TL;DR

**Ours wins.** Don't switch. The brief mandates our model (§2 privilege list + §4 `RunAgent` method); we've already shipped it through Phase 4. Switching would gut the daemon, push privilege into the CLI, and contradict the spec P3 is conforming to.

## The actual difference (one sentence)

**Where does process lifecycle live?**

- **Ours:** the daemon `fork+exec`s each agent (cgroup-aware fork via `SysProcAttr.UseCgroupFD`). The daemon is the agent's parent. The CLI is a thin RPC client over Unix socket.
- **Mehul's (per D-009):** the CLI `fork+exec`s the agent and binds itself into the cgroup; the daemon only manages BPF programs, policy maps, and an HTTP+SSE event stream on `:9000`.

That single decision cascades into every other tradeoff below.

## What changes downstream

| concern | ours (daemon-owned lifecycle) | Mehul's (CLI-owned lifecycle) |
|---|---|---|
| **privileges** | only the daemon needs `CAP_BPF`/`CAP_SYS_ADMIN`; CLI is a normal user binary | CLI needs `CAP_SYS_ADMIN` to write `cgroup.procs` — setuid, sudo wrapper, or run CLI as root |
| **trust boundary** | one process to audit | two: every CLI invocation is a privileged process |
| **process supervision** | `cmd.Wait()` → SIGCHLD → exit code + crash detection for free | daemon must poll cgroup events or watch `cgroup.events`; harder, racier |
| **agents-survive-restart (brief §6 P3 task 7)** | hard — currently a CAVEAT (§23). Needs `bpf.Adopt()` to re-open pinned maps | natural — the agent is a child of the CLI / init, not the daemon. Daemon restart is invisible to the running agent. |
| **parallelism** | one daemon = one serialization point on RunAgent | each `agentctl run` is independent; scales linearly |
| **CLI complexity** | minimal — JSON over Unix socket, no fork | fat — fork, env merge, cgroup binding, stdio handling, signal forwarding |
| **brief alignment** | matches §2, §4, §6 P2 task 5, §10 ("they conform to you") | diverges from §2 privilege model and §4 method shape |
| **work to switch (this branch)** | already built (4 phases, tagged v0.1.0) | rewrite IPC, demote daemon, move ~600 LOC into the CLI repo (which isn't ours) |

## Where Mehul's model is genuinely better

Two real wins, both narrow:

1. **Restart survival is free.** Our CAVEAT §23 (daemon restart doesn't re-adopt running agents) is solved by construction in his model. In ours, we fix it with `bpf.Adopt()` reading from `/sys/fs/bpf/agent-sandbox/<id>/`.
2. **HTTP/SSE is friendlier to the web UI (P5).** They can hit `:9000/events` directly without a Unix-socket bridge.

Neither is decisive:

- (1) is a finite engineering task we've already half-done with map pinning — `bpf.Adopt()` is <100 LOC.
- (2) is exactly what `internal/events/websocket.go` at `ws://127.0.0.1:7443/events` already provides.

## Recommendation

Keep ours. If P5 wants HTTP/SSE specifically, our WS endpoint already covers that case. If "restart survival" is the real motivator behind D-009, finish `bpf.Adopt()` (CAVEATS §23) — small, scoped, doesn't blow up the architecture.

The one thing worth verifying: does Mehul control the brief, or is D-009 his own design doc that diverged? If he authored a competing spec without team alignment, that's a coordination issue, not an architecture one — escalate to whoever owns scope rather than retro-fitting code to match.
