# Wire Protocol Reference

This document is the canonical reference for every cross-component
contract in the agent-sandbox runtime. If you implement a new client
(another orchestrator, an alternative dashboard, a CI tool that
introspects running agents) read this. The Go types backing each
schema live in [`internal/ipc/protocol.go`](../internal/ipc/protocol.go)
(daemon side) and [`internal/client/protocol.go`](../internal/client/protocol.go)
(CLI side); both are kept lock-step with this document.

## Surfaces

| Surface         | Address                                  | Auth   | Speakers                |
|-----------------|------------------------------------------|--------|-------------------------|
| IPC RPC         | `/run/agent-sandbox.sock` (Unix DGRAM)   | uid 0  | agentctl, orchestrator  |
| Event stream    | `ws://127.0.0.1:7443/events`             | none*  | dashboards, bridges     |
| Viewer relay    | `ws://127.0.0.1:8765`                    | none*  | senders, viewers        |

\* All sockets bind to loopback only; uid 0 (or the daemon user) is
required to read the IPC socket via filesystem permissions.

---

## 1. IPC framing

Every direction (client→server and server→client) sends
**length-prefixed JSON frames** over the Unix socket:

```
+──────────────────────────+──────────────────────────+
| 4 bytes, big-endian uint | N bytes of UTF-8 JSON    |
+──────────────────────────+──────────────────────────+
```

Maximum frame size: 16 MiB. Frames larger than this are an error and
the daemon closes the connection.

Worked example — a `DaemonStatus` request:

```
hex:    00 00 00 21
text:    [length=33]
json:    {"method":"DaemonStatus","params":{}}
```

A successful response:

```
hex:    00 00 00 78
text:    [length=120]
json:    {"ok":true,"result":{"version":"0.1.0-phase3","uptime_sec":4287,"socket":"/run/agent-sandbox.sock","agents":3}}
```

A typed error:

```
json:    {"ok":false,"error":{"code":"INVALID_MANIFEST","message":"…"}}
```

## 2. Request / Response envelopes

Client → server:

```json
{
  "method": "RunAgent",
  "params": { ... method-specific ... }
}
```

Server → client (one frame per request, except `StreamEvents` — see §4):

```json
{ "ok": true,  "result": { ... method-specific ... } }
{ "ok": false, "error":  { "code": "...", "message": "..." } }
```

`ok=true` ⇒ `result` populated. `ok=false` ⇒ `error` populated.

## 3. Methods

### 3.1 RunAgent

Submit a manifest; the daemon spawns the agent.

**Request params**:

```json
{
  "manifest": {
    "name":           "my-agent",
    "command":        ["python3", "agent.py"],
    "mode":           "enforce",
    "allowed_hosts":  ["api.openai.com:443", "10.0.0.0/8"],
    "allowed_paths":  ["/tmp/work"],
    "allowed_bins":   ["/usr/bin/python3"],
    "forbidden_caps": ["CAP_SYS_ADMIN"],
    "working_dir":    "/tmp/work",
    "env":            {"FOO": "bar"},
    "user":           "1000",
    "stdin":          "close",
    "timeout_ns":     0,
    "description":    "human note"
  },
  "manifest_source":  { "path": "/path/my.yaml", "sha256": "…" },
  "restart_on_crash": false,
  "max_restarts":     0
}
```

**Result**:

```json
{
  "name":            "my-agent",
  "agent_id":        "agt_a1b2c3d4",
  "pid":             14963,
  "cgroup_path":     "/sys/fs/cgroup/agent-sandbox/agt_a1b2c3d4",
  "started_at":      "2026-04-30T11:51:38.027Z",
  "policy_summary":  "hosts:1 paths:1 bins:1 mode:enforce"
}
```

**Errors**: `INVALID_MANIFEST`, `CGROUP_FAILED`, `BPF_LOAD_FAILED`,
`LAUNCH_FAILED`, `INTERNAL`.

### 3.2 StopAgent

Idempotent: SIGTERM, wait 5 s, SIGKILL.

**Request**: `{ "agent_id": "agt_a1b2c3d4" }`
**Result**:  `{ "ok": true }`
**Errors**:  `AGENT_NOT_FOUND`.

### 3.3 ListAgents

**Request**: `{}`
**Result**:

```json
{
  "agents": [
    { "agent_id": "...", "name": "...", "status": "running",
      "started_at": "...", "pid": 14963 }
  ]
}
```

`status` ∈ `running | exited | crashed`.

### 3.4 AgentLogs

**Request**: `{ "agent_id": "...", "tail_n": 100 }`
**Result**:  `{ "lines": [Event, Event, ...] }`

If `tail_n=0`, returns all retained events for that agent (subject to
the daemon's per-agent log rotation policy — currently 10 MB).

### 3.5 StreamEvents (special: streaming)

Subscribes to live events. `agent_id=""` means "all agents."

**Request**: `{ "agent_id": "..." }` (empty for all)

**Response**: each event arrives as one frame containing
`{"ok":true,"result":<Event>}`. The stream ends when the client
closes the socket or the daemon receives SIGTERM.

### 3.6 IngestEvent

Used by the orchestrator (P4) to push LLM events into the daemon's
fanout pipeline so they share the same `agent_id` namespace as kernel
events.

**Request**: `{ "event": <Event> }`
Example:

```json
{
  "agent_id": "agt_a1b2c3d4",
  "event": {
    "type": "llm.tool_call",
    "ts": "2026-05-11T12:00:00.000000Z",
    "details": {
      "tool": "fetch_url",
      "args": { "url": "https://example.com" }
    }
  }
}
```

**Result**:  `{}`

The daemon rejects non-`llm.*` event types. It does not persist these
in the registry; it only forwards them to subscribers.

### 3.7 DaemonStatus

**Request**: `{}`
**Result**:

```json
{
  "version":     "0.1.0-phase3",
  "uptime_sec":  4287,
  "socket":      "/run/agent-sandbox.sock",
  "agents":      3,
  "bpf_dir":     "/usr/lib/agent-sandbox/bpf",
  "active_lsms": "lockdown,capability,landlock,yama,apparmor,bpf"
}
```

---

## 4. Event schema

All events share a common envelope:

```json
{
  "ts":       "RFC 3339 nanosecond timestamp",
  "agent_id": "agt_a1b2c3d4",
  "type":     "net.connect | file.open | exec | creds.setuid | …",
  "pid":      12345,
  "details":  { ... type-specific ... }
}
```

### 4.1 Kernel event types

| `type`           | Source                | Verdict-bearing | Key `details` fields                    |
|------------------|-----------------------|-----------------|------------------------------------------|
| `net.connect`    | lsm/socket_connect    | yes             | `family`, `daddr`, `dport`, `verdict`    |
| `net.sendto`     | tp/sys_enter_sendto   | no (audit)      | `comm`, `verdict`                        |
| `file.open`      | lsm.s/file_open       | yes             | `path`, `flags`, `verdict`               |
| `exec`           | tp/sched_process_exec | no (audit)      | `filename`, `comm`, `ppid`, `verdict`    |
| `exec.bprm`      | lsm/bprm_check_security| yes            | `filename`, `verdict`                    |
| `creds.setuid`   | lsm/task_fix_setuid   | yes             | `old_id`, `new_id`, `verdict`            |
| `creds.setgid`   | lsm/task_fix_setgid   | yes             | `old_id`, `new_id`, `verdict`            |
| `creds.capset`   | lsm/capset            | yes             | `cap_effective`, `verdict`               |

`verdict` ∈ `allow | deny | audit`.

Common header fields the daemon adds: `cgroup_id`, `comm`, `tgid`,
`uid`, `gid`, `time_ns` (kernel `bpf_ktime_get_ns()`).

### 4.2 Lifecycle events

Synthesized by the daemon, not the kernel:

| `type`                 | When emitted                                | Key `details` fields |
|------------------------|---------------------------------------------|----------------------|
| `agent.started`        | After `cmd.Start()` succeeds                | none                 |
| `agent.exited`         | When `cmd.Wait()` returns nil               | `exit_code`          |
| `agent.crashed`        | When `cmd.Wait()` returns a non-nil error   | `exit_code`          |
| `agent.kill_requested` | When StopAgent has been called              | none                 |
| `agent.stdout`         | For each stdout line emitted by the agent   | `line`, `truncated`  |
| `agent.stderr`         | For each stderr line emitted by the agent   | `line`, `truncated`  |

`agent.stdout` and `agent.stderr` preserve agent text as line-oriented
events so alternate dashboards and orchestrators can parse semantic
markers without shelling out to `agentctl logs`.

### 4.3 Orchestrator events

Pushed by the orchestrator via `IngestEvent`:

| `type`            | `details` fields                                            |
|-------------------|-------------------------------------------------------------|
| `llm.tool_call`   | `tool` (name), `args` (JSON), `request_id` (model-supplied) |
| `llm.tool_result` | `tool`, `ok`, `request_id`, plus tool-specific result data  |
| `llm.user_input`  | `text`                                                      |
| `llm.agent_output`| `text`                                                      |
| `llm.injection_suspected` | `confidence`, `reason`                              |

Raw stdout/stderr stays in `agent.stdout` / `agent.stderr`. The
orchestrator only ingests parsed semantic events back into the daemon
to avoid a self-referential loop.

---

## 5. WebSocket: daemon `:7443/events`

A simple GET upgrade. Optional query string `?agent=<id>` filters to
one agent. No subprotocol.

Each message is a single JSON event matching §4 — no framing other
than the WebSocket message boundary. The daemon never coalesces
events into arrays.

The daemon does not enforce backpressure: if a client falls behind,
the kernel's TCP send buffer fills and the daemon drops the
connection. Fast clients should not be affected.

---

## 6. WebSocket: viewer relay `:8765`

Each connecting client sends one handshake message within
`HANDSHAKE_TIMEOUT_MS` (3000) of opening. Two roles:

```json
{ "role": "sender", "name": "agentd-bridge" }
```

```json
{ "role": "viewer" }
```

**Sender** clients send raw JSON event messages; the relay broadcasts
each to every connected viewer. **Viewer** clients receive events
only.

If no handshake is received in time, the client is treated as a
viewer and warned in the relay log.

The relay does no buffering, replay, or persistence. Late-arriving
viewers see only events from after they connected.

---

## 7. Backwards-compatibility policy

- Adding a new method, a new event type, or a new optional field is
  non-breaking and may happen in a minor release.
- Renaming or removing a method, event type, or required field is a
  breaking change and bumps the major version.
- Behavior changes (e.g. tightening manifest validation) are
  documented in [`docs/CHANGELOG.md`](CHANGELOG.md) (planned).

When you implement a new client, parse JSON tolerantly: ignore unknown
fields and unknown event types so a daemon upgrade doesn't break you.
