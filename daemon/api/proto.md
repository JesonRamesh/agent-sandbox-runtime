# Sandbox Daemon IPC Contract

This document is the **source of truth** for the IPC API between the sandbox daemon (P2) and any client (P3's `agentctl`, P4's orchestrator, P5's UI). When the daemon's behavior diverges from this doc, the doc is right and the daemon is wrong.

## Transport

- **Socket**: Unix domain socket at `/run/agent-sandbox.sock` (root-owned, mode `0600`).
- **Framing**: 4-byte big-endian length prefix, then UTF-8 JSON. One frame per logical message in either direction.
- **Connection model**:
  - One request per connection for the **request/response** methods (RunAgent, StopAgent, ListAgents, AgentLogs, DaemonStatus). The server reads one request frame, writes one response frame, closes.
  - Persistent for `StreamEvents` — the client sends one request frame, the server writes event frames until either side closes.
- **Errors**: every response is one of:
  ```json
  { "ok": true,  "result": { ... } }
  { "ok": false, "error": { "code": "string", "message": "string" } }
  ```
  Error codes are stable strings; messages are human-readable.

## Methods (v0.1)

### `RunAgent`

Launch an agent in a fresh sandbox.

```jsonc
// request
{ "method": "RunAgent", "params": { "manifest": <Manifest> } }
// response
{ "ok": true, "result": { "agent_id": "string" } }
```

`agent_id` is opaque (e.g., `agt_<8-hex>`). Use it for all subsequent calls.

### `StopAgent`

Stop a running agent. Idempotent — stopping an unknown or already-exited agent returns `ok: true`.

```jsonc
{ "method": "StopAgent", "params": { "agent_id": "string" } }
{ "ok": true, "result": { "ok": true } }
```

### `ListAgents`

```jsonc
{ "method": "ListAgents", "params": {} }
{ "ok": true, "result": { "agents": [<AgentSummary>, ...] } }
```

### `AgentLogs`

Returns the last `tail_n` events for one agent. Reads from the per-agent log file at `/var/log/agent-sandbox/<agent-id>.log`.

```jsonc
{ "method": "AgentLogs", "params": { "agent_id": "string", "tail_n": 100 } }
{ "ok": true, "result": { "lines": [<Event>, ...] } }
```

### `StreamEvents`

Persistent connection. Server pushes one `Event` JSON per frame. `agent_id` is optional — omit to subscribe to all agents.

```jsonc
// request (one frame)
{ "method": "StreamEvents", "params": { "agent_id": "string?" } }
// response (many frames, until close)
{ "ok": true, "result": <Event> }
{ "ok": true, "result": <Event> }
...
```

### `DaemonStatus`

```jsonc
{ "method": "DaemonStatus", "params": {} }
{ "ok": true, "result": { "version": "string", "uptime_sec": 0, "agent_count": 0 } }
```

## Schemas

### `Manifest`

P3 owns the YAML format. P3 parses YAML and sends parsed JSON to the daemon. The four guardrail fields (`allowed_hosts`, `allowed_paths`, `allowed_bins`, `forbidden_caps`) feed directly into the kernel-side `struct policy` defined in `daemon/bpf/common.h.reference` — they correspond one-to-one to the four eBPF pillars (network / file / exec / creds).

```jsonc
{
  "name": "string",                  // human-readable name; not unique
  "command": ["string", ...],        // argv; required, length >= 1
  "mode": "audit | enforce",         // default "enforce"; "audit" emits events but never blocks
  "allowed_hosts": ["string", ...],  // "host[:port]" or "ip[/cidr][:port]"; default port 443; v0 is IPv4 only
  "allowed_paths": ["string", ...],  // path prefixes for the file pillar (bpf_d_path resolved)
  "allowed_bins":  ["string", ...],  // exec allow-list (full path); empty = allow all binaries
  "forbidden_caps": ["CAP_NAME", ...], // capabilities the agent must not hold; e.g. "CAP_SYS_ADMIN"
  "env": {"KEY": "VALUE"},           // extra env vars (merged onto daemon env)
  "working_dir": "string"            // optional; default = daemon cwd
}
```

Field limits (mirroring `bpf/common.h.reference`):

- `allowed_hosts` — up to 64 resolved IP+port entries
- `allowed_paths` — up to 64 entries, each ≤ 255 chars
- `allowed_bins`  — up to 32 entries, each ≤ 255 chars
- `forbidden_caps` — any subset of `man 7 capabilities` names; the daemon validates each name before accepting the manifest.

Concurrent agents are bounded by the kernel's `policies` ARRAY map (`MAX_POLICIES = 32` today). The 33rd `RunAgent` returns `BPF_LOAD_FAILED` with a message about capacity.

DNS rotation after launch is not handled — see `LIMITATIONS.md`.

### `AgentSummary`

```jsonc
{
  "agent_id": "string",
  "name": "string",
  "status": "running | exited | crashed",
  "started_at": "RFC3339Nano",
  "pid": 1234
}
```

### `Event`

Produced by the daemon, consumed by the CLI (via `AgentLogs`/`StreamEvents`) and the UI (via WebSocket). The `type` discriminator covers the four kernel pillars plus three lifecycle events. `details` carries pillar-specific payload plus a common header (`verdict`, `comm`, `tgid`, `uid`, `gid`, `time_ns`, `cgroup_id`).

```jsonc
{
  "ts": "2026-04-27T15:04:05.123456789Z",
  "agent_id": "string",
  "type": "net.connect | net.sendto | file.open | exec | creds.setuid | creds.setgid | creds.capset | agent.started | agent.exited | agent.crashed",
  "pid": 1234,
  "details": { ... type-specific ... }
}
```

Common `details` fields on every kernel-pillar event (any of the `net.*`, `file.*`, `exec`, `creds.*` types):

```jsonc
{
  "verdict":   "allow | deny | audit",
  "comm":      "curl",          // 16-char comm field of the syscalling task
  "tgid":      1234,
  "uid":       1000,
  "gid":       1000,
  "time_ns":   1714210000000000000,
  "cgroup_id": 99
}
```

Pillar-specific `details` (merged with the common fields above):

- `net.connect`, `net.sendto`:
  ```jsonc
  { "family": 2, "dport": 443, "daddr": "1.2.3.4" }
  ```
  `family` is `AF_INET=2` (only AF_INET is enforced in v0; v6 events are not emitted).
- `file.open`:
  ```jsonc
  { "flags": 32768, "path": "/etc/shadow" }
  ```
- `exec`:
  ```jsonc
  { "ppid": 1, "filename": "/usr/bin/curl" }
  ```
- `creds.setuid`, `creds.setgid`, `creds.capset`:
  ```jsonc
  { "old_id": 1000, "new_id": 0, "cap_effective": 9007199254740992 }
  ```
  `cap_effective` is the kernel capability bitmask (see `man 7 capabilities`); non-zero only on `creds.capset`.

Lifecycle `details`:

- `agent.started`:
  ```jsonc
  { "command": ["...", "..."], "cgroup_path": "/sys/fs/cgroup/agent-sandbox/agt_xxx", "cgroup_id": 99, "policy_id": 3 }
  ```
- `agent.exited`:
  ```jsonc
  { "exit_code": 0, "duration_sec": 12.3 }
  ```
- `agent.crashed`:
  ```jsonc
  { "exit_code": 1, "signal": "SIGSEGV", "duration_sec": 12.3 }
  ```

## Policy schema (BPF maps)

The daemon-internal BPF policy maps follow the layout in `daemon/bpf/common.h.reference` (frozen contract with the eBPF engineer, P1). Clients never see this — it's documented here because P5 may want to inspect maps via `bpftool` and needs to interpret keys/values.

Two-tier indirection:

```c
// HASH map: cgroup_id -> policy_id (0 = unmanaged, default ALLOW + AUDIT)
__u64 cgroup_id   ->   __u32 policy_id

// ARRAY map: policy_id -> struct policy
struct policy {
    __u32 mode;                 // 0 = audit, 1 = enforce
    __u32 n_hosts; __u32 n_paths; __u32 n_bins;
    __u64 forbidden_caps;       // bitmask of cap bits to deny
    struct host_rule   hosts[64];  // {addr_v4 BE, prefix_len, port}
    struct path_rule   paths[64];  // {prefix[256]} — prefix-match
    struct binary_rule bins[32];   // {path[256]}   — exact path match
};
```

Each agent receives a freshly-allocated `policy_id ∈ [1, MAX_POLICIES=32]` from the daemon's allocator. The daemon writes:

1. `policies[policy_id] = compiled_policy` (struct above)
2. `cgroup_policy[agent_cgroup_id] = policy_id`

…in that order, so the kernel's first lookup never reads a half-populated `struct policy`. On agent exit, the daemon clears `cgroup_policy[cgroup_id]`, zeros `policies[policy_id]`, and returns the id to the allocator.

Lookup semantics in the kernel programs (see `bpf/network.bpf.c` etc.):

- A cgroup with no `cgroup_policy` entry → `pol_id = 0` → "unmanaged" → **allow + no event** (the program early-returns).
- A cgroup whose policy is `mode = audit` → events emitted with `verdict = audit`, syscalls always allowed.
- A cgroup whose policy is `mode = enforce` → events emitted with `verdict = allow | deny`; deny returns `-EPERM`.

The `MAX_POLICIES = 32` limit caps concurrent agents per host. Bumping it requires recompiling Mehul's `bpf/common.h` and the four `.bpf.o` objects.

DNS rotation after launch is not handled — see `LIMITATIONS.md`.

## WebSocket (Phase 3+)

Same `Event` schema, served at `ws://127.0.0.1:7443/events` with optional `?agent=<id>`. Localhost-bind only; no auth in v0.1.

## Out of scope (v0.2 or later)

- Encryption / authentication on either the Unix socket or WebSocket.
- HTTP / gRPC remote API.
- Multiple manifests per request, manifest validation hooks.
- Hot policy reload (changing `allowed_hosts` on a running agent).
- Filesystem policy (`allowed_paths`).
- Per-event filtering server-side (clients filter what they need).

## Error codes

Stable across versions:

| code | meaning |
|---|---|
| `INVALID_MANIFEST` | manifest failed validation (missing field, bad shape) |
| `AGENT_NOT_FOUND` | agent_id does not match any registered agent |
| `CGROUP_FAILED` | cgroup creation or write failed (see message) |
| `BPF_LOAD_FAILED` | eBPF program load/attach failed (see message) |
| `LAUNCH_FAILED` | exec.Cmd.Start returned an error |
| `INTERNAL` | catch-all for unexpected errors; message includes details |
