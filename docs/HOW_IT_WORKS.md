# How It Works (in plain English)

If you build AI agents but have never touched the Linux kernel, here's
what each piece of this runtime does for you, without jargon. Read
this once and you'll know what's happening when you type
`agentctl run my-agent.yaml`.

For the deep technical tour — syscalls, eBPF verifier, cgroup
internals — see [`ARCHITECTURE.md`](ARCHITECTURE.md). This document
is the on-ramp.

---

## The kernel programs (`bpf/`) — the bouncer at the door

When your agent calls `requests.get("evil.com")`, that call eventually
becomes a `connect()` *syscall* — a request to the operating system's
kernel asking "please open this network connection." Right at that
moment, before the connection actually leaves the machine, the kernel
runs our small programs and asks them: "is this allowed for this
agent?" If the answer is no, the kernel returns an error and the
network packet is never sent.

**The agent itself can't disable or bypass this check** — the check
happens after the agent has already asked, in a place the agent has
no access to. Same idea applies to opening files, running new
programs, and changing privileges.

These programs are written in a tiny verified language called eBPF.
Verified means the kernel proves they're safe before running them
(no infinite loops, no out-of-bounds memory access). That's why we
can run security policy code inside the kernel without risking a
crash.

## The daemon (`cmd/agentd/`) — the supervisor that sets up the sandbox

Before each agent starts, something has to tell the kernel "this new
process is going to be `my-agent`, and *its* policy is the one in
this manifest." That's the daemon's job. When you ask to run an
agent, the daemon:

1. Creates a fresh, isolated bucket (a *cgroup*) for the new process.
2. Loads the policy from your manifest into kernel memory.
3. Starts your agent inside the bucket atomically — there is no
   window in which the agent is running without policy.
4. Listens to a stream of events from the kernel and writes them to
   logs and a live event feed.

It's the only privileged piece — your agent runs with normal user
permissions. The daemon needs four Linux capabilities
(`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE`) to talk to the kernel;
the agent gets none of them.

## The CLI (`cmd/agentctl/`) — your control panel

`agentctl` is what you actually type. `agentctl run -f my-agent.yaml`
reads your manifest, validates it (catching typos and bad host
patterns with line-precise error messages), and tells the daemon to
spin up the agent.

Other useful commands:

| Command                       | What it does                                            |
|-------------------------------|---------------------------------------------------------|
| `agentctl list`               | Shows running agents and their status                   |
| `agentctl logs <name>`        | Tails kernel events for one agent                       |
| `agentctl stop <agent-id>`    | Sends SIGTERM (then SIGKILL after 5 s) to an agent      |
| `agentctl manifest validate`  | Parses a manifest without contacting the daemon         |
| `agentctl daemon status`      | Confirms the daemon is up and responding                |

JSON output (`--json`) for piping into your own tooling.

## The orchestrator (`orchestrator/`) — for the LLM agent loop itself

This is the Python side. If your agent uses an LLM with tools (a
`fetch_url`, a `run_command`, etc.), the orchestrator is the harness
that:

- runs the tool loop,
- parses tool calls from the model's output,
- spawns the agent under the sandbox (via the daemon),
- pushes "the model just called tool X" events into the same stream
  where the kernel reports its verdicts — so kernel events and LLM
  events share an `agent_id` and you can correlate them.

It includes a worked **prompt injection demo**: a small "evil server"
returns text containing hidden instructions; the model gets hijacked
and tries to exfiltrate; the kernel says no; you see the attack land
harmlessly in the dashboard. Useful both as a teaching tool and as a
regression test for "does the kernel actually enforce what we
expect?"

## The viewer (`viewer/`) — the live dashboard

Open `http://localhost:8765` in your browser. Two panels:

- **Left — LLM events**: every tool call your model made, with
  arguments.
- **Right — kernel events**: every connect, file open, exec —
  coloured by allow / deny / audit.

When a kernel deny lines up in time with a tool call, the UI
highlights both — that's prompt injection caught red-handed.

There's also a tiny relay process (`viewer/server/bridge.js`) that
forwards events from the daemon's WebSocket into the dashboard, so
the moving parts stay decoupled. The dashboard never talks to the
daemon directly; the daemon never knows the dashboard exists.

---

## Putting it together (a 30-second mental model)

```
   you type:  agentctl run my-agent.yaml
                           │
                           ▼
   agentd      validates, asks kernel to apply policy P to agent A,
               starts your code inside the sandbox bucket
                           │
                           ▼
   your agent  runs normally — same Python, same Node, same shell —
               unless it tries something the manifest didn't permit
                           │
                           ▼
   kernel      every disallowed connect / open / exec returns EPERM
               and emits a "DENIED" event
                           │
                           ▼
   viewer      shows you each event live, correlates with LLM tool
               calls so injection attempts are obvious
```

The system's promise: **a hijacked agent can attempt anything; only
the things in your manifest succeed.**

---

## Want the deep version?

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — Linux primitives from
  scratch (syscalls, capabilities, cgroups, LSM), eBPF in 800 words,
  LLM agents in 600 words, then a full end-to-end walk-through of a
  single blocked connect.
- [`INTERFACES.md`](INTERFACES.md) — wire-protocol reference: IPC
  framing, every RPC method, every event schema.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what we defend against, what
  we don't, what an operator must assume for the defence to hold.
- [`DEVELOPMENT.md`](DEVELOPMENT.md) — how to build, test, and
  contribute.
