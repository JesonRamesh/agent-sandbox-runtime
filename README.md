# Agent Sandbox Runtime

**A Linux runtime that stops prompt-injected AI agents from doing damage.**
The policy lives in the kernel, not in the agent — so even an agent
that's been fully hijacked by a prompt injection cannot reach the
attacker's host, read your secrets, or escalate privileges. The bad
syscall fails with `EPERM`; the operator sees it land in a live
dashboard.

```
  agentctl run my-agent.yaml
              │
              ▼
       agentd daemon  ──── creates a sandbox, loads the policy
              │
              ▼
        your AI agent ──── runs normally inside the sandbox
              │
              ▼
   eBPF programs in the kernel  ──── allow the syscalls in the
                                     manifest, deny everything else
```

## What this is for

You should look at this project if you're:

- **Building an AI agent that touches a real machine.** Anything with
  a `fetch_url`, `run_command`, `read_file`, or `write_file` tool.
  Python guardrails in your agent code are not a defence against
  prompt injection — the agent itself is the layer the attacker is
  driving. This runtime moves the policy below the agent.
- **Running untrusted agents on shared infrastructure.** Multi-tenant
  hosts, CI runners, eval harnesses where the prompts come from
  outside.
- **Studying agent security.** The repo includes a worked prompt
  injection demo (`orchestrator/evil_server.py`) and a real-time
  dashboard so you can watch the attack land and the kernel block it.

If your agents are already running inside an unprivileged container
with a tight network policy, you have a partial answer to the same
problem. This runtime gives you a finer-grained, per-agent policy
(distinct allow-lists per agent, instead of one container-wide one)
and per-syscall observability (every denied attempt, with full
context, on the dashboard).

> Want a guided tour of how each piece works in plain English?
> See [`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md).
> For the deep technical version with Linux primitives taught from
> scratch, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Spin up the whole thing in 5 minutes

You need a Linux 6.8+ environment. On a Mac, the recommended path is
Lima (lightweight, native on Apple Silicon). All commands below
assume you're starting from a fresh checkout of this repo.

### Step 1 — boot a Linux VM (skip if you're already on Linux)

**Apple Silicon Mac** (M1/M2/M3/M4):

```bash
brew install lima
limactl start --name=agentsandbox \
  --cpus=4 --memory=4 --disk=30 \
  --mount-writable --mount=$(pwd) \
  template:ubuntu-lts
```

**Intel Mac / Windows / other**:

```bash
brew install vagrant       # macOS only
vagrant up                  # uses the Vagrantfile in this repo
vagrant ssh
```

### Step 2 — open a shell inside the VM

```bash
limactl shell agentsandbox     # or: vagrant ssh
cd /Users/<you>/Documents/AgentOS    # (Lima mounts your $HOME read-write at the same path)
```

### Step 3 — install dependencies + activate BPF LSM

```bash
bash scripts/setup-vm.sh
```

The script installs Go, Node, the eBPF toolchain, and verifies the
BPF Linux Security Module is active. **If the script prints a yellow
"REBOOT REQUIRED" banner**, run `sudo reboot`, log back in, and
verify with:

```bash
cat /sys/kernel/security/lsm | grep -o bpf
# → bpf
```

This is the most important check. Without `bpf` in this list, every
LSM hook will load but never fire — every policy decision will
silently allow.

### Step 4 — build everything

```bash
make all
```

Produces:

- `bin/agentd` — the daemon
- `bin/agentctl` — the CLI
- `bin/test-client` — a raw IPC test client
- `bpf/*.bpf.o` — the four eBPF programs

### Step 5 — start the daemon (terminal #1)

```bash
sudo ./bin/agentd \
  -bpf-dir=$(pwd)/bpf \
  -socket=/run/agent-sandbox.sock \
  -ws-addr=127.0.0.1:7443
```

The daemon must run as root (or with `CAP_BPF + CAP_NET_ADMIN +
CAP_SYS_ADMIN`) to load eBPF. It stays in the foreground; leave this
terminal open. You'll see startup logs ending in `daemon listening`.

### Step 6 — install the dashboard's sudoers fragment (one time)

The dashboard's "run scenario" buttons spawn `agentctl run` against the
root-owned daemon socket. This one-line script installs a tightly-scoped
`/etc/sudoers.d/` fragment that lets the unprivileged viewer process
do exactly that — and *only* that — without a password prompt:

```bash
sudo bash scripts/install-viewer-sudoers.sh
```

The grant covers only `agentctl run -f <playground-dir>/*` against the
well-known socket path. Skip this step if you only intend to run agents
manually via `sudo ./bin/agentctl …` from a terminal — the dashboard
will still show events, just without the in-browser run buttons.

### Step 7 — start the live dashboard (terminal #2)

```bash
HOST=0.0.0.0 bash viewer/scripts/start-viewer.sh
```

Open **`http://127.0.0.1:8765`** in your host browser (Lima and Vagrant
auto-forward loopback ports; `HOST=0.0.0.0` is required so VirtualBox's
NAT-to-loopback forward actually reaches the Node process inside the
guest). The dashboard gives you:

- A **demo scenarios** strip at the top with one ▶ button per manifest in
  [`examples/playground/`](examples/playground/). Click to fire; the
  button shows ✓ or ✗ when done.
- A **▸ permissions** toggle next to each scenario that expands to a
  4-pillar (NET / FILE / EXEC / CRED) card showing what the manifest
  allows in plain English — colour-coded by tone (red restrictive,
  yellow permissive, green allow).
- A **per-pillar stats row** with allowed / blocked counters per pillar
  plus tool-call count and uptime; the blocked counter pulses red when
  it ticks up.
- The **kernel events pane** shows every verdict with a pillar chip
  (`NET` / `FILE` / `EXEC` / `CRED`), an `ALLOW` / `BLOCK` badge, and
  the daemon's plain-English deny reason
  (e.g. *"8.8.8.8:53 not in allowed_hosts [1.1.1.1:80]"*).
- **Click any kernel row** → side panel with full event detail
  (matched rule, reason code, raw JSON). Esc closes it.
- A **↺ reset** button (top-right) clears the dashboard back to its
  initial state without dropping the WebSocket connection.

### Step 8 — run an agent

You can either click ▶ on a dashboard scenario, or fire one from a
shell:

```bash
sudo ./bin/agentctl --socket=/run/agent-sandbox.sock \
  run -f examples/playground/02-network-deny.yaml
# expected: agent prints "OK: kernel denied connect() errno=1"

sudo ./bin/agentctl --socket=/run/agent-sandbox.sock \
  run -f examples/playground/01-baseline-allowed.yaml
# expected: agent prints "DONE — all actions allowed"
```

For a complete smoke test that asserts the original net-pillar verdicts
in one go:

```bash
sudo bash examples/test-it.sh
```

### Step 9 — write your own manifest

```yaml
# my-agent.yaml
name: my-agent
command: ["python3", "agent.py"]
mode: enforce                  # "audit" for observe-only mode
allowed_hosts:
  - api.openai.com:443
  - api.anthropic.com:443
allowed_paths:
  - /tmp/agent-workdir
allowed_bins:                  # optional; empty = allow any binary
  - /usr/bin/python3
forbidden_caps:                # optional; refuses these privilege grants
  - CAP_SYS_ADMIN
  - CAP_BPF
working_dir: /tmp/agent-workdir
env:
  AGENT_NAME: my-agent
```

Then `sudo ./bin/agentctl --socket=/run/agent-sandbox.sock run -f my-agent.yaml`.

Full manifest schema and validation rules:
[`docs/INTERFACES.md`](docs/INTERFACES.md).

---

## Stopping it cleanly

```bash
# In terminal #1: Ctrl-C the daemon. Any agents it spawned will be reaped.
# In terminal #2: Ctrl-C the viewer.
# Or, from anywhere:
sudo pkill -INT agentd
sudo pkill -INT -f "node server.js"
```

To remove the VM entirely (Lima):

```bash
limactl stop agentsandbox
limactl delete agentsandbox
```

---

## Documentation

| Document                                                | What it covers                                                  |
|---------------------------------------------------------|-----------------------------------------------------------------|
| [`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md)          | Plain-English tour of every stage. Read this first.             |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)          | Deep technical guide: Linux primitives, eBPF, LLM agents, full data path. |
| [`docs/INTERFACES.md`](docs/INTERFACES.md)              | Wire-protocol reference: IPC framing, RPC methods, event schemas. |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)          | What we defend against, what we don't, operator assumptions.    |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)            | How to build, test, and contribute.                             |
| [`docs/operations.md`](docs/operations.md)              | Running the daemon as a long-lived systemd service.             |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)                    | Branch and commit conventions, PR checklist.                    |

---

## Requirements

- Ubuntu 24.04 (kernel 6.8+) or any distro on kernel 6.8+
- `CONFIG_BPF_LSM=y` **and** `bpf` in the runtime `lsm=` cmdline
  (`scripts/setup-vm.sh` handles this automatically)
- cgroup v2 unified hierarchy (Ubuntu 24.04 default)
- Go 1.23, Node 20+, Python 3.10+
- For production: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` on the
  daemon. The systemd unit in [`deploy/systemd/`](deploy/systemd/)
  grants exactly those.

## Components

| Subtree                       | Language     | Purpose                                                            |
|-------------------------------|--------------|--------------------------------------------------------------------|
| `bpf/`                        | C (eBPF)     | Kernel-side policy engine — LSM hooks for net, file, exec, creds   |
| `cmd/agentd/`                 | Go           | The privileged daemon — cgroup + BPF + process lifecycle           |
| `cmd/agentctl/`               | Go           | The CLI — manifest validation, daemon RPC, event tail              |
| `cmd/test-client/`            | Go           | A raw IPC client for protocol testing                              |
| `internal/`                   | Go           | Shared libraries — `bpf`, `cgroup`, `events`, `ipc`, `policy`, etc.|
| `internal/policy/attribute.go`| Go           | Userspace post-hoc explanation of every kernel verdict (drives the dashboard's deny-reason text) |
| `orchestrator/`               | Python       | LLM-driven launcher and prompt-injection demo                      |
| `viewer/server/`              | Node         | WebSocket relay + bridge from `agentd` + scenario-runner HTTP API  |
| `viewer/server/transform.js`  | Node         | Daemon→UI event schema translator (pillar-aware types, friendly agent names) |
| `viewer/server/runner.js`     | Node         | Sandboxed `agentctl run` spawner backing the dashboard's ▶ buttons |
| `viewer/server/manifest.js`   | Node         | Tiny YAML reader + permissions summarizer for the ▸ permissions panel |
| `viewer/viewer-app/`          | React        | Dashboard UI — pillar stats, kernel rows, event detail, scenario runner |
| `examples/playground/`        | YAML         | Demo manifests the dashboard's ▶ buttons fire (one per pillar)     |
| `scripts/install-viewer-sudoers.sh` | bash    | Installs the tightly-scoped sudoers fragment the relay needs to spawn `agentctl run` |

## License

Apache 2.0 — see [LICENSE](LICENSE).
