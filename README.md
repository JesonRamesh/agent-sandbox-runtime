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

## Try it now — any OS, no VM required

The orchestrator, model selection, and live dashboard work on **Mac,
Windows, and Linux** without a Linux VM. In local mode the agent runs
as a normal process — the kernel enforcement is inactive, but everything
else works: tool tracing, model switching, multi-agent scenarios, and
the event dashboard.

```bash
pip install pyyaml websocket-client openai
pip install -e .          # installs the orchestrator package
cd orchestrator
python -m orchestrator run -f examples/quickstart/scenario.yaml
```

To start the dashboard alongside it (requires Node 20+):

```bash
bash scripts/local-demo.sh
```

Or open this repo in [GitHub Codespaces](https://codespaces.new/Harrishayy/AgentOS) —
the devcontainer sets everything up automatically.

**Sandbox your existing agent in two lines:**

```python
from orchestrator import tool_tracer, emit_user_input, emit_agent_output

@tool_tracer          # emits [TOOL]/[RESULT] events automatically
def fetch_url(url: str) -> str:
    return requests.get(url).text
```

**Switch models without touching your code** — set `model` and `provider`
in your manifest and the orchestrator injects `MODEL`, `API_BASE_URL`,
and `API_KEY` as env vars:

```yaml
model: claude-sonnet-4-6
provider: anthropic
```

> **Local mode vs full stack:** The kernel-level sandbox policy
> (eBPF enforcement, `EPERM` on denied syscalls) only activates in
> full stack mode, which requires **Linux 6.8+**. See below.

---

## Spin up the whole thing in 5 minutes

You need a Linux 6.8+ environment. The kernel enforcement only runs on
Linux — the quickest path on a Mac is the one-command setup below.

### macOS — one command (Apple Silicon and Intel)

From the repo root:

```bash
bash scripts/setup-lima.sh
```

This installs Lima (via Homebrew if needed), boots an Ubuntu 24.04 VM,
runs `scripts/setup-vm.sh` inside it to install all dependencies and
activate the BPF LSM, reboots the VM if required, and builds the daemon.
When it finishes it prints exactly what to run next.

**Requires:** Homebrew and the repo checked out under your home directory.

### Windows — WSL 2

Install WSL 2 if you haven't already (run in PowerShell as Administrator):

```powershell
wsl --install
```

Then open a WSL terminal, clone the repo **inside the WSL filesystem**
(not under `/mnt/c/` — filesystem performance and file-watcher support
are much better in the native WSL fs), and follow the Linux steps:

```bash
bash scripts/setup-vm.sh   # installs deps; notes kernel enforcement limits on WSL
make all
```

**Local mode works fully in WSL** — orchestrator, tool tracing, multi-agent
scenarios, and the dashboard all run. WSL ports forward to your Windows
browser automatically, so `http://127.0.0.1:8765` just works.

Kernel enforcement (eBPF policy, `EPERM` on denied syscalls) requires a
real Linux kernel. For that on Windows, use the Vagrant path below or
a cloud Linux VM.

### Linux

On a native Linux 6.8+ machine:

```bash
bash scripts/setup-vm.sh   # installs deps, activates BPF LSM (reboot if prompted)
make all                    # builds bin/agentd, bin/agentctl, bpf/*.bpf.o
```

### Vagrant / VirtualBox (optional alternative)

If you specifically want VirtualBox rather than WSL or Lima:

```bash
bash scripts/setup-vagrant.sh
```

Requires [Vagrant](https://developer.hashicorp.com/vagrant/downloads) and
[VirtualBox](https://www.virtualbox.org/wiki/Downloads). Run from Git Bash
on Windows.

---

All commands below assume the build is done and you are inside the Linux
environment (VM shell or native Linux).

### Step 1 — start the daemon (terminal #1)

```bash
sudo ./bin/agentd \
  -bpf-dir=$(pwd)/bpf \
  -socket=/run/agent-sandbox.sock \
  -ws-addr=127.0.0.1:7443
```

The daemon must run as root (or with `CAP_BPF + CAP_NET_ADMIN +
CAP_SYS_ADMIN`) to load eBPF. It stays in the foreground; leave this
terminal open. You'll see startup logs ending in `daemon listening`.

### Step 2 — start the live dashboard (terminal #2, optional)

```bash
bash viewer/scripts/start-viewer.sh
```

Open **`http://127.0.0.1:8765`** in your normal Mac/host browser
(Lima and Vagrant auto-forward loopback ports). Two panes appear: LLM
events on the left, kernel events on the right. Real events stream in
once you launch an agent. The viewer also spawns a small bridge
process that subscribes to the daemon's event stream — so kernel
events show up in the dashboard automatically.

### Step 3 — run an agent (terminal #3)

```bash
# A manifest with no allowed_hosts — every connect should be denied.
sudo ./bin/agentctl --socket=/run/agent-sandbox.sock \
  run -f examples/blocked-net.yaml
# expected: agent prints "OK: kernel denied connect errno=1"

# A manifest with 1.1.1.1 in allowed_hosts — same connect should succeed.
sudo ./bin/agentctl --socket=/run/agent-sandbox.sock \
  run -f examples/allowed-net.yaml
# expected: agent prints "OK: connect succeeded"
```

Watch the dashboard while you do this — you'll see the deny event
appear in red on the right pane.

For a complete smoke test that asserts both verdicts in one go:

```bash
sudo bash examples/test-it.sh
```
### Or use the orchestrator

```bash
cd orchestrator
python -m orchestrator run -f examples/two_agent/scenario.yaml
python -m orchestrator status
```

### Step 4 — write your own manifest

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
| [`docs/RECIPES.md`](docs/RECIPES.md)                    | Common manifest and orchestrator patterns.                      |
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

| Subtree            | Language     | Purpose                                                            |
|--------------------|--------------|--------------------------------------------------------------------|
| `bpf/`             | C (eBPF)     | Kernel-side policy engine — LSM hooks for net, file, exec, creds   |
| `cmd/agentd/`      | Go           | The privileged daemon — cgroup + BPF + process lifecycle           |
| `cmd/agentctl/`    | Go           | The CLI — manifest validation, daemon RPC, event tail              |
| `cmd/test-client/` | Go           | A raw IPC client for protocol testing                              |
| `internal/`        | Go           | Shared libraries — `bpf`, `cgroup`, `events`, `ipc`, `policy`, etc.|
| `orchestrator/`    | Python       | LLM-driven launcher and prompt-injection demo                      |
| `viewer/`          | Node + React | Real-time event dashboard + daemon bridge                          |

## License

Apache 2.0 — see [LICENSE](LICENSE).
