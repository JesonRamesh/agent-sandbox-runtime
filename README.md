# Agent Sandbox Runtime

**A Linux-only runtime that stops prompt-injected AI agents from doing damage.**
The policy lives in the kernel, not in the agent — so even an agent
that's been fully hijacked by a prompt injection cannot reach the
attacker's host, read your secrets, or escalate privileges. The bad
syscall fails with `EPERM`; the operator sees it land in a live
dashboard.

> **⚠️ Platform: Linux 6.8+ required.** The entire sandbox — daemon,
> eBPF enforcement, cgroup isolation — is Linux-only. It cannot run on
> macOS or Windows natively. Mac and Windows users must use a Linux VM
> (Lima, Vagrant, or cloud). A limited **local mode** exists for
> exploring the Python orchestrator and dashboard on any OS, but it
> provides **no kernel-level security enforcement**.

```
  agentctl run -f my-agent.yaml
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

> **GitHub repo:** [Harrishayy/AgentOS](https://github.com/Harrishayy/AgentOS)

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
  injection demo (`orchestrator/examples/prompt_injection/`) and a
  real-time dashboard so you can watch the attack land and the kernel
  block it.

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

## Try the orchestrator (local mode — any OS, no security enforcement)

> **This is not the sandbox.** Local mode lets you explore the Python
> orchestrator, tool tracing, model switching, and the live dashboard
> on Mac, Windows, or Linux — but the agent runs as a **normal,
> unsandboxed process**. There is no kernel enforcement, no `EPERM`,
> no cgroup isolation. For the actual security sandbox, see
> ["Spin up the whole thing"](#spin-up-the-whole-thing-in-5-minutes-linux-required)
> below (Linux 6.8+ required).

```bash
pip install pyyaml websocket-client
pip install -e .          # installs the orchestrator package + `orchestrator` CLI
cd orchestrator
python -m orchestrator run -f examples/quickstart/scenario.yaml
```

> **Note:** The quickstart scenario runs in simulation mode by default.
> To use a real LLM, set `model` and `provider` in the agent manifest
> and export your API key (e.g. `export OPENAI_API_KEY=...`). See
> [`docs/RECIPES.md`](docs/RECIPES.md) for framework-specific examples
> (OpenAI SDK, Anthropic Claude SDK, LangChain).

To start the dashboard alongside it (requires Node 20+):

```bash
bash scripts/local-demo.sh
```

Or open this repo in [GitHub Codespaces](https://codespaces.new/Harrishayy/AgentOS) —
the devcontainer installs all dependencies automatically for local-mode
development (orchestrator, tool tracing, dashboard — **no kernel
enforcement, no sandbox security**).

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

> **⚠️ Local mode is not sandboxed.** The kernel-level security
> (eBPF enforcement, `EPERM` on denied syscalls, cgroup isolation)
> only works on **Linux 6.8+** with the full daemon running. Local
> mode is useful for development and demonstration only — it provides
> **zero security guarantees**. See below for full-stack setup.

---

## Spin up the whole thing in 5 minutes (Linux required)

The sandbox is a **Linux-only system**. The daemon (`agentd`), the eBPF
programs, the cgroup isolation, and all kernel-level enforcement require
**Linux 6.8+** with `CONFIG_BPF_LSM=y` and `bpf` in the kernel's `lsm=`
command line. There is no macOS or Windows port — Mac and Windows users
must run a Linux VM. The quickest paths are below.

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

### Windows — GitHub Codespaces (local mode) or cloud VM (full enforcement)

The kernel enforcement layer requires Linux 6.8+ with the BPF LSM
enabled. Neither WSL 2 nor the current Codespaces devcontainer provides
this — both run in **local mode** (orchestrator, tool tracing, and
dashboard work; kernel-level `EPERM` enforcement does not).

**Local mode via Codespaces** — the fastest path to explore:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Harrishayy/AgentOS)

The devcontainer installs Python, Node, and all orchestrator
dependencies. Once the codespace is ready:

```bash
cd orchestrator
python -m orchestrator run -f examples/quickstart/scenario.yaml
```

The dashboard at `http://127.0.0.1:8765` is forwarded to your browser
automatically.

**Full enforcement** requires a Linux 6.8+ environment. On Windows,
the recommended path is a cloud VM (Ubuntu 24.04 on EC2, Azure, GCP)
or a Vagrant/VirtualBox VM:

```bash
bash scripts/setup-vagrant.sh
```

Requires [Vagrant](https://developer.hashicorp.com/vagrant/downloads) and
[VirtualBox](https://www.virtualbox.org/wiki/Downloads). Run from Git Bash.

> **WSL 2 (local mode only):** WSL 2 works for the orchestrator,
> tool tracing, and dashboard. The kernel enforcement is unavailable
> because WSL uses Microsoft's custom kernel without BPF LSM support.

### Linux

On a native Linux 6.8+ machine:

```bash
bash scripts/setup-vm.sh   # installs deps, activates BPF LSM (reboot if prompted)
make all                    # builds bin/agentd, bin/agentctl, bpf/*.bpf.o
```

### Vagrant / VirtualBox (optional alternative)

If you specifically want VirtualBox rather than Lima:

```bash
bash scripts/setup-vagrant.sh
```

Requires [Vagrant](https://developer.hashicorp.com/vagrant/downloads) and
[VirtualBox](https://www.virtualbox.org/wiki/Downloads).

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
CAP_SYS_ADMIN + CAP_SYS_RESOURCE`) to load eBPF. It stays in the foreground; leave this
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

The orchestrator supports multi-agent scenarios with dependencies:

```yaml
# scenario.yaml
name: research-writer-pipeline
agents:
  - id: research
    manifest: ./research-agent.yaml
  - id: writer
    manifest: ./writer-agent.yaml
    depends_on: [research]
    launch_when: success
```

More examples:

| Directory | What it demonstrates |
|-----------|---------------------|
| `orchestrator/examples/quickstart/` | Simplest possible agent — runs in simulation or with a real LLM |
| `orchestrator/examples/single_agent/` | One agent, one manifest, no daemon required |
| `orchestrator/examples/two_agent/` | Pipeline: research agent → writer agent |
| `orchestrator/examples/fanout/` | Three independent agents launched in parallel |
| `orchestrator/examples/code_exec/` | Sandboxed agent: no network, one binary, one writable path |
| `orchestrator/examples/prompt_injection/` | Worked prompt-injection attack + kernel block demo |
| `examples/playground/` | 9 graduated manifests — from baseline to cleartext-egress deny |

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

To remove the VM entirely:

```bash
# Lima
limactl stop agentsandbox
limactl delete agentsandbox

# Vagrant
vagrant destroy -f
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
| [`docs/RECIPES.md`](docs/RECIPES.md)                    | Common manifest patterns, model/provider switching, framework integration (OpenAI, Anthropic, LangChain). |
| [`docs/operations.md`](docs/operations.md)              | Running the daemon as a long-lived systemd service + CI runner pattern. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)                    | Branch and commit conventions, PR checklist.                    |
| [`orchestrator/README.md`](orchestrator/README.md)      | Orchestrator-specific API, scenario format, daemon-mode details.|
| [`viewer/README.md`](viewer/README.md)                  | Viewer architecture, event schemas, mock sender usage.          |

---

## Requirements

**Full-stack (kernel enforcement):**

- Ubuntu 24.04 (kernel 6.8+) or any distro on kernel 6.8+
- `CONFIG_BPF_LSM=y` **and** `bpf` in the runtime `lsm=` cmdline
  (`scripts/setup-vm.sh` handles this automatically)
- cgroup v2 unified hierarchy (Ubuntu 24.04 default)
- Go 1.23+, Node 20+, Python 3.10+
- For production: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and
  `CAP_SYS_RESOURCE` on the daemon. The systemd unit in
  [`deploy/systemd/`](deploy/systemd/) grants those capabilities.

**Local mode (any OS — orchestrator + dashboard only, NO security enforcement):**

- Python 3.10+ and `pip install pyyaml websocket-client`
- Node 20+ (for the viewer dashboard; Node 22+ is only needed for the
  optional `viewer/scripts/mock_kernel_sender.js` helper)
- No Linux VM, no root, no special kernel
- ⚠️ Agents run unsandboxed — local mode is for development/demo only

## Components

| Subtree            | Language     | Purpose                                                            |
|--------------------|--------------|--------------------------------------------------------------------|
| `bpf/`             | C (eBPF)     | Kernel-side policy engine — LSM hooks for net, file, exec, creds   |
| `cmd/agentd/`      | Go           | The privileged daemon — cgroup + BPF + process lifecycle           |
| `cmd/agentctl/`    | Go           | The CLI — manifest validation, daemon RPC, event tail              |
| `cmd/test-client/` | Go           | A raw IPC client for protocol testing                              |
| `internal/`        | Go           | Shared libraries — `bpf`, `cgroup`, `events`, `ipc`, `policy`, etc.|
| `orchestrator/`    | Python       | Full orchestrator: CLI (`run`/`validate`/`status`), multi-agent scenarios, `@tool_tracer`, daemon-mode lifecycle, model/provider switching |
| `viewer/`          | Node + React | Real-time event dashboard + daemon bridge + policy/manifest UI     |
| `examples/`        | YAML         | Shipped manifests for testing — `allowed-net`, `blocked-net`, `playground/` graduated series |
| `scripts/`         | Bash         | Setup scripts — `setup-lima.sh`, `setup-vagrant.sh`, `setup-vm.sh`, `quickstart.sh`, `local-demo.sh` |
| `deploy/`          | Bash + systemd | Production install/uninstall + systemd service unit              |
| `docs/`            | Markdown     | Architecture, interfaces, threat model, recipes, operations        |

## Known Limitations

- **IPv4 only.** `network.bpf.c` handles AF_INET only; IPv6 connections
  currently fall through to allow. IPv6 support is planned for v0.2.
- **DNS is resolved once at launch.** `allowed_hosts` entries are resolved
  when the agent starts. DNS rotation after launch is not tracked.
- **Concurrent agent limit.** The BPF policy array has a fixed maximum
  (currently 64 slots). The daemon returns `BPF_LOAD_FAILED` if all slots
  are in use.
- **Codespaces runs in local mode.** The current devcontainer does not
  provide a 6.8+ kernel with BPF LSM. Kernel enforcement requires a
  native Linux host or a VM (Lima, Vagrant, cloud).

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full threat
model.

## License

Apache 2.0 — see [LICENSE](LICENSE).
