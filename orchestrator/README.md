# P4 Orchestrator

This subtree is now split cleanly:

- `orchestrator/orchestrator/` contains the core package
- `orchestrator/examples/` contains demos and sample scenarios
- `orchestrator/tests/` contains P4-side verification

## What P4 owns

- Orchestrator lifecycle management
- LLM-level event parsing and viewer forwarding
- Multi-agent scenario coordination
- Examples that demonstrate how to use the runtime

## Structure

```text
orchestrator/
  orchestrator/
    core.py
    daemon.py
    events.py
    manifest.py
    process.py
    scenario.py
    cli.py
  examples/
    prompt_injection/
    two_agent/
  tests/
```

## Core usage

From the `orchestrator/` directory, run a multi-agent scenario with:

```bash
python -m orchestrator run -f examples/two_agent/scenario.yaml
```

This launches one OS process per agent and applies the usual orchestrator
behavior: launch, monitor, stop, and optional restart-on-crash handling.

Validate a scenario and every referenced manifest before launch with:

```bash
python -m orchestrator validate -f examples/two_agent/scenario.yaml --json
```

Install the package and console script from the repo root with:

```bash
python -m pip install -e .
orchestrator validate -f orchestrator/examples/two_agent/scenario.yaml
```

Inspect the daemon's current view of running agents with:

```bash
python -m orchestrator status
```

### Scenario format

```yaml
name: research-writer-pipeline
description: Research runs first, writer runs only after successful completion.
stagger_seconds: 0.5
max_retries: 1
agents:
  - id: research
    manifest: ./research-agent.yaml
  - id: writer
    manifest: ./writer-agent.yaml
    depends_on: [research]
    launch_when: success
```

Each referenced manifest is still a single-agent sandbox contract. The scenario
file is the P4 layer that coordinates multiple agents.

Current scenario-agent fields:

- `id`: stable workflow identifier
- `manifest`: relative or absolute path to an agent manifest
- `depends_on`: other scenario agent ids that must finish first
- `launch_when`: `success` or `complete`
- `description`: optional human note

Top-level scenario fields:

- `name`
- `description`
- `stagger_seconds`
- `max_retries`
- `agents`

JSON Schema for editors lives at:

```text
orchestrator/orchestrator/schema/scenario.schema.json
```

When a run finishes, the orchestrator can emit a machine-readable summary:

```bash
python -m orchestrator run -f examples/two_agent/scenario.yaml --json --summary-file summary.json
```

### Launch one agent directly in Python

```python
from orchestrator import Orchestrator

orch = Orchestrator(ws_url="ws://localhost:8765")
orch.launch("path/to/agent.yaml")
orch.wait_for("my-agent")
orch.stop_all()
```

Restart policy lives on the orchestrator:

```python
orch = Orchestrator(restart_on_crash=True, max_restarts=3)
```

## Manifest format

```yaml
name: llm-agent
command: ["/usr/bin/python3", "/opt/agents/demo.py"]
allowed_hosts:
  - api.openai.com:443
allowed_paths:
  - /opt/agents/
working_dir: /opt/agents
env:
  PYTHONUNBUFFERED: "1"
user: "65534"
timeout: "5m"
description: "Example agent"
```

Top-level manifest keys accepted by the integrated runtime are:

- `name`
- `command`
- `mode`
- `allowed_hosts`
- `allowed_paths`
- `allowed_bins`
- `forbidden_caps`
- `working_dir`
- `env`
- `user`
- `stdin`
- `timeout`
- `description`

## Examples

### Prompt injection

The prompt-injection example now lives in:

```text
examples/prompt_injection/
```

Run it with:

```bash
python examples/prompt_injection/demo_launcher.py https://<your-ngrok-url>
```

### Two-agent handoff

The multi-agent example now lives in:

```text
examples/two_agent/
```

It demonstrates the recommended pattern for process isolation: agents stay in
separate OS processes and interact through an explicit handoff path rather than
sharing memory or a PID.

### Single-agent quickstart

Use `examples/single_agent/` for the smallest scenario in the repo:

```bash
python -m orchestrator run -f examples/single_agent/scenario.yaml
```

### Fanout and code exec

Two more sample scenarios are available:

- `examples/fanout/` launches three independent agents in parallel.
- `examples/code_exec/` shows an agent with no network access, one allowed
  binary, and one writable path.

## Daemon mode

When `agentd` is running on `/run/agent-sandbox.sock`, the orchestrator:

1. Submits the manifest via `RunAgent` — no `subprocess.Popen`, the daemon
   handles `clone3` into the sandbox cgroup.
2. Subscribes to `StreamEvents` for the returned `agent_id` and tracks
   lifecycle from `agent.started` / `agent.exited` / `agent.crashed`.
3. Receives every line the agent writes as `agent.stdout` / `agent.stderr`
   events and parses `[TOOL]` / `[RESULT]` / `[USER]` / `[AGENT]` markers.
4. Forwards parsed LLM events back into the daemon's unified pipeline via
   `IngestEvent` as `llm.tool_call`, `llm.tool_result`, `llm.user_input`,
   and `llm.agent_output`, so anything else subscribing to the daemon
   stream (`agentctl logs`, alternate dashboards) sees them keyed by the
   same `agent_id` as the kernel events.

In local mode (daemon socket absent), the orchestrator falls back to
`subprocess.Popen` and forwards events only to the viewer relay.

## Verification

Run the P4 tests with:

```bash
python -m unittest discover -s tests -v
```

Per-agent orchestrator logs are written under:

```text
~/.cache/agent-sandbox/orchestrator/<scenario-or-session>/<agent>.log
```

Run the all-in-one Linux bootstrap from the repo root with:

```bash
bash scripts/quickstart.sh
```
