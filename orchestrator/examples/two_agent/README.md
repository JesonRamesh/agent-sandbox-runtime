## Two-Agent Example

This example shows how to coordinate two agents while keeping the
"one OS process per agent" rule intact.

- `research-agent.yaml` is the research-stage agent. It writes a handoff file.
- `writer-agent.yaml` is the local agent. It can read the handoff file and
  write the final answer, but it has no external network access.
- `scenario.yaml` makes the dependency explicit: `writer` depends on
  `research` and launches only after successful completion.

The orchestrator launches both as separate processes. They interact only
through a handoff file in the system temp directory (`/tmp/agent-handoff/`
on Linux), which keeps the boundary explicit and preserves per-agent
sandbox policy.

Run the scenario from the `orchestrator/` directory with:

```bash
python -m orchestrator run -f examples/two_agent/scenario.yaml --json
```

On success, the handoff and final output land in the system temp
directory under `agent-handoff/`.
