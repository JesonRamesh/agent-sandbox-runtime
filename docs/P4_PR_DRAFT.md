# P4 PR Draft

## Title

`feat(p4): orchestrator CLI + multi-agent scenarios + daemon stdout streaming`

## Body

### Summary

This PR promotes the Python orchestrator into a real developer entrypoint for
the sandbox runtime.

It adds:

- `python -m orchestrator run|validate|status`
- multi-agent `scenario.yaml` support with dependencies and `launch_when`
- daemon-mode lifecycle tracking via `StreamEvents`
- LLM event parsing from agent output, including forwarding semantic `llm.*`
  events back into the daemon via `IngestEvent`
- runnable example scenarios for single-agent, fanout, two-agent handoff, and
  code-exec flows
- packaging (`pyproject.toml`), scenario JSON Schema, quickstart script, and
  P4 CI coverage

### Cross-Team Change

The only cross-team daemon contract extension in this PR is that
`cmd/agentd/main_linux.go` now emits `agent.stdout` and `agent.stderr`
events. The event schema is documented in `docs/INTERFACES.md` §4.2.

### Test Plan

- `make all`
- `python -m unittest discover -s orchestrator/tests -v`
- `python -m orchestrator run -f orchestrator/examples/two_agent/scenario.yaml --json`
- `python -m orchestrator run -f orchestrator/examples/fanout/scenario.yaml --json`
- `python -m orchestrator run -f orchestrator/examples/code_exec/scenario.yaml --json`
- optional gated real-daemon E2E: `AGENT_SANDBOX_E2E=1 python -m unittest discover -s orchestrator/tests -v`

### Review Asks

- **P2**: review `cmd/agentd/main_linux.go` and `internal/ipc/protocol.go`
  changes, especially `agent.stdout` / `agent.stderr` and `IngestEvent`
  interaction
- **P5**: review event-shape expectations for viewer impact
