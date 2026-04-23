# Agent Sandbox Runtime

A Linux-based sandbox that prevents prompt-injected AI agents from making unauthorized network connections — enforced at the kernel level using eBPF.

## What it does

When an AI agent gets tricked via prompt injection, it might try to exfiltrate data or connect to malicious hosts. Standard Python-level guardrails can be bypassed. This runtime moves enforcement *below* the agent — into the kernel itself — so the bad syscall is blocked regardless of what the agent tries.

```
┌─────────────────────────────────┐
│        agentctl run agent.yaml  │  ← you write this
└────────────────┬────────────────┘
                 │
        ┌────────▼────────┐
        │  Sandbox daemon  │  ← creates cgroup, loads policy
        └────────┬─────────┘
                 │
        ┌────────▼─────────┐
        │   AI agent        │  ← runs inside cgroup
        └────────┬──────────┘
                 │ tries to connect to evil.com
        ┌────────▼──────────┐
        │  eBPF (kernel)    │  ← BLOCKED
        └───────────────────┘
```

## Quickstart

```bash
vagrant up          # spin up the pre-configured Ubuntu 24.04 VM
vagrant ssh
agentctl run examples/demo-agent.yaml
```

## Manifest format

```yaml
name: my-agent
command: ["python", "agent.py"]
allowed_hosts:
  - api.openai.com
  - api.anthropic.com
allowed_paths:
  - /tmp/agent-workdir
```

## Requirements

- Ubuntu 24.04 (kernel 6.8+)
- BPF LSM enabled
- cgroup v2 unified hierarchy

Use the provided Vagrantfile to get a correctly configured environment instantly.

## Architecture

| Component | Owner | Description |
|---|---|---|
| eBPF enforcement | P1 | Kernel programs intercepting network syscalls |
| Sandbox daemon | P2 | Cgroup lifecycle, policy loading, process launch |
| CLI + manifest | P3 | `agentctl` command and YAML format |
| Orchestrator | P4 | Multi-agent management and demo |
| Process viewer | P5 | Real-time web UI for LLM + kernel events |

## License

Apache 2.0 — see [LICENSE](LICENSE).
