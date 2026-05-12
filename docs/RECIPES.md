# Recipes

Common orchestrator and manifest patterns that turn the runtime from a
demo into a useful developer tool.

## Agent With LLM-Only Network Access

```yaml
name: llm-only-agent
command: ["/usr/bin/python3", "agent.py"]
allowed_hosts:
  - api.openai.com:443
allowed_paths: []
```

Use this when the agent should call an LLM API but should not browse the
arbitrary internet.

## Agent With Read-Only `/etc`

```yaml
name: inspect-host
command: ["/usr/bin/python3", "inspect.py"]
allowed_hosts: []
allowed_paths:
  - /etc/
```

Keep writes somewhere else such as `/tmp/agent-workdir`.

## Agent That Can Exec One Subprocess

```yaml
name: python-runner
command: ["/usr/bin/python3", "agent.py"]
allowed_hosts: []
allowed_paths:
  - /tmp/sandbox
allowed_bins:
  - /usr/bin/python3
working_dir: /tmp/sandbox
```

See [`orchestrator/examples/code_exec/`](../orchestrator/examples/code_exec/).

## Two Agents Handing Off Via File

```yaml
name: research-writer
agents:
  - id: research
    manifest: ./research-agent.yaml
  - id: writer
    manifest: ./writer-agent.yaml
    depends_on: [research]
```

See [`orchestrator/examples/two_agent/`](../orchestrator/examples/two_agent/).

## Fan-Out With Independent Policies

```yaml
name: fanout-demo
agents:
  - id: alpha
    manifest: ./alpha.yaml
  - id: beta
    manifest: ./beta.yaml
  - id: gamma
    manifest: ./gamma.yaml
```

Each manifest can advertise a different `allowed_hosts` list while the
orchestrator still treats them as one scenario.
