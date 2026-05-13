# Fanout Example

This scenario launches three independent agents in parallel. There are
no dependencies, so it is the simplest way to see the orchestrator run
a small fleet instead of a pipeline.

Run it from the `orchestrator/` directory with:

```bash
python -m orchestrator run -f examples/fanout/scenario.yaml --json
```

Each manifest advertises a different `allowed_hosts` list so the
scenario doubles as a policy-shape example.
