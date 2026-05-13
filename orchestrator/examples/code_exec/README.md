# Code-Exec Example

This scenario shows the shape of an agent that is allowed to execute a
single interpreter and write only inside `/tmp/sandbox`.

Run it from the `orchestrator/` directory with:

```bash
python -m orchestrator run -f examples/code_exec/scenario.yaml
```

In daemon mode, the manifest is intentionally narrow:

- `allowed_hosts: []`
- `allowed_bins: ["/usr/bin/python3"]`
- `allowed_paths: ["/tmp/sandbox"]`

That makes it a compact example for the exec hook from the
orchestrator side.
