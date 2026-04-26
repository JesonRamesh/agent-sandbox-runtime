# Contributing

## Layout & ownership

The four pillars are independent — a verifier failure in one does
not take down the others (decision D-005). Touch the file/dir for
your area; touch `daemon/internal/loader/` only if you change the
shared map schema.

| Area | Files |
|---|---|
| eBPF — network        | `bpf/network.bpf.c` |
| eBPF — file           | `bpf/file.bpf.c`    |
| eBPF — creds          | `bpf/creds.bpf.c`   |
| eBPF — exec           | `bpf/exec.bpf.c`    |
| Daemon (Go)           | `daemon/`           |
| Web GUI               | `gui/`              |
| CLI                   | `cli/agentctl/`     |
| VM bootstrap / ISO    | `Vagrantfile`, `setup-vm.sh`, `iso/` |

## Decision & bug logs

- Architectural choices: append to `decision.md` (newest at top,
  numbered `D-NNN`). Cross-reference from code comments.
- Bugs / limits: `bug_report.md`, numbered `B-NNN`. Cross-reference
  from the code that has the workaround.

## Branches

Work on a feature branch, open a PR to `main`. CI must pass; one
reviewer must approve.

## Commit style

```
bpf/network: handle AF_INET6 in socket_connect
daemon: hot-reload on SIGHUP
gui: add live event filter
fix(B-002): retry apt-get update with backoff
```

## Local dev loop

```bash
# Inside the VM:
make           # bpf + daemon + cli
sudo make run  # foreground daemon, points at repo dirs
# in another shell:
sudo cli/agentctl/agentctl run examples/demo-agent.yaml
```

Open `http://127.0.0.1:9000/ui/` to watch live events.
