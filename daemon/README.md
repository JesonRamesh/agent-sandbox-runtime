# Agent Sandbox — Sandbox Daemon

The Go control-plane daemon for the
[Agent Sandbox Runtime](https://github.com/JesonRamesh/agent-sandbox-runtime).
Creates per-agent cgroup v2 sandboxes, binds them to a kernel-side BPF
LSM policy, launches the agent inside via cgroup-aware fork, and streams
kernel-level events (network / file / exec / creds) back to the CLI and
web UI.

This is **the daemon only** — the eBPF C programs live in `../bpf/`
(see [`docs/integration-with-mehul-ebpf.md`](docs/integration-with-mehul-ebpf.md)
for the integration shape).

## Quickstart (Ubuntu 24.04 inside the project's Vagrant VM)

```bash
# From the repo root, with the bpf objects already built (see ../bpf/Makefile):
cd daemon
make build

# Install the four .bpf.o files where the daemon expects them.
sudo install -d /usr/lib/agent-sandbox/bpf
sudo install -m 0644 ../bpf/*.bpf.o /usr/lib/agent-sandbox/bpf/

# Run the daemon (foreground, stderr log).
sudo bin/agent-sandbox-daemon --bpf-dir=/usr/lib/agent-sandbox/bpf

# In another terminal: send a manifest.
sudo bin/test-client --socket /run/agent-sandbox.sock run examples/curl-blocked.json
sudo bin/test-client list
sudo bin/test-client logs <agent-id>

# Watch live events on the WebSocket.
websocat ws://127.0.0.1:7443/events
```

For the systemd / install-script flow:

```bash
sudo make install      # creates the agent-sandbox user, installs the binary,
                       # mounts bpffs, enables the systemd unit.
sudo make uninstall    # reverses the install (leaves logs, user, bpffs mount).
```

## Architecture (one-liner)

`agentctl run <manifest>` → Unix socket → daemon: `cgroup.Create` →
`policy.Compile` (resolves hosts, packs `struct policy`) →
`bpf.Runtime.Bind` (allocates `policy_id`, writes `policies[id]` and
`cgroup_policy[cg]→id` into the kernel maps loaded once at startup) →
`exec.Cmd` cgroup-aware fork → kernel LSM hooks fire → events fan out
to slog + per-agent log file + WebSocket subscribers.

Detailed per-package breakdown and lifecycle walkthrough:
[docs/architecture.md](docs/architecture.md). Operating runbook (logs,
errors, recovery): [docs/operations.md](docs/operations.md). Frozen
contract with the eBPF side and merge-day asks:
[docs/integration-with-mehul-ebpf.md](docs/integration-with-mehul-ebpf.md).

## Target environment

| | |
|---|---|
| OS | Ubuntu 24.04 (kernel 6.8+ with BTF and BPF LSM enabled) |
| Boot args | `lsm=…,bpf` in the kernel cmdline (Mehul's `setup-vm.sh` patches GRUB) |
| Go | 1.22+ (we need `SysProcAttr.UseCgroupFD`) |
| cgroup | v2 unified hierarchy only |
| bpffs | mounted at `/sys/fs/bpf` (install.sh handles this) |

The daemon is Linux-only. Code under `internal/cgroup/` and
`internal/bpf/` is gated with `//go:build linux` so the repo still
builds cleanly on macOS for development.

## Make targets

| target | what it does |
|---|---|
| `make build` | builds `bin/agent-sandbox-daemon`, `bin/test-client` |
| `make test` | non-privileged unit tests, race-enabled |
| `make test-integration` | privileged tests touching cgroup v2 + BPF (uses `sudo`) |
| `make test-e2e` | full end-to-end suite |
| `make lint` | golangci-lint |
| `make install` | runs `deploy/install.sh` (creates user, installs binaries, mounts bpffs, enables unit) |
| `make uninstall` | reverses the install |

There is no `make generate` — the daemon does not author or compile
eBPF C. The four `.bpf.o` objects come from the sibling `bpf/`
directory on the `Mehul` branch.

## BPF dependency

The daemon loads four prebuilt `.bpf.o` objects at startup:
`network.bpf.o`, `file.bpf.o`, `creds.bpf.o`, `exec.bpf.o`. The Go
struct mirrors are validated against
[`bpf/common.h.reference`](bpf/common.h.reference) — a vendored
read-only copy of the kernel-side header. See
[`docs/integration-with-mehul-ebpf.md`](docs/integration-with-mehul-ebpf.md)
for the frozen contract (map names, struct field order, hook attach
points).

## Docs

- [`docs/integration-with-mehul-ebpf.md`](docs/integration-with-mehul-ebpf.md) — frozen contract with Mehul's eBPF side, runtime expectations, and the merge-day ask list.
- [`docs/architecture.md`](docs/architecture.md) — internal design and per-package responsibilities.
- [`docs/operations.md`](docs/operations.md) — runbook with named fixes for common errors.
- [`api/proto.md`](api/proto.md) — IPC contract between daemon and CLI/UI.
- [`bpf/README.md`](bpf/README.md) — explains the vendored read-only `common.h.reference`.

## Known v0 scope

- AF_INET only — IPv6 hosts in the manifest are rejected (the network pillar in `bpf/network.bpf.c` is AF_INET-only).
- DNS rotation after agent launch is not handled — addresses are resolved once at `RunAgent` time.
- Concurrent-agent ceiling is 32 (kernel `policies` ARRAY map size). See the integration doc's "Asks for merge day" for the bump request.

## License

Apache 2.0. See [LICENSE](LICENSE).
