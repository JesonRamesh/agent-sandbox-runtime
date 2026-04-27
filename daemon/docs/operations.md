# Operations

Operator-facing reference for running `agent-sandbox-daemon` on a real Linux host. For internal architecture, see [`architecture.md`](architecture.md). For deliberate scope cuts, see [`../LIMITATIONS.md`](../LIMITATIONS.md). For unverified-on-real-hardware claims, see [`../CAVEATS.md`](../CAVEATS.md).

## 1. Log locations

The daemon emits two kinds of logs:

- **Daemon journal**: structured slog output (JSON in production, text with `--log-json=false`) goes to stderr, captured by systemd. Tail it with:
  ```bash
  journalctl -u agent-sandbox -f
  ```
  The unit file ([`deploy/systemd/agent-sandbox.service`](../deploy/systemd/agent-sandbox.service)) sets `StandardOutput=journal` and `StandardError=journal`, and `ExecStart` passes `--log-json` so the journal carries one JSON object per event.

- **Per-agent event log**: one file per agent at `/var/log/agent-sandbox/<agent-id>.log`. Each line is a JSON `Event` (`network.allow`, `network.block`, `agent.started`, `agent.exited`, `agent.crashed`). Files are size-rotated by `internal/events/pipeline.go`'s `rotatingWriter` at 10 MiB with 3 files retained: `<id>.log`, `<id>.log.1`, `<id>.log.2`. Override the directory with `--log-dir`.

`agentctl logs <agent-id>` and the WebSocket at `ws://127.0.0.1:7443/events?agent=<id>` are both backed by these files / the pipeline.

## 2. Common errors and their fixes

The daemon wraps every error with the operation name and (where relevant) the most likely fix in the `slog` `fix` field. The table below indexes the substrings you will most commonly see.

| Error message substring | Diagnosis | Named fix |
|---|---|---|
| `removing MEMLOCK rlimit` | Kernel <5.11, or daemon is missing `CAP_SYS_RESOURCE` (which the unit file sets in `AmbientCapabilities`). | Confirm `AmbientCapabilities` and `CapabilityBoundingSet` in [`deploy/systemd/agent-sandbox.service`](../deploy/systemd/agent-sandbox.service) include `CAP_SYS_RESOURCE`. Upgrade to a kernel ≥5.11 (Ubuntu 22.04 HWE: `sudo apt install linux-generic-hwe-22.04 && sudo reboot`). |
| `creating pin dir /sys/fs/bpf/...` | bpffs is not mounted. | `sudo mount -t bpf bpf /sys/fs/bpf` or re-run `sudo deploy/install.sh` (which writes a fstab entry so it remounts on boot). |
| `attaching connect4 to /sys/fs/cgroup/...` | The kernel does not support cgroup-attach BPF (`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`), or the cgroup is not on the v2 unified hierarchy. | Verify with `./scripts/verify-host.sh` — the `BPF cgroup_sock attach supported` check covers this. Install the HWE kernel: `sudo apt install linux-generic-hwe-22.04 && sudo reboot`. |
| `loading spike_connect4 ELF` (or `spike_connect6`) | The bpf2go-generated `*_bpfel.go` files are missing. They are gitignored on purpose; build needs codegen. | `make generate` (which runs `go generate ./internal/bpf/...`). Requires `clang`, `bpf2go`, and a generated `internal/bpf/vmlinux.h` (run `./scripts/gen-vmlinux.sh` once). |
| `INVALID_MANIFEST: command must have at least one argument` | `Manifest.Validate()` rejected the request: `command:` in the YAML is empty or missing. | Check the manifest YAML — `command` is required and must be a non-empty list of strings. See [`api/proto.md`](../api/proto.md) §Manifest. |
| `INVALID_MANIFEST: name is required` | Same validation, missing `name`. | Add a `name:` to the manifest. The name is human-readable, not unique. |
| `policy: lookup "<host>"` (host resolution) | DNS is broken from the daemon's view, or the host does not resolve. | Inspect `/etc/resolv.conf` from the daemon's namespace; the daemon resolves via `net.LookupHost` with the daemon's resolver, not the agent's. Test with `getent hosts <host>` as the `agent-sandbox` user. If you need a literal IP and want to bypass DNS, list `1.2.3.4:443` directly in `allowed_hosts`. |
| `pinning <name> map` | Pin path already exists from a prior run, or `/sys/fs/bpf/agent-sandbox/` is on a non-bpf filesystem. | See §4 below — clear the stale pin directory. |
| `creating cgroup ...: file exists` | A cgroup with this id already exists (rare — IDs are random hex). | The id collision is almost certainly a leftover from a prior crash. See §5 for cgroup leftover cleanup. |
| `websocket addr "..." must bind a loopback address` | `--ws-addr` was set to a non-loopback host. The daemon refuses outright. | Set `--ws-addr=127.0.0.1:7443` (or any `127.0.0.0/8` / `::1` address). The brief mandates localhost-only and there is no auth. |
| `agent-sandbox-daemon must run as root` | Daemon was launched without root euid. | Run via `systemctl start agent-sandbox` (systemd starts it as root, then drops to the `agent-sandbox` user with the capability set in the unit) or, for ad-hoc testing, `sudo ./bin/agent-sandbox-daemon`. |

## 3. bpftool recipes

`bpftool` ships with `linux-tools-common` / `linux-tools-$(uname -r)`. All of these need root.

List every loaded BPF program; the cgroup-attached connect programs from running agents will appear here:

```bash
sudo bpftool prog list | grep -E 'cgroup_sock_addr|connect'
```

List every loaded map; the daemon's per-agent maps are named `policy`, `events`, `policy6`, `events6`:

```bash
sudo bpftool map list | grep -E 'policy|events'
```

Dump the allowlist for a specific agent (one entry per allowed `(addr, port, proto, family)` tuple, keyed by cgroup id):

```bash
sudo bpftool map dump pinned /sys/fs/bpf/agent-sandbox/<agent-id>/policy
sudo bpftool map dump pinned /sys/fs/bpf/agent-sandbox/<agent-id>/policy6
```

Dump the events ringbuf metadata (size, flags). The ringbuf payload is consumed by the daemon's reader goroutine; you cannot easily tail it with bpftool, but you can confirm it exists:

```bash
sudo bpftool map show pinned /sys/fs/bpf/agent-sandbox/<agent-id>/events
```

If `link.Pin` ever lands in the loader (today only maps are pinned), program-show will work via:

```bash
sudo bpftool prog show pinned /sys/fs/bpf/agent-sandbox/<agent-id>/<link-name>
```

## 4. Recovery from corrupted pinned-map state

**Symptom**: the daemon refuses to start with one of:

- `creating pin dir /sys/fs/bpf/agent-sandbox/<id>: ...`
- `pinning <name> map: ...` mentioning `EEXIST`
- `loading existing pinned map` style errors after a partial restart

**Diagnosis**: a previous daemon crashed mid-`Load` and left a partial pin directory, or you upgraded the daemon binary and the on-disk map shape no longer matches.

**Fix** (acknowledging this kills enforcement for that orphaned agent — the BPF program will still be attached to the cgroup until you also clean the cgroup, but with no daemon reading the ringbuf and no map for it to consult, behavior is undefined):

```bash
sudo systemctl stop agent-sandbox
sudo rm -rf /sys/fs/bpf/agent-sandbox/<id>
sudo systemctl start agent-sandbox
```

To clear all pinned state for every agent (only safe when you know none are running you care about):

```bash
sudo systemctl stop agent-sandbox
sudo rm -rf /sys/fs/bpf/agent-sandbox/
sudo systemctl start agent-sandbox
```

The daemon will recreate `/sys/fs/bpf/agent-sandbox/` on the next `RunAgent`. Restart-reconciliation today only logs orphans; it does not adopt them (CAVEATS §23). Pair this fix with §5 below to also drop the leftover cgroup if no PIDs remain in it.

## 5. Cgroup leftovers after a daemon crash

**Symptom**: `/sys/fs/cgroup/agent-sandbox/<id>/` directories exist but the daemon has no record of them. `agentctl list` is empty (or doesn't list them) yet the directory is on disk. The daemon log on startup shows `orphan cgroup from prior daemon — leaving running, not adopted in v0.1` (this is `daemon.reconcileStartup` in `cmd/daemon/main_linux.go`).

**Diagnosis**: check whether anything is still running in the cgroup:

```bash
cat /sys/fs/cgroup/agent-sandbox/<id>/cgroup.procs
```

- Empty: the agent has already exited; the directory is just stale state. Skip to the rmdir step.
- Non-empty: those PIDs are the orphaned agent. Decide whether to keep them or kill them.

**Fix** (kernel 5.14+ supports `cgroup.kill` for an atomic group SIGKILL; older kernels need a per-PID loop):

```bash
# Atomic kill of every pid in the cgroup (kernel 5.14+).
echo 1 | sudo tee /sys/fs/cgroup/agent-sandbox/<id>/cgroup.kill

# Then remove the directory.
sudo rmdir /sys/fs/cgroup/agent-sandbox/<id>
```

If `rmdir` fails with `EBUSY`, the kernel has not finished reaping yet — wait a moment and retry (CAVEATS §9 tracks adding backoff to `Cgroup.Destroy`). To clean up every leftover at once:

```bash
for d in /sys/fs/cgroup/agent-sandbox/*/; do
  echo 1 | sudo tee "$d/cgroup.kill" >/dev/null
  sudo rmdir "$d"
done
```

## 6. Verifying installation

After `sudo deploy/install.sh` (or `sudo make install`), confirm the daemon is healthy:

```bash
# 1. Kernel features the daemon needs.
./scripts/verify-host.sh

# 2. systemd unit is active.
systemctl status agent-sandbox

# 3. Daemon is running as the non-root user, not root.
ps -o user= -C agent-sandbox-daemon
# Expected output: agent-sandbox

# 4. BPF programs are loadable on this host (will only show entries once at
#    least one agent has been run).
sudo bpftool prog list | grep -i cgroup

# 5. Socket exists and is mode 0600.
ls -l /run/agent-sandbox.sock

# 6. WebSocket is bound to loopback and listening.
ss -ltnp | grep 7443
```

If `verify-host.sh` fails, the most common fix is the HWE kernel: `sudo apt install linux-generic-hwe-22.04 && sudo reboot`. If `ps` returns `root`, the unit was bypassed; restart via `systemctl restart agent-sandbox` rather than `sudo ./bin/agent-sandbox-daemon`.

## 7. Known limitations

These are scoped out of v0.1 by design, not bugs:

- **DNS rotation, IPv6/Happy-Eyeballs interaction, TCP-only enforcement**: see [`../LIMITATIONS.md`](../LIMITATIONS.md).
- **Restart-reconciliation gap, single-agent maps, hardcoded shutdown grace, etc.**: see [`../CAVEATS.md`](../CAVEATS.md), particularly §23 (restart adoption), §25 (2-second SIGTERM grace), §27 (bpffs mount requirement), §29 (10-second reap tick).

If you hit something not on either list, capture `journalctl -u agent-sandbox` output, the contents of `/sys/fs/cgroup/agent-sandbox/` and `/sys/fs/bpf/agent-sandbox/`, and file an issue.
