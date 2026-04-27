# Caveats and Known Issues

Living list of deviations, assumptions, and unverified claims that teammates need to confirm or fix when running this on real Linux hardware. Updated incrementally during implementation.

## Environment deviations from the brief

| Brief says | We did | Why |
|---|---|---|
| Ubuntu 24.04, kernel 6.8+ | Ubuntu 22.04 + HWE kernel | Team's actual hardware. May need `linux-generic-hwe-22.04` for 6.x kernel. |
| Develop on Linux | Develop on macOS arm64 | Maintainer is on a Mac; Linux-only code is `//go:build linux` with stubs so `go build ./...` works locally. |
| Run §6 verification commands and report | Wrote `scripts/verify-host.sh` for teammates | Cannot run those commands on macOS. |

If 22.04 + HWE turns out to be insufficient, we may need to either upgrade to 24.04 (revert the deviation) or detect missing features at runtime and disable them.

## Unverified claims (need real Linux to confirm)

These were written without being able to compile or run. First teammate to build will hit any of these that are wrong:

1. **`go.mod` deps and version pin.** `github.com/cilium/ebpf v0.16.0` is pinned. `go mod tidy` on first Linux build will pull `go.sum` and may surface incompatibilities. If v0.16.0 has API changes from what's used in `internal/bpf/loader.go`, pin to a known-good version (e.g., v0.15.0).
2. **`ebpf.AttachCGroupInet4Connect` constant name.** Used in `internal/bpf/loader.go`. Cilium ebpf may name it `ebpf.AttachCGroupInetIngress` or similar across versions. Verify against the installed version of `github.com/cilium/ebpf`.
3. **bpf2go directive correctness.** `internal/bpf/gen.go` uses `-target bpfel -type event SpikeConnect4 programs/spike_connect4.c -- -I.`. The `-type event` requires `struct event` to exist in the C source — it does (defined in `spike_connect4.c`). The `-I.` lets `#include "../vmlinux.h"` resolve.
4. **`spike_connect4.c` is a stub.** Tetragon attribution is in the header but the program logic is hand-written, not vendored. Replace with P1's real `cgroup/connect4` program when available. `bpf_printk` format string and `bpf_ntohs` use are best-effort and may need adjustment.
5. **CI vmlinux.h fallback.** If `/sys/kernel/btf/vmlinux` is missing on the GHA runner, CI substitutes an empty stub and the bpf compile will likely fail. Real fix: vendor a known-good `vmlinux.h` in the repo (~3 MB) or run CI on a self-hosted runner with BTF.
6. **`SysProcAttr.UseCgroupFD` requires Go 1.22+.** `go.mod` reflects this. If the host's Go is older, the spike will not compile.

## Phase 2 additions

7. **Generated bpf2go field names.** `internal/bpf/loader.go` references `objs.Connect4`, `objs.Events`, `objs.Policy`. These follow bpf2go's standard PascalCase rule applied to the C names (`connect4` program, `events` ringbuf, `policy` hash). If bpf2go nests them under `objs.SpikeConnect4Programs` / `objs.SpikeConnect4Maps`, the field accesses need adjusting on first Linux build. Tracked as `TODO(CAVEATS)` in `loader.go`.
8. **`struct event` ABI alignment.** Go-side `rawEvent` mirrors C `struct event` field-for-field with explicit `_pad`. If bpf2go's `-type event` generates a Go struct with different padding, prefer the generated type and delete `rawEvent`.
9. **Cgroup `cgroup.kill` semantics.** `Destroy()` writes `1` to `cgroup.kill` and then rmdirs. Kernel may not have reaped all pids by the time we return — if the rmdir fails with `EBUSY`, retry with backoff (not yet implemented).
10. **Cgroup test cleanup namespace.** Integration tests use `agent-sandbox-test/` — won't collide with the production `agent-sandbox/` namespace, but if a test crashes mid-run leftover dirs require manual `rmdir`.
11. **IPC frame size cap = 16 MiB** (in `internal/ipc/protocol.go` as `maxFrameBytes`). Not in the proto.md spec. If real manifests/events ever exceed this, bump or make configurable.
12. **`syscall.SysProcAttr.UseCgroupFD` requires Go 1.22+.** `go.mod` reflects this. If a teammate's host has older Go, the daemon fails to compile with a non-obvious error.
13. **Daemon's StreamEvents and AgentLogs are stubbed for Phase 2.** They return errors directing the caller to Phase 3. The IPC layer supports them; only the daemon-side handler is missing.
14. **Single-agent enforcement.** Phase 2 daemon's map technically supports multiple entries, but `RunAgent` doesn't reject a second concurrent request — Phase 3 either lifts this with the registry or rejects properly.

## Phase 3 additions

15. **Policy package compile not verified on Mac.** Go is not installed on the maintainer's macOS dev box, so `internal/policy/policy.go` and `policy_test.go` have not been run through `go vet` / `go test`. Stdlib-only and cross-platform by design (no build tags), but first teammate to build on Linux should run `go test ./internal/policy/...`. Test for `localhost` resolution assumes the host resolver returns at least one address — in pathological CI environments with no `localhost` entry this will fail.
16. **`net.LookupHost` uses the daemon's resolver, not the agent's.** If the daemon runs in a different netns or with `/etc/resolv.conf` pointing to a different recursor than the agent expects, the IPs in the policy map may not match the IPs the agent's libc would resolve. v0.1 ships single-namespace so this is fine; revisit if/when we sandbox per-netns.
17. **Policy schema is two-tier (cgroup → policy_id → struct policy).** Replaced the original flat `EntryV4` map design when porting onto Mehul's BPF LSM contract. `internal/policy/policy.go:Compiled` mirrors `struct policy` from `bpf/common.h.reference` byte-for-byte. Confirm with `pahole` on Linux that the Go layout matches the kernel's actual layout — Go's default struct layout aligns to natural boundaries which usually matches C, but verifier-loaded BPF programs are unforgiving if it doesn't.
18. **`internal/events` not compile-verified.** Go is not installed on the maintainer's Mac. `pipeline.go`, `websocket.go`, and `pipeline_test.go` have not been through `go build` or `go test`. First Linux build should run `go mod tidy` (we added `nhooyr.io/websocket v1.8.10` to `go.mod` without a `go.sum` update) and then `go test ./internal/events/...`.
19. **Pipeline.Submit recovers from panic.** The hot-path `Submit` defers a `recover()` to swallow the rare send-on-closed-channel panic that races with `Close`. Cheaper than locking on every event; downside is that genuine bugs which panic inside the channel send get masked. If observability for that becomes important, add a `closeMu sync.RWMutex` and have Close take the write lock.
20. **WebSocket uses `InsecureSkipVerify: true`.** The brief mandates localhost-only; `Start` refuses non-loopback addresses. Origin checking on a loopback-only listener is theatre — but if someone removes the loopback guard later, this defaults wide-open. Revisit if remote access ever lands.
21. **One slow subscriber blocks fan-out.** `Pipeline.fanOut` calls sinks synchronously under the subscribers' read lock. A subscriber whose Sink takes 100ms stalls every event for everyone. The websocket sink uses a 1-second per-write timeout that returns an error and triggers removal, which bounds the worst case but a chatty event burst can still build up latency. Per-sub goroutine + bounded queue is the obvious fix when this matters.
22. **`AgentLogTail` reads the whole file.** Fine for the default 10 MiB cap; if the cap ever grows or `tail_n` becomes part of a hot UI path, switch to reading from the end with `os.Seek` + a backwards line scanner.

## Phase 3 daemon integration additions

23. **Restart reconciliation is partial.** Brief §6 Phase 3 task 7 expects running agents to survive daemon restart and remain controllable. We pin the BPF maps under `/sys/fs/bpf/agent-sandbox/<agent-id>/` and the cgroup keeps the program attached, but the daemon does **not yet** re-attach to those pins on startup — `reconcileStartup()` only logs orphan cgroups. To complete: implement `bpf.Adopt(agentID)` that calls `ebpf.LoadPinnedMap` for `policy`/`events` and re-opens a `ringbuf.NewReader`, then construct a `*registry.Agent` with `Status=Adopted`. Cgroup `Adopt` is already implemented.
24. **`cmd/spike-cgroup` removed in Phase 3.** Brief §3 schedules its deletion after Phase 2; we removed it as part of the Phase 3 commit. `LoadSpike`/`SpikeHandle` are gone too. If a teammate kept a local checkout still referencing them, rebase.
25. **Daemon shutdown gives 2s grace for SIGTERM.** Hardcoded; not configurable via flag. Long-running agents that don't handle SIGTERM get SIGKILL'd after 2s. If 2s is too short for some agent class, we'll need a per-manifest grace setting in v0.2.
26. **No `bpf2go` pipeline anymore.** Ported off bpf2go onto `ebpf.LoadCollectionSpec(<path>.bpf.o)`. The four `.bpf.o` objects come from Mehul's `bpf/Makefile`; daemon expects them at `--bpf-dir` (default `/usr/lib/agent-sandbox/bpf`). All Go struct mirrors live in hand-written form in `internal/bpf/event.go` and `internal/policy/policy.go`, validated against `bpf/common.h.reference`. Drift between common.h and the Go mirrors silently corrupts events — if the field ordering or sizes ever change on the kernel side, update both halves in the same commit.
27. **Pinning requires `/sys/fs/bpf` to be mounted.** Many distros mount it by default but if it's missing the daemon fails at `MkdirAll(/sys/fs/bpf/agent-sandbox/<id>)`. `deploy/install.sh` (Phase 4) will mount it; for now teammates run `sudo mount -t bpf bpf /sys/fs/bpf` if needed.
28. **WebSocket port 7443 is hardcoded as default.** Configurable via `--ws-addr`; e2e test asks for `127.0.0.1:0` which the WS server's loopback check accepts but the OS allocates a free port. The test cannot then easily discover that port — fine because the test uses `AgentLogs`/`AgentLogTail` (file-based), not the WS, but a websocket-focused e2e test would need a different design.
29. **`reapLoop` runs every 10s.** Hardcoded; the `--keep-crashed` window is approximate to within 10s on the high side. Acceptable for v0.1.

## Phase 4 ship-readiness additions

30. **Daemon euid-0 check removed.** Phase 2/3 main_linux.go bailed if `os.Geteuid() != 0`. The systemd unit runs as the unprivileged `agent-sandbox` user with ambient caps, so we removed the check. Without root + without the caps the cgroup/BPF syscalls now fail with their own (descriptive) errors instead. If a teammate runs `./bin/agent-sandbox-daemon` directly without sudo and without caps, the failure point moves from "euid==0" to "creating cgroup parent /sys/fs/cgroup/agent-sandbox: permission denied".
31. **`Type=simple` systemd unit, no sd_notify.** The unit considers the daemon ready as soon as ExecStart returns. There's a brief window after Start where IPC/WS aren't yet listening; an early-startup `agentctl run` could see ECONNREFUSED. Acceptable for v0.1; v0.2 can add `Type=notify` + `sd_notify("READY=1\n")` after listeners bind.
32. **`MemoryDenyWriteExecute` is NOT set** on the unit — it's incompatible with the eBPF JIT (the JIT writes program code into kernel-allocated W+X pages, but the systemd directive blocks userspace W+X which is a different thing yet some kernels interact poorly). Comment in the unit file explains. If a teammate enables it and the daemon refuses to load programs, this is why.
33. **Bpffs fstab entry added by `install.sh` is `bpf /sys/fs/bpf bpf defaults 0 0`.** First boot after install relies on `RequiresMountsFor=/sys/fs/bpf` in the unit; the install script mounts it imperatively for the current boot. Verify on next reboot that the mount comes back automatically.
34. **`BenchmarkConnectionCost` measures fork+connect, not connect alone.** Bash `/dev/tcp` redirection inside the cgroup is the cleanest way to exercise the BPF hook from a benchmark, but bash startup adds ~500 µs of jitter. The unsandboxed sub-bench subtracts most of that out. If we ever miss the brief's <1 µs target by a hair, blame fork variance before blaming the BPF program.
35. **`BenchmarkPolicyMapLookup` is a userspace proxy.** It exercises `Map.Update` + `Map.Lookup` from Go, not from kernel-side BPF. Useful for catching map-shape regressions; not a substitute for the in-kernel measurement.
36. **`make spike` removed from Makefile.** Phase 1's spike binary is gone (`cmd/spike-cgroup` deleted in Phase 3). Anyone with a stale checkout running `make spike` gets "no rule to make target".
37. **No `Type=notify` means `systemctl start` returns before the daemon listens.** The post-`enable --now` `is-active` check in install.sh sleeps 2 s before checking state — gives the daemon time to bind. Brittle; refactor to a notify-style readiness check in v0.2.
38. **Docs claim some bpftool output formats and ps output formats** that aren't tested against a live host (CAVEATS-style claims are documented in `docs/operations.md`). First teammate to follow the operations runbook end-to-end should flag any divergence.

## Mehul-branch integration additions (Harrish/sandbox-daemon)

39. **Concurrent-agent cap = 32.** The kernel `policies` ARRAY map has `MAX_POLICIES = 32` in `bpf/common.h.reference`. The 33rd `RunAgent` returns `BPF_LOAD_FAILED` with a "max concurrent agents reached" message. Bumping it requires Mehul recompiling the four `.bpf.o` objects with a larger constant — see `docs/integration-with-mehul-ebpf.md` § "Asks for merge day".
40. **LSM hooks require boot with `lsm=…,bpf` in kernel cmdline.** Mehul's `setup-vm.sh` patches GRUB to do this; reboot is required after the script runs. On a host without BPF LSM enabled, `link.AttachLSM` fails at daemon startup and the error message includes the missing kernel feature.
41. **No `bpf2go` / `vmlinux.h` / `make generate` anymore.** Removed when porting to Mehul's prebuilt `.bpf.o` model. The `internal/bpf/programs/` directory and `gen-vmlinux.sh` script have been deleted. CI no longer compiles BPF C — that lives in `bpf/` on Mehul's branch.
42. **The `daemon/` stub on Mehul's branch is not reconciled.** Mehul's branch has its own `daemon/cmd/agentd/` with HTTP+SSE control surface. This branch (`Harrish/sandbox-daemon`) ships our per-agent IPC daemon. Tomorrow's merge needs to pick which architecture wins — `docs/daemon-model-comparison.md` argues for ours; `docs/integration-with-mehul-ebpf.md` notes this as a team decision, not a code-change ask for Mehul.

## Things we deliberately deferred or stubbed

- **CI integration tests are not run in GHA.** Privileged kernel access on GHA runners is unreliable; teammates run `make test-integration` locally on the Vagrant VM.
