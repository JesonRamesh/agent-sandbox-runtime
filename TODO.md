# TODO — P4 (Orchestrator)

> Owner: arzaan (P4). Source branch: `arzaan1`. Target: `main`.
>
> **Endgame for the project.** The runtime ships as a developer tool: a dev
> writes an agent manifest (or a multi-agent scenario), runs one command, and
> their agent runs inside a kernel-enforced sandbox while a live dashboard
> shows every LLM tool-call alongside every kernel decision. Prompt-injection
> attacks become observable and inert.
>
> **P4's slice of the endgame.** The Python orchestrator is the "high-level"
> entry point for that dev. It owns:
>
> 1. The Python API (`from orchestrator import Orchestrator`).
> 2. The `python -m orchestrator run|validate` CLI for scenarios.
> 3. Multi-agent coordination (DAG, dependencies, `launch_when`).
> 4. LLM-event capture from agent stdout, forwarded to P5's viewer so the
>    dashboard correlates "model decided to call fetch_url" with "kernel
>    blocked the connect()".
> 5. The prompt-injection demo — the killer scenario that justifies the
>    whole project.
> 6. Daemon-mode lifecycle tracking via `StreamEvents` (no `subprocess.Popen`
>    when the daemon is available).
>
> **Where `arzaan1` stands right now.**
>
> Ahead of `main` on: orchestrator CLI, `ScenarioRunner`, two-agent example,
> daemon-mode lifecycle tracking, ~430 lines of P4 tests, and a daemon patch
> that streams agent stdout/stderr as `agent.stdout`/`agent.stderr` events
> (needed by daemon mode).
>
> Behind `main` on: viewer-v2 (P5 dashboard rewrite), daemon security
> hardening (`working_dir` traversal check, `PERMISSION_DENIED` error,
> per-step cleanup retry, 8-byte agent IDs), more daemon unit tests, and a
> CI workflow that builds (the `arzaan1` workflow still references the
> obsolete `daemon/` subdir and is broken).
>
> Strategy: **merge `main` → `arzaan1`, then PR back to `main`**.

---

## Status snapshot (last updated after the merge session)

- `arzaan1` is **merged with `main`** at commit `8db9890` and pushed.
- Backup branch `arzaan1-backup` (local-only) points at the pre-merge
  commit `a5b6ef0` — safety net if the merge ever needs to be unwound.
- 16/16 orchestrator unit tests pass:
  `cd orchestrator && python -m unittest discover -s tests`.
- Phases 0 and 1 are **done**. Most of Phase 3a is **done**. Phases 2,
  3a-remainder, 3b, 3c, 4, 5 are pending.

---

## ✅ Phase 0 — Catch up with main (DONE — commits a5f9f3b, 8db9890)

The orchestrator code on `arzaan1` was on a stale base and the CI was
broken. Resolved by merging `main` in. What landed:

- [x] Backup branch `arzaan1-backup` created (local, not pushed).
- [x] `git merge origin/main` resolved with two manual conflicts and
      ~67 auto-merged files.
- [x] `cmd/agentd/main_linux.go` blended cleanly: kept `main`'s
      `cleanupMu` + 8-byte `agentIDBytes` + per-step retry; preserved
      this branch's `streamAgentOutput` + `stdoutPipe`/`stderrPipe`
      goroutines + `maxAgentOutputChunkBytes`.
- [x] `internal/ipc/protocol.go` adopted `main`'s `validateWorkingDir`
      traversal guard and `PERMISSION_DENIED` error code/var.
- [x] `orchestrator/orchestrator/daemon.py`: kept this branch's
      `disappeared` property + logger-based RPC failure path; adopted
      `main`'s enriched docstrings on `_recv_exact` and the `_rpc`
      `except` block.
- [x] `orchestrator/orchestrator/manifest.py`: kept this branch's
      `_format_yaml_location` + `path:line:col` errors; adopted
      `main`'s longer `ManifestError` docstring and the utf-8 comment.
- [x] `viewer/**` taken wholesale from `main` (v2 dashboard).
- [x] `.github/workflows/ci.yml` taken from `main` (the `daemon/`
      subdir job on this branch was broken post-unification).
- [x] Force-pushed to `origin/arzaan1` with `--force-with-lease`.

If a future session ever needs to redo this: `git reset --hard
arzaan1-backup` puts arzaan1 back to `a5b6ef0`.

---

## ✅ Phase 1 — Close the daemon-mode gaps (DONE — commit a5f9f3b)

The README claimed `IngestEvent` and `agent.stdout`/`agent.stderr` were
blocked outside P4. Both were already wired in the daemon code on
`arzaan1` (`cmd/agentd/main_linux.go:296-297, 341-371, 575-599`). The
real remaining gap was the orchestrator's stdout parser — it forwarded
`[TOOL]`/`[RESULT]` lines to the P5 viewer relay but didn't push them
back into the daemon's unified pipeline. Resolved:

- [x] **Verified `agent.stdout`/`agent.stderr` works** by reading the
      daemon code, not the stale README.
- [x] **Verified `IngestEvent` works** end-to-end via the daemon's
      `IngestEvent` handler (`main_linux.go:575-599`) which validates
      the `llm.` prefix and submits to the same pipeline as kernel
      events.
- [x] **Wired `IngestEvent` into the stdout parser.** Added
      `AgentProcess._emit` (`process.py`) that fans every parsed
      semantic event (`tool_call`, `tool_result`, `user_input`,
      `agent_output`) to both the streamer AND the daemon. Raw
      `stdout` lines are excluded to avoid a self-referential loop
      with `agent.stdout`.
- [x] **Added 2 new tests**:
      `test_daemon_mode_forwards_llm_events_via_ingest_event` and
      `test_local_mode_does_not_call_ingest_event`. Plus the
      `FakeDaemon` test fixture now records `ingest_event` calls.
- [x] **Rewrote `orchestrator/README.md`** "Daemon mode status"
      section. The four-step daemon-mode flow is now documented as
      working, not blocked.

---

## Phase 2 — Ship the P4 PR to main

Open the PR after Phase 1 is green. Keep it as one logical change so
reviewers can audit the contract surface.

- [ ] **PR title:** `feat(p4): orchestrator CLI + multi-agent scenarios
  + daemon stdout streaming`.
- [ ] **PR body checklist:**
  - Summary of what `orchestrator/` now does (CLI, scenarios, daemon
    mode).
  - Note the one cross-team change: `cmd/agentd/main_linux.go` now
    emits `agent.stdout`/`agent.stderr` events. Reference
    `docs/INTERFACES.md` §4.2 (extend the table in this PR).
  - Test plan: `make all`, `python -m unittest`, a smoke run of
    `examples/two_agent/scenario.yaml`, a smoke run of
    `examples/prompt_injection/demo_launcher.py`.
- [ ] **Update `docs/INTERFACES.md` §4.2** to add `agent.stdout` and
  `agent.stderr` with their `details` schema (`line`, `truncated`).
- [ ] **Update `docs/ARCHITECTURE.md` §8 (P4)** to reflect the new
  layout (`orchestrator/orchestrator/` package, scenarios,
  `python -m orchestrator`).
- [ ] **Request review from P2** (daemon owner) for
  `cmd/agentd/main_linux.go` and `internal/ipc/protocol.go` changes;
  from **P5** for the event schema and any viewer impact.

**Done when:** PR is merged into `main`.

---

## Phase 3 — Make it usable as a developer tool

Once the PR is in, the orchestrator works but isn't yet *pleasant*.
This phase is about adoption: a dev should pick it up in 5 minutes.

### 3a — Developer ergonomics

- [x] **Structured logging** (commit a5f9f3b). New module
      `orchestrator/orchestrator/log.py`; every `print("[orchestrator]
      …")` swapped for `logger`. Top-level `-q`/`-v` flags on the CLI.
      The agent stdout mirror `[<name>] <line>` is intentionally kept
      as `print` because it's a live stream, not log output.
- [x] **Friendlier error output** (commit a5f9f3b). YAML parse
      failures now render as `path:line:col: invalid YAML: <problem>`
      for both manifests and scenarios via the shared
      `manifest._format_yaml_location` helper. `ManifestError` is now
      caught alongside `ScenarioError` at the CLI top level.
- [x] **Stop-on-Ctrl-C race** (commit a5f9f3b).
      `Orchestrator.stop_all` now catches `KeyError` (agent already
      removed — silent skip) but logs every other exception via
      `logger.warning` so real daemon-side bugs surface.
- [x] **Daemon socket health** (commit a5f9f3b). `DaemonClient` now
      tracks `_was_available_at_startup` separately and exposes a
      `.disappeared` property. On RPC failure it re-probes and, if the
      socket has vanished, logs ERROR. `AgentProcess.start()` notices
      `disappeared` before falling back to local mode and logs ERROR
      so the operator can't miss an unsandboxed launch.
- [ ] **Top-level quickstart for the orchestrator.** Add a section to
  the project `README.md` (between "Step 7" and "Step 8") titled
  "Or use the orchestrator" with three lines:
  `python -m orchestrator run -f examples/two_agent/scenario.yaml`.
- [ ] **`orchestrator status` subcommand.** Calls `ListAgents` against
  the daemon and prints a table. Useful when a scenario is running and
  you want to know what's alive without `agentctl list`.

### 3b — More examples (the README's job is to convince)

- [ ] **`examples/single_agent/`.** The simplest possible example: one
  agent, one manifest, no daemon required. Pure
  `python -m orchestrator run -f examples/single_agent/scenario.yaml`.
  Currently the README's "single-agent" path is buried in the
  `prompt_injection` directory which also requires `ngrok` and an
  OpenAI key.
- [ ] **`examples/fanout/`.** Three agents launched in parallel
  (different `allowed_hosts`), no dependencies between them. Shows the
  orchestrator running a fleet, not just a pipeline.
- [ ] **`examples/code_exec/`.** Sandboxed agent with `allowed_bins:
  ["/usr/bin/python3"]` and `allowed_paths: ["/tmp/sandbox"]`, no
  network. Tests P1's exec hook from the orchestrator side.

### 3c — Tests that cover production paths

- [ ] **End-to-end test against a real daemon.** Today every test uses
  `FakeDaemon`. Add one test in `orchestrator/tests/` gated by an
  `AGENT_SANDBOX_E2E=1` env var that:
  1. Skips if not on Linux or the daemon binary isn't present.
  2. Starts `agentd` in a tmpdir with a tmp socket.
  3. Runs a scenario with a deny-network agent.
  4. Asserts the orchestrator forwarded an `agent.stderr` line
     containing `EPERM`.
  This guards against the kind of integration drift that motivated the
  `997b726 refactor: unify into single Go module` work.
- [ ] **CI: add a `python orchestrator tests` job** to
  `.github/workflows/ci.yml`. Pin Python 3.11, run
  `pip install pyyaml websocket-client`, then
  `python -m unittest discover -s orchestrator/tests -v`. Currently the
  orchestrator has no CI gate at all.

---

## Phase 4 — Production polish (later, after Phase 3 lands)

Stretch items. Not blocking adoption but expected of a mature tool.

- [ ] **Reconnect on transient WS failure.** `EventStreamer` drops
  events silently when the relay restarts. Add a small reconnect loop
  with capped backoff; buffer up to N events while disconnected.
- [ ] **Backpressure.** `EventStreamer.emit` blocks on `ws.send`. A
  slow viewer can pause an entire scenario. Move the send into a
  bounded queue + worker thread; drop oldest with a logged warning when
  the queue fills.
- [ ] **Cancellation token in `wait_for`.** Today `Orchestrator.wait_for`
  blocks forever if `timeout=None`. Accept a `threading.Event` so
  callers can cancel. (Improves the signal-handling story in 3a.)
- [ ] **Per-agent log files.** Mirror `agentctl logs` behaviour:
  write `~/.cache/agent-sandbox/orchestrator/<scenario_id>/<agent>.log`
  with every stdout/stderr line. Devs need this for post-mortems.
- [ ] **Scenario-level retries.** Today only individual agent restarts
  exist. Add scenario-level retry semantics (e.g. "if `research` fails
  and there's a retry budget, restart the whole scenario").
- [ ] **Schema/JSON Schema for scenarios.** Publish a JSON Schema for
  `scenario.yaml` so editors (VS Code YAML extension) can autocomplete
  and validate.
- [ ] **`pyproject.toml` + console script.** Backlog. Promote
  `python -m orchestrator` → `orchestrator` on PATH. Defer until the
  package contract is stable and you have at least 2 examples plus
  reconnect/backpressure done.

---

## Phase 5 — Endgame, beyond P4

Things that make the *whole project* a real developer tool. Track them
here because they affect P4's UX, but coordinate before doing them.

- [ ] **One-command bootstrap.** `make demo` (or
  `scripts/quickstart.sh`) that starts daemon, viewer, and runs the
  two_agent scenario. Today the README has 7 steps across 3 terminals.
- [ ] **Injection detection heuristics.** A small module that watches
  the stream for "ignore previous instructions"-class patterns in tool
  *results* (not user prompts) and emits
  `llm.injection_suspected` via `IngestEvent`. Cheap heuristic + a
  hook for a real classifier later.
- [ ] **Scenario authoring UI.** P5's dashboard could grow a tab for
  "compose a manifest" with the JSON Schema from 4. Big lift; only
  worth it if the project gets traction.
- [ ] **`docs/RECIPES.md`.** Common patterns: "agent with only LLM
  network access", "agent with read-only `/etc`", "agent that can
  exec one subprocess", "two agents handing off via file", "fan-out
  with rate limit". This is the doc that turns curious readers into
  users.
- [ ] **Deployment guide for self-hosted CI.** `docs/operations.md`
  covers systemd; extend it with how to drop an orchestrator scenario
  into a GitHub Actions runner so untrusted PRs run sandboxed.

---

## Watchlist (not P4's bug, but watch them)

- **P2 daemon:** `agent.exited` vs `agent.crashed` semantics. The
  orchestrator's `_handle_daemon_event` (process.py:266) keys on
  `agent.exited` for any clean exit. If P2 changes the event name or
  payload, daemon-mode lifecycle tracking breaks silently.
- **P3 CLI:** `manifest.mode` field. The CLI's `internal/manifest`
  validator accepts `enforce`/`audit`. The orchestrator's
  `AgentManifest` defaults to `"enforce"` but doesn't validate. If P3
  adds a third mode, the orchestrator will pass it through and the
  daemon will reject — fine, but the error message will be confusing.
  Worth syncing once.
- **P5 viewer:** the sender handshake `{role: "sender", name:
  "p4-orchestrator"}` is hardcoded in `events.py:33`. If P5 starts
  routing by sender name, coordinate the constant.
