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

## Phase 0 — Catch up with main (do this first, ~half a day)

The orchestrator code on `arzaan1` won't merge cleanly into a stale base.
Sync first, fix the breakage, then ship.

- [ ] **Back up the branch** before doing anything destructive:
  `git branch arzaan1-backup`
- [ ] **Merge `main` into `arzaan1`**:
  `git fetch origin && git merge origin/main`
- [ ] **Resolve conflicts**, keeping these specific things from each side:
  - `cmd/agentd/main_linux.go` — **keep `main`'s** elaborate cleanup
    (`cleanupMu`, per-step retry bools, the `done` channel, 8-byte
    `agentIDBytes`). **Re-apply on top of it**: the `streamAgentOutput`
    function, the `stdoutPipe`/`stderrPipe` captures, the two
    `go d.streamAgentOutput(...)` goroutines, and the
    `maxAgentOutputChunkBytes` constant. These are the orchestrator's
    daemon-mode contract.
  - `internal/ipc/protocol.go` — **keep `main`'s** `validateWorkingDir` and
    the `PERMISSION_DENIED` error code/var. They're security hardening, not
    orchestrator territory.
  - `orchestrator/**` — **keep `arzaan1`'s** version verbatim. `main` only
    has the original P4 import; you've rewritten the package.
  - `.github/workflows/ci.yml` — **keep `main`'s** version. The `daemon/`
    subdir job on `arzaan1` is leftover from before the Go-module
    unification and is broken.
  - `viewer/**` — **keep `main`'s** version. P5's v2 rewrite supersedes
    everything on your branch.
- [ ] **Build and test locally** before pushing:
  - `make all` (Go side)
  - `cd orchestrator && python -m unittest discover -s tests -v`
  - `python -m orchestrator validate -f examples/two_agent/scenario.yaml`
- [ ] **Force-push** the merged branch: `git push origin arzaan1`.
  Coordinate with anyone else who has it checked out.

**Done when:** `make all` is green, P4 tests pass, the CI workflow on the
pushed branch passes, and `git log main..arzaan1 -- orchestrator/` still
shows your orchestrator commits.

---

## Phase 1 — Close the daemon-mode gaps (before the PR)

Your README still says "integrated daemon `IngestEvent` support" and
"guaranteed `agent.stdout` / `agent.stderr` event emission" are blocked
outside P4. The first is actually wired up in `internal/ipc/protocol.go`
and documented in `docs/INTERFACES.md` §3.6; the second is the patch
sitting on your branch. Make both work end-to-end and add tests.

- [ ] **Verify `agent.stdout`/`agent.stderr` flows.** With a daemon
  running, launch an agent via the orchestrator in daemon mode, and
  confirm the orchestrator's `[<name>] <line>` mirror appears for every
  line the agent prints. Check `orchestrator/orchestrator/process.py:259`
  (`_handle_daemon_event`) actually receives the events.
- [ ] **Verify `IngestEvent`.** Add a method
  `Orchestrator.report_llm_event(agent_id, event_type, details)` that
  calls `DaemonClient.ingest_event` and confirm the daemon fans the
  event out on `ws://127.0.0.1:7443/events` (subscribe with a small
  Python script using `websockets`).
- [ ] **Wire `IngestEvent` into the agent stdout parser.** When the
  orchestrator sees a `[TOOL]` or `[RESULT]` line in daemon mode, push
  it as an `llm.tool_call` / `llm.tool_result` via `IngestEvent` so the
  dashboard sees one unified stream keyed by `agent_id`. Today these
  only go out via the direct WebSocket to P5's relay — daemon-mode
  subscribers miss them.
- [ ] **Test.** Extend `orchestrator/tests/test_orchestrator.py`:
  - A new `AgentProcessDaemonModeTests` case that feeds an
    `agent.stdout` event with a `[TOOL]` line and asserts the
    streamer recorded a `tool_call` event.
  - A `DaemonClientTests` case that exercises the `IngestEvent`
    happy path against a fake socket server.
- [ ] **Update `orchestrator/README.md`.** Drop the "Daemon mode status"
  caveats once the gaps are closed.

**Done when:** the prompt-injection demo runs end-to-end in daemon mode
(daemon enforces, dashboard shows both the model's tool call and the
kernel's deny, correlated by `agent_id`), and the new tests pass.

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

- [ ] **Top-level quickstart for the orchestrator.** Add a section to
  the project `README.md` (between "Step 7" and "Step 8") titled
  "Or use the orchestrator" with three lines:
  `python -m orchestrator run -f examples/two_agent/scenario.yaml`.
- [ ] **Structured logging.** Replace every `print("[orchestrator] …")`
  in `core.py`, `process.py`, `events.py` with a module-level
  `logging.Logger`. Default level INFO, `--quiet`/`--verbose` flags on
  the CLI. Devs hate uncontrollable stdout noise.
- [ ] **Friendlier error output.** `cli._print_error` currently shows
  bare exception strings. Wrap `ScenarioError` and `ManifestError` with
  the offending YAML path and (where available) line number — match the
  pattern `agentctl` uses (`manifest.yaml:14:3: …`).
- [ ] **Stop-on-Ctrl-C is racy.** `core.Orchestrator.stop_all` swallows
  every exception. Distinguish "agent already exited" (fine) from "stop
  RPC failed" (log it). Otherwise a flaky stop hides a real daemon bug.
- [ ] **Daemon socket health.** `DaemonClient._probe` runs once at
  construction and never retries. If the daemon restarts mid-scenario,
  the orchestrator silently falls back to local mode (no sandbox!).
  Either re-probe on every RPC, or fail loud if the socket was reachable
  at startup and is now gone.
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
