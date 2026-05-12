# Usability Gaps — P4 Ease-of-Use Roadmap

Tracks known friction points for developers adopting the orchestrator.
Start from Gap 1 each session — work top to bottom.

---

## Gap 1 — The `allowed_hosts` trap ⬅ START HERE NEXT SESSION

**What happens:** A dev sets `provider: anthropic` and `model: claude-sonnet-4-6`
in their manifest but forgets to add `api.anthropic.com:443` to `allowed_hosts`.
In full-stack mode (daemon running) their agent silently gets kernel-blocked on
the first LLM call. The error surfaces deep inside the agent process as a cryptic
network failure, not as an orchestrator warning.

**The fix:** The orchestrator already knows the provider and its base URL
(from `manifest.resolved_base_url()`). On startup it should cross-check:
if `provider` is set and the provider's hostname isn't in `allowed_hosts`,
emit a clear warning before launching the agent.

**Files to touch:**
- `orchestrator/orchestrator/process.py` — add the check in `start()` before
  `_daemon.run_agent()` or `_start_local()`
- `orchestrator/orchestrator/manifest.py` — add a helper `missing_provider_hosts()`
  that returns hostnames implied by `provider`/`base_url` but absent from
  `allowed_hosts`
- `orchestrator/tests/test_orchestrator.py` — tests for the new helper and the
  warning path

**Provider → hostname map** (already partially in `_PROVIDER_BASE_URLS`):

| Provider | Host to check in `allowed_hosts` |
|----------|----------------------------------|
| anthropic | `api.anthropic.com` |
| openai | `api.openai.com` |
| cisco / outshift | `llm-proxy.dev.outshift.ai` |
| azure | derived from `base_url` |

---

## Gap 2 — Quickstart runs in fake mode by default

**What happens:** `examples/quickstart/` runs a simulation when `MODEL` isn't set.
A dev sees it "work" but doesn't know what to do next to run a real LLM call.
There's no obvious bridge from "simulation worked" to "real call working."

**The fix:** After the simulation completes, print a clear next-step message:
```
[quickstart] Simulation complete. To use a real LLM, edit examples/quickstart/agent.yaml:
  uncomment 'model' and 'provider', add the provider host to allowed_hosts,
  then set your API key: export OPENAI_API_KEY=...
```

Also: the Cisco proxy is available by default for this project — the quickstart
could default to `provider: cisco` (pre-commented but prominent) so teammates
can uncomment one block and immediately have a working real-LLM run.

**Files to touch:**
- `orchestrator/examples/quickstart/agent.py` — add next-step print after `_run_simulated()`
- `orchestrator/examples/quickstart/agent.yaml` — promote the Cisco block to top,
  make it the first/most prominent option

---

## Gap 3 — Framework integration is undocumented

**What happens:** `@tool_tracer` works on plain Python functions. Devs using
LangChain, LangGraph, or the Anthropic Claude SDK have tool calls happening
inside framework internals — they don't know if or how `@tool_tracer` plugs in.

**The fix:** Add a section to `orchestrator/README.md` (or `docs/RECIPES.md`)
showing how to wrap tools in the three most common patterns:

1. **Plain OpenAI SDK** — already shown in `examples/quickstart/agent.py`
2. **Anthropic Claude SDK** — `@tool_tracer` on the tool function, pass to
   `client.messages.create(tools=[...])` as normal
3. **LangChain** — wrap LangChain `@tool`-decorated functions with `@tool_tracer`
   (order matters: `@tool_tracer` outermost so it fires before LangChain's wrapper)

No new code needed — just docs and a small example per pattern.

**Files to touch:**
- `docs/RECIPES.md` — add "Using tool_tracer with your framework" section
- Possibly `orchestrator/examples/` — one new example per framework if examples
  are more convincing than docs

---

## Gap 4 — Injection demo broken with modern models *(not a priority)*

**What happens:** `examples/prompt_injection/` requires the model to follow
injected instructions in tool results. Modern models (GPT-4 class+) resist this
reliably, so the demo fails to trigger the attack — making the project's flagship
scenario unreliable.

**Why deprioritised:** This is a model behaviour issue, not a code issue.
Fixing it requires either using an older/less safety-trained model or redesigning
the demo to not depend on injection succeeding. The kernel enforcement story
can be demonstrated without the injection (just show the kernel blocking an
unauthorised connection directly). Revisit when the rest of the usability gaps
are closed.

---

## Gap 5 — Full-stack setup on Mac is still 7 steps

**What happens:** Getting from a Mac to kernel enforcement running requires:
Lima install → VM boot → `setup-vm.sh` → reboot → `make all` → start daemon →
start viewer. `scripts/quickstart.sh` assumes the daemon is already built.
No single script takes a Mac user from zero to enforcement running.

**The fix:** A `scripts/setup-lima.sh` that does the full journey:
1. Checks for / installs Lima
2. Starts the agentsandbox VM with the right config
3. Runs `setup-vm.sh` inside the VM
4. Builds the daemon
5. Drops the user into a shell with instructions for the next step

This is a bash scripting task, not an orchestrator code task.

**Files to touch:**
- `scripts/setup-lima.sh` — new script (macOS/Lima)
- `scripts/setup-vagrant.sh` — new script (Intel Mac / Windows / Linux via Vagrant)
- `README.md` — replace the manual 7-step Lima section with one command

---

## Progress tracker

| Gap | Status |
|-----|--------|
| 1 — allowed_hosts warning | ✅ Done |
| 2 — Quickstart next-step message | ✅ Done |
| 3 — Framework integration docs | ✅ Done |
| 4 — Injection demo | ⏸ Deprioritised |
| 5 — Mac full-stack one-liner | ✅ Done |
