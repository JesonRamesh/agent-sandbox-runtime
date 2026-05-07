# Claude Code Instructions — Agent Sandbox Runtime (P5 Extended)

Read this file fully before doing anything. These are standing rules for every session.

---

## Startup ritual — every session

1. Run `git branch --show-current` — if not on `p5/viewer-v2`, switch immediately
2. Read `context.md` fully
3. Tell the user in 3 lines:
   - Current branch
   - Last task completed
   - Next task

Do not proceed until this is done.

---

## CRITICAL: What already exists — do not rebuild

The integration merge significantly upgraded the codebase.
Before writing ANY code, read these files to understand current APIs:

Must read before touching App.jsx:
- viewer/viewer-app/src/App.jsx
- viewer/viewer-app/src/components/AlertBanner.jsx
- viewer/viewer-app/src/components/LLMPanel.jsx

Must read before touching server.js:
- viewer/server/server.js (especially broadcastToViewers function signature)

These components already exist and work — never recreate them:
Header, AgentTabs, StatsRow, LLMPanel, KernelPanel, AlertBanner
AlertBanner already handles injection attack display.
server.js already has HTTP+WebSocket+static serving.
App.jsx already has findInjectionTarget(), staged banner reveal, injectionTargets Set.

---

## Autonomous loop — how every task runs

### Step 1 — Plan (show to user)
- Read the relevant existing files first
- Write a plan covering: files to create/modify, exact changes to existing files,
  how it integrates with existing code, how to verify
- End with: "Ready to build. Confirm with 'yes' or tell me what to change."

### Step 2 — Build (after user says yes)
Build completely. If ambiguous, make a reasonable choice and note it.

### Step 3 — Verify (pause for user)
Show: files created/modified, exact test commands, what success looks like.
Say: "Please test and confirm it works. I will then commit and update context.md."

### Step 4 — Commit (after user says it works)
1. `git add viewer/`
2. `git commit -m "p5: [description]"`
3. `git push origin p5/viewer-v2`
4. Update context.md — mark done, update next task, add session log entry
5. Say: "Done. Next task: [name]. Say 'go' when ready."

---

## Two mandatory pause points

1. After plan — wait for "yes"
2. After test instructions — wait for "it works"

Never commit unverified code.

---

## Token management

After each completed task, if session feels long, tell user:
"Session getting long. Type /compact now, then say 'go' to continue."
After /compact: re-read context.md immediately before anything else.

---

## One task at a time

Never start the next task until current one is committed and context.md updated.

---

## Branch rule

Always on `p5/viewer-v2`. Never commit to main or another branch.

---

## File boundaries

Write and edit ONLY:
- `viewer/` — your domain
- `CLAUDE.md` — only if project changes require it
- `context.md` — after every completed task

Read (never edit):
- `p2/daemon/` — kernel event format
- `p4/orchestrator/` — LLM event format
- `README.md`

Never edit outside `viewer/` without explicit confirmation.

---

## Files that must NEVER be committed

- `context.md` — gitignored
- `.env`, `.env.local`
- `viewer/server/node_modules/`
- `viewer/viewer-app/node_modules/`
- `viewer/viewer-app/dist/`

Never `git add .`

---

## Project purpose

Linux sandbox stopping prompt-injected AI agents from making unauthorized
network connections — enforced at kernel level using eBPF.

Your piece: process viewer — adding security analysis engine, security panel,
and workflow graph on top of the existing working dashboard.

---

## Tech stack

- Server: Node.js, ws library + http module, port 8765
- Frontend: React with Vite
- New dependencies: openai (server), reactflow (frontend)
- Styling: Plain CSS
- Language: JavaScript only

---

## Event schemas

LLM (P4 → server → LEFT PANEL):
{ agent, type: stdout|tool_call|stopped|crashed, ts, data }

Kernel (P2 → server → RIGHT PANEL):
{ agent, type: connect_attempt|connect_allowed|connect_blocked, ts, data }

New — security analysis (server → browser):
{ agent, type: security_analysis, ts,
  data: { threatLevel: low|medium|high|critical,
          summary: string, concerns: string[], recommendation: string } }

---

## Extended tasks

### Task 1: Analyse main branch first
```bash
git fetch origin
git log origin/main --oneline -10
git diff p5/viewer-v2..origin/main -- viewer/
```
Read LLMPanel.jsx and KernelPanel.jsx to understand their current prop APIs.
Report findings. Do not build until done.

### Task 2: Security analysis engine
File: viewer/server/analyser.js + minor edits to server.js

analyser.js:
- Exports startAnalyser(getRecentEvents, broadcastFn)
- Every 30s, calls getRecentEvents() → sends to Cisco proxy → broadcasts result
- Uses OpenAI-compatible client: baseURL https://llm-proxy.dev.outshift.ai/v1

server.js changes (minimal):
- Add recentEventsBuffer = [] (rolling last 20 events)
- Push to buffer in broadcastToViewers after parsing
- Import and call startAnalyser at bottom of file

### Task 3: Security panel
File: viewer/viewer-app/src/components/SecurityPanel.jsx
+ minor additions to App.jsx (new state, new event type routing, render below panels)
NOTE: AlertBanner already exists — SecurityPanel is the ongoing AI analysis view,
not the per-event alert. Different purpose, different component.

### Task 4: Workflow graph
File: viewer/viewer-app/src/components/WorkflowGraph.jsx
+ tab system added to App.jsx (Events tab / Workflow tab)
Library: reactflow (npm install in viewer/viewer-app/)

---

## Model

Use whatever model is available on the current plan.
Use /compact after ~20 messages. Use /clear between tasks after context.md updated.
