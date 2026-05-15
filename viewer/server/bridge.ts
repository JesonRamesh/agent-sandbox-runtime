#!/usr/bin/env node
// =============================================================================
// Agent Sandbox — daemon → viewer WebSocket bridge
//
// The daemon (P2) emits live kernel events on ws://127.0.0.1:7443/events.
// The viewer relay (P5) accepts connections on ws://127.0.0.1:8765 and
// expects each client to identify itself as either a "sender" (pushes events)
// or a "viewer" (receives them).
//
// Without something connecting both, the dashboard never sees real kernel
// events — only mock events or whatever the orchestrator (P4) chooses to
// push. This bridge fills that gap: it subscribes to the daemon and replays
// every frame to the viewer relay tagged as a sender.
//
// Usage:
//   node viewer/scripts/bridge.js
//
// Env vars (all optional):
//   DAEMON_WS    daemon event stream URL  (default ws://127.0.0.1:7443/events)
//   VIEWER_WS    viewer relay URL         (default ws://127.0.0.1:8765)
//   SENDER_NAME  human-readable label     (default "agentd-bridge")
// =============================================================================

const WebSocket = require('ws');
const { transformDaemonEvent } = require('./transform');

const DAEMON_WS  = process.env.DAEMON_WS  || 'ws://127.0.0.1:7443/events';
const VIEWER_WS  = process.env.VIEWER_WS  || 'ws://127.0.0.1:8765';
const SENDER     = process.env.SENDER_NAME || 'agentd-bridge';
// Forwarded to the viewer relay's sender handshake. Must match VIEWER_TOKEN
// on the relay; if neither side sets one, sender auth is disabled (loopback
// bind is the access control).
const VIEWER_TOKEN = process.env.VIEWER_TOKEN || '';

const RECONNECT_BASE_MS = 500;
const RECONNECT_MAX_MS  = 30_000;
// Jitter prevents a thundering-herd reconnect when many bridges restart in
// lockstep (systemd unit restart, daemon bounce). 0–25% multiplicative jitter
// is enough to spread a hundred reconnects across ~7s when the deterministic
// delay would have stacked them on a single millisecond.
const RECONNECT_JITTER_FRAC = 0.25;

function jittered(baseMs: number): number {
  return Math.floor(baseMs * (1 + Math.random() * RECONNECT_JITTER_FRAC));
}

function ts() { return new Date().toISOString(); }
function log(...a: any[]) { console.log(`[${ts()}] [bridge]`, ...a); }
function warn(...a: any[]) { console.warn(`[${ts()}] [bridge]`, ...a); }

// Connection state. Each side reconnects independently with exponential
// backoff; messages are dropped while the other side is down (events are
// observability, not durable). The dashboard catches up once both sides
// reconnect.
let daemonWS: any = null;
let viewerWS: any = null;
let viewerReady = false;
let daemonBackoff = RECONNECT_BASE_MS;
let viewerBackoff = RECONNECT_BASE_MS;

// agent_id → friendly manifest name. Populated as `agent.started` events
// arrive; consulted by the transform when building UI events. Survives
// daemon reconnects (a restarted daemon will issue fresh agent.started
// frames for the agents it relaunches).
const agentNames = new Map();

function connectViewer() {
  log(`viewer: dial ${VIEWER_WS}`);
  viewerReady = false;
  viewerWS = new WebSocket(VIEWER_WS);

  viewerWS.on('open', () => {
    log('viewer: connected; sending sender handshake');
    const handshake: Record<string, any> = { role: 'sender', name: SENDER };
    if (VIEWER_TOKEN) handshake.token = VIEWER_TOKEN;
    viewerWS.send(JSON.stringify(handshake));
    viewerReady = true;
    viewerBackoff = RECONNECT_BASE_MS;
  });
  viewerWS.on('close', (code: number) => {
    const delay = jittered(viewerBackoff);
    warn(`viewer: closed (code ${code}); reconnecting in ${delay}ms`);
    viewerReady = false;
    setTimeout(connectViewer, delay);
    viewerBackoff = Math.min(viewerBackoff * 2, RECONNECT_MAX_MS);
  });
  viewerWS.on('error', (err: any) => {
    warn(`viewer: error ${err.code || err.message}`);
    // 'close' will follow.
  });
}

function connectDaemon() {
  log(`daemon: dial ${DAEMON_WS}`);
  daemonWS = new WebSocket(DAEMON_WS);

  daemonWS.on('open', () => {
    log('daemon: connected; relaying events');
    daemonBackoff = RECONNECT_BASE_MS;
  });
  daemonWS.on('message', (data: any) => {
    if (!viewerReady || viewerWS.readyState !== WebSocket.OPEN) return;
    // The daemon's wire schema (docs/INTERFACES.md §4) does not match the
    // shape the browser viewer consumes (viewer-app/src/App.jsx). Translate
    // here — the bridge is the natural adapter point. transform.js returns
    // null for events the UI does not model (lifecycle agent.started, llm.*,
    // unknowns); we drop those silently so the UI sees a clean stream.
    let raw: any;
    try {
      raw = JSON.parse(data.toString());
    } catch (err) {
      warn(`daemon: dropping malformed JSON frame: ${err instanceof Error ? err.message : err}`);
      return;
    }
    const ui = transformDaemonEvent(raw, agentNames);
    if (ui === null) return;
    viewerWS.send(JSON.stringify(ui));
  });
  daemonWS.on('close', (code: number) => {
    const delay = jittered(daemonBackoff);
    warn(`daemon: closed (code ${code}); reconnecting in ${delay}ms`);
    setTimeout(connectDaemon, delay);
    daemonBackoff = Math.min(daemonBackoff * 2, RECONNECT_MAX_MS);
  });
  daemonWS.on('error', (err: any) => {
    warn(`daemon: error ${err.code || err.message}`);
    // 'close' will follow.
  });
}

connectViewer();
connectDaemon();

// Graceful shutdown so systemd / Ctrl-C doesn't leave half-open sockets.
function shutdown() {
  log('shutting down');
  try { daemonWS && daemonWS.close(); } catch {}
  try { viewerWS && viewerWS.close(); } catch {}
  setTimeout(() => process.exit(0), 200);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
