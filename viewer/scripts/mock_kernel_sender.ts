#!/usr/bin/env node
/*
 * P5 viewer — mock kernel sender (stand-in for P2 daemon).
 *
 * Connects to the viewer's WebSocket relay as a sender and pushes a scripted
 * scenario of kernel events so the React dashboard's RIGHT panel can be
 * exercised end-to-end before P2's real Go daemon is wired up.
 *
 * P2 will reimplement this in Go; this file documents the expected wire
 * format, handshake, and reconnect semantics.
 *
 * Uses Node's built-in WebSocket (stable in Node 22+), so no `npm install`
 * is required to run it.
 *
 * ---------------------------------------------------------------------------
 * Wire format (must match the contract in CLAUDE.md / context.md)
 * ---------------------------------------------------------------------------
 *
 * Handshake (sent immediately after connect, before any events):
 *     {"role": "sender", "name": "p2-daemon"}
 *
 * Event:
 *     {
 *       "agent": "demo-agent",
 *       "type":  "connect_blocked",   // connect_attempt | connect_allowed |
 *                                     //   connect_blocked
 *       "ts":    1714000000.456,       // float seconds since epoch
 *       "data":  {
 *         "dst_ip":   "203.0.113.42",
 *         "dst_port": 80,
 *         "hostname": "evil.com",
 *         "reason":   "no policy match"   // present on allowed/blocked
 *       }
 *     }
 *
 * ---------------------------------------------------------------------------
 * Usage
 * ---------------------------------------------------------------------------
 *
 *     node viewer/scripts/mock_kernel_sender.js
 *     node viewer/scripts/mock_kernel_sender.js --agent demo-agent --interval 1.5
 *     node viewer/scripts/mock_kernel_sender.js --once   # run scenario once and exit
 *     node viewer/scripts/mock_kernel_sender.js --host 127.0.0.1 --port 8765
 */

'use strict';

// Node 22+ exposes WebSocket as a global. Fail loudly on older Node.
if (typeof WebSocket === 'undefined') {
  console.error(
    "error: this script needs Node 22+ (built-in WebSocket).\n" +
    "       your Node version: " + process.version
  );
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Scripted scenario — kernel-side counterpart to mock_sender.py.
// Mirrors the LLM mock's prompt-injection story so when both run together
// the LEFT and RIGHT panels tell the same story in roughly the same rhythm.
// Each entry is { type, data } — the agent + ts are filled in at send time.
// ---------------------------------------------------------------------------
const SCENARIO = [
  {
    type: 'connect_attempt',
    data: { dst_ip: '93.184.216.34', dst_port: 443, hostname: 'example.com' },
  },
  {
    type: 'connect_allowed',
    data: {
      dst_ip: '93.184.216.34',
      dst_port: 443,
      hostname: 'example.com',
      reason: 'in allowed_hosts',
    },
  },
  {
    type: 'connect_attempt',
    data: { dst_ip: '203.0.113.42', dst_port: 80, hostname: 'evil.com' },
  },
  {
    type: 'connect_blocked',
    data: {
      dst_ip: '203.0.113.42',
      dst_port: 80,
      hostname: 'evil.com',
      reason: 'no policy match',
    },
  },
];

// ---------------------------------------------------------------------------
// CLI parsing — small hand-rolled parser to avoid a commander dep.
// ---------------------------------------------------------------------------
interface MockOptions {
  host: string;
  port: number;
  agent: string;
  interval: number;
  once: boolean;
}

function parseArgs(argv: string[]): MockOptions {
  const opts: MockOptions = {
    host: 'localhost',
    port: 8765,
    agent: 'demo-agent',
    interval: 1.5,
    once: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) {
        usage(`missing value for ${a}`);
      }
      return v;
    };
    switch (a) {
      case '--host':     opts.host = next(); break;
      case '--port':     opts.port = parseInt(next(), 10); break;
      case '--agent':    opts.agent = next(); break;
      case '--interval': opts.interval = parseFloat(next()); break;
      case '--once':     opts.once = true; break;
      case '-h':
      case '--help':     usage(); break;
      default:           usage(`unknown argument: ${a}`);
    }
  }
  if (!Number.isFinite(opts.port) || opts.port <= 0) usage('--port must be a positive integer');
  if (!Number.isFinite(opts.interval) || opts.interval <= 0) usage('--interval must be a positive number');
  return opts;
}

function usage(errMsg?: string) {
  const out = errMsg ? console.error : console.log;
  if (errMsg) out(`error: ${errMsg}\n`);
  out('Usage: node mock_kernel_sender.js [options]');
  out('  --host HOST        viewer server host (default: localhost)');
  out('  --port PORT        viewer server port (default: 8765)');
  out('  --agent NAME       agent name in each event (default: demo-agent)');
  out('  --interval SECS    seconds between events (default: 1.5)');
  out('  --once             run the scenario once and exit');
  out('  -h, --help         print this message');
  process.exit(errMsg ? 1 : 0);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function nowTs() {
  return Date.now() / 1000;
}

function makeEvent(agent: string, etype: string, data: Record<string, unknown>) {
  return { agent, type: etype, ts: nowTs(), data };
}

// ---------------------------------------------------------------------------
// Single connection lifecycle: open → handshake → stream scenario → close.
// Returns when the socket closes (normal or error).
// ---------------------------------------------------------------------------
function connectAndStream(opts: MockOptions, stopSignal: AbortSignal) {
  return new Promise<string>((resolve) => {
    const uri = `ws://${opts.host}:${opts.port}`;
    console.log(`[ws] connecting to ${uri} ...`);
    const ws = new WebSocket(uri);

    let streamingTask = null;
    let closed = false;

    const finish = (reason: string) => {
      if (closed) return;
      closed = true;
      try { ws.close(); } catch (_) { /* already closed */ }
      resolve(reason);
    };

    // Bail out early if the user hits Ctrl-C before/while connecting.
    const onStop = () => finish('stopped');
    stopSignal.addEventListener('abort', onStop, { once: true });

    ws.addEventListener('open', () => {
      const handshake = { role: 'sender', name: 'p2-daemon' };
      ws.send(JSON.stringify(handshake));
      console.log(`[ws] connected, handshake sent: ${JSON.stringify(handshake)}`);

      streamingTask = (async () => {
        let runIdx = 0;
        try {
          while (!closed) {
            runIdx += 1;
            console.log(`[scenario] run #${runIdx} starting (agent=${opts.agent})`);
            for (const step of SCENARIO) {
              if (closed) return;
              const event = makeEvent(opts.agent, step.type, step.data);
              ws.send(JSON.stringify(event));
              console.log(`[sent] ${step.type.padEnd(16)} ${JSON.stringify(step.data)}`);
              await sleep(opts.interval * 1000);
            }
            if (opts.once) {
              console.log('[scenario] --once specified, exiting after one run');
              finish('once-done');
              return;
            }
            // Quiet gap between runs so the dashboard has visible breathing room.
            await sleep(Math.max(opts.interval * 3, 5.0) * 1000);
          }
        } catch (err) {
          // Errors during send usually mean the socket is closing — let the
          // 'close' event handle reconnect.
          console.warn(`[ws] send loop ended: ${err instanceof Error ? err.message : err}`);
        }
      })();
    });

    ws.addEventListener('close', (ev) => {
      const code = ev.code;
      const reason = ev.reason || '';
      console.log(`[ws] socket closed code=${code}${reason ? ` reason="${reason}"` : ''}`);
      finish('socket-closed');
    });

    ws.addEventListener('error', (ev) => {
      // Node's WebSocket error events expose .message; fall back to a generic msg.
      const msg = (ev && (ev.message || ev.error?.message)) || 'unknown error';
      console.warn(`[ws] socket error: ${msg}`);
      // 'error' is followed by 'close', so we let close drive resolution.
    });
  });
}

// ---------------------------------------------------------------------------
// Outer loop — reconnect with exponential backoff if the server drops.
// ---------------------------------------------------------------------------
async function mainLoop(opts: MockOptions, stopSignal: AbortSignal) {
  let backoff = 1.0;
  const backoffMax = 30.0;

  while (!stopSignal.aborted) {
    const reason = await connectAndStream(opts, stopSignal);

    if (stopSignal.aborted) return;
    if (reason === 'once-done') return;

    if (opts.once) {
      console.log('[ws] --once specified, not reconnecting');
      return;
    }

    console.log(`[ws] disconnected; retrying in ${backoff.toFixed(1)}s`);
    // Sleep, but wake early if the user hits Ctrl-C.
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        stopSignal.removeEventListener('abort', onAbort);
        resolve();
      }, backoff * 1000);
      const onAbort = () => {
        clearTimeout(timer);
        resolve();
      };
      stopSignal.addEventListener('abort', onAbort, { once: true });
    });
    backoff = Math.min(backoff * 2, backoffMax);
  }
}

// ---------------------------------------------------------------------------
// Entrypoint — wire up signals, run the loop, exit cleanly.
// ---------------------------------------------------------------------------
async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const ac = new AbortController();

  const onSignal = (sig: string) => {
    if (ac.signal.aborted) return;
    console.log(`\n[signal] ${sig} received, closing socket...`);
    ac.abort();
  };
  process.on('SIGINT', () => onSignal('SIGINT'));
  process.on('SIGTERM', () => onSignal('SIGTERM'));

  await mainLoop(opts, ac.signal);
  console.log('[exit] mock_kernel_sender done');
}

main().catch((err) => {
  console.error('[fatal]', err);
  process.exit(1);
});
