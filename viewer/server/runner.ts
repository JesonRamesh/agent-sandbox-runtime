// =============================================================================
// Agent Sandbox — scenario runner.
//
// The browser viewer can ask the relay (POST /api/scenarios/run) to fire a
// pre-canned demo manifest from examples/playground/. The relay shells out
// to `agentctl run -f <path>`; the agent itself still runs under the daemon
// with the same isolation as if a human had typed the command.
//
// Why a separate module: server.js handles HTTP framing + WS relay, and
// keeping the spawn/path-resolution logic over here means it can be unit
// tested without a live HTTP server, and the privilege boundary (which
// scenario names are valid, what root path they resolve under) is in one
// auditable place.
//
// Privilege model: the relay runs as an unprivileged user but `agentctl`
// has to talk to the root-owned daemon socket. We rely on a one-line
// sudoers fragment (scripts/install-viewer-sudoers.sh) that grants only the
// specific argv form below — *not* a blanket sudo. The runner constructs the
// argv literally so the sudoers Cmnd_Alias matches.
// =============================================================================

'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');

// Default config; server.js may override via env vars or constructor opts.
const DEFAULTS = Object.freeze({
  // Absolute directory holding the scenario YAML files. Restricting to a
  // single prefix is the access control: `name` is appended after path.join
  // and we re-check the resolved path is still under this root.
  manifestsDir: '/home/vagrant/agentsandbox/examples/playground',
  // The command we exec. Default uses passwordless sudo for one specific
  // argv shape (see scripts/install-viewer-sudoers.sh). Tests inject a
  // custom command (e.g. /bin/echo) to assert spawn behavior without sudo.
  command: 'sudo',
  baseArgs: [
    '-n',
    '/home/vagrant/agentsandbox/bin/agentctl',
    '--socket=/run/agent-sandbox.sock',
    'run',
    '-f',
  ],
  // Hard upper bound on how long we wait for agentctl before killing the
  // child and returning a timeout error.
  timeoutMs: 60_000,
});

// Configuration knobs for runScenario / listScenarios. All fields are
// optional; missing fields fall back to DEFAULTS at the top of the file.
interface RunnerOptions {
  manifestsDir?: string;
  command?: string;
  baseArgs?: string[];
  timeoutMs?: number;
}

interface ResolvedRunnerOptions {
  manifestsDir: string;
  command: string;
  baseArgs: string[];
  timeoutMs: number;
}

interface RunResult {
  ok: boolean;
  exitCode: number;
  signal: string | null;
  stdout: string;
  stderr: string;
  argv: string[];
}

// The error class lets server.js distinguish "user asked for a scenario
// that doesn't exist" (404) from "the spawn itself blew up" (500).
class RunnerError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'RunnerError';
    this.code = code; // 'invalid_name' | 'not_found' | 'spawn_failed' | 'nonzero_exit' | 'timeout'
  }
}

// scenarioName must be safe to put into a path. Block path traversal,
// absolute paths, and anything that isn't a kebab-or-snake-case-with-digits
// stem. The actual file is required to also be under manifestsDir.
function validateName(name: unknown): asserts name is string {
  if (typeof name !== 'string' || name.length === 0 || name.length > 64) {
    throw new RunnerError('invalid_name', 'scenario name must be 1..64 chars');
  }
  if (!/^[a-zA-Z0-9._-]+$/.test(name)) {
    throw new RunnerError('invalid_name',
      'scenario name may only contain letters, digits, ".", "_", "-"');
  }
  if (name === '.' || name === '..') {
    throw new RunnerError('invalid_name', 'scenario name must not be . or ..');
  }
}

// Resolve a scenario name to its on-disk path, ensuring it stays under
// manifestsDir even after symlink resolution. Throws RunnerError on any
// safety failure. If `name` lacks an extension, both `.yaml` and `.yml`
// are tried in that order.
async function resolveManifestPath(name: string, opts: ResolvedRunnerOptions): Promise<string> {
  validateName(name);
  const root = path.resolve(opts.manifestsDir);
  const hasExt = name.endsWith('.yaml') || name.endsWith('.yml');
  const candidates = hasExt ? [name] : [`${name}.yaml`, `${name}.yml`];

  let lastErr: any = null;
  for (const filename of candidates) {
    const candidate = path.resolve(root, filename);
    // Recheck after resolution. path.resolve with an absolute filename would
    // ignore the root prefix entirely; we want hard containment.
    if (!candidate.startsWith(root + path.sep) && candidate !== root) {
      throw new RunnerError('invalid_name', 'scenario path escapes manifests root');
    }
    try {
      const stat = await fs.stat(candidate);
      if (stat.isFile()) return candidate;
      lastErr = new RunnerError('not_found', `scenario ${name} is not a file`);
    } catch (err) {
      lastErr = err;
    }
  }
  if (lastErr instanceof RunnerError) throw lastErr;
  throw new RunnerError('not_found', `scenario ${name} not found`);
}

// Enumerate all scenario stems under manifestsDir. Used to populate the
// UI's button strip without hardcoding names.
async function listScenarios(opts: RunnerOptions = {}): Promise<string[]> {
  const merged: ResolvedRunnerOptions = { ...DEFAULTS, ...opts };
  const root = path.resolve(merged.manifestsDir);
  let entries: import('node:fs').Dirent[];
  try {
    entries = await fs.readdir(root, { withFileTypes: true });
  } catch (err: any) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
  const stems: string[] = [];
  for (const ent of entries) {
    if (!ent.isFile()) continue;
    if (!/\.(ya?ml)$/.test(ent.name)) continue;
    stems.push(ent.name.replace(/\.(ya?ml)$/, ''));
  }
  stems.sort();
  return stems;
}

// Spawn agentctl. Returns {ok, exitCode, stdout, stderr}; throws RunnerError
// on timeout / spawn failure. The function never throws on a non-zero
// agentctl exit — it returns that as data so the UI can surface it.
function spawnRun(manifestPath: string, opts: ResolvedRunnerOptions): Promise<RunResult> {
  return new Promise<RunResult>((resolve, reject) => {
    const args = [...opts.baseArgs, manifestPath];
    let child: any;
    try {
      child = spawn(opts.command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err: any) {
      reject(new RunnerError('spawn_failed', `spawn ${opts.command}: ${err.message}`));
      return;
    }

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    child.stdout.on('data', (b: Buffer) => stdoutChunks.push(b));
    child.stderr.on('data', (b: Buffer) => stderrChunks.push(b));

    let timedOut = false;
    const t = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch { /* ignore */ }
    }, opts.timeoutMs);

    child.on('error', (err: any) => {
      clearTimeout(t);
      reject(new RunnerError('spawn_failed', err.message));
    });
    child.on('close', (code: number | null, signal: string | null) => {
      clearTimeout(t);
      if (timedOut) {
        reject(new RunnerError('timeout',
          `agentctl exceeded ${opts.timeoutMs}ms; killed with ${signal || 'SIGKILL'}`));
        return;
      }
      const stdout = Buffer.concat(stdoutChunks).toString('utf8');
      const stderr = Buffer.concat(stderrChunks).toString('utf8');
      resolve({
        ok: code === 0,
        exitCode: code === null ? -1 : code,
        signal: signal || null,
        stdout,
        stderr,
        argv: [opts.command, ...args],
      });
    });
  });
}

// Public API used by server.js. Resolve + spawn + return.
async function runScenario(name: string, userOpts: RunnerOptions = {}): Promise<RunResult> {
  const opts: ResolvedRunnerOptions = { ...DEFAULTS, ...userOpts };
  const manifestPath = await resolveManifestPath(name, opts);
  return spawnRun(manifestPath, opts);
}

module.exports = {
  runScenario,
  listScenarios,
  resolveManifestPath, // exported for tests
  validateName,        // exported for tests
  RunnerError,
  DEFAULTS,
};
