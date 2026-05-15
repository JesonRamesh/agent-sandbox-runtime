// =============================================================================
// Agent Sandbox — file-backed policy store for the dashboard's PolicyView.
//
// The v2 dashboard's PolicyView/PolicyDialog (originally written for a
// REST-y `/api/policies` daemon endpoint that doesn't exist on our daemon)
// is wired against the playground YAML manifests instead. Each manifest is
// "a policy"; CRUD on /api/policies maps to writing/rewriting/deleting
// files under examples/playground/.
//
// Why files-on-disk instead of an in-memory store: the same files are also
// the input to scenario runs (agentctl run -f <yaml>), so a policy edit is
// immediately visible the next time the user clicks "run" — no separate
// reconciliation step. The daemon is the source of truth for what's
// enforced; this store is the source of truth for what's *configured*.
//
// Policy id mapping:
//   Filenames are normalized to "<id>-<slug>.yaml". The numeric id at the
//   front is what the UI sees. New policies allocate the next free id.
//   Pre-existing files that don't follow the pattern (e.g. test-it.sh)
//   are skipped so we don't surface them as policies.
// =============================================================================

'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

const { parseManifest, summarizePermissions } = require('./manifest');

// Filenames that look like a policy stem: <id>-<slug>.yaml or .yml.
// Captures the leading id and the slug (everything after the dash).
const POLICY_FILE_RE = /^(\d+)-([a-zA-Z0-9_-]+)\.(ya?ml)$/;

// Default command we drop into newly-created policies so that hitting "Run"
// after a fresh "Create" actually exercises the kernel pillars and produces
// visible events. Probes net, file, and exec; designed to fail loudly under
// a tight allow-list and to pass under a permissive one.
const DEFAULT_COMMAND = [
  '/bin/sh',
  '-c',
  [
    'echo "[probe] starting (will try net + file + exec) ..."',
    '/bin/echo "[probe] /bin/echo allowed"',
    'python3 -c \'',
    '  import socket, sys',
    '  try: socket.create_connection(("1.1.1.1", 80), timeout=3).close(); print("[probe] connect 1.1.1.1:80 OK")',
    '  except OSError as e: print(f"[probe] connect 1.1.1.1:80 BLOCKED errno={e.errno}")',
    '  try: open("/etc/hostname").read(); print("[probe] read /etc/hostname OK")',
    '  except OSError as e: print(f"[probe] read /etc/hostname BLOCKED errno={e.errno}")',
    '\' || true',
    'echo "[probe] done"',
  ].join('; '),
];

class PolicyStoreError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'PolicyStoreError';
    this.code = code; // 'not_found' | 'invalid' | 'conflict' | 'io'
  }
}

// Shape returned by readEntry / getById / listAll / create / update.
// Mirrors what PolicyView/PolicyDialog in the viewer-app consume.
interface Policy {
  id: number;
  name: string;
  display_name?: string;
  file?: string;
  mode: string;
  description?: string;
  allowed_hosts: string[];
  allowed_paths: string[];
  allowed_bins: string[];
  forbidden_caps: string[];
  deny_cleartext_egress?: boolean;
  command: string[];
  permissions?: unknown;
  raw?: string;
  parse_error?: string;
}

// Input shape for create/update. All allow-lists are optional because the
// UI omits empty ones; we coerce to [] downstream. The id is required for
// create; update derives it from the URL path.
interface PolicyInput {
  id?: number;
  name: string;
  display_name?: string;
  mode?: string;
  description?: string;
  allowed_hosts?: string[];
  allowed_paths?: string[];
  allowed_bins?: string[];
  forbidden_caps?: string[];
  deny_cleartext_egress?: boolean;
  command?: string[];
}

// Internal: enumerate every file in playgroundDir that matches the policy
// pattern, return {id, name, file} for each, sorted by id ascending.
async function listEntries(playgroundDir: string): Promise<{ id: number; name: string; file: string }[]> {
  let names: string[];
  try {
    names = await fs.readdir(playgroundDir);
  } catch (err: any) {
    if (err.code === 'ENOENT') return [];
    throw new PolicyStoreError('io', `read playground dir: ${err.message}`);
  }
  const entries: { id: number; name: string; file: string }[] = [];
  for (const name of names) {
    const m = POLICY_FILE_RE.exec(name);
    if (!m) continue;
    entries.push({
      id: Number(m[1]),
      name: m[2],
      file: path.join(playgroundDir, name),
    });
  }
  entries.sort((a, b) => a.id - b.id);
  return entries;
}

// Read one entry from disk and project it into the API shape the v2 UI
// consumes. Returns null on read/parse error so listAll can keep going.
async function readEntry(entry: { id: number; name: string; file: string }): Promise<Policy | null> {
  let text: string;
  try {
    text = await fs.readFile(entry.file, 'utf8');
  } catch {
    return null;
  }
  // parseManifest comes via require() so its return is `any` at this site.
  let parsed: any;
  try {
    parsed = parseManifest(text);
  } catch {
    // Manifest is broken on disk — surface the raw text so the UI can
    // still let the user fix it via the dialog.
    return {
      id: entry.id,
      name: entry.name,
      file: path.basename(entry.file),
      mode: 'enforce',
      allowed_hosts: [], allowed_paths: [], allowed_bins: [], forbidden_caps: [],
      command: [],
      description: '',
      raw: text,
      parse_error: 'manifest parse failed; edit and save to repair',
      permissions: null,
    };
  }
  return {
    id: entry.id,
    name: entry.name, // file slug (kebab); UI uses parsed.name as display label
    display_name: parsed.name || entry.name,
    file: path.basename(entry.file),
    mode: parsed.mode || 'enforce',
    description: parsed.description || '',
    allowed_hosts: parsed.allowed_hosts || [],
    allowed_paths: parsed.allowed_paths || [],
    allowed_bins: parsed.allowed_bins || [],
    forbidden_caps: parsed.forbidden_caps || [],
    deny_cleartext_egress: !!parsed.deny_cleartext_egress,
    command: parsed.command || [],
    permissions: summarizePermissions(parsed),
  };
}

async function listAll(playgroundDir: string): Promise<Policy[]> {
  const entries = await listEntries(playgroundDir);
  const out: Policy[] = [];
  for (const entry of entries) {
    const policy = await readEntry(entry);
    if (policy) out.push(policy);
  }
  return out;
}

async function getById(id: number, playgroundDir: string): Promise<Policy> {
  if (!Number.isInteger(id) || id < 1) {
    throw new PolicyStoreError('invalid', 'id must be a positive integer');
  }
  const entries = await listEntries(playgroundDir);
  const match = entries.find((e) => e.id === id);
  if (!match) throw new PolicyStoreError('not_found', `policy id=${id} not found`);
  const policy = await readEntry(match);
  if (!policy) throw new PolicyStoreError('io', `could not read policy id=${id}`);
  return policy;
}

// Render a policy object back out to a YAML string. Format-stable so a
// round-trip through the dashboard doesn't churn the file unnecessarily.
function renderYaml(policy: Policy | (PolicyInput & { display_name?: string })): string {
  const lines: string[] = [];
  lines.push('# Generated/edited by the viewer dashboard. Hand-edits welcome.');
  lines.push(`name: ${yamlScalar(policy.display_name || policy.name || 'unnamed')}`);
  if (policy.description) lines.push(`description: ${yamlScalar(policy.description)}`);
  lines.push(`mode: ${policy.mode || 'enforce'}`);
  if (policy.deny_cleartext_egress) {
    lines.push('deny_cleartext_egress: true');
  }

  const cmd = Array.isArray(policy.command) && policy.command.length > 0
    ? policy.command
    : DEFAULT_COMMAND;
  lines.push('command:');
  for (let i = 0; i < cmd.length; i++) {
    const s = String(cmd[i]);
    if (s.includes('\n')) {
      // Multi-line content → block scalar. The parser drops these on
      // re-read, but the agent's shell still sees them when run.
      lines.push('  - |');
      for (const ln of s.split('\n')) lines.push(`    ${ln}`);
    } else {
      lines.push(`  - ${yamlScalar(s)}`);
    }
  }

  for (const [key, list] of [
    ['allowed_hosts',  policy.allowed_hosts],
    ['allowed_paths',  policy.allowed_paths],
    ['allowed_bins',   policy.allowed_bins],
    ['forbidden_caps', policy.forbidden_caps],
  ]) {
    const arr = Array.isArray(list) ? list : [];
    if (arr.length === 0) {
      lines.push(`${key}: []`);
    } else {
      lines.push(`${key}:`);
      for (const item of arr) lines.push(`  - ${yamlScalar(String(item))}`);
    }
  }
  return lines.join('\n') + '\n';
}

// Quote a scalar only when the YAML reader would otherwise misinterpret it.
// We err on the side of quoting whenever the string contains a colon, hash,
// or starts with characters YAML treats specially.
function yamlScalar(s: string): string {
  if (s === '') return '""';
  if (/[:#"'\\]/.test(s) || /^[!&*?|>%@`-]/.test(s) || /^\s|\s$/.test(s)) {
    // Escape backslashes + double quotes, wrap in double quotes.
    const escaped = s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    return `"${escaped}"`;
  }
  return s;
}

function validateForCreate(policy: unknown): asserts policy is PolicyInput & { id: number } {
  if (!policy || typeof policy !== 'object') {
    throw new PolicyStoreError('invalid', 'policy body must be an object');
  }
  const p = policy as PolicyInput;
  const id = Number(p.id);
  if (!Number.isInteger(id) || id < 1) {
    throw new PolicyStoreError('invalid', 'id must be a positive integer');
  }
  if (typeof p.name !== 'string' || p.name.trim() === '') {
    throw new PolicyStoreError('invalid', 'name is required');
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(p.name)) {
    throw new PolicyStoreError('invalid', 'name may only contain letters, digits, "-", "_"');
  }
}

async function create(policy: PolicyInput, playgroundDir: string): Promise<Policy> {
  validateForCreate(policy);
  const entries = await listEntries(playgroundDir);
  if (entries.some((e) => e.id === policy.id)) {
    throw new PolicyStoreError('conflict', `id=${policy.id} already exists`);
  }
  const file = path.join(playgroundDir, `${policy.id}-${policy.name}.yaml`);
  const yaml = renderYaml({ ...policy, display_name: policy.display_name || policy.name });
  await fs.writeFile(file, yaml, 'utf8');
  return getById(policy.id!, playgroundDir);
}

async function update(id: number, policy: PolicyInput, playgroundDir: string): Promise<Policy> {
  if (!Number.isInteger(id) || id < 1) {
    throw new PolicyStoreError('invalid', 'id must be a positive integer');
  }
  if (typeof policy.name !== 'string' || policy.name.trim() === '') {
    throw new PolicyStoreError('invalid', 'name is required');
  }
  const entries = await listEntries(playgroundDir);
  const match = entries.find((e) => e.id === id);
  if (!match) throw new PolicyStoreError('not_found', `policy id=${id} not found`);

  // Preserve the existing command unless the caller sent one; the v2
  // PolicyDialog doesn't surface command, so a policy edit must not nuke
  // whatever script the manifest is meant to run.
  let command = policy.command;
  if (!Array.isArray(command) || command.length === 0) {
    const existing = await readEntry(match);
    command = (existing && existing.command) || DEFAULT_COMMAND;
  }

  const merged = {
    id,
    name: policy.name,
    display_name: policy.display_name || policy.name,
    mode: policy.mode || 'enforce',
    description: policy.description || '',
    allowed_hosts: policy.allowed_hosts || [],
    allowed_paths: policy.allowed_paths || [],
    allowed_bins:  policy.allowed_bins  || [],
    forbidden_caps: policy.forbidden_caps || [],
    deny_cleartext_egress: !!policy.deny_cleartext_egress,
    command,
  };

  // If the slug changed, rename the file. Otherwise just rewrite in place.
  const newFile = path.join(playgroundDir, `${id}-${policy.name}.yaml`);
  const yaml = renderYaml(merged);
  await fs.writeFile(match.file, yaml, 'utf8');
  if (path.resolve(match.file) !== path.resolve(newFile)) {
    await fs.rename(match.file, newFile);
  }
  return getById(id, playgroundDir);
}

async function remove(id: number, playgroundDir: string): Promise<{ id: number; removed: boolean }> {
  if (!Number.isInteger(id) || id < 1) {
    throw new PolicyStoreError('invalid', 'id must be a positive integer');
  }
  const entries = await listEntries(playgroundDir);
  const match = entries.find((e) => e.id === id);
  if (!match) throw new PolicyStoreError('not_found', `policy id=${id} not found`);
  await fs.unlink(match.file);
  return { id, removed: true };
}

// nextId returns the smallest free positive integer not currently assigned
// to any policy file. Used by the UI's "create" form to pre-fill the id.
async function nextId(playgroundDir: string): Promise<number> {
  const entries = await listEntries(playgroundDir);
  const used = new Set(entries.map((e) => e.id));
  let i = 1;
  while (used.has(i)) i += 1;
  return i;
}

// Map a policy id to the agentctl-runnable scenario stem (the filename
// without extension). Used by /api/bindings to translate a policy_id into
// something runner.runScenario understands.
async function scenarioStemForId(id: number, playgroundDir: string): Promise<string> {
  const entries = await listEntries(playgroundDir);
  const match = entries.find((e) => e.id === id);
  if (!match) throw new PolicyStoreError('not_found', `policy id=${id} not found`);
  return path.basename(match.file).replace(/\.(ya?ml)$/, '');
}

module.exports = {
  listAll,
  getById,
  create,
  update,
  remove,
  nextId,
  scenarioStemForId,
  PolicyStoreError,
  // Exported for tests + introspection.
  POLICY_FILE_RE,
  DEFAULT_COMMAND,
  renderYaml,
};
