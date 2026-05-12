// =============================================================================
// Agent Sandbox — manifest reader for the dashboard's permissions view.
//
// We deliberately do not pull in a full YAML library here. The viewer only
// needs to display the four allow-lists (allowed_hosts, allowed_paths,
// allowed_bins, forbidden_caps) plus a few scalar fields (name, mode,
// description). The on-disk manifest format is well-controlled: the
// playground YAMLs only use a tiny subset of YAML — top-level keys, simple
// scalars, lists of scalars, an inline empty list `[]`, and one block
// scalar (`|`) inside `command:` whose contents we don't care about.
//
// This parser is purpose-built for that subset. It deliberately rejects
// anything it doesn't recognize at the top level rather than guessing —
// a malformed manifest should fail the GET /api/scenarios response loudly,
// not silently render half-correct permissions.
//
// The kernel still validates the real manifest via internal/manifest in Go;
// this module only powers the dashboard's "what is this agent allowed to
// do?" panel, so a parse mismatch with the canonical Go validator is not a
// security boundary.
// =============================================================================

'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

// Top-level keys we recognize. Anything else found at column 0 is an error
// (so a typo in the manifest doesn't silently disappear from the UI).
const KNOWN_KEYS = new Set([
  'name', 'command', 'mode', 'description',
  'allowed_hosts', 'allowed_paths', 'allowed_bins', 'forbidden_caps',
  'deny_cleartext_egress',  // bool — kernel forbids non-TLS-port connects
  'working_dir', 'env', 'user', 'stdin', 'timeout',
]);

class ManifestParseError extends Error {
  constructor(line, message) {
    super(`manifest parse error at line ${line}: ${message}`);
    this.name = 'ManifestParseError';
    this.lineNumber = line;
  }
}

function parseScalar(raw) {
  let s = raw.trim();
  if (s === '') return '';
  // Quoted strings — strip surrounding quotes, no escape handling (our
  // manifests don't use any).
  if ((s.startsWith('"') && s.endsWith('"')) ||
      (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  if (/^-?\d+$/.test(s)) return Number(s);
  if (/^-?\d+\.\d+$/.test(s)) return Number(s);
  // YAML 1.2 boolean literals; the Go parser is permissive here too
  // (see internal/manifest/parse.go scalarBool).
  const lower = s.toLowerCase();
  if (lower === 'true'  || lower === 'yes' || lower === 'on')  return true;
  if (lower === 'false' || lower === 'no'  || lower === 'off') return false;
  if (s === 'null' || s === '~') return null;
  return s;
}

function stripComment(line) {
  // Comment scanner that respects (single-quoted, double-quoted) strings.
  // Returns the line up to but not including the first unquoted '#'.
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '#' && !inSingle && !inDouble) return line.slice(0, i);
  }
  return line;
}

// Parse a manifest YAML document into a plain object containing exactly the
// keys we care about. Throws ManifestParseError on unsupported or malformed
// input.
function parseManifest(text) {
  const lines = text.split('\n');
  const result = {};
  let currentKey = null;
  let inBlockScalar = false;
  let blockScalarIndent = -1;

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    let line = stripComment(lines[i]).replace(/\s+$/, '');
    if (line === '') {
      // Blank line — does not exit a block scalar, does not break a list.
      continue;
    }

    // If we're inside a block scalar, exit only when indentation drops.
    if (inBlockScalar) {
      const indent = line.match(/^ */)[0].length;
      if (indent > blockScalarIndent) continue; // still inside
      inBlockScalar = false;
      blockScalarIndent = -1;
      // Fall through and process this line as normal.
    }

    // Top-level key: must start at column 0.
    const topMatch = /^([a-zA-Z_][a-zA-Z0-9_]*):\s*(.*)$/.exec(line);
    if (line[0] !== ' ' && line[0] !== '\t') {
      if (!topMatch) {
        throw new ManifestParseError(lineNo, `expected "key:" at column 0, got ${JSON.stringify(line)}`);
      }
      const key = topMatch[1];
      const valueRaw = topMatch[2];
      if (!KNOWN_KEYS.has(key)) {
        throw new ManifestParseError(lineNo, `unknown top-level key ${JSON.stringify(key)}`);
      }
      currentKey = key;

      const v = valueRaw.trim();
      if (v === '') {
        // Bare key — expect either a following list of `- entries` or a
        // block scalar. We seed the value as [] and let the next iteration
        // either fill it or detect a block scalar.
        result[key] = [];
      } else if (v === '[]') {
        result[key] = [];
        currentKey = null;
      } else if (v === '{}') {
        result[key] = {};
        currentKey = null;
      } else if (v === '|' || v === '|-' || v === '>' || v === '>-') {
        // Block scalar that ends at the next column-0 line.
        inBlockScalar = true;
        blockScalarIndent = 0;
        result[key] = null; // signal "skipped block scalar"
        currentKey = null;
      } else {
        result[key] = parseScalar(v);
        currentKey = null;
      }
      continue;
    }

    // Indented line: must be either a list item, an entry under `env:`,
    // a block-scalar marker `- |`, or content we ignore (e.g. continuation
    // of a block scalar — handled above).
    const listMatch = /^( +)- (.*)$/.exec(line);
    if (listMatch) {
      if (currentKey === null) {
        throw new ManifestParseError(lineNo, 'list item without an enclosing key');
      }
      const indent = listMatch[1].length;
      const item = listMatch[2].trim();
      if (item === '|' || item === '|-' || item === '>' || item === '>-') {
        // Block scalar list item (multiline string in `command:`). Track
        // its indent and skip lines indented more than the parent dash.
        inBlockScalar = true;
        blockScalarIndent = indent;
        // We deliberately do not push a value — the dashboard never shows
        // command bodies.
        continue;
      }
      if (!Array.isArray(result[currentKey])) {
        throw new ManifestParseError(lineNo, `list item under non-list key ${JSON.stringify(currentKey)}`);
      }
      result[currentKey].push(parseScalar(item));
      continue;
    }

    // env: subkey lines (`  KEY: value`). We only need the keys to know
    // what env vars the agent runs with — don't error, just skip them.
    if (currentKey === 'env' && /^( +)[A-Za-z_][A-Za-z0-9_]*:\s*(.*)$/.test(line)) {
      // Lift result.env to a map if we hadn't yet, then drop the entry in.
      if (!result.env || typeof result.env !== 'object' || Array.isArray(result.env)) {
        result.env = {};
      }
      const m = /^( +)([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$/.exec(line);
      result.env[m[2]] = parseScalar(m[3]);
      continue;
    }

    // Anything else indented and not in a block scalar is malformed for our
    // dashboard's needs. Don't silently swallow it.
    throw new ManifestParseError(lineNo, `unexpected indented line ${JSON.stringify(line)}`);
  }

  return result;
}

// Produce a UI-ready summary from a parsed manifest. The output is what the
// React permissions card consumes; it deliberately interprets the four
// pillars' "empty allow-list" semantics (which differ between pillars) so
// the UI doesn't have to.
function summarizePermissions(manifest) {
  const m = manifest || {};
  const mode = (m.mode || 'enforce').toString();
  const pillars = [
    {
      id: 'network',
      label: 'Network',
      manifestKey: 'allowed_hosts',
      allowed: Array.isArray(m.allowed_hosts) ? m.allowed_hosts.map(String) : [],
      tlsOnly: !!m.deny_cleartext_egress,
      // allowed_hosts: empty list = deny all outbound.
      describe(allowed, _forbidden, ctx) {
        const tlsSuffix = ctx && ctx.tlsOnly
          ? ' — and the kernel denies any non-TLS port even on this list (deny_cleartext_egress=true)'
          : '';
        if (allowed.length === 0) {
          return { tone: 'restrictive', text: 'all outbound network is blocked' + tlsSuffix };
        }
        return { tone: 'allow', text: `outbound only to ${formatList(allowed)}` + tlsSuffix };
      },
    },
    {
      id: 'filesystem',
      label: 'Filesystem',
      manifestKey: 'allowed_paths',
      allowed: Array.isArray(m.allowed_paths) ? m.allowed_paths.map(String) : [],
      // allowed_paths: empty list = deny all opens.
      describe(allowed) {
        if (allowed.length === 0) {
          return { tone: 'restrictive', text: 'every file open is blocked (the agent cannot even load its own libraries)' };
        }
        if (allowed.length === 1 && allowed[0] === '/') {
          return { tone: 'permissive', text: 'every path is reachable (no filesystem isolation)' };
        }
        return { tone: 'allow', text: `paths reachable: ${formatList(allowed)}` };
      },
    },
    {
      id: 'exec',
      label: 'Exec',
      manifestKey: 'allowed_bins',
      allowed: Array.isArray(m.allowed_bins) ? m.allowed_bins.map(String) : [],
      // allowed_bins: empty list = allow any binary (per the daemon's
      // policy.Explain semantics in internal/policy/attribute.go).
      describe(allowed) {
        if (allowed.length === 0) {
          return { tone: 'permissive', text: 'any binary may exec (no exec allow-list)' };
        }
        return { tone: 'allow', text: `only these binaries may exec: ${formatList(allowed)}` };
      },
    },
    {
      id: 'credentials',
      label: 'Credentials',
      manifestKey: 'forbidden_caps',
      allowed: [],
      forbidden: Array.isArray(m.forbidden_caps) ? m.forbidden_caps.map(String) : [],
      // forbidden_caps: list of caps the agent is NOT allowed to acquire.
      describe(_allowed, forbidden) {
        if (!forbidden || forbidden.length === 0) {
          return { tone: 'permissive', text: 'no capability operations are blocked' };
        }
        return { tone: 'restrictive', text: `agent may not acquire ${formatList(forbidden)}` };
      },
    },
  ];

  // Build per-pillar entries with the description prefilled.
  for (const p of pillars) {
    const d = p.describe(p.allowed, p.forbidden, p);
    p.tone = d.tone;
    p.summary = d.text;
    delete p.describe;
  }

  return {
    name: m.name || '',
    mode,
    description: m.description || '',
    deny_cleartext_egress: !!m.deny_cleartext_egress,
    pillars,
  };
}

function formatList(xs) {
  if (xs.length <= 3) return xs.join(', ');
  return `${xs.slice(0, 3).join(', ')}, +${xs.length - 3} more`;
}

// Read + parse + summarize a single scenario file under manifestsDir. Used
// by the server to populate the GET /api/scenarios response.
async function loadPermissions(scenarioName, manifestsDir) {
  const candidates = [
    path.join(manifestsDir, `${scenarioName}.yaml`),
    path.join(manifestsDir, `${scenarioName}.yml`),
  ];
  for (const candidate of candidates) {
    try {
      const text = await fs.readFile(candidate, 'utf8');
      const parsed = parseManifest(text);
      return { ok: true, summary: summarizePermissions(parsed) };
    } catch (err) {
      if (err.code === 'ENOENT') continue;
      return { ok: false, error: err.message };
    }
  }
  return { ok: false, error: `manifest ${scenarioName} not found` };
}

module.exports = {
  parseManifest,
  summarizePermissions,
  loadPermissions,
  ManifestParseError,
};
