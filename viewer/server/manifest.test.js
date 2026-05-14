// Run with: node --test viewer/server/manifest.test.js
//
// Covers the tiny YAML reader for manifest files used by the dashboard's
// permissions panel. We test against synthetic YAMLs that mirror the
// playground manifest shape, plus a couple of edge cases the parser must
// reject loudly.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

const {
  parseManifest,
  summarizePermissions,
  loadPermissions,
  ManifestParseError,
} = require('./manifest');

const SAMPLE_FULL = `# A representative scenario manifest.
name: scenario-1-baseline-allowed
mode: enforce
description: "baseline scenario"
command:
  - python3
  - -c
  - |
    import socket, sys
    socket.create_connection(("1.1.1.1", 80))
    print("done")
allowed_hosts:
  - 1.1.1.1:80
allowed_paths:
  - /
allowed_bins:
  - /usr/bin/python3
forbidden_caps: []
`;

test('parseManifest reads scalars, lists, [], and skips block scalars', () => {
  const m = parseManifest(SAMPLE_FULL);
  assert.equal(m.name, 'scenario-1-baseline-allowed');
  assert.equal(m.mode, 'enforce');
  assert.equal(m.description, 'baseline scenario');
  assert.deepEqual(m.allowed_hosts, ['1.1.1.1:80']);
  assert.deepEqual(m.allowed_paths, ['/']);
  assert.deepEqual(m.allowed_bins, ['/usr/bin/python3']);
  assert.deepEqual(m.forbidden_caps, []);
  // command's block scalar body is dropped, but the list itself records
  // the non-block items.
  assert.deepEqual(m.command, ['python3', '-c']);
});

test('parseManifest tolerates blank lines inside lists', () => {
  const m = parseManifest(`
allowed_paths:
  - /etc/hostname

  - /etc/ld.so.cache
`);
  assert.deepEqual(m.allowed_paths, ['/etc/hostname', '/etc/ld.so.cache']);
});

test('parseManifest preserves comments only when inside quoted strings', () => {
  const m = parseManifest(`name: "foo # not a comment"\nmode: enforce # this is a comment\n`);
  assert.equal(m.name, 'foo # not a comment');
  assert.equal(m.mode, 'enforce');
});

test('parseManifest rejects unknown top-level keys', () => {
  assert.throws(
    () => parseManifest('mystery_key: hello\n'),
    ManifestParseError,
  );
});

test('parseManifest rejects garbage at column 0', () => {
  assert.throws(
    () => parseManifest('---not yaml---\n'),
    ManifestParseError,
  );
});

test('parseManifest rejects orphan list items', () => {
  assert.throws(
    () => parseManifest('  - orphan\n'),
    ManifestParseError,
  );
});

test('summarizePermissions describes empty allowed_hosts as fully blocked', () => {
  const s = summarizePermissions({ allowed_hosts: [], allowed_paths: ['/etc/hostname'] });
  const network = s.pillars.find((p) => p.id === 'network');
  assert.equal(network.tone, 'restrictive');
  assert.match(network.summary, /all outbound network is blocked/);
});

test('summarizePermissions describes allowed_paths=[/] as no filesystem isolation', () => {
  const s = summarizePermissions({ allowed_paths: ['/'] });
  const fs_ = s.pillars.find((p) => p.id === 'filesystem');
  assert.equal(fs_.tone, 'permissive');
  assert.match(fs_.summary, /every path is reachable/);
});

test('summarizePermissions describes empty allowed_bins as "any binary"', () => {
  const s = summarizePermissions({ allowed_bins: [] });
  const exec_ = s.pillars.find((p) => p.id === 'exec');
  assert.equal(exec_.tone, 'permissive');
  assert.match(exec_.summary, /any binary may exec/);
});

test('summarizePermissions describes forbidden_caps as a deny list', () => {
  const s = summarizePermissions({ forbidden_caps: ['CAP_SYS_ADMIN', 'CAP_BPF'] });
  const cred = s.pillars.find((p) => p.id === 'credentials');
  assert.equal(cred.tone, 'restrictive');
  assert.match(cred.summary, /CAP_SYS_ADMIN/);
  assert.match(cred.summary, /CAP_BPF/);
});

test('summarizePermissions truncates long allow-lists', () => {
  const s = summarizePermissions({ allowed_paths: ['/a', '/b', '/c', '/d', '/e'] });
  const fs_ = s.pillars.find((p) => p.id === 'filesystem');
  assert.match(fs_.summary, /\+2 more/);
});

test('summarizePermissions defaults mode to "enforce"', () => {
  assert.equal(summarizePermissions({}).mode, 'enforce');
  assert.equal(summarizePermissions({ mode: 'audit' }).mode, 'audit');
});

test('parseManifest reads deny_cleartext_egress as a truthy/falsy scalar', () => {
  // The generic YAML scalar parser returns `true` for the YAML 1.2 bool
  // words and `1`/`0` (as numbers) for the digit literals — the
  // consuming code coerces via `!!`. Test truthiness, not literal type.
  const m = parseManifest(`
name: tls-only
mode: enforce
allowed_hosts:
  - example.com:443
deny_cleartext_egress: true
`);
  assert.equal(m.deny_cleartext_egress, true);
  for (const v of ['yes', 'on', '1', 'true']) {
    const m2 = parseManifest(`name: x\ndeny_cleartext_egress: ${v}\n`);
    assert.ok(m2.deny_cleartext_egress, `value ${v} should be truthy`);
  }
  for (const v of ['false', 'no', 'off', '0']) {
    const m2 = parseManifest(`name: x\ndeny_cleartext_egress: ${v}\n`);
    assert.ok(!m2.deny_cleartext_egress, `value ${v} should be falsy`);
  }
});

test('summarizePermissions surfaces deny_cleartext_egress in the network pillar text', () => {
  const s = summarizePermissions({
    allowed_hosts: ['example.com:443'],
    deny_cleartext_egress: true,
  });
  assert.equal(s.deny_cleartext_egress, true);
  const net = s.pillars.find((p) => p.id === 'network');
  assert.match(net.summary, /deny_cleartext_egress/);
});

test('loadPermissions reads .yaml under a temp dir and returns summary', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'manifest-test-'));
  await fs.writeFile(path.join(dir, '01-baseline.yaml'), SAMPLE_FULL, 'utf8');
  const out = await loadPermissions('01-baseline', dir);
  assert.equal(out.ok, true);
  assert.equal(out.summary.name, 'scenario-1-baseline-allowed');
  const network = out.summary.pillars.find((p) => p.id === 'network');
  assert.deepEqual(network.allowed, ['1.1.1.1:80']);
});

test('loadPermissions returns ok=false for missing scenarios', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'manifest-test-'));
  const out = await loadPermissions('nope', dir);
  assert.equal(out.ok, false);
  assert.match(out.error, /not found/);
});

test('loadPermissions returns parser errors verbatim (does not throw)', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'manifest-test-'));
  await fs.writeFile(path.join(dir, 'bad.yaml'), 'mystery: yes\n', 'utf8');
  const out = await loadPermissions('bad', dir);
  assert.equal(out.ok, false);
  assert.match(out.error, /unknown top-level key/);
});

// Roundtrip: parse all four real playground manifests through the parser to
// make sure the production files are happy. Skipped if the directory does
// not exist (e.g. running tests from a packaged tarball).
test('parses every real playground manifest without error', async () => {
  const dir = path.resolve(__dirname, '..', '..', 'examples', 'playground');
  let files;
  try { files = await fs.readdir(dir); } catch { return; }
  for (const f of files) {
    if (!/\.(ya?ml)$/.test(f)) continue;
    const text = await fs.readFile(path.join(dir, f), 'utf8');
    let parsed;
    try { parsed = parseManifest(text); }
    catch (err) {
      assert.fail(`parsing ${f} failed: ${err.message}`);
    }
    // Make sure summarize doesn't throw on real input.
    summarizePermissions(parsed);
  }
});
