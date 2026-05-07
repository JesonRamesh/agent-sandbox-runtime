// Run with: node --test viewer/server/transform.test.js
//
// Covers the daemon→UI schema translation in transform.js. We don't stub a
// network — the function is pure on purpose so it's directly callable.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  transformDaemonEvent,
  isoToEpochSeconds,
  agentLabel,
  buildKernelData,
  pillarOf,
  uiTypeFor,
  UI_KERNEL_TYPES,
  UI,
} = require('./transform');

test('isoToEpochSeconds parses RFC3339 to float seconds', () => {
  assert.equal(isoToEpochSeconds('1970-01-01T00:00:00Z'), 0);
  assert.equal(isoToEpochSeconds('1970-01-01T00:00:01.500Z'), 1.5);
});

test('isoToEpochSeconds returns 0 on bad input (never NaN)', () => {
  assert.equal(isoToEpochSeconds('not a date'), 0);
  assert.equal(isoToEpochSeconds(undefined), 0);
  assert.equal(isoToEpochSeconds(null), 0);
  assert.equal(isoToEpochSeconds(12345), 0);
});

test('agentLabel uses name from registry when known', () => {
  const names = new Map([['agt_abc123def456', 'my-agent']]);
  assert.equal(agentLabel('agt_abc123def456', names), 'my-agent');
});

test('agentLabel falls back to id prefix when name unknown', () => {
  assert.equal(agentLabel('agt_abc123def456789', new Map()), 'agt_abc123de');
});

test('agentLabel keeps short ids intact', () => {
  assert.equal(agentLabel('short', new Map()), 'short');
});

test('pillarOf groups kinds correctly', () => {
  assert.equal(pillarOf('net.connect'), 'net');
  assert.equal(pillarOf('net.sendto'), 'net');
  assert.equal(pillarOf('file.open'), 'file');
  assert.equal(pillarOf('exec'), 'exec');
  assert.equal(pillarOf('exec.bprm'), 'exec');
  assert.equal(pillarOf('creds.setuid'), 'cred');
  assert.equal(pillarOf('creds.capset'), 'cred');
  assert.equal(pillarOf('made.up'), 'unknown');
});

test('uiTypeFor encodes pillar × verdict', () => {
  assert.equal(uiTypeFor('net', 'allow'), 'net_allowed');
  assert.equal(uiTypeFor('net', 'deny'), 'net_blocked');
  assert.equal(uiTypeFor('file', 'allow'), 'file_allowed');
  assert.equal(uiTypeFor('file', 'deny'), 'file_blocked');
  assert.equal(uiTypeFor('exec', 'audit'), 'exec_allowed'); // audit ≠ deny → allowed
  assert.equal(uiTypeFor('cred', 'deny'), 'cred_blocked');
});

test('UI_KERNEL_TYPES exports the eight pillar×verdict types', () => {
  assert.equal(UI_KERNEL_TYPES.size, 8);
  for (const t of [
    'net_allowed', 'net_blocked',
    'file_allowed', 'file_blocked',
    'exec_allowed', 'exec_blocked',
    'cred_allowed', 'cred_blocked',
  ]) {
    assert.equal(UI_KERNEL_TYPES.has(t), true, `missing ${t}`);
  }
});

test('agent.started registers the manifest name and is dropped', () => {
  const names = new Map();
  const result = transformDaemonEvent(
    {
      ts: '2026-05-06T21:00:00Z',
      agent_id: 'agt_xyz1',
      type: 'agent.started',
      pid: 1234,
      details: { name: 'scenario-1', command: ['python3'] },
    },
    names,
  );
  assert.equal(result, null);
  assert.equal(names.get('agt_xyz1'), 'scenario-1');
});

test('net.connect deny → net_blocked carrying daemon-attributed reason', () => {
  const names = new Map([['agt_xyz1', 'scenario-2']]);
  const ev = transformDaemonEvent(
    {
      ts: '2026-05-06T21:00:00Z',
      agent_id: 'agt_xyz1',
      type: 'net.connect',
      pid: 1234,
      details: {
        verdict: 'deny',
        comm: 'python3',
        daddr: '8.8.8.8',
        dport: 53,
        reason_code: 'host_not_in_allowlist',
        reason_message: '8.8.8.8:53 not in allowed_hosts [1.1.1.1:80]',
        pillar: 'net',
      },
    },
    names,
  );
  assert.equal(ev.type, 'net_blocked');
  assert.equal(ev.agent, 'scenario-2');
  assert.equal(ev.ts, 1778101200);
  assert.equal(ev.data.pillar, 'net');
  assert.equal(ev.data.kind, 'net.connect');
  assert.equal(ev.data.target, '8.8.8.8:53');
  assert.equal(ev.data.dst_ip, '8.8.8.8');
  assert.equal(ev.data.dst_port, 53);
  assert.equal(ev.data.reason_code, 'host_not_in_allowlist');
  assert.equal(ev.data.reason, '8.8.8.8:53 not in allowed_hosts [1.1.1.1:80]');
  assert.equal(ev.data.pid, 1234);
});

test('net.connect allow with matched_rule → net_allowed surfacing the rule', () => {
  const ev = transformDaemonEvent(
    {
      ts: '2026-05-06T21:00:00Z',
      agent_id: 'agt_a',
      type: 'net.connect',
      pid: 1,
      details: {
        verdict: 'allow',
        daddr: '1.1.1.1',
        dport: 80,
        reason_code: 'host_allowed',
        reason_message: '1.1.1.1:80 matches "1.1.1.1:80"',
        matched_rule: '1.1.1.1:80',
      },
    },
    new Map(),
  );
  assert.equal(ev.type, 'net_allowed');
  assert.equal(ev.data.matched_rule, '1.1.1.1:80');
  assert.equal(ev.data.reason, '1.1.1.1:80 matches "1.1.1.1:80"');
});

test('net.connect audit verdict treated as allowed (call did not fail)', () => {
  const ev = transformDaemonEvent(
    {
      ts: '2026-05-06T21:00:00Z',
      agent_id: 'agt_a',
      type: 'net.connect',
      pid: 1,
      details: { verdict: 'audit', daddr: '1.2.3.4', dport: 9 },
    },
    new Map(),
  );
  assert.equal(ev.type, 'net_allowed');
});

test('file.open deny → file_blocked with target=path, no dst_ip', () => {
  const ev = transformDaemonEvent(
    {
      ts: '2026-05-06T21:00:00Z',
      agent_id: 'agt_3',
      type: 'file.open',
      pid: 1,
      details: {
        verdict: 'deny',
        comm: 'python3',
        path: '/etc/shadow',
        reason_message: '/etc/shadow not in allowed_paths [/etc/hostname]',
      },
    },
    new Map([['agt_3', 'scenario-3']]),
  );
  assert.equal(ev.type, 'file_blocked');
  assert.equal(ev.agent, 'scenario-3');
  assert.equal(ev.data.target, '/etc/shadow');
  assert.equal(ev.data.path, '/etc/shadow');
  assert.equal(ev.data.dst_ip, undefined);
  assert.equal(ev.data.reason, '/etc/shadow not in allowed_paths [/etc/hostname]');
});

test('exec.bprm deny → exec_blocked with target=filename', () => {
  const ev = transformDaemonEvent(
    {
      ts: '2026-05-06T21:00:00Z',
      agent_id: 'agt_4',
      type: 'exec.bprm',
      pid: 1,
      details: {
        verdict: 'deny',
        comm: 'sh',
        filename: '/usr/bin/curl',
        reason_message: '/usr/bin/curl not in allowed_bins [/bin/sh, /bin/echo]',
      },
    },
    new Map(),
  );
  assert.equal(ev.type, 'exec_blocked');
  assert.equal(ev.data.target, '/usr/bin/curl');
  assert.equal(ev.data.filename, '/usr/bin/curl');
});

test('creds.capset deny formats cap_effective as hex', () => {
  const ev = transformDaemonEvent(
    {
      ts: '2026-05-06T21:00:00Z',
      agent_id: 'agt_5',
      type: 'creds.capset',
      pid: 1,
      details: { verdict: 'deny', cap_effective: 0xdeadbeef },
    },
    new Map(),
  );
  assert.equal(ev.type, 'cred_blocked');
  assert.match(ev.data.target, /capset: cap_eff=0xdeadbeef/);
});

test('agent.exited → stopped with exit_code', () => {
  const ev = transformDaemonEvent(
    {
      ts: '2026-05-06T21:00:00Z',
      agent_id: 'agt_6',
      type: 'agent.exited',
      pid: 1,
      details: { exit_code: 0 },
    },
    new Map([['agt_6', 'scenario-6']]),
  );
  assert.equal(ev.type, 'stopped');
  assert.equal(ev.data.exit_code, 0);
  assert.equal(ev.agent, 'scenario-6');
});

test('agent.crashed → crashed', () => {
  const ev = transformDaemonEvent(
    {
      ts: '2026-05-06T21:00:00Z',
      agent_id: 'agt_7',
      type: 'agent.crashed',
      pid: 1,
      details: { exit_code: 137 },
    },
    new Map(),
  );
  assert.equal(ev.type, 'crashed');
  assert.equal(ev.data.exit_code, 137);
});

test('llm.* and unknown event types are dropped', () => {
  for (const t of ['llm.tool_call', 'llm.stdout', 'totally_made_up']) {
    const ev = transformDaemonEvent(
      { ts: '2026-05-06T21:00:00Z', agent_id: 'agt_x', type: t, pid: 1, details: {} },
      new Map(),
    );
    assert.equal(ev, null, `expected drop for type ${t}`);
  }
});

test('malformed input is rejected', () => {
  for (const bad of [
    null,
    {},
    { type: 'net.connect' },                         // missing agent_id
    { agent_id: 'agt_x' },                            // missing type
    { agent_id: 'agt_x', type: 42 },                 // type wrong sort
  ]) {
    assert.equal(transformDaemonEvent(bad, new Map()), null);
  }
});

test('buildKernelData on unknown kind preserves the kind name', () => {
  const data = buildKernelData('made.up.kind', { verdict: 'allow', comm: 'x' });
  assert.equal(data.target, 'kernel:made.up.kind');
  assert.equal(data.kind, 'made.up.kind');
});

test('falls back when daemon does not provide reason_message', () => {
  // Old-format daemon event (no reason_message). Bridge should still
  // produce something sensible.
  const ev = transformDaemonEvent(
    {
      ts: '2026-05-06T21:00:00Z',
      agent_id: 'agt_z',
      type: 'net.connect',
      pid: 1,
      details: { verdict: 'deny', daddr: '8.8.8.8', dport: 53 },
    },
    new Map(),
  );
  assert.equal(ev.type, 'net_blocked');
  assert.match(ev.data.reason, /net\.connect deny/);
});
