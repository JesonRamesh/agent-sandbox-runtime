// Run with: node --test viewer/server/runner.test.js
//
// Covers scenario name validation, path resolution (containment + traversal
// rejection), listScenarios enumeration, and the spawn pipeline. The spawn
// tests exec /bin/echo or /bin/false rather than agentctl so they are
// hermetic — no daemon, no sudo.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

const {
  runScenario,
  listScenarios,
  resolveManifestPath,
  validateName,
  RunnerError,
} = require('./runner');

async function makeTempPlayground() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'runner-test-'));
  await fs.writeFile(path.join(dir, '01-baseline.yaml'),  'name: t\n', 'utf8');
  await fs.writeFile(path.join(dir, '02-second.yml'),     'name: t\n', 'utf8');
  await fs.writeFile(path.join(dir, 'README.md'),         '# noise\n', 'utf8');
  return dir;
}

test('validateName rejects empty, too long, traversal, and odd chars', () => {
  for (const bad of ['', '.', '..', 'a/b', '../etc/passwd', 'name with space', 'x'.repeat(65)]) {
    assert.throws(() => validateName(bad), RunnerError, `bad name should throw: ${JSON.stringify(bad)}`);
  }
});

test('validateName accepts kebab/snake/dot names', () => {
  for (const ok of ['01-baseline-allowed', 'foo_bar', 'a.b.c', 'X1', 'agent-2_v2']) {
    assert.doesNotThrow(() => validateName(ok));
  }
});

test('resolveManifestPath finds .yaml and .yml stems and rejects missing', async () => {
  const dir = await makeTempPlayground();
  const yaml = await resolveManifestPath('01-baseline', { manifestsDir: dir });
  assert.equal(yaml, path.join(dir, '01-baseline.yaml'));
  const yml = await resolveManifestPath('02-second', { manifestsDir: dir });
  assert.equal(yml, path.join(dir, '02-second.yml'));
  await assert.rejects(
    resolveManifestPath('does-not-exist', { manifestsDir: dir }),
    (err: any) => err instanceof RunnerError && err.code === 'not_found',
  );
});

test('resolveManifestPath rejects traversal even via dotted name', async () => {
  const dir = await makeTempPlayground();
  // The file `..yaml` would be inside dir, but `..` alone is rejected.
  await assert.rejects(
    resolveManifestPath('..', { manifestsDir: dir }),
    (err: any) => err instanceof RunnerError && err.code === 'invalid_name',
  );
});

test('listScenarios returns sorted stems and skips non-yaml files', async () => {
  const dir = await makeTempPlayground();
  const stems = await listScenarios({ manifestsDir: dir });
  assert.deepEqual(stems, ['01-baseline', '02-second']);
});

test('listScenarios returns [] when dir is missing rather than throwing', async () => {
  const stems = await listScenarios({ manifestsDir: '/no/such/path-89234' });
  assert.deepEqual(stems, []);
});

test('runScenario spawns the configured command with manifest path appended', async () => {
  const dir = await makeTempPlayground();
  // Use /bin/echo so the test is hermetic. echo prints its argv, which lets
  // us assert the manifest path is the LAST positional arg.
  const res = await runScenario('01-baseline', {
    manifestsDir: dir,
    command: '/bin/echo',
    baseArgs: ['preamble'],
    timeoutMs: 10_000,
  });
  assert.equal(res.ok, true);
  assert.equal(res.exitCode, 0);
  assert.match(res.stdout, /preamble/);
  assert.match(res.stdout, /01-baseline\.yaml$/m);
});

test('runScenario reports non-zero exit without throwing', async () => {
  const dir = await makeTempPlayground();
  const res = await runScenario('01-baseline', {
    manifestsDir: dir,
    command: '/bin/false',
    baseArgs: [],
    timeoutMs: 10_000,
  });
  assert.equal(res.ok, false);
  assert.notEqual(res.exitCode, 0);
});

test('runScenario times out and rejects with RunnerError(timeout)', async () => {
  const dir = await makeTempPlayground();
  // Use `node -e` so the trailing manifest path argv is harmless. /bin/sleep
  // would error out on extra operands; node treats them as positional argv
  // for an -e expression that explicitly ignores them.
  await assert.rejects(
    runScenario('01-baseline', {
      manifestsDir: dir,
      command: process.execPath,
      baseArgs: ['-e', 'setTimeout(() => {}, 5000)'],
      timeoutMs: 200,
    }),
    (err: any) => err instanceof RunnerError && err.code === 'timeout',
  );
});

test('runScenario rejects bad name before spawning anything', async () => {
  const dir = await makeTempPlayground();
  await assert.rejects(
    runScenario('../passwd', {
      manifestsDir: dir,
      command: '/bin/echo',
      baseArgs: [],
      timeoutMs: 10_000,
    }),
    (err: any) => err instanceof RunnerError && err.code === 'invalid_name',
  );
});
