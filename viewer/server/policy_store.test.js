// Run with: node --test viewer/server/policy_store.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

const {
  listAll, getById, create, update, remove, nextId, scenarioStemForId,
  PolicyStoreError, renderYaml,
} = require('./policy_store');

async function tempPlayground() {
  return fs.mkdtemp(path.join(os.tmpdir(), 'policy-store-test-'));
}

const SAMPLE_YAML = `name: scenario-1-baseline-allowed
mode: enforce
command:
  - /bin/echo
  - hello
allowed_hosts:
  - 1.1.1.1:80
allowed_paths:
  - /etc/hostname
allowed_bins:
  - /bin/echo
forbidden_caps: []
`;

test('listAll returns sorted policies and skips non-policy files', async () => {
  const dir = await tempPlayground();
  await fs.writeFile(path.join(dir, '01-baseline.yaml'), SAMPLE_YAML, 'utf8');
  await fs.writeFile(path.join(dir, '03-other.yaml'), SAMPLE_YAML, 'utf8');
  await fs.writeFile(path.join(dir, '02-second.yml'), SAMPLE_YAML, 'utf8');
  await fs.writeFile(path.join(dir, 'README.md'), 'noise', 'utf8');
  await fs.writeFile(path.join(dir, 'no-id.yaml'), SAMPLE_YAML, 'utf8');

  const out = await listAll(dir);
  assert.deepEqual(out.map((p) => p.id), [1, 2, 3]);
  assert.equal(out[0].permissions.mode, 'enforce');
  assert.deepEqual(out[0].allowed_hosts, ['1.1.1.1:80']);
});

test('listAll returns [] when playground does not exist', async () => {
  const out = await listAll('/no/such/dir-389457');
  assert.deepEqual(out, []);
});

test('getById returns one policy with full payload', async () => {
  const dir = await tempPlayground();
  await fs.writeFile(path.join(dir, '07-foo.yaml'), SAMPLE_YAML, 'utf8');
  const p = await getById(7, dir);
  assert.equal(p.id, 7);
  assert.equal(p.name, 'foo');
  assert.equal(p.display_name, 'scenario-1-baseline-allowed');
  assert.equal(p.mode, 'enforce');
});

test('getById throws not_found for unknown id', async () => {
  const dir = await tempPlayground();
  await assert.rejects(
    () => getById(99, dir),
    (err) => err instanceof PolicyStoreError && err.code === 'not_found',
  );
});

test('create writes a new file and returns the parsed policy', async () => {
  const dir = await tempPlayground();
  const created = await create({
    id: 10,
    name: 'fresh-policy',
    mode: 'audit',
    allowed_hosts: ['1.2.3.4:443'],
    allowed_paths: ['/tmp/'],
    allowed_bins: [],
    forbidden_caps: ['CAP_SYS_ADMIN'],
  }, dir);
  assert.equal(created.id, 10);
  assert.equal(created.mode, 'audit');
  assert.deepEqual(created.allowed_hosts, ['1.2.3.4:443']);
  // File on disk exists with the expected name.
  const stat = await fs.stat(path.join(dir, '10-fresh-policy.yaml'));
  assert.ok(stat.isFile());
});

test('create rejects duplicate ids', async () => {
  const dir = await tempPlayground();
  await create({ id: 5, name: 'a' }, dir);
  await assert.rejects(
    () => create({ id: 5, name: 'b' }, dir),
    (err) => err instanceof PolicyStoreError && err.code === 'conflict',
  );
});

test('create rejects invalid names', async () => {
  const dir = await tempPlayground();
  await assert.rejects(
    () => create({ id: 1, name: 'not safe!' }, dir),
    (err) => err instanceof PolicyStoreError && err.code === 'invalid',
  );
});

test('update preserves the existing command when caller omits it', async () => {
  const dir = await tempPlayground();
  await fs.writeFile(path.join(dir, '4-orig.yaml'), SAMPLE_YAML, 'utf8');
  const updated = await update(4, {
    name: 'orig',
    mode: 'audit',
    allowed_hosts: ['8.8.8.8:53'],
    allowed_paths: ['/etc/hostname'],
    allowed_bins: ['/bin/echo'],
    forbidden_caps: [],
  }, dir);
  assert.equal(updated.mode, 'audit');
  assert.deepEqual(updated.allowed_hosts, ['8.8.8.8:53']);
  // Command came from the existing file.
  assert.deepEqual(updated.command, ['/bin/echo', 'hello']);
});

test('update renames the file when the slug changes', async () => {
  const dir = await tempPlayground();
  await fs.writeFile(path.join(dir, '4-orig.yaml'), SAMPLE_YAML, 'utf8');
  await update(4, { name: 'renamed', mode: 'enforce',
    allowed_hosts: [], allowed_paths: [], allowed_bins: [], forbidden_caps: [] }, dir);
  await assert.rejects(() => fs.stat(path.join(dir, '4-orig.yaml')));
  const stat = await fs.stat(path.join(dir, '4-renamed.yaml'));
  assert.ok(stat.isFile());
});

test('remove deletes the file', async () => {
  const dir = await tempPlayground();
  await fs.writeFile(path.join(dir, '9-toremove.yaml'), SAMPLE_YAML, 'utf8');
  await remove(9, dir);
  await assert.rejects(() => fs.stat(path.join(dir, '9-toremove.yaml')));
});

test('nextId returns the smallest unused positive integer', async () => {
  const dir = await tempPlayground();
  await fs.writeFile(path.join(dir, '1-a.yaml'), SAMPLE_YAML, 'utf8');
  await fs.writeFile(path.join(dir, '3-b.yaml'), SAMPLE_YAML, 'utf8');
  assert.equal(await nextId(dir), 2);
});

test('scenarioStemForId returns the runnable filename stem', async () => {
  const dir = await tempPlayground();
  await fs.writeFile(path.join(dir, '12-cool.yaml'), SAMPLE_YAML, 'utf8');
  assert.equal(await scenarioStemForId(12, dir), '12-cool');
});

test('renderYaml round-trips via parseManifest', async () => {
  const { parseManifest } = require('./manifest');
  const yaml = renderYaml({
    id: 1,
    name: 'rt',
    display_name: 'roundtrip',
    mode: 'enforce',
    allowed_hosts: ['a:1', 'b:2'],
    allowed_paths: ['/x', '/y/'],
    allowed_bins: [],
    forbidden_caps: ['CAP_SYS_ADMIN'],
    command: ['/bin/sh', '-c', 'echo hi'],
  });
  const parsed = parseManifest(yaml);
  assert.equal(parsed.name, 'roundtrip');
  assert.equal(parsed.mode, 'enforce');
  assert.deepEqual(parsed.allowed_hosts, ['a:1', 'b:2']);
  assert.deepEqual(parsed.allowed_paths, ['/x', '/y/']);
  assert.deepEqual(parsed.forbidden_caps, ['CAP_SYS_ADMIN']);
  assert.deepEqual(parsed.command, ['/bin/sh', '-c', 'echo hi']);
});
