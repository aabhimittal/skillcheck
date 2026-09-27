import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareSnapshots } from '../dist/index.js';

const base = {
  name: 'example-mcp',
  type: 'npm',
  fetchedAt: '2026-01-01T00:00:00Z',
  latest: '1.2.0',
  hashes: { '1.1.0': 'sha512-aaa', '1.2.0': 'sha512-bbb' },
  maintainers: ['alice'],
};

function ids(findings) {
  return findings.map((f) => f.ruleId);
}

test('a republished version is the strongest available signal', () => {
  const next = { ...base, hashes: { ...base.hashes, '1.1.0': 'sha512-zzz' } };
  const findings = compareSnapshots(base, next);
  const f = findings.find((x) => x.ruleId === 'registry/republished-version');
  assert.ok(f);
  assert.equal(f.severity, 'critical');
  assert.match(f.evidence, /sha512-aaa/);
});

test('publisher changes are surfaced before any code changes', () => {
  const findings = compareSnapshots(base, { ...base, maintainers: ['alice', 'mallory'] });
  const f = findings.find((x) => x.ruleId === 'registry/maintainer-change');
  assert.ok(f);
  assert.equal(f.severity, 'high');
  assert.match(f.evidence, /mallory/);
});

test('unpublished versions and new releases are distinguished', () => {
  const removed = compareSnapshots(base, { ...base, hashes: { '1.2.0': 'sha512-bbb' } });
  assert.ok(ids(removed).includes('registry/version-removed'));

  const released = compareSnapshots(base, {
    ...base, latest: '1.3.0', hashes: { ...base.hashes, '1.3.0': 'sha512-ccc' },
  });
  assert.ok(ids(released).includes('registry/new-version'));
  assert.ok(!ids(released).includes('registry/republished-version'));
});

test('a steady state produces nothing', () => {
  assert.deepEqual(compareSnapshots(base, { ...base }), []);
});

test('the first observation is a baseline, and a fetch failure says so', () => {
  assert.deepEqual(ids(compareSnapshots(undefined, base)), ['registry/baseline']);
  assert.deepEqual(ids(compareSnapshots(base, { ...base, error: 'HTTP 503' })), ['registry/unreachable']);
});

test('monitored URL content changes are reported', () => {
  const prev = { name: 'hosted-skill', type: 'url', fetchedAt: '', hashes: { content: 'abc123' } };
  const next = { ...prev, hashes: { content: 'def456' } };
  const f = compareSnapshots(prev, next).find((x) => x.ruleId === 'registry/content-change');
  assert.ok(f);
  assert.equal(f.severity, 'high');
});

const withSupplyChain = {
  ...base,
  latestDeps: { zod: '^3.0.0' },
  latestInstallScripts: [],
  latestProvenance: true,
};

test('losing provenance on a new release is flagged; never having it is not', () => {
  const next = { ...withSupplyChain, latest: '1.3.0', latestProvenance: false };
  const f = compareSnapshots(withSupplyChain, next).find((x) => x.ruleId === 'registry/provenance-dropped');
  assert.ok(f);
  assert.equal(f.severity, 'high');

  const neverHad = { ...withSupplyChain, latestProvenance: false };
  assert.ok(!ids(compareSnapshots(neverHad, { ...neverHad, latest: '1.3.0' })).includes('registry/provenance-dropped'),
    'most packages predate provenance; its absence alone is not a signal');
});

test('a new install-time script is flagged', () => {
  const next = { ...withSupplyChain, latest: '1.3.0', latestInstallScripts: ['postinstall'] };
  const f = compareSnapshots(withSupplyChain, next).find((x) => x.ruleId === 'registry/install-script-added');
  assert.ok(f);
  assert.match(f.title, /postinstall/);
});

test('a new dependency is surfaced as supply chain one level down', () => {
  const next = { ...withSupplyChain, latest: '1.3.0', latestDeps: { zod: '^3.0.0', 'left-pad': '1.0.0' } };
  const f = compareSnapshots(withSupplyChain, next).find((x) => x.ruleId === 'registry/dependency-added');
  assert.ok(f);
  assert.match(f.title, /left-pad/);
});
