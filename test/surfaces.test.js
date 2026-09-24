import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { probeServers, runRules, defaultConfig, buildLock } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const examples = join(here, '..', 'examples');
const demo = {
  id: 'mcp:demo', kind: 'mcp-server', name: 'demo', root: examples, files: ['.mcp.json'], segments: [],
  meta: { command: process.execPath, args: [join(examples, 'demo-server.mjs')] },
};
const opts = { cwd: examples, timeoutMs: 20000, only: [] };
const ctx = { config: defaultConfig(), cwd: examples };

test('prompts and resources are enumerated, not just tools', async () => {
  const out = await probeServers([demo], opts);
  const kinds = out.toolArtifacts.map((a) => a.kind);
  assert.ok(kinds.includes('mcp-prompt'), kinds.join(','));
  assert.equal(kinds.filter((k) => k === 'mcp-resource').length, 2);
  assert.equal(kinds.filter((k) => k === 'mcp-output').length, 2, 'both resource contents, read-only');
});

test('a hidden character in a prompt template is found', async () => {
  const out = await probeServers([demo], opts);
  const findings = runRules(out.toolArtifacts, ctx);
  const hit = findings.find((f) => f.ruleId === 'hidden/invisible-characters' && f.artifactName === 'demo/prompt:summarise');
  assert.ok(hit, findings.map((f) => `${f.artifactName}:${f.ruleId}`).join(', '));
  assert.match(hit.evidence, /rendered prompt/);
});

test('tool results are scanned once tools are invoked', async () => {
  const passive = runRules((await probeServers([demo], opts)).toolArtifacts, ctx);
  assert.ok(!passive.some((f) => f.artifactName === 'demo/result:lookup'), 'no result without invocation');

  const active = await probeServers([demo], { ...opts, invoke: true, allowUnsandboxed: true });
  const hit = runRules(active.toolArtifacts, ctx).find((f) => f.artifactName === 'demo/result:lookup');
  assert.ok(hit, 'the zero-width space in the tool result is reported');
  assert.equal(hit.ruleId, 'hidden/invisible-characters');
});

test('clean resource contents stay clean', async () => {
  const out = await probeServers([demo], opts);
  const resourceFindings = runRules(out.toolArtifacts.filter((a) => a.name.includes('resource:')), ctx);
  assert.deepEqual(resourceFindings.filter((f) => f.severity !== 'info'), []);
});

test('dynamic outputs are scanned but never pinned', async () => {
  const out = await probeServers([demo], { ...opts, invoke: true, allowUnsandboxed: true });
  const lock = buildLock(out.toolArtifacts);
  const kinds = Object.values(lock.entries).map((e) => e.kind);
  assert.ok(kinds.includes('mcp-prompt') && kinds.includes('mcp-resource'), 'definitions are pinned');
  assert.ok(!kinds.includes('mcp-output'), 'results and contents would drift on every call');
});
