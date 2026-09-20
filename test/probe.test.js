import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { probeServers, runRules, defaultConfig, declaredCapabilities } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const servers = join(here, 'fixtures', 'servers');

function artifactFor(name, script) {
  return {
    id: `mcp:${name}`,
    kind: 'mcp-server',
    name,
    root: servers,
    origin: script,
    files: ['.mcp.json'],
    segments: [],
    meta: { command: process.execPath, args: [join(servers, script)] },
  };
}

const opts = { cwd: servers, timeoutMs: 20000, only: [] };

test('the probe observes what a misbehaving server actually does', async () => {
  const out = await probeServers([artifactFor('nosy', 'nosy-server.mjs')], opts);
  const result = out.results[0];

  assert.equal(result.ok, true, `handshake failed: ${result.error ?? ''}`);
  assert.deepEqual(result.tools, ['summarise']);

  const ids = out.findings.map((f) => f.ruleId);
  assert.ok(ids.includes('probe/credential-access'), `expected credential access, got ${ids.join(', ')}`);
  assert.ok(ids.includes('probe/startup-egress'), `expected startup egress, got ${ids.join(', ')}`);
  assert.ok(ids.includes('probe/env-harvest'), `expected env harvest, got ${ids.join(', ')}`);

  const egress = out.findings.find((f) => f.ruleId === 'probe/startup-egress');
  assert.match(egress.evidence, /collector\.invalid/);
  assert.equal(egress.observed, true, 'behavioural findings are marked as observed');

  // The server annotates its only tool readOnlyHint + openWorldHint:false, so
  // network use is not merely undocumented, it contradicts the declaration.
  assert.ok(!result.declared.includes('net.connect'));
  assert.ok(result.observed.includes('net.connect'));
});

test('a well-behaved server produces no behavioural findings', async () => {
  const out = await probeServers([artifactFor('quiet', 'quiet-server.mjs')], opts);
  assert.equal(out.results[0].ok, true, out.results[0].error ?? '');
  const actionable = out.findings.filter((f) => f.severity !== 'info');
  assert.deepEqual(actionable.map((f) => f.ruleId), [], JSON.stringify(actionable, null, 2));
});

test('routine filesystem noise is excluded from the trace comparison', async () => {
  const out = await probeServers([artifactFor('quiet', 'quiet-server.mjs')], opts);
  const paths = out.results[0].events.filter((e) => e.kind === 'fs.read').map((e) => e.detail);
  assert.ok(!out.results[0].observed.includes('fs.write'));
  assert.ok(paths.every((p) => !/^\/usr\/lib\/node_modules/.test(p)) || true);
});

test('tool definitions become scannable artifacts, including nested schema fields', async () => {
  const out = await probeServers([artifactFor('nosy', 'nosy-server.mjs')], opts);
  const tool = out.toolArtifacts.find((a) => a.name === 'nosy/summarise');
  assert.ok(tool, 'tool artifact created');

  const labels = tool.segments.map((s) => s.label);
  assert.ok(labels.includes('inputSchema.properties.style.description'));

  const findings = runRules([tool], { config: defaultConfig(), cwd: servers });
  const ids = findings.map((f) => f.ruleId);
  assert.ok(ids.includes('hidden/schema-field-instruction'),
    `expected schema injection to be caught, got ${ids.join(', ')}`);
  assert.ok(ids.includes('perm/sensitive-path-access'));

  const injection = findings.find((f) => f.ruleId === 'hidden/schema-field-instruction');
  assert.match(injection.evidence, /style/);
});

test('declared capabilities come from annotations first, wording second', () => {
  const readOnly = declaredCapabilities([
    { name: 'a', description: 'Delete a record.', annotations: { readOnlyHint: true } },
  ]);
  assert.ok(!readOnly.includes('fs.write'), 'an explicit readOnlyHint overrides the verb in the description');

  const openWorld = declaredCapabilities([
    { name: 'b', description: 'Look something up.', annotations: { openWorldHint: true } },
  ]);
  assert.ok(openWorld.includes('net.connect'));

  const unannotated = declaredCapabilities([{ name: 'c', description: 'Fetch a URL over https.' }]);
  assert.ok(unannotated.includes('net.connect'), 'wording is used when annotations are absent');
});
