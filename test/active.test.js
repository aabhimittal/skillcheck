import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  probeServers, createSandbox, detectContainment, findCanaries,
  decideInvoke, synthesiseArgs, bench, defaultConfig,
} from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const servers = join(here, 'fixtures', 'servers');
const repo = join(here, '..');

/** Every signal detectContainment() honours, cleared together. Clearing a
 *  subset silently re-enables invocation on whichever CI sets the other one. */
const CONTAINMENT_ENV = ['CI', 'GITHUB_ACTIONS', 'KUBERNETES_SERVICE_HOST', 'CODESPACES', 'GITPOD_WORKSPACE_ID'];

function withoutContainmentEnv(fn) {
  const saved = Object.fromEntries(CONTAINMENT_ENV.map((k) => [k, process.env[k]]));
  for (const k of CONTAINMENT_ENV) delete process.env[k];
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

/** True when this machine is contained for reasons no env var can undo. */
function containedByFilesystem() {
  return existsSync('/.dockerenv') || existsSync('/run/.containerenv');
}

function artifactFor(name, script) {
  return {
    id: `mcp:${name}`, kind: 'mcp-server', name, root: servers, files: ['.mcp.json'], segments: [],
    meta: { command: process.execPath, args: [join(servers, script)] },
  };
}

/* ------------------------------------------------------------- sandbox --- */

test('the sandbox plants decoy credentials and removes them afterwards', () => {
  const sb = createSandbox();
  try {
    assert.ok(existsSync(join(sb.home, '.aws', 'credentials')));
    assert.ok(existsSync(join(sb.home, '.ssh', 'id_rsa')));
    assert.equal(sb.env.HOME, sb.home);
    assert.equal(sb.env.USERPROFILE, sb.home, 'Windows resolves the home directory differently');

    // Decoys must be findable in the files that carry them, and must never be
    // real secrets: every token is generated per run and self-identifying.
    const aws = readFileSync(join(sb.home, '.aws', 'credentials'), 'utf8');
    assert.equal(findCanaries(aws, sb.canaries).length, 1);
    // Decoys must not identify the probe: one substring search would let a
    // server detect it and behave for the duration.
    assert.ok(sb.canaries.every((c) => !/skillcheck|canary/i.test(c.token)), 'no self-identifying marker');
    assert.ok(sb.canaries.every((c) => c.token.length >= 36), 'long enough that an accidental match is not a concern');
    assert.match(sb.canaries.find((c) => c.where === '$GITHUB_TOKEN').token, /^ghp_[A-Za-z0-9]{36}$/, 'shaped like the real thing');
    assert.ok(sb.canaries.some((c) => c.where === '$GITHUB_TOKEN'));
    assert.equal(new Set(sb.canaries.map((c) => c.token)).size, sb.canaries.length, 'tokens are unique');
  } finally {
    sb.dispose();
  }
  assert.equal(existsSync(sb.home), false, 'the sandbox is removed');
});

test('containment detection treats an unknown environment as unsafe', () => {
  withoutContainmentEnv(() => {
    if (!containedByFilesystem()) {
      assert.equal(detectContainment().contained, false,
        'fails closed when nothing identifies a disposable environment');
    }
    process.env.CI = 'true';
    assert.equal(detectContainment().contained, true);
  });
});

/* ------------------------------------------------- invocation policy ----- */

test('only positively-safe tools are called', () => {
  assert.equal(decideInvoke({ name: 'search', annotations: { readOnlyHint: true } }, false).invoke, true);
  assert.equal(decideInvoke({ name: 'deleteRecord', annotations: { destructiveHint: true } }, false).invoke, false);

  // No annotations means the server has told us nothing, so we decline.
  const unknown = decideInvoke({ name: 'process' }, false);
  assert.equal(unknown.invoke, false);
  assert.match(unknown.reason, /readOnlyHint/);

  // A dangerous-sounding name is refused even without annotations.
  assert.equal(decideInvoke({ name: 'sendEmail' }, false).invoke, false);

  // The explicit opt-in overrides the name heuristic but not much else.
  assert.equal(decideInvoke({ name: 'sendEmail' }, true).invoke, true);
});

test('synthesised arguments are minimal and point nowhere real', () => {
  const args = synthesiseArgs({
    type: 'object',
    properties: {
      url: { type: 'string', format: 'uri' },
      count: { type: 'integer', minimum: 5 },
      mode: { type: 'string', enum: ['fast', 'slow'] },
      optional: { type: 'string' },
    },
    required: ['url', 'count', 'mode'],
  });
  assert.equal(args.count, 5);
  assert.equal(args.mode, 'fast');
  assert.ok(!('optional' in args), 'only required fields are sent');
  // RFC 2606 reserves .invalid so a probe can never reach a third party.
  assert.match(String(args.url), /\.invalid/);
});

/* ---------------------------------------------------- active probing ----- */

const probeOpts = { cwd: servers, timeoutMs: 20000, only: [] };

test('a passive probe clears a server that only steals when called', async () => {
  const out = await probeServers([artifactFor('thief', 'thief-server.mjs')], probeOpts);
  const actionable = out.findings.filter((f) => f.severity !== 'info');
  assert.deepEqual(actionable.map((f) => f.ruleId), [],
    'this is the gap active probing exists to close');
});

test('an active probe catches a decoy credential leaving the process', async () => {
  const out = await probeServers([artifactFor('thief', 'thief-server.mjs')], {
    ...probeOpts, invoke: true, allowUnsandboxed: true,
  });
  const ids = out.findings.map((f) => f.ruleId);
  assert.ok(ids.includes('probe/canary-exfiltration'), ids.join(', '));
  assert.ok(ids.includes('probe/canary-in-result'), ids.join(', '));

  const exfil = out.findings.filter((f) => f.ruleId === 'probe/canary-exfiltration');
  assert.equal(exfil.length, 1, 'one attempt to send one secret to one host is one finding');
  assert.equal(exfil[0].severity, 'critical');
  assert.match(exfil[0].evidence, /~\/\.aws\/credentials/);
  // Attribution matters: this is conditional behaviour, not a startup beacon.
  assert.match(exfil[0].evidence, /call:lookup/);
  assert.equal(out.results[0].invokedCount, 2);
});

test('a well-behaved server stays clean when its tools are actually called', async () => {
  const out = await probeServers([artifactFor('quiet', 'quiet-server.mjs')], {
    ...probeOpts, invoke: true, allowUnsandboxed: true,
  });
  const actionable = out.findings.filter((f) => f.severity !== 'info');
  assert.deepEqual(actionable.map((f) => f.ruleId), [], JSON.stringify(actionable, null, 2));
  assert.equal(out.results[0].invokedCount, 1);
});

test('active probing is refused outside a container unless overridden', async (t) => {
  if (containedByFilesystem()) {
    t.skip('this machine is genuinely contained, so there is nothing to refuse');
    return;
  }
  // probeServers resolves containment synchronously, before its first await, so
  // clearing the environment across the call alone is enough; the variables are
  // restored while the probe is still running.
  const out = await withoutContainmentEnv(() =>
    probeServers([artifactFor('thief', 'thief-server.mjs')], { ...probeOpts, invoke: true }));
  assert.ok(out.findings.some((f) => f.ruleId === 'probe/refused-unsandboxed'),
    out.findings.map((f) => f.ruleId).join(', '));
  assert.equal(out.results[0].invokedCount, 0, 'it falls back to passive rather than running the tools');
});

/* ---------------------------------------------------------- corpus ------- */

test('the benign corpus produces no build-failing findings', () => {
  const r = bench(join(repo, 'corpus', 'benign'), defaultConfig());
  assert.ok(r.skills >= 10, `corpus shrank to ${r.skills} skills`);
  assert.equal(r.falsePositives, 0,
    'false positives: ' + JSON.stringify(r.byRule.filter((s) => s.unexpected > 0), null, 2));
  assert.equal(r.dirtyRate, 0);
});

test('tuning for false positives has not blinded any rule', () => {
  const r = bench(join(repo, 'test', 'fixtures', 'workspace', '.claude', 'skills'), defaultConfig());
  assert.deepEqual(r.missed, [], 'a rule listed in expected.json stopped firing');
  assert.ok(r.truePositives >= 7);
  assert.equal(r.falsePositives, 0, 'the benign skill beside it stayed clean');
});
