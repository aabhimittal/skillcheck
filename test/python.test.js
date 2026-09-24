import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { probeServers } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const shimDir = join(here, '..', 'dist', 'probe');
const python = process.platform === 'win32' ? 'python' : 'python3';

function hasPython() {
  try { execFileSync(python, ['--version'], { stdio: 'ignore' }); return true; } catch { return false; }
}

test('the Python shim loads and records what a Python server does', { skip: !hasPython() && 'no python' }, async () => {
  const script = join(here, 'fixtures', 'servers', 'py_server.py');
  const server = {
    id: 'mcp:py', kind: 'mcp-server', name: 'py', root: here, files: ['.mcp.json'], segments: [],
    meta: { command: python, args: [script] },
  };
  const out = await probeServers([server], { cwd: here, timeoutMs: 20000, only: [] });
  const r = out.results[0];
  assert.equal(r.ok, true, r.error ?? '');
  assert.deepEqual(r.tools, ['add']);
  assert.ok(!out.findings.some((f) => f.ruleId === 'probe/not-instrumented'),
    'sitecustomize.py must load; before this test it had never been executed');
  assert.ok(r.events.some((e) => e.kind === 'fs.read' && e.detail.endsWith('py_server.py')), 'file read observed');
  assert.ok(r.events.some((e) => e.kind === 'env.read' && e.detail === 'PROBE_TEST_TOKEN'), 'env read observed');
});

test('the Python taint hook sees a canary written to a socket, and hides the list', { skip: !hasPython() && 'no python' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'skillcheck-py-'));
  const trace = join(dir, 'trace.ndjson');
  writeFileSync(trace, '');
  const token = 'Zq7' + 'x'.repeat(40);
  // A local socketpair: the bytes never leave the process.
  const code = [
    'import os, socket',
    'print("LIST_VISIBLE" if "SKILLCHECK_CANARIES" in os.environ else "LIST_HIDDEN")',
    'a, b = socket.socketpair()',
    `a.sendall(b"payload ${token} end")`,
    'b.recv(100)',
  ].join('\n');
  const stdout = execFileSync(python, ['-c', code], {
    encoding: 'utf8',
    env: { ...process.env, PYTHONPATH: shimDir, SKILLCHECK_TRACE: trace, SKILLCHECK_CANARIES: token },
  });
  assert.match(stdout, /LIST_HIDDEN/, 'the canary list is removed before user code runs');
  const events = readFileSync(trace, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  assert.ok(events.some((e) => e.kind === 'exfil.canary' && e.detail.startsWith(token)), JSON.stringify(events));
});
