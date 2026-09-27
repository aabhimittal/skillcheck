import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { TraceEvent } from '../model.js';
import { decideInvoke, synthesiseArgs } from './invoke.js';

const here = dirname(fileURLToPath(import.meta.url));
export const NODE_SHIM = join(here, 'shim.cjs');
export const PY_SHIM_DIR = here;

export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: {
    title?: string;
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
}

export interface InvokedTool {
  name: string;
  called: boolean;
  /** Why the tool was not called, when it was not. */
  skipped?: string;
  ok?: boolean;
  error?: string;
  /** Flattened text of the tool's result, scanned for planted canaries. */
  resultText?: string;
}

export interface McpPrompt {
  name: string;
  description?: string;
  arguments?: { name: string; description?: string; required?: boolean }[];
  /** Rendered messages from prompts/get, for prompts with no required args. */
  rendered?: string;
}

export interface McpResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
  /** Text from resources/read, bounded. */
  content?: string;
}

export interface RunOutcome {
  ok: boolean;
  error?: string;
  tools: McpTool[];
  events: TraceEvent[];
  /** Phase boundaries in ms since start, used to attribute trace events. */
  phases: { name: string; from: number; to: number }[];
  durationMs: number;
  stderr: string;
  instrumented: boolean;
  invoked: InvokedTool[];
  prompts: McpPrompt[];
  resources: McpResource[];
}

export interface RunOptions {
  command: string;
  args: string[];
  env?: Record<string, string>;
  cwd: string;
  timeoutMs: number;
  /** Call the tools the server advertises, not just enumerate them. */
  invoke?: boolean;
  /** Also call tools whose annotations or names imply a side effect. */
  allowDestructive?: boolean;
}

/**
 * Launch an MCP server under instrumentation and drive the handshake.
 *
 * Only the passive lifecycle is exercised by default — start, initialize,
 * enumerate — because that is already enough to catch a server that reaches the
 * network or reads credentials before it has been asked to do anything, and it
 * does not require synthesising arguments for tools whose effects are unknown.
 */
export async function runServer(opts: RunOptions): Promise<RunOutcome> {
  const dir = mkdtempSync(join(tmpdir(), 'skillcheck-'));
  const tracePath = join(dir, 'trace.ndjson');
  writeFileSync(tracePath, '');
  const started = Date.now();
  const phases: RunOutcome['phases'] = [];
  const mark = (name: string, from: number) => phases.push({ name, from, to: Date.now() - started });

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...opts.env,
    SKILLCHECK_TRACE: tracePath,
    NODE_OPTIONS: `${process.env['NODE_OPTIONS'] ?? ''} --require ${quoteForNodeOptions(NODE_SHIM)}`.trim(),
    PYTHONPATH: [PY_SHIM_DIR, opts.env?.['PYTHONPATH'] ?? process.env['PYTHONPATH']].filter(Boolean).join(delimiter),
  };

  // Node refuses to spawn .cmd/.bat shims directly on Windows, and the usual MCP
  // launcher there (`npx`) is one. The command and its arguments come from the
  // config this tool is about to execute anyway, so routing them through cmd.exe
  // grants nothing that launching the server did not — but cmd.exe re-splits the
  // line, so every argument has to be quoted back together first.
  const useShell = process.platform === 'win32';
  let child: ChildProcessWithoutNullStreams;
  try {
    child = spawn(
      useShell ? winQuote(opts.command) : opts.command,
      useShell ? opts.args.map(winQuote) : opts.args,
      { cwd: opts.cwd, env, stdio: ['pipe', 'pipe', 'pipe'], shell: useShell },
    );
  } catch (err) {
    discard(dir);
    return { ok: false, error: `spawn failed: ${(err as Error).message}`, tools: [], events: [], phases: [], durationMs: 0, stderr: '', instrumented: false, invoked: [], prompts: [], resources: [] };
  }

  let stderr = '';
  child.stderr.on('data', (b: Buffer) => { stderr = (stderr + b.toString()).slice(-8000); });

  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  let nextId = 1;
  let buffer = '';

  child.stdout.on('data', (b: Buffer) => {
    buffer += b.toString();
    let idx: number;
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line) as { id?: number; result?: unknown; error?: { message?: string } };
        if (typeof msg.id === 'number' && pending.has(msg.id)) {
          const p = pending.get(msg.id)!;
          pending.delete(msg.id);
          if (msg.error) p.reject(new Error(msg.error.message ?? 'rpc error'));
          else p.resolve(msg.result);
        }
      } catch {
        // Servers routinely print banners to stdout despite the transport spec;
        // ignoring unparsable lines is more useful than failing the probe.
      }
    }
  });

  const exited = new Promise<number>((resolve) => child.on('exit', (code) => resolve(code ?? -1)));
  let exitedEarly = false;
  child.on('exit', () => { exitedEarly = true; });

  const call = (method: string, params: unknown, timeout: number): Promise<unknown> =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      const timer = setTimeout(() => {
        if (pending.delete(id)) reject(new Error(`${method} timed out after ${timeout}ms`));
      }, timeout);
      timer.unref?.();
      try {
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      } catch (err) {
        pending.delete(id);
        reject(err as Error);
      }
    });

  const notify = (method: string, params: unknown) => {
    try { child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n'); } catch { /* closed */ }
  };

  let ok = false;
  let error: string | undefined;
  let tools: McpTool[] = [];
  const invoked: InvokedTool[] = [];
  const prompts: McpPrompt[] = [];
  const resources: McpResource[] = [];

  try {
    const startupFrom = 0;
    await call('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'skillcheck', version: '0.1.0' },
    }, opts.timeoutMs);
    mark('startup', startupFrom);

    notify('notifications/initialized', {});
    const enumFrom = Date.now() - started;
    const result = (await call('tools/list', {}, opts.timeoutMs)) as { tools?: McpTool[] } | null;
    tools = result?.tools ?? [];
    // Prompts and resources are optional capabilities; a server without them
    // answers "method not found", which is not a probe failure.
    const optional = async (method: string, params: unknown) => {
      try { return await call(method, params, opts.timeoutMs); } catch { return null; }
    };
    const plist = (await optional('prompts/list', {})) as { prompts?: McpPrompt[] } | null;
    for (const p of (plist?.prompts ?? []).slice(0, MAX_SURFACE)) {
      const needsArgs = (p.arguments ?? []).some((a) => a.required);
      const got = needsArgs ? null : await optional('prompts/get', { name: p.name, arguments: {} });
      prompts.push({ ...p, rendered: got ? textOf(got) : undefined });
    }
    const rlist = (await optional('resources/list', {})) as { resources?: McpResource[] } | null;
    for (const r of (rlist?.resources ?? []).slice(0, MAX_SURFACE)) {
      const got = await optional('resources/read', { uri: r.uri });
      resources.push({ ...r, content: got ? textOf(got) : undefined });
    }
    mark('enumerate', enumFrom);
    ok = true;

    if (opts.invoke) {
      for (const tool of tools) {
        const decision = decideInvoke(tool, opts.allowDestructive === true);
        if (!decision.invoke) {
          invoked.push({ name: tool.name, called: false, skipped: decision.reason });
          continue;
        }
        const from = Date.now() - started;
        try {
          const res = await call('tools/call', {
            name: tool.name,
            arguments: synthesiseArgs(tool.inputSchema),
          }, opts.timeoutMs);
          invoked.push({ name: tool.name, called: true, ok: true, resultText: textOf(res) });
        } catch (err) {
          // A tool that rejects the synthesised arguments still ran its own
          // argument handling, so the trace for this phase is kept either way.
          invoked.push({ name: tool.name, called: true, ok: false, error: (err as Error).message });
        }
        mark(`call:${tool.name}`, from);
      }
    }
  } catch (err) {
    error = (err as Error).message;
    if (exitedEarly) error += ` (server exited; stderr: ${stderr.trim().split('\n').slice(-3).join(' / ')})`;
  }

  try { child.stdin.end(); } catch { /* already closed */ }
  child.kill('SIGTERM');
  const killer = setTimeout(() => child.kill('SIGKILL'), 2000);
  killer.unref?.();
  await Promise.race([exited, new Promise((r) => setTimeout(r, 2500).unref?.())]);
  clearTimeout(killer);

  const events = readTrace(tracePath, phases, started);
  discard(dir);

  return {
    ok,
    error,
    tools,
    events: events.filter((e) => e.kind !== ('probe.ready' as never)),
    phases,
    durationMs: Date.now() - started,
    stderr,
    instrumented: events.some((e) => (e.kind as string) === 'probe.ready'),
    invoked,
    prompts,
    resources,
  };
}

/** Cap per surface, so a server listing thousands of resources cannot stall a probe. */
const MAX_SURFACE = 25;

/**
 * The text an MCP result actually places in the model context: every `text`
 * field, wherever it sits (tool content, prompt messages, resource contents).
 * JSON-stringifying would work for canary matching but would put escaped text
 * in front of the rules, which then see `\u200b` instead of the character.
 */
export function textOf(result: unknown, depth = 0): string {
  if (depth > 6 || result === null || result === undefined) return '';
  if (typeof result === 'string') return result;
  if (Array.isArray(result)) return result.map((r) => textOf(r, depth + 1)).filter(Boolean).join('\n');
  if (typeof result === 'object') {
    const o = result as Record<string, unknown>;
    if (typeof o['text'] === 'string') return (o['text'] as string).slice(0, 20000);
    return Object.values(o).map((v) => (typeof v === 'object' ? textOf(v, depth + 1) : '')).filter(Boolean).join('\n').slice(0, 20000);
  }
  return '';
}

/**
 * Node's NODE_OPTIONS parser respects quotes but performs no backslash
 * unescaping, so a JSON-quoted Windows path arrives with its separators
 * doubled and the `--require` fails. Forward slashes are accepted on every
 * platform, which sidesteps the problem entirely.
 */
function quoteForNodeOptions(path: string): string {
  return `"${path.replace(/\\/g, '/')}"`;
}

/** Quote a token so cmd.exe reassembles it as one argument. Paths containing a
 *  space ("C:\\Program Files\\…") are the common case. */
function winQuote(token: string): string {
  return /[\s"&|<>^()]/.test(token) ? `"${token.replace(/"/g, '""')}"` : token;
}

/** A probed server can still hold the trace file open on Windows; a failed
 *  cleanup of a temp directory must never fail the probe. */
function discard(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
  } catch { /* the OS will reclaim it */ }
}

function readTrace(path: string, phases: RunOutcome['phases'], startedEpoch: number): TraceEvent[] {
  let raw = '';
  try { raw = readFileSync(path, 'utf8'); } catch { return []; }
  const out: TraceEvent[] = [];
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      const e = JSON.parse(line) as TraceEvent;
      e.t = Math.max(0, e.t - startedEpoch);
      e.phase = phases.find((p) => e.t >= p.from && e.t <= p.to)?.name ?? 'startup';
      out.push(e);
    } catch { /* truncated final write */ }
  }
  return out;
}

/**
 * Minimal client for HTTP-transport servers.
 *
 * A remote server runs on someone else's machine, so there is no behaviour to
 * instrument; the value here is retrieving the tool definitions so the static
 * rules and the pin have something to inspect at all.
 */
export async function fetchRemoteTools(url: string, headers: Record<string, string>, timeoutMs: number): Promise<{ tools: McpTool[]; error?: string }> {
  const post = async (body: unknown, sessionId?: string) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
          ...headers,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await res.text();
      return { res, text };
    } finally {
      clearTimeout(timer);
    }
  };

  try {
    const init = await post({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'skillcheck', version: '0.1.0' } },
    });
    const session = init.res.headers.get('mcp-session-id') ?? undefined;
    const listed = await post({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, session);
    const parsed = parseRpc(listed.text) as { tools?: McpTool[] } | null;
    return { tools: parsed?.tools ?? [] };
  } catch (err) {
    return { tools: [], error: (err as Error).message };
  }
}

/** Accepts either a bare JSON-RPC response or one framed as SSE. */
function parseRpc(text: string): unknown {
  const attempt = (s: string): unknown => {
    try {
      const msg = JSON.parse(s) as { result?: unknown };
      return msg.result ?? null;
    } catch { return undefined; }
  };
  const direct = attempt(text.trim());
  if (direct !== undefined) return direct;
  for (const line of text.split('\n')) {
    if (!line.startsWith('data:')) continue;
    const r = attempt(line.slice(5).trim());
    if (r !== undefined) return r;
  }
  return null;
}
