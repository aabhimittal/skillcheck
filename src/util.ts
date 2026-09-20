import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Deterministic JSON serialisation: keys sorted at every depth.
 *
 * Hash-pinning is worthless if a hash changes when a publisher reorders keys, and
 * dangerous if it fails to change when they reorder content, so the canonical
 * form must depend on values and key names only.
 */
export function canonicalJson(value: unknown): string {
  const walk = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v as object).sort()) {
        out[k] = walk((v as Record<string, unknown>)[k]);
      }
      return out;
    }
    return v;
  };
  return JSON.stringify(walk(value));
}

export function readTextSafe(path: string): string | null {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > 4 * 1024 * 1024) return null;
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

export function readJsonSafe<T = unknown>(path: string): T | null {
  const raw = readTextSafe(path);
  if (raw === null) return null;
  try {
    return JSON.parse(stripJsonComments(raw)) as T;
  } catch {
    return null;
  }
}

/** Editor MCP configs (.vscode/mcp.json, .cursor/mcp.json) are routinely JSONC. */
export function stripJsonComments(input: string): string {
  let out = '';
  let inStr = false;
  let esc = false;
  for (let i = 0; i < input.length; i++) {
    const c = input[i]!;
    const n = input[i + 1];
    if (inStr) {
      out += c;
      if (esc) esc = false;
      else if (c === '\\') esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === '/' && n === '/') { while (i < input.length && input[i] !== '\n') i++; out += '\n'; continue; }
    if (c === '/' && n === '*') { i += 2; while (i < input.length && !(input[i] === '*' && input[i + 1] === '/')) i++; i++; continue; }
    out += c;
  }
  return out;
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'vendor', '__pycache__', 'target']);

export function walkDir(dir: string, maxDepth = 6, depth = 0): string[] {
  if (depth > maxDepth) return [];
  let entries: import('node:fs').Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const files: string[] = [];
  for (const e of entries) {
    if (e.name.startsWith('.') && e.name !== '.claude' && e.name !== '.mcp.json' && e.name !== '.vscode' && e.name !== '.cursor') continue;
    if (SKIP_DIRS.has(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) files.push(...walkDir(p, maxDepth, depth + 1));
    else if (e.isFile()) files.push(p);
  }
  return files;
}

/** 1-indexed line number of a byte offset. */
export function lineAt(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

/** Render a snippet safely: control and invisible characters become escapes. */
export function escapeEvidence(s: string, max = 160): string {
  const cut = s.length > max ? s.slice(0, max) + '…' : s;
  return cut.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g, (c) =>
    '\\u' + c.codePointAt(0)!.toString(16).padStart(4, '0'),
  ).replace(/[\u{e0000}-\u{e007f}]/gu, (c) => '\\u{' + c.codePointAt(0)!.toString(16) + '}');
}

export function rel(cwd: string, path: string): string {
  const r = relative(cwd, path);
  return r.startsWith('..') ? path : r.split(sep).join('/');
}

export function uniq<T>(xs: T[]): T[] {
  return [...new Set(xs)];
}
