/**
 * A deliberately small YAML front-matter reader.
 *
 * Skill front-matter is a flat map of scalars and short lists in practice, and
 * pulling in a full YAML parser would mean shipping a parser to a security tool
 * that must itself be trivially auditable. Anything this parser cannot model is
 * preserved as a raw string rather than silently dropped, because text that the
 * scanner fails to parse is still text the model will read.
 */
export interface FrontMatter {
  data: Record<string, unknown>;
  /** Raw front-matter text, kept for scanning. */
  raw: string;
  body: string;
  /** Byte offset of `body` inside the original file. */
  bodyOffset: number;
}

export function parseFrontMatter(source: string): FrontMatter {
  const m = /^\ufeff?---\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(source);
  if (!m) return { data: {}, raw: '', body: source, bodyOffset: 0 };
  const raw = m[1] ?? '';
  return { data: parseBlock(raw), raw, body: source.slice(m[0].length), bodyOffset: m[0].length };
}

function parseBlock(raw: string): Record<string, unknown> {
  const data: Record<string, unknown> = {};
  const lines = raw.split(/\r?\n/);
  let key: string | null = null;
  let list: string[] | null = null;
  let nested: Record<string, string> | null = null;

  const flush = () => {
    if (key === null) return;
    if (list) data[key] = list;
    else if (nested) data[key] = nested;
    key = null; list = null; nested = null;
  };

  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const item = /^\s*-\s*(.*)$/.exec(line);
    if (item && key !== null) { (list ??= []).push(unquote(item[1] ?? '')); continue; }

    const indented = /^\s+(\S[^:]*):\s*(.*)$/.exec(line);
    if (indented && key !== null && !list) {
      (nested ??= {})[indented[1]!.trim()] = unquote(indented[2] ?? '');
      continue;
    }

    const kv = /^([A-Za-z0-9_.-]+):\s*(.*)$/.exec(line);
    if (!kv) continue;
    flush();
    key = kv[1]!;
    const value = (kv[2] ?? '').trim();
    if (value === '') continue;           // block scalar or list follows
    data[key] = coerce(unquote(value));
    key = null;
  }
  flush();
  return data;
}

function unquote(s: string): string {
  const t = s.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1);
  }
  return t;
}

function coerce(v: string): unknown {
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (/^\[.*\]$/.test(v)) {
    return v.slice(1, -1).split(',').map((x) => unquote(x)).filter((x) => x !== '');
  }
  return v;
}

/** Front-matter values that may legitimately be a string or a list. */
export function asList(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === 'string') return v.split(',').map((s) => s.trim()).filter(Boolean);
  return [];
}
