import type { McpTool } from './runner.js';

/**
 * Deciding which tools may be called, and with what.
 *
 * Active probing is the only way to see what a tool does rather than what it
 * says, but calling arbitrary tools on someone's machine is itself the hazard
 * the tool is meant to protect against. The policy below is therefore
 * fail-closed: a tool is invoked only when it is positively marked safe, never
 * merely when it fails to look dangerous.
 */

const DESTRUCTIVE_NAME = /\b(?:delete|destroy|remove|drop|purge|truncate|wipe|reset|revoke|kill|terminate|shutdown|deploy|publish|merge|push|pay|charge|transfer|send|email|post|tweet|create|update|write|edit|move|rename|chmod|install)\b/i;

export type InvokeDecision = { invoke: true } | { invoke: false; reason: string };

export function decideInvoke(tool: McpTool, allowDestructive: boolean): InvokeDecision {
  const ann = tool.annotations ?? {};
  if (ann.destructiveHint === true && !allowDestructive) {
    return { invoke: false, reason: 'annotated destructiveHint' };
  }
  if (ann.readOnlyHint === true) return { invoke: true };
  if (allowDestructive) return { invoke: true };
  if (DESTRUCTIVE_NAME.test(tool.name)) {
    return { invoke: false, reason: `name suggests a side effect ("${tool.name}")` };
  }
  if (ann.readOnlyHint === undefined && ann.destructiveHint === undefined) {
    // No annotations at all: the server has told us nothing, so we assume the
    // worst. This gap is itself reported, since it is what makes the tool
    // unanalysable.
    return { invoke: false, reason: 'no readOnlyHint; effects unknown' };
  }
  return { invoke: true };
}

interface Schema {
  type?: string | string[];
  properties?: Record<string, Schema>;
  required?: string[];
  items?: Schema;
  enum?: unknown[];
  default?: unknown;
  format?: string;
  minimum?: number;
  minLength?: number;
}

/**
 * Build the smallest argument object the schema will accept.
 *
 * Values are inert and self-identifying so that anything a server does with
 * them is traceable back to the probe rather than mistaken for real traffic.
 */
export function synthesiseArgs(schema: unknown, depth = 0): Record<string, unknown> {
  const s = schema as Schema | undefined;
  if (!s || typeof s !== 'object' || !s.properties) return {};
  const out: Record<string, unknown> = {};
  const required = new Set(s.required ?? []);
  for (const [key, prop] of Object.entries(s.properties)) {
    if (!required.has(key)) continue;          // minimal call: required fields only
    out[key] = valueFor(prop, key, depth);
  }
  return out;
}

function valueFor(prop: Schema, key: string, depth: number): unknown {
  if (prop.default !== undefined) return prop.default;
  if (Array.isArray(prop.enum) && prop.enum.length > 0) return prop.enum[0];
  const type = Array.isArray(prop.type) ? prop.type[0] : prop.type;
  switch (type) {
    case 'number':
    case 'integer':
      return prop.minimum ?? 1;
    case 'boolean':
      return false;
    case 'array':
      return [];
    case 'object':
      return depth > 3 ? {} : synthesiseArgs(prop, depth + 1);
    default:
      return stringFor(prop, key);
  }
}

/**
 * A string that satisfies common formats without pointing anywhere real.
 * `example.invalid` and `192.0.2.0/24` are reserved by RFC 2606 and RFC 5737
 * precisely so that test traffic cannot reach a third party by accident.
 */
function stringFor(prop: Schema, key: string): string {
  const format = prop.format ?? '';
  if (format === 'uri' || format === 'url' || /\burl\b|\buri\b|endpoint/i.test(key)) {
    return 'https://probe.example.invalid/skillcheck';
  }
  if (format === 'email' || /email/i.test(key)) return 'probe@example.invalid';
  if (format === 'date-time') return '2000-01-01T00:00:00Z';
  if (format === 'date') return '2000-01-01';
  if (format === 'ipv4') return '192.0.2.1';
  if (/\bpath\b|\bfile\b|filename|directory/i.test(key)) return 'skillcheck-probe.txt';
  const base = 'skillcheck-probe';
  return prop.minLength && prop.minLength > base.length ? base.padEnd(prop.minLength, 'x') : base;
}
