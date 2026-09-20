import { existsSync, readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import type { Artifact, Segment } from './model.js';
import { parseFrontMatter } from './frontmatter.js';
import { lineAt, readJsonSafe, readTextSafe, rel, uniq } from './util.js';

/**
 * Where agent artifacts actually live.
 *
 * Coverage matters more than elegance here: an artifact the scanner never finds
 * is indistinguishable from one it cleared.
 */
function skillRoots(cwd: string, extra: string[]): string[] {
  const home = homedir();
  return uniq([
    join(cwd, '.claude', 'skills'),
    join(cwd, '.agent', 'skills'),
    join(cwd, 'skills'),
    join(home, '.claude', 'skills'),
    ...pluginSkillRoots(join(home, '.claude', 'plugins')),
    ...pluginSkillRoots(join(cwd, '.claude', 'plugins')),
    ...extra.map((p) => resolve(cwd, p)),
  ]).filter((p) => existsSync(p));
}

/** Plugins nest skills one level deeper: <plugins>/<plugin>/skills/<skill>/SKILL.md */
function pluginSkillRoots(pluginsDir: string): string[] {
  if (!existsSync(pluginsDir)) return [];
  const out: string[] = [];
  for (const e of safeDirs(pluginsDir)) {
    const direct = join(pluginsDir, e, 'skills');
    if (existsSync(direct)) out.push(direct);
    // marketplace layout: <plugins>/<marketplace>/<plugin>/skills
    for (const inner of safeDirs(join(pluginsDir, e))) {
      const nested = join(pluginsDir, e, inner, 'skills');
      if (existsSync(nested)) out.push(nested);
    }
  }
  return out;
}

function safeDirs(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    return [];
  }
}

export function discoverSkills(cwd: string, extraPaths: string[] = []): Artifact[] {
  const artifacts: Artifact[] = [];
  const seenDir = new Set<string>();
  const seenId = new Set<string>();
  for (const root of skillRoots(cwd, extraPaths)) {
    for (const name of safeDirs(root)) {
      const dir = resolve(root, name);
      const skillMd = join(dir, 'SKILL.md');
      if (!existsSync(skillMd)) continue;
      if (seenDir.has(dir)) continue;
      seenDir.add(dir);
      const a = loadSkill(cwd, dir, skillMd);
      if (!a) continue;
      // Roots are ordered nearest-first, so the project copy of a skill wins
      // over a same-named one in the home directory -- which is also how an
      // agent resolves it. The same root reached by two paths collapses here too.
      if (seenId.has(a.id)) continue;
      seenId.add(a.id);
      artifacts.push(a);
    }
  }
  return artifacts;
}

export function loadSkill(cwd: string, dir: string, skillMd: string): Artifact | null {
  const source = readTextSafe(skillMd);
  if (source === null) return null;
  const fm = parseFrontMatter(source);
  const name = String(fm.data['name'] ?? basename(dir));
  const relSkill = rel(cwd, skillMd);
  const segments: Segment[] = [];

  const descOffset = Math.max(0, source.indexOf(String(fm.data['description'] ?? '\u0000')));
  const description = String(fm.data['description'] ?? '');
  if (description) {
    // Shown in a marketplace listing AND injected into the agent's skill index,
    // which is precisely why it is the highest-value place to hide an instruction.
    segments.push({
      file: relSkill,
      label: 'front-matter description',
      visibility: 'both',
      text: description,
      offset: descOffset,
      startLine: lineAt(source, descOffset),
    });
  }
  segments.push({
    file: relSkill,
    label: 'front-matter',
    visibility: 'model',
    text: fm.raw,
    offset: 0,
    startLine: 2,
  });
  segments.push({
    file: relSkill,
    label: 'SKILL.md body',
    visibility: 'model',
    text: fm.body,
    offset: fm.bodyOffset,
    startLine: lineAt(source, fm.bodyOffset),
  });

  const files = [skillMd];
  // Everything the skill body can pull in is also model-visible once referenced.
  for (const extra of supportingFiles(dir)) {
    const text = readTextSafe(extra);
    if (text === null) continue;
    files.push(extra);
    const isReadme = /^readme(\.md)?$/i.test(basename(extra));
    segments.push({
      file: rel(cwd, extra),
      label: isReadme ? 'README' : 'bundled file',
      visibility: isReadme ? 'user' : 'model',
      text,
      offset: 0,
      startLine: 1,
    });
  }

  return {
    id: `skill:${name}`,
    kind: 'skill',
    name,
    version: fm.data['version'] ? String(fm.data['version']) : undefined,
    root: dir,
    origin: rel(cwd, dir),
    files: files.map((f) => rel(cwd, f)),
    segments,
    meta: fm.data,
  };
}

const SUPPORTING_EXT = /\.(md|markdown|txt|sh|bash|zsh|py|js|mjs|cjs|ts|json|ya?ml|toml)$/i;

function supportingFiles(dir: string, depth = 0): string[] {
  if (depth > 3) return [];
  let out: string[] = [];
  let entries: import('node:fs').Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  for (const e of entries) {
    if (e.name === 'SKILL.md' || e.name.startsWith('.') || e.name === 'node_modules') continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) out = out.concat(supportingFiles(p, depth + 1));
    else if (SUPPORTING_EXT.test(e.name)) {
      try {
        if (statSync(p).size <= 512 * 1024) out.push(p);
      } catch { /* unreadable file: nothing to scan */ }
    }
  }
  return out;
}

/* ------------------------------------------------------------ MCP servers -- */

export interface ServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  type?: string;
  headers?: Record<string, string>;
  [k: string]: unknown;
}

function mcpConfigPaths(cwd: string, extra: string[]): string[] {
  const home = homedir();
  const appSupport = process.platform === 'darwin'
    ? join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
    : process.platform === 'win32'
      ? join(process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json')
      : join(home, '.config', 'Claude', 'claude_desktop_config.json');
  return uniq([
    join(cwd, '.mcp.json'),
    join(cwd, '.vscode', 'mcp.json'),
    join(cwd, '.cursor', 'mcp.json'),
    join(cwd, 'mcp.json'),
    join(home, '.claude.json'),
    join(home, '.cursor', 'mcp.json'),
    appSupport,
    ...extra.map((p) => resolve(cwd, p)),
  ]).filter((p) => existsSync(p));
}

export function discoverServers(cwd: string, extraConfigs: string[] = []): Artifact[] {
  const artifacts: Artifact[] = [];
  const seen = new Set<string>();
  for (const path of mcpConfigPaths(cwd, extraConfigs)) {
    const doc = readJsonSafe<Record<string, unknown>>(path);
    if (!doc) continue;
    for (const [name, cfg] of collectServers(doc)) {
      const id = `mcp:${name}`;
      if (seen.has(id)) continue;   // nearest config wins; project before home
      seen.add(id);
      artifacts.push(serverArtifact(cwd, path, name, cfg));
    }
  }
  return artifacts;
}

/** Pull server maps out of every config shape we know about. */
function collectServers(doc: Record<string, unknown>): [string, ServerConfig][] {
  const out: [string, ServerConfig][] = [];
  const take = (v: unknown) => {
    if (!v || typeof v !== 'object') return;
    for (const [name, cfg] of Object.entries(v as Record<string, unknown>)) {
      if (cfg && typeof cfg === 'object') out.push([name, cfg as ServerConfig]);
    }
  };
  take(doc['mcpServers']);
  take(doc['servers']);            // .vscode/mcp.json
  const projects = doc['projects'];
  if (projects && typeof projects === 'object') {
    for (const p of Object.values(projects as Record<string, unknown>)) {
      if (p && typeof p === 'object') take((p as Record<string, unknown>)['mcpServers']);
    }
  }
  return out;
}

export function serverArtifact(cwd: string, configPath: string, name: string, cfg: ServerConfig): Artifact {
  const relConfig = rel(cwd, configPath);
  const origin = cfg.url
    ? cfg.url
    : [cfg.command, ...(cfg.args ?? [])].filter(Boolean).join(' ');
  return {
    id: `mcp:${name}`,
    kind: 'mcp-server',
    name,
    version: packageVersionFromSpec(origin),
    root: dirname(configPath),
    origin,
    files: [relConfig],
    segments: [{
      file: relConfig,
      label: `mcpServers.${name}`,
      visibility: 'user',
      text: JSON.stringify(cfg, null, 2),
      offset: 0,
      startLine: 1,
    }],
    meta: cfg as Record<string, unknown>,
  };
}

/**
 * Extract a pinned version from an invocation like `npx -y some-server@1.2.3`.
 * Returns undefined for floating specs, which is itself a finding.
 */
export function packageVersionFromSpec(spec: string): string | undefined {
  const m = /(?:^|\s)(@?[\w./-]+)@(\d[\w.\-+]*)(?=\s|$)/.exec(spec);
  return m?.[2];
}
