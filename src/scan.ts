import { existsSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Artifact, Config, Finding, ProbeResult, ScanResult, Severity } from './model.js';
import { SEVERITY_ORDER, severityRank } from './model.js';
import { discoverServers, discoverSkills, loadSkill } from './discover.js';
import { runRules } from './rules/index.js';
import { probeServers } from './probe/index.js';
import { applySuppressions } from './config.js';
import { diffAgainstLock, readLock, LOCKFILE_NAME } from './lock.js';
import { toolsToArtifacts } from './probe/index.js';
import { readJsonSafe } from './util.js';
import type { McpTool } from './probe/runner.js';

export const VERSION = '0.1.0';

export interface ScanOptions {
  cwd: string;
  config: Config;
  probe: boolean;
  probeTimeoutMs: number;
  probeOnly: string[];
  lockPath?: string;
  /** Path to a JSON file of tool definitions, for CI without a live server. */
  toolsFrom?: string;
  /** Scan a single artifact path instead of discovering. */
  target?: string;
}

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  const artifacts = opts.target ? loadTarget(opts.cwd, opts.target) : discover(opts);
  const probes: ProbeResult[] = [];
  let findings: Finding[] = [];

  const servers = artifacts.filter((a) => a.kind === 'mcp-server');

  if (opts.toolsFrom) {
    // A definitions dump lets CI scan tool descriptions without executing anything.
    const doc = readJsonSafe<Record<string, McpTool[]>>(resolve(opts.cwd, opts.toolsFrom));
    for (const [serverName, tools] of Object.entries(doc ?? {})) {
      const server = servers.find((s) => s.name === serverName)
        ?? { id: `mcp:${serverName}`, kind: 'mcp-server' as const, name: serverName, root: opts.cwd, files: [opts.toolsFrom], segments: [], meta: {} };
      artifacts.push(...toolsToArtifacts(server, tools ?? [], opts.cwd));
    }
  }

  if (opts.probe && servers.length > 0) {
    const out = await probeServers(servers, {
      cwd: opts.cwd,
      timeoutMs: opts.probeTimeoutMs,
      only: opts.probeOnly,
    });
    probes.push(...out.results);
    findings.push(...out.findings);
    artifacts.push(...out.toolArtifacts);
  }

  findings.push(...runRules(artifacts, { config: opts.config, cwd: opts.cwd }));

  const lockPath = opts.lockPath ?? join(opts.cwd, LOCKFILE_NAME);
  const lock = existsSync(lockPath) ? readLock(lockPath) : null;
  if (lock) {
    // Tool artifacts only exist when a probe ran; diffing them against a lock
    // built with a probe would otherwise report every tool as removed.
    const comparable = lock.entries && Object.values(lock.entries).some((e) => e.kind === 'mcp-tool')
      ? artifacts
      : artifacts.filter((a) => a.kind !== 'mcp-tool');
    findings.push(...diffAgainstLock(comparable, lock));
  }

  const { active, suppressed, notices } = applySuppressions(findings, opts.config);
  findings = [...active, ...notices];
  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.ruleId.localeCompare(b.ruleId));

  const summary = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) summary[f.severity]++;

  return {
    version: VERSION,
    scannedAt: new Date().toISOString(),
    cwd: opts.cwd,
    artifacts,
    findings,
    suppressed,
    probes,
    summary,
  };
}

function discover(opts: ScanOptions): Artifact[] {
  return [
    ...discoverSkills(opts.cwd, opts.config.skillPaths),
    ...discoverServers(opts.cwd, opts.config.mcpConfigs),
  ];
}

function loadTarget(cwd: string, target: string): Artifact[] {
  const path = resolve(cwd, target);
  if (!existsSync(path)) return [];
  const dir = statSync(path).isDirectory() ? path : join(path, '..');
  const skillMd = statSync(path).isDirectory() ? join(path, 'SKILL.md') : path;
  if (!existsSync(skillMd)) return [];
  const a = loadSkill(cwd, dir, skillMd);
  return a ? [a] : [];
}
