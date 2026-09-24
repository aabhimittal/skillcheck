#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import type { Config, Severity } from './model.js';
import { loadConfig, shouldFail, defaultConfig, CONFIG_NAME } from './config.js';
import { scan, VERSION } from './scan.js';
import { render, FORMATS, type Format } from './report/index.js';
import { buildLock, diffAgainstLock, entryFor, readLock, writeLock, LOCKFILE_NAME } from './lock.js';
import { discoverServers, discoverSkills } from './discover.js';
import { allRules } from './rules/index.js';
import { compareSnapshots, discoverNpm, loadSources, readState, snapshotAll, writeState } from './registry.js';
import { renderText } from './report/text.js';
import { bench, renderBench } from './bench.js';

const HELP = `skillcheck v${VERSION} — security scanning for agent skills and MCP servers

USAGE
  npx skillcheck [command] [options]

COMMANDS
  scan            Scan installed skills and MCP servers (default)
  pin             Record current hashes to ${LOCKFILE_NAME}
  diff            Show what changed since the pin
  watch           Poll registry sources for rug pulls and publisher changes
  discover        Build a watch source list from an npm registry search
  bench           Measure false positives against a corpus of trusted skills
  rules           List the rules and what they mean
  init            Write a starter ${CONFIG_NAME}

SCAN OPTIONS
  --probe                 Launch each MCP server under instrumentation and diff
                          observed behaviour against what it declares.
                          This executes third-party code. Use a disposable container.
  --invoke                Also call each server's tools, in a sandbox home
                          seeded with decoy credentials, and report any decoy
                          that reaches a socket or a tool result.
                          Refused outside a container unless --allow-unsandboxed.
  --invoke-destructive    Also call tools whose annotations or names imply a
                          side effect. Only inside a disposable container.
  --allow-unsandboxed     Permit --invoke with no container detected.
  --probe-only <names>    Comma-separated server names to probe
  --probe-timeout <ms>    Per-server timeout (default 15000)
  --tools-from <file>     JSON map of {serverName: [toolDefinition]} to scan
                          without launching anything
  --target <path>         Scan one skill directory instead of discovering
  --format <fmt>          ${FORMATS.join(' | ')}  (default text)
  --out <file>            Write the report to a file instead of stdout
  --fail-on <sev>         critical | high | medium | low | info | never (default high)
  --fail-confidence <c>   low | medium | high (default medium)
  --config <file>         Config file (default ${CONFIG_NAME})
  --lock <file>           Lockfile path (default ${LOCKFILE_NAME})

BENCH OPTIONS
  --corpus <dir>          Directory of skill directories (default corpus/benign).
                          An optional expected.json in it maps skill name ->
                          rule ids that SHOULD fire.
  --max-fp <n>            Fail if more than n unexpected findings (default 0)
  --count-low             Also count low-confidence findings

WATCH OPTIONS
  --sources <file>        JSON list of {name, type: npm|url, spec}
  --state <file>          Snapshot history (default skillcheck-registry.json)

EXIT CODES
  0  no findings at or above the failure threshold
  1  findings at or above the threshold
  2  skillcheck itself failed
`;

interface Args {
  command: string;
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) { flags[a.slice(2, eq)] = a.slice(eq + 1); continue; }
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { flags[key] = next; i++; }
      else flags[key] = true;
    } else positional.push(a);
  }
  return { command: positional[0] ?? 'scan', flags };
}

function str(flags: Args['flags'], key: string): string | undefined {
  const v = flags[key];
  return typeof v === 'string' ? v : undefined;
}

async function main(): Promise<number> {
  const { command, flags } = parseArgs(process.argv.slice(2));
  if (flags['help'] || flags['h'] || command === 'help') { process.stdout.write(HELP); return 0; }
  if (flags['version'] || flags['v']) { process.stdout.write(VERSION + '\n'); return 0; }

  const cwd = resolve(str(flags, 'cwd') ?? process.cwd());
  const config = withOverrides(loadConfig(cwd, str(flags, 'config')), flags);
  const lockPath = resolve(cwd, str(flags, 'lock') ?? LOCKFILE_NAME);

  switch (command) {
    case 'scan': return cmdScan(cwd, config, flags, lockPath);
    case 'pin': return cmdPin(cwd, config, flags, lockPath);
    case 'diff': return cmdDiff(cwd, config, flags, lockPath);
    case 'watch': return cmdWatch(cwd, flags);
    case 'discover': return cmdDiscover(cwd, flags);
    case 'bench': return cmdBench(cwd, config, flags);
    case 'rules': return cmdRules();
    case 'init': return cmdInit(cwd);
    default:
      process.stderr.write(`Unknown command "${command}".\n\n${HELP}`);
      return 2;
  }
}

function withOverrides(config: Config, flags: Args['flags']): Config {
  const failOn = str(flags, 'fail-on');
  const failConfidence = str(flags, 'fail-confidence');
  if (failOn) config.failOn = failOn as Severity;
  if (failConfidence) config.failConfidence = failConfidence as Config['failConfidence'];
  return config;
}

async function cmdScan(cwd: string, config: Config, flags: Args['flags'], lockPath: string): Promise<number> {
  const probe = flags['probe'] === true || flags['probe'] === 'true'
    || flags['invoke'] === true || flags['invoke-destructive'] === true;
  if (probe) {
    process.stderr.write(
      'skillcheck: --probe launches each configured MCP server, which executes third-party code.\n' +
      '            Run it in a disposable, network-observed container.\n\n',
    );
  }
  const result = await scan({
    cwd,
    config,
    probe,
    probeTimeoutMs: Number(str(flags, 'probe-timeout') ?? 15000),
    probeOnly: (str(flags, 'probe-only') ?? '').split(',').map((s) => s.trim()).filter(Boolean),
    probeInvoke: flags['invoke'] === true || flags['invoke-destructive'] === true,
    probeDestructive: flags['invoke-destructive'] === true,
    probeAllowUnsandboxed: flags['allow-unsandboxed'] === true,
    lockPath,
    toolsFrom: str(flags, 'tools-from'),
    target: str(flags, 'target'),
  });

  emit(render(result, formatOf(flags)), str(flags, 'out'));
  if (str(flags, 'fail-on') === 'never' || config.failOn === ('never' as Severity)) return 0;
  return shouldFail(result.findings, config) ? 1 : 0;
}

async function cmdPin(cwd: string, config: Config, flags: Args['flags'], lockPath: string): Promise<number> {
  const probe = flags['probe'] === true;
  const result = await scan({
    cwd, config, probe,
    probeTimeoutMs: Number(str(flags, 'probe-timeout') ?? 15000),
    probeOnly: [], lockPath, target: str(flags, 'target'),
    toolsFrom: str(flags, 'tools-from'),
  });
  const previous = existsSync(lockPath) ? readLock(lockPath) : null;
  const lock = buildLock(result.artifacts, previous);
  writeLock(lockPath, lock);

  const count = Object.keys(lock.entries).length;
  process.stdout.write(`Pinned ${count} artifact(s) to ${lockPath}\n`);
  for (const e of Object.values(lock.entries)) {
    process.stdout.write(`  ${e.kind.padEnd(11)} ${e.name.padEnd(28)} model ${e.modelHash.slice(0, 12)}  user ${e.userHash.slice(0, 12)}\n`);
  }
  process.stdout.write('\nCommit this file. Every later scan compares against it.\n');
  return 0;
}

async function cmdDiff(cwd: string, config: Config, flags: Args['flags'], lockPath: string): Promise<number> {
  const lock = readLock(lockPath);
  if (!lock) {
    process.stderr.write(`No lockfile at ${lockPath}. Run \`skillcheck pin\` first.\n`);
    return 2;
  }
  const artifacts = [
    ...discoverSkills(cwd, config.skillPaths),
    ...discoverServers(cwd, config.mcpConfigs),
  ];
  const only = str(flags, 'artifact');
  const subject = only ? artifacts.filter((a) => a.id === only || a.name === only) : artifacts;
  const findings = diffAgainstLock(subject, only ? { ...lock, entries: pick(lock.entries, subject.map((a) => a.id)) } : lock);

  if (findings.length === 0) {
    process.stdout.write('No drift: every pinned artifact hashes as recorded.\n');
    return 0;
  }
  process.stdout.write(renderText({
    version: VERSION, scannedAt: new Date().toISOString(), cwd, artifacts: subject,
    findings, suppressed: [], probes: [],
    summary: countBy(findings.map((f) => f.severity)),
  }) + '\n');

  for (const a of subject) {
    const prev = lock.entries[a.id];
    if (!prev) continue;
    const cur = entryFor(a);
    if (prev.modelHash === cur.modelHash) continue;
    process.stdout.write(`\n${a.name}: files whose content changed\n`);
    for (const file of new Set([...Object.keys(prev.files ?? {}), ...Object.keys(cur.files)])) {
      if (prev.files?.[file] !== cur.files[file]) process.stdout.write(`  ${file}\n`);
    }
  }
  return shouldFail(findings, config) ? 1 : 0;
}

async function cmdWatch(cwd: string, flags: Args['flags']): Promise<number> {
  const sourcesPath = resolve(cwd, str(flags, 'sources') ?? 'skillcheck-sources.json');
  const statePath = resolve(cwd, str(flags, 'state') ?? 'skillcheck-registry.json');
  const sources = loadSources(sourcesPath);
  if (sources.length === 0) {
    process.stderr.write(`No sources in ${sourcesPath}. Expected {"sources":[{"name":"…","type":"npm","spec":"…"}]}\n`);
    return 2;
  }

  const state = readState(statePath);
  const snapshots = await snapshotAll(sources);
  const findings = snapshots.flatMap((s) => compareSnapshots(state.snapshots[s.name], s));
  for (const s of snapshots) if (!s.error) state.snapshots[s.name] = s;
  state.updatedAt = new Date().toISOString();
  writeState(statePath, state);

  const result = {
    version: VERSION, scannedAt: state.updatedAt, cwd, artifacts: [],
    findings, suppressed: [], probes: [],
    summary: countBy(findings.map((f) => f.severity)),
  };
  emit(render(result, formatOf(flags)), str(flags, 'out'));
  return findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 1 : 0;
}

function cmdBench(cwd: string, config: Config, flags: Args['flags']): number {
  const dir = resolve(cwd, str(flags, 'corpus') ?? join('corpus', 'benign'));
  if (!existsSync(dir)) {
    process.stderr.write(`No corpus at ${dir}.\n`);
    return 2;
  }
  const result = bench(dir, config, flags['count-low'] === true);
  if (formatOf(flags) === 'json') emit(JSON.stringify(result, null, 2), str(flags, 'out'));
  else emit(renderBench(result), str(flags, 'out'));

  const maxFp = Number(str(flags, 'max-fp') ?? 0);
  if (result.missed.length > 0) return 1;
  return result.falsePositives > maxFp ? 1 : 0;
}

async function cmdDiscover(cwd: string, flags: Args['flags']): Promise<number> {
  const query = str(flags, 'query') ?? 'keywords:mcp-server';
  const outPath = resolve(cwd, str(flags, 'out') ?? 'skillcheck-sources.json');
  const found = await discoverNpm(query, Number(str(flags, 'size') ?? 50));
  const existing = loadSources(outPath);
  const byName = new Map(existing.map((x) => [x.name, x]));
  let added = 0;
  for (const src of found) if (!byName.has(src.name)) { byName.set(src.name, src); added++; }
  writeFileSync(outPath, JSON.stringify({ sources: [...byName.values()] }, null, 2) + '\n', 'utf8');
  process.stdout.write(`${found.length} found for "${query}", ${added} new; ${byName.size} sources in ${outPath}\n`);
  return 0;
}

function cmdRules(): number {
  const groups = new Map<string, typeof allRules>();
  for (const r of allRules) {
    const area = r.id.split('/')[0]!;
    groups.set(area, [...(groups.get(area) ?? []), r]);
  }
  for (const [area, rules] of groups) {
    process.stdout.write(`\n${area}\n`);
    for (const r of rules) {
      process.stdout.write(`  ${r.id.padEnd(36)} ${r.severity.padEnd(9)} ${r.kinds.join(', ')}\n      ${r.title}\n`);
    }
  }
  process.stdout.write('\nprobe/* rules are produced by --probe from observed behaviour, not from text.\n');
  process.stdout.write('drift/* rules compare against skillcheck.lock.json.\n');
  process.stdout.write('registry/* rules are produced by `skillcheck watch`.\n');
  return 0;
}

function cmdInit(cwd: string): number {
  const path = join(cwd, CONFIG_NAME);
  if (existsSync(path)) {
    process.stderr.write(`${CONFIG_NAME} already exists.\n`);
    return 2;
  }
  const template = {
    ...defaultConfig(),
    ignore: [{
      rule: 'hidden/instruction-override',
      artifact: 'skill:example',
      reason: 'Documentation about prompt injection; quoted, not executed. Reviewed 2026-01-01.',
      expires: '2026-12-31',
    }],
  };
  writeFileSync(path, JSON.stringify(template, null, 2) + '\n', 'utf8');
  process.stdout.write(`Wrote ${path}\nEvery suppression needs a reason; entries without one are not applied.\n`);
  return 0;
}

function formatOf(flags: Args['flags']): Format {
  const f = str(flags, 'format') ?? (flags['json'] ? 'json' : 'text');
  return (FORMATS as string[]).includes(f) ? (f as Format) : 'text';
}

function emit(text: string, out?: string): void {
  if (!out) { process.stdout.write(text + '\n'); return; }
  const path = resolve(out);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text + '\n', 'utf8');
  process.stderr.write(`Wrote ${path}\n`);
}

function countBy(severities: Severity[]): Record<Severity, number> {
  const base = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const s of severities) base[s]++;
  return base;
}

function pick<T>(obj: Record<string, T>, keys: string[]): Record<string, T> {
  return Object.fromEntries(keys.filter((k) => k in obj).map((k) => [k, obj[k]!]));
}

main().then(
  (code) => { process.exitCode = code; },
  (err: Error) => {
    process.stderr.write(`skillcheck: ${err.stack ?? err.message}\n`);
    process.exitCode = 2;
  },
);
