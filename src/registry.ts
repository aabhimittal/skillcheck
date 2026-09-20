import { writeFileSync } from 'node:fs';
import type { Finding } from './model.js';
import { readJsonSafe, sha256 } from './util.js';

/**
 * Continuous, registry-wide monitoring.
 *
 * A one-off scan answers "is this artifact malicious today". A rug pull is the
 * case where the answer was no and later becomes yes without anything visible
 * changing, so the only defence is a record of what each artifact looked like
 * last time and an alarm when it stops matching.
 *
 * For npm-hosted servers the registry metadata is enough and no tarball needs to
 * be downloaded: `dist.integrity` already is the content hash, and a change to a
 * *published version's* integrity is unambiguous evidence of a republish.
 */

export type SourceType = 'npm' | 'url';

export interface Source {
  name: string;
  type: SourceType;
  /** npm package name, or an absolute URL for raw text. */
  spec: string;
}

export interface Snapshot {
  name: string;
  type: SourceType;
  fetchedAt: string;
  /** npm: resolved dist-tag latest. url: not set. */
  latest?: string;
  /** npm: version → integrity. url: single "content" → hash. */
  hashes: Record<string, string>;
  maintainers?: string[];
  deprecated?: string;
  error?: string;
}

export interface RegistryState {
  stateVersion: 1;
  updatedAt: string;
  snapshots: Record<string, Snapshot>;
}

export function emptyState(): RegistryState {
  return { stateVersion: 1, updatedAt: new Date().toISOString(), snapshots: {} };
}

export function readState(path: string): RegistryState {
  const doc = readJsonSafe<RegistryState>(path);
  return doc && doc.stateVersion === 1 ? doc : emptyState();
}

export function writeState(path: string, state: RegistryState): void {
  writeFileSync(path, JSON.stringify(state, null, 2) + '\n', 'utf8');
}

export async function takeSnapshot(source: Source, timeoutMs = 15000): Promise<Snapshot> {
  const base: Snapshot = { name: source.name, type: source.type, fetchedAt: new Date().toISOString(), hashes: {} };
  try {
    if (source.type === 'npm') {
      const doc = await getJson(`https://registry.npmjs.org/${encodeURIComponent(source.spec).replace('%40', '@')}`, timeoutMs);
      const versions = (doc['versions'] ?? {}) as Record<string, { dist?: { integrity?: string; shasum?: string } }>;
      for (const [v, meta] of Object.entries(versions)) {
        const integrity = meta.dist?.integrity ?? meta.dist?.shasum;
        if (integrity) base.hashes[v] = integrity;
      }
      base.latest = (doc['dist-tags'] as Record<string, string> | undefined)?.['latest'];
      base.maintainers = ((doc['maintainers'] ?? []) as { name?: string }[])
        .map((m) => m.name ?? '')
        .filter(Boolean)
        .sort();
      if (typeof doc['deprecated'] === 'string') base.deprecated = doc['deprecated'];
    } else {
      const text = await getText(source.spec, timeoutMs);
      base.hashes['content'] = sha256(text);
    }
  } catch (err) {
    base.error = (err as Error).message;
  }
  return base;
}

export async function snapshotAll(sources: Source[], concurrency = 6, timeoutMs = 15000): Promise<Snapshot[]> {
  const out: Snapshot[] = [];
  const queue = [...sources];
  const workers = Array.from({ length: Math.min(concurrency, queue.length || 1) }, async () => {
    for (;;) {
      const s = queue.shift();
      if (!s) return;
      out.push(await takeSnapshot(s, timeoutMs));
    }
  });
  await Promise.all(workers);
  return out;
}

/** Everything interesting is a difference between two snapshots. */
export function compareSnapshots(prev: Snapshot | undefined, next: Snapshot): Finding[] {
  const findings: Finding[] = [];
  const f = (extra: Partial<Finding> & { ruleId: string; title: string; rationale: string; remediation: string }): Finding => ({
    severity: 'medium', confidence: 'high', artifactId: `registry:${next.name}`, artifactName: next.name,
    ...extra,
  });

  if (next.error) {
    return [f({
      ruleId: 'registry/unreachable',
      title: 'Source could not be fetched',
      severity: 'low',
      evidence: next.error,
      rationale: 'No comparison was possible for this cycle, so a change during this window would not have been seen.',
      remediation: 'Check the source spec and network access, then re-run.',
    })];
  }
  if (!prev || prev.error) {
    return [f({
      ruleId: 'registry/baseline',
      title: 'Baseline recorded',
      severity: 'info',
      rationale: 'First successful snapshot for this source. Subsequent runs compare against it.',
      remediation: 'None.',
    })];
  }

  // The strongest signal available: a version that already existed now hashes
  // differently. Published versions are supposed to be immutable.
  for (const [version, hash] of Object.entries(next.hashes)) {
    const before = prev.hashes[version];
    if (before && before !== hash) {
      findings.push(f({
        ruleId: 'registry/republished-version',
        title: `Published version ${version} changed content`,
        severity: 'critical',
        evidence: `${before.slice(0, 24)}… → ${hash.slice(0, 24)}…`,
        rationale:
          'A released version is immutable by convention, so anyone who pinned this version reviewed different bytes than they now receive. This is the cleanest possible evidence of a supply-chain substitution.',
        remediation: 'Stop using this source, verify against your own copy, and report the republish to the registry.',
      }));
    }
  }

  for (const version of Object.keys(prev.hashes)) {
    if (!(version in next.hashes)) {
      findings.push(f({
        ruleId: 'registry/version-removed',
        title: `Version ${version} was unpublished`,
        severity: 'high',
        rationale: 'Unpublishing breaks anyone pinned to that version and is a common step after a malicious release is noticed — by the attacker or by the registry.',
        remediation: 'Find out why it was removed before installing any replacement.',
      }));
    }
  }

  if (prev.latest && next.latest && prev.latest !== next.latest) {
    findings.push(f({
      ruleId: 'registry/new-version',
      title: `New release: ${prev.latest} → ${next.latest}`,
      severity: 'low',
      rationale: 'Anything installed with a floating specifier is now running this code. It has not been reviewed.',
      remediation: 'Review the diff, then pin the new version deliberately.',
    }));
  }

  if (prev.maintainers && next.maintainers) {
    const added = next.maintainers.filter((m) => !prev.maintainers!.includes(m));
    const removed = prev.maintainers.filter((m) => !next.maintainers!.includes(m));
    if (added.length || removed.length) {
      findings.push(f({
        ruleId: 'registry/maintainer-change',
        title: 'Publisher set changed',
        severity: 'high',
        evidence: `${added.length ? `added: ${added.join(', ')}` : ''}${added.length && removed.length ? '; ' : ''}${removed.length ? `removed: ${removed.join(', ')}` : ''}`,
        rationale:
          'A new publisher on an established package is the visible half of both a legitimate handover and an account takeover, and the two look identical from outside. It is the earliest warning available before any malicious code is pushed.',
        remediation: 'Confirm the change against the project\'s own announcements before accepting further releases.',
      }));
    }
  }

  if (!prev.deprecated && next.deprecated) {
    findings.push(f({
      ruleId: 'registry/deprecated',
      title: 'Source was deprecated',
      severity: 'medium',
      evidence: next.deprecated,
      rationale: 'A deprecated package stops receiving fixes while remaining installable, and deprecation notices are a common vehicle for redirecting users to a replacement.',
      remediation: 'Verify any suggested replacement independently.',
    }));
  }

  if (next.type === 'url' && prev.hashes['content'] && prev.hashes['content'] !== next.hashes['content']) {
    findings.push(f({
      ruleId: 'registry/content-change',
      title: 'Monitored content changed',
      severity: 'high',
      evidence: `${prev.hashes['content']!.slice(0, 16)}… → ${next.hashes['content']!.slice(0, 16)}…`,
      rationale: 'The document at this URL is not what it was at the last check. For a hosted skill or tool manifest, the agent now reads different instructions.',
      remediation: 'Diff against your pinned copy before the next agent run.',
    }));
  }

  return findings;
}

async function getJson(url: string, timeoutMs: number): Promise<Record<string, unknown>> {
  return JSON.parse(await getText(url, timeoutMs, { accept: 'application/vnd.npm.install-v1+json, application/json' })) as Record<string, unknown>;
}

async function getText(url: string, timeoutMs: number, headers: Record<string, string> = {}): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'user-agent': 'skillcheck/0.1 (+https://github.com/aabhimittal/skillcheck)', ...headers },
      redirect: 'follow',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The npm "install" metadata document omits `maintainers`, so the full document
 * is requested. That is heavier per package, which is why concurrency is capped
 * and why a registry-wide sweep is meant to run on a schedule, not per commit.
 */
export function loadSources(path: string): Source[] {
  const doc = readJsonSafe<{ sources?: Source[] } | Source[]>(path);
  if (!doc) return [];
  const list = Array.isArray(doc) ? doc : doc.sources ?? [];
  return list.filter((s) => s && typeof s.name === 'string' && typeof s.spec === 'string');
}
