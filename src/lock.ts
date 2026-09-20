import { writeFileSync } from 'node:fs';
import type { Artifact, Finding, Lockfile, LockEntry } from './model.js';
import { computeSurfaces } from './surface.js';
import { readJsonSafe } from './util.js';

export const LOCKFILE_NAME = 'skillcheck.lock.json';

export function emptyLock(): Lockfile {
  return { lockfileVersion: 1, generatedBy: 'skillcheck', entries: {} };
}

export function readLock(path: string): Lockfile | null {
  const doc = readJsonSafe<Lockfile>(path);
  if (!doc || doc.lockfileVersion !== 1 || typeof doc.entries !== 'object') return null;
  return doc;
}

export function entryFor(a: Artifact, pinnedAt = new Date().toISOString()): LockEntry {
  const s = computeSurfaces(a);
  return {
    id: a.id,
    kind: a.kind,
    name: a.name,
    version: a.version,
    origin: a.origin,
    userHash: s.userHash,
    modelHash: s.modelHash,
    files: s.fileHashes,
    pinnedAt,
  };
}

export function buildLock(artifacts: Artifact[], previous?: Lockfile | null): Lockfile {
  const lock = emptyLock();
  for (const a of artifacts) {
    const prev = previous?.entries[a.id];
    const next = entryFor(a);
    // Preserve the original pin date when nothing the model sees has changed, so
    // `pinnedAt` answers "since when has this content been trusted".
    if (prev && prev.modelHash === next.modelHash && prev.userHash === next.userHash) {
      next.pinnedAt = prev.pinnedAt;
    }
    lock.entries[a.id] = next;
  }
  return lock;
}

export function writeLock(path: string, lock: Lockfile): void {
  writeFileSync(path, JSON.stringify(lock, null, 2) + '\n', 'utf8');
}

/**
 * Compare the current state of the world against the pin.
 *
 * The rug pull signature is specific and worth naming precisely: the text the
 * model reads changed while the text a human reads did not. The package looks
 * identical on its listing page, the agent is running different instructions.
 */
export function diffAgainstLock(artifacts: Artifact[], lock: Lockfile): Finding[] {
  const findings: Finding[] = [];
  const present = new Set<string>();

  for (const a of artifacts) {
    present.add(a.id);
    const prev = lock.entries[a.id];
    const cur = entryFor(a);
    if (!prev) {
      findings.push({
        ruleId: 'drift/unpinned',
        title: 'Artifact is not present in the lockfile',
        severity: 'low',
        confidence: 'high',
        artifactId: a.id,
        artifactName: a.name,
        file: a.files[0],
        rationale:
          'This artifact was installed after the last pin, so none of its content has ever been reviewed against a known-good hash.',
        remediation: 'Review the artifact, then run `skillcheck pin` to record its hashes.',
      });
      continue;
    }

    const modelChanged = prev.modelHash !== cur.modelHash;
    const userChanged = prev.userHash !== cur.userHash;

    if (modelChanged && !userChanged) {
      findings.push({
        ruleId: 'drift/silent-model-surface-change',
        title: 'Instructions the model reads changed while the human-visible description did not',
        severity: 'critical',
        confidence: 'high',
        artifactId: a.id,
        artifactName: a.name,
        file: changedFiles(prev, cur)[0] ?? a.files[0],
        evidence: `modelHash ${short(prev.modelHash)} → ${short(cur.modelHash)}; userHash unchanged (${short(cur.userHash)})`,
        rationale:
          'This is the signature of a rug pull: the package presents the same description it was reviewed under, but the text loaded into the agent has been rewritten. Files changed: ' +
          (changedFiles(prev, cur).join(', ') || 'unknown'),
        remediation:
          'Diff the artifact against the pinned revision before running the agent again (`skillcheck diff ' + a.id + '`), and treat the new content as unreviewed.',
      });
    } else if (modelChanged) {
      findings.push({
        ruleId: 'drift/model-surface-change',
        title: 'Instructions the model reads changed since the last pin',
        severity: 'medium',
        confidence: 'high',
        artifactId: a.id,
        artifactName: a.name,
        file: changedFiles(prev, cur)[0] ?? a.files[0],
        evidence: `modelHash ${short(prev.modelHash)} → ${short(cur.modelHash)}`,
        rationale:
          'Tool definitions are executable input to the agent. A content change is a code change and deserves the same review. Files changed: ' +
          (changedFiles(prev, cur).join(', ') || 'unknown'),
        remediation: 'Review the change, then re-pin with `skillcheck pin`.',
      });
    }

    if (prev.version && cur.version && prev.version !== cur.version) {
      findings.push({
        ruleId: 'drift/version-change',
        title: `Version changed: ${prev.version} → ${cur.version}`,
        severity: 'low',
        confidence: 'high',
        artifactId: a.id,
        artifactName: a.name,
        file: a.files[0],
        rationale: 'A version bump is expected to change behaviour; it is listed so the change is acknowledged rather than assumed.',
        remediation: 'Re-pin after reviewing the upgrade.',
      });
    }
  }

  for (const id of Object.keys(lock.entries)) {
    if (present.has(id)) continue;
    const prev = lock.entries[id]!;
    findings.push({
      ruleId: 'drift/removed',
      title: 'Pinned artifact is no longer installed',
      severity: 'info',
      confidence: 'high',
      artifactId: id,
      artifactName: prev.name,
      rationale: 'The artifact was pinned previously but was not found in this scan.',
      remediation: 'Re-pin to drop the stale entry, or restore the artifact.',
    });
  }

  return findings;
}

function changedFiles(prev: LockEntry, cur: LockEntry): string[] {
  const files = new Set([...Object.keys(prev.files ?? {}), ...Object.keys(cur.files ?? {})]);
  return [...files].filter((f) => prev.files?.[f] !== cur.files?.[f]);
}

function short(h: string): string {
  return h.slice(0, 12);
}
