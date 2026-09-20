import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Config, Finding, Severity } from './model.js';
import { readJsonSafe } from './util.js';
import { severityRank } from './model.js';

export const CONFIG_NAME = 'skillcheck.config.json';

export function defaultConfig(): Config {
  return {
    ignore: [],
    disable: [],
    failOn: 'high',
    failConfidence: 'medium',
    skillPaths: [],
    mcpConfigs: [],
  };
}

export function loadConfig(cwd: string, explicit?: string): Config {
  const path = explicit ? resolve(cwd, explicit) : join(cwd, CONFIG_NAME);
  if (!existsSync(path)) return defaultConfig();
  const doc = readJsonSafe<Partial<Config>>(path);
  if (!doc) return defaultConfig();
  return { ...defaultConfig(), ...doc, ignore: doc.ignore ?? [] };
}

export interface Partitioned {
  active: Finding[];
  suppressed: Finding[];
  /** Suppressions that have expired or match nothing, reported so the file stays honest. */
  notices: Finding[];
}

/**
 * Apply suppressions.
 *
 * Every suppression must carry a reason and may carry an expiry. This is the
 * one place where the tool is opinionated about process rather than about code:
 * a scanner accumulates permanent unexplained exceptions until it reports
 * nothing, and the failure mode is invisible. An expired or unused suppression
 * is surfaced rather than silently honoured or silently dropped.
 */
export function applySuppressions(findings: Finding[], config: Config, now = new Date()): Partitioned {
  const active: Finding[] = [];
  const suppressed: Finding[] = [];
  const notices: Finding[] = [];
  const used = new Set<number>();

  for (const f of findings) {
    let matched = -1;
    for (const [i, rule] of config.ignore.entries()) {
      if (rule.rule !== f.ruleId && rule.rule !== '*') continue;
      if (rule.artifact && rule.artifact !== f.artifactId && rule.artifact !== f.artifactName) continue;
      if (!rule.reason || !rule.reason.trim()) continue;      // unexplained: not honoured
      if (rule.expires && new Date(rule.expires) < now) continue;
      matched = i;
      break;
    }
    if (matched >= 0) {
      used.add(matched);
      suppressed.push(f);
    } else {
      active.push(f);
    }
  }

  for (const [i, rule] of config.ignore.entries()) {
    if (!rule.reason || !rule.reason.trim()) {
      notices.push(meta(`Suppression for \`${rule.rule}\` has no reason and was ignored`,
        'A suppression without a stated reason cannot be reviewed later, so it is not applied.'));
      continue;
    }
    if (rule.expires && new Date(rule.expires) < now) {
      notices.push(meta(`Suppression for \`${rule.rule}\` expired on ${rule.expires}`,
        'The exception has lapsed and the underlying finding is active again.'));
      continue;
    }
    if (!used.has(i)) {
      notices.push(meta(`Suppression for \`${rule.rule}\` matched nothing`,
        'Either the issue was fixed and the entry can be removed, or the entry never matched what its author believed it did.'));
    }
  }

  return { active, suppressed, notices };
}

function meta(title: string, rationale: string): Finding {
  return {
    ruleId: 'config/suppression',
    title,
    severity: 'info',
    confidence: 'high',
    artifactId: 'skillcheck.config.json',
    artifactName: 'configuration',
    file: CONFIG_NAME,
    rationale,
    remediation: 'Update skillcheck.config.json.',
  };
}

const CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 } as const;

/** A finding fails the build only if it is both severe enough and sure enough. */
export function shouldFail(findings: Finding[], config: Config): boolean {
  const minSeverity = severityRank(config.failOn as Severity);
  const minConfidence = CONFIDENCE_RANK[config.failConfidence];
  return findings.some(
    (f) => severityRank(f.severity) >= minSeverity && CONFIDENCE_RANK[f.confidence] >= minConfidence,
  );
}
