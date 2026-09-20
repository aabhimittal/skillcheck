import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Config, Finding } from './model.js';
import { loadSkill } from './discover.js';
import { runRules } from './rules/index.js';
import { readJsonSafe } from './util.js';

/**
 * Measure the scanner against a corpus instead of asserting it is accurate.
 *
 * A rule set that has never been run over real skills has an unknown false
 * positive rate, and an unknown false positive rate is indistinguishable from a
 * bad one. This turns that into a number that can regress in CI. Point it at
 * the bundled benign corpus, or at a directory of skills you actually trust.
 */

export interface Expectation {
  /** skill name -> rule ids that SHOULD fire for it. Everything else is a miss. */
  [skill: string]: string[];
}

export interface RuleStat {
  ruleId: string;
  expected: number;
  unexpected: number;
  samples: { skill: string; evidence?: string; file?: string; line?: number }[];
}

export interface BenchResult {
  corpus: string;
  skills: number;
  /** Findings that the expectation file predicted. */
  truePositives: number;
  /** Findings on skills that should have been clean. */
  falsePositives: number;
  /** Rules the expectation file predicted that never fired. */
  missed: { skill: string; ruleId: string }[];
  /** Share of corpus skills with at least one unexpected finding. */
  dirtyRate: number;
  byRule: RuleStat[];
  /** Only findings at or above the confidence that can fail a build count. */
  countedConfidence: string[];
}

const COUNTED_CONFIDENCE = ['medium', 'high'];

export function bench(corpusDir: string, config: Config, countLowConfidence = false): BenchResult {
  const root = resolve(corpusDir);
  const expectations = readJsonSafe<Expectation>(join(root, 'expected.json')) ?? {};
  const counted = countLowConfidence ? ['low', ...COUNTED_CONFIDENCE] : COUNTED_CONFIDENCE;

  const byRule = new Map<string, RuleStat>();
  const missed: BenchResult['missed'] = [];
  let truePositives = 0;
  let falsePositives = 0;
  let skills = 0;
  const dirty = new Set<string>();

  for (const name of readdirSync(root, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name)) {
    const dir = join(root, name);
    const skillMd = join(dir, 'SKILL.md');
    if (!existsSync(skillMd)) continue;
    const artifact = loadSkill(root, dir, skillMd);
    if (!artifact) continue;
    skills++;

    const expected = new Set(expectations[artifact.name] ?? expectations[name] ?? []);
    const findings = runRules([artifact], { config, cwd: root })
      .filter((f) => counted.includes(f.confidence));

    for (const f of findings) {
      const stat = byRule.get(f.ruleId) ?? { ruleId: f.ruleId, expected: 0, unexpected: 0, samples: [] };
      if (expected.has(f.ruleId)) {
        stat.expected++;
        truePositives++;
      } else {
        stat.unexpected++;
        falsePositives++;
        dirty.add(name);
        if (stat.samples.length < 3) {
          stat.samples.push({ skill: name, evidence: f.evidence, file: f.file, line: f.line });
        }
      }
      byRule.set(f.ruleId, stat);
    }

    for (const ruleId of expected) {
      if (!findings.some((f) => f.ruleId === ruleId)) missed.push({ skill: name, ruleId });
    }
  }

  return {
    corpus: root,
    skills,
    truePositives,
    falsePositives,
    missed,
    dirtyRate: skills === 0 ? 0 : dirty.size / skills,
    byRule: [...byRule.values()].sort((a, b) => b.unexpected - a.unexpected),
    countedConfidence: counted,
  };
}

export function renderBench(r: BenchResult): string {
  const out: string[] = [];
  out.push(`corpus: ${r.corpus}`);
  out.push(`${r.skills} skill(s); counting ${r.countedConfidence.join('/')} confidence findings only`);
  out.push('');
  out.push(`  expected findings hit   ${r.truePositives}`);
  out.push(`  unexpected findings     ${r.falsePositives}`);
  out.push(`  skills with >=1 FP      ${Math.round(r.dirtyRate * 100)}%`);
  if (r.missed.length > 0) {
    out.push('');
    out.push('  MISSED (expected but did not fire):');
    for (const m of r.missed) out.push(`    ${m.skill}: ${m.ruleId}`);
  }
  if (r.byRule.some((s) => s.unexpected > 0)) {
    out.push('');
    out.push('  false positives by rule:');
    for (const s of r.byRule.filter((x) => x.unexpected > 0)) {
      out.push(`    ${s.ruleId}  x${s.unexpected}`);
      for (const sample of s.samples) {
        out.push(`      ${sample.skill}${sample.line ? `:${sample.line}` : ''}  ${(sample.evidence ?? '').slice(0, 110)}`);
      }
    }
  }
  return out.join('\n');
}
