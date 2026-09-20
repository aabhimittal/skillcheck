import type { Artifact, Confidence, Finding, Segment, Severity } from '../model.js';
import { escapeEvidence } from '../util.js';

export interface MatchSpec {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  rationale: string | ((m: RegExpExecArray, s: Segment) => string);
  remediation: string;
  /** Restrict the rule to segments the model reads, or the ones a human reads. */
  only?: 'model' | 'user';
  /** Cap findings per artifact; repeated hits of the same rule add nothing. */
  max?: number;
}

export function lineOf(segment: Segment, index: number): number {
  const base = segment.startLine ?? 1;
  let extra = 0;
  for (let i = 0; i < index && i < segment.text.length; i++) if (segment.text[i] === '\n') extra++;
  return base + extra;
}

export function modelSegments(a: Artifact): Segment[] {
  return a.segments.filter((s) => s.visibility === 'model' || s.visibility === 'both');
}

export function scan(a: Artifact, pattern: RegExp, spec: MatchSpec): Finding[] {
  const findings: Finding[] = [];
  const max = spec.max ?? 3;
  const segments = a.segments.filter((s) => {
    if (spec.only === 'model') return s.visibility === 'model' || s.visibility === 'both';
    if (spec.only === 'user') return s.visibility === 'user' || s.visibility === 'both';
    return true;
  });

  for (const segment of segments) {
    const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(segment.text)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      findings.push({
        ruleId: spec.ruleId,
        title: spec.title,
        severity: spec.severity,
        confidence: spec.confidence,
        artifactId: a.id,
        artifactName: a.name,
        file: segment.file,
        line: lineOf(segment, m.index),
        evidence: escapeEvidence(context(segment.text, m.index, m[0].length)),
        rationale: typeof spec.rationale === 'function' ? spec.rationale(m, segment) : spec.rationale,
        remediation: spec.remediation,
      });
      if (findings.length >= max) return findings;
    }
  }
  return findings;
}

function context(text: string, index: number, length: number, pad = 40): string {
  const start = Math.max(0, index - pad);
  const end = Math.min(text.length, index + length + pad);
  return (start > 0 ? '…' : '') + text.slice(start, end).replace(/\n/g, ' ⏎ ') + (end < text.length ? '…' : '');
}
