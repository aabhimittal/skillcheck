import type { ScanResult, Severity } from '../model.js';
import { summariseProbe } from '../probe/differ.js';

const ICON: Record<Severity, string> = {
  critical: '🛑', high: '🔴', medium: '🟠', low: '🔵', info: '⚪',
};

/** Compact enough to paste into a PR comment without collapsing the thread. */
export function renderMarkdown(result: ScanResult): string {
  const out: string[] = [];
  const counts = (Object.keys(result.summary) as Severity[])
    .reverse()
    .filter((s) => result.summary[s] > 0)
    .map((s) => `${ICON[s]} ${result.summary[s]} ${s}`)
    .join(' · ');

  out.push('### skillcheck');
  out.push('');
  out.push(counts || '✅ No findings.');
  out.push('');

  if (result.probes.length > 0) {
    out.push('<details><summary>Behavioural probe</summary>', '');
    for (const p of result.probes) out.push(`- ${p.ok ? '✓' : '✗'} \`${p.name}\` — ${summariseProbe(p)}`);
    out.push('', '</details>', '');
  }

  const shown = result.findings.filter((f) => f.severity !== 'info');
  if (shown.length > 0) {
    out.push('| | Finding | Artifact | Location | Confidence |');
    out.push('|---|---|---|---|---|');
    for (const f of shown.slice(0, 50)) {
      const loc = f.file ? `\`${f.file}${f.line ? `:${f.line}` : ''}\`` : '—';
      out.push(`| ${ICON[f.severity]} | **${escape(f.title)}**<br><sub>${escape(f.rationale)}</sub> | \`${f.artifactName}\` | ${loc} | ${f.confidence}${f.observed ? ' · observed' : ''} |`);
    }
    if (shown.length > 50) out.push(`| | _…and ${shown.length - 50} more_ | | | |`);
    out.push('');
  }

  if (result.suppressed.length > 0) {
    out.push(`<sub>${result.suppressed.length} finding(s) suppressed via \`skillcheck.config.json\`.</sub>`);
  }
  return out.join('\n');
}

function escape(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}
