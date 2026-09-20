import type { Finding, ScanResult, Severity } from '../model.js';
import { summariseProbe } from '../probe/differ.js';

const useColor = process.stdout.isTTY && !process.env['NO_COLOR'];
const c = (code: string, s: string) => (useColor ? `\u001b[${code}m${s}\u001b[0m` : s);
const dim = (s: string) => c('2', s);
const bold = (s: string) => c('1', s);

const SEVERITY_STYLE: Record<Severity, (s: string) => string> = {
  critical: (s) => c('1;31', s),
  high: (s) => c('31', s),
  medium: (s) => c('33', s),
  low: (s) => c('36', s),
  info: dim,
};

export function renderText(result: ScanResult): string {
  const out: string[] = [];
  const skills = result.artifacts.filter((a) => a.kind === 'skill').length;
  const servers = result.artifacts.filter((a) => a.kind === 'mcp-server').length;
  const tools = result.artifacts.filter((a) => a.kind === 'mcp-tool').length;

  out.push(bold('skillcheck') + dim(` v${result.version}`));
  out.push(dim(`scanned ${skills} skill(s), ${servers} MCP server(s)${tools ? `, ${tools} tool definition(s)` : ''} in ${result.cwd}`));
  out.push('');

  if (result.probes.length > 0) {
    out.push(bold('Behavioural probe'));
    for (const p of result.probes) {
      out.push(`  ${p.ok ? '✓' : '✗'} ${p.name} — ${summariseProbe(p)}`);
    }
    out.push('');
  }

  const visible = result.findings.filter((f) => f.severity !== 'info');
  const infos = result.findings.filter((f) => f.severity === 'info');

  if (visible.length === 0) {
    out.push(c('32', 'No findings above informational severity.'));
  }

  for (const f of [...visible, ...infos]) {
    out.push(renderFinding(f));
  }

  out.push('');
  out.push(bold('Summary'));
  const parts = (Object.keys(result.summary) as Severity[])
    .reverse()
    .filter((s) => result.summary[s] > 0)
    .map((s) => SEVERITY_STYLE[s](`${result.summary[s]} ${s}`));
  out.push('  ' + (parts.length ? parts.join(dim(' · ')) : 'clean'));
  if (result.suppressed.length > 0) {
    out.push(dim(`  ${result.suppressed.length} finding(s) suppressed by skillcheck.config.json`));
  }
  const lowConfidence = result.findings.filter((f) => f.confidence === 'low').length;
  if (lowConfidence > 0) {
    out.push(dim(`  ${lowConfidence} low-confidence finding(s) — review prompts, not verdicts`));
  }
  return out.join('\n');
}

function renderFinding(f: Finding): string {
  const style = SEVERITY_STYLE[f.severity];
  const head = `${style(f.severity.toUpperCase().padEnd(8))} ${bold(f.title)}`;
  const where = [f.file, f.line ? `:${f.line}` : ''].join('');
  const lines = [
    head,
    `  ${dim('artifact')}   ${f.artifactName}${where ? dim(`  (${where})`) : ''}`,
    `  ${dim('rule')}       ${f.ruleId}  ${dim(`confidence: ${f.confidence}${f.observed ? ' · observed' : ''}`)}`,
  ];
  if (f.evidence) lines.push(`  ${dim('evidence')}   ${f.evidence}`);
  lines.push(`  ${dim('why')}        ${wrap(f.rationale)}`);
  lines.push(`  ${dim('fix')}        ${wrap(f.remediation)}`);
  lines.push('');
  return lines.join('\n');
}

function wrap(text: string, width = 92, indent = ' '.repeat(15)): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = '';
  for (const w of words) {
    if (line.length + w.length + 1 > width) { lines.push(line); line = w; }
    else line = line ? `${line} ${w}` : w;
  }
  if (line) lines.push(line);
  return lines.join('\n' + indent);
}
