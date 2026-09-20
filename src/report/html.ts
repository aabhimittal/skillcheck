import type { ScanResult, Severity } from '../model.js';
import { summariseProbe } from '../probe/differ.js';

const COLORS: Record<Severity, string> = {
  critical: '#b3261e', high: '#c2410c', medium: '#a16207', low: '#0369a1', info: '#64748b',
};

/**
 * A single self-contained page, suitable for publishing scan results.
 *
 * No external assets: a security report that fetches a stylesheet from a CDN is
 * a poor advertisement for the thing it is reporting on.
 */
export function renderHtml(result: ScanResult): string {
  const shown = result.findings.filter((f) => f.severity !== 'info');
  const rows = shown.map((f) => `
      <tr>
        <td><span class="sev" style="--c:${COLORS[f.severity]}">${f.severity}</span></td>
        <td>
          <div class="t">${esc(f.title)}</div>
          <div class="r">${esc(f.rationale)}</div>
          ${f.evidence ? `<pre>${esc(f.evidence)}</pre>` : ''}
          <div class="fix"><strong>Fix:</strong> ${esc(f.remediation)}</div>
        </td>
        <td><code>${esc(f.artifactName)}</code>${f.file ? `<div class="loc">${esc(f.file)}${f.line ? ':' + f.line : ''}</div>` : ''}</td>
        <td><span class="conf ${f.confidence}">${f.confidence}</span>${f.observed ? '<span class="obs">observed</span>' : ''}<div class="loc">${esc(f.ruleId)}</div></td>
      </tr>`).join('');

  const counts = (Object.keys(result.summary) as Severity[]).reverse()
    .filter((s) => result.summary[s] > 0)
    .map((s) => `<span class="pill" style="--c:${COLORS[s]}">${result.summary[s]} ${s}</span>`)
    .join('');

  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>skillcheck results</title>
<style>
:root{--bg:#fff;--fg:#111827;--muted:#6b7280;--line:#e5e7eb;--card:#f9fafb}
@media (prefers-color-scheme:dark){:root{--bg:#0b0f14;--fg:#e5e7eb;--muted:#9ca3af;--line:#1f2937;--card:#111827}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--muted);font-size:13px;margin-bottom:20px}
.pill{display:inline-block;margin:0 8px 8px 0;padding:3px 10px;border-radius:999px;background:color-mix(in srgb,var(--c) 14%,transparent);color:var(--c);font-size:13px;font-weight:600;border:1px solid color-mix(in srgb,var(--c) 35%,transparent)}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{text-align:left;vertical-align:top;padding:12px 10px;border-top:1px solid var(--line);font-size:14px}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);border-top:0}
.sev{font-size:11px;font-weight:700;text-transform:uppercase;color:var(--c);white-space:nowrap}
.t{font-weight:600;margin-bottom:3px}
.r{color:var(--muted);font-size:13px}
.fix{margin-top:6px;font-size:13px}
.loc,.obs{color:var(--muted);font-size:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.obs{margin-left:6px;color:#0f766e}
.conf{font-size:12px;font-weight:600}
.conf.low{color:var(--muted)}.conf.medium{color:#a16207}.conf.high{color:#15803d}
pre{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px;margin:6px 0;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
.probe{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:18px 0;font-size:13px}
.probe div{margin:3px 0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.note{color:var(--muted);font-size:12px;margin-top:28px;border-top:1px solid var(--line);padding-top:14px}
@media(max-width:640px){td:nth-child(3),th:nth-child(3){display:none}}
</style></head><body><div class="wrap">
<h1>skillcheck results</h1>
<div class="sub">${esc(result.cwd)} · ${new Date(result.scannedAt).toUTCString()} · v${esc(result.version)}</div>
<div>${counts || '<span class="pill" style="--c:#15803d">clean</span>'}</div>
${result.probes.length ? `<div class="probe"><strong>Behavioural probe</strong>${result.probes.map((p) => `<div>${p.ok ? '✓' : '✗'} ${esc(p.name)} — ${esc(summariseProbe(p))}</div>`).join('')}</div>` : ''}
${shown.length ? `<table><thead><tr><th>Severity</th><th>Finding</th><th>Artifact</th><th>Rule</th></tr></thead><tbody>${rows}</tbody></table>` : '<p>No findings above informational severity.</p>'}
<div class="note">
Scanned ${result.artifacts.filter((a) => a.kind === 'skill').length} skill(s) and
${result.artifacts.filter((a) => a.kind === 'mcp-server').length} MCP server(s).
${result.probes.length === 0 ? 'Static checks only — no server behaviour was observed. ' : ''}
Static text analysis cannot determine intent: low-confidence findings are review prompts, not verdicts,
and an empty report means nothing was detected, not that the artifacts are safe.
</div>
</div></body></html>`;
}

function esc(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}
