import type { Finding, ScanResult, Severity } from '../model.js';
import { allRules } from '../rules/index.js';

/** GitHub code scanning maps `error` to a blocking alert and `note` to a hint. */
const LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

export function renderSarif(result: ScanResult): string {
  const ruleIds = [...new Set(result.findings.map((f) => f.ruleId))];
  const knownTitle = new Map(allRules.map((r) => [r.id, r.title]));

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'skillcheck',
          version: result.version,
          informationUri: 'https://github.com/aabhimittal/skillcheck',
          rules: ruleIds.map((id) => ({
            id,
            name: id.replace(/[^A-Za-z0-9]/g, ''),
            shortDescription: { text: knownTitle.get(id) ?? id },
            defaultConfiguration: { level: LEVEL[severityOf(result.findings, id)] },
          })),
        },
      },
      results: result.findings.map((f) => ({
        ruleId: f.ruleId,
        level: LEVEL[f.severity],
        message: { text: `${f.title}. ${f.rationale} Fix: ${f.remediation}` },
        properties: {
          severity: f.severity,
          confidence: f.confidence,
          artifact: f.artifactId,
          observed: Boolean(f.observed),
        },
        locations: f.file
          ? [{
              physicalLocation: {
                artifactLocation: { uri: f.file.split('#')[0] },
                ...(f.line ? { region: { startLine: f.line } } : {}),
              },
            }]
          : [],
        partialFingerprints: { skillcheck: `${f.ruleId}:${f.artifactId}:${f.line ?? 0}` },
      })),
    }],
  };
  return JSON.stringify(sarif, null, 2);
}

function severityOf(findings: Finding[], ruleId: string): Severity {
  return findings.find((f) => f.ruleId === ruleId)?.severity ?? 'medium';
}
