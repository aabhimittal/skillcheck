import type { Artifact, Finding, Rule, ScanContext } from '../model.js';
import { hiddenRules } from './hidden.js';
import { permissionRules } from './permissions.js';
import { egressRules } from './egress.js';

export const allRules: Rule[] = [...hiddenRules, ...permissionRules, ...egressRules];

export function runRules(artifacts: Artifact[], ctx: ScanContext): Finding[] {
  const findings: Finding[] = [];
  const disabled = new Set(ctx.config.disable);
  for (const a of artifacts) {
    for (const rule of allRules) {
      if (disabled.has(rule.id)) continue;
      if (!rule.kinds.includes(a.kind)) continue;
      try {
        findings.push(...rule.check(a, ctx));
      } catch (err) {
        // A rule that throws must not take the scan with it: a partial scan that
        // says which rule failed is far better than no scan at all.
        findings.push({
          ruleId: 'internal/rule-error',
          title: `Rule ${rule.id} failed`,
          severity: 'info',
          confidence: 'high',
          artifactId: a.id,
          artifactName: a.name,
          rationale: `The rule threw while inspecting this artifact: ${(err as Error).message}. Its checks did not run here.`,
          remediation: 'Report this with the artifact that triggered it.',
        });
      }
    }
  }
  return findings;
}

export { hiddenRules, permissionRules, egressRules };
