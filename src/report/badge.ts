import type { ScanResult } from '../model.js';

/**
 * Shields.io endpoint payload.
 *
 * The badge states what was checked as well as the result, because a green
 * badge that silently means "static checks only" is worse than no badge.
 */
export function renderBadge(result: ScanResult): string {
  const crit = result.summary.critical + result.summary.high;
  const probed = result.probes.filter((p) => p.ok).length;
  const label = probed > 0 ? 'skillcheck (probed)' : 'skillcheck (static)';
  const message = crit > 0
    ? `${crit} issue${crit === 1 ? '' : 's'}`
    : result.summary.medium > 0
      ? `${result.summary.medium} medium`
      : 'clean';
  const color = crit > 0 ? 'critical' : result.summary.medium > 0 ? 'orange' : 'brightgreen';
  return JSON.stringify({ schemaVersion: 1, label, message, color }, null, 2);
}
