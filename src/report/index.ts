import type { ScanResult } from '../model.js';
import { renderText } from './text.js';
import { renderSarif } from './sarif.js';
import { renderMarkdown } from './markdown.js';
import { renderBadge } from './badge.js';
import { renderHtml } from './html.js';

export type Format = 'text' | 'json' | 'sarif' | 'markdown' | 'badge' | 'html';

export const FORMATS: Format[] = ['text', 'json', 'sarif', 'markdown', 'badge', 'html'];

export function render(result: ScanResult, format: Format): string {
  switch (format) {
    case 'json': return JSON.stringify(serialisable(result), null, 2);
    case 'sarif': return renderSarif(result);
    case 'markdown': return renderMarkdown(result);
    case 'badge': return renderBadge(result);
    case 'html': return renderHtml(result);
    default: return renderText(result);
  }
}

/** Segment text is dropped from JSON output: it can be large and is reproducible. */
function serialisable(result: ScanResult): unknown {
  return {
    ...result,
    artifacts: result.artifacts.map((a) => ({
      id: a.id, kind: a.kind, name: a.name, version: a.version,
      origin: a.origin, files: a.files, parent: a.parent,
    })),
  };
}

export { renderText, renderSarif, renderMarkdown, renderBadge, renderHtml };
