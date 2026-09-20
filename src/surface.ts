import type { Artifact, Segment, Visibility } from './model.js';
import { canonicalJson, sha256 } from './util.js';

export interface Surfaces {
  user: string;
  model: string;
  userHash: string;
  modelHash: string;
  fileHashes: Record<string, string>;
}

function segmentsFor(a: Artifact, v: Exclude<Visibility, 'both'>): Segment[] {
  return a.segments
    .filter((s) => s.visibility === v || s.visibility === 'both')
    .slice()
    .sort((x, y) => (x.file + x.label).localeCompare(y.file + y.label));
}

/**
 * Normalise text before hashing.
 *
 * Only two things are neutralised: line endings, and runs of horizontal
 * whitespace. Blank lines are deliberately significant, because in Markdown they
 * decide whether a block is a code fence, a paragraph or a list, and a pin that
 * ignores them is a pin an author can slip a structural change past. Every
 * further "harmless" normalisation is another place to hide a change, so the
 * list stops here.
 */
function normalise(text: string): string {
  return text
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/ $/gm, '')
    .trim();
}

export function computeSurfaces(a: Artifact): Surfaces {
  const render = (v: Exclude<Visibility, 'both'>) =>
    segmentsFor(a, v).map((s) => ({ label: s.label, text: normalise(s.text) }));

  const user = render('user');
  const model = render('model');
  const fileHashes: Record<string, string> = {};
  for (const s of a.segments) {
    // Several segments can share a file; hash the file's contribution as a whole.
    fileHashes[s.file] = '';
  }
  for (const file of Object.keys(fileHashes)) {
    const parts = a.segments
      .filter((s) => s.file === file)
      .sort((x, y) => x.label.localeCompare(y.label))
      .map((s) => ({ label: s.label, text: normalise(s.text) }));
    fileHashes[file] = sha256(canonicalJson(parts));
  }

  return {
    user: user.map((s) => s.text).join('\n'),
    model: model.map((s) => s.text).join('\n'),
    userHash: sha256(canonicalJson(user)),
    modelHash: sha256(canonicalJson(model)),
    fileHashes,
  };
}
