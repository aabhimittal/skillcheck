import type { Artifact, Confidence, Segment } from '../model.js';

/**
 * Context helpers that separate "this artifact does something risky" from
 * "this artifact does something risky without saying so".
 *
 * The distinction is the whole point of the two-surface model, and applying it
 * consistently is what keeps the rule set usable: a deploy skill whose
 * description says it uses the operator's SSH key has a documented capability,
 * not a hidden one. Reporting both at the same confidence trains people to
 * ignore the output.
 */

/** Text a human is shown before installing: description and README. */
export function disclosure(a: Artifact): string {
  return a.segments
    .filter((s) => s.visibility === 'user' || s.visibility === 'both')
    .map((s) => s.text)
    .join('\n')
    .toLowerCase();
}

/** Whether the human-visible surface admits to the capability in question. */
export function discloses(a: Artifact, keywords: string[]): boolean {
  const text = disclosure(a);
  return keywords.some((k) => text.includes(k));
}

/**
 * Drop a finding to low confidence when the capability is disclosed. Low
 * confidence never fails a build by default, so the finding is still visible
 * to a reviewer without being an alarm.
 */
export function confidenceFor(a: Artifact, keywords: string[], undisclosed: Confidence): Confidence {
  return discloses(a, keywords) ? 'low' : undisclosed;
}

/**
 * Character ranges within a segment that are quoted rather than asserted:
 * fenced code blocks, inline code and Markdown blockquotes.
 *
 * An instruction the document is *displaying* reads identically to one it is
 * *issuing* if you only match strings. Security documentation, changelogs and
 * detection rules all quote attack text, and they are exactly the corpus a
 * naive matcher drowns in.
 */
export function quotedRanges(text: string): [number, number][] {
  const ranges: [number, number][] = [];
  const fence = /^[ \t]*(?:```|~~~)[^\n]*\n[\s\S]*?^[ \t]*(?:```|~~~)[ \t]*$/gm;
  const inline = /`[^`\n]+`/g;
  const quote = /^[ \t]*>[^\n]*(?:\n[ \t]*>[^\n]*)*/gm;
  for (const re of [fence, inline, quote]) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) ranges.push([m.index, m.index + m[0].length]);
  }
  return ranges;
}

export function isQuoted(ranges: [number, number][], index: number): boolean {
  return ranges.some(([from, to]) => index >= from && index < to);
}

/** Memoised per segment, since several rules ask the same question. */
const cache = new WeakMap<Segment, [number, number][]>();

export function quotedRangesOf(segment: Segment): [number, number][] {
  let r = cache.get(segment);
  if (!r) {
    r = quotedRanges(segment.text);
    cache.set(segment, r);
  }
  return r;
}
