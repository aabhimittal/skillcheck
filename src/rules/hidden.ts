import type { Artifact, Finding, Rule } from '../model.js';
import { escapeEvidence } from '../util.js';
import { lineOf, modelSegments, scan } from './util.js';

/**
 * Text the model reads but the user does not.
 *
 * These rules are the cheap half of the product and they are honest about it:
 * they catch text that is *mechanically* hidden or *lexically* imperative. They
 * cannot decide whether an instruction is malicious, and the confidence field
 * on every finding says so. Semantic injection written in ordinary prose is out
 * of reach of any matcher, which is why the probe exists.
 */

const INVISIBLE = /[\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff]|[\u{e0000}-\u{e007f}]/gu;

const invisibleCharacters: Rule = {
  id: 'hidden/invisible-characters',
  title: 'Invisible or bidirectional control characters in model-visible text',
  severity: 'critical',
  kinds: ['skill', 'mcp-server', 'mcp-tool'],
  check(a: Artifact): Finding[] {
    const findings: Finding[] = [];
    for (const segment of modelSegments(a)) {
      const re = new RegExp(INVISIBLE.source, 'gu');
      let m: RegExpExecArray | null;
      const hits: { index: number; char: string }[] = [];
      while ((m = re.exec(segment.text)) !== null) hits.push({ index: m.index, char: m[0] });
      if (hits.length === 0) continue;
      const first = hits[0]!;
      findings.push({
        ruleId: 'hidden/invisible-characters',
        title: 'Invisible or bidirectional control characters in model-visible text',
        severity: 'critical',
        // Zero-width and tag characters have no legitimate use in a tool
        // description. There is no benign reading of this one.
        confidence: 'high',
        artifactId: a.id,
        artifactName: a.name,
        file: segment.file,
        line: lineOf(segment, first.index),
        evidence: `${hits.length} hidden code point(s) in "${segment.label}", first at offset ${first.index}: ${escapeEvidence(hits.slice(0, 8).map((h) => h.char).join(''))}`,
        rationale:
          'These code points render as nothing in a terminal, a diff and a marketplace listing, but they are tokenised and read by the model. They are the standard carrier for instructions meant to reach the agent without reaching the reviewer.',
        remediation: 'Strip the code points and confirm with the maintainer that the visible text is the whole text.',
      });
    }
    return findings;
  },
};

const OVERRIDE = new RegExp(
  [
    'ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|prompts|rules|messages)',
    'disregard (?:all |any )?(?:previous|prior|the above|earlier)',
    'do not (?:tell|inform|mention (?:this )?to|show|reveal (?:this )?to) the (?:user|human|operator)',
    'without (?:telling|informing|notifying|asking) the (?:user|human)',
    "(?:don't|do not) (?:ask|request|seek) (?:for )?(?:permission|confirmation|approval)",
    'you (?:are|must)(?: now)? (?:act as|operate as|behave as) (?:a |an )?(?:different|new|unrestricted)',
    '(?:reveal|print|output|repeat|disclose) (?:your |the )?(?:system prompt|initial instructions|developer message)',
    'this (?:instruction|message|note) (?:is|are) (?:hidden|invisible|only) for (?:the )?(?:ai|assistant|model|agent)',
    '(?:bypass|skip|disable|suppress) (?:the )?(?:safety|security|permission|approval|sandbox)',
  ].join('|'),
  'i',
);

const instructionOverride: Rule = {
  id: 'hidden/instruction-override',
  title: 'Text that instructs the agent to override its instructions or conceal activity',
  severity: 'critical',
  kinds: ['skill', 'mcp-server', 'mcp-tool'],
  check: (a) =>
    scan(a, OVERRIDE, {
      ruleId: 'hidden/instruction-override',
      title: 'Text that instructs the agent to override its instructions or conceal activity',
      severity: 'critical',
      confidence: 'medium',
      only: 'model',
      rationale:
        'A skill or tool definition asking the agent to ignore prior instructions, to act without confirmation, or to keep an action from the user is an instruction aimed past the user. Confidence is medium because documentation about prompt injection contains these phrases too; read the surrounding context before acting.',
      remediation: 'Confirm the phrasing is quoted documentation rather than a live instruction. If it is live, do not install.',
    }),
};

const hiddenComment: Rule = {
  id: 'hidden/comment-instruction',
  title: 'Imperative text inside an HTML comment',
  severity: 'high',
  kinds: ['skill'],
  check: (a) =>
    scan(a, /<!--[\s\S]{0,600}?(?:you (?:must|should|will)|always |never |instruction|assistant|agent|ignore )[\s\S]{0,600}?-->/i, {
      ruleId: 'hidden/comment-instruction',
      title: 'Imperative text inside an HTML comment',
      severity: 'high',
      confidence: 'medium',
      only: 'model',
      rationale:
        'HTML comments disappear from every rendered view of a Markdown file — the marketplace page, the GitHub preview, the docs site — while remaining in the raw text the agent loads.',
      remediation: 'Move genuine notes into visible prose, or delete them.',
    }),
};

const encodedPayload: Rule = {
  id: 'hidden/encoded-payload',
  title: 'Long encoded blob in model-visible text',
  severity: 'medium',
  kinds: ['skill', 'mcp-server', 'mcp-tool'],
  check: (a) => [
    ...scan(a, /(?:base64|atob|b64decode|from_?base64)[^\n]{0,40}[A-Za-z0-9+/]{60,}={0,2}/i, {
      ruleId: 'hidden/encoded-payload',
      title: 'Long encoded blob in model-visible text',
      severity: 'medium',
      confidence: 'medium',
      only: 'model',
      max: 2,
      rationale:
        'Encoded content defeats review by anyone reading the source, and both the model and a shell can decode it. Legitimate uses exist (embedded images, fixtures), so this is a prompt to look, not a verdict.',
      remediation: 'Decode the blob and confirm what it contains.',
    }),
    ...scan(a, /(?:\\x[0-9a-f]{2}){12,}|(?:%[0-9a-f]{2}){20,}/i, {
      ruleId: 'hidden/encoded-payload',
      title: 'Long escaped-byte sequence in model-visible text',
      severity: 'medium',
      confidence: 'medium',
      only: 'model',
      max: 2,
      rationale: 'Hex or percent escaping of a long run of bytes hides the content from a reader while remaining executable.',
      remediation: 'Decode the sequence and confirm what it contains.',
    }),
  ],
};

/**
 * The parameter-description attack, specific to MCP.
 *
 * A JSON Schema `description` is documentation to a developer and context to the
 * model. Putting an instruction in one reaches the agent every time the tool is
 * offered, and appears nowhere in the tool's own description.
 */
const schemaInjection: Rule = {
  id: 'hidden/schema-field-instruction',
  title: 'Instruction-shaped text inside a JSON Schema field',
  severity: 'high',
  kinds: ['mcp-tool'],
  check(a: Artifact): Finding[] {
    const findings: Finding[] = [];
    const imperative =
      /\b(?:you (?:must|should|have to|need to)|always (?:include|send|pass|read|call)|before (?:using|calling) this tool,? (?:you|read|first)|first,? read|also (?:read|send|include)|do not (?:tell|mention|show)|ignore )\b/i;
    for (const segment of a.segments) {
      if (!segment.label.includes('inputSchema') && !segment.label.includes('outputSchema')) continue;
      const m = imperative.exec(segment.text);
      if (!m) continue;
      findings.push({
        ruleId: 'hidden/schema-field-instruction',
        title: 'Instruction-shaped text inside a JSON Schema field',
        severity: 'high',
        confidence: 'medium',
        artifactId: a.id,
        artifactName: a.name,
        file: segment.file,
        line: lineOf(segment, m.index),
        evidence: `${segment.label}: ${escapeEvidence(segment.text, 200)}`,
        rationale:
          'A parameter description is loaded into the model context alongside the tool, but is not shown in any tool listing and is rarely read during review. Imperative text here directs the agent rather than documenting the field.',
        remediation: 'Rewrite the field description to describe the parameter only. Treat directives here as hostile until the maintainer explains them.',
      });
    }
    return findings;
  },
};

const conflictingSurface: Rule = {
  id: 'hidden/surface-mismatch',
  title: 'Model-visible text describes capabilities the description does not mention',
  severity: 'medium',
  kinds: ['skill', 'mcp-tool'],
  check(a: Artifact): Finding[] {
    const describe = a.segments.find((s) => s.visibility === 'both' || s.visibility === 'user');
    if (!describe) return [];
    const declared = describe.text.toLowerCase();
    const body = modelSegments(a).filter((s) => s !== describe).map((s) => s.text).join('\n');
    const findings: Finding[] = [];

    const probes: { cap: string; re: RegExp; words: string[] }[] = [
      { cap: 'network requests', re: /\b(?:curl|wget|fetch\(|https?:\/\/(?!(?:www\.)?(?:example|localhost))|requests\.(?:get|post)|urllib)\b/i, words: ['http', 'network', 'fetch', 'download', 'upload', 'api', 'url', 'web', 'remote', 'request'] },
      { cap: 'shell execution', re: /\b(?:subprocess|os\.system|child_process|exec\(|eval\(|bash -c|sh -c)\b/i, words: ['run', 'execute', 'shell', 'command', 'script', 'bash', 'process'] },
      { cap: 'credential access', re: /(?:~\/\.(?:ssh|aws|gnupg|kube|npmrc|docker)|\.env\b|id_rsa|credentials|AWS_SECRET|GITHUB_TOKEN|ANTHROPIC_API_KEY)/i, words: ['credential', 'secret', 'token', 'key', 'auth', 'login', 'password', 'env'] },
    ];

    for (const p of probes) {
      const m = p.re.exec(body);
      if (!m) continue;
      if (p.words.some((w) => declared.includes(w))) continue;
      findings.push({
        ruleId: 'hidden/surface-mismatch',
        title: `Model-visible text uses ${p.cap}, which the description does not mention`,
        severity: p.cap === 'credential access' ? 'high' : 'medium',
        confidence: 'low',
        artifactId: a.id,
        artifactName: a.name,
        file: a.files[0],
        evidence: escapeEvidence(m[0], 80),
        rationale:
          `The description a human reads when installing this artifact says nothing about ${p.cap}, but the text loaded into the agent does. The gap may be sloppy documentation rather than intent — this is reported at low confidence as a review prompt.`,
        remediation: `State ${p.cap} in the description, or remove it from the body.`,
      });
    }
    return findings;
  },
};

export const hiddenRules: Rule[] = [
  invisibleCharacters,
  instructionOverride,
  hiddenComment,
  encodedPayload,
  schemaInjection,
  conflictingSurface,
];
