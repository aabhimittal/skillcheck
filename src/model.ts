/**
 * Core data model.
 *
 * The central idea of skillcheck is that every artifact has two surfaces:
 *
 *   - the USER surface: what a human reads before installing (a name, a one-line
 *     description, a README, a marketplace card).
 *   - the MODEL surface: what the agent actually loads into its context at
 *     runtime (the full skill body, every tool description, every nested JSON
 *     Schema `description` field).
 *
 * Almost every interesting attack lives in the gap between the two, so the
 * surfaces are tracked, hashed and diffed separately throughout.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
/** `both` marks text that is shown to a human AND loaded into the model's context. */
export type Visibility = 'user' | 'model' | 'both';
export type ArtifactKind = 'skill' | 'mcp-server' | 'mcp-tool';

export const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** A contiguous piece of text belonging to an artifact, with its provenance. */
export interface Segment {
  /** File the text came from, repo-relative where possible. */
  file: string;
  /** Human label, e.g. "SKILL.md body" or "tools/fetch.inputSchema.properties.url.description". */
  label: string;
  visibility: Visibility;
  text: string;
  /** Byte offset of `text` within `file`, when the segment is a slice of a real file. */
  offset?: number;
  /** 1-indexed line in `file` where `text` starts, so findings can be located. */
  startLine?: number;
}

export interface Artifact {
  /** Stable identity across scans; used as the lockfile key. */
  id: string;
  kind: ArtifactKind;
  name: string;
  version?: string;
  /** Directory or config file the artifact was discovered from. */
  root: string;
  /** Where the artifact came from (npm spec, command line, git url) when known. */
  origin?: string;
  files: string[];
  segments: Segment[];
  /** Raw parsed metadata: skill front-matter, server config, or tool definition. */
  meta: Record<string, unknown>;
  /** Parent artifact id, e.g. the server an mcp-tool belongs to. */
  parent?: string;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  /**
   * How sure we are that this is real, kept deliberately separate from severity.
   * Static text matching cannot resolve intent, so `low` confidence findings are
   * reported as leads, never as verdicts, and never fail a build by default.
   */
  confidence: Confidence;
  artifactId: string;
  artifactName: string;
  file?: string;
  line?: number;
  /** The matched text, truncated and control-character escaped. */
  evidence?: string;
  /** Why this matters, in one or two sentences. */
  rationale: string;
  remediation: string;
  /** Set for findings produced by the runtime probe rather than by static rules. */
  observed?: boolean;
}

export interface SuppressionRule {
  rule: string;
  artifact?: string;
  /** Required: an unexplained suppression is how a scanner quietly goes blind. */
  reason: string;
  /** ISO date; an expired suppression stops applying and is reported. */
  expires?: string;
}

export interface Config {
  ignore: SuppressionRule[];
  /** Rule ids to disable outright. */
  disable: string[];
  failOn: Severity;
  /** Minimum confidence that may fail a build. */
  failConfidence: Confidence;
  /** Extra directories to search for skills. */
  skillPaths: string[];
  /** Extra MCP config files to parse. */
  mcpConfigs: string[];
}

export interface ScanContext {
  config: Config;
  cwd: string;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  /** Rule applies to these artifact kinds. */
  kinds: ArtifactKind[];
  check(artifact: Artifact, ctx: ScanContext): Finding[];
}

export interface ScanResult {
  version: string;
  scannedAt: string;
  cwd: string;
  artifacts: Artifact[];
  findings: Finding[];
  suppressed: Finding[];
  probes: ProbeResult[];
  summary: Record<Severity, number>;
}

/* ---------------------------------------------------------------- probe --- */

export type Capability =
  | 'fs.read'
  | 'fs.write'
  | 'net.connect'
  | 'net.dns'
  | 'process.exec'
  | 'env.read'
  /** A planted canary credential was written to a socket. Not a capability so
   *  much as a verdict: it is only ever produced by exfiltration. */
  | 'exfil.canary';

export interface TraceEvent {
  /** ms since probe start. */
  t: number;
  kind: Capability;
  /** Path, host:port, command, or env var name. */
  detail: string;
  /** Probe phase the event was attributed to, by time window. */
  phase?: string;
  /** Short stack excerpt, for attribution back to source. */
  frame?: string;
}

export interface ProbeResult {
  artifactId: string;
  name: string;
  ok: boolean;
  error?: string;
  /** Tool names the server advertised. */
  tools: string[];
  /** Capabilities the artifact declared, via annotations or description. */
  declared: Capability[];
  /** Capabilities actually exercised during the probe. */
  observed: Capability[];
  events: TraceEvent[];
  durationMs: number;
  /** How many tools were actually called; 0 means the probe stayed passive. */
  invokedCount?: number;
}

/* ------------------------------------------------------------- lockfile --- */

export interface LockEntry {
  id: string;
  kind: ArtifactKind;
  name: string;
  version?: string;
  origin?: string;
  /** sha256 of the canonicalised user-visible surface. */
  userHash: string;
  /** sha256 of the canonicalised model-visible surface. */
  modelHash: string;
  /** Per-file hashes, so drift can be attributed. */
  files: Record<string, string>;
  pinnedAt: string;
}

export interface Lockfile {
  lockfileVersion: 1;
  generatedBy: string;
  entries: Record<string, LockEntry>;
}
