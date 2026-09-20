import type { Capability, Finding, ProbeResult, TraceEvent } from '../model.js';
import { escapeEvidence, uniq } from '../util.js';
import type { InvokedTool, McpTool } from './runner.js';
import { findCanaries, type Canary } from './sandbox.js';

/**
 * Behavioural differencing.
 *
 * Static rules ask "does this text look dangerous". This asks a question with an
 * answer: "did this server do something it never said it would". The declared
 * side comes from MCP annotations and, failing those, from the wording of the
 * tool descriptions; the observed side comes from the trace. The interesting
 * findings are in the difference, and they are evidence rather than suspicion —
 * which is why they are the only findings marked `observed`.
 */

const SENSITIVE_PATH = /\.(?:ssh|aws|gnupg|kube|npmrc|netrc|pypirc)\b|id_rsa|id_ed25519|\.aws\/credentials|\.env(?:$|[^\w/])|\.claude\.json|\.claude\/\.credentials|Keychains|Cookies|Login Data|\/etc\/(?:passwd|shadow)|\.git-credentials/i;

/**
 * Paths every process touches to exist at all. Reporting these would bury the
 * signal, and an attacker cannot hide anything interesting inside them.
 */
const NOISE_PATH = /node_modules|\/usr\/|\/nix\/|\/proc\/|\/sys\/|\/dev\/|\/etc\/(?:ssl|ca-certificates|resolv\.conf|hosts|localtime|nsswitch)|site-packages|dist-packages|\/lib\/python|\.nvm\/|\.pyenv\/|__pycache__|[\\\\/]skillcheck-[A-Za-z0-9]{6}|package\.json$|\.node$|\.so(?:\.\d+)*$|\.pyc$/;

const LOCAL_HOST = /^(?:tls:)?(?:fetch:)?(?:https?:\/\/)?(?:localhost|127\.0\.0\.1|::1|0\.0\.0\.0|\[::1\])(?::|$|\/)/i;

export function declaredCapabilities(tools: McpTool[]): Capability[] {
  const caps = new Set<Capability>();
  for (const tool of tools) {
    const ann = tool.annotations ?? {};
    const text = `${tool.name} ${tool.description ?? ''}`.toLowerCase();

    // Annotations are the explicit contract and take precedence over wording.
    if (ann.readOnlyHint !== true) {
      if (/\b(?:write|create|update|delete|save|edit|modify|append|upload|commit|remove)\b/.test(text)) caps.add('fs.write');
    }
    if (ann.openWorldHint === true) caps.add('net.connect');
    if (/\b(?:http|https|url|web|fetch|download|api|request|remote|search|browse|crawl|internet|endpoint)\b/.test(text)) {
      caps.add('net.connect');
      caps.add('net.dns');
    }
    if (/\b(?:read|list|get|open|load|show|view|search|find|grep|cat|file|directory|folder|path)\b/.test(text)) caps.add('fs.read');
    if (/\b(?:run|execute|shell|command|spawn|terminal|bash|process|script|compile|build|test)\b/.test(text)) caps.add('process.exec');
    if (/\b(?:credential|token|secret|api key|auth|login|env(?:ironment)? var)\b/.test(text)) caps.add('env.read');
    if (/\b(?:write|create|save|edit|modify|append|delete|remove)\b/.test(text) && ann.readOnlyHint !== true) caps.add('fs.write');
  }
  // A server that speaks stdio still has to exist on disk; reading is implied.
  caps.add('fs.read');
  return [...caps];
}

export function observedCapabilities(events: TraceEvent[]): Capability[] {
  return uniq(events.filter((e) => !isNoise(e)).map((e) => e.kind));
}

function isNoise(e: TraceEvent): boolean {
  if (e.kind === 'fs.read' || e.kind === 'fs.write') {
    if (SENSITIVE_PATH.test(e.detail)) return false;
    return NOISE_PATH.test(e.detail);
  }
  return false;
}

export interface DiffInput {
  artifactId: string;
  artifactName: string;
  file?: string;
  tools: McpTool[];
  events: TraceEvent[];
  /** Decoys planted in the sandbox home, when one was used. */
  canaries?: Canary[];
  /** Outcome of the active phase, when tools were invoked. */
  invoked?: InvokedTool[];
}

/** Strip a path, scheme and prefix so the same destination seen by the socket
 *  layer and by the HTTP layer collapses to one host. */
function hostOf(detail: string): string {
  return detail
    .replace(/^(?:tls:|fetch:)/, '')
    .replace(/^https?:\/\//, '')
    .split('/')[0]!
    .split(':')[0]!
    .trim() || 'unknown';
}

export function diffBehaviour(input: DiffInput): { findings: Finding[]; declared: Capability[]; observed: Capability[] } {
  const declared = declaredCapabilities(input.tools);
  const events = input.events.filter((e) => !isNoise(e));
  const observed = uniq(events.map((e) => e.kind));
  const findings: Finding[] = [];

  const base = (extra: Partial<Finding>): Finding => ({
    ruleId: 'probe/undeclared-capability',
    title: 'Observed behaviour not covered by the declared capability',
    severity: 'high',
    confidence: 'high',
    artifactId: input.artifactId,
    artifactName: input.artifactName,
    file: input.file,
    rationale: '',
    remediation: '',
    observed: true,
    ...extra,
  });

  /* A planted decoy reaching a socket is the one finding here that needs no
     interpretation: the bytes were written, and they could only have come from
     a credential file or environment variable the server chose to read. */
  // The same write is seen by several hooks (fetch, ClientRequest, socket), so
  // collapse them: one attempt to send one secret to one host is one finding.
  const exfilSeen = new Set<string>();
  for (const e of events.filter((x) => x.kind === 'exfil.canary')) {
    const [tokenPart, destination] = e.detail.split(' -> ');
    const canary = (input.canaries ?? []).find((c) => c.token === tokenPart?.trim());
    const host = hostOf(destination ?? '');
    const key = `${tokenPart}|${host}`;
    if (host !== 'unknown' && exfilSeen.has(key)) continue;
    if (host === 'unknown' && exfilSeen.size > 0) continue;   // a less specific view of a hit already reported
    exfilSeen.add(key);
    findings.push(base({
      ruleId: 'probe/canary-exfiltration',
      title: 'Server transmitted a planted credential to a remote destination',
      severity: 'critical',
      evidence: `${canary ? canary.where : 'canary'} -> ${escapeEvidence(destination ?? 'unknown', 100)} during "${e.phase}"`,
      rationale:
        'A decoy credential was written into an outbound connection. The check runs before encryption, so TLS does not conceal it, and the value exists nowhere except the sandbox this probe created — there is no benign path by which it reaches a network socket.',
      remediation: 'Do not install this server. Rotate anything it had access to and report it to the registry it was published on.',
    }));
  }

  for (const call of input.invoked ?? []) {
    if (!call.resultText) continue;
    for (const hit of findCanaries(call.resultText, input.canaries ?? [])) {
      findings.push(base({
        ruleId: 'probe/canary-in-result',
        title: `Tool "${call.name}" returned a planted credential in its result`,
        severity: 'critical',
        evidence: `${hit.where} appeared in the result of ${call.name}(${'…'})`,
        rationale:
          'The tool read a credential and handed it back to the agent, which places it in the model context where any later instruction can forward it. No network call is needed for this to be an exfiltration path.',
        remediation: 'Do not install this server. Treat any credential reachable from the agent\'s environment as exposed.',
      }));
    }
  }

  /* Credential access is reported whether or not it was declared: a tool that
     declares it is still worth surfacing, because the user rarely knows. */
  for (const e of events.filter((x) => (x.kind === 'fs.read' || x.kind === 'fs.write') && SENSITIVE_PATH.test(x.detail))) {
    findings.push(base({
      ruleId: 'probe/credential-access',
      title: 'Server touched credential storage during a passive probe',
      severity: 'critical',
      evidence: `${e.kind} ${escapeEvidence(e.detail, 120)} during "${e.phase}"${e.frame ? ` (${escapeEvidence(e.frame, 80)})` : ''}`,
      rationale:
        'The probe only started the server and listed its tools. No tool was invoked, so nothing about the task required a credential file to be opened.',
      remediation: 'Ask the maintainer why startup reads this path. Treat any credential it can reach as exposed until answered.',
    }));
  }

  const startupNet = dedupeByHost(events.filter((e) => e.kind === 'net.connect' && e.phase === 'startup' && !LOCAL_HOST.test(e.detail)));
  for (const e of startupNet.slice(0, 3)) {
    findings.push(base({
      ruleId: 'probe/startup-egress',
      title: 'Server contacted a remote host before any tool was called',
      severity: 'high',
      evidence: `${escapeEvidence(e.detail, 120)} at +${e.t}ms during "${e.phase}"`,
      rationale:
        'Connections made during initialisation happen on every agent session regardless of what the user asks for. Whatever this call carries — telemetry, a config fetch, a beacon — is unconditional.',
      remediation: 'Confirm the endpoint and payload with the maintainer, and prefer a server that defers network access until a tool is invoked.',
    }));
  }

  const undeclared = observed.filter((c) => !declared.includes(c) && c !== 'net.dns' && c !== 'exfil.canary');
  for (const cap of undeclared) {
    const samples = events.filter((e) => e.kind === cap);
    if (cap === 'net.connect' && samples.every((s) => LOCAL_HOST.test(s.detail))) {
      findings.push(base({
        ruleId: 'probe/undeclared-capability',
        title: 'Server opened a local connection that no tool description mentions',
        severity: 'low',
        confidence: 'medium',
        evidence: samples.slice(0, 3).map((s) => escapeEvidence(s.detail, 60)).join(', '),
        rationale: 'Local sockets are usually a database or IPC rather than egress, so this is listed for completeness rather than as a problem.',
        remediation: 'No action needed unless the local service is unexpected.',
      }));
      continue;
    }
    findings.push(base({
      ruleId: 'probe/undeclared-capability',
      title: `Server used ${cap} but no tool declares it`,
      severity: cap === 'process.exec' || cap === 'env.read' ? 'high' : cap === 'net.connect' ? 'high' : 'medium',
      evidence: samples.slice(0, 3).map((s) => `${escapeEvidence(s.detail, 80)} [${s.phase}]`).join('; '),
      rationale:
        `Neither the MCP annotations nor the tool descriptions of this server imply ${cap}, yet the probe observed it. The gap between the declared contract and the observed behaviour is the finding; the intent behind it is not something a scan can establish.`,
      remediation: `Either the capability is real and belongs in the description and annotations, or it does not belong in the server. Ask which.`,
    }));
  }

  for (const e of events.filter((x) => x.kind === 'env.read')) {
    findings.push(base({
      ruleId: 'probe/env-harvest',
      title: e.detail === '<enumerate>'
        ? 'Server enumerated the entire process environment'
        : `Server read a credential-shaped environment variable (${e.detail})`,
      severity: e.detail === '<enumerate>' ? 'high' : 'medium',
      confidence: e.detail === '<enumerate>' ? 'medium' : 'high',
      evidence: `${escapeEvidence(e.detail, 80)} during "${e.phase}"`,
      rationale:
        'An MCP server inherits the environment of the agent that launched it, which typically includes the agent\'s own API keys and any credentials in the developer\'s shell. Reading them is a prerequisite for forwarding them.',
      remediation: 'Launch the server with an explicit minimal `env` block rather than the inherited environment.',
    }));
  }

  const unanalysable = (input.invoked ?? []).filter((c) => !c.called && /no readOnlyHint/.test(c.skipped ?? ''));
  if (unanalysable.length > 0) {
    findings.push(base({
      ruleId: 'probe/unannotated-tools',
      title: `${unanalysable.length} tool(s) could not be exercised: no behaviour annotations`,
      severity: 'low',
      confidence: 'high',
      evidence: unanalysable.map((c) => c.name).join(', '),
      rationale:
        'Without readOnlyHint or destructiveHint the probe cannot tell a lookup from a deletion, so it declines to call them. Their behaviour is unmeasured, and the report says nothing about them either way.',
      remediation: 'Ask the maintainer to annotate the tools, or re-run with --invoke-destructive inside a disposable container.',
    }));
  }

  const unusedDeclarations = declared.filter((c) => !observed.includes(c) && c !== 'fs.read');
  if (unusedDeclarations.length > 0) {
    findings.push(base({
      ruleId: 'probe/over-broad-declaration',
      title: 'Declared capabilities not exercised during the probe',
      severity: 'info',
      confidence: 'low',
      evidence: unusedDeclarations.join(', '),
      rationale:
        'The probe is passive, so this is expected for most servers and is reported only to show what the declared surface covers. It becomes interesting when the declared surface is much wider than anything the tools need.',
      remediation: 'Compare the declared surface with the tools actually offered.',
    }));
  }

  return { findings, declared, observed };
}

/** Keep the first event per destination host. */
function dedupeByHost(events: TraceEvent[]): TraceEvent[] {
  const seen = new Set<string>();
  return events.filter((e) => {
    const host = hostOf(e.detail);
    if (seen.has(host)) return false;
    seen.add(host);
    return true;
  });
}

export function summariseProbe(p: ProbeResult): string {
  const gap = p.observed.filter((c) => !p.declared.includes(c));
  if (!p.ok) return `probe failed: ${p.error ?? 'unknown error'}`;
  const called = p.invokedCount ?? 0;
  const mode = called > 0 ? `${called} tool(s) invoked` : 'passive';
  return `${p.tools.length} tool(s), ${mode}; declared [${p.declared.join(', ') || 'none'}]; observed [${p.observed.join(', ') || 'none'}]${gap.length ? `; undeclared: ${gap.join(', ')}` : ''}`;
}
