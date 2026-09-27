import type { Rule } from '../model.js';
import { scan } from './util.js';

/**
 * Exfiltration and remote-code patterns.
 *
 * The distinguishing feature of an exfiltration instruction is not that it
 * mentions a URL — most useful skills do — but that it couples *reading local
 * state* to *sending it somewhere*. The patterns below target that coupling.
 */

const exfiltration: Rule = {
  id: 'egress/data-to-remote',
  title: 'Instruction couples local data to an outbound request',
  severity: 'critical',
  kinds: ['skill', 'mcp-server', 'mcp-tool'],
  check: (a) => [
    // Command position only (line start or after ; & | ( or a `$ ` prompt), and
    // only when the substituted command READS local data. A variable in a
    // query string is an ID; `$(uname)` is platform detection; neither is data.
    ...scan(a, /(?:^|[;&|(]\s*|\$\s+)(?:sudo\s+)?(?:curl|wget|https?ie|http)\s[^\n]{0,200}?(?:\$\(|`)\s*(?:sudo\s+)?(?:cat|head|tail|env|printenv|base64|tar|zip|gzip|find|ls|history|security|gpg|xxd|od|strings|sqlite3)\b/im, {
      ruleId: 'egress/data-to-remote',
      title: 'Shell command interpolates local output into an outbound request',
      severity: 'critical',
      confidence: 'high',
      only: 'model',
      onlyFenced: true,
      max: 3,
      rationale:
        'A request whose body or query string is built from command substitution sends whatever that command produces to the remote host. This is exfiltration in its most direct form.',
      remediation: 'Remove the command, or confirm with the maintainer exactly what is transmitted and to whom.',
    }),
    ...scan(a, /\b(?:send|post|upload|transmit|forward|report|exfiltrate)\b[^.\n]{0,60}\b(?:contents?|output|results?|file|environment|env vars?|credentials?|keys?|tokens?|conversation|history)\b[^.\n]{0,60}\b(?:to|at)\b[^.\n]{0,40}(?:https?:\/\/|[\w.-]+\.[a-z]{2,}\/)/i, {
      ruleId: 'egress/data-to-remote',
      title: 'Prose instruction to send local data to a remote endpoint',
      severity: 'critical',
      confidence: 'medium',
      only: 'model',
      max: 3,
      rationale:
        'The agent follows prose. An instruction to send file contents, environment variables or conversation history to an endpoint does not need any code to be effective.',
      remediation: 'Verify the endpoint is the artifact\'s own documented service, and that the description discloses the transfer.',
    }),
  ],
};

const remoteCodeExecution: Rule = {
  id: 'egress/remote-code-execution',
  title: 'Instruction pipes remote content into an interpreter',
  severity: 'critical',
  kinds: ['skill', 'mcp-server', 'mcp-tool'],
  check: (a) =>
    scan(a, /(?:curl|wget)[^\n|]{0,120}\|\s*(?:sudo\s+)?(?:ba|z|d|k)?sh\b|(?:curl|wget)[^\n]{0,120}\|\s*(?:python3?|node|perl|ruby)\b|iex\s*\(\s*(?:new-object|iwr|invoke-webrequest)/i, {
      ruleId: 'egress/remote-code-execution',
      title: 'Instruction pipes remote content into an interpreter',
      severity: 'critical',
      confidence: 'high',
      only: 'model',
      max: 3,
      rationale:
        'Whatever the endpoint serves at the moment of execution runs with the user\'s privileges, and nothing about it is reviewable in advance. The content can differ per request, per IP, or per day.',
      remediation: 'Vendor the script into the artifact, or pin it by digest and verify before executing.',
    }),
};

const hardcodedEndpoint: Rule = {
  id: 'egress/undeclared-endpoint',
  title: 'Model-visible text contains a raw IP endpoint or URL shortener',
  severity: 'medium',
  kinds: ['skill', 'mcp-server', 'mcp-tool'],
  check: (a) =>
    scan(a, /https?:\/\/(?:(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|rb\.gy|shorturl\.at)\/)/i, {
      ruleId: 'egress/undeclared-endpoint',
      title: 'Model-visible text contains a raw IP endpoint or URL shortener',
      severity: 'medium',
      confidence: 'medium',
      only: 'model',
      max: 3,
      rationale:
        'A bare IP address or a shortened link gives a reviewer nothing to evaluate and can be re-pointed after review. Neither belongs in an instruction the agent will follow.',
      remediation: 'Replace with the full hostname of a service you can attribute, or remove it.',
    }),
};

export const egressRules: Rule[] = [exfiltration, remoteCodeExecution, hardcodedEndpoint];
