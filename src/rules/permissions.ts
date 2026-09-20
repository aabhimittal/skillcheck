import type { Artifact, Finding, Rule } from '../model.js';
import { asList } from '../frontmatter.js';
import { escapeEvidence } from '../util.js';
import { scan } from './util.js';

/** Tool grants that place no bound on what the agent may run. */
const UNBOUNDED = /^(?:Bash|Shell|Execute|Run)(?:\(\s*\*?\s*\)|\(\s*\*\s*:\s*\*\s*\))?$/i;

const broadToolGrant: Rule = {
  id: 'perm/unbounded-tool-grant',
  title: 'Skill requests an unbounded execution grant',
  severity: 'high',
  kinds: ['skill'],
  check(a: Artifact): Finding[] {
    const tools = asList(a.meta['allowed-tools'] ?? a.meta['allowedTools'] ?? a.meta['tools']);
    const findings: Finding[] = [];
    for (const t of tools) {
      const trimmed = t.trim();
      if (!UNBOUNDED.test(trimmed) && trimmed !== '*') continue;
      findings.push({
        ruleId: 'perm/unbounded-tool-grant',
        title: 'Skill requests an unbounded execution grant',
        severity: 'high',
        confidence: 'high',
        artifactId: a.id,
        artifactName: a.name,
        file: a.files[0],
        evidence: `allowed-tools: ${escapeEvidence(trimmed, 60)}`,
        rationale:
          'An unrestricted shell grant means any instruction that reaches this skill — including one injected into content it processes — runs with the user\'s full privileges. The grant is the blast radius.',
        remediation: 'Narrow the grant to the commands the skill actually runs, e.g. `Bash(git status:*)`.',
      });
    }
    return findings;
  },
};

const wildcardCommandGrant: Rule = {
  id: 'perm/wildcard-network-grant',
  title: 'Skill grants a network-capable command with a wildcard argument',
  severity: 'medium',
  kinds: ['skill'],
  check(a: Artifact): Finding[] {
    const tools = asList(a.meta['allowed-tools'] ?? a.meta['allowedTools'] ?? a.meta['tools']);
    const risky = /^(?:Bash|Shell)\(\s*(curl|wget|nc|ncat|ssh|scp|rsync|npx|pip|git|node|python3?|eval)\s*:\s*\*\s*\)$/i;
    return tools.flatMap((t) => {
      const m = risky.exec(t.trim());
      if (!m) return [];
      return [{
        ruleId: 'perm/wildcard-network-grant',
        title: `Skill grants \`${m[1]}\` with unrestricted arguments`,
        severity: 'medium' as const,
        confidence: 'high' as const,
        artifactId: a.id,
        artifactName: a.name,
        file: a.files[0],
        evidence: escapeEvidence(t, 60),
        rationale:
          `\`${m[1]}\` with a wildcard argument can reach any host or run any payload, so this grant is only nominally narrower than a full shell grant.`,
        remediation: 'Pin the allowed argument prefix, e.g. `Bash(curl:https://api.example.com/*)`.',
      }];
    });
  },
};

const SENSITIVE = new RegExp(
  [
    '~/\\.ssh(?:/|\\b)', 'id_rsa', 'id_ed25519',
    '~/\\.aws(?:/|\\b)', '\\.aws/credentials',
    '~/\\.config/gcloud', '~/\\.kube/config',
    '~/\\.gnupg', '~/\\.netrc', '~/\\.npmrc', '~/\\.pypirc', '~/\\.docker/config\\.json',
    '~/\\.claude\\.json', '~/\\.claude/\\.credentials',
    '\\.git-credentials',
    'Library/Keychains', 'login\\.keychain',
    '(?:Cookies|Login Data)(?:\\b|$)',
    '/etc/shadow',
    '(?<![\\w./-])\\.env(?:\\.[\\w-]+)?(?![\\w/])',
  ].join('|'),
  'i',
);

const sensitivePaths: Rule = {
  id: 'perm/sensitive-path-access',
  title: 'Model-visible text references credential storage',
  severity: 'high',
  kinds: ['skill', 'mcp-server', 'mcp-tool'],
  check: (a) =>
    scan(a, SENSITIVE, {
      ruleId: 'perm/sensitive-path-access',
      title: 'Model-visible text references credential storage',
      severity: 'high',
      confidence: 'medium',
      only: 'model',
      max: 4,
      rationale:
        'Instructions that point the agent at private keys, cloud credentials, browser cookie stores or agent config files are how a skill turns read access into account access. Some tools legitimately manage these paths; check whether this one claims to.',
      remediation: 'Confirm the skill needs the path. If it does, scope the access and say so in the description.',
    }),
};

const SECRET_ENV = /\b(?:[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)[A-Z0-9_]*)\b/;

const inlineSecret: Rule = {
  id: 'perm/inline-secret',
  title: 'Literal credential in an MCP server configuration',
  severity: 'high',
  kinds: ['mcp-server'],
  check(a: Artifact): Finding[] {
    const env = a.meta['env'];
    const headers = a.meta['headers'];
    const findings: Finding[] = [];
    const inspect = (obj: unknown, where: string) => {
      if (!obj || typeof obj !== 'object') return;
      for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
        if (typeof v !== 'string' || v.length < 12) continue;
        // `${input:token}` and `$VAR` are indirections, not literals.
        if (/^\$\{?[A-Za-z_]/.test(v) || /^\$\{(?:input|env|localEnv):/.test(v)) continue;
        if (!SECRET_ENV.test(k) && !/^(?:Authorization|Proxy-Authorization|Cookie)$/i.test(k)) continue;
        findings.push({
          ruleId: 'perm/inline-secret',
          title: 'Literal credential in an MCP server configuration',
          severity: 'high',
          confidence: 'high',
          artifactId: a.id,
          artifactName: a.name,
          file: a.files[0],
          evidence: `${where}.${k} = ${v.slice(0, 4)}…(${v.length} chars)`,
          rationale:
            'The value is committed in plain text wherever this config lives, and is handed to a third-party process on every launch. Config files are shared, synced and screenshotted far more often than key stores are.',
          remediation: 'Replace the literal with an environment reference and rotate the credential, which should be assumed exposed.',
        });
      }
    };
    inspect(env, 'env');
    inspect(headers, 'headers');
    return findings;
  },
};

const floatingVersion: Rule = {
  id: 'perm/unpinned-server-version',
  title: 'MCP server runs from an unpinned package specifier',
  severity: 'medium',
  kinds: ['mcp-server'],
  check(a: Artifact): Finding[] {
    const cmd = String(a.meta['command'] ?? '');
    const args = Array.isArray(a.meta['args']) ? (a.meta['args'] as unknown[]).map(String) : [];
    const line = [cmd, ...args].join(' ');
    if (!/\b(?:npx|pnpm dlx|bunx|uvx|pipx run)\b/.test(line)) return [];
    const spec = args.find((x) => !x.startsWith('-')) ?? '';
    if (/@\d[\w.\-+]*$/.test(spec) || /@sha256:/.test(spec)) return [];
    return [{
      ruleId: 'perm/unpinned-server-version',
      title: 'MCP server runs from an unpinned package specifier',
      severity: 'medium',
      confidence: 'high',
      artifactId: a.id,
      artifactName: a.name,
      file: a.files[0],
      evidence: escapeEvidence(line, 120),
      rationale:
        'An unpinned runner re-resolves the package on every launch, so whatever the publisher pushes last runs next. That is the exact mechanism a rug pull needs, and it removes any meaning from a prior review of the server.',
      remediation: 'Pin an exact version (`package@1.4.2`) and re-pin deliberately after reviewing each upgrade.',
    }];
  },
};

export const permissionRules: Rule[] = [
  broadToolGrant,
  wildcardCommandGrant,
  sensitivePaths,
  inlineSecret,
  floatingVersion,
];
