import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * A disposable home directory seeded with decoy credentials.
 *
 * Observing that a server *reads* a credential path is useful but weak: reading
 * is not stealing, and a maintainer can always claim the read was incidental.
 * Planting uniquely-tokened decoys turns the question into one with a factual
 * answer — did this exact byte sequence leave the process? The canary is never
 * a real secret, so the probe is safe to run against a hostile server, and a hit
 * is not a heuristic.
 */
export interface Canary {
  token: string;
  /** Where it was planted, for the finding's evidence. */
  where: string;
}

export interface Sandbox {
  home: string;
  canaries: Canary[];
  /** Environment overrides handed to the probed server. */
  env: Record<string, string>;
  dispose(): void;
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function rand(n: number, alphabet = ALNUM): string {
  const bytes = randomBytes(n);
  let out = '';
  for (let i = 0; i < n; i++) out += alphabet[bytes[i]! % alphabet.length];
  return out;
}

/**
 * Decoys shaped like the credential they stand in for.
 *
 * An earlier version used `skillcheck-canary-...`, which let a server detect
 * the probe with one substring search and behave for its duration. The mapping
 * from token to planted location now lives only in this process, and the
 * values are indistinguishable in form from real secrets. Randomness is long
 * enough (>= 36 chars) that an accidental match elsewhere is not a concern.
 */
const FORMATS = {
  aws: () => rand(40, ALNUM + '/+'),
  ssh: () => rand(68, ALNUM + '+/'),
  npm: () => `npm_${rand(36)}`,
  dotenv: () => rand(40),
  agent: () => rand(48, ALNUM + '-_'),
  github: () => `ghp_${rand(36)}`,
  apikey: () => `sk-${rand(48)}`,
} as const;

function token(kind: keyof typeof FORMATS): string {
  return FORMATS[kind]();
}

export function createSandbox(): Sandbox {
  const home = mkdtempSync(join(tmpdir(), 'skillcheck-home-'));
  const canaries: Canary[] = [];

  const plant = (relPath: string, kind: keyof typeof FORMATS, render: (t: string) => string) => {
    const t = token(kind);
    const full = join(home, relPath);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, render(t), { mode: 0o600 });
    canaries.push({ token: t, where: `~/${relPath}` });
  };

  plant('.aws/credentials', 'aws', (t) => `[default]\naws_access_key_id = AKIA${'X'.repeat(16)}\naws_secret_access_key = ${t}\n`);
  plant('.ssh/id_rsa', 'ssh', (t) => `-----BEGIN OPENSSH PRIVATE KEY-----\n${t}\n-----END OPENSSH PRIVATE KEY-----\n`);
  plant('.npmrc', 'npm', (t) => `//registry.npmjs.org/:_authToken=${t}\n`);
  plant('.env', 'dotenv', (t) => `DATABASE_URL=postgres://user:${t}@localhost/app\n`);
  plant('.claude/.credentials.json', 'agent', (t) => JSON.stringify({ claudeAiOauth: { accessToken: t } }, null, 2));

  // Credential-shaped environment variables, since an MCP server inherits the
  // launching agent's environment and that is the cheapest thing to harvest.
  const envCanaries: Record<string, string> = {};
  const envKinds: [string, keyof typeof FORMATS][] = [
    ['AWS_SECRET_ACCESS_KEY', 'aws'], ['GITHUB_TOKEN', 'github'],
    ['ANTHROPIC_API_KEY', 'apikey'], ['OPENAI_API_KEY', 'apikey'],
  ];
  for (const [name, kind] of envKinds) {
    const t = token(kind);
    envCanaries[name] = t;
    canaries.push({ token: t, where: `$${name}` });
  }

  return {
    home,
    canaries,
    env: {
      ...envCanaries,
      HOME: home,
      USERPROFILE: home,
      // The shim scans outbound writes for these before they are encrypted.
      SKILLCHECK_CANARIES: canaries.map((c) => c.token).join(','),
    },
    dispose() {
      try {
        rmSync(home, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
      } catch { /* the OS will reclaim it */ }
    },
  };
}

/** Find any planted canary inside arbitrary text, e.g. a tool's own result. */
export function findCanaries(text: string, canaries: Canary[]): Canary[] {
  return canaries.filter((c) => text.includes(c.token));
}

/**
 * Whether this process is inside something that can absorb a hostile server.
 *
 * Deliberately conservative: an unrecognised environment is treated as the
 * user's own machine, because the cost of being wrong is running attacker code
 * on a laptop with real credentials.
 */
export function detectContainment(): { contained: boolean; reason: string } {
  if (existsSync('/.dockerenv')) return { contained: true, reason: 'Docker container' };
  if (existsSync('/run/.containerenv')) return { contained: true, reason: 'Podman container' };
  if (process.env['KUBERNETES_SERVICE_HOST']) return { contained: true, reason: 'Kubernetes pod' };
  if (process.env['CODESPACES'] || process.env['GITPOD_WORKSPACE_ID']) return { contained: true, reason: 'cloud workspace' };
  if (process.env['CI'] === 'true' || process.env['GITHUB_ACTIONS'] === 'true') return { contained: true, reason: 'ephemeral CI runner' };
  return { contained: false, reason: 'no container or ephemeral runner detected' };
}
