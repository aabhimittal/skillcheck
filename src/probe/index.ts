import type { Artifact, Finding, ProbeResult, Segment } from '../model.js';
import { rel } from '../util.js';
import { diffBehaviour, declaredCapabilities } from './differ.js';
import { fetchRemoteTools, runServer, type McpTool } from './runner.js';

export interface ProbeOptions {
  cwd: string;
  timeoutMs: number;
  /** Only probe servers whose name is in this list, when non-empty. */
  only: string[];
}

export interface ProbeOutput {
  results: ProbeResult[];
  findings: Finding[];
  /** One artifact per advertised tool, fed back through the static rules. */
  toolArtifacts: Artifact[];
}

export async function probeServers(servers: Artifact[], opts: ProbeOptions): Promise<ProbeOutput> {
  const results: ProbeResult[] = [];
  const findings: Finding[] = [];
  const toolArtifacts: Artifact[] = [];

  for (const server of servers) {
    if (opts.only.length > 0 && !opts.only.includes(server.name)) continue;
    const url = typeof server.meta['url'] === 'string' ? (server.meta['url'] as string) : undefined;
    const command = typeof server.meta['command'] === 'string' ? (server.meta['command'] as string) : undefined;

    if (url) {
      const headers = (server.meta['headers'] as Record<string, string> | undefined) ?? {};
      const { tools, error } = await fetchRemoteTools(url, headers, opts.timeoutMs);
      const declared = declaredCapabilities(tools);
      results.push({
        artifactId: server.id, name: server.name, ok: !error, error,
        tools: tools.map((t) => t.name), declared, observed: [], events: [], durationMs: 0,
      });
      if (!error) {
        findings.push({
          ruleId: 'probe/remote-not-instrumented',
          title: 'Remote server: tool definitions retrieved, behaviour not observable',
          severity: 'info',
          confidence: 'high',
          artifactId: server.id,
          artifactName: server.name,
          file: server.files[0],
          rationale:
            'The server runs on infrastructure you do not control, so no trace can be collected. Its definitions are pinned and statically scanned; its behaviour is taken on trust.',
          remediation: 'Rely on the pin to catch definition changes, and scope the credentials the server receives accordingly.',
        });
      }
      toolArtifacts.push(...toolsToArtifacts(server, tools, opts.cwd));
      continue;
    }

    if (!command) continue;

    const args = Array.isArray(server.meta['args']) ? (server.meta['args'] as unknown[]).map(String) : [];
    const env = (server.meta['env'] as Record<string, string> | undefined) ?? {};
    const outcome = await runServer({ command, args, env, cwd: opts.cwd, timeoutMs: opts.timeoutMs });
    const diff = diffBehaviour({
      artifactId: server.id,
      artifactName: server.name,
      file: server.files[0],
      tools: outcome.tools,
      events: outcome.events,
    });

    results.push({
      artifactId: server.id,
      name: server.name,
      ok: outcome.ok,
      error: outcome.error,
      tools: outcome.tools.map((t) => t.name),
      declared: diff.declared,
      observed: diff.observed,
      events: outcome.events,
      durationMs: outcome.durationMs,
    });
    findings.push(...diff.findings);

    if (outcome.ok && !outcome.instrumented) {
      findings.push({
        ruleId: 'probe/not-instrumented',
        title: 'Server started but instrumentation did not load',
        severity: 'info',
        confidence: 'high',
        artifactId: server.id,
        artifactName: server.name,
        file: server.files[0],
        rationale:
          `The server runs under a runtime the shims do not cover (command: ${command}), so tool definitions were collected but no behaviour was observed. Absence of findings here means absence of visibility, not absence of activity.`,
        remediation: 'Run the probe inside a network-isolated container and watch egress externally for this server.',
      });
    }
    if (!outcome.ok) {
      findings.push({
        ruleId: 'probe/failed',
        title: 'Probe could not complete the MCP handshake',
        severity: 'low',
        confidence: 'high',
        artifactId: server.id,
        artifactName: server.name,
        file: server.files[0],
        evidence: outcome.error,
        rationale: 'Nothing was verified for this server. It may need credentials, a different working directory, or it may be broken.',
        remediation: 'Supply the required environment and re-run, or exclude the server explicitly so its absence from the report is deliberate.',
      });
    }

    toolArtifacts.push(...toolsToArtifacts(server, outcome.tools, opts.cwd));
  }

  return { results, findings, toolArtifacts };
}

/**
 * Turn each advertised tool into a first-class artifact.
 *
 * Every nested schema `description` becomes its own segment, which is what lets
 * a finding point at `inputSchema.properties.path.description` rather than at
 * "somewhere in this server".
 */
export function toolsToArtifacts(server: Artifact, tools: McpTool[], cwd: string): Artifact[] {
  return tools.map((tool) => {
    const file = rel(cwd, `${server.files[0] ?? server.root}#${server.name}/${tool.name}`);
    const segments: Segment[] = [{
      file,
      label: 'tool description',
      visibility: 'both',
      text: tool.description ?? '',
      startLine: 1,
    }];
    for (const schemaKey of ['inputSchema', 'outputSchema'] as const) {
      const schema = tool[schemaKey];
      if (!schema) continue;
      for (const [pointer, text] of schemaStrings(schema, schemaKey)) {
        segments.push({ file, label: pointer, visibility: 'model', text, startLine: 1 });
      }
    }
    if (tool.annotations?.title) {
      segments.push({ file, label: 'annotations.title', visibility: 'both', text: tool.annotations.title, startLine: 1 });
    }
    return {
      id: `mcp-tool:${server.name}/${tool.name}`,
      kind: 'mcp-tool',
      name: `${server.name}/${tool.name}`,
      root: server.root,
      origin: server.origin,
      files: [file],
      segments,
      meta: tool as unknown as Record<string, unknown>,
      parent: server.id,
    };
  });
}

/** Collect every human-readable string in a schema, with a JSON-pointer-ish label. */
function schemaStrings(node: unknown, path: string, depth = 0): [string, string][] {
  if (depth > 8 || !node || typeof node !== 'object') return [];
  const out: [string, string][] = [];
  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    const here = `${path}.${key}`;
    if (typeof value === 'string' && (key === 'description' || key === 'title' || key === 'default' || key === '$comment')) {
      if (value.trim()) out.push([here, value]);
    } else if (value && typeof value === 'object') {
      out.push(...schemaStrings(value, here, depth + 1));
    }
  }
  return out;
}
