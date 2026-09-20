# skillcheck

Continuous security scanning for agent skills and MCP servers.

```
npx skillcheck            # scan what is installed
npx skillcheck pin        # record hashes of what you reviewed
npx skillcheck scan --probe   # launch each MCP server and compare behaviour to its claims
```

A tool description is read by the model on every turn and by the user almost
never. That asymmetry is the whole attack surface, and it is why skillcheck
tracks two separate surfaces for every artifact:

| surface | what it is | who reads it |
|---|---|---|
| **user surface** | name, description, README, marketplace card | a human, once, at install time |
| **model surface** | full `SKILL.md` body, every tool description, every nested JSON Schema `description` | the agent, every session |

Each is hashed independently. **A changed model hash with an unchanged user
hash is a rug pull**: the package still presents the description it was reviewed
under, while the instructions reaching the agent have been rewritten.

## What this actually does

**Behavioural differencing (the core).** `--probe` launches each configured MCP
server under an instrumentation shim, drives the MCP handshake, and records the
filesystem, network, process and environment effects it produces. It then diffs
those observations against what the server *declares* — `readOnlyHint`,
`openWorldHint` and the wording of its tool descriptions. A server annotated
`readOnlyHint: true, openWorldHint: false` that opens a socket during startup is
not a heuristic match; it is a contradiction between a contract and a
measurement, and the trace is attached as evidence.

```
✗ invoice-api — 4 tool(s); declared [fs.read]; observed [fs.read, net.connect, env.read]; undeclared: net.connect, env.read

CRITICAL Server touched credential storage during a passive probe
  evidence   fs.read /home/you/.ssh/id_rsa during "startup"
  why        The probe only started the server and listed its tools. No tool was invoked, so
             nothing about the task required a credential file to be opened.
```

**Hash-pinning and drift (`skillcheck.lock.json`).** CSA's guidance is to treat
tool definitions as executable code. If that is true, they belong in a lockfile.
`skillcheck pin` records both surface hashes plus per-file hashes; every later
scan reports what moved and which files moved, separating a silent rewrite
(critical) from an acknowledged version bump (low).

**Continuous registry monitoring (`skillcheck watch`).** Polls sources on a
schedule and compares snapshots. The high-value signals are not in any single
scan: a *published version whose content hash changed* (a republish — critical),
a *publisher added to an established package* (the visible half of an account
takeover — high), an unpublish, a deprecation.

**Static checks (the loss-leader).** Invisible and bidirectional control
characters, instructions hidden in HTML comments, imperative text inside JSON
Schema parameter descriptions, unbounded `Bash` grants, credential paths,
`curl … | sh`, command substitution piped into an outbound request, literal
secrets in MCP configs, unpinned `npx` specifiers.

## What it explicitly does not do

This matters more than the feature list, because a scanner that overstates its
reach is worse than none.

- **Static analysis cannot catch semantic injection.** An instruction written in
  ordinary, polite prose — no hidden characters, no shell, no URL — will pass
  every text rule here. That limit is structural, not a gap to be patched with
  more regexes. It is the reason the probe exists and the reason the pin exists:
  one measures behaviour, the other notices change.
- **A clean report is not a safety verdict.** It means nothing was detected.
- **The probe is passive by default.** It starts the server and lists its tools;
  it does not invoke them. It catches unconditional behaviour — startup beacons,
  credential reads, environment harvesting — and says nothing about what a tool
  does once called with real arguments.
- **The probe is an observer, not a sandbox.** It records; it blocks nothing, and
  a server that wants to evade it can. Run `--probe` in a disposable, network-
  observed container. A server that behaves differently under instrumentation
  has still told you something.
- **Remote (HTTP) servers cannot be observed at all.** Their definitions are
  fetched, scanned and pinned; their behaviour is taken on trust.

## False positives

Text rules carry a `confidence` separate from `severity`, and low-confidence
findings are review prompts, not verdicts. By default a build fails only on
`high`+ severity at `medium`+ confidence, so a lead never breaks anyone's CI.

Suppressions live in `skillcheck.config.json` and **must** carry a reason:

```json
{
  "failOn": "high",
  "failConfidence": "medium",
  "ignore": [
    {
      "rule": "hidden/instruction-override",
      "artifact": "skill:prompt-injection-docs",
      "reason": "Quoted attack examples in documentation. Reviewed 2026-03-11 by @you.",
      "expires": "2026-12-31"
    }
  ]
}
```

An entry with no reason is not applied. An expired entry stops applying. An
entry matching nothing is reported. A scanner accumulates unexplained
exceptions until it reports nothing, and that failure is invisible unless the
tool makes it visible.

If skillcheck flags your project wrongly, that is a bug — open an issue with the
artifact and the rule id.

## CI

```yaml
- uses: actions/setup-node@v4
  with: { node-version: '20' }
- run: npx skillcheck scan --format sarif --out skillcheck.sarif --fail-on never
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: skillcheck.sarif }
- run: npx skillcheck scan --fail-on high
```

Formats: `text`, `json`, `sarif`, `markdown` (PR comments), `html` (a
self-contained results page), `badge` (a shields.io endpoint payload — it says
`skillcheck (static)` or `skillcheck (probed)`, because a green badge that
silently means "static checks only" is worse than no badge).

Monitoring, on a schedule:

```jsonc
// skillcheck-sources.json
{ "sources": [
  { "name": "invoice-mcp", "type": "npm", "spec": "@example/invoice-mcp" },
  { "name": "hosted-skill", "type": "url", "spec": "https://example.com/skills/foo/SKILL.md" }
] }
```

```
npx skillcheck watch --sources skillcheck-sources.json --state skillcheck-registry.json
```

Commit the state file; the diff between runs *is* the alert.

## Commands

| command | purpose |
|---|---|
| `scan` | Scan installed skills and MCP servers. `--probe` adds behavioural differencing. |
| `pin` | Write `skillcheck.lock.json`. |
| `diff` | Show what changed since the pin, and in which files. |
| `watch` | Poll registry sources for republishes and publisher changes. |
| `rules` | List every rule, its severity and what it means. |
| `init` | Write a starter config. |

Exit codes: `0` clean, `1` findings at or above the threshold, `2` skillcheck
itself failed.

## Where artifacts are found

Skills: `.claude/skills`, `.agent/skills`, `./skills`, `~/.claude/skills`, and
plugin layouts under `~/.claude/plugins`. MCP servers: `.mcp.json`,
`.vscode/mcp.json`, `.cursor/mcp.json`, `~/.claude.json` (including per-project
blocks), and the Claude Desktop config on macOS, Linux and Windows. Extra paths
go in the config.

## Prior art

[Invariant's mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) covers
static MCP tool-poisoning detection and runtime proxying; Snyk and several
vendors ship scanners for the same file formats. skillcheck overlaps them on
static checks deliberately — those are table stakes. The parts that are not
table stakes are the declared-versus-observed diff, the two-surface hash that
names a rug pull specifically, and registry-wide monitoring across time.

## API

```js
import { scan, probeServers, computeSurfaces, compareSnapshots } from 'skillcheck';

const result = await scan({ cwd: process.cwd(), config, probe: true, probeTimeoutMs: 15000, probeOnly: [] });
```

Requires Node 20+. No runtime dependencies.

## License

MIT
