# skillcheck

Continuous security scanning for agent skills and MCP servers.

See it work end to end — `bash examples/demo.sh` — on a benign local server
carrying one planted zero-width space.

```
npx skillcheck                  # scan what is installed
npx skillcheck pin              # record hashes of what you reviewed
npx skillcheck scan --probe     # launch each server, compare behaviour to its claims
npx skillcheck scan --invoke    # also call its tools, with decoy credentials planted
npx skillcheck bench            # measure the scanner's false positive rate
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

**Active probing with planted decoys (`--invoke`).** A server that behaves
during startup and steals during a tool call is invisible to a passive probe, so
`--invoke` calls the tools as well. Every probe — passive or active — runs with
a disposable home directory seeded with uniquely-tokened decoy credentials in
`~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.npmrc`, `~/.env` and the agent's own
credential file, plus decoy values for `GITHUB_TOKEN` and friends.

The shim then watches for those exact tokens on every outbound `write()` —
*before* TLS encrypts anything — and in every tool result. That turns a vague
question into a factual one:

```
CRITICAL Server transmitted a planted credential to a remote destination
  evidence   ~/.aws/credentials -> collector.invalid/ingest during "call:lookup"
  why        A decoy credential was written into an outbound connection. The check runs
             before encryption, so TLS does not conceal it, and the value exists nowhere
             except the sandbox this probe created.

CRITICAL Tool "describe" returned a planted credential in its result
  why        The tool read a credential and handed it back to the agent, which places it in
             the model context where any later instruction can forward it.
```

The decoys are never real secrets, so this is safe to run against a hostile
server. Their values are shaped like the credential they replace (`ghp_…`,
`AKIA…`) with no `skillcheck` marker, and the shim deletes the token list from
the environment before the server runs, so a server cannot detect the probe by
searching for its own bait.

**All four model-visible MCP surfaces, not just tools.** A probe enumerates
`prompts/list` and `resources/list` alongside `tools/list`, renders argument-free
prompts and reads resource contents, and — under `--invoke` — scans every tool
result. A prompt template is injected into the context verbatim when selected;
resource contents and tool outputs reach it too. All four now run under the same
rule set. Static definitions (tool, prompt, resource) are pinned; dynamic
outputs (results, resource contents) are scanned but never pinned, since they
change per call. Which tools get called is decided fail-closed: a tool is invoked only
when `readOnlyHint: true`, never merely because it failed to look dangerous, and
tools with no annotations at all are skipped and reported as unmeasured.
`--invoke` is **refused outside a container** unless you pass
`--allow-unsandboxed`.

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

**Continuous registry monitoring (`skillcheck watch` / `discover`).** `discover`
builds the source list from an npm search (`keywords:mcp-server`) rather than by
hand; `watch` polls and diffs snapshots. The high-value signals are not in any
single scan: a *republished version* (content hash of an existing version changed
— critical), a *dropped provenance attestation* (a release built outside the
pipeline that signed the last one — high), a *new install-time script*
(`postinstall` runs before any review — high), a *publisher added* to an
established package (high), a *new dependency* (supply chain one level down —
medium), an unpublish, a deprecation.

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
- **The probe is an observer, not a sandbox.** It records; it blocks nothing,
  and a server that wants to evade it can. The decoy home limits what a probe
  can *lose*, not what a server can *do* — it is bait, not isolation. Run probes
  in a disposable, network-observed container; `--invoke` insists on one. A
  server that behaves differently under instrumentation has still told you
  something.
- **`--invoke` reaches one call deep.** Tools are called once, with the minimal
  arguments their schema accepts. Behaviour that only appears on a specific
  argument, a second call, or after a delay is not exercised. Tools without
  `readOnlyHint` are not called at all.
- **Remote (HTTP) servers cannot be observed at all.** Their definitions are
  fetched, scanned and pinned; their behaviour is taken on trust.

## False positives, measured

An unmeasured false positive rate is indistinguishable from a bad one, so it is
a number here rather than a claim. `skillcheck bench` runs the rules over a
corpus of skills you trust and counts anything that fires:

```
npx skillcheck bench                                   # the bundled benign corpus
npx skillcheck bench --corpus ~/.claude/skills         # your own installed skills
npx skillcheck bench --corpus ./corpus --max-fp 3      # fail CI above a budget
```

`corpus/benign/` holds ten realistic skills chosen to stress the patterns that
break naive scanners: security documentation quoting attack strings, a deploy
skill that legitimately uses `~/.ssh`, an i18n skill containing real
bidirectional marks, a fixture file with an embedded base64 PNG, an `.env`
manager, wildcard `git`/`curl` grants.

The first run over that corpus produced **15 findings across 6 of 10 skills**,
every one a false positive; then, run against the 19 real skills in
`anthropics/skills` (which I did not write), **4 more across 2 skills** — two
rules that fired on `curl` in documentation and on any skill that merely
mentioned the network. They were fixed by principle, not by exception:

| pattern | fix |
|---|---|
| security docs quoting attack strings | matches inside code fences, inline code and blockquotes are skipped; an artifact whose *user-visible* description identifies it as security material drops to low confidence |
| `~/.ssh` in a deploy skill | a capability the description **discloses** drops to low confidence; an undisclosed one stays high. This is the two-surface model doing its actual job |
| editorial HTML comments | the comment must address the agent, not a human maintainer |
| bidirectional marks in RTL text | LRM/RLM beside right-to-left script is typography; zero-width and tag characters stay critical |
| embedded `data:image/png;base64,` | a self-describing data URI declares its own contents; opaque blobs still count |

Both were fixed by principle: the shell-exfiltration rule now matches only in
fenced code, in command position, with a substitution that actually reads local
data (`$(cat …)`, not `?id=$X`); and the network/shell surface-mismatch probes
were deleted after measurement showed they carried no signal on real skills.

Current rate: **0 findings at build-failing confidence** across all three
corpora — my 10, the 19 real ones, and the detection fixture (whose 8 planted
findings all still fire). Twenty-nine real skills is still small; point `bench`
at your own directory, and open an issue if something fires wrongly.

The reverse regression matters just as much. `bench` reads an optional
`expected.json` mapping a skill to the rules that *must* fire for it, and reports
any that stopped. The detection fixture in `test/fixtures/` carries one, so
tuning for false positives cannot quietly blind a rule — that guard runs in CI.

One trade is explicit: an artifact that claims to be security material in the
surface a human reads buys a lower alarm level for quoted attack strings. That
claim is visible on the listing page, which is exactly where a reviewer is
positioned to judge it.

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
| `scan` | Scan installed skills and MCP servers. `--probe` adds behavioural differencing; `--invoke` adds active probing with decoys. |
| `pin` | Write `skillcheck.lock.json`. |
| `diff` | Show what changed since the pin, and in which files. |
| `watch` | Poll registry sources for republishes, provenance loss, install scripts and publisher changes. |
| `discover` | Build a watch source list from an npm registry search. |
| `bench` | Measure false positives against a corpus of trusted skills. |
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
