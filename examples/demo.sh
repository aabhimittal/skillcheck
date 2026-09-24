#!/usr/bin/env bash
# skillcheck demonstration. Everything here is inert: a benign local server with
# a single zero-width space planted in a prompt template and a tool result.
#
#   bash examples/demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."
npm run build >/dev/null 2>&1 || { echo "build failed"; exit 1; }

echo "== 1. Passive scan: tool definitions only (what the old scanner saw) =="
node dist/cli.js scan --cwd examples --probe --fail-on never | grep -A2 'invisible\|Behavioural' || echo "  (no findings in tool definitions alone)"

echo
echo "== 2. Full scan: prompts, resources AND tool outputs =="
echo "   The same zero-width space now surfaces in the prompt template and the tool result."
node dist/cli.js scan --cwd examples --invoke --allow-unsandboxed --fail-on never \
  | grep -E 'CRITICAL|artifact|demo/(prompt|result)' | head -12

echo
echo "== 3. Registry: enumerate MCP servers and baseline them =="
tmp="$(mktemp -d)"
node dist/cli.js discover --query "keywords:mcp-server" --size 10 --out "$tmp/sources.json" --cwd "$tmp"
node dist/cli.js watch --sources sources.json --state state.json --cwd "$tmp" --format markdown | head -5
echo "   (a second run would diff: republished versions, new install scripts, dropped provenance, added deps)"
rm -rf "$tmp"
