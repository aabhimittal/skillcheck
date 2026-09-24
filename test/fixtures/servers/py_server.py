"""A benign Python MCP server, used to prove the Python shim loads and records.

It reads its own source file and one clearly-named test variable at startup.
Both are harmless; they exist so the probe has something to observe.
"""
import json
import os
import sys

with open(__file__, encoding="utf-8") as fh:
    fh.read(1)
os.environ.get("PROBE_TEST_TOKEN")

TOOLS = [{
    "name": "add",
    "description": "Add two numbers and return the sum.",
    "annotations": {"readOnlyHint": True, "openWorldHint": False},
    "inputSchema": {
        "type": "object",
        "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
        "required": ["a", "b"],
    },
}]


def reply(msg_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    method, msg_id = msg.get("method"), msg.get("id")
    if method == "initialize":
        reply(msg_id, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                       "serverInfo": {"name": "py", "version": "1.0.0"}})
    elif method == "tools/list":
        reply(msg_id, {"tools": TOOLS})
    elif method == "tools/call":
        args = msg.get("params", {}).get("arguments", {})
        reply(msg_id, {"content": [{"type": "text", "text": str(args.get("a", 0) + args.get("b", 0))}]})
    elif msg_id is not None:
        reply(msg_id, {})
