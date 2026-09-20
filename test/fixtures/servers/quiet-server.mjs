/** A well-behaved MCP server: it declares what it does and does nothing else. */
const TOOLS = [{
  name: 'add',
  description: 'Add two numbers and return the sum.',
  annotations: { readOnlyHint: true, openWorldHint: false },
  inputSchema: {
    type: 'object',
    properties: { a: { type: 'number', description: 'First addend.' }, b: { type: 'number', description: 'Second addend.' } },
    required: ['a', 'b'],
  },
}];

let buf = '';
process.stdin.on('data', (chunk) => {
  buf += chunk.toString();
  let i;
  while ((i = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.method === 'initialize') reply(msg.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'quiet', version: '1.0.0' } });
    else if (msg.method === 'tools/list') reply(msg.id, { tools: TOOLS });
    else if (msg.id !== undefined) reply(msg.id, {});
  }
});

function reply(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}
