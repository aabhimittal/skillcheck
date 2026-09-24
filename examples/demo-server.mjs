/**
 * skillcheck demo server: a small MCP server exposing all four model-visible
 * surfaces -- a tool definition, a tool result, a prompt template and resource
 * contents.
 *
 * It is inert. The only thing to find is a single zero-width space (U+200B) in
 * the prompt template and in the tool's result, written below as an escape so
 * it is visible when reading this file. Before skillcheck scanned prompts,
 * resources and tool outputs, both were invisible to it.
 *
 *   node dist/cli.js scan --cwd examples --invoke --allow-unsandboxed
 */
const ZWSP = '​';

const TOOLS = [{
  name: 'lookup',
  description: 'Look up a record by id. Read-only.',
  annotations: { readOnlyHint: true, openWorldHint: false },
  inputSchema: { type: 'object', properties: { id: { type: 'string', description: 'Record id.' } }, required: ['id'] },
}];

const PROMPTS = [{ name: 'summarise', description: 'Summarise the current document.' }];

const RESOURCES = [
  { uri: 'notes://readme', name: 'readme', description: 'Project readme.', mimeType: 'text/plain' },
  { uri: 'notes://changelog', name: 'changelog', description: 'Release notes.', mimeType: 'text/plain' },
];

const CONTENTS = {
  'notes://readme': 'A demo project. Nothing to see here.',
  'notes://changelog': '1.0.0 - first release.',
};

function handle(msg) {
  const p = msg.params ?? {};
  switch (msg.method) {
    case 'initialize':
      return { protocolVersion: '2025-06-18', capabilities: { tools: {}, prompts: {}, resources: {} }, serverInfo: { name: 'demo', version: '1.0.0' } };
    case 'tools/list': return { tools: TOOLS };
    case 'tools/call': return { content: [{ type: 'text', text: `record${ZWSP} not found` }] };
    case 'prompts/list': return { prompts: PROMPTS };
    case 'prompts/get':
      return { messages: [{ role: 'user', content: { type: 'text', text: `Summarise${ZWSP} the document in three bullet points.` } }] };
    case 'resources/list': return { resources: RESOURCES };
    case 'resources/read':
      return { contents: [{ uri: p.uri, mimeType: 'text/plain', text: CONTENTS[p.uri] ?? '' }] };
    default: return {};
  }
}

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
    if (msg.id !== undefined) process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: handle(msg) }) + '\n');
  }
});
