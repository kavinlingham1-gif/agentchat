import test from 'node:test';
import assert from 'node:assert/strict';
import {chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {agentApps, wireAgents} from '../lib/agents.mjs';

const CMD = '/Users/sam/.agentchat/bin/agentchat', ARGS = ['mcp'];
const freshHome = () => mkdtempSync(join(tmpdir(), 'agentchat-apps-'));
const support = home => join(home, 'Library', 'Application Support');
const put = (file, text, mode) => { mkdirSync(dirname(file), {recursive: true}); writeFileSync(file, text); if (mode) chmodSync(file, mode); return file; };
const json = file => JSON.parse(readFileSync(file, 'utf8'));
const modeOf = file => statSync(file).mode & 0o777;
const noClaude = {pathDirs: [], run: () => { throw new Error('the claude command should not run'); }};
const wire = (home, mode, extra = noClaude) => wireAgents({command: CMD, args: ARGS, mode, home, platform: 'darwin', env: {}, ...extra});
const statuses = results => results.map(r => [r.app, r.status]);

test("add puts Agentchat into every agent app found, in each app's own format, and touches nothing else", () => {
  const home = freshHome();
  const cursor = put(join(home, '.cursor', 'mcp.json'), JSON.stringify({mcpServers: {other: {command: 'x'}}}, null, 4));
  const claude = put(join(support(home), 'Claude', 'claude_desktop_config.json'), '{"globalShortcut": "Cmd+K"}', 0o600);
  const codex = put(join(home, '.codex', 'config.toml'), 'model = "gpt"\n');
  const vscode = put(join(support(home), 'Code', 'User', 'mcp.json'), '{\n  // my servers\n  "servers": {}\n}\n');
  const gemini = put(join(home, '.gemini', 'settings.json'), JSON.stringify({theme: 'dark'}));
  mkdirSync(join(home, '.codeium', 'windsurf'), {recursive: true});

  const results = wire(home, 'add');
  assert.deepEqual(statuses(results), [['Cursor', 'added'], ['Claude Desktop', 'added'], ['Codex', 'added'], ['Windsurf', 'added'], ['VS Code', 'skipped'], ['Gemini CLI', 'added']]);
  assert.deepEqual(json(cursor).mcpServers, {other: {command: 'x'}, agentchat: {command: CMD, args: ARGS}});
  assert.match(readFileSync(cursor, 'utf8'), /^ {4}"mcpServers"/m, "the file's indentation is kept");
  assert.deepEqual(json(claude), {globalShortcut: 'Cmd+K', mcpServers: {agentchat: {command: CMD, args: ARGS}}});
  if (process.platform !== 'win32') assert.deepEqual([modeOf(claude), modeOf(`${claude}.bak-agentchat`)], [0o600, 0o600], 'a private config and its backup stay private');
  assert.equal(readFileSync(codex, 'utf8'), `model = "gpt"\n\n[mcp_servers.agentchat]\ncommand = "${CMD}"\nargs = ["mcp"]\n`);
  assert.deepEqual(json(join(home, '.codeium', 'windsurf', 'mcp_config.json')).mcpServers.agentchat, {command: CMD, args: ARGS});
  assert.match(results.find(r => r.app === 'VS Code').note, /"type":"stdio"/);
  assert.doesNotMatch(readFileSync(vscode, 'utf8'), /agentchat/, 'a config with comments is left alone');
  assert.deepEqual(json(gemini), {theme: 'dark', mcpServers: {agentchat: {command: CMD, args: ARGS}}});
  assert.ok(results.filter(r => r.status === 'added').every(r => r.next), 'each wired app says what to do next');

  const before = readFileSync(cursor, 'utf8');
  assert.ok(wire(home, 'add').filter(r => r.app !== 'VS Code').every(r => r.status === 'unchanged'), 'running it again changes nothing');
  assert.equal(readFileSync(cursor, 'utf8'), before);

  assert.deepEqual(statuses(wire(home, 'remove')), [['Cursor', 'removed'], ['Claude Desktop', 'removed'], ['Codex', 'removed'], ['Windsurf', 'removed'], ['VS Code', 'skipped'], ['Gemini CLI', 'removed']]);
  assert.deepEqual(json(cursor).mcpServers, {other: {command: 'x'}});
  assert.equal(readFileSync(codex, 'utf8'), 'model = "gpt"\n');
});

test('refresh re-points only the entries that exist, keeps their other fields, and never replaces the first backup', () => {
  const home = freshHome();
  const original = JSON.stringify({mcpServers: {agentchat: {command: '/opt/homebrew/bin/node', args: ['/opt/homebrew/lib/node_modules/agentchat/bin/agentchat.js', 'mcp'], env: {A: '1'}}}});
  const cursor = put(join(home, '.cursor', 'mcp.json'), original, 0o640);
  put(join(support(home), 'Claude', 'claude_desktop_config.json'), '{}');
  put(join(home, '.codex', 'config.toml'), '');
  assert.deepEqual(statuses(wire(home, 'refresh')), [['Cursor', 'updated']], 'apps without Agentchat are not added on an update');
  assert.deepEqual(json(cursor).mcpServers.agentchat, {command: CMD, args: ARGS, env: {A: '1'}});
  if (process.platform !== 'win32') assert.deepEqual([modeOf(cursor), modeOf(`${cursor}.bak-agentchat`)], [0o640, 0o640]);
  wireAgents({command: '/somewhere/else', args: ARGS, mode: 'refresh', home, platform: 'darwin', env: {}, ...noClaude});
  assert.equal(readFileSync(`${cursor}.bak-agentchat`, 'utf8'), original, 'the backup is still the pre-Agentchat original');

  const empty = freshHome();
  put(join(empty, '.cursor', 'mcp.json'), '{}');
  assert.deepEqual(statuses(wire(empty, 'refresh')), [['Cursor', 'added']], 'with no entries anywhere yet, refresh adds them');
});

test('a symlinked config is updated through the link', {skip: process.platform === 'win32' && 'symlinks need Developer Mode on Windows'}, () => {
  const home = freshHome();
  const real = put(join(home, 'dotfiles', 'cursor-mcp.json'), '{"mcpServers": {}}');
  mkdirSync(join(home, '.cursor'));
  symlinkSync(real, join(home, '.cursor', 'mcp.json'));
  wire(home, 'add');
  assert.ok(lstatSync(join(home, '.cursor', 'mcp.json')).isSymbolicLink());
  assert.deepEqual(json(real).mcpServers.agentchat, {command: CMD, args: ARGS});
});

test('Codex: only an exact [mcp_servers.agentchat] table is edited or removed; any other mention of agentchat is left alone', () => {
  const home = freshHome();
  const codex = put(join(home, '.codex', 'config.toml'), 'model = "gpt"\n\n[mcp_servers.agentchat]\ncommand = "/old"\nargs = ["mcp"]\n\n[mcp_servers.agentchat.env]\nA = "1"\n\n# keep me\n[mcp_servers.other]\ncommand = "x"\n');
  assert.deepEqual(statuses(wire(home, 'refresh')), [['Codex', 'updated']]);
  assert.ok(readFileSync(codex, 'utf8').includes(`[mcp_servers.agentchat]\ncommand = "${CMD}"\nargs = ["mcp"]\n\n[mcp_servers.agentchat.env]\nA = "1"`));
  assert.deepEqual(statuses(wire(home, 'refresh')), [['Codex', 'unchanged']]);
  assert.deepEqual(statuses(wire(home, 'remove')), [['Codex', 'removed']]);
  assert.equal(readFileSync(codex, 'utf8'), 'model = "gpt"\n\n# keep me\n[mcp_servers.other]\ncommand = "x"\n', 'the table and its sub-tables go; the next table keeps its comment');

  const inline = freshHome();
  const text = '[mcp_servers]\nagentchat = { command = "/x", args = ["mcp"] }\n';
  const file = put(join(inline, '.codex', 'config.toml'), text);
  assert.deepEqual(statuses(wire(inline, 'add')), [['Codex', 'skipped']], 'a second definition would stop Codex from starting');
  assert.deepEqual(statuses(wire(inline, 'remove')), []);
  assert.equal(readFileSync(file, 'utf8'), text);

  const closed = freshHome();
  const servers = 'mcp_servers = { other = { command = "x" } }\n';
  const config = put(join(closed, '.codex', 'config.toml'), servers);
  const skipped = wire(closed, 'add');
  assert.deepEqual(statuses(skipped), [['Codex', 'skipped']], 'an inline mcp_servers table cannot be extended with a [mcp_servers.agentchat] header');
  assert.match(skipped[0].note, /inside it yourself/);
  assert.equal(readFileSync(config, 'utf8'), servers);
});

test('Claude Code is changed only through the claude command, never by editing ~/.claude.json', () => {
  const home = freshHome(), calls = [];
  const bin = put(join(home, '.local', 'bin', 'claude'), '', 0o755);
  const state = JSON.stringify({mcpServers: {agentchat: {type: 'stdio', command: '/old', args: ['mcp'], env: {}}}, numStartups: 9});
  put(join(home, '.claude.json'), state);
  const run = (file, args) => { calls.push([file, ...args]); return {status: 0}; };
  assert.deepEqual(statuses(wire(home, 'refresh', {pathDirs: [], run})), [['Claude Code', 'updated']]);
  const slashes = list => list.map(call => call.map(part => part.replace(/\\/g, '/')));
  assert.deepEqual(slashes(calls), slashes([[bin, 'mcp', 'remove', '-s', 'user', 'agentchat'], [bin, 'mcp', 'add', '-s', 'user', 'agentchat', '--', CMD, 'mcp']]));
  assert.equal(readFileSync(join(home, '.claude.json'), 'utf8'), state);
  calls.length = 0;
  assert.deepEqual(statuses(wire(home, 'remove', {pathDirs: [], run})), [['Claude Code', 'removed']]);
  assert.deepEqual(slashes(calls), slashes([[bin, 'mcp', 'remove', '-s', 'user', 'agentchat']]));
  const failing = wire(home, 'add', {pathDirs: [], run: () => ({status: 1})});
  assert.equal(failing[0].status, 'skipped');
  assert.match(failing[0].note, /claude mcp remove -s user agentchat/);
  assert.equal(existsSync(join(home, '.claude.json.bak-agentchat')), false);
});

test('each OS keeps its agent configs in its own places', () => {
  const win = Object.fromEntries(agentApps('C:\\Users\\Sam', {platform: 'win32', env: {APPDATA: 'C:\\Users\\Sam\\AppData\\Roaming'}}).filter(a => a.file).map(a => [a.name, a.file]));
  assert.equal(win['Claude Desktop'], 'C:\\Users\\Sam\\AppData\\Roaming\\Claude\\claude_desktop_config.json');
  assert.equal(win['VS Code'], 'C:\\Users\\Sam\\AppData\\Roaming\\Code\\User\\mcp.json');
  assert.equal(win.Cursor, 'C:\\Users\\Sam\\.cursor\\mcp.json');
  const linux = agentApps('/home/sam', {platform: 'linux', env: {}});
  assert.equal(linux.some(a => a.name === 'Claude Desktop'), false, 'there is no Claude Desktop for Linux');
  assert.equal(linux.find(a => a.name === 'VS Code').file, '/home/sam/.config/Code/User/mcp.json');
  assert.equal(linux.find(a => a.name === 'Codex').file, '/home/sam/.codex/config.toml');
});
