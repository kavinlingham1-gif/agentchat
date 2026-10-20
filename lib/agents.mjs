import {spawnSync} from 'node:child_process';
import {chmodSync, copyFileSync, existsSync, readFileSync, realpathSync, renameSync, statSync, writeFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {delimiter, posix, win32} from 'node:path';

export function agentApps(home = homedir(), {platform = process.platform, env = process.env} = {}) {
  const {join} = platform === 'win32' ? win32 : posix;
  const config = platform === 'darwin' ? join(home, 'Library', 'Application Support') : platform === 'win32' ? env.APPDATA || join(home, 'AppData', 'Roaming') : join(home, '.config');
  return [
    {name: 'Cursor', dir: join(home, '.cursor'), file: join(home, '.cursor', 'mcp.json'), key: 'mcpServers', next: 'turn it on under Cursor Settings → MCP if it is off'},
    ...(platform === 'linux' ? [] : [{name: 'Claude Desktop', dir: join(config, 'Claude'), file: join(config, 'Claude', 'claude_desktop_config.json'), key: 'mcpServers', next: 'quit and reopen Claude Desktop'}]),
    {name: 'Claude Code', cli: 'claude', next: 'new Claude Code sessions have it'},
    {name: 'Codex', dir: join(home, '.codex'), file: join(home, '.codex', 'config.toml'), toml: true, next: 'new Codex sessions have it'},
    {name: 'Windsurf', dir: join(home, '.codeium', 'windsurf'), file: join(home, '.codeium', 'windsurf', 'mcp_config.json'), key: 'mcpServers', next: 'refresh MCP servers in Windsurf'},
    {name: 'VS Code', dir: join(config, 'Code', 'User'), file: join(config, 'Code', 'User', 'mcp.json'), key: 'servers', type: 'stdio', next: "start agentchat from VS Code's MCP server list"},
    {name: 'Gemini CLI', dir: join(home, '.gemini'), file: join(home, '.gemini', 'settings.json'), key: 'mcpServers', next: 'new Gemini CLI sessions have it'},
  ];
}

const sameArgs = (a, b) => JSON.stringify(a ?? []) === JSON.stringify(b ?? []);
const runCli = (file, args) => spawnSync(file, args, {stdio: ['ignore', 'pipe', 'pipe'], timeout: 20000, encoding: 'utf8'});

// Dotfile managers often symlink these configs, and they can hold API keys, so writes go through the link and keep the file's mode; the first backup is the pre-Agentchat original and is never replaced.
function save(file, text) {
  const target = existsSync(file) ? realpathSync(file) : file;
  const mode = existsSync(target) ? statSync(target).mode & 0o777 : 0o600;
  if (existsSync(target) && !existsSync(`${target}.bak-agentchat`)) {
    copyFileSync(target, `${target}.bak-agentchat`);
    chmodSync(`${target}.bak-agentchat`, mode);
  }
  const temp = `${target}.agentchat-${process.pid}`;
  writeFileSync(temp, text, {mode});
  chmodSync(temp, mode);
  renameSync(temp, target);
}

function jsonApp(app, {command, args, mode}) {
  const text = existsSync(app.file) ? readFileSync(app.file, 'utf8') : '';
  let config;
  try { config = text.trim() ? JSON.parse(text) : {}; } catch { config = null; }
  const servers = config?.[app.key] ?? {};
  if (!config || typeof config !== 'object' || Array.isArray(config) || typeof servers !== 'object' || Array.isArray(servers)) {
    return {status: 'skipped', note: `couldn't read ${app.file} (comments?); add this under "${app.key}" yourself: "agentchat": ${JSON.stringify({...(app.type ? {type: app.type} : {}), command, args})}`};
  }
  const current = servers.agentchat;
  if (mode === 'remove') {
    if (!current) return null;
    delete servers.agentchat;
  } else {
    if (!current && mode === 'refresh') return null;
    if (current && current.command === command && sameArgs(current.args, args) && (!app.type || current.type === app.type)) return {status: 'unchanged'};
    config[app.key] = {...servers, agentchat: {...current, ...(app.type ? {type: app.type} : {}), command, args}};
  }
  save(app.file, `${JSON.stringify(config, null, /^([ \t]+)"/m.exec(text)?.[1] ?? 2)}\n`);
  return {status: mode === 'remove' ? 'removed' : current ? 'updated' : 'added'};
}

// Codex refuses to start on a duplicate key, so only an exact [mcp_servers.agentchat] table is ever edited, and a file that names agentchat any other way is left alone.
function codexApp(app, {command, args, mode}) {
  const text = existsSync(app.file) ? readFileSync(app.file, 'utf8') : '';
  const lines = text.split('\n');
  const header = /^\[mcp_servers\.agentchat\][ \t]*(#.*)?$/;
  const start = lines.findIndex(l => header.test(l));
  const tableEnd = from => { let i = from + 1; while (i < lines.length && !/^\s*\[/.test(lines[i])) i++; return i; };
  const ownEnd = from => { let i = tableEnd(from); while (i > from + 1 && /^\s*(#.*)?$/.test(lines[i - 1])) i--; return i; };
  const body = [`command = ${JSON.stringify(command)}`, `args = ${JSON.stringify(args)}`];
  if (start < 0) {
    if (/agentchat/.test(text)) return mode === 'remove' || mode === 'refresh' ? null : {status: 'skipped', note: `${app.file} already mentions agentchat outside an [mcp_servers.agentchat] table; check it by hand`};
    if (mode === 'add' && /^\s*mcp_servers\s*=/m.test(text)) return {status: 'skipped', note: `${app.file} defines mcp_servers as an inline table, which can't take another entry; add agentchat = { command = ${JSON.stringify(command)}, args = ${JSON.stringify(args)} } inside it yourself`};
    if (mode !== 'add') return null;
    save(app.file, `${text}${text && !text.endsWith('\n') ? '\n' : ''}${text.trim() ? '\n' : ''}[mcp_servers.agentchat]\n${body.join('\n')}\n`);
    return {status: 'added'};
  }
  const end = tableEnd(start);
  if (mode === 'remove') {
    const drop = new Set();
    for (let i = 0; i < lines.length; i++) {
      if (i === start || /^\[mcp_servers\.agentchat\.[^\]]+\][ \t]*(#.*)?$/.test(lines[i])) for (let j = i; j < ownEnd(i); j++) drop.add(j);
    }
    save(app.file, lines.filter((_, i) => !drop.has(i)).join('\n').replace(/\n{3,}/g, '\n\n').replace(/^\n+/, '').replace(/\n+$/, '\n'));
    return {status: 'removed'};
  }
  const table = lines.slice(start + 1, end);
  if (table.some(l => /^\s*(command|args)\s*=/.test(l) && /("""|'''|\[\s*$)/.test(l))) return {status: 'skipped', note: `the [mcp_servers.agentchat] table in ${app.file} is multi-line; set command = ${JSON.stringify(command)} yourself`};
  const kept = table.filter(l => !/^\s*(command|args)\s*=/.test(l));
  if (table.length === kept.length + 2 && table.some(l => l.trim() === body[0]) && table.some(l => l.trim() === body[1])) return {status: 'unchanged'};
  save(app.file, [...lines.slice(0, start + 1), ...body, ...kept, ...lines.slice(end)].join('\n'));
  return {status: 'updated'};
}

// ~/.claude.json is rewritten constantly by Claude Code itself, so it is only ever read here; changes go through the claude command.
function claudeApp(app, {command, args, mode, home, pathDirs, run, platform}) {
  const {join} = platform === 'win32' ? win32 : posix;
  // On Windows claude is a .cmd shim, which can't be started safely without a shell, so the command is printed instead.
  if (platform === 'win32') return pathDirs.some(dir => existsSync(join(dir, 'claude.cmd')) || existsSync(join(dir, 'claude.exe'))) && mode === 'add' ? {status: 'skipped', note: `run: claude mcp add -s user agentchat -- ${[command, ...args].map(a => (/\s/.test(a) ? `"${a}"` : a)).join(' ')}`} : null;
  const cli = [...pathDirs.map(dir => join(dir, 'claude')), join(home, '.local', 'bin', 'claude')].find(existsSync);
  if (!cli) return undefined;
  let current;
  try { current = JSON.parse(readFileSync(join(home, '.claude.json'), 'utf8')).mcpServers?.agentchat; } catch {}
  if (mode !== 'add' && !current) return null;
  if (mode !== 'remove' && current?.command === command && sameArgs(current.args, args)) return {status: 'unchanged'};
  const ok = result => result?.status === 0;
  if (current && !ok(run(cli, ['mcp', 'remove', '-s', 'user', 'agentchat']))) return {status: 'skipped', note: 'the claude command could not remove the old entry; run: claude mcp remove -s user agentchat'};
  if (mode === 'remove') return {status: 'removed'};
  if (!ok(run(cli, ['mcp', 'add', '-s', 'user', 'agentchat', '--', command, ...args]))) return {status: 'skipped', note: `the claude command failed; run: claude mcp add -s user agentchat -- ${[command, ...args].map(a => JSON.stringify(a)).join(' ')}`};
  return {status: current ? 'updated' : 'added'};
}

/**
 * add: every app found gets an entry. refresh: re-point the entries that exist, or add everywhere if none do yet. remove: delete them.
 * Returns one result per app that has (or had) Agentchat or needs attention: {app, status: added|updated|unchanged|removed|skipped, next?, note?}.
 */
export function wireAgents({command, args, mode = 'add', home = homedir(), platform = process.platform, env = process.env, pathDirs = [...(env.PATH ?? env.Path ?? '').split(platform === 'win32' ? ';' : delimiter).filter(Boolean), ...(platform === 'darwin' ? ['/opt/homebrew/bin', '/usr/local/bin'] : [])], run = runCli}) {
  const once = m => agentApps(home, {platform, env}).flatMap(app => {
    if (!app.cli && !existsSync(app.dir)) return [];
    let result;
    try { result = app.cli ? claudeApp(app, {command, args, mode: m, home, pathDirs, run, platform}) : app.toml ? codexApp(app, {command, args, mode: m}) : jsonApp(app, {command, args, mode: m}); } catch (error) { result = {status: 'skipped', note: `couldn't update it: ${error.message}`}; }
    return result ? [{app: app.name, ...result, ...(['added', 'updated'].includes(result.status) ? {next: app.next} : {})}] : [];
  });
  const results = once(mode);
  return mode === 'refresh' && !results.some(r => r.status !== 'skipped') ? once('add') : results;
}
