#!/usr/bin/env node
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 13)) {
  console.error(`Agentchat needs Node 22.13 or newer; this computer has ${process.version}.`);
  process.exit(1);
}

const {spawnSync} = await import('node:child_process');
const {createHash} = await import('node:crypto');
const {existsSync, readFileSync} = await import('node:fs');
const {delimiter, dirname, join: joinPath} = await import('node:path');
const {fileURLToPath} = await import('node:url');
const {alertsText, createNode, wiring, Problem, VERSION} = await import('../lib/node.mjs');
const {callTool, mcpServer} = await import('../lib/tools.mjs');
const {wireAgents} = await import('../lib/agents.mjs');
const {addToProfile, installApp, installRoot, runInstalled, withInstallLock, writeLauncher} = await import('../lib/install.mjs');
const {RELEASE_KEYS} = await import('../lib/release.mjs');
const {defaultHome} = await import('../lib/store.mjs');
const {decodeInvite} = await import('../lib/wire.mjs');

const [command, ...rest] = process.argv.slice(2);
const flags = {}, args = [];
for (let i = 0; i < rest.length; i++) {
  if (!rest[i].startsWith('--')) args.push(rest[i]);
  else flags[rest[i].slice(2)] = rest[i + 1] && !rest[i + 1].startsWith('--') ? rest[++i] : true;
}

const USAGE = `agentchat ${VERSION}: end-to-end encrypted chat between people's agents

  agentchat join <invite> [--as handle] [--agent]  set up this computer from an invite; --agent makes a Mac approve with a software key (for always-on agents)
  agentchat invite [--for handle]         invite someone; prints the message to send them
  agentchat approvals                     what is waiting for you
  agentchat approve <id> [--deny]         approve or deny a contact request
  agentchat verify <handle> [--confirm]   show your safety number; --confirm marks it verified
  agentchat wiring [--print | --remove]   connect your agent apps (Cursor, Claude, Codex, VS Code...); --print shows the config and Grok Bot steps
  agentchat notify [<webhook URL> | off]  alert your agent when messages arrive (key via prompt or stdin)
  agentchat update [--check | off | on]   install the newest signed release now, show it, or turn automatic updates off/on
  agentchat leave                         delete your handle and this computer's Agentchat keys
  agentchat mcp                           MCP server over stdio, for agents
  agentchat call <tool> ['<json>' | -]    run one agent tool and print JSON; - reads the JSON from stdin
  agentchat version                       print the installed version

On a Mac, approvals use Touch ID. On Linux, Windows or a Mac set up with --agent they use a software key, and contacts see that.
First computer on a new relay: agentchat join --owner <handle> --relay <url> [--package-sha <sha256>]`;

function showWiring() {
  const connect = wiring();
  console.log(`\nConnect your agents\n\nCursor (~/.cursor/mcp.json) or Claude Desktop (claude_desktop_config.json):\n${JSON.stringify(connect.mcp, null, 2)}\n\nGrok Bot: set up a routine that Agentchat alerts when messages arrive\n\n${connect.grok}`);
  if (connect.warning) console.log(`\nNote: ${connect.warning}`);
}

function connectAgents(mode) {
  const {command, args, warning} = wiring();
  const results = wireAgents({command, args, mode});
  const wired = results.filter(r => ['added', 'updated', 'unchanged'].includes(r.status));
  if (mode === 'remove') console.log(results.some(r => r.status === 'removed') ? `Removed Agentchat from ${results.filter(r => r.status === 'removed').map(r => r.app).join(', ')}.` : 'No agent app had Agentchat set up.');
  else console.log(wired.length ? `\nYour agents can use Agentchat in: ${wired.map(r => r.app).join(', ')}.` : '\nNo agent apps found to connect. agentchat wiring --print shows the config to add by hand.');
  for (const r of results) if (r.next || r.note) console.log(`  ${r.app}: ${r.next ?? r.note}`);
  if (mode !== 'remove') console.log(`Grok Bot or other webhook agents: agentchat wiring --print. Undo: agentchat wiring --remove${warning ? `\nNote: ${warning}` : ''}`);
}

async function readStdin() {
  let data = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

async function readSecret(prompt) {
  if (!process.stdin.isTTY) return (await readStdin()).trim() || undefined;
  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.setEncoding('utf8');
  process.stdin.resume();
  return new Promise(resolve => {
    let value = '';
    const onData = chunk => {
      for (const ch of chunk) {
        if (ch === '\u0003') { process.stdout.write('\n'); process.exit(130); }
        if (ch !== '\r' && ch !== '\n') { value = ch === '\u007f' ? value.slice(0, -1) : value + ch; continue; }
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.off('data', onData);
        process.stdout.write('\n');
        return resolve(value.trim() || undefined);
      }
    };
    process.stdin.on('data', onData);
  });
}

const testResult = last => !last ? 'not sent (an alert was already waiting)' : last.skipped ? `skipped (${last.skipped})` : last.status >= 200 && last.status < 300 ? `HTTP ${last.status}; your agent should run within a minute (check with: agentchat notify)` : `failed (${last.status ? `HTTP ${last.status}` : last.error}); check the webhook URL and key`;

const updateText = r => ({
  'not-installer': "This copy wasn't installed by the Agentchat line (it came from npm or a source checkout), so it can't update itself. Paste the install line again to switch.",
  none: `No signed release is published yet; this is Agentchat ${r.installed}.`,
  current: `Agentchat ${r.installed} is up to date.`,
  available: `Agentchat ${r.version} is available, signed by @${r.signer}. Run agentchat update to install it.`,
  updated: `Updated to Agentchat ${r.version}. Agents pick it up the next time they start Agentchat.`,
  busy: 'Another update is already running.',
  failed: r.installed !== r.was ? `Agentchat ${r.installed} is installed, but its final setup step failed: ${r.error}` : `The update failed: ${r.error}. Nothing changed; this is still Agentchat ${r.installed}.`,
})[r.status];

try {
  switch (command) {
    case 'mcp': {
      const node = await createNode();
      const {McpServer} = await import('@modelcontextprotocol/server');
      const {serveStdio} = await import('@modelcontextprotocol/server/stdio');
      serveStdio(() => mcpServer(node, McpServer));
      break;
    }
    case 'call': {
      // Only an explicit "-" reads stdin, so a runner that leaves stdin open can't hang `call check_inbox`.
      const raw = args[1] === '-' ? (await readStdin()).replace(/^\uFEFF/, '') : args[1];
      let input;
      try { input = raw ? JSON.parse(raw) : {}; } catch { throw new Problem(`The tool argument must be JSON, like '{"thread":"abc"}', or - to read it from stdin.`); }
      const out = JSON.stringify(await callTool(await createNode(), args[0], input), null, 2);
      // Windows PowerShell decodes captured output with the console code page, so anything outside ASCII goes out as \u escapes.
      console.log(process.platform === 'win32' ? out.replace(/[\u007f-\uffff]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`) : out);
      break;
    }
    case 'install': {
      // Run by install.sh or install.ps1 from the unpacked package, with the pinned Node.
      const root = installRoot(), pkgDir = fileURLToPath(new URL('..', import.meta.url));
      const tarball = joinPath(dirname(pkgDir), `agentchat-${VERSION}.tgz`);
      const placed = await withInstallLock(root, async () => { installApp(root, pkgDir, VERSION); return writeLauncher(root, {node: process.execPath, version: VERSION}); });
      if (!placed.inUse) console.log(`Agentchat ${placed.current.version} is already installed, so this older ${VERSION} package was left unused.`);
      // An automatic update leaves PATH alone, so a PATH block someone removed stays removed.
      const profile = process.platform === 'win32' || flags.update ? null : addToProfile();
      const target = placed.inUse ? {node: process.execPath, script: joinPath(root, 'app', VERSION, 'bin', 'agentchat.js')} : placed.current;
      // Invites send friends this tarball's fingerprint, so it is recorded only when this package is the one that runs.
      const sha = placed.inUse && existsSync(tarball) ? createHash('sha256').update(readFileSync(tarball)).digest('hex') : null;
      const joined = runInstalled(target, ['join', ...rest, ...(sha ? ['--package-sha', sha, '--package-version', VERSION] : [])]);
      if (joined.status !== 0) {
        if (!flags.update) console.error('\nSetup stopped before finishing. Fix what it says above (for example, pick another name with --as), then paste the same line again.');
        process.exitCode = joined.status ?? 1;
        break;
      }
      if (flags.update) break;
      console.log(`\nUpdates come from @${RELEASE_KEYS[0].handle}'s signed releases; agentchat update off stops them.`);
      if (!(process.env.PATH ?? '').split(delimiter).includes(joinPath(root, 'bin'))) console.log(profile || process.platform === 'win32' ? 'Open a new terminal window to use the agentchat command.' : `Add ${joinPath(root, 'bin')} to your PATH to use the agentchat command.`);
      break;
    }
    case 'join': {
      // The installer runs `join` after every install; with no invite and no data yet, nothing is created, not even a Keychain item.
      const installed = `Agentchat ${VERSION} is installed. To join, paste the line from your invite.`;
      if (!flags.owner && !args[0] && !existsSync(joinPath(defaultHome(), 'node.db'))) { console.log(installed); break; }
      const node = await createNode({agent: flags.agent === true}), cfg = node.config(), sha = typeof flags['package-sha'] === 'string' ? flags['package-sha'] : undefined;
      if (!flags.owner && !args[0] && !cfg.handle) { console.log(installed); break; }
      if (!flags.owner && cfg.handle) {
        const me = await node.afterInstall({packageSha: sha, packageVersion: flags['package-version']});
        console.log(`Agentchat ${VERSION} is set up for ${me.handle}.`);
        const inviter = args[0] && decodeInvite(args[0])?.i;
        if (inviter && inviter !== cfg.handle && !me.contacts.some(c => c.handle === `@${inviter}` && c.status === 'connected')) console.log(`You're already ${me.handle}, so this invite wasn't used. To connect with @${inviter}, have your agent add_contact @${inviter}.`);
        // An automatic update leaves agent configs alone: the launcher they point at never moves, and entries someone removed stay removed.
        if (!flags.update) connectAgents('refresh');
        break;
      }
      const joined = flags.owner ? await node.joinOwner({handle: flags.owner, relay: flags.relay, packageSha: sha}) : await node.join(args[0], {as: flags.as});
      if (joined.updated) { console.log(joined.updated); break; }
      console.log(`You're ${joined.handle}${joined.connected_to ? `, connected to ${joined.connected_to} (keys verified through the invite)` : ''}.\nYour fingerprint: ${joined.fingerprint}\nApprovals here use: ${joined.approvals_by}${joined.pending ? `\n${joined.pending}` : ''}`);
      connectAgents('add');
      break;
    }
    case 'update': {
      if (!existsSync(joinPath(defaultHome(), 'node.db'))) { console.log('Nothing to update yet: join first with the line from your invite.'); break; }
      const node = await createNode({autoUpdate: null});
      if (args[0] === 'off' || args[0] === 'on') {
        node.setUpdates(args[0] === 'on');
        console.log(args[0] === 'on' ? 'Automatic updates are on.' : 'Automatic updates are off; agentchat update still installs one when you run it.');
        break;
      }
      if (flags.auto && node.updateState().off) break;
      const result = await node.update({check: flags.check === true, record: flags.auto === true || !flags.check});
      console.log(updateText(result));
      if (flags.check) {
        const state = node.updateState();
        console.log(`Automatic updates: ${state.off ? 'off' : 'on'} · ${state.at ? `last attempt ${new Date(state.at).toLocaleString()}: ${state.result}` : 'no attempt yet'}`);
      }
      if (result.status === 'failed') process.exitCode = 1;
      break;
    }
    case 'version':
      console.log(VERSION);
      break;
    case 'notify': {
      const node = await createNode();
      if (!args[0]) console.log(alertsText(await node.notifyStatus()));
      else if (args[0] === 'off') { await node.clearNotify(); console.log('Alerts are off.'); }
      else {
        const saved = await node.setNotify({url: args[0], key: await readSecret('Webhook key (press Enter if there is none): ')});
        console.log(`Alerts go to ${saved.host}. Test alert: ${testResult(saved.test)}`);
      }
      break;
    }
    case 'invite': {
      const invite = await (await createNode()).invite({for: typeof flags.for === 'string' ? flags.for : undefined});
      const copied = process.platform === 'darwin' && spawnSync('/usr/bin/pbcopy', {input: invite.message}).status === 0;
      console.log(`Send this to the person you're inviting${copied ? ' (it is on your clipboard)' : ''}:\n\n${invite.message}${invite.commands ? `\n\nNo AI agent? Send this instead; each line is pinned to your install:\n\n${invite.commands}` : ''}`);
      break;
    }
    case 'approvals': {
      const waiting = (await createNode()).approvals();
      if (!waiting.length) console.log('Nothing is waiting for you.');
      for (const a of waiting) console.log(`${a.id}  ${a.what}${a.their_fingerprint ? `\n          fingerprint ${a.their_fingerprint}` : ''}${a.new_fingerprint ? `\n          new fingerprint ${a.new_fingerprint}\n          compare, then run: ${a.owner_runs}` : ''}${a.untrusted_text ? `\n          their note (unverified): ${a.untrusted_text}` : ''}`);
      if (waiting.some(a => !a.owner_runs)) console.log('\nContact requests: agentchat approve <id> to accept, or agentchat approve <id> --deny');
      break;
    }
    case 'approve': {
      if (!args[0]) { console.log('Usage: agentchat approve <id> [--deny]   (agentchat approvals lists the ids)'); break; }
      const done = await (await createNode()).approve({id: args[0], decision: flags.deny ? 'deny' : 'approve'});
      console.log(done.connected ? `Connected to ${done.connected}. ${done.next}` : `Denied ${done.denied}.`);
      break;
    }
    case 'verify': {
      if (!args[0]) { console.log('Usage: agentchat verify <handle> [--confirm]'); break; }
      const result = await (await createNode()).verify(args[0], {confirm: flags.confirm === true});
      const groups = result.safety_number.split(' ');
      console.log(`Safety number with ${result.handle}:\n${[0, 4, 8].map(i => groups.slice(i, i + 4).join(' ')).join('\n')}`);
      if (flags.confirm) console.log(`\n${result.handle} is verified.`);
      else console.log(`\n${result.keys_changed ? `${result.handle}'s keys changed. ` : ''}Compare these digits with ${result.handle} in person or on a call. If they match: agentchat verify ${args[0].replace(/^@/, '')} --confirm`);
      break;
    }
    case 'wiring':
      if (flags.print) showWiring();
      else connectAgents(flags.remove ? 'remove' : 'add');
      break;
    case 'leave': {
      const left = await (await createNode()).leave();
      console.log(`Deleted ${left.deleted} from the relay and removed this computer's Agentchat keys.${left.note ? `\n${left.note}` : ''}`);
      break;
    }
    default:
      console.log(USAGE);
  }
} catch (error) {
  console.error(error instanceof Problem || error?.code ? error.message : `agentchat: ${error?.stack ?? error}`);
  process.exitCode = 1;
}
