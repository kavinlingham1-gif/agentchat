import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync, spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync} from 'node:fs';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {currentInstall, launcherFile} from '../lib/install.mjs';
import {VERSION, createNode} from '../lib/node.mjs';
import {defaultHome} from '../lib/store.mjs';
import * as w from '../lib/wire.mjs';
import {RELAY, network, softwareApprover} from './fakes.mjs';

const REPO = fileURLToPath(new URL('..', import.meta.url));
const NODE_VERSION = /^NODE_VERSION=(.+)$/m.exec(readFileSync(join(REPO, 'install.sh'), 'utf8'))[1];
const windows = process.platform === 'win32';
const NEXT = VERSION.replace(/\d+$/, n => String(Number(n) + 1));
const temp = prefix => mkdtempSync(join(tmpdir(), prefix));

// Newline-delimited JSON-RPC, the way MCP hosts talk to `agentchat mcp`.
function mcp(command, args, env) {
  const child = spawn(command, args, {env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true}), waiting = new Map();
  let buffer = '';
  child.stdout.on('data', chunk => {
    buffer += chunk;
    for (let i; (i = buffer.indexOf('\n')) >= 0;) {
      const line = buffer.slice(0, i);
      buffer = buffer.slice(i + 1);
      try { const message = JSON.parse(line); waiting.get(message.id)?.(message); } catch {}
    }
  });
  const rpc = (id, method, params = {}) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`agentchat mcp did not answer ${method}`)), 20000);
    waiting.set(id, message => { clearTimeout(timer); resolve(message); });
    child.stdin.write(`${JSON.stringify({jsonrpc: '2.0', id, method, params})}\n`);
  });
  return {child, rpc, notify: method => child.stdin.write(`${JSON.stringify({jsonrpc: '2.0', method})}\n`)};
}

test('an install updates itself from a signed release while an old agentchat mcp keeps answering', {timeout: 240000}, async t => {
  const home = temp('agentchat-ota-'), env = {...process.env, HOME: home, USERPROFILE: home, LOCALAPPDATA: join(home, 'AppData', 'Local'), APPDATA: join(home, 'AppData', 'Roaming'), SHELL: '/bin/zsh', PATH: windows ? process.env.PATH : '/usr/bin:/bin'};
  const root = join(home, '.agentchat');
  // The pinned Node is already in place, so neither install downloads it.
  const nodeDir = join(root, 'node', windows ? `v${NODE_VERSION}-win-${process.arch}` : process.platform === 'darwin' ? `v${NODE_VERSION}-${process.arch}` : `v${NODE_VERSION}-linux-${process.arch}`);
  mkdirSync(windows ? nodeDir : join(nodeDir, 'bin'), {recursive: true});
  if (windows) copyFileSync(process.execPath, join(nodeDir, 'node.exe')); else symlinkSync(process.execPath, join(nodeDir, 'bin', 'node'));

  // This version, installed by its own install step, the way the pasted line does it.
  const work = temp('agentchat-pkgs-');
  execFileSync(windows ? 'npm.cmd' : 'npm', ['pack', '--pack-destination', work], {cwd: REPO, stdio: 'ignore', shell: windows});
  execFileSync(windows ? join(process.env.SystemRoot, 'System32', 'tar.exe') : 'tar', ['-xzf', join(work, `agentchat-${VERSION}.tgz`), '-C', work]);
  execFileSync(join(nodeDir, windows ? 'node.exe' : 'bin/node'), [join(work, 'package', 'bin', 'agentchat.js'), 'install'], {env, stdio: 'ignore'});
  assert.equal(currentInstall(root).version, VERSION);

  // The next version: the same package with a higher version number, signed by a test release key.
  const pkgJson = join(work, 'package', 'package.json');
  writeFileSync(pkgJson, readFileSync(pkgJson, 'utf8').replace(`"version": "${VERSION}"`, `"version": "${NEXT}"`));
  execFileSync(windows ? join(process.env.SystemRoot, 'System32', 'tar.exe') : 'tar', ['-czf', join(work, `agentchat-${NEXT}.tgz`), '-C', work, 'package']);
  const tarball = readFileSync(join(work, `agentchat-${NEXT}.tgz`));
  const signer = softwareApprover(), keys = [{handle: 'kavin', ik: 'IK', rk: signer.publicKey}];
  const sign = async fields => { const payload = w.approvalPayload('kavin', 'IK', 'release.publish', fields); return JSON.stringify({payload, sig: await signer.sign(payload)}); };
  const release = {version: NEXT, package: `agentchat-${NEXT}.tgz`, sha256: createHash('sha256').update(tarball).digest('hex'), size: tarball.length};
  let manifest = null;
  const server = createServer((req, res) => {
    if (req.url === '/dl/release.json' && manifest) return res.end(manifest);
    if (req.url === `/dl/agentchat-${NEXT}.tgz`) return res.end(tarball);
    res.writeHead(404).end('{"error":"Not found"}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const net = network(), owner = await net.owner('kavin');
  const fetch = (url, init) => (String(url).startsWith(`${RELAY}/dl/`) ? globalThis.fetch(String(url).replace(RELAY, `http://127.0.0.1:${server.address().port}`), init) : net.fetch(url, init));

  // A joined always-on node in this HOME's data folder, so updates know their relay.
  const bot = await createNode({home: defaultHome({home, env}), agent: true, fetch, autoUpdate: null});
  await bot.join((await owner.invite()).code, {as: 'kavin_grok'});
  const update = options => bot.update({keys, home, env, ...options});

  assert.equal((await update()).status, 'none', 'nothing published yet is not an error');
  manifest = await sign({...release, sha256: 'b'.repeat(64)});
  const tampered = await update();
  assert.deepEqual([tampered.status, currentInstall(root).version], ['failed', VERSION], 'a package that does not match its signature is refused');
  assert.match(tampered.error, /doesn't match the signed release/);
  manifest = JSON.stringify({payload: JSON.parse(await sign(release)).payload, sig: JSON.parse(await sign({...release, size: 1})).sig});
  assert.match((await update()).error, /isn't signed by a trusted release key/);
  manifest = await sign({...release, version: '0.0.1', package: 'agentchat-0.0.1.tgz'});
  assert.equal((await update()).status, 'current', 'an older release never downgrades');
  manifest = await sign(release);
  assert.deepEqual(await update({check: true, record: false}), {status: 'available', version: NEXT, signer: 'kavin', installed: VERSION});

  const launcher = launcherFile(root);
  const old = windows ? mcp('cmd', ['/d', '/c', launcher, 'mcp'], env) : mcp(launcher, ['mcp'], env);
  t.after(() => old.child.kill());
  assert.equal((await old.rpc(1, 'initialize', {protocolVersion: '2025-11-25', capabilities: {}, clientInfo: {name: 'test', version: '0'}})).result.serverInfo.version, VERSION);
  old.notify('notifications/initialized');

  const applied = await update();
  assert.deepEqual([applied.status, applied.version], ['updated', NEXT], applied.error);
  assert.equal(currentInstall(root).version, NEXT);
  assert.ok(existsSync(join(root, 'app', VERSION, 'package.json')), 'the old version stays for the agents still running it');
  assert.equal(execFileSync(windows ? 'cmd' : launcher, windows ? ['/d', '/c', launcher, 'version'] : ['version'], {env, encoding: 'utf8'}).trim(), NEXT, 'the next launch is the new version');
  assert.equal((await old.rpc(2, 'tools/list')).result.tools.length, 13, 'the old agentchat mcp keeps answering');
  assert.equal(bot.config().package.url, `${RELAY}/dl/agentchat-${NEXT}.tgz`, "this computer's invites now install the new version");
  assert.equal(bot.config().package.sha256, release.sha256);
  assert.equal(bot.updateState().result, `updated to ${NEXT}`);
  assert.equal((await update()).status, 'current');
});
