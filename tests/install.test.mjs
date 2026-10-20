import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import {copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {addToProfile, installApp, launcherTarget, launcherText, withInstallLock, writeLauncher} from '../lib/install.mjs';
import {VERSION, unixLine} from '../lib/node.mjs';
import {defaultHome} from '../lib/store.mjs';
import {b64, encodeInvite} from '../lib/wire.mjs';

// Everything this file, and anything it spawns, puts in the temp folder lands in one folder removed at the end.
const scratch = mkdtempSync(join(tmpdir(), 'agentchat-run-'));
process.env.TMPDIR = process.env.TMP = process.env.TEMP = scratch;
// Windows keeps open databases and killed children's files locked; a leftover folder there is not a test failure.
test.after(() => { try { rmSync(scratch, {recursive: true, force: true, maxRetries: 3}); } catch (error) { if (process.platform !== 'win32') throw error; } });

const REPO = fileURLToPath(new URL('..', import.meta.url));
const NODE_VERSION = /^NODE_VERSION=(.+)$/m.exec(readFileSync(join(REPO, 'install.sh'), 'utf8'))[1];
const unix = process.platform !== 'win32';
const temp = prefix => mkdtempSync(join(tmpdir(), prefix));

// A throwaway HOME where the pinned Node is already in place, so nothing downloads.
function homeWithNode() {
  const home = temp('agentchat-install-');
  for (const name of ['arm64', 'x64', 'linux-arm64', 'linux-x64']) {
    mkdirSync(join(home, '.agentchat', 'node', `v${NODE_VERSION}-${name}`, 'bin'), {recursive: true});
    symlinkSync(process.execPath, join(home, '.agentchat', 'node', `v${NODE_VERSION}-${name}`, 'bin', 'node'));
  }
  return home;
}

let packed;
const pack = () => (packed ??= (() => {
  const dir = temp('agentchat-pack-');
  execFileSync('npm', ['pack', '--pack-destination', dir], {cwd: REPO, stdio: 'ignore'});
  const file = join(dir, `agentchat-${VERSION}.tgz`);
  return {file, url: `file://${file}`, sha256: createHash('sha256').update(readFileSync(file)).digest('hex')};
})());

// macOS mktemp ignores TMPDIR, so the folder a pasted line makes there is found by name and removed.
const lineTemp = process.platform === 'darwin' ? execFileSync('getconf', ['DARWIN_USER_TEMP_DIR'], {encoding: 'utf8'}).trim() : scratch;
const pasteLine = (shell, home, tail, extraEnv = {}) => {
  const before = new Set(readdirSync(lineTemp));
  const result = spawnSync(shell, ['-c', unixLine(pack(), `agentchat-${VERSION}.tgz`, tail)], {env: {...process.env, HOME: home, SHELL: '/bin/zsh', ...extraEnv}, encoding: 'utf8'});
  for (const name of readdirSync(lineTemp)) if (!before.has(name) && existsSync(join(lineTemp, name, `agentchat-${VERSION}.tgz`))) rmSync(join(lineTemp, name), {recursive: true, force: true});
  return result;
};

test('launchers: the Unix line keeps the exact format 0.2.0 installers read, and the Windows one is relative to itself', () => {
  const unixText = launcherText({root: "/Users/o'brien/.agentchat", node: "/Users/o'brien/.agentchat/node/v24.22.0-arm64/bin/node", version: '0.3.0', platform: 'darwin'});
  assert.equal(unixText, `#!/bin/sh\nexec '/Users/o'\\''brien/.agentchat/node/v24.22.0-arm64/bin/node' '/Users/o'\\''brien/.agentchat/app/0.3.0/bin/agentchat.js' "$@"\n`);
  assert.deepEqual(launcherTarget("/Users/o'brien/.agentchat", unixText, 'darwin'), {node: "/Users/o'brien/.agentchat/node/v24.22.0-arm64/bin/node", script: "/Users/o'brien/.agentchat/app/0.3.0/bin/agentchat.js", version: '0.3.0'});
  const root = 'C:\\Users\\Fírst Lást\\.agentchat';
  const winText = launcherText({root, node: `${root}\\node\\v24.22.0-win-x64\\node.exe`, version: '0.3.0', platform: 'win32'});
  assert.equal(winText, '@"%~dp0..\\node\\v24.22.0-win-x64\\node.exe" "%~dp0..\\app\\0.3.0\\bin\\agentchat.js" %* & exit /b\r\n');
  assert.ok(/^[\x00-\x7f]*$/.test(winText), 'cmd reads .cmd files in the OEM code page, so no profile name goes inside');
  assert.deepEqual(launcherTarget(root, winText, 'win32'), {node: `${root}\\node\\v24.22.0-win-x64\\node.exe`, script: `${root}\\app\\0.3.0\\bin\\agentchat.js`, version: '0.3.0'});
});

test('an app folder is never rewritten, and the launcher never moves to an older version', () => {
  const root = join(temp('agentchat-root-'), '.agentchat'), pkg = temp('agentchat-pkg-');
  writeFileSync(join(pkg, 'package.json'), '{"version":"0.3.0"}');
  const app = installApp(root, pkg, '0.3.0');
  writeFileSync(join(app, 'running-agent-marker'), 'x');
  installApp(root, pkg, '0.3.0');
  assert.ok(existsSync(join(app, 'running-agent-marker')), 'a second install leaves the folder a running agent uses alone');
  const node = join(root, 'node', 'v24.22.0-test', process.platform === 'win32' ? 'node.exe' : 'node');
  assert.equal(writeLauncher(root, {node, version: '0.3.0'}).inUse, true);
  const refused = writeLauncher(root, {node, version: '0.2.9'});
  assert.deepEqual([refused.inUse, refused.current.version, refused.current.node], [false, '0.3.0', node]);
  assert.equal(writeLauncher(root, {node, version: '0.10.0'}).inUse, true, 'versions compare as numbers, not text');
});

test('a lock left by a dead or 30-minute-old installer is taken over instead of blocking every install after it', async () => {
  const root = join(temp('agentchat-lock-'), '.agentchat'), said = [];
  mkdirSync(root, {recursive: true});
  writeFileSync(join(root, 'install.lock'), JSON.stringify({pid: 999999, at: Date.now()}));
  assert.equal(await withInstallLock(root, async () => 'ran', {say: m => said.push(m)}), 'ran');
  writeFileSync(join(root, 'install.lock'), JSON.stringify({pid: process.pid, at: Date.now() - 31 * 60000}));
  assert.equal(await withInstallLock(root, async () => 'ran again', {say: m => said.push(m)}), 'ran again');
  assert.equal(said.length, 2);
  assert.match(said[0], /stale install lock left by process 999999/);
  assert.equal(existsSync(join(root, 'install.lock')), false);
});

test('the PATH block goes in the profile each shell actually reads, once', {skip: !unix}, () => {
  const zsh = temp('agentchat-zsh-');
  addToProfile({home: zsh, shell: '/bin/zsh'});
  addToProfile({home: zsh, shell: '/bin/zsh'});
  assert.equal(readFileSync(join(zsh, '.zprofile'), 'utf8').match(/>>> agentchat >>>/g).length, 1);
  const bash = temp('agentchat-bash-');
  writeFileSync(join(bash, '.profile'), 'export FOO=1\n');
  assert.equal(addToProfile({home: bash, shell: '/bin/bash'}), join(bash, '.profile'));
  assert.equal(existsSync(join(bash, '.bash_profile')), false, 'creating ~/.bash_profile would stop bash reading ~/.profile');
  assert.equal(addToProfile({home: temp('agentchat-dash-'), shell: '/bin/dash'}), null);
});

test('install.sh hands its arguments to the package unchanged', {skip: !unix}, () => {
  const home = homeWithNode(), work = temp('agentchat-line-'), pkg = join(work, 'package');
  mkdirSync(join(pkg, 'bin'), {recursive: true});
  writeFileSync(join(pkg, 'bin', 'agentchat.js'), 'console.log("ARGS " + JSON.stringify(process.argv.slice(2)))');
  copyFileSync(join(REPO, 'install.sh'), join(pkg, 'install.sh'));
  const out = execFileSync('/bin/sh', [join(pkg, 'install.sh'), 'agentchat1-code', '--as', 'sam', '--agent'], {env: {...process.env, HOME: home}, encoding: 'utf8'});
  assert.deepEqual(JSON.parse(/^ARGS (.*)$/m.exec(out)[1]), ['install', 'agentchat1-code', '--as', 'sam', '--agent']);
});

test("the friend's exact line installs the packed tarball under dash and zsh, and pasting it again updates in place", {skip: !unix}, () => {
  for (const shell of ['/bin/dash', '/bin/zsh'].filter(existsSync)) {
    const home = homeWithNode();
    for (let run = 0; run < 2; run++) {
      const result = pasteLine(shell, home, ' --agent');
      assert.equal(result.status, 0, `${shell} run ${run}: ${result.stderr}`);
      assert.match(result.stdout, new RegExp(`Agentchat ${VERSION.replace(/\./g, '\\.')} is installed\\. To join, paste the line from your invite\\.`));
    }
    const launcher = readFileSync(join(home, '.agentchat', 'bin', 'agentchat'), 'utf8');
    assert.match(launcher, new RegExp(`^#!/bin/sh\\nexec '[^']+/bin/node' '${home.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/\\.agentchat/app/${VERSION.replace(/\./g, '\\.')}/bin/agentchat\\.js' "\\$@"\\n$`));
    assert.ok(existsSync(join(home, '.agentchat', 'app', VERSION, 'install.ps1')), 'the whole package is installed');
    assert.equal(readFileSync(join(home, '.zprofile'), 'utf8').match(/>>> agentchat >>>/g).length, 1);
    assert.equal(existsSync(defaultHome({home})), false, 'with no invite nothing is created: no keys, no store');
  }
});

test('the shipped 0.2.0 installer refuses to downgrade a 0.3.0 install', {skip: process.platform !== 'darwin' || !existsSync(join(REPO, 'public', 'dl', 'agentchat-0.2.0.tgz'))}, () => {
  const home = homeWithNode();
  assert.equal(pasteLine('/bin/sh', home, '').status, 0);
  const old = temp('agentchat-020-');
  execFileSync('tar', ['-xzf', join(REPO, 'public', 'dl', 'agentchat-0.2.0.tgz'), '-C', old]);
  const out = execFileSync('/bin/sh', [join(old, 'package', 'install.sh')], {env: {...process.env, HOME: home, SHELL: '/bin/zsh'}, encoding: 'utf8'});
  assert.match(out, new RegExp(`Agentchat ${VERSION.replace(/\./g, '\\.')} is already installed, so this older 0\\.2\\.0 package was left unused`));
  assert.match(readFileSync(join(home, '.agentchat', 'bin', 'agentchat'), 'utf8'), new RegExp(`/app/${VERSION.replace(/\./g, '\\.')}/`));
});

test('the line gets the invite and --as through to join (proved against a relay that does not exist, so nothing registers)', {skip: !unix}, () => {
  const home = homeWithNode();
  const invite = encodeInvite({r: 'https://relay.invalid', i: 'kavin', s: b64(randomBytes(32)), f: '00000 00000 00000 00000 00000 00000'});
  const result = pasteLine('/bin/sh', home, ` ${invite} --as sam --agent`);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Could not reach the Agentchat relay/);
  assert.match(result.stderr, /paste the same line again/);
  assert.doesNotMatch(result.stderr, /Pick a handle/, '--as arrived');
  assert.match(readFileSync(join(defaultHome({home}), 'approval.key'), 'utf8'), /"tier":"software"/, '--agent arrived: a software key, never the Keychain');
});
