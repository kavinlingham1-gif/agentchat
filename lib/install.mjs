import {spawn, spawnSync} from 'node:child_process';
import {appendFileSync, closeSync, cpSync, existsSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {dirname, posix, win32} from 'node:path';
import {fileURLToPath} from 'node:url';

const paths = platform => (platform === 'win32' ? win32 : posix);
export const installRoot = ({home = homedir(), platform = process.platform} = {}) => paths(platform).join(home, '.agentchat');
export const launcherFile = (root, platform = process.platform) => paths(platform).join(root, 'bin', platform === 'win32' ? 'agentchat.cmd' : 'agentchat');

export function atLeast(a, b) {
  const x = a.split('.').map(Number), y = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0);
  return true;
}

const quote = text => `'${text.replace(/'/g, `'\\''`)}'`;

// 0.2.0's install.sh reads the installed version out of this exact `exec '<node>' '<root>/app/X.Y.Z/bin/agentchat.js' "$@"` line, so its format is frozen.
export function launcherText({root, node, version, platform = process.platform}) {
  if (platform !== 'win32') return `#!/bin/sh\nexec ${quote(node)} ${quote(posix.join(root, 'app', version, 'bin', 'agentchat.js'))} "$@"\n`;
  // cmd reads .cmd files in the OEM code page, so paths are relative to the launcher and work for any profile name; `& exit /b` stops cmd reading a file an update replaced.
  return `@"%~dp0..\\${win32.relative(root, node)}" "%~dp0..\\app\\${version}\\bin\\agentchat.js" %* & exit /b\r\n`;
}

export function launcherTarget(root, text, platform = process.platform) {
  if (platform === 'win32') {
    const m = /^@"%~dp0\.\.\\([^"]+)" "%~dp0\.\.\\app\\(\d+\.\d+\.\d+)\\bin\\agentchat\.js"/.exec(text);
    return m && {node: win32.join(root, m[1]), script: win32.join(root, 'app', m[2], 'bin', 'agentchat.js'), version: m[2]};
  }
  const m = /^exec '((?:[^']|'\\'')*)' '((?:[^']|'\\'')*\/app\/(\d+\.\d+\.\d+)\/bin\/agentchat\.js)' "\$@"$/m.exec(text);
  const unquote = s => s.replace(/'\\''/g, "'");
  return m && {node: unquote(m[1]), script: unquote(m[2]), version: m[3]};
}

export function currentInstall(root, platform = process.platform) {
  try { return launcherTarget(root, readFileSync(launcherFile(root, platform), 'utf8'), platform); } catch { return null; }
}

const alive = pid => { try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; } };
const pause = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// Windows Defender scans freshly written files and briefly locks them.
function renameRetry(from, to) {
  for (let i = 0; ; i++) {
    try { return renameSync(from, to); } catch (error) {
      if (process.platform !== 'win32' || !['EPERM', 'EBUSY', 'EACCES'].includes(error.code) || i >= 40) throw error;
      pause(250);
    }
  }
}

// The pasted line and the background updater both install here, one at a time. A lock left by a dead or 30-minute-old process is taken over, so one killed update can't block every install after it.
export async function withInstallLock(root, fn, {say = message => console.error(message), now = Date.now} = {}) {
  mkdirSync(root, {recursive: true});
  const file = paths(process.platform).join(root, 'install.lock');
  for (let waited = 0; ; waited++) {
    try { writeFileSync(file, JSON.stringify({pid: process.pid, at: now()}), {flag: 'wx'}); break; } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      let held = null;
      try { held = JSON.parse(readFileSync(file, 'utf8')); } catch {}
      const young = (() => { try { return now() - statSync(file).mtimeMs < 5000; } catch { return false; } })();
      if ((!held && !young) || (held && (!alive(held.pid) || now() - held.at > 30 * 60000))) {
        say(`Taking over a stale install lock${held ? ` left by process ${held.pid}` : ''}.`);
        rmSync(file, {force: true});
        continue;
      }
      if (waited >= 180) throw new Error('Another Agentchat install is still running; try again in a few minutes.');
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  try {
    for (const dir of ['app', 'node', 'bin']) {
      const parent = paths(process.platform).join(root, dir);
      let names = [];
      try { names = readdirSync(parent); } catch {}
      for (const name of names.filter(n => n.startsWith('.tmp-'))) {
        const stale = paths(process.platform).join(parent, name);
        try { if (now() - statSync(stale).mtimeMs > 3600000) rmSync(stale, {recursive: true, force: true}); } catch {}
      }
    }
    return await fn();
  } finally { rmSync(file, {force: true}); }
}

// A version's folder is never rewritten: running agents keep loading files and the Touch ID helper from it.
export function installApp(root, pkgDir, version) {
  const p = paths(process.platform), app = p.join(root, 'app', version);
  if (existsSync(p.join(app, 'package.json'))) return app;
  const temp = p.join(root, 'app', `.tmp-${process.pid}`);
  rmSync(temp, {recursive: true, force: true});
  mkdirSync(dirname(temp), {recursive: true});
  cpSync(pkgDir, temp, {recursive: true});
  try { renameRetry(temp, app); } catch (error) {
    rmSync(temp, {recursive: true, force: true});
    if (!existsSync(p.join(app, 'package.json'))) throw new Error(`${app} exists but isn't a complete install (${error.code}); delete it and run the line again.`);
  }
  return app;
}

export function writeLauncher(root, {node, version, platform = process.platform}) {
  const file = launcherFile(root, platform), current = currentInstall(root, platform);
  if (current && !atLeast(version, current.version)) return {inUse: false, current};
  mkdirSync(dirname(file), {recursive: true});
  const temp = `${file}.new-${process.pid}`;
  writeFileSync(temp, launcherText({root, node, version, platform}), {mode: 0o755});
  renameRetry(temp, file);
  return {inUse: true, current};
}

// Bash stops reading ~/.profile once ~/.bash_profile exists, so the block goes into whichever of the two is already there.
export function addToProfile({home = homedir(), shell = process.env.SHELL ?? ''} = {}) {
  let profile = null;
  if (shell.endsWith('/zsh')) profile = posix.join(home, '.zprofile');
  else if (shell.endsWith('/bash')) profile = existsSync(posix.join(home, '.bash_profile')) || !existsSync(posix.join(home, '.profile')) ? posix.join(home, '.bash_profile') : posix.join(home, '.profile');
  if (!profile) return null;
  if (!(existsSync(profile) && readFileSync(profile, 'utf8').includes('# >>> agentchat >>>'))) appendFileSync(profile, '\n# >>> agentchat >>>\nexport PATH="$HOME/.agentchat/bin:$PATH"\n# <<< agentchat <<<\n');
  return profile;
}

// An installer-made install runs through its launcher, which never moves, so agent configs keep working across updates.
export function launcherCommand({script, home = homedir(), platform = process.platform, realpath = realpathSync, exists = existsSync}) {
  const p = paths(platform), root = installRoot({home, platform}), launcher = launcherFile(root, platform);
  let apps;
  try { apps = realpath(p.join(root, 'app')); } catch { return null; }
  if (!script.startsWith(apps + p.sep) || !exists(launcher)) return null;
  return platform === 'win32' ? {launcher, command: 'cmd', args: ['/d', '/c', launcher, 'mcp']} : {launcher, command: launcher, args: ['mcp']};
}

// A detached `agentchat update --auto` with its own log, so it outlives the agent that started it and never writes into that agent's MCP stream. Null when this isn't an installer-made install.
export function updaterFor({script = realpathSync(fileURLToPath(new URL('../bin/agentchat.js', import.meta.url))), home = homedir(), platform = process.platform} = {}) {
  const installed = launcherCommand({script, home, platform});
  if (!installed) return null;
  return () => {
    const log = openSync(paths(platform).join(installRoot({home, platform}), 'update.log'), 'a');
    try {
      const [command, args] = platform === 'win32' ? ['cmd', ['/d', '/c', installed.launcher, 'update', '--auto']] : [installed.launcher, ['update', '--auto']];
      spawn(command, args, {detached: true, stdio: ['ignore', log, log], windowsHide: true}).unref();
    } finally { closeSync(log); }
  };
}

export const runInstalled = (target, args, options = {}) => spawnSync(target.node, [target.script, ...args], {stdio: 'inherit', windowsHide: true, ...options});
