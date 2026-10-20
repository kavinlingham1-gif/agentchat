import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {existsSync, readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

test('the npm package carries only the local node, its installers and its bundled dependencies', () => {
  const [pack] = JSON.parse(execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['pack', '--dry-run', '--json'], {cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], shell: process.platform === 'win32'}));
  const files = pack.files.map(f => f.path.replace(/\\/g, '/'));
  for (const required of ['package.json', 'install.sh', 'install.ps1', 'bin/agentchat.js', 'bin/agentchat-approve', 'swift/approve.swift', 'lib/wire.mjs', 'lib/node.mjs', 'lib/store.mjs', 'lib/keychain.mjs', 'lib/approval.mjs', 'lib/tools.mjs', 'lib/agents.mjs', 'lib/install.mjs', 'lib/release.mjs']) assert.ok(files.includes(required), `missing ${required}`);
  for (const forbidden of [/^api\//, /^server\//, /^tests\//, /^scripts\//, /^public\//, /(^|\/)\.env/, /^\.vercel\//, /^lib\/relay\.mjs$/, /\.tgz$/, /release\.key/]) assert.ok(!files.some(f => forbidden.test(f)), `ships ${forbidden}`);
  for (const bundled of ['libsodium-wrappers', 'libsodium', 'zod', '@modelcontextprotocol/server', '@modelcontextprotocol/core']) assert.ok(files.some(f => f.startsWith(`node_modules/${bundled}/`)), `does not bundle ${bundled}`);
});

test('install.sh parses under every /bin/sh it will meet (bash on macOS, dash on Debian and Ubuntu)', {skip: process.platform === 'win32'}, () => {
  for (const shell of ['/bin/sh', '/bin/dash', '/bin/bash'].filter(existsSync)) execFileSync(shell, ['-n', 'install.sh'], {cwd: root});
});

test('install.ps1 is plain ASCII, which is how Windows PowerShell 5.1 reads a file without a byte-order mark', () => {
  const bytes = readFileSync(`${root}/install.ps1`);
  assert.ok(bytes.every(b => b < 0x80), 'a non-ASCII byte would break parsing on Windows PowerShell 5.1');
  assert.doesNotMatch(bytes.toString(), /^\s*param\s*\(/m, 'a param() block would swallow the invite and --as');
});

test('install.sh and install.ps1 pin the same Node version', () => {
  const sh = readFileSync(`${root}/install.sh`, 'utf8'), ps = readFileSync(`${root}/install.ps1`, 'utf8');
  assert.equal(/^NODE_VERSION=(.+)$/m.exec(sh)[1], /^\$NodeVersion = '(.+)'$/m.exec(ps)[1]);
});
