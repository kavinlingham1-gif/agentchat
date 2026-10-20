import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync, readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {unixLine, windowsLine} from '../lib/node.mjs';

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

test('the join page shows exactly the lines an invite sends, for a package that is served, in markup where no placeholder can vanish', () => {
  const html = readFileSync(`${root}/public/join/index.html`, 'utf8');
  const tags = new Set([...html.matchAll(/<\/?([^\s>/]+)/g)].map(m => m[1]));
  assert.deepEqual([...tags].filter(tag => !['!doctype', 'html', 'head', 'meta', 'title', 'body', 'h1', 'h2', 'p', 'ol', 'li', 'pre', 'code', 'a'].includes(tag)), [], 'a raw <CODE> would be read as a tag and disappear, a comment could hide a line, and the page runs no script');
  const decode = text => text.replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&quot;', '"').replaceAll('&amp;', '&');
  const lines = [...html.matchAll(/<pre>([^<]*)<\/pre>/g)].map(m => decode(m[1]));
  const [, url, file] = /curl -fsSLO (\S+\/dl\/(agentchat-[\d.]+\.tgz)) /.exec(lines[0] ?? '') ?? [];
  assert.ok(file, 'the first line downloads a package from /dl/');
  const pkg = {url, sha256: createHash('sha256').update(readFileSync(`${root}/public/dl/${file}`)).digest('hex')};
  assert.deepEqual(lines, [unixLine(pkg, file, '<CODE>', ' --as <NAME>'), windowsLine(pkg, file, '<CODE>', ' --as <NAME>')]);
});

test('install.sh and install.ps1 pin the same Node version', () => {
  const sh = readFileSync(`${root}/install.sh`, 'utf8'), ps = readFileSync(`${root}/install.ps1`, 'utf8');
  assert.equal(/^NODE_VERSION=(.+)$/m.exec(sh)[1], /^\$NodeVersion = '(.+)'$/m.exec(ps)[1]);
});
