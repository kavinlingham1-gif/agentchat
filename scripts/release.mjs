// npm run release: makes public/dl/agentchat-<version>.tgz the release every Agentchat install updates to, then deploys it.
// The release key lives in this Mac's Secure Enclave, so the signature needs Kavin's Touch ID; an agent can't publish to friends on its own.
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {homedir, tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {runHelper} from '../lib/approval.mjs';
import {RELEASE_KEYS, checkRelease, downloadPackage, readRelease} from '../lib/release.mjs';
import {approvalPayload} from '../lib/wire.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const FRONT_DOOR = 'https://agentchat-baa560.vercel.app';
const KEY_FILE = join(homedir(), 'Library', 'Application Support', 'agentchat-release', 'release.key');
const {version} = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const pkg = `agentchat-${version}.tgz`, file = join(root, 'public', 'dl', pkg);

if (!existsSync(KEY_FILE)) throw new Error(`No release key at ${KEY_FILE}; restore it from "archive/01 Backups/agentchat-release-key".`);
const releaseKey = RELEASE_KEYS.find(k => k.rk === JSON.parse(readFileSync(KEY_FILE, 'utf8')).public_key);
if (!releaseKey) throw new Error("This Mac's release key isn't in lib/release.mjs RELEASE_KEYS, so installs would reject its signature.");

execFileSync('npm', ['test'], {cwd: root, stdio: 'inherit'});
// A version's tarball is never rebuilt once it exists: installs and invites already pin its fingerprint.
if (!existsSync(file)) execFileSync('npm', ['pack', '--pack-destination', join(root, 'public', 'dl')], {cwd: root, stdio: 'inherit'});
const bytes = readFileSync(file), sha256 = createHash('sha256').update(bytes).digest('hex');
console.log(`Releasing ${pkg}\n  sha256 ${sha256}\n  ${bytes.length} bytes\nTouch ID will ask to "publish agentchat ${version} to every Agentchat install".`);

const payload = approvalPayload(releaseKey.handle, releaseKey.ik, 'release.publish', {version, package: pkg, sha256, size: bytes.length});
const signed = {payload, sig: (await runHelper(['sign', KEY_FILE], JSON.stringify({payload}), 120000)).signature};

// The package being released must itself trust this signature, or installs updated to it could never update again.
const unpacked = mkdtempSync(join(tmpdir(), 'agentchat-release-'));
try {
  execFileSync('tar', ['-xzf', file, '-C', unpacked]);
  const shipped = await import(pathToFileURL(join(unpacked, 'package', 'lib', 'release.mjs')).href);
  if (!readRelease(signed) || !shipped.readRelease(signed)) throw new Error(`The signature doesn't verify against ${pkg}'s own release keys; nothing was published.`);
} finally { rmSync(unpacked, {recursive: true, force: true}); }

writeFileSync(join(root, 'public', 'dl', 'release.json'), `${JSON.stringify(signed)}\n`);
execFileSync('vercel', ['deploy', '--prod', '--yes'], {cwd: root, stdio: 'inherit'});

// Checked with the same code installs run, so this one Touch ID also proves the download path friends will use.
const live = await checkRelease({relay: FRONT_DOOR});
if (live?.version !== version || live.sha256 !== sha256) throw new Error(`The deployed release.json says ${live?.version ?? 'nothing'}, not ${version}.`);
const fetched = mkdtempSync(join(tmpdir(), 'agentchat-published-'));
try { await downloadPackage({relay: FRONT_DOOR, release: live, dir: fetched}); } finally { rmSync(fetched, {recursive: true, force: true}); }
console.log(`Published agentchat ${version}. Installs pick it up within a day; agentchat update installs it now.`);
