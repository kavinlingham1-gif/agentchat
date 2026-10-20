import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {verifyApprovalSignature} from './wire.mjs';

// Updates are trusted only when signed by one of these Secure Enclave keys, never because of the server they came from. A signed release can add the next key before this one's Mac is retired.
export const RELEASE_KEYS = [
  {handle: 'kavin', ik: '90D6tL3U8mUyvCem4xrcZZcxue3J0rjL-E9GOH7lQ2s', rk: 'BPU9l735m3D-FSWPu7034oAWb-y3V9WwueFA66OEUFHvQqXU49pnA8DfG2hp2cclAlC9-BIdHCsobf2YEoITnow'},
];

// A release payload uses the approval format so the Touch ID helper can word the prompt, but it has no expiry: "newer than what's installed" is its freshness rule.
export function readRelease(signed, keys = RELEASE_KEYS) {
  if (!signed || typeof signed.payload !== 'string' || signed.payload.length > 4096 || typeof signed.sig !== 'string') return null;
  let p;
  try { p = JSON.parse(signed.payload); } catch { return null; }
  if (p?.ctx !== 'agentchat/v1/approval' || p.action !== 'release.publish' || !/^\d+\.\d+\.\d+$/.test(p.version ?? '') || p.package !== `agentchat-${p.version}.tgz`) return null;
  if (!/^[0-9a-f]{64}$/.test(p.sha256 ?? '') || !Number.isInteger(p.size) || p.size < 1 || p.size > 64 * 1048576) return null;
  return keys.some(k => p.signer === k.handle && p.signer_ik === k.ik && verifyApprovalSignature(k.rk, signed.payload, signed.sig)) ? p : null;
}

export async function checkRelease({relay, fetch = globalThis.fetch, keys = RELEASE_KEYS}) {
  const response = await fetch(`${relay}/dl/release.json`, {signal: AbortSignal.timeout(15000), cache: 'no-store'});
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`the server answered ${response.status} for release.json`);
  const text = await response.text();
  let signed;
  try { signed = text.length <= 16384 ? JSON.parse(text) : null; } catch {}
  return readRelease(signed, keys) ?? Promise.reject(new Error("release.json isn't signed by a trusted release key, so it was ignored"));
}

// The host is untrusted, so the size is enforced while the bytes arrive, not only afterwards.
export async function downloadPackage({relay, release, dir, fetch = globalThis.fetch}) {
  const response = await fetch(`${relay}/dl/${release.package}`, {signal: AbortSignal.timeout(300000)});
  if (!response.ok) throw new Error(`the server answered ${response.status} for ${release.package}`);
  const declared = Number(response.headers.get('content-length') ?? 0);
  if (declared && declared !== release.size) throw new Error(`${release.package} isn't the size the signed release says`);
  const hash = createHash('sha256'), chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > release.size) throw new Error(`${release.package} is larger than the signed release says`);
    hash.update(chunk);
    chunks.push(chunk);
  }
  if (size !== release.size || hash.digest('hex') !== release.sha256) throw new Error(`${release.package} doesn't match the signed release`);
  const file = join(dir, release.package);
  writeFileSync(file, Buffer.concat(chunks));
  return file;
}

// The new package's own installer does the rest, exactly as when someone pastes the line: its Node pins, its app folder, the launcher and the package this computer's invites send.
export async function applyUpdate({relay, release, fetch, platform = process.platform, env = process.env}) {
  const dir = mkdtempSync(join(tmpdir(), 'agentchat-update-'));
  try {
    const file = await downloadPackage({relay, release, dir, fetch});
    const system = env.SystemRoot ?? 'C:\\Windows';
    const unpacked = spawnSync(platform === 'win32' ? join(system, 'System32', 'tar.exe') : 'tar', ['-xzf', file, '-C', dir], {encoding: 'utf8', windowsHide: true});
    if (unpacked.status !== 0) throw new Error(`couldn't unpack ${release.package}: ${(unpacked.stderr || unpacked.error?.message || '').trim()}`);
    const [command, args] = platform === 'win32'
      ? [join(system, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', join(dir, 'package', 'install.ps1'), '--update']]
      : ['/bin/sh', [join(dir, 'package', 'install.sh'), '--update']];
    const installed = spawnSync(command, args, {env, encoding: 'utf8', windowsHide: true, timeout: 900000});
    if (installed.status !== 0) throw new Error(`the ${release.version} installer failed: ${`${installed.stderr ?? ''}${installed.stdout ?? ''}`.trim().split('\n').slice(-3).join(' ') || installed.error?.message}`);
    return installed.stdout;
  } finally { rmSync(dir, {recursive: true, force: true}); }
}
