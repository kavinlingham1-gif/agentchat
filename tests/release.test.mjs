import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {join} from 'node:path';
import {RELEASE_KEYS, readRelease} from '../lib/release.mjs';
import * as w from '../lib/wire.mjs';
import {softwareApprover} from './fakes.mjs';

const good = {version: '0.3.1', package: 'agentchat-0.3.1.tgz', sha256: 'a'.repeat(64), size: 1000};
const signWith = async (signer, fields, {handle = 'kavin', ik = 'IK', action = 'release.publish'} = {}) => {
  const payload = w.approvalPayload(handle, ik, action, fields);
  return {payload, sig: await signer.sign(payload)};
};

test('a release is trusted only when a built-in release key signed exactly the package it names', async () => {
  const signer = softwareApprover(), keys = [{handle: 'kavin', ik: 'IK', rk: signer.publicKey}];
  assert.equal(readRelease(await signWith(signer, good), keys).version, '0.3.1');
  assert.equal(readRelease(await signWith(softwareApprover(), good), keys), null, 'another key');
  assert.equal(readRelease(await signWith(signer, good, {handle: 'mallory'}), keys), null, 'another signer');
  assert.equal(readRelease(await signWith(signer, good, {ik: 'OTHER'}), keys), null, 'another identity');
  assert.equal(readRelease(await signWith(signer, good, {action: 'invite.create'}), keys), null, 'an approval for something else');
  for (const bad of [{package: 'agentchat-9.9.9.tgz'}, {version: '0.3'}, {sha256: 'nope'}, {size: 0}, {size: 1e9}]) assert.equal(readRelease(await signWith(signer, {...good, ...bad}), keys), null, JSON.stringify(bad));
  const signed = await signWith(signer, good);
  assert.equal(readRelease({...signed, payload: signed.payload.replace('0.3.1', '0.3.2')}, keys), null, 'tampered after signing');
  const stale = JSON.stringify({...JSON.parse(signed.payload), iat: w.now() - 86400 * 30, exp: w.now() - 86400 * 30 + 600});
  assert.equal(readRelease({payload: stale, sig: await signer.sign(stale)}, keys).version, '0.3.1', "a release isn't an approval: it stays valid until a newer one replaces it");
  assert.equal(readRelease(await signWith(signer, good)), null, 'and test keys are never trusted by the real list');
});

test("the built-in release key is this Mac's Secure Enclave release key, which needs Touch ID", {skip: !existsSync(join(homedir(), 'Library', 'Application Support', 'agentchat-release', 'release.key'))}, () => {
  const key = JSON.parse(readFileSync(join(homedir(), 'Library', 'Application Support', 'agentchat-release', 'release.key'), 'utf8'));
  assert.ok(RELEASE_KEYS.some(k => k.rk === key.public_key));
  assert.equal(key.tier, 'se-biometry');
});
