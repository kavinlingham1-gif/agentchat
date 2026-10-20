import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {alertsText} from '../lib/node.mjs';
import * as w from '../lib/wire.mjs';
import {RELAY, hookCatcher, memoryRedis, relayFetch, softwareApprover} from './fakes.mjs';

async function setup({clock, redisClock, send: hookSend = hookCatcher().send} = {}) {
  const redis = memoryRedis(redisClock ?? (clock ? () => clock() * 1000 : undefined)), owners = [];
  const fetch = relayFetch({redis, ownerKeys: owners, send: hookSend, ...(clock ? {clock} : {})});
  const send = async (who, method, path, body) => {
    const text = body === undefined ? '' : JSON.stringify(body);
    const response = await fetch(RELAY + path, {method, headers: {authorization: w.signRequest(who.identity, who.handle, method, path, text)}, body: method === 'GET' ? undefined : text});
    return {status: response.status, body: await response.json()};
  };
  const person = async (handle, {owner = false} = {}) => {
    const identity = w.identityFromSeed(randomBytes(32)), approver = softwareApprover(), box = await w.boxKeypair(), prekey = await w.boxKeypair();
    if (owner) owners.push(identity.ik);
    const who = {handle, identity, approver, box};
    who.record = (fields = {}) => w.makeRecord(identity, {handle, bk: box.pk, ak: approver.publicKey, tier: 'software', prekeys: [{id: 'p1', pk: prekey.pk, exp: w.now() + 86400}], ...fields});
    who.approval = async (action, fields) => { const payload = w.approvalPayload(handle, identity.ik, action, fields); return {payload, sig: await approver.sign(payload)}; };
    return who;
  };
  const register = async (who, invite) => send(who, 'POST', '/api/keys', {...who.record(), ...(invite ? {invite} : {})});
  const invite = async (inviter, validFor = 3600) => {
    const keys = w.inviteKeys(randomBytes(32));
    return {keys, response: await send(inviter, 'POST', '/api/invites', {approval: await inviter.approval('invite.create', {token_hash: keys.tokenHash, valid_until: w.now() + validFor})})};
  };
  return {redis, send, person, register, invite};
}

test('only listed owner keys can register without an invite, and handles cannot be taken twice', async () => {
  const {person, register} = await setup();
  assert.equal((await register(await person('mallory'))).status, 403);
  const kavin = await person('kavin', {owner: true});
  assert.equal((await register(kavin)).status, 201);
  assert.equal((await register(await person('kavin', {owner: true}))).status, 409);
});

test('requests need a valid, fresh, unreplayed signature', async () => {
  const relay = await setup();
  const kavin = await relay.person('kavin', {owner: true});
  await relay.register(kavin);
  assert.equal((await relay.send({...kavin, identity: w.identityFromSeed(randomBytes(32))}, 'GET', '/api/messages')).status, 401);
  const header = w.signRequest(kavin.identity, 'kavin', 'GET', '/api/messages', '');
  const fetch = relayFetch({redis: relay.redis, ownerKeys: []});
  assert.equal((await fetch(`${RELAY}/api/messages`, {headers: {authorization: header}})).status, 200);
  assert.equal((await fetch(`${RELAY}/api/messages`, {headers: {authorization: header}})).status, 401, 'replayed nonce');
  const late = relayFetch({redis: relay.redis, ownerKeys: [], clock: () => w.now() + 600});
  assert.equal((await late(`${RELAY}/api/messages`, {headers: {authorization: w.signRequest(kavin.identity, 'kavin', 'GET', '/api/messages', '')}})).status, 401, 'stale timestamp');
});

test('identity and approval keys cannot be swapped by a request signed only with the identity key', async () => {
  const relay = await setup();
  const kavin = await relay.person('kavin', {owner: true});
  await relay.register(kavin);
  assert.equal((await relay.send(kavin, 'PUT', '/api/keys', kavin.record({prekeys: [{id: 'p2', pk: (await w.boxKeypair()).pk, exp: w.now() + 86400}]}))).status, 200);
  assert.equal((await relay.send(kavin, 'PUT', '/api/keys', kavin.record({ak: softwareApprover().publicKey}))).status, 403);
});

test('invites need a fresh approval for exactly that inviter and action, and work once', async () => {
  const relay = await setup();
  const kavin = await relay.person('kavin', {owner: true}), alex = await relay.person('alex', {owner: true});
  await relay.register(kavin), await relay.register(alex);
  assert.equal((await relay.send(kavin, 'POST', '/api/invites', {})).status, 403, 'no approval');
  assert.equal((await relay.send(kavin, 'POST', '/api/invites', {approval: await kavin.approval('handle.delete', {})})).status, 403, 'wrong action');
  const approval = await kavin.approval('invite.create', {token_hash: w.inviteKeys(randomBytes(32)).tokenHash, valid_until: w.now() + 3600});
  assert.equal((await relay.send(alex, 'POST', '/api/invites', {approval})).status, 403, 'another handle cannot use it');
  assert.equal((await relay.send(kavin, 'POST', '/api/invites', {approval})).status, 201);
  assert.equal((await relay.send(kavin, 'POST', '/api/invites', {approval})).status, 403, 'replayed approval nonce');
  const {keys} = await relay.invite(kavin);
  assert.equal((await relay.register(await relay.person('pranav'), keys.gate)).status, 201);
  assert.equal((await relay.register(await relay.person('sam'), keys.gate)).status, 403, 'single use');
  assert.equal((await relay.register(await relay.person('lee'), w.inviteKeys(randomBytes(32)).gate)).status, 403, 'unknown invite');
});

test('invites expire', async () => {
  let offset = 0;
  const relay = await setup({clock: () => w.now() + offset});
  const kavin = await relay.person('kavin', {owner: true});
  await relay.register(kavin);
  const {keys} = await relay.invite(kavin, 60);
  offset = 120;
  assert.equal((await relay.register(await relay.person('pranav'), keys.gate)).status, 403);
});

test('space access lists need the owner approval and the current version; non-members cannot read', async () => {
  const relay = await setup();
  const kavin = await relay.person('kavin', {owner: true}), pranav = await relay.person('pranav', {owner: true}), mallory = await relay.person('mallory', {owner: true});
  for (const p of [kavin, pranav, mallory]) await relay.register(p);
  const space = w.id(), acl = (who, fields) => who.approval('space.acl', {space, version: 1, prev_version: 0, key_epoch: 1, members: ['kavin', 'pranav'], prev_members: [], name_hash: 'h', ...fields});
  const wraps = {kavin: 'w1', pranav: 'w2'};
  assert.equal((await relay.send(kavin, 'PUT', '/api/spaces', {acl: {payload: (await acl(kavin)).payload, sig: (await acl(mallory)).sig}, wraps})).status, 403, 'signature from another key');
  assert.equal((await relay.send(kavin, 'PUT', '/api/spaces', {acl: await acl(kavin), wraps})).status, 200);
  assert.equal((await relay.send(kavin, 'PUT', '/api/spaces', {acl: await acl(kavin), wraps})).status, 409, 'stale version');
  assert.equal((await relay.send(mallory, 'PUT', '/api/spaces', {acl: await acl(mallory, {version: 2, prev_version: 1, members: ['mallory'], prev_members: ['kavin', 'pranav']}), wraps: {mallory: 'w'}})).status, 403, 'only the owner');
  assert.equal((await relay.send(pranav, 'GET', `/api/spaces?id=${space}`)).status, 200);
  assert.equal((await relay.send(mallory, 'GET', `/api/spaces?id=${space}`)).status, 403);
  assert.equal((await relay.send(mallory, 'POST', '/api/spaces', {space, entry: {id: 'e1', epoch: 1, nonce: 'n', ct: 'c'}})).status, 403);
});

test('deleting a handle needs its approval key and removes its data', async () => {
  const relay = await setup();
  const kavin = await relay.person('kavin', {owner: true});
  await relay.register(kavin);
  await relay.send(kavin, 'PUT', '/api/notify', {url: 'https://hooks.example.com/kavin'});
  assert.equal((await relay.send(kavin, 'DELETE', '/api/keys', {})).status, 403);
  assert.equal((await relay.send(kavin, 'DELETE', '/api/keys', {approval: await kavin.approval('handle.delete', {})})).status, 200);
  for (const key of ['rec:kavin', 'hook:kavin', 'pinged:kavin']) assert.equal(relay.redis.data.has(key), false, key);
});

async function pair(options) {
  const relay = await setup(options);
  const kavin = await relay.person('kavin', {owner: true}), pranav = await relay.person('pranav', {owner: true});
  await relay.register(kavin), await relay.register(pranav);
  const mail = count => relay.send(kavin, 'POST', '/api/messages', {envelopes: Array.from({length: count}, () => ({to: 'pranav', pk: 'p1', ct: 'x'}))});
  const status = async () => (await relay.send(pranav, 'GET', '/api/notify')).body;
  return {relay, kavin, pranav, mail, status};
}

test('alert hooks must be public https URLs, and status never returns the key', async () => {
  const {relay, pranav, status} = await pair();
  for (const url of ['http://hooks.example.com/x', 'https://127.0.0.1/x', 'https://[::1]/x', 'https://localhost/x', 'https://box.local/x', 'https://svc.internal/x', 'https://user:pw@hooks.example.com/x', 'https://intranet/x']) {
    assert.equal((await relay.send(pranav, 'PUT', '/api/notify', {url})).status, 400, url);
  }
  assert.equal((await relay.send(pranav, 'PUT', '/api/notify', {url: 'https://hooks.example.com/x', key: 'has space'})).status, 400);
  assert.equal((await relay.send(pranav, 'PUT', '/api/notify', {url: 'https://hooks.example.com/x', key: 'k3y-secret'})).status, 200);
  const current = await status();
  assert.deepEqual([current.host, current.has_key], ['hooks.example.com', true]);
  assert.ok(!JSON.stringify(current).includes('k3y-secret'));
});

test('mail wakes the recipient once per unread batch, with the bearer key and a fixed body', async () => {
  const hooks = hookCatcher(), {relay, pranav, mail, status} = await pair({send: hooks.send});
  const saved = (await relay.send(pranav, 'PUT', '/api/notify', {url: 'https://hooks.example.com/pranav', key: 'k3y-secret'})).body;
  assert.equal(saved.test.status, 202, 'saving sends a test alert');
  assert.deepEqual([hooks.calls[0].init.headers.authorization, hooks.calls[0].init.body], ['Bearer k3y-secret', '{"source":"agentchat","event":"new_messages"}']);
  assert.ok((await status()).waiting_since, 'the test alert waits for the agent like a real one');
  await mail(1);
  assert.equal(hooks.calls.length, 1, 'already waiting, so no second wake');
  await relay.send(pranav, 'GET', '/api/messages');
  assert.equal((await status()).waiting_since, null, 'checking the inbox answers the alert');
  assert.match(alertsText(await status()), /answered/);
  await mail(2);
  assert.equal(hooks.calls.length, 2, 'the next batch wakes it once');
});

test('re-saving a hook clears a stale wait and sends a fresh test alert', async () => {
  let offset = 0;
  const hooks = hookCatcher(), {relay, pranav, status} = await pair({send: hooks.send, clock: () => w.now() + offset});
  await relay.send(pranav, 'PUT', '/api/notify', {url: 'https://hooks.example.com/pranav'});
  const first = (await status()).waiting_since;
  offset = 120;
  assert.equal((await relay.send(pranav, 'PUT', '/api/notify', {url: 'https://hooks.example.com/pranav'})).body.test.status, 202);
  assert.equal(hooks.calls.length, 2);
  assert.ok((await status()).waiting_since > first);
});

test('a failed alert is retried on the next message, never shown as answered, and never fails the send', async () => {
  const hooks = hookCatcher(), {relay, pranav, mail, status} = await pair({send: hooks.send});
  hooks.respond = () => 401;
  assert.equal((await relay.send(pranav, 'PUT', '/api/notify', {url: 'https://hooks.example.com/pranav'})).body.test.status, 401);
  const failed = await status();
  assert.equal(failed.waiting_since, null);
  assert.match(alertsText(failed), /failed \(HTTP 401\)/);
  assert.doesNotMatch(alertsText(failed), /answered/);
  hooks.respond = () => { throw new Error('hook is down'); };
  assert.equal((await mail(1)).status, 201, 'a broken hook never fails the sender');
  assert.equal(hooks.calls.length, 2, 'retried because the last alert failed');
  assert.match(alertsText(await status()), /failed \(unreachable\)/);
});

test('turning alerts off while an alert is in flight keeps them off', async () => {
  const hooks = hookCatcher(), {relay, pranav, status} = await pair({send: hooks.send});
  let release;
  hooks.respond = () => new Promise(resolve => { release = () => resolve(202); });
  const saving = relay.send(pranav, 'PUT', '/api/notify', {url: 'https://hooks.example.com/pranav'});
  while (!release) await new Promise(resolve => setTimeout(resolve, 1));
  await relay.send(pranav, 'DELETE', '/api/notify');
  release();
  await saving;
  assert.equal((await status()).alerts, false);
  assert.equal(relay.redis.data.has('hook:pranav'), false);
});

test('a wake nobody answers expires after 30 minutes', async () => {
  let later = 0;
  const hooks = hookCatcher(), {relay, pranav, mail} = await pair({send: hooks.send, redisClock: () => Date.now() + later});
  await relay.send(pranav, 'PUT', '/api/notify', {url: 'https://hooks.example.com/pranav'});
  await mail(1);
  assert.equal(hooks.calls.length, 1);
  later = 1801 * 1000;
  await mail(1);
  assert.equal(hooks.calls.length, 2);
});

test('alerts are capped at 20 per hour per handle', async () => {
  const t = w.now(), hooks = hookCatcher(), {relay, pranav, mail, status} = await pair({send: hooks.send, clock: () => t});
  await relay.send(pranav, 'PUT', '/api/notify', {url: 'https://hooks.example.com/pranav'});
  for (let i = 0; i < 20; i++) { await relay.send(pranav, 'GET', '/api/messages'); await mail(1); }
  assert.equal(hooks.calls.length, 20);
  const capped = await status();
  assert.equal(capped.last.skipped, 'hourly cap');
  assert.match(alertsText(capped), /skipped \(hourly cap\)/);
  assert.doesNotMatch(alertsText(capped), /answered/);
});

test('signed requests are rate limited per handle', async () => {
  const t = w.now(), relay = await setup({clock: () => t});
  const kavin = await relay.person('kavin', {owner: true});
  await relay.register(kavin);
  const statuses = [];
  for (let i = 0; i < 121; i++) statuses.push((await relay.send(kavin, 'GET', '/api/messages')).status);
  assert.equal(statuses.at(-1), 429);
});
