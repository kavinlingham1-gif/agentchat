import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createNode} from '../lib/node.mjs';
import {upstash} from '../lib/relay.mjs';
import {valkey} from '../server/valkey.mjs';
import {memoryKeystore, softwareApprover} from '../tests/fakes.mjs';

// Two throwaway nodes talk through the deployed relay; then every relay key is scanned for plaintext and both handles delete themselves.
const relay = process.env.SMOKE_RELAY, seed = process.env.SMOKE_OWNER_SEED, store = process.env.AGENTCHAT_VALKEY;
if (!relay || !seed || !(store || process.env.KV_REST_API_URL)) {
  console.error('Needs SMOKE_RELAY, SMOKE_OWNER_SEED (whose identity key is in AGENTCHAT_OWNER_KEYS) and the relay\'s storage: the Upstash env from `vercel env pull .env.local`, or AGENTCHAT_VALKEY with a user that may SCAN.');
  process.exit(1);
}

const tag = randomBytes(3).toString('hex'), owner = `smoke_a_${tag}`, friend = `smoke_b_${tag}`, homes = [];
const open = async keystore => { const home = mkdtempSync(join(tmpdir(), 'agentchat-smoke-')); homes.push(home); return createNode({home, keystore, approver: softwareApprover()}); };
const markers = {purpose: `smoke purpose ${tag}`, note: `smoke note ${tag}`, space: `Smoke space ${tag}`, entry: `smoke entry ${tag}`, text: `smoke text ${tag}`};
const start = new Date(Date.now() + 86400000).toISOString(), end = new Date(Date.now() + 90000000).toISOString();
const redis = store ? valkey(store, {user: process.env.AGENTCHAT_VALKEY_USER, password: process.env.AGENTCHAT_VALKEY_PASSWORD}) : upstash();

async function everyValue() {
  const keys = [];
  let cursor = '0';
  do { const [next, batch] = await redis('SCAN', cursor, 'COUNT', 500); cursor = String(next); keys.push(...batch); } while (cursor !== '0');
  const read = {string: k => redis('GET', k), list: k => redis('LRANGE', k, 0, -1), set: k => redis('SMEMBERS', k), zset: k => redis('ZRANGE', k, 0, -1)};
  return {keys, values: await Promise.all(keys.map(async k => read[await redis('TYPE', k)]?.(k)))};
}

try {
  const ownerKeys = memoryKeystore();
  await ownerKeys.set('identity', seed);
  const a = await open(ownerKeys);
  await a.joinOwner({handle: owner, relay});
  const b = await open(memoryKeystore());
  await b.join((await a.invite()).code, {as: friend});
  await a.sync();
  assert.deepEqual((await a.whoami()).contacts, [{handle: `@${friend}`, status: 'connected', verified: true}]);
  console.log(`invite + mutual verification: ok (${owner} <-> ${friend})`);

  const {thread} = await a.askAvailability({to: [friend], start, end, minutes: 60, purpose: markers.purpose});
  assert.equal((await b.checkInbox()).items.find(i => i.kind === 'availability_request').untrusted_text, markers.purpose);
  await b.replyAvailability({thread, status: 'free', slots: [{start, end}], note: markers.note});
  assert.equal((await a.getThread({thread})).availability.common_free.length, 1);
  console.log('availability ask, answer and overlap: ok');

  await a.shareSpace({space: markers.space, add: [friend]});
  await a.writeSpace({space: markers.space, text: markers.entry});
  assert.equal((await b.readSpace({space: markers.space})).entries[0].untrusted_text.text, markers.entry);
  await b.sendMessage({to: [owner], text: markers.text});
  assert.ok((await a.checkInbox()).items.some(i => i.untrusted_text === markers.text));
  console.log('shared space read without approval + message: ok');

  const hook = await a.setNotify({url: `${relay}/api/notify`});
  assert.ok(hook.test?.status >= 300, `the relay's outbound alert should land on its own /api/notify and get a non-2xx; got ${JSON.stringify(hook.test)}`);
  console.log(`outbound alert from the deployed relay: reached ${hook.host} (HTTP ${hook.test.status}): ok`);

  const {keys, values} = await everyValue();
  const dump = JSON.stringify(values);
  for (const [name, marker] of Object.entries(markers)) assert.ok(!dump.includes(marker), `relay stored plaintext: ${name}`);
  console.log(`plaintext scan of ${keys.length} relay keys: clean`);

  await b.leave();
  await a.leave();
  const left = (await everyValue()).keys.filter(k => /^(rec|inbox|env|spaces|invites|hook|pinged):/.test(k) && (k.includes(owner) || k.includes(friend)));
  assert.deepEqual(left, []);
  console.log('both handles deleted their data: ok');
} finally {
  for (const home of homes) rmSync(home, {recursive: true, force: true});
}
