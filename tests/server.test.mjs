import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createNode} from '../lib/node.mjs';
import * as w from '../lib/wire.mjs';
import {relayServer} from '../server/relay.mjs';
import {hookCatcher, memoryKeystore, memoryRedis, softwareApprover} from './fakes.mjs';

// Everything this file, and anything it spawns, puts in the temp folder lands in one folder removed at the end.
const scratch = mkdtempSync(join(tmpdir(), 'agentchat-run-'));
process.env.TMPDIR = process.env.TMP = process.env.TEMP = scratch;
// Windows keeps open databases and killed children's files locked; a leftover folder there is not a test failure.
test.after(() => { try { rmSync(scratch, {recursive: true, force: true, maxRetries: 3}); } catch (error) { if (process.platform !== 'win32') throw error; } });

const RELAY = 'https://sovereign.test';

test('the unchanged relay handlers work behind the self-hosted server, over real HTTP', async () => {
  const redis = memoryRedis(), owners = [], hooks = hookCatcher();
  const server = relayServer({redis, ownerKeys: owners, send: hooks.send});
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  // The client only accepts https relays; this stands in for TLS ending at the proxy in front of the origin.
  const fetchVia = (url, init) => fetch(String(url).replace(RELAY, origin), init);
  const open = keystore => createNode({home: mkdtempSync(join(tmpdir(), 'agentchat-server-')), keystore, approver: softwareApprover(), fetch: fetchVia});
  try {
    const ownerKeys = memoryKeystore(), seed = randomBytes(32);
    await ownerKeys.set('identity', w.b64(seed));
    owners.push(w.identityFromSeed(seed).ik);
    const kavin = await open(ownerKeys);
    await kavin.joinOwner({handle: 'kavin', relay: RELAY});
    const jackson = await open(memoryKeystore());
    await jackson.join((await kavin.invite()).code, {as: 'jackson'});
    await kavin.sync();
    assert.deepEqual((await kavin.whoami()).contacts, [{handle: '@jackson', status: 'connected', verified: true}]);

    const start = new Date(Date.now() + 86400000).toISOString(), end = new Date(Date.now() + 90000000).toISOString();
    const {thread} = await kavin.askAvailability({to: ['jackson'], start, end, minutes: 60, purpose: 'lake day'});
    await jackson.checkInbox();
    await jackson.replyAvailability({thread, status: 'free', slots: [{start, end}]});
    assert.equal((await kavin.getThread({thread})).availability.common_free.length, 1);
    await kavin.shareSpace({space: 'Lake weekend', add: ['jackson']});
    await kavin.writeSpace({space: 'Lake weekend', text: 'meet at the boathouse'});
    assert.equal((await jackson.readSpace({space: 'Lake weekend'})).entries[0].untrusted_text.text, 'meet at the boathouse');
    await jackson.sendMessage({to: ['kavin'], text: 'see you there'});
    assert.ok((await kavin.checkInbox()).items.some(i => i.untrusted_text === 'see you there'), 'DELETE bodies and signed query strings survive the server');
    assert.equal((await jackson.setNotify({url: 'https://hooks.example.com/jackson'})).test.status, 202);

    const stored = JSON.stringify([...redis.data.values()].map(v => (v instanceof Map || v instanceof Set ? [...v] : v)));
    for (const secret of ['lake day', 'Lake weekend', 'meet at the boathouse', 'see you there']) assert.ok(!stored.includes(secret), `relay holds "${secret}"`);
  } finally {
    server.close();
  }
});

test('the self-hosted server caps bodies, ignores client-supplied forwarding hops and serves only the relay', async () => {
  const t = w.now(), redis = memoryRedis();
  const server = relayServer({redis, ownerKeys: [], clock: () => t});
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(`${origin}/api/messages`, {method: 'POST', body: 'x'.repeat(300000)})).status, 413);
    assert.equal((await fetch(`${origin}/dl/agentchat-0.2.0.tgz`)).status, 404, 'downloads stay on the front door');
    const health = await fetch(`${origin}/healthz`);
    assert.deepEqual([health.status, health.headers.get('x-content-type-options')], [200, 'nosniff']);
    const statuses = [];
    for (let i = 0; i < 61; i++) statuses.push((await fetch(`${origin}/api/keys?h=kavin`, {headers: {'x-forwarded-for': `10.9.${i}.1, 203.0.113.7`}})).status);
    assert.equal(statuses.at(-1), 429, 'a forged first hop cannot dodge the per-address limit');
  } finally {
    server.close();
  }
});
