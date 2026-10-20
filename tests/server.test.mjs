import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {mkdtempSync, rmSync} from 'node:fs';
import {request} from 'node:http';
import {createServer, isIP} from 'node:net';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createNode} from '../lib/node.mjs';
import * as w from '../lib/wire.mjs';
import {publicSend, relayServer} from '../server/relay.mjs';
import {valkey} from '../server/valkey.mjs';
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

test('the health check covers storage, and with no trusted proxy a client-sent X-Forwarded-For is ignored', async () => {
  const t = w.now(), memory = memoryRedis();
  let up = true;
  const server = relayServer({redis: (...args) => (up ? memory(...args) : Promise.reject(new Error('storage down'))), ownerKeys: [], clock: () => t}, {trustedProxyHops: 0});
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(`${origin}/healthz`)).status, 200);
    up = false;
    assert.equal((await fetch(`${origin}/healthz`)).status, 503);
    up = true;
    const statuses = [];
    for (let i = 0; i < 61; i++) statuses.push((await fetch(`${origin}/api/keys?h=kavin`, {headers: {'x-forwarded-for': `203.0.113.${i}`}})).status);
    assert.equal(statuses.at(-1), 429, 'made-up addresses cannot spread one client over many rate-limit buckets');
  } finally {
    server.close();
  }
});

// The commands a client has sent so far, as arrays of strings, and the bytes of any command still arriving.
function readCommands(buffer) {
  const commands = [];
  let at = 0;
  next: while (buffer[at] === 42) {
    let eol = buffer.indexOf('\r\n', at), i = eol + 2;
    if (eol < 0) break;
    const args = [];
    for (let n = Number(buffer.toString('latin1', at + 1, eol)); n > 0; n--) {
      eol = buffer.indexOf('\r\n', i);
      if (eol < 0) break next;
      const length = Number(buffer.toString('latin1', i + 1, eol));
      if (buffer.length < eol + 4 + length) break next;
      args.push(buffer.toString('utf8', eol + 2, eol + 2 + length));
      i = eol + 4 + length;
    }
    commands.push(args);
    at = i;
  }
  return [commands, buffer.subarray(at)];
}

// A stand-in Valkey: answer(args, socket) returns the raw reply, or null to send nothing.
async function fakeValkey(answer) {
  const seen = [], connections = new Set();
  const server = createServer(socket => {
    connections.add(socket);
    let rest = Buffer.alloc(0);
    socket.on('error', () => {});
    socket.on('data', chunk => {
      const [commands, more] = readCommands(Buffer.concat([rest, chunk]));
      rest = more;
      for (const args of commands) { seen.push(args); const reply = answer(args, socket); if (reply !== null) socket.write(reply); }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {seen, address: `127.0.0.1:${server.address().port}`, close() { for (const socket of connections) socket.destroy(); server.close(); }};
}

test('the Valkey client signs in first, keeps replies in order and fails a lost command instead of resending it', async t => {
  const bulk = text => { const bytes = Buffer.from(text); return Buffer.concat([Buffer.from(`$${bytes.length}\r\n`), bytes, Buffer.from('\r\n')]); };
  const fake = await fakeValkey(([command, ...args], socket) => {
    if (command === 'AUTH') return args.at(-1) === 'pw' ? '+OK\r\n' : '-WRONGPASS invalid username-password pair\r\n';
    if (command === 'SPLIT') { socket.write('$5\r\nhel'); setTimeout(() => socket.write('lo\r\n'), 20); return null; }
    if (command === 'DROP') { socket.destroy(); return null; }
    return {ECHO: () => bulk(args[0]), PING: () => '+PONG\r\n', INCR: () => ':3\r\n', MGET: () => '*2\r\n$1\r\na\r\n$-1\r\n', NONE: () => '*-1\r\n', GET: () => '$-1\r\n', BAD: () => '-ERR wrong\r\n'}[command]?.() ?? null;
  });
  t.after(() => fake.close());
  const redis = valkey(fake.address, {user: 'relay', password: 'pw', timeout: 300}), text = 'h\u00e9llo \u2713 \u96ea';
  assert.deepEqual(await Promise.all([redis('ECHO', text), redis('PING'), redis('INCR', 'n'), redis('MGET', 'a', 'b'), redis('NONE'), redis('GET', 'x'), redis('SPLIT')]), [text, 'PONG', 3, ['a', null], null, null, 'hello']);
  assert.deepEqual(fake.seen.slice(0, 2), [['AUTH', 'relay', 'pw'], ['ECHO', text]], 'it signs in first and sizes arguments in bytes');
  await assert.rejects(redis('BAD'), /redis BAD: ERR wrong/);
  await assert.rejects(redis('HANG'), /redis HANG: timed out/);
  await assert.rejects(redis('DROP'), /redis: /);
  assert.equal(await redis('PING'), 'PONG', 'the next command reconnects');
  assert.deepEqual(['HANG', 'DROP', 'AUTH'].map(c => fake.seen.filter(([seen]) => seen === c).length), [1, 1, 3], 'lost commands are never resent; each connection signs in again');
  await assert.rejects(valkey(fake.address, {user: 'relay', password: 'nope'})('PING'), /WRONGPASS/);
});

test('self-hosted alerts refuse names that resolve into private networks, a tailnet included', async () => {
  const resolvesTo = (...addresses) => (name, options, callback) => callback(null, addresses.map(address => ({address, family: isIP(address)})));
  for (const address of ['127.0.0.1', '10.1.2.3', '100.101.102.103', '192.168.1.20', '169.254.169.254', '::1', 'fd7a:115c:a1e0::1', '::ffff:192.168.0.1', '64:ff9b::c0a8:1']) {
    await assert.rejects(publicSend('https://hooks.example.com/a', {method: 'POST', body: '{}'}, resolvesTo(address)), /private/, address);
  }
  await assert.rejects(publicSend('https://[fd00::1]/a', {method: 'POST'}), /private/);
  // Beside a private address, only the public one is tried; nothing answers at this one, so the attempt fails without being refused.
  await assert.rejects(publicSend('https://hooks.example.com/a', {method: 'POST', signal: AbortSignal.timeout(300)}, resolvesTo('10.0.0.1', '203.0.113.10')), error => !/private/.test(error.message));
});

test('the start command serves the relay on this machine only, or on a socket, storing in Valkey', async t => {
  const fake = await fakeValkey(([command]) => (command === 'PING' ? '+PONG\r\n' : '+OK\r\n'));
  t.after(() => fake.close());
  const start = listen => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('../server/start.mjs', import.meta.url))], {env: {...process.env, AGENTCHAT_LISTEN: listen, AGENTCHAT_VALKEY: fake.address, AGENTCHAT_VALKEY_USER: 'relay', AGENTCHAT_VALKEY_PASSWORD: 'pw'}, stdio: ['ignore', 'pipe', 'inherit']});
    t.after(() => child.kill());
    let out = '';
    child.stdout.on('data', chunk => { out += chunk; const started = /agentchat relay on (\S+), storing in Valkey/.exec(out); if (started) resolve(started[1]); });
    child.on('exit', code => reject(new Error(`start.mjs exited with ${code}: ${out}`)));
  });
  const where = await start('0');
  assert.match(where, /^127\.0\.0\.1:\d+$/, 'a bare port stays on this machine');
  const health = await fetch(`http://${where}/healthz`);
  assert.deepEqual([health.status, await health.text()], [200, 'ok']);
  assert.ok(fake.seen.some(args => args.join(' ') === 'AUTH relay pw'));
  if (process.platform === 'win32') return;
  const dir = mkdtempSync('/tmp/ac-');
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const socketPath = await start(join(dir, 'r.sock'));
  assert.equal(await new Promise((resolve, reject) => request({socketPath, path: '/healthz'}, res => { res.resume(); resolve(res.statusCode); }).on('error', reject).end()), 200);
});
