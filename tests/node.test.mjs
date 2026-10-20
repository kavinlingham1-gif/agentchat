import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {InMemoryTransport, McpServer} from '@modelcontextprotocol/server';
import {softwareKey} from '../lib/approval.mjs';
import {installRoot} from '../lib/install.mjs';
import {fileKeystore} from '../lib/keychain.mjs';
import {VERSION, alertsText, createNode, instructionsFor, keyTier, rulesFor, stableNode, wiring} from '../lib/node.mjs';
import {defaultHome} from '../lib/store.mjs';
import {mcpServer, toolsFor} from '../lib/tools.mjs';
import * as w from '../lib/wire.mjs';
import {RELAY, hookCatcher, memoryKeystore, network, softwareApprover} from './fakes.mjs';

// Everything this file, and anything it spawns, puts in the temp folder lands in one folder removed at the end.
const scratch = mkdtempSync(join(tmpdir(), 'agentchat-run-'));
process.env.TMPDIR = process.env.TMP = process.env.TEMP = scratch;
// Windows keeps open databases and killed children's files locked; a leftover folder there is not a test failure.
test.after(() => { try { rmSync(scratch, {recursive: true, force: true, maxRetries: 3}); } catch (error) { if (process.platform !== 'win32') throw error; } });

const window = {start: '2026-10-10T12:00:00-05:00', end: '2026-10-10T18:00:00-05:00'};
const envelopesFor = (net, handle) => [...net.redis.data.keys()].filter(k => k.startsWith(`env:${handle}:`));

test('three people plan through their agents', async t => {
  const net = network();
  const kavin = await net.owner('kavin');
  const pranav = await net.invited(kavin, 'pranav');
  const alex = await net.invited(kavin, 'alex');
  let thread;

  await t.test('an invite verifies both people without comparing numbers', async () => {
    assert.deepEqual((await kavin.whoami()).contacts, [{handle: '@alex', status: 'connected', verified: true}, {handle: '@pranav', status: 'connected', verified: true}]);
    assert.deepEqual((await pranav.whoami()).contacts, [{handle: '@kavin', status: 'connected', verified: true}]);
    assert.ok((await kavin.checkInbox()).items.some(i => i.kind === 'notice' && /@pranav joined/.test(i.text)));
  });

  await t.test("each friend's agent answers with free slots only and the overlap is computed", async () => {
    ({thread} = await kavin.askAvailability({to: ['@pranav', 'alex'], ...window, minutes: 120, purpose: 'hike on the river trail', my_slots: [{start: '2026-10-10T13:00:00-05:00', end: '2026-10-10T18:00:00-05:00'}]}));
    const request = (await pranav.checkInbox()).items.find(i => i.kind === 'availability_request');
    assert.equal(request.from, '@kavin');
    assert.equal(request.untrusted_text, 'hike on the river trail');
    const reply = await pranav.replyAvailability({thread, status: 'partly_free', slots: [{start: '2026-10-10T14:00:00-05:00', end: '2026-10-10T17:30:00-05:00'}], note: 'free after lunch'});
    assert.deepEqual(reply.not_sent_to, ['@alex'], 'pranav and alex are not contacts, so only kavin gets the reply');
    await alex.checkInbox();
    await alex.replyAvailability({thread, status: 'free', slots: [{start: '2026-10-10T12:00:00-05:00', end: '2026-10-10T16:30:00-05:00'}]});
    const view = await kavin.getThread({thread});
    assert.deepEqual(view.availability.common_free, [{start: '2026-10-10T19:00:00.000Z', end: '2026-10-10T21:30:00.000Z'}]);
    assert.deepEqual(view.availability.waiting_on, []);
  });

  await t.test('a plan is confirmed only when everyone approves with their own key', async () => {
    const {plan} = await kavin.proposePlan({thread, title: 'Sunset hike', start: '2026-10-10T14:00:00-05:00', end: '2026-10-10T16:00:00-05:00', place: 'the riverside trailhead'});
    await pranav.checkInbox();
    await pranav.respondToPlan({thread, decision: 'accept'});
    assert.equal(pranav.approver.prompts.at(-1).payload.action, 'plan.confirm');
    await alex.checkInbox();
    alex.approver.fail = 'no-interaction';
    await assert.rejects(alex.respondToPlan({thread, decision: 'accept'}), /run this in Terminal: agentchat call respond_to_plan '\{"thread":"[^"]+","plan":"[^"]+","decision":"accept"\}'/);
    alex.approver.fail = 'canceled';
    await assert.rejects(alex.respondToPlan({thread, decision: 'accept'}), /Not approved: Touch ID was cancelled/);
    alex.approver.fail = null;
    await assert.rejects(alex.respondToPlan({thread, decision: 'accept'}), /wait \d+ seconds/, 'a cancel pauses further prompts');
    assert.notEqual((await kavin.getThread({thread})).plans[0].status, 'confirmed');
    alex.store.meta('prompt.cooldown', '0');
    await alex.respondToPlan({thread, decision: 'accept'});
    const status = (await kavin.getThread({thread})).plans.find(p => p.plan === plan);
    assert.equal(status.status, 'confirmed');
    assert.deepEqual(status.responses['@pranav'], {decision: 'accept', confirmed_with: 'software key'});
    assert.notEqual(status.responses['@alex'].confirmed_with, 'Touch ID', 'a software key never shows as Touch ID');
    for (const friend of [pranav, alex]) {
      const view = await friend.getThread({thread});
      assert.deepEqual([view.plans[0].status, view.plans[0].reported_by], ['confirmed', '@kavin'], 'friends hear the outcome from the proposer');
      assert.equal(view.availability.common_free, undefined, 'only the asker sees the overlap');
      assert.ok(view.availability.your_answer);
    }
  });

  await t.test("the best friend's agent reads the shared project with no prompt to anyone", async () => {
    const kavinPrompts = kavin.approver.prompts.length;
    assert.deepEqual((await kavin.shareSpace({space: 'Lake trip', add: ['pranav']})).members, ['@kavin', '@pranav']);
    assert.equal(kavin.approver.prompts.length, kavinPrompts + 1);
    assert.deepEqual(kavin.approver.prompts.at(-1).labels.name, 'Lake trip');
    await kavin.writeSpace({space: 'Lake trip', title: 'Cabin', text: 'Cabin key under the blue pot, check-in after 4pm'});
    const pranavPrompts = pranav.approver.prompts.length;
    const read = await pranav.readSpace({space: 'lake trip'});
    assert.equal(read.entries[0].untrusted_text.text, 'Cabin key under the blue pot, check-in after 4pm');
    assert.equal(pranav.approver.prompts.length, pranavPrompts);
    assert.equal(kavin.approver.prompts.length, kavinPrompts + 1);
    assert.equal(read.untrusted_text, 'Lake trip', "a name a friend chose is marked untrusted");
    const listed = (await pranav.whoami()).spaces[0];
    assert.deepEqual([listed.name, listed.untrusted_text, listed.id], [undefined, 'Lake trip', read.space]);
    assert.ok((await pranav.checkInbox()).items.some(i => i.kind === 'notice' && i.space === read.space && i.untrusted_text === 'Lake trip' && !i.text.includes('Lake trip')));
    await pranav.writeSpace({space: 'Lake trip', text: 'I will bring the kayak'});
    assert.ok((await kavin.readSpace({space: 'Lake trip'})).entries.some(e => e.by === '@pranav' && e.untrusted_text.text === 'I will bring the kayak'));
  });

  await t.test('contact requests need both owners, and only verified contacts can join a space', async () => {
    await pranav.addContact({handle: '@alex', note: 'from the hike'});
    await alex.checkInbox();
    const [request] = alex.approvals();
    assert.match(request.what, /@pranav wants to connect/);
    await alex.approve({id: request.id});
    await pranav.checkInbox();
    assert.deepEqual((await pranav.whoami()).contacts.find(c => c.handle === '@alex'), {handle: '@alex', status: 'connected', verified: false});
    await assert.rejects(pranav.shareSpace({space: 'Gear list', add: ['alex']}), /isn't verified yet/);
  });

  await t.test('removing a member rotates the key so new entries stay unreadable to them', async () => {
    const removal = await kavin.shareSpace({space: 'Lake trip', remove: ['pranav']});
    assert.deepEqual(removal.removed, ['@pranav']);
    await kavin.writeSpace({space: 'Lake trip', text: 'New meeting spot: the north pavilion'});
    const after = await pranav.readSpace({space: 'Lake trip'});
    assert.match(after.note, /removed/);
    assert.ok(!JSON.stringify(after.entries).includes('New meeting spot: the north pavilion'));
    const space = [...net.redis.data.keys()].find(k => k.endsWith(':log')).split(':')[1];
    const newest = JSON.parse(net.redis.data.get(`space:${space}:log`).at(-1));
    assert.equal(newest.epoch, 2);
    const oldKey = pranav.store.get('select key from space_keys where space = ? and epoch = 1', space).key;
    assert.equal(await w.openEntry(newest, space, pranav.store.open(oldKey, `space-key:${space}:1`)), null);
    assert.equal(pranav.store.get('select 1 from space_keys where space = ? and epoch = 2', space), undefined);
  });

  await t.test("a relay that swaps someone's keys gets the contact locked instead of a silent interception", async () => {
    const attacker = w.identityFromSeed(randomBytes(32));
    net.redis.data.set('rec:alex', JSON.stringify(w.makeRecord(attacker, {handle: 'alex', bk: (await w.boxKeypair()).pk, ak: softwareApprover().publicKey, tier: 'se-biometry', prekeys: [{id: 'evil', pk: (await w.boxKeypair()).pk, exp: w.now() + 86400}]})));
    await assert.rejects(kavin.sendMessage({to: ['alex'], text: 'are you in?'}), /keys changed/);
    const mine = await kavin.whoami();
    assert.equal(mine.contacts.find(c => c.handle === '@alex').status, 'locked');
    const rekey = mine.approvals_needed.find(a => /@alex's keys changed/.test(a.what));
    assert.equal(rekey.owner_runs, 'agentchat verify alex');
    await assert.rejects(kavin.shareSpace({space: 'Lake trip', add: ['alex']}), /not a connected contact/);
    await assert.rejects(kavin.approve({id: rekey.id}), /agents can't accept @alex's new keys/, 'agents cannot re-trust swapped keys');
    assert.equal((await kavin.verify('alex')).keys_changed, true);
    await kavin.verify('alex', {confirm: true});
    assert.deepEqual((await kavin.whoami()).contacts.find(c => c.handle === '@alex'), {handle: '@alex', status: 'connected', verified: true}, 'only the owner, in Terminal, re-trusts');
  });

  await t.test('a friend who was offline for weeks still reads what was sent meanwhile', async () => {
    await kavin.sendMessage({to: ['pranav'], text: 'sent while you were away'});
    pranav.store.run('update prekeys set exp = ?', w.now() - 60);
    assert.ok((await pranav.checkInbox()).items.some(i => i.untrusted_text === 'sent while you were away'));
    assert.equal(pranav.store.get('select count(*) n from prekeys where exp < ?', w.now()).n, 0, 'expired prekeys are deleted only after reading');
    assert.equal(pranav.store.get('select count(*) n from prekeys').n, 1, 'and a fresh one replaces them');
  });

  await t.test('a refused send does not cause a false gap warning later', async () => {
    const day = `sent:kavin:${Math.floor(w.now() / 86400)}`;
    net.redis.data.set(day, '999999');
    await assert.rejects(kavin.sendMessage({to: ['pranav'], text: 'refused'}), /Daily sending limit/);
    net.redis.data.delete(day);
    await kavin.sendMessage({to: ['pranav'], text: 'after a refusal'});
    assert.equal((await pranav.checkInbox()).items.find(i => i.untrusted_text === 'after a refusal').warning, undefined);
  });

  const textsFromKavin = () => pranav.store.get("select count(*) n from messages where sender = 'kavin' and type = 'text'").n;

  await t.test('two agents syncing the same Mac at once store each message exactly once', async () => {
    const twin = await net.open(pranav.keystore, pranav.approver, pranav.home), before = textsFromKavin();
    await kavin.sendMessage({to: ['pranav'], text: 'are you driving?'});
    await Promise.all([pranav.sync(), twin.sync()]);
    assert.equal(textsFromKavin(), before + 1);
    twin.close();
  });

  await t.test('a replayed or duplicated envelope is ignored', async () => {
    await kavin.sendMessage({to: ['pranav'], text: 'replay me'});
    const original = JSON.parse(net.redis.data.get(envelopesFor(net, 'pranav')[0]));
    await pranav.checkInbox();
    const before = textsFromKavin();
    for (const id of [original.id, w.id()]) {
      net.redis.data.set(`env:pranav:${id}`, JSON.stringify({...original, id}));
      await net.redis('ZADD', 'inbox:pranav', w.now(), id);
    }
    assert.equal((await pranav.checkInbox()).items.filter(i => i.untrusted_text === 'replay me').length, 0);
    assert.equal(textsFromKavin(), before);
  });

  await t.test('a gap in the sequence is flagged', async () => {
    kavin.store.run("update seqs set sent = sent + 3 where peer = 'pranav'");
    await kavin.sendMessage({to: ['pranav'], text: 'after a gap'});
    assert.match((await pranav.checkInbox()).items.find(i => i.untrusted_text === 'after a gap').warning, /may not have arrived/);
  });

  await t.test('a message sealed to a deleted prekey cannot be read', async () => {
    await kavin.sendMessage({to: ['pranav'], text: 'sealed to an old key'});
    pranav.store.run('delete from prekeys');
    assert.ok(!(await pranav.checkInbox()).items.some(i => i.untrusted_text === 'sealed to an old key'));
    assert.deepEqual(envelopesFor(net, 'pranav'), [], 'acknowledged and gone from the relay');
  });

  await t.test('the relay never stored any plaintext', () => {
    const everything = JSON.stringify([...net.redis.data.values()].map(v => (v instanceof Map || v instanceof Set ? [...v] : v)));
    for (const secret of ['hike on the river trail', 'free after lunch', 'Sunset hike', 'the riverside trailhead', 'Lake trip', 'Cabin key under the blue pot', 'New meeting spot: the north pavilion', 'I will bring the kayak', 'from the hike', 'are you driving', 'replay me', 'after a gap', 'sent while you were away', 'after a refusal']) {
      assert.ok(!everything.includes(secret), `relay holds "${secret}"`);
    }
  });
});

test('someone leaving does not break replies in threads they were part of', async () => {
  const net = network();
  const kavin = await net.owner('kavin');
  const pranav = await net.invited(kavin, 'pranav'), alex = await net.invited(kavin, 'alex');
  await pranav.addContact({handle: 'alex'});
  await alex.checkInbox();
  await alex.approve({id: alex.approvals()[0].id});
  await pranav.checkInbox();
  const {thread} = await kavin.askAvailability({to: ['pranav', 'alex'], ...window, minutes: 60});
  await pranav.checkInbox();
  await alex.leave();
  const reply = await pranav.replyAvailability({thread, status: 'free', slots: [window]});
  assert.deepEqual(reply.not_sent_to, ['@alex']);
  assert.deepEqual((await kavin.getThread({thread})).availability.answers['@pranav'].status, 'free');
});

test("a friend's agent is alerted when mail arrives, once, until it checks in", async () => {
  const hooks = hookCatcher(), net = network({send: hooks.send});
  const kavin = await net.owner('kavin'), pranav = await net.invited(kavin, 'pranav');
  assert.equal((await pranav.setNotify({url: 'https://hooks.example.com/pranav', key: 'k3y-secret'})).test.status, 202);
  assert.match(alertsText(await pranav.notifyStatus()), /alert waiting since/);
  await pranav.checkInbox();
  assert.match(alertsText(await pranav.notifyStatus()), /answered/);
  const asked = await kavin.askAvailability({to: ['pranav'], ...window, minutes: 60});
  assert.doesNotMatch(asked.next, /check-in/);
  await kavin.sendMessage({thread: asked.thread, text: 'no rush'});
  assert.equal(hooks.calls.length, 2, 'the test alert plus one wake for both messages');
  assert.equal((await pranav.checkInbox()).items.filter(i => i.from === '@kavin').length, 2);
  assert.deepEqual(await pranav.clearNotify(), {alerts: false});
  assert.match(alertsText(await pranav.notifyStatus()), /Alerts are off/);
});

test('re-running join --owner only updates the package fingerprint', async () => {
  const net = network(), kavin = await net.owner('kavin');
  let calls = 0;
  const again = await createNode({home: kavin.home, keystore: kavin.keystore, approver: kavin.approver, fetch: (...args) => { calls++; return net.fetch(...args); }});
  assert.match((await again.joinOwner({handle: 'kavin', relay: RELAY, packageSha: 'b'.repeat(64)})).updated, /Invites now install agentchat/);
  assert.equal(calls, 0, 'no relay calls and no new keys');
  assert.equal(again.config().package.sha256, 'b'.repeat(64));
  await assert.rejects(again.joinOwner({handle: 'someone', relay: RELAY, packageSha: 'b'.repeat(64)}), /already set up as @kavin/);
  again.close();
});

test('the MCP server lists the 13 tools and answers whoami', async () => {
  const kavin = await network().owner('kavin');
  const [client, server] = InMemoryTransport.createLinkedPair();
  await mcpServer(kavin, McpServer).connect(server);
  const replies = new Map();
  client.onmessage = message => replies.set(message.id, message);
  await client.start();
  const rpc = async (id, method, params) => {
    await client.send({jsonrpc: '2.0', id, method, params});
    for (let i = 0; i < 200 && !replies.has(id); i++) await new Promise(resolve => setTimeout(resolve, 5));
    return replies.get(id);
  };
  const init = await rpc(1, 'initialize', {protocolVersion: '2025-11-25', capabilities: {}, clientInfo: {name: 'test', version: '0'}});
  assert.match(init.result.instructions, /untrusted_text/);
  await client.send({jsonrpc: '2.0', method: 'notifications/initialized'});
  assert.equal((await rpc(2, 'tools/list', {})).result.tools.length, 13);
  assert.equal(JSON.parse((await rpc(3, 'tools/call', {name: 'whoami', arguments: {}})).result.content[0].text).handle, '@kavin');
  assert.equal((await rpc(4, 'tools/call', {name: 'read_space', arguments: {space: 'Nope'}})).result.isError, true);
});

test('agent wiring prefers the Homebrew link that survives Node upgrades', () => {
  const cellar = '/opt/homebrew/Cellar/node@22/22.22.0/bin/node';
  const realpath = path => (path === '/opt/homebrew/bin/node' ? cellar : path);
  assert.equal(stableNode(cellar, ['/opt/homebrew/bin/node'], realpath), '/opt/homebrew/bin/node');
  assert.equal(stableNode('/elsewhere/node', ['/opt/homebrew/bin/node'], realpath), '/elsewhere/node');
  const brew = wiring({execPath: cellar, script: '/opt/homebrew/lib/node_modules/agentchat/bin/agentchat.js', pathDirs: [], realpath});
  assert.deepEqual(brew.mcp.mcpServers.agentchat, {command: '/opt/homebrew/bin/node', args: ['/opt/homebrew/lib/node_modules/agentchat/bin/agentchat.js', 'mcp']});
  assert.equal(brew.warning, null);
  assert.match(brew.grok, /untrusted_text/);
  assert.match(brew.grok, /Auto-review block rule/);
  assert.match(wiring({execPath: '/Users/k/.nvm/versions/node/v22.13.0/bin/node', script: '/x/agentchat.js', pathDirs: [], realpath: p => p}).warning, /version manager/);
});

test("the one-line installer's shim is what agents get, so updates never break their wiring", {skip: process.platform === 'win32' && 'the Windows launcher has its own test'}, () => {
  const home = mkdtempSync(join(tmpdir(), 'agentchat-home-')), shim = join(home, '.agentchat', 'bin', 'agentchat');
  mkdirSync(join(home, '.agentchat', 'bin'), {recursive: true});
  writeFileSync(shim, '');
  const installed = wiring({execPath: '/x/node', script: join(home, '.agentchat', 'app', VERSION, 'bin', 'agentchat.js'), pathDirs: [], realpath: p => p, home, platform: 'darwin'});
  assert.deepEqual([installed.command, installed.args, installed.mcp.mcpServers.agentchat], [shim, ['mcp'], {command: shim, args: ['mcp']}]);
  assert.ok(installed.grok.includes(`"${shim}" call check_inbox`));
  assert.equal(wiring({execPath: '/x/node', script: '/checkout/bin/agentchat.js', pathDirs: [], realpath: p => p, home, platform: 'darwin'}).command, '/x/node', 'a dev checkout keeps node + script');
});

test('an invite is one pasted line per OS that checks the package, installs it and joins under the chosen name', async () => {
  const net = network(), kavin = await net.owner('kavin'), sha = 'c'.repeat(64), file = `agentchat-${VERSION}.tgz`;
  await kavin.joinOwner({handle: 'kavin', relay: RELAY, packageSha: sha});
  const named = await kavin.invite({for: '@Sam'});
  assert.ok(named.message.includes(`Mac or Linux: paste this into Terminal (macOS 13.5+ or 64-bit Linux):\ncd "$(mktemp -d)" && curl -fsSLO ${RELAY}/dl/${file} && echo "${sha}  ${file}" | $(command -v shasum >/dev/null && echo 'shasum -a 256' || echo sha256sum) -c - && tar xzf ${file} && sh package/install.sh ${named.code} --as sam\n`));
  assert.ok(named.message.includes(`Windows 10 or 11: paste this into PowerShell:\n$ErrorActionPreference='Stop'; `));
  assert.ok(named.message.includes(`if ((Get-FileHash ${file} -Algorithm SHA256).Hash -ne '${sha}') { throw 'The download did not match its fingerprint.' }; & "$env:SystemRoot\\System32\\tar.exe" -xzf ${file}; powershell -NoProfile -ExecutionPolicy Bypass -File package\\install.ps1 ${named.code} --as sam\n`));
  assert.doesNotMatch(named.message, /Not on a Mac/);
  const plain = await kavin.invite();
  assert.ok(plain.message.includes(`sh package/install.sh ${plain.code}\n`), 'with no chosen name the line leaves --as out');
  assert.match(plain.message, /Not on a Mac\? Add --as <your name> to the end of the line\./, 'Linux and Windows have no username to fall back on');
  assert.doesNotMatch(named.message + plain.message, /yourname|Node 22/);
  assert.equal(w.decodeInvite(plain.code).p, sha, 'the code itself still carries the package');
  kavin.store.meta('config', JSON.stringify({...kavin.config(), package: {sha256: sha, url: `${RELAY}/dl/agentchat-0.2.0.tgz`}}));
  const macOnly = (await kavin.invite()).message;
  assert.match(macOnly, /Paste this into Terminal on your Mac/, "0.2.0's installer only runs on macOS");
  assert.doesNotMatch(macOnly, /Windows|Linux|install\.ps1/);
  kavin.store.meta('config', JSON.stringify({...kavin.config(), package: {sha256: sha, url: `${RELAY}/dl/agentchat-0.1.1.tgz`}}));
  const legacy = (await kavin.invite()).message;
  assert.match(legacy, /npm i -g \/tmp\/agentchat\.tgz/, 'a package without install.sh keeps the npm instructions');
  assert.doesNotMatch(legacy, /install\.sh|yourname/);
});

test("an installer run on a set-up Mac records only a package of exactly this version, so invites never pin the wrong file", async () => {
  const net = network(), kavin = await net.owner('kavin'), kept = 'a'.repeat(64), next = 'b'.repeat(64);
  await kavin.joinOwner({handle: 'kavin', relay: RELAY, packageSha: kept});
  for (const packageVersion of [undefined, '0.0.1', '99.0.0']) assert.equal((await kavin.afterInstall({packageSha: next, packageVersion})).handle, '@kavin');
  assert.equal(kavin.config().package.sha256, kept);
  await kavin.afterInstall({packageSha: next, packageVersion: VERSION});
  assert.deepEqual(kavin.config().package, {sha256: next, url: `${RELAY}/dl/agentchat-${VERSION}.tgz`});
});

test('inviting someone who already has a handle is refused before Touch ID', async () => {
  const net = network(), kavin = await net.owner('kavin');
  await net.invited(kavin, 'pranav');
  const prompts = kavin.approver.prompts.length;
  await assert.rejects(kavin.invite({for: '@pranav'}), /already on this relay.*add_contact @pranav/);
  await assert.rejects(kavin.invite({for: 'kavin'}), /That's you/);
  assert.equal(kavin.approver.prompts.length, prompts);
});

test('pasting the install line again after a lost response finishes the join instead of dead-ending on "taken"', async () => {
  const net = network(), kavin = await net.owner('kavin'), {code} = await kavin.invite();
  let lose = true;
  const flaky = async (url, init) => {
    const response = await net.fetch(url, init);
    if (lose && init?.method === 'POST' && new URL(url).pathname === '/api/keys') { lose = false; throw new TypeError('fetch failed'); }
    return response;
  };
  const home = mkdtempSync(join(tmpdir(), 'agentchat-test-')), keystore = memoryKeystore(), approver = softwareApprover();
  const first = await createNode({home, keystore, approver, fetch: flaky});
  await assert.rejects(first.join(code, {as: 'sam'}), /Could not reach the Agentchat relay/);
  first.close();
  const again = await createNode({home, keystore, approver, fetch: flaky});
  assert.equal((await again.join(code, {as: 'sam'})).connected_to, '@kavin');
  await kavin.sync();
  assert.deepEqual((await kavin.whoami()).contacts, [{handle: '@sam', status: 'connected', verified: true}]);
  await assert.rejects((await net.open()).join((await kavin.invite()).code, {as: 'sam'}), /@sam is taken/, "someone else's keys still can't take the handle");
});

test("a friend's introduction is resent until it lands, always before their first message, and dropped after a week", async () => {
  const net = network(), kavin = await net.owner('kavin');
  const joinDroppingHello = async (code, as) => {
    let drop = true;
    const fetch = async (url, init) => {
      if (drop && init?.method === 'POST' && new URL(url).pathname === '/api/messages') { drop = false; throw new TypeError('fetch failed'); }
      return net.fetch(url, init);
    };
    const node = await createNode({home: mkdtempSync(join(tmpdir(), 'agentchat-test-')), keystore: memoryKeystore(), approver: softwareApprover(), fetch});
    return {node, joined: await node.join(code, {as})};
  };

  const {node: sam, joined} = await joinDroppingHello((await kavin.invite()).code, 'sam');
  assert.match(joined.pending, /retries/);
  await kavin.sync();
  assert.deepEqual((await kavin.whoami()).contacts, [], 'kavin has not heard from sam yet');
  await sam.sendMessage({to: ['kavin'], text: 'made it'});
  const [helloAt, messageAt] = envelopesFor(net, 'kavin').map(key => JSON.parse(net.redis.data.get(key)).at);
  assert.ok(messageAt > helloAt, 'the message is filed a second after the introduction, so Redis cannot reorder them');
  const inbox = await kavin.checkInbox();
  assert.ok(inbox.items.some(i => i.kind === 'notice' && /@sam joined/.test(i.text)));
  assert.ok(inbox.items.some(i => i.untrusted_text === 'made it'), 'the first message arrives after the introduction, so it is kept');
  assert.equal(sam.store.meta('pending.hello'), null);

  const {node: lee} = await joinDroppingHello((await kavin.invite()).code, 'lee');
  await lee.sync();
  await kavin.sync();
  assert.ok((await kavin.whoami()).contacts.some(c => c.handle === '@lee' && c.verified), 'the next sync delivers it');

  const {node: max} = await joinDroppingHello((await kavin.invite()).code, 'max');
  const stale = JSON.parse(max.store.meta('pending.hello'));
  max.store.meta('pending.hello', JSON.stringify({...stale, at: w.now() - 8 * 86400}));
  const before = envelopesFor(net, 'kavin').length;
  await max.sync();
  assert.equal(max.store.meta('pending.hello'), null);
  assert.equal(envelopesFor(net, 'kavin').length, before, 'a week-old introduction is not sent; the invite has expired');
});

test("the installer's run on a Mac with no invite creates no store and no Keychain item", {skip: process.platform !== 'darwin'}, () => {
  const home = mkdtempSync(join(tmpdir(), 'agentchat-home-'));
  const out = execFileSync(process.execPath, [fileURLToPath(new URL('../bin/agentchat.js', import.meta.url)), 'join', '--package-sha', 'a'.repeat(64)], {env: {...process.env, HOME: home}, encoding: 'utf8'});
  assert.match(out, /is installed\. To join, paste the line from your invite\./);
  assert.equal(existsSync(join(home, 'Library')), false);
});

// A temp HOME's own data folder, laid out the way a fresh `agentchat` process on this OS looks for it.
const tempHome = () => mkdtempSync(join(tmpdir(), 'agentchat-home-'));
const childEnv = home => ({...process.env, HOME: home, USERPROFILE: home, LOCALAPPDATA: join(home, 'AppData', 'Local')});
const dataHomeOf = home => defaultHome({home, env: childEnv(home)});

test('a software node (Linux, Windows, or a Mac set up with --agent) keeps its keys in files and contacts see "software key"', async () => {
  const net = network(), kavin = await net.owner('kavin'), home = tempHome(), dataHome = dataHomeOf(home);
  const bot = await createNode({home: dataHome, agent: true, fetch: net.fetch, autoUpdate: null});
  await bot.join((await kavin.invite()).code, {as: 'kavin_grok'});
  await kavin.sync();
  assert.equal(keyTier(dataHome), 'software');
  assert.equal(bot.software, true);
  assert.equal((await bot.whoami()).approvals_by, 'software key');
  assert.match((await bot.whoami()).rules, /take effect immediately, so do them only when your owner asked/);
  if (process.platform !== 'win32') assert.equal(statSync(join(dataHome, 'keys.json')).mode & 0o777, 0o600);

  const {thread} = await kavin.askAvailability({to: ['kavin_grok'], start: '2026-10-10T12:00:00-05:00', end: '2026-10-10T18:00:00-05:00', minutes: 60});
  const {plan} = await kavin.proposePlan({thread, title: 'Lake day', start: '2026-10-10T13:00:00-05:00', end: '2026-10-10T14:00:00-05:00'});
  await bot.checkInbox();
  await bot.respondToPlan({thread, decision: 'accept'});
  assert.equal((await kavin.getThread({thread})).plans.find(p => p.plan === plan).responses['@kavin_grok'].confirmed_with, 'software key', 'the honest label reaches the other side');

  // A fresh process finds the same identity in the files, without the Keychain.
  const out = execFileSync(process.execPath, [fileURLToPath(new URL('../bin/agentchat.js', import.meta.url)), 'call', 'whoami'], {env: childEnv(home), encoding: 'utf8'});
  const seen = JSON.parse(out);
  assert.deepEqual([seen.handle, seen.fingerprint, seen.approvals_by], ['@kavin_grok', (await bot.whoami()).fingerprint, 'software key']);
});

test('the key mode is chosen once: --agent never turns an existing Touch ID node into a software one, and key files are never replaced', async () => {
  const home = mkdtempSync(join(tmpdir(), 'agentchat-data-'));
  writeFileSync(join(home, 'approval.key'), JSON.stringify({tier: 'se-biometry', public_key: 'x', blob: 'y'}));
  writeFileSync(join(home, 'node.db'), '');
  await assert.rejects(createNode({home, agent: true, autoUpdate: null}), /already has an Agentchat identity; --agent only applies/);
  const keys = fileKeystore(join(mkdtempSync(join(tmpdir(), 'agentchat-keys-')), 'keys.json'));
  await keys.set('identity', 'first');
  await keys.set('identity', 'first');
  await assert.rejects(keys.set('identity', 'second'), /Refusing to replace the identity key/);
  assert.equal(await keys.get('identity'), 'first');
  const broken = join(mkdtempSync(join(tmpdir(), 'agentchat-keys-')), 'keys.json');
  writeFileSync(broken, '{not json');
  await assert.rejects(fileKeystore(broken).get('storage'), /Can't read/, 'a damaged key file is reported, never silently treated as empty');
});

test('a software key signs only Agentchat approvals, and its signatures verify against its public key', async () => {
  const file = join(mkdtempSync(join(tmpdir(), 'agentchat-sk-')), 'approval.key'), key = softwareKey(file);
  const created = key.create();
  writeFileSync(file, JSON.stringify(created));
  const payload = w.approvalPayload('sam', 'ik', 'plan.confirm', {plan: 'p'});
  assert.equal(w.verifyApprovalSignature(created.public_key, payload, await key.sign(payload)), true);
  await assert.rejects(key.sign(JSON.stringify({ctx: 'agentchat/v1/approval', action: 'wire.money'})), /not an Agentchat approval/);
  await assert.rejects(key.sign('hello'), /not an Agentchat approval/);
});

test('off macOS there is no username to fall back on, so a handle must be chosen', async () => {
  const net = network(), kavin = await net.owner('kavin');
  const linux = await createNode({home: mkdtempSync(join(tmpdir(), 'agentchat-linux-')), keystore: memoryKeystore(), approver: softwareApprover(), fetch: net.fetch, platform: 'linux', autoUpdate: null});
  await assert.rejects(linux.join((await kavin.invite()).code), /add --as <name> to the end of the line/);
});

test('each OS keeps keys and messages apart from the installed app, so leave never deletes the app', () => {
  assert.equal(defaultHome({platform: 'darwin', home: '/Users/sam'}), '/Users/sam/Library/Application Support/agentchat');
  assert.equal(defaultHome({platform: 'linux', home: '/root', env: {XDG_DATA_HOME: '/elsewhere'}}), '/root/.local/share/agentchat', 'a runner with another environment still finds the same folder');
  const win = {platform: 'win32', home: 'C:\\Users\\Fírst Lást', env: {LOCALAPPDATA: 'C:\\Users\\Fírst Lást\\AppData\\Local'}};
  assert.equal(defaultHome(win), 'C:\\Users\\Fírst Lást\\AppData\\Local\\agentchat');
  for (const os of [win, {platform: 'linux', home: '/root'}, {platform: 'darwin', home: '/Users/sam'}]) {
    const data = defaultHome(os), app = installRoot(os);
    assert.ok(!data.startsWith(app) && !app.startsWith(data), `${os.platform}: ${data} vs ${app}`);
  }
});

test('Windows agents run Agentchat through cmd /d /c and the launcher, and the agent text says how to pass JSON there', () => {
  const home = 'C:\\Users\\Fírst Lást', launcher = `${home}\\.agentchat\\bin\\agentchat.cmd`;
  const wired = wiring({execPath: 'x', script: `${home}\\.agentchat\\app\\${VERSION}\\bin\\agentchat.js`, pathDirs: [], realpath: p => p, exists: p => p === launcher, home, platform: 'win32', dataHome: `${home}\\AppData\\Local\\agentchat`});
  assert.deepEqual(wired.mcp.mcpServers.agentchat, {command: 'cmd', args: ['/d', '/c', launcher, 'mcp']}, '/d keeps AutoRun output out of the MCP stream');
  assert.match(wired.grok, /\| cmd \/d \/c ".+agentchat\.cmd" call reply_availability -/);
  assert.match(wired.grok, /on this computer, with these instructions/);
  assert.match(wired.grok, /never read keys\.json, approval\.key or anything else in C:\\Users\\Fírst Lást\\AppData\\Local\\agentchat/);
});

test('agent-facing text follows the approval tier everywhere', () => {
  assert.match(instructionsFor(true), /take effect immediately\. Do them only when your owner asked/);
  assert.doesNotMatch(instructionsFor(true), /need your owner's Touch ID/);
  assert.match(rulesFor(false), /need your owner's Touch ID/);
  assert.match(rulesFor(false), /"with software key" came from that person's always-on agent, not from them in person/);
  for (const [software, phrase] of [[true, /Takes effect immediately with this computer's software key/], [false, /Asks your owner for Touch ID/]]) {
    const tools = toolsFor(software);
    for (const name of ['respond_to_plan', 'share_space', 'add_contact', 'approve']) assert.match(tools.find(t => t.name === name).description, phrase, name);
  }
});

test('the daily update check runs at most once a day, is recorded before it starts, and respects "off"', async () => {
  const net = network();
  let started = 0;
  const kavin = await net.owner('kavin');
  const node = await createNode({home: kavin.home, keystore: kavin.keystore, approver: kavin.approver, fetch: net.fetch, autoUpdate: () => { started++; }});
  await node.sync();
  await node.sync();
  assert.equal(started, 1);
  assert.ok(Date.now() - node.updateState().checked < 60000);
  node.store.meta('update', JSON.stringify({checked: 0}));
  node.setUpdates(false);
  await node.sync();
  assert.equal(started, 1, 'off means off');
  const crashing = await createNode({home: kavin.home, keystore: kavin.keystore, approver: kavin.approver, fetch: net.fetch, autoUpdate: () => { throw new Error('spawn EACCES'); }});
  crashing.setUpdates(true);
  crashing.store.meta('update', JSON.stringify({checked: 0}));
  await crashing.sync();
  assert.match(crashing.updateState().result, /couldn't start: spawn EACCES/);
  node.close();
  crashing.close();
});
